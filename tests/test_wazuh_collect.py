#!/usr/bin/env python3
"""Tests for wazuh-collect.py against a fake manager tree, a fake wazuh-db, a fake HTTPS indexer
and a fake upload receiver. Synthetic data only.

    python3 tests/test_wazuh_collect.py

On the oldest supported Python, and on the manager's 3.10 with the cryptography it bundles
(4.14.8 pins 48.0.1), from the script's folder; tests/run_docker.py runs both:

    docker run --rm -v "$PWD":/src:ro -w /src -e PYTHONDONTWRITEBYTECODE=1 \\
        python:3.6 python3 tests/test_wazuh_collect.py
    docker run --rm -v "$PWD":/src:ro -w /src -e PYTHONDONTWRITEBYTECODE=1 python:3.10 \\
        sh -c 'pip install -q cryptography==48.0.1 && python3 tests/test_wazuh_collect.py'

Where this Python has no cryptography library able to encrypt AES-256 CMS, the runs that send use
a stand-in encryptor, so the upload path is still tested, and the Encryption tests are skipped.

WC_SCRIPT names the script under test (default: the one beside this folder), so the mutation
runner can point the suite at a broken copy.
"""

import base64
import contextlib
import csv
import datetime
import gzip
import importlib.util
import io
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fake_indexer as fi  # noqa: E402
import fake_receiver as fr  # noqa: E402
import fake_wazuhdb as fw  # noqa: E402

SCRIPT = os.environ.get("WC_SCRIPT") or os.path.join(os.path.dirname(HERE), "wazuh-collect.py")
USER = "collector"
PASSWORD = "S3cret-Pass-word-Q7"
BASIC = base64.b64encode(("%s:%s" % (USER, PASSWORD)).encode()).decode()
TOKEN = "Tq3vX9a-Lw2_bN8cR5dK1mP7sY4hJ6gF0eZiUoAtWxE"
OTHER_TOKEN = "Zz3vX9a-Lw2_bN8cR5dK1mP7sY4hJ6gF0eZiUoAtWxQ"
CLUSTER_KEY = "CLUSTER-KEY-CANARY-c0ffee"
NODE = "node-a"
PROXY_VARS = ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY",
              "all_proxy", "ALL_PROXY")


def load_script():
    spec = importlib.util.spec_from_file_location("wazuh_collect", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WC = load_script()
CERT_DIR = tempfile.mkdtemp(prefix="wc-certs-")
CERTS = fi.make_certs(CERT_DIR)
with open(CERTS["recipient"][0], encoding="ascii") as _fh:
    RECIPIENT = _fh.read()

try:
    from cryptography.hazmat.primitives.serialization import pkcs7 as _pkcs7
    HAVE_CRYPTO = hasattr(getattr(_pkcs7, "PKCS7EnvelopeBuilder", None),
                          "set_content_encryption_algorithm")
except ImportError:
    HAVE_CRYPTO = False


def stand_in_encrypt(data, pem):
    return b"STAND-IN" + data[::-1], {
        "recipient_sha256": "0" * 64, "recipient_subject": "CN=stand-in",
        "recipient_not_after": "2099-01-01T00:00:00Z", "content_cipher": "none (test stand-in)"}


def padded_encrypt(data, pem):
    """The stand-in, padded to 16 MiB: larger than any socket buffer, so a receiver that stops
    reading leaves the client still sending."""
    blob, meta = stand_in_encrypt(data, pem)
    return blob + b"\0" * (16 * 1024 * 1024), meta


ENCRYPT = WC.encrypt_package if HAVE_CRYPTO else stand_in_encrypt


def tearDownModule():
    shutil.rmtree(CERT_DIR, ignore_errors=True)


OSSEC_CONF = """<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
  </global>
  <!--
  <cluster>
    <name>commented-out</name>
    <node_type>worker</node_type>
    <disabled>no</disabled>
  </cluster>
  -->
  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>
  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>{url}</host>
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>{ca}</ca>
      </certificate_authorities>
      <certificate>/etc/filebeat/certs/filebeat.pem</certificate>
      <key>/etc/filebeat/certs/filebeat-key.pem</key>
    </ssl>
  </indexer>
</ossec_config>
<ossec_config>
  <cluster>
    <name>wazuh</name>
    <node_name>{node}</node_name>
    <node_type>{node_type}</node_type>
    <key>{key}</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>10.0.0.1</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>{disabled}</disabled>
  </cluster>
</ossec_config>
"""

SCANNER_LINE = ("2026/10/21 10:00:00 wazuh-modulesd:vulnerability-scanner: INFO: Feed update "
                "process completed.")
OTHER_LINE = "2026/10/21 10:00:01 wazuh-analysisd: INFO: unrelated OTHER-LOG-CANARY"
ROTATED_LINE = ("2026/10/20 09:00:00 wazuh-modulesd:vulnerability-scanner: INFO: Vulnerability "
                "scan for agent '001' started.")
JSON_LOG_LINE = "wazuh-modulesd:vulnerability-scanner JSON-LOG-CANARY"


def make_manager(root, node_type="master", disabled="no", url="https://localhost:1",
                 ca=None):
    """A manager's files under root, as the script reads them under /var/ossec."""
    for d in ("etc", "logs/ossec/2026/Oct", "queue/db"):
        os.makedirs(os.path.join(root, d), exist_ok=True)
    with open(os.path.join(root, "etc", "ossec.conf"), "w") as fh:
        fh.write(OSSEC_CONF.format(url=url, ca=ca or CERTS["ca"], node="node01",
                                   node_type=node_type, key=CLUSTER_KEY, disabled=disabled))
    with open(os.path.join(root, "VERSION.json"), "w") as fh:
        fh.write('{"version": "4.14.8", "stage": "rc2"}\n')
    with open(os.path.join(root, "logs", "ossec.log"), "w") as fh:
        fh.write(SCANNER_LINE + "\n" + OTHER_LINE + "\n")
    with gzip.open(os.path.join(root, "logs/ossec/2026/Oct/ossec-20.log.gz"), "wt") as fh:
        fh.write(ROTATED_LINE + "\n" + OTHER_LINE + "\n")
    with gzip.open(os.path.join(root, "logs/ossec/2026/Oct/ossec-20.json.gz"), "wt") as fh:
        fh.write(JSON_LOG_LINE + "\n")


class Run:
    def __init__(self, code, out_dir, stderr):
        self.code, self.out_dir, self.stderr = code, out_dir, stderr
        self.files = sorted(os.listdir(out_dir))

    def path(self, suffix):
        found = [f for f in self.files if f.endswith(suffix)]
        assert len(found) == 1, (suffix, self.files)
        return os.path.join(self.out_dir, found[0])

    @property
    def zip_path(self):
        return self.path(".zip")

    def entries(self):
        with zipfile.ZipFile(self.zip_path) as zf:
            return {name: zf.read(name) for name in zf.namelist()}

    def manifest(self):
        return json.loads(self.entries()["manifest.json"].decode())

    def json(self, name):
        return json.loads(self.entries()[name].decode())

    def rows(self, name="wazuh-states.csv"):
        text = self.entries()[name].decode("utf-8")
        return list(csv.reader(io.StringIO(text)))


class Base(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.pop(k) for k in PROXY_VARS if k in os.environ}
        os.environ["no_proxy"] = "*"   # tests choose any proxy themselves, never the machine's
        self.out = tempfile.mkdtemp(prefix="wc-out-")
        self.addCleanup(shutil.rmtree, self.out, True)
        # A short path: a Unix socket path is limited to about 104 bytes.
        self.root = tempfile.mkdtemp(prefix="wc-", dir="/tmp")
        self.addCleanup(shutil.rmtree, self.root, True)

    def tearDown(self):
        for k in PROXY_VARS:
            os.environ.pop(k, None)
        os.environ.update(self._saved)

    @staticmethod
    def indexer(cert="localhost", vuln_agents=3, per_agent=40, skip=(), suffix="wazuh"):
        fake = fi.FakeIndexer(CERTS, USER, PASSWORD, cert=cert)
        for pattern in fi.PATTERNS:
            if pattern in skip:
                continue
            agents = vuln_agents if pattern == fi.VULN_PATTERN else 3
            fake.add_index(pattern, fi.docs_for(pattern, agents, per_agent,
                                                prefix=pattern.split("-")[2][:4]),
                           suffix=suffix)
        return fake

    @staticmethod
    def receiver(cert="localhost", tokens=(TOKEN,)):
        fake = fr.FakeReceiver(CERTS, cert=cert)
        for token in tokens:
            fake.mint(token)
        return fake

    def collect(self, extra=(), send=TOKEN, receiver=None, prompt=None, wazuh_dir=None,
                recipient=RECIPIENT, encrypt=None, upload_ca=None, user=USER, admin=None):
        """One run. admin is the indexer admin certificate pair the run finds on the host;
        None means none is there."""
        argv = ["--out-dir", self.out, "--page-size", "1000"] + list(extra)
        if user:
            argv += ["--user", user]
        if send:
            argv += ["--send", send]
        absent = (os.path.join(self.root, "no-admin.pem"), os.path.join(self.root, "no-admin.key"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = WC.main(argv, prompt=prompt or (lambda _: PASSWORD), ask=lambda _: USER,
                           wazuh_dir=self.root if wazuh_dir is None else wazuh_dir,
                           upload_url=receiver.url if receiver else "https://localhost:1/v1/upload",
                           upload_ca=upload_ca or CERTS["ca"], recipient=recipient,
                           encrypt=encrypt or ENCRYPT, hostname=NODE, admin_cert=admin or absent)
        return Run(code, self.out, err.getvalue())

    def assertNoSecret(self, run, extra=()):
        blobs = [run.stderr.encode()]
        for name in run.files:
            with open(os.path.join(run.out_dir, name), "rb") as fh:
                blobs.append(fh.read())
        if any(f.endswith(".zip") for f in run.files):
            blobs.extend(run.entries().values())
        for blob in blobs:
            for secret in (PASSWORD, BASIC, TOKEN, CLUSTER_KEY, fw.KEY_CANARY) + tuple(extra):
                self.assertNotIn(secret.encode(), blob)


def _not_called(_):
    raise AssertionError("the password was asked for on a run that does not read the indexer")


class MasterRun(Base):
    """One complete run on a master node, past 10,000 indexer rows, sent."""

    @classmethod
    def setUpClass(cls):
        cls._saved = {k: os.environ.pop(k) for k in PROXY_VARS if k in os.environ}
        os.environ["no_proxy"] = "*"
        cls.out = tempfile.mkdtemp(prefix="wc-out-")
        cls.root = tempfile.mkdtemp(prefix="wc-", dir="/tmp")
        cls.fake = cls.indexer(vuln_agents=25, per_agent=420).__enter__()
        make_manager(cls.root, url=cls.fake.url)
        cls.wdb = fw.FakeWazuhDb(cls.root, agents=3).__enter__()
        cls.rx = cls.receiver().__enter__()
        # Not "run": that name is TestCase.run.
        cls.done = cls("test_exit_and_files").collect(receiver=cls.rx)

    @classmethod
    def tearDownClass(cls):
        cls.rx.__exit__(None, None, None)
        cls.wdb.__exit__(None, None, None)
        cls.fake.__exit__(None, None, None)
        shutil.rmtree(cls.out, ignore_errors=True)
        shutil.rmtree(cls.root, ignore_errors=True)
        for k in PROXY_VARS:
            os.environ.pop(k, None)
        os.environ.update(cls._saved)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_exit_and_files(self):
        run = self.done
        self.assertEqual(run.code, 0, run.stderr)
        self.assertEqual(len(run.files), 3, run.files)
        stem = r"^wazuh-collect-node-a-\d{8}T\d{6}Z"
        self.assertRegex(run.files[0], stem + r"\.log$")
        self.assertRegex(run.files[1], stem + r"\.zip$")
        self.assertRegex(run.files[2], stem + r"\.zip\.p7m$")

    def test_zip_entries(self):
        self.assertEqual(sorted(self.done.entries()), [
            "collect.log", "manager/agents.json", "manager/inventory.json", "manager/node.json",
            "manager/scan_times.json", "manager/sync_info.json",
            "manager/vulnerability-detection.conf", "manager/vulnerability-scanner.log",
            "manifest.json", "wazuh-states.csv"])

    def test_inventory_rows_whole_per_agent(self):
        # Wazuh before 4.13 puts no inventory in the indexer; wazuh-db holds it.
        inventory = self.done.json("manager/inventory.json")
        self.assertEqual(len(inventory), 3 * len(WC.INVENTORY_TABLES))
        self.assertEqual({(i["agent"], i["table"]) for i in inventory},
                         {(a, t) for a in ("001", "002", "003") for t in WC.INVENTORY_TABLES})
        programs = next(i for i in inventory if i["agent"] == "002"
                        and i["table"] == "sys_programs")
        self.assertEqual([r["name"] for r in programs["rows"]], ["pkg-0", "pkg-1", "pkg-2"])
        self.assertTrue(programs["reconciled"])
        addresses = next(i for i in inventory if i["agent"] == "003"
                         and i["table"] == "sys_netaddr")
        self.assertEqual(addresses["rows"][0]["address"], "10.0.0.3")
        item = next(i for i in self.done.manifest()["items"]
                    if i["entry"] == "manager/inventory.json")
        self.assertTrue(item["reconciled"])
        self.assertEqual(item["rows"], sum(len(i["rows"]) for i in inventory))

    def test_every_document_of_six_data_sets_past_ten_thousand(self):
        rows = self.done.rows()
        per_index = {}
        for row in rows[1:]:
            per_index[row[0]] = per_index.get(row[0], 0) + 1
        expected = {fi.index_name(p): (25 * 420 if p == fi.VULN_PATTERN else 3 * 420)
                    for p in fi.PATTERNS}
        self.assertEqual(per_index, expected)
        self.assertEqual(len({(r[0], r[1]) for r in rows[1:]}), len(rows) - 1)
        manifest = self.done.manifest()
        self.assertEqual(len(manifest["patterns"]), 6)
        for p in manifest["patterns"]:
            self.assertTrue(p["reconciled"], p)
            self.assertEqual(p["rows_written"], p["snapshot_total"])

    def test_columns_are_the_reporting_form_of_every_mapped_field(self):
        header = self.done.rows()[0]
        self.assertEqual(header[:2], ["_index", "_id"])
        fields = set()
        for pattern in fi.PATTERNS:
            fields.update(name for name, _ in fi.fields_of(pattern))
        self.assertEqual(header[2:], ["_source." + f for f in sorted(fields)])

    def test_values_as_the_adapter_reads_them(self):
        rows = self.done.rows()
        header = rows[0]
        vuln = next(dict(zip(header, r)) for r in rows[1:]
                    if r[0] == fi.index_name(fi.VULN_PATTERN))
        self.assertEqual(vuln["_source.vulnerability.score.base"], "7.5")
        self.assertEqual(vuln["_source.vulnerability.under_evaluation"], "false")
        self.assertEqual(vuln["_source.vulnerability.category"], "Packages")
        self.assertEqual(vuln["_source.package.description"],
                         "synthetic package, with a comma and \"quotes\"")
        self.assertEqual(vuln["_source.host.os.kernel.release"], "")
        system = next(dict(zip(header, r)) for r in rows[1:]
                      if r[0] == fi.index_name("wazuh-states-inventory-system-*"))
        self.assertEqual(system["_source.host.os.kernel.release"], "6.8.0-142-generic")
        self.assertEqual(system["_source.vulnerability.id"], "")

    def test_agent_table_without_keys(self):
        agents = self.done.json("manager/agents.json")
        self.assertEqual([a["id"] for a in agents], [0, 1, 2, 3])
        self.assertEqual(agents[1]["name"], "agent-001-" + "x" * 10)
        self.assertEqual(agents[1]["last_keepalive"], 1761100001)
        self.assertEqual(agents[1]["group"], "default")
        self.assertNotIn("internal_key", json.dumps(agents))
        item = next(i for i in self.done.manifest()["items"]
                    if i["entry"] == "manager/agents.json")
        self.assertTrue(item["reconciled"])
        self.assertEqual(item["rows"], 4)

    def test_sync_info_and_scan_times_per_agent(self):
        sync = self.done.json("manager/sync_info.json")
        self.assertEqual([s["agent"] for s in sync], ["001", "002", "003"])
        self.assertEqual(len(sync[0]["rows"]), len(fw.COMPONENTS))
        packages = next(r for r in sync[1]["rows"] if r["component"] == "syscollector-packages")
        self.assertEqual(packages["last_completion"], 1761000003)
        scans = self.done.json("manager/scan_times.json")
        self.assertEqual(len(scans), 3 * len(WC.SCAN_TABLES))
        programs = next(s for s in scans if s["agent"] == "001" and s["table"] == "sys_programs")
        self.assertEqual(programs["max_scan_time"], "2026/10/22 10:00:00")
        self.assertEqual(programs["rows"], 3)

    def test_node_config_and_scanner_log(self):
        node = self.done.json("manager/node.json")
        self.assertEqual(node["role"], "master")
        self.assertEqual(node["cluster"], {"name": "wazuh", "node_name": "node01",
                                           "node_type": "master", "disabled": "no"})
        self.assertEqual(node["manager_version"], {"version": "4.14.8", "stage": "rc2"})
        conf = self.done.entries()["manager/vulnerability-detection.conf"].decode()
        self.assertIn("<feed-update-interval>60m</feed-update-interval>", conf)
        self.assertNotIn("<indexer>", conf)
        log = self.done.entries()["manager/vulnerability-scanner.log"].decode()
        self.assertEqual(log.splitlines(), [
            os.path.join("ossec", "2026", "Oct", "ossec-20.log.gz") + ": " + ROTATED_LINE,
            "ossec.log: " + SCANNER_LINE])

    def test_no_secret_anywhere(self):
        self.assertNoSecret(self.done, extra=("OTHER-LOG-CANARY", "JSON-LOG-CANARY"))

    def test_only_allowed_statements_and_requests(self):
        for command in self.wdb.commands:
            WC.check_sql(command)
            self.assertNotIn("internal_key", command)
            select, _, rest = command.partition(" FROM ")
            if "rowid AS row_id, *" in select:
                # Every column, of an inventory table only.
                self.assertIn(rest.split(" ")[0], WC.INVENTORY_TABLES)
                select = select.replace("rowid AS row_id, *", "")
            self.assertNotIn("*", select.replace("COUNT(*)", ""))
        for method, path, query, _ in self.fake.requests:
            WC.check_allowed(method, path, query)

    def test_sent_once_as_the_encrypted_file(self):
        self.assertEqual(len(self.rx.received), 1)
        name, body = self.rx.received[0]
        with open(self.done.path(".p7m"), "rb") as fh:
            self.assertEqual(body, fh.read())
        self.assertEqual(name, os.path.basename(self.done.path(".p7m")))
        self.assertEqual(self.rx.state(TOKEN), "used")
        method, path, headers = self.rx.requests[0]
        self.assertEqual((method, path), ("PUT", "/v1/upload"))
        self.assertEqual(headers["Content-Type"], "application/octet-stream")
        self.assertIn("sent: the receiver holds rx-%s" % name, self.done.stderr)

    def test_names_itself_in_every_request(self):
        # Cloudflare's Browser Integrity Check refused urllib's default agent string.
        agent = "wazuh-collect/" + WC.VERSION
        self.assertTrue(self.fake.user_agents)
        self.assertEqual(set(self.fake.user_agents), {agent})
        _, _, headers = self.rx.requests[0]
        sent = [v for k, v in headers.items() if k.lower() == "user-agent"]
        self.assertEqual(sent, [agent])

    def test_files_are_owner_only(self):
        for name in self.done.files:
            self.assertEqual(os.stat(os.path.join(self.out, name)).st_mode & 0o777, 0o600, name)

    def test_manifest_and_removal_line(self):
        m = self.done.manifest()
        self.assertEqual(m["result"], "complete")
        self.assertEqual(m["role"], "master")
        with open(SCRIPT, "rb") as fh:
            import hashlib
            self.assertEqual(m["script_sha256"], hashlib.sha256(fh.read()).hexdigest())
        for item in m["items"]:
            self.assertTrue(item["reconciled"], item)
        self.assertIn("to remove what this run left here: rm -- ", self.done.stderr)

    def test_search_contexts_released(self):
        self.assertEqual(len(self.fake.freed), 6)


class Roles(Base):
    def test_worker_reads_only_its_agent_databases(self):
        make_manager(self.root, node_type="worker")
        with fw.FakeWazuhDb(self.root, agents=3, worker_agents=[2]) as wdb, \
                self.receiver() as rx:
            run = self.collect(receiver=rx, prompt=_not_called, user=None)
        self.assertEqual(run.code, 0, run.stderr)
        entries = run.entries()
        self.assertNotIn("wazuh-states.csv", entries)
        self.assertNotIn("manager/agents.json", entries)
        self.assertEqual([s["agent"] for s in run.json("manager/sync_info.json")], ["002"])
        self.assertFalse([c for c in wdb.commands if c.startswith("global")])
        self.assertEqual(len(rx.received), 1)
        self.assertEqual(run.manifest()["role"], "worker")

    def test_cluster_disabled_is_standalone_and_reads_everything(self):
        # With no cluster, Wazuh names the indices after the host.
        with self.indexer(suffix=NODE) as fake:
            make_manager(self.root, disabled="yes", url=fake.url)
            with fw.FakeWazuhDb(self.root, agents=2):
                run = self.collect(send=None)
        self.assertEqual(run.code, 0, run.stderr)
        self.assertEqual(run.manifest()["role"], "standalone")
        self.assertEqual(run.manifest()["index_name"], NODE)
        self.assertIn("manager/agents.json", run.entries())
        self.assertIn("wazuh-states.csv", run.entries())

    def test_not_a_manager_needs_the_indexer_named(self):
        run = self.collect(send=None)
        self.assertEqual(run.code, 2)
        self.assertIn("give --url and --ca-file", run.stderr)
        self.assertIn("not a Wazuh manager", run.stderr)
        self.assertEqual(run.files, [])

    def test_not_a_manager_reads_the_indexer_only(self):
        with self.indexer() as fake:
            run = self.collect(extra=["--url", fake.url, "--ca-file", CERTS["ca"]], send=None)
        self.assertEqual(run.code, 0, run.stderr)
        self.assertEqual(sorted(run.entries()), ["collect.log", "manifest.json",
                                                 "wazuh-states.csv"])
        self.assertEqual(run.manifest()["role"], "not a manager")

    def test_arguments_override_ossec_conf(self):
        with self.indexer() as fake:
            make_manager(self.root, url="https://localhost:1", ca="/nonexistent/ca.pem")
            with fw.FakeWazuhDb(self.root, agents=1):
                run = self.collect(extra=["--url", fake.url, "--ca-file", CERTS["ca"]],
                                   send=None)
        self.assertEqual(run.code, 0, run.stderr)


class ConfigReading(Base):
    def config(self, text):
        os.makedirs(os.path.join(self.root, "etc"))
        with open(os.path.join(self.root, "etc", "ossec.conf"), "w") as fh:
            fh.write(text)
        return WC.read_config(self.root)

    def test_cluster_key_and_indexer_key_never_read(self):
        make_manager(self.root)
        config = WC.read_config(self.root)
        text = json.dumps(config)
        self.assertNotIn(CLUSTER_KEY, text)
        self.assertNotIn("filebeat-key.pem", text)
        self.assertEqual(config["indexer_host"], "https://localhost:1")
        self.assertEqual(config["indexer_ca"], CERTS["ca"])

    def test_no_cluster_block_is_standalone(self):
        self.assertEqual(self.config("<ossec_config></ossec_config>")["role"], "standalone")

    def test_commented_cluster_block_is_ignored(self):
        config = self.config("<ossec_config><!-- <cluster><node_type>worker</node_type>"
                             "<disabled>no</disabled></cluster> --></ossec_config>")
        self.assertEqual(config["role"], "standalone")

    def test_unknown_node_type_refused(self):
        with self.assertRaises(WC.UsageError):
            self.config("<cluster><node_type>client</node_type><disabled>no</disabled>"
                        "</cluster>")


class WazuhDb(Base):
    def master(self, **wdb_args):
        make_manager(self.root, url="https://localhost:1")
        return fw.FakeWazuhDb(self.root, **wdb_args)

    def run_master(self, wdb, send=TOKEN, rx=None):
        with self.indexer() as fake:
            make_manager(self.root, url=fake.url)
            return self.collect(send=send, receiver=rx)

    def test_answers_over_the_size_limit_are_read_in_smaller_pages(self):
        with self.master(agents=400, name_length=400) as wdb:
            run = self.run_master(wdb, send=None)
        self.assertEqual(run.code, 0, run.stderr)
        self.assertEqual(len(run.json("manager/agents.json")), 401)
        self.assertIn("reading 100 rows at a time", run.stderr)
        pages = [c for c in wdb.commands if c.startswith("global sql SELECT id")]
        self.assertTrue(any("LIMIT 100 " in c for c in pages), pages)

    def test_a_row_longer_than_the_limit_stops_the_run(self):
        with self.master(agents=1, name_length=70000) as wdb:
            with self.receiver() as rx:
                run = self.run_master(wdb, rx=rx)
            self.assertEqual(rx.requests, [])
            self.assertEqual(rx.state(TOKEN), "unused")
        self.assertEqual(run.code, 2, run.stderr)
        self.assertIn("is longer than wazuh-db's 65536-byte answer", run.stderr)
        self.assertIn("NOT SENT: the run stopped", run.stderr)

    def test_rows_missing_from_a_page_do_not_reconcile_but_are_sent(self):
        with self.master(agents=3) as wdb:
            wdb.faults["drop_rows_for"] = "agent 002 sql SELECT component"
            with self.receiver() as rx:
                run = self.run_master(wdb, rx=rx)
            self.assertEqual(len(rx.received), 1)
        self.assertEqual(run.code, 1, run.stderr)
        self.assertRegex(run.zip_path, r"-INCOMPLETE\.zip$")
        item = next(i for i in run.manifest()["items"]
                    if i["entry"] == "manager/sync_info.json")
        self.assertFalse(item["reconciled"])
        self.assertIn("agent 002 sync_info: 9 rows read but the count is 10", item["notes"][0])

    def test_an_error_answer_is_recorded_with_its_text(self):
        with self.master(agents=2) as wdb:
            wdb.faults["err_for"] = "FROM sys_hwinfo"
            run = self.run_master(wdb, send=None)
        self.assertEqual(run.code, 1, run.stderr)
        scans = run.json("manager/scan_times.json")
        failed = [s for s in scans if "error" in s]
        self.assertEqual(len(failed), 2)
        self.assertIn("err Cannot execute SQL query", failed[0]["error"])
        self.assertIn("err Cannot execute SQL query", run.stderr)

    def test_an_answer_that_is_not_json_is_an_error_not_an_empty_result(self):
        with self.master(agents=1) as wdb:
            wdb.faults["not_json_for"] = "COUNT(*) AS n FROM sync_info"
            run = self.run_master(wdb, send=None)
        self.assertEqual(run.code, 1, run.stderr)
        sync = run.json("manager/sync_info.json")
        self.assertIn("is not JSON", sync[0]["error"])

    def test_a_dropped_connection_stops_the_run_unsent(self):
        with self.master(agents=1) as wdb:
            wdb.faults["close_for"] = "global sql SELECT COUNT"
            with self.receiver() as rx:
                run = self.run_master(wdb, rx=rx)
            self.assertEqual(rx.requests, [])
        self.assertEqual(run.code, 2, run.stderr)
        self.assertIn("wazuh-db closed the connection", run.stderr)

    def test_statements_outside_the_list_are_refused(self):
        for command in ("global sql SELECT internal_key FROM agent",
                        "global sql SELECT id, name, internal_key FROM agent ORDER BY id "
                        "LIMIT 10 OFFSET 0",
                        "agent 001 sql DELETE FROM sync_info",
                        "agent 001 sql SELECT MAX(scan_time) AS max_scan_time, COUNT(*) AS n "
                        "FROM sys_users",
                        "agent 1 sql SELECT COUNT(*) AS n FROM sync_info",
                        "agent 001 sql SELECT COUNT(*) AS n FROM sync_info; DROP TABLE x",
                        "global sql SELECT COUNT(*) AS n FROM agent ",
                        WC.GLOBAL_PAGE.format(limit=0, offset=0),
                        WC.INVENTORY_PAGE.format(agent="001", inventory="sys_users", limit=5,
                                                 offset=0),
                        WC.INVENTORY_COUNT.format(agent="001", inventory="sys_processes"),
                        "agent 001 sql SELECT rowid AS row_id, * FROM agent ORDER BY rowid "
                        "LIMIT 5 OFFSET 0"):
            with self.assertRaises(WC.CollectError, msg=command):
                WC.check_sql(command)
        for command in (WC.GLOBAL_COUNT, WC.GLOBAL_PAGE.format(limit=200, offset=400),
                        WC.SYNC_PAGE.format(agent="1024", limit=5, offset=0),
                        WC.SCAN_TIME.format(agent="001", table="sys_netiface"),
                        WC.INVENTORY_COUNT.format(agent="001", inventory="sys_netproto"),
                        WC.INVENTORY_PAGE.format(agent="001", inventory="sys_programs",
                                                 limit=200, offset=0)):
            WC.check_sql(command)

    def test_inventory_rows_missing_do_not_reconcile_but_are_sent(self):
        with self.master(agents=2) as wdb:
            wdb.faults["drop_rows_for"] = "agent 002 sql SELECT rowid AS row_id, * FROM sys_programs"
            with self.receiver() as rx:
                run = self.run_master(wdb, rx=rx)
            self.assertEqual(len(rx.received), 1)
        self.assertEqual(run.code, 1, run.stderr)
        item = next(i for i in run.manifest()["items"] if i["entry"] == "manager/inventory.json")
        self.assertFalse(item["reconciled"])
        self.assertIn("agent 002 sys_programs: 2 rows read but the count is 3", item["notes"][0])

    def test_a_refused_statement_never_reaches_the_socket(self):
        with self.master(agents=1) as wdb:
            with self.assertRaises(WC.CollectError):
                WC.wdb_query(wdb.socket_path, "global sql SELECT internal_key FROM agent")
            self.assertEqual(wdb.commands, [])


class IndexerReconciliation(Base):
    def collect_with(self, send=TOKEN, skip=(), **faults):
        with self.indexer(skip=skip) as fake, self.receiver() as rx:
            for k, v in faults.items():
                setattr(fake.faults, k, v)
            make_manager(self.root, url=fake.url)
            with fw.FakeWazuhDb(self.root, agents=1):
                run = self.collect(send=send, receiver=rx)
            return run, fake, rx

    def assertIncomplete(self, run, code=1):
        self.assertEqual(run.code, code, run.stderr)
        zips = [f for f in run.files if f.endswith(".zip")]
        self.assertEqual(len(zips), 1, run.files)
        self.assertRegex(zips[0], r"-INCOMPLETE\.zip$")
        names = sorted(run.entries())
        self.assertIn("wazuh-states.csv.incomplete", names)
        self.assertNotIn("wazuh-states.csv", names)
        self.assertEqual(run.manifest()["result"], "incomplete")

    def test_lost_page_is_incomplete_and_still_sent(self):
        run, _, rx = self.collect_with(drop_page=0)
        self.assertIncomplete(run)
        vuln = run.manifest()["patterns"][0]
        self.assertFalse(vuln["reconciled"])
        self.assertEqual(vuln["rows_written"], 0)
        self.assertEqual(len(rx.received), 1)
        csv_item = next(i for i in run.manifest()["items"] if i["entry"] == "wazuh-states.csv")
        self.assertEqual(csv_item["notes"],
                         ["wazuh-states-vulnerabilities-* did not reconcile; see its entry"])

    def test_page_served_twice(self):
        with self.indexer(per_agent=500) as fake, self.receiver() as rx:
            fake.faults.repeat_page = 0
            make_manager(self.root, url=fake.url)
            with fw.FakeWazuhDb(self.root, agents=1):
                run = self.collect(receiver=rx)
        self.assertIncomplete(run)
        self.assertEqual(run.manifest()["patterns"][0]["rows_written"], 2500)

    def test_page_replaced_by_a_duplicate_balances_the_count_but_not_the_ids(self):
        with self.indexer(per_agent=1000) as fake:
            fake.faults.replace_page = 1
            make_manager(self.root, url=fake.url)
            with fw.FakeWazuhDb(self.root, agents=1):
                run = self.collect(send=None)
        self.assertIncomplete(run)
        vuln = run.manifest()["patterns"][0]
        self.assertEqual(vuln["rows_written"], 3000)
        self.assertEqual(vuln["distinct_ids"], 2000)

    def test_total_disagrees(self):
        run, _, _ = self.collect_with(total_offset=5)
        self.assertIncomplete(run)

    def test_total_given_as_a_lower_bound_stops_the_run_unsent(self):
        run, _, rx = self.collect_with(total_relation="gte")
        self.assertEqual(run.code, 2, run.stderr)
        self.assertIn("lower bound", run.manifest()["error"])
        self.assertEqual(rx.requests, [])

    def test_count_moving_during_the_run_is_noted_not_failed(self):
        run, _, _ = self.collect_with(send=None, count_drift=3)
        self.assertEqual(run.code, 0, run.stderr)
        notes = run.manifest()["patterns"][0]["notes"]
        self.assertEqual(len(notes), 1)
        self.assertIn("counts moved during the run: before 120, snapshot 120, after 123", notes[0])

    def test_optional_data_set_with_no_index_is_noted_not_incomplete(self):
        run, _, _ = self.collect_with(send=None, skip=("wazuh-states-inventory-hotfixes-*",))
        self.assertEqual(run.code, 0, run.stderr)
        hotfixes = next(p for p in run.manifest()["patterns"]
                        if p["pattern"] == "wazuh-states-inventory-hotfixes-*")
        self.assertTrue(hotfixes["reconciled"])
        self.assertIn("no index matches this pattern", hotfixes["notes"][0])

    def test_required_data_set_with_no_index_is_incomplete(self):
        run, _, _ = self.collect_with(send=None, skip=("wazuh-states-vulnerabilities-*",))
        self.assertIncomplete(run)

    def test_no_packages_index_on_a_manager_is_noted_not_incomplete(self):
        # Wazuh before 4.13 indexes no inventory; on a manager it is read from wazuh-db.
        run, _, _ = self.collect_with(send=None, skip=("wazuh-states-inventory-packages-*",))
        self.assertEqual(run.code, 0, run.stderr)
        packages = next(p for p in run.manifest()["patterns"]
                        if p["pattern"] == "wazuh-states-inventory-packages-*")
        self.assertTrue(packages["reconciled"])
        self.assertIn("manager/inventory.json", packages["notes"][0])

    def test_no_packages_index_off_a_manager_is_incomplete(self):
        with self.indexer(skip=("wazuh-states-inventory-packages-*",)) as fake:
            run = self.collect(extra=["--url", fake.url, "--ca-file", CERTS["ca"]], send=None)
        self.assertIncomplete(run)

    def test_unmapped_field_stops_the_run(self):
        run, fake, _ = self.collect_with(extra_field_at=(fi.VULN_PATTERN, 5))
        self.assertIncomplete(run, code=2)
        self.assertIn("field unmapped_field is in a document but not in the index mapping",
                      run.manifest()["error"])
        self.assertEqual(fake.freed, ["scroll-0"])

    def test_list_of_objects_stops_the_run(self):
        run, _, _ = self.collect_with(object_list_at=(fi.VULN_PATTERN, 5))
        self.assertIncomplete(run, code=2)
        self.assertIn("field objects holds a list of objects", run.manifest()["error"])

    def test_version_unreadable_is_recorded_not_failed(self):
        run, _, _ = self.collect_with(send=None, version_status=403)
        self.assertEqual(run.code, 0, run.stderr)
        self.assertEqual(run.manifest()["indexer_version"], "unknown")
        self.assertIn("indexer version: unknown (HTTP 403", run.stderr)


class Refusals(Base):
    def indexer_only(self, url, ca=None, prompt=None, send=None, rx=None):
        return self.collect(extra=["--url", url, "--ca-file", ca or CERTS["ca"]], send=send,
                            prompt=prompt, receiver=rx)

    def test_http_url_refused(self):
        run = self.indexer_only("http://localhost:9200")
        self.assertEqual(run.code, 2)
        self.assertIn("must start with https://", run.stderr)
        self.assertEqual(run.files, [])

    def test_credentials_in_url_refused(self):
        run = self.indexer_only("https://u:p@localhost:9200")
        self.assertEqual(run.code, 2)
        self.assertIn("must not contain credentials", run.stderr)

    def test_wrong_ca(self):
        with self.indexer() as fake:
            run = self.indexer_only(fake.url, ca=CERTS["otherca"])
        self.assertEqual(run.code, 2)
        self.assertIn("did not verify against the CA file", run.stderr)
        self.assertNoSecret(run)

    def test_certificate_for_another_host(self):
        with self.indexer(cert="wronghost") as fake:
            run = self.indexer_only(fake.url)
        self.assertEqual(run.code, 2)
        self.assertIn("does not name the host used", run.stderr)

    def test_redirect_refused(self):
        with self.indexer() as fake:
            fake.faults.redirect_path = "/"
            run = self.indexer_only(fake.url)
            followed = [r for r in fake.requests if r[1] == "/elsewhere"]
        self.assertEqual(run.code, 2)
        self.assertIn("redirects are refused", run.stderr)
        self.assertEqual(followed, [])

    def test_wrong_password_stops_unsent_and_keeps_the_token(self):
        with self.indexer() as fake, self.receiver() as rx:
            run = self.indexer_only(fake.url, prompt=lambda _: "wrong", send=TOKEN, rx=rx)
            self.assertEqual(rx.requests, [])
            self.assertEqual(rx.state(TOKEN), "unused")
        self.assertEqual(run.code, 2)
        self.assertIn("HTTP 401", run.stderr)
        self.assertIn("username or password was not accepted", run.stderr)
        self.assertIn("the token is still unused", run.stderr)

    def test_server_error_recorded_with_its_text(self):
        with self.indexer() as fake:
            fake.faults.status[("GET", "/_mapping")] = (500, {"error": "shard failure xyz"})
            run = self.indexer_only(fake.url)
        self.assertEqual(run.code, 2)
        self.assertIn("shard failure xyz", run.stderr)
        self.assertIn("shard failure xyz", run.manifest()["error"])

    def test_request_outside_the_allow_list_never_sent(self):
        with self.indexer() as fake:
            ix = WC.Indexer(fake.url, CERTS["ca"], USER, PASSWORD)
            for method, path, query in (("PUT", "/x", {}),
                                        ("GET", "/wazuh-alerts-*/_count", {}),
                                        ("GET", "/wazuh-states-inventory-users-*/_count", {}),
                                        ("POST", "/wazuh-states-vulnerabilities-*/_search", {}),
                                        ("DELETE", "/wazuh-states-vulnerabilities-test", {}),
                                        ("GET", "/_cat/indices", {}),
                                        ("GET", "/wazuh-states-vulnerabilities-a*b/_count", {}),
                                        ("POST", "/wazuh-states-inventory-users-wazuh/_search",
                                         {"scroll": "1m"}),
                                        ("GET", "/wazuh-states-vulnerabilities-wazuh/_mapping",
                                         {})):
                with self.assertRaises(WC.CollectError):
                    ix.request(method, path, query)
            self.assertEqual(fake.requests, [])

    def test_malformed_token_refused_before_anything(self):
        run = self.collect(send="not-a-token")
        self.assertEqual(run.code, 2)
        self.assertIn("43-character upload token", run.stderr)
        self.assertEqual(run.files, [])

    def test_send_without_a_recipient_certificate_refused_before_anything(self):
        run = self.collect(recipient="")
        self.assertEqual(run.code, 2)
        self.assertIn("carries no recipient certificate", run.stderr)
        self.assertEqual(run.files, [])

    def test_the_shipped_copy_carries_one_pem_certificate(self):
        cert = WC.RECIPIENT_CERTIFICATE or ""
        self.assertTrue(cert.startswith("-----BEGIN CERTIFICATE-----\n"))
        self.assertTrue(cert.endswith("-----END CERTIFICATE-----\n"))
        self.assertEqual(cert.count("BEGIN"), 1)


class AdminCertificate(Base):
    """One command and nothing else: where the indexer runs on the host, its admin certificate
    signs the script in, with no account and no password."""

    def master_run(self, admin, rx=None, send=None, cert="localhost"):
        with self.indexer(cert=cert) as fake:
            make_manager(self.root, url=fake.url)
            with fw.FakeWazuhDb(self.root, agents=1):
                run = self.collect(send=send, receiver=rx, user=None, prompt=_not_called,
                                   admin=admin)
            return run, fake

    def test_the_admin_certificate_signs_in_with_no_account_or_password(self):
        with self.receiver() as rx:
            run, fake = self.master_run(CERTS["admin"], rx=rx, send=TOKEN)
            self.assertEqual(len(rx.received), 1)
        self.assertEqual(run.code, 0, run.stderr)
        self.assertTrue(fake.requests)
        self.assertEqual({r[3] for r in fake.requests}, {None}, "an Authorization header was sent")
        self.assertEqual(set(fake.client_cns), {"admin"})
        self.assertEqual(run.manifest()["indexer_auth"], "certificate")
        self.assertIn("the indexer's admin certificate", run.stderr)
        with open(CERTS["admin"][1], encoding="ascii") as fh:
            key_body = fh.read().splitlines()[1]
        self.assertNoSecret(run, extra=(key_body,))

    def test_no_certificate_and_no_account_stops_before_anything(self):
        with self.receiver() as rx:
            run, fake = self.master_run(None, rx=rx, send=TOKEN)
            self.assertEqual(rx.requests, [])
            self.assertEqual(rx.state(TOKEN), "unused")
            self.assertEqual(fake.requests, [])
        self.assertEqual(run.code, 2)
        self.assertIn("the indexer's admin certificate is not on this host", run.stderr)
        self.assertIn("the upload token is still unused", run.stderr)
        self.assertEqual(run.files, [])

    def test_a_key_that_does_not_load_stops_before_anything(self):
        bad = os.path.join(self.root, "bad-key.pem")
        with open(bad, "w") as fh:
            fh.write("not a key\n")
        run, fake = self.master_run((CERTS["admin"][0], bad))
        self.assertEqual(run.code, 2)
        self.assertIn("cannot be used", run.stderr)
        self.assertEqual(run.files, [])
        self.assertEqual(fake.requests, [])

    def test_a_certificate_the_indexer_does_not_trust_is_refused_unsent(self):
        with self.receiver() as rx:
            run, fake = self.master_run(CERTS["rogueadmin"], rx=rx, send=TOKEN)
            self.assertEqual(rx.requests, [])
            self.assertEqual(rx.state(TOKEN), "unused")
        self.assertEqual(run.code, 2)
        self.assertIn("NOT SENT: the run stopped", run.stderr)
        self.assertNotIn("admin", set(fake.client_cns))

    def test_the_allow_list_binds_the_certificate_too(self):
        with self.indexer() as fake:
            ix = WC.Indexer(fake.url, CERTS["ca"], None, None, client_cert=CERTS["admin"])
            for method, path, query in (("PUT", "/x", {}),
                                        ("GET", "/_cat/indices", {}),
                                        ("DELETE", "/wazuh-states-vulnerabilities-wazuh", {}),
                                        ("GET", "/wazuh-states-inventory-users-*/_count", {})):
                with self.assertRaises(WC.CollectError):
                    ix.request(method, path, query)
            self.assertEqual(fake.requests, [])


class IndexNames(Base):
    """Only the indices of the current name are read; others left by an earlier name are
    listed, not read."""

    def test_only_the_current_names_index_is_read(self):
        with self.indexer() as fake:
            fake.add_index(fi.VULN_PATTERN, fi.docs_for(fi.VULN_PATTERN, 1, 7, prefix="old"),
                           suffix="ip-10-0-0-1")
            make_manager(self.root, url=fake.url)
            with fw.FakeWazuhDb(self.root, agents=1):
                run = self.collect(send=None)
            searched = [r[1] for r in fake.requests if r[1].endswith("/_search")]
        self.assertEqual(run.code, 0, run.stderr)
        self.assertEqual({r[0] for r in run.rows()[1:]},
                         {fi.index_name(p) for p in fi.PATTERNS})
        vuln = next(p for p in run.manifest()["patterns"] if p["pattern"] == fi.VULN_PATTERN)
        self.assertEqual(vuln["other_indices"],
                         [{"index": "wazuh-states-vulnerabilities-ip-10-0-0-1", "documents": 7}])
        self.assertFalse([p for p in searched if "ip-10-0-0-1" in p], searched)
        self.assertEqual(run.manifest()["index_name"], "wazuh")

    def test_no_index_of_the_current_name_is_incomplete_whatever_else_is_there(self):
        with self.indexer(suffix="ip-10-0-0-1") as fake:
            make_manager(self.root, url=fake.url)
            with fw.FakeWazuhDb(self.root, agents=1):
                run = self.collect(send=None)
        self.assertEqual(run.code, 1, run.stderr)
        self.assertRegex(run.zip_path, r"-INCOMPLETE\.zip$")
        vuln = next(p for p in run.manifest()["patterns"] if p["pattern"] == fi.VULN_PATTERN)
        self.assertIn("no index named wazuh-states-vulnerabilities-wazuh, the current name",
                      vuln["notes"])
        self.assertEqual(len(vuln["other_indices"]), 1)


class Upload(Base):
    def collect_sent(self, rx, send=TOKEN, **kwargs):
        with self.indexer() as fake:
            make_manager(self.root, url=fake.url)
            with fw.FakeWazuhDb(self.root, agents=1):
                return self.collect(send=send, receiver=rx, **kwargs)

    def test_unknown_token(self):
        with self.receiver(tokens=()) as rx:
            run = self.collect_sent(rx)
        self.assertEqual(run.code, 2)
        self.assertIn("HTTP 401", run.stderr)
        self.assertIn("unknown or has expired", run.stderr)

    def test_used_token(self):
        # A body larger than the socket buffers, so the refusal arrives while it is being sent.
        with self.receiver() as rx:
            rx.tokens[next(iter(rx.tokens))]["state"] = "used"
            run = self.collect_sent(rx, encrypt=padded_encrypt)
        self.assertEqual(run.code, 2)
        self.assertIn("HTTP 409", run.stderr)

    def test_receiver_closing_without_an_answer_is_named(self):
        with self.receiver() as rx:
            rx.faults["close_without_answer"] = True
            run = self.collect_sent(rx, encrypt=padded_encrypt)
        self.assertEqual(run.code, 2)
        self.assertIn("the receiver closed the connection without answering", run.stderr)
        self.assertIn("NOT SENT", run.stderr)

    def test_a_write_error_after_the_head_is_held_back(self):
        class Stub:
            def __init__(self):
                self.sent = []

            def send(self, data):
                if not data.startswith(b"PUT ") and self.sent:
                    raise BrokenPipeError(32, "Broken pipe")
                self.sent.append(data)

        class Connection(WC._KeepEarlyAnswer, Stub):
            pass

        conn = Connection()
        conn.send(b"PUT /v1/upload HTTP/1.1\r\n\r\n")
        conn.send(b"body")
        conn.send(b"more")
        self.assertTrue(conn.head_sent)
        self.assertIsInstance(conn.body_interrupted, BrokenPipeError)
        self.assertEqual(conn.body_sent, 0)
        self.assertEqual(len(conn.sent), 1)

    def test_receiver_limit(self):
        with self.receiver(tokens=()) as rx:
            rx.mint(TOKEN, limit=100)
            run = self.collect_sent(rx)
            self.assertEqual(rx.received, [])
        self.assertEqual(run.code, 2)
        self.assertIn("HTTP 413", run.stderr)

    def test_hash_mismatch_leaves_the_token_usable(self):
        with self.receiver() as rx:
            rx.faults["mismatch"] = True
            run = self.collect_sent(rx)
            self.assertEqual(rx.state(TOKEN), "unused")
            self.assertEqual(rx.received, [])
        self.assertEqual(run.code, 2)
        self.assertIn("HTTP 422", run.stderr)
        self.assertIn("run the command again", run.stderr)

    def test_receipt_that_does_not_match(self):
        with self.receiver() as rx:
            rx.faults["receipt_sha256"] = "f" * 64
            run = self.collect_sent(rx)
        self.assertEqual(run.code, 2)
        self.assertIn("the receipt does not match what was sent", run.stderr)

    def test_redirect_refused(self):
        with self.receiver() as rx:
            rx.faults["redirect"] = True
            run = self.collect_sent(rx)
        self.assertEqual(run.code, 2)
        self.assertIn("redirects are refused", run.stderr)

    def test_receiver_certificate_verified(self):
        with self.receiver() as rx:
            run = self.collect_sent(rx, upload_ca=CERTS["otherca"])
            self.assertEqual(rx.requests, [])
        self.assertEqual(run.code, 2)
        self.assertIn("NOT SENT", run.stderr)
        self.assertIn("did not verify", run.stderr)

    def test_receiver_error_recorded_with_its_text(self):
        with self.receiver() as rx:
            rx.faults["status"] = (500, {"error": "disk full xyz"})
            run = self.collect_sent(rx)
        self.assertEqual(run.code, 2)
        self.assertIn("disk full xyz", run.stderr)

    def test_over_the_limit_is_not_sent(self):
        saved = WC.MAX_UPLOAD_BYTES
        WC.MAX_UPLOAD_BYTES = 100
        try:
            with self.receiver() as rx:
                run = self.collect_sent(rx)
                self.assertEqual(rx.requests, [])
        finally:
            WC.MAX_UPLOAD_BYTES = saved
        self.assertEqual(run.code, 2)
        self.assertIn("over the 100-byte upload limit", run.stderr)
        self.assertIn(os.path.basename(run.path(".p7m")), run.stderr)

    def test_no_encryption_means_nothing_sent(self):
        def cannot(data, pem):
            raise WC.NotEncrypted("this Python has no usable cryptography library (test)")
        with self.receiver() as rx:
            run = self.collect_sent(rx, encrypt=cannot)
            self.assertEqual(rx.requests, [])
        self.assertEqual(run.code, 2)
        self.assertIn("NOT ENCRYPTED", run.stderr)
        self.assertFalse([f for f in run.files if f.endswith(".p7m")])
        self.assertEqual(len([f for f in run.files if f.endswith(".zip")]), 1)

    def test_without_send_nothing_is_sent(self):
        with self.receiver() as rx:
            run = self.collect_sent(rx, send=None)
            self.assertEqual(rx.requests, [])
        self.assertEqual(run.code, 0, run.stderr)
        self.assertIn("not sent: no --send given", run.stderr)
        self.assertEqual(len([f for f in run.files if f.endswith(".p7m")]), 1)

    def test_only_the_one_upload_is_allowed(self):
        for method, url in (("POST", "https://localhost:1/v1/upload"),
                            ("PUT", "http://localhost:1/v1/upload"),
                            ("PUT", "https://localhost:1/v1/other"),
                            ("PUT", "https://localhost:1/v1/upload?x=1"),
                            ("PUT", "https://u:p@localhost:1/v1/upload")):
            with self.assertRaises(WC.CollectError, msg=(method, url)):
                WC.check_upload(method, url)
        WC.check_upload("PUT", WC.UPLOAD_URL)

    def test_the_production_address(self):
        self.assertEqual(WC.UPLOAD_URL, "https://upload.4amlabs.com/v1/upload")
        self.assertEqual(WC.MAX_UPLOAD_BYTES, 95000000)


@unittest.skipUnless(HAVE_CRYPTO, "this Python's cryptography cannot encrypt AES-256 CMS")
class Encryption(Base):
    def decrypt(self, path, key=None):
        out = path + ".dec"
        proc = subprocess.run(["openssl", "cms", "-decrypt", "-binary", "-inform", "DER",
                               "-in", path, "-recip", CERTS["recipient"][0],
                               "-inkey", key or CERTS["recipient"][1], "-out", out],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(out, "rb") as fh:
            return fh.read()

    def test_the_sent_file_decrypts_to_the_package(self):
        with self.indexer() as fake, self.receiver() as rx:
            make_manager(self.root, url=fake.url)
            with fw.FakeWazuhDb(self.root, agents=1):
                run = self.collect(receiver=rx, encrypt=WC.encrypt_package)
        self.assertEqual(run.code, 0, run.stderr)
        with open(run.zip_path, "rb") as fh:
            package = fh.read()
        work = tempfile.mkdtemp(prefix="wc-dec-")
        self.addCleanup(shutil.rmtree, work, True)
        sent = os.path.join(work, "sent.p7m")
        with open(sent, "wb") as fh:
            fh.write(rx.received[0][1])
        self.assertEqual(self.decrypt(sent), package)
        self.assertIn("aes-256-cbc", run.stderr)

    def test_structure_names_aes_256(self):
        blob, info = WC.encrypt_package(b"sample", RECIPIENT)
        path = os.path.join(self.out, "s.p7m")
        with open(path, "wb") as fh:
            fh.write(blob)
        proc = subprocess.run(["openssl", "cms", "-cmsout", "-print", "-inform", "DER",
                               "-in", path], stdout=subprocess.PIPE, universal_newlines=True)
        self.assertIn("aes-256-cbc", proc.stdout)
        self.assertNotIn("aes-128-cbc", proc.stdout)
        self.assertEqual(self.decrypt(path), b"sample")
        self.assertEqual(info["content_cipher"], "aes-256-cbc")

    def printed(self, blob):
        """The blob saved under the run's folder, and openssl's print of its structure."""
        path = os.path.join(self.out, "route.p7m")
        with open(path, "wb") as fh:
            fh.write(blob)
        proc = subprocess.run(["openssl", "cms", "-cmsout", "-print", "-inform", "DER",
                               "-in", path], stdout=subprocess.PIPE, universal_newlines=True)
        return path, proc.stdout

    def recipient_cert(self):
        from cryptography import x509
        return x509.load_pem_x509_certificate(RECIPIENT.encode("ascii"))

    def test_a_builder_without_a_cipher_choice_uses_its_default(self):
        # Wazuh 4.10 to 4.13 bundle cryptography 43 and 44, whose builder has no
        # set_content_encryption_algorithm and encrypts to AES-128-CBC.
        from cryptography.hazmat.primitives.serialization import pkcs7
        real = pkcs7.PKCS7EnvelopeBuilder

        class OldBuilder:
            def __init__(self, inner=None):
                self._inner = inner or real()

            def set_data(self, data):
                return OldBuilder(self._inner.set_data(data))

            def add_recipient(self, cert):
                return OldBuilder(self._inner.add_recipient(cert))

            def encrypt(self, encoding, options):
                return self._inner.encrypt(encoding, options)

        blob, cipher = WC.envelope(b"sample", self.recipient_cert(), RECIPIENT, OldBuilder)
        path, structure = self.printed(blob)
        self.assertIn("aes-128-cbc", structure)
        self.assertEqual(self.decrypt(path), b"sample")
        self.assertEqual(cipher, "aes-128-cbc")

    def fake_openssl(self, script):
        bindir = tempfile.mkdtemp(prefix="wc-path-")
        self.addCleanup(shutil.rmtree, bindir, True)
        fake = os.path.join(bindir, "openssl")
        with open(fake, "w") as fh:
            fh.write("#!/bin/sh\n" + script)
        os.chmod(fake, 0o755)
        return bindir

    def test_no_builder_encrypts_with_openssl(self):
        # Wazuh 4.8 and 4.9 bundle cryptography 42, which has no CMS encryption.
        scratch = tempfile.mkdtemp(prefix="wc-tmp-")
        self.addCleanup(shutil.rmtree, scratch, True)
        with mock.patch.object(WC.tempfile, "tempdir", scratch):
            blob, cipher = WC.envelope(b"sample", self.recipient_cert(), RECIPIENT, None)
        self.assertEqual(os.listdir(scratch), [], "the certificate's directory is left behind")
        path, structure = self.printed(blob)
        self.assertIn("aes-256-cbc", structure)
        self.assertNotIn("aes-128-cbc", structure)
        self.assertEqual(self.decrypt(path), b"sample")
        self.assertTrue(cipher.startswith("aes-256-cbc (openssl at "), cipher)

    def test_no_builder_and_no_openssl_is_not_encrypted(self):
        empty = tempfile.mkdtemp(prefix="wc-path-")
        self.addCleanup(shutil.rmtree, empty, True)
        with mock.patch.dict(os.environ, {"PATH": empty}):
            with self.assertRaises(WC.NotEncrypted) as ctx:
                WC.envelope(b"sample", self.recipient_cert(), RECIPIENT, None)
        self.assertIn("no openssl program", str(ctx.exception))

    def test_an_openssl_failure_is_not_encrypted_with_its_text(self):
        bindir = self.fake_openssl("echo partial\necho 'cms: simulated failure' >&2\nexit 3\n")
        with mock.patch.dict(os.environ, {"PATH": bindir}):
            with self.assertRaises(WC.NotEncrypted) as ctx:
                WC.envelope(b"sample", self.recipient_cert(), RECIPIENT, None)
        self.assertIn("exit 3", str(ctx.exception))
        self.assertIn("simulated failure", str(ctx.exception))

    def test_an_openssl_with_no_output_is_not_encrypted(self):
        bindir = self.fake_openssl("exit 0\n")
        with mock.patch.dict(os.environ, {"PATH": bindir}):
            with self.assertRaises(WC.NotEncrypted) as ctx:
                WC.envelope(b"sample", self.recipient_cert(), RECIPIENT, None)
        self.assertIn("exit 0", str(ctx.exception))

    def test_expired_recipient_certificate_refused(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime(2020, 1, 1))
                .not_valid_after(datetime.datetime(2020, 1, 2))
                .sign(key, hashes.SHA256()))
        pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        with self.receiver() as rx:
            with self.indexer() as fake:
                make_manager(self.root, url=fake.url)
                with fw.FakeWazuhDb(self.root, agents=1):
                    run = self.collect(receiver=rx, recipient=pem, encrypt=WC.encrypt_package)
            self.assertEqual(rx.requests, [])
        self.assertEqual(run.code, 2)
        self.assertIn("recipient certificate in this script expired", run.stderr)


RUNNER = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location("wc", sys.argv[1])
wc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wc)
sys.exit(wc.main(sys.argv[4:], prompt=lambda _: sys.argv[2], ask=lambda _: "",
                 wazuh_dir=sys.argv[3]))
"""


class KilledRun(Base):
    def test_killed_run_leaves_the_partial_zip_and_the_log(self):
        with self.indexer(per_agent=500) as fake:
            fake.faults.hold_after_pages = 1
            env = dict(os.environ, no_proxy="*")
            proc = subprocess.Popen(
                [sys.executable, "-c", RUNNER, SCRIPT, PASSWORD, self.root, "--url", fake.url,
                 "--ca-file", CERTS["ca"], "--user", USER, "--out-dir", self.out,
                 "--page-size", "1000"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            try:
                self.assertTrue(fake.held.wait(60), "the run never reached the second page")
                proc.kill()
                proc.wait(30)
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.stdout.close()
                proc.stderr.close()
        files = sorted(os.listdir(self.out))
        self.assertEqual(len(files), 2, files)
        self.assertTrue(files[0].endswith(".log") and files[1].endswith(".zip.partial"), files)
        with open(os.path.join(self.out, files[0]), encoding="utf-8") as fh:
            log = fh.read()
        self.assertIn("snapshot total 1500", log)
        self.assertNotIn(PASSWORD, log)


class TlsSettings(Base):
    def test_tls_below_1_2_refused(self):
        context = WC.tls_context(CERTS["ca"])
        if hasattr(ssl, "TLSVersion"):
            self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        else:
            self.assertTrue(context.options & ssl.OP_NO_TLSv1)
            self.assertTrue(context.options & ssl.OP_NO_TLSv1_1)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_upload_context_verifies(self):
        context, source = WC.upload_context(CERTS["ca"])
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(source, CERTS["ca"])


class Proxy(Base):
    def test_proxy_honoured_and_logged(self):
        with self.indexer() as fake, fi.ConnectProxy() as proxy:
            os.environ.pop("no_proxy")
            os.environ["https_proxy"] = proxy.url
            run = self.collect(extra=["--url", fake.url, "--ca-file", CERTS["ca"]], send=None)
        self.assertEqual(run.code, 0, run.stderr)
        self.assertTrue(proxy.connects)
        self.assertEqual(run.manifest()["proxy"], proxy.url)
        self.assertIn("indexer proxy: " + proxy.url, run.stderr)

    def test_intercepting_proxy_fails_verification(self):
        with self.indexer() as fake, fi.ConnectProxy(rogue_cert=CERTS["rogue"]) as proxy:
            os.environ.pop("no_proxy")
            os.environ["https_proxy"] = proxy.url
            run = self.collect(extra=["--url", fake.url, "--ca-file", CERTS["ca"]], send=None)
            reached = list(fake.requests)
        self.assertEqual(run.code, 2)
        self.assertIn("did not verify against the CA file", run.stderr)
        self.assertEqual(reached, [])
        self.assertNoSecret(run)


if __name__ == "__main__":
    unittest.main(verbosity=2)
