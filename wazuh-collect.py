#!/usr/bin/env python3
"""Collect a Wazuh manager's vulnerability evidence, package it, and send it to 4am Labs.

Run it as root on each Wazuh manager node, with the manager's own Python:

    /var/ossec/framework/python/bin/python3 -I wazuh-collect.py --send TOKEN \\
        [--user NAME] [--url https://INDEXER:9200] [--ca-file CA.pem] [--out-dir DIR]

TOKEN is the upload token that came with this script. It is good for one upload, to the one
address below, until it expires. Without --send the package is made and left on this host, and
nothing is sent anywhere.

What it reads
-------------

When this host is a Wazuh manager (it has the wazuh-db socket /var/ossec/queue/db/wdb):

    /var/ossec/etc/ossec.conf
        From the <cluster> block: name, node_name, node_type and disabled, nothing else (never
        its key). From the <indexer> block: the first <host> and the first <ca>, used as --url
        and --ca-file when those are not given, nothing else. The <vulnerability-detection>
        block, copied as it stands.
    /var/ossec/VERSION.json
        The manager's version.
    /var/ossec/logs/ossec.log and the rotated logs under /var/ossec/logs/ossec/
        Only the lines the vulnerability scanner wrote (those carrying
        "wazuh-modulesd:vulnerability-scanner"): feed updates and scans.
    wazuh-db, through its socket, with the fixed SELECT statements in WDB_STATEMENTS below and
    nothing else:
        On the master or a standalone manager, the agent table: each agent's id, name,
        addresses, OS fields, agent version, manager and node, registration time, last
        keep-alive, connection status, disconnection time and groups. Never the agent's key.
        For every agent database on this node: its sync_info table (when each inventory
        component last synchronised with the manager), and the newest scan_time and the row
        count of its OS, packages, hotfixes, hardware and network interface tables. No rows of
        those tables.

On the master, a standalone manager, or a host that is not a manager: every document of six
index patterns of the Wazuh indexer, through the read requests in ALLOWED_REQUESTS below and
nothing else:

    wazuh-states-vulnerabilities-*        wazuh-states-inventory-system-*
    wazuh-states-inventory-packages-*     wazuh-states-inventory-hotfixes-*
    wazuh-states-inventory-networks-*     wazuh-states-inventory-hardware-*

A worker node (cluster enabled, node_type worker) reads only its own agent databases and does
not contact the indexer; the master's run covers the rest. Run the same command on every node.

The indexer password is asked for at a hidden prompt and held in memory for the run only. It is
never written to the terminal, the log or any file.

What it writes, in --out-dir (default: the current directory), each file readable by root only
----------------------------------------------------------------------------------------------

    wazuh-collect-<node>-<time>.zip        the package (-INCOMPLETE.zip if anything did not
                                           reconcile or a run stopped), holding:
        wazuh-states.csv                   every indexer document, one row each, the columns
                                           _index, _id and _source.<field> for every field in
                                           the six mappings; a data set's rows leave the other
                                           data sets' columns empty
        manager/node.json                  this node: host name, clock, cluster role, version
        manager/agents.json                the agent table columns above (master, standalone)
        manager/sync_info.json             sync_info per agent database on this node
        manager/scan_times.json            newest scan_time and row count per table and agent
        manager/vulnerability-detection.conf    the ossec.conf block named above
        manager/vulnerability-scanner.log  the scanner's log lines, each with its file
        manifest.json                      per item: rows, reconciliation, SHA-256; the script's
                                           version and SHA-256; node, clocks, start and end
        collect.log                        this run's log up to packaging
    wazuh-collect-<node>-<time>.zip.p7m    the same package encrypted (CMS, AES-256; AES-128 on
                                           Wazuh 4.10 to 4.13, whose library offers no other) to
                                           4am Labs' certificate, RECIPIENT_CERTIFICATE below;
                                           this file, and only this file, is what is sent
    wazuh-collect-<node>-<time>.log        the whole run's log, including the upload

Nothing is deleted afterwards, so that what was sent can be checked. The last lines printed give
each file's path and SHA-256 and the command that removes them.

What it sends
-------------

With --send, and only once the package is complete or marked INCOMPLETE (never after a stopping
error, so that a mistyped password does not use up the token), one request:

    PUT https://upload.4amlabs.com/v1/upload      (UPLOAD_URL)
    body: the .p7m file; headers: the token, the body's length and SHA-256, its file name, and
    the script's name and version (User-Agent, also sent to the indexer)

It refuses redirects, verifies the receiver's certificate, and checks that the receipt names the
same length and SHA-256. It never retries by itself. A package over 95,000,000 bytes is not sent;
the script says so and names the file to return to 4am Labs another way. Where the package
cannot be encrypted (see the last paragraph), nothing is sent either.

How it behaves
--------------

- It only reads. Every wazuh-db statement and every indexer request is checked against its fixed
  list before it is sent, and anything else stops the run before the socket opens. The one
  indexer DELETE releases the search context this run opened; it changes no data.
- It verifies the indexer's certificate against the CA file, including the host name, and has no
  option to switch verification off. Redirects are refused. It uses the proxy settings Python
  finds in the environment (HTTPS_PROXY, NO_PROXY) and logs which proxy, if any, was used.
- It reconciles. For each index pattern the rows written must equal the total the indexer
  reports for the same snapshot, and every (_index, _id) must be distinct; counts taken before
  and after are noted if they moved. For each wazuh-db table the rows read must equal its count.
  wazuh-db cuts answers over 65,536 bytes short without saying so, so tables are read in pages
  small enough to arrive whole, and an answer that reaches the limit is read again in smaller
  pages.
- Exit status: 0 when everything was collected, reconciled and (with --send) sent; 1 when an
  item did not reconcile (the package is marked INCOMPLETE and still sent); 2 when a usage,
  connection, certificate, authentication, encryption or upload error stopped it.

Do not open the CSV in a spreadsheet program before sending it: its values come from the
monitored devices, and a spreadsheet can treat some values as formulas.

Python 3.6 or later. Standard library only, plus the cryptography library that the Wazuh
manager installs for its own Python, used for the encryption alone. On Wazuh 4.8 and 4.9 that
library has no CMS encryption, so the script runs the host's openssl to encrypt instead
(openssl cms -encrypt -aes256, the package on standard input), first writing the certificate to
a temporary directory readable by root only and removing it afterwards. It runs no other
program. Where openssl is also missing, nothing is sent.
"""

import argparse
import base64
import csv
import datetime
import getpass
import gzip
import hashlib
import http.client
import io
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

VERSION = "1.0.0"
# Sent with every request. Cloudflare, in front of the receiver, refuses urllib's default.
USER_AGENT = "wazuh-collect/" + VERSION

WAZUH_DIR = "/var/ossec"
UPLOAD_URL = "https://upload.4amlabs.com/v1/upload"
MAX_UPLOAD_BYTES = 95000000

# 4am Labs' recipient certificate (PEM). The package is encrypted to it, and only the holder of
# its private key can read what is sent. RSA 3072, valid 2026-10-22 to 2028-10-21, SHA-256
# fingerprint 06:EA:00:D7:4F:15:E6:A2:2A:F1:8B:1A:BE:E8:26:07:86:78:30:33:E0:20:18:1E:03:C5:33:FB:
# 47:4E:77:AB.
RECIPIENT_CERTIFICATE = """\
-----BEGIN CERTIFICATE-----
MIIEPDCCAqSgAwIBAgIUKoQzKYuKnFZHu+BLMMEgP9X+NUEwDQYJKoZIhvcNAQEL
BQAwPjERMA8GA1UECgwINGFtIExhYnMxKTAnBgNVBAMMIDRhbSBMYWJzIHdhenVo
LWNvbGxlY3QgcmVjaXBpZW50MB4XDTI2MTAyMjA4MjQ0N1oXDTI4MTAyMTA4MjQ0
N1owPjERMA8GA1UECgwINGFtIExhYnMxKTAnBgNVBAMMIDRhbSBMYWJzIHdhenVo
LWNvbGxlY3QgcmVjaXBpZW50MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKC
AYEApMH8G7aGH/TWxt+DGwqf9DRdOp2XBO5CaRSmnE1qlHAR/tThzQFtMa1Yq0sC
C1HI3uZYz3BBxt75x2DLygMDBsIqMpw/HbajpCj5qfiTBsWjWGrpXGXMe9MohcB1
ITWfNHUWG42YU5y9af8nqqOq5LgQXOi6F6bCYFv6usfXais+T1w0/NSktBDZHJYH
tmPvNKhvrqZiKqTiziohazImVFj5HRexMbvKFe/xofWYGVqKUZtgbIsJEm1iYKUU
BFHsw+fEDU3YHJXfeTCOQWS73zrrGYBMuA+Fbg1ywhp7VL5low33Il0SmeB8GTtO
LVjZzsxB490teM4Z/iWoKr7Im8pdrvBenJQUumP8V+HrPsq4S/BwogrK12oCQYAq
OesNLWflc1cn9WSE5uvVd+rX0kwdu4FKRP9mwV1RSBJxX2qe08+51FOqA7z03BLi
LlzlIIAGCFK3IojBmzDRsVPoXOo+V4qv2rFRNXtKWeq7w4X0CQwls99hJvXYRa37
NAOjAgMBAAGjMjAwMB0GA1UdDgQWBBSPWYKWlJVbE37pdQjUGewbIa/QpzAPBgNV
HRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBgQAEQqWD4vM9C89s4kHsO5je
bjbrv4zgYNsf9rdYK5H5soF/6CYAOLNWsnYaAolEy4qMsLbNLGFvQd+2spQUHRdl
e/6XIuMqd1jNrur7CR6zaHsvPPKftZZfJrP1dMyQSYFdFSG1WYlsXuGDukDJQ+JT
pEI0vESTVVK6SvQIe9sTarMGS1JMuEyGDftj+RSmI6hn8vARI/pGLVitaZhgVdKm
DubZB/vSC0W7hdyt8pdI6QKztlGeH60oun3zC3kvcp4FAc6oF2CcH61eSIf+4dnW
7GWvZBbLH8RPqZj96jtuJ7uuQbriJWo/InJY2hd9PE4k2lJ6ezZBjX22YBqHofaU
IhssU7Owtjj5eM1M8OhYUwwfnylsdDFRf/rTxRaMhD1BuL5A7kmaJ3PKBJkD5NGn
ZJKAqTMtDEWoB7meMlS1B7RDyXSMhg4vTl/BUV0T6UQBCFT3iIQbxo5WXWu6CLSS
p/LKEzr26onFtrvBQ34UALozqpn4utk4b0AgW2M6mME=
-----END CERTIFICATE-----
"""

PATTERNS = (
    ("vulnerabilities", "wazuh-states-vulnerabilities-*"),
    ("inventory-packages", "wazuh-states-inventory-packages-*"),
    ("inventory-networks", "wazuh-states-inventory-networks-*"),
    ("inventory-system", "wazuh-states-inventory-system-*"),
    ("inventory-hotfixes", "wazuh-states-inventory-hotfixes-*"),
    ("inventory-hardware", "wazuh-states-inventory-hardware-*"),
)
# A pattern matching no index leaves the package INCOMPLETE only for these; the other four
# indices may not exist on a manager whose agents report no such inventory.
REQUIRED_PATTERNS = ("wazuh-states-vulnerabilities-*", "wazuh-states-inventory-packages-*")
CSV_ENTRY = "wazuh-states.csv"
SOURCE_PREFIX = "_source."
KEEP_ALIVE = "1m"
DEFAULT_PAGE_SIZE = 1000
TIMEOUT_SECONDS = 120
UPLOAD_TIMEOUT_SECONDS = 600
PROGRESS_EVERY_PAGES = 10

SCANNER_LOG_TAG = "wazuh-modulesd:vulnerability-scanner"
ROTATED_LOG = re.compile(r"^ossec-\d+(?:-\d+)?\.log(?:\.gz)?$")
AGENT_DB = re.compile(r"^(\d{3,})\.db$")
TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$")

EXIT_COMPLETE = 0
EXIT_INCOMPLETE = 1
EXIT_ERROR = 2


class UsageError(Exception):
    """Bad arguments or setup: reported before anything is contacted or written."""


class CollectError(Exception):
    """Anything that stops the run once it has started."""


class NotEncrypted(Exception):
    """This Python cannot encrypt the package, so it is not sent."""


# -- wazuh-db ------------------------------------------------------------------------------------

# wazuh-db writes each answer into a buffer of this size (OS_MAXSTR) and cuts it short silently.
WDB_MAX_REPLY = 65536
WDB_PAGE = 200
WDB_TIMEOUT_SECONDS = 60

AGENT_COLUMNS = ("id", "name", "ip", "register_ip", "os_name", "os_version", "os_major",
                 "os_minor", "os_codename", "os_build", "os_platform", "os_uname", "os_arch",
                 "version", "manager_host", "node_name", "date_add", "last_keepalive",
                 "connection_status", "disconnection_time", "`group`")
SYNC_COLUMNS = ("component", "last_attempt", "last_completion", "n_attempts", "n_completions",
                "last_manager_checksum", "last_agent_checksum")
SCAN_TABLES = ("sys_osinfo", "sys_programs", "sys_hotfixes", "sys_hwinfo", "sys_netiface")

GLOBAL_COUNT = "global sql SELECT COUNT(*) AS n FROM agent"
GLOBAL_PAGE = ("global sql SELECT " + ", ".join(AGENT_COLUMNS)
               + " FROM agent ORDER BY id LIMIT {limit} OFFSET {offset}")
SYNC_COUNT = "agent {agent} sql SELECT COUNT(*) AS n FROM sync_info"
SYNC_PAGE = ("agent {agent} sql SELECT " + ", ".join(SYNC_COLUMNS)
             + " FROM sync_info ORDER BY component LIMIT {limit} OFFSET {offset}")
SCAN_TIME = "agent {agent} sql SELECT MAX(scan_time) AS max_scan_time, COUNT(*) AS n FROM {table}"

# Every statement this script sends to wazuh-db. Nothing else is ever sent.
WDB_STATEMENTS = (GLOBAL_COUNT, GLOBAL_PAGE, SYNC_COUNT, SYNC_PAGE, SCAN_TIME)

_PLACEHOLDERS = {
    "agent": "[0-9]{3,}",
    "limit": "[1-9][0-9]*",
    "offset": "[0-9]+",
    "table": "(?:%s)" % "|".join(SCAN_TABLES),
}


def _statement_rx(template):
    rx = re.escape(template)
    for name, value in _PLACEHOLDERS.items():
        rx = rx.replace(re.escape("{%s}" % name), value)
    return re.compile("^%s$" % rx)


_WDB_ALLOWED = tuple(_statement_rx(t) for t in WDB_STATEMENTS)


def check_sql(command):
    for rx in _WDB_ALLOWED:
        if rx.match(command):
            return
    raise CollectError("refused to send %r to wazuh-db: it is not one of the read statements "
                       "this script makes" % command)


class _TooBig(Exception):
    """wazuh-db's answer reached its buffer size, so it may have been cut short."""


def _recv_exact(sock, size):
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(min(65536, size - len(buf)))
        if not chunk:
            raise CollectError("wazuh-db closed the connection after %d of %d bytes"
                               % (len(buf), size))
        buf.extend(chunk)
    return bytes(buf)


def wdb_query(socket_path, command):
    """Send one allowed statement and return wazuh-db's rows."""
    check_sql(command)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(WDB_TIMEOUT_SECONDS)
    try:
        sock.connect(socket_path)
        data = command.encode("utf-8")
        sock.sendall(struct.pack("<I", len(data)) + data)
        size = struct.unpack("<I", _recv_exact(sock, 4))[0]
        reply = _recv_exact(sock, size)
    except (OSError, socket.timeout) as exc:
        raise CollectError("wazuh-db (%s): %r: %s" % (socket_path, command, exc))
    finally:
        sock.close()
    if size >= WDB_MAX_REPLY:
        raise _TooBig()
    text = reply.decode("utf-8", "replace")
    status, _, payload = text.partition(" ")
    if status != "ok":
        raise CollectError("wazuh-db answered %r to %r" % (text[:2000], command))
    try:
        rows = json.loads(payload) if payload else []
    except ValueError as exc:
        raise CollectError("wazuh-db's answer to %r is not JSON (%s): %s"
                           % (command, exc, payload[:2000]))
    if not isinstance(rows, list):
        raise CollectError("wazuh-db's answer to %r is not a list of rows: %s"
                           % (command, payload[:2000]))
    return rows


def _count(socket_path, command):
    rows = wdb_query(socket_path, command)
    if len(rows) != 1 or not isinstance(rows[0].get("n"), (int, float)):
        raise CollectError("wazuh-db gave no count for %r: %s" % (command, rows))
    return int(rows[0]["n"])


def read_table(socket_path, count_command, page_template, key, log, **fields):
    """Every row of one table, in pages that arrive whole. Returns a manifest entry and rows."""
    result = {"count_before": None, "rows": 0, "distinct": 0, "count_after": None,
              "reconciled": False, "notes": []}
    total = result["count_before"] = _count(socket_path, count_command.format(**fields))
    rows, offset, limit = [], 0, WDB_PAGE
    while offset < total:
        command = page_template.format(limit=limit, offset=offset, **fields)
        try:
            page = wdb_query(socket_path, command)
        except _TooBig:
            if limit == 1:
                raise CollectError("one row of %r is longer than wazuh-db's %d-byte answer, "
                                   "so it cannot be read whole" % (command, WDB_MAX_REPLY))
            limit = max(1, limit // 2)
            log("wazuh-db: an answer reached %d bytes; reading %d rows at a time"
                % (WDB_MAX_REPLY, limit))
            continue
        if not page:
            break
        rows.extend(page)
        offset += len(page)
    result["count_after"] = _count(socket_path, count_command.format(**fields))
    result["rows"] = len(rows)
    result["distinct"] = len({str(r.get(key)) for r in rows})
    problems = []
    if len(rows) != total:
        problems.append("%d rows read but the count is %d" % (len(rows), total))
    if result["distinct"] != len(rows):
        problems.append("%d rows read but only %d distinct %s values"
                        % (len(rows), result["distinct"], key))
    result["reconciled"] = not problems
    result["notes"].extend(problems)
    if result["count_after"] != total:
        result["notes"].append("count moved during the read: before %d, after %d"
                               % (total, result["count_after"]))
    return result, rows


# -- ossec.conf, version and log -----------------------------------------------------------------


def _strip_comments(text):
    return re.sub(r"<!--.*?-->", "", text, flags=re.S)


def _blocks(text, tag):
    return re.findall(r"<%s>(.*?)</%s>" % (tag, tag), text, flags=re.S)


def _value(block, tag):
    match = re.search(r"<%s>\s*(.*?)\s*</%s>" % (tag, tag), block, flags=re.S)
    return match.group(1) if match else None


def read_config(wazuh_dir):
    """What this script takes from ossec.conf, and nothing else from it."""
    path = os.path.join(wazuh_dir, "etc", "ossec.conf")
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = _strip_comments(fh.read())
    config = {"cluster": None, "cluster_blocks": 0, "role": "standalone",
              "indexer_host": None, "indexer_ca": None, "vulnerability_detection": ""}
    clusters = _blocks(text, "cluster")
    config["cluster_blocks"] = len(clusters)
    if clusters:
        block = clusters[-1]
        cluster = {k: _value(block, k) for k in ("name", "node_name", "node_type", "disabled")}
        config["cluster"] = cluster
        if (cluster["disabled"] or "no").lower() != "yes":
            node_type = (cluster["node_type"] or "").lower()
            if node_type not in ("master", "worker"):
                raise UsageError("%s: the <cluster> block is enabled but its node_type is %r, "
                                 "neither master nor worker" % (path, cluster["node_type"]))
            config["role"] = node_type
    for block in _blocks(text, "indexer"):
        hosts = _blocks(block, "hosts")
        if hosts and config["indexer_host"] is None:
            config["indexer_host"] = _value(hosts[0], "host")
        authorities = _blocks(block, "certificate_authorities")
        if authorities and config["indexer_ca"] is None:
            config["indexer_ca"] = _value(authorities[0], "ca")
    config["vulnerability_detection"] = "\n".join(
        m.strip() for m in re.findall(r"<vulnerability-detection>.*?</vulnerability-detection>",
                                      text, flags=re.S))
    return config


def read_version(wazuh_dir):
    path = os.path.join(wazuh_dir, "VERSION.json")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return {"version": data.get("version"), "stage": data.get("stage")}, None
    except (OSError, ValueError) as exc:
        return {"version": None, "stage": None}, "%s: %s" % (path, exc)


def scanner_log_files(wazuh_dir):
    """ossec.log, then the rotated logs in date order of their directories and names."""
    logs = os.path.join(wazuh_dir, "logs")
    found = [os.path.join(logs, "ossec.log")]
    rotated = []
    for root, dirs, files in os.walk(os.path.join(logs, "ossec")):
        dirs.sort()
        for name in sorted(files):
            if ROTATED_LOG.match(name):
                rotated.append(os.path.join(root, name))
    return sorted(rotated) + found


# -- indexer -------------------------------------------------------------------------------------


def _quote(pattern):
    return urllib.parse.quote(pattern, safe="*-_.")


_PATTERN_ALTERNATIVES = "|".join(re.escape(_quote(p)) for _, p in PATTERNS)

# (method, path, the exact set of query parameters). Nothing else is ever sent to the indexer.
ALLOWED_REQUESTS = (
    ("GET", re.compile(r"^/$"), frozenset()),
    ("GET", re.compile(r"^/(?:%s)/_mapping$" % _PATTERN_ALTERNATIVES), frozenset()),
    ("GET", re.compile(r"^/(?:%s)/_count$" % _PATTERN_ALTERNATIVES), frozenset()),
    ("POST", re.compile(r"^/(?:%s)/_search$" % _PATTERN_ALTERNATIVES), frozenset({"scroll"})),
    ("POST", re.compile(r"^/_search/scroll$"), frozenset()),
    ("DELETE", re.compile(r"^/_search/scroll$"), frozenset()),
)


def check_allowed(method, path, query):
    for allowed_method, path_rx, query_keys in ALLOWED_REQUESTS:
        if method == allowed_method and path_rx.match(path) and set(query) == query_keys:
            return
    raise CollectError("refused to send %s %s %s: it is not one of the read requests this "
                       "script makes" % (method, path, sorted(query)))


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def open_private(path, mode):
    """Create a new file readable by its owner only; refuse to replace an existing one."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if "b" in mode:
        flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    if "b" in mode:
        return os.fdopen(fd, mode)
    return os.fdopen(fd, mode, encoding="utf-8", newline="\n")


class Log:
    """Writes each line to the terminal and to the side log as it happens."""

    def __init__(self, path):
        self.path = path
        self._fh = open_private(path, "w")

    def __call__(self, message):
        line = "%s %s" % (iso(utc_now()), message)
        print(line, file=sys.stderr, flush=True)
        if self._fh is not None:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self):
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def tls_context(ca_file):
    context = ssl.create_default_context(cafile=ca_file)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:  # Python 3.6
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    return context


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CollectError("%s answered %s %s with a redirect to %s; redirects are refused so "
                           "that credentials and data are only ever sent to the address given"
                           % (urllib.parse.urlsplit(req.full_url).netloc, req.get_method(),
                              urllib.parse.urlsplit(req.full_url).path, newurl))


def proxy_in_use(base_url):
    """The proxy urllib will use for this URL, without any credentials in it, or None."""
    host = urllib.parse.urlsplit(base_url).hostname
    proxy = urllib.request.getproxies().get("https")
    if not proxy or urllib.request.proxy_bypass(host):
        return None
    parts = urllib.parse.urlsplit(proxy if "://" in proxy else "http://" + proxy)
    netloc = parts.hostname or ""
    if parts.port:
        netloc += ":%d" % parts.port
    return "%s://%s" % (parts.scheme, netloc)


def _opener(context):
    return urllib.request.build_opener(urllib.request.ProxyHandler(),
                                       urllib.request.HTTPSHandler(context=context),
                                       _RefuseRedirect())


class Indexer:
    def __init__(self, base_url, ca_file, user, password, timeout=TIMEOUT_SECONDS):
        self.base_url = base_url
        self.timeout = timeout
        token = base64.b64encode(("%s:%s" % (user, password)).encode("utf-8")).decode("ascii")
        self._authorization = "Basic " + token
        self._opener = _opener(tls_context(ca_file))

    def request(self, method, path, query=None, body=None, tolerate=()):
        """Send one allowed request. Returns (status, parsed JSON or None)."""
        query = query or {}
        check_allowed(method, path, query)
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", self._authorization)
        req.add_header("User-Agent", USER_AGENT)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        what = "%s %s" % (method, path)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                status, raw = resp.getcode(), resp.read()
        except urllib.error.HTTPError as exc:
            try:
                text = exc.read().decode("utf-8", "replace")
            finally:
                exc.close()
            if exc.code in tolerate:
                return exc.code, text
            raise CollectError(_describe_status(what, exc.code, text))
        except urllib.error.URLError as exc:
            raise CollectError(_describe_unreachable(what, exc.reason))
        except (ssl.SSLError, ssl.CertificateError, socket.timeout, OSError) as exc:
            # On Python 3.6 a host name mismatch raises ssl.CertificateError, a ValueError.
            raise CollectError(_describe_unreachable(what, exc))
        try:
            return status, json.loads(raw.decode("utf-8"))
        except ValueError as exc:
            raise CollectError("%s: the indexer's answer is not JSON (%s): %s"
                               % (what, exc, raw[:2000].decode("utf-8", "replace")))

    def version(self):
        status, body = self.request("GET", "/", tolerate=(401, 403))
        if status != 200:
            return None, "HTTP %s: %s" % (status, body)
        return (body.get("version") or {}).get("number"), None

    def count(self, pattern):
        _, body = self.request("GET", "/%s/_count" % _quote(pattern))
        return int(body["count"])

    def mapping(self, pattern):
        _, body = self.request("GET", "/%s/_mapping" % _quote(pattern))
        return body

    def first_page(self, pattern, size):
        _, body = self.request(
            "POST", "/%s/_search" % _quote(pattern), query={"scroll": KEEP_ALIVE},
            body={"size": size, "sort": ["_doc"], "track_total_hits": True,
                  "query": {"match_all": {}}})
        return body

    def next_page(self, scroll_id):
        _, body = self.request("POST", "/_search/scroll",
                               body={"scroll": KEEP_ALIVE, "scroll_id": scroll_id})
        return body

    def free(self, scroll_id):
        return self.request("DELETE", "/_search/scroll", body={"scroll_id": [scroll_id]},
                            tolerate=(404,))


def _describe_status(what, code, text):
    hint = {
        401: " The username or password was not accepted.",
        403: " The account is not permitted to do this; it needs read access to the six index "
             "patterns.",
    }.get(code, "")
    return "%s: the indexer answered HTTP %s.%s Response: %s" % (what, code, hint, text)


def _describe_unreachable(what, reason):
    text = str(reason)
    hint = ""
    if (isinstance(reason, ssl.CertificateError) or "CERTIFICATE_VERIFY_FAILED" in text
            or "certificate verify failed" in text):
        hint = (" The certificate did not verify against the CA file given, or does not name "
                "the host used; give --url with an address the certificate names.")
    return "%s: could not complete the request: %s.%s" % (what, text, hint)


def leaf_fields(properties, prefix=""):
    for name, spec in properties.items():
        full = prefix + name
        if isinstance(spec, dict) and "properties" in spec:
            for leaf in leaf_fields(spec["properties"], full + "."):
                yield leaf
        else:
            yield full


def cell(value):
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return json.dumps(value)
    raise CollectError("unexpected value type %s" % type(value).__name__)


def flatten(source, prefix="", out=None):
    """Document fields as {dotted name: text}. Arrays of objects are refused, not guessed at."""
    out = {} if out is None else out
    for key, value in source.items():
        name = prefix + key
        if isinstance(value, dict):
            flatten(value, name + ".", out)
            continue
        if isinstance(value, list):
            if any(isinstance(item, (dict, list)) for item in value):
                raise CollectError("field %s holds a list of objects, which cannot be written "
                                   "as one column without guessing; nothing was flattened"
                                   % name)
            text = ", ".join(cell(item) for item in value)
        else:
            text = cell(value)
        if name in out:
            raise CollectError("field %s appears twice in one document" % name)
        out[name] = text
    return out


def _csv_line(values):
    buf = io.StringIO()
    csv.writer(buf).writerow(values)
    return buf.getvalue().encode("utf-8")


def _total(body):
    total = body["hits"]["total"]
    if isinstance(total, int):
        return total
    if total.get("relation") != "eq":
        raise CollectError("the indexer gave the total as a lower bound (%s), not an exact "
                           "count" % total)
    return int(total["value"])


def survey_pattern(indexer, pattern, log):
    """Count and mapping for one pattern. Returns (manifest entry, its fields)."""
    result = {"pattern": pattern, "indices": [], "count_before": None, "snapshot_total": None,
              "rows_written": 0, "distinct_ids": 0, "count_after": None, "sha256": None,
              "reconciled": False, "notes": []}
    log("%s: counting documents" % pattern)
    result["count_before"] = indexer.count(pattern)
    mapping = indexer.mapping(pattern)
    result["indices"] = sorted(mapping)
    fields = set()
    for index_mapping in mapping.values():
        properties = (index_mapping.get("mappings") or {}).get("properties") or {}
        fields.update(leaf_fields(properties))
    log("%s: %d indices, %d fields, %d documents counted" % (
        pattern, len(result["indices"]), len(fields), result["count_before"]))
    return result, fields


def export_pattern(indexer, result, fields, columns, entry, page_size, log):
    """Append one pattern's documents to the combined CSV and reconcile them."""
    pattern = result["pattern"]
    if not result["indices"]:
        result["count_after"] = indexer.count(pattern)
        if pattern in REQUIRED_PATTERNS:
            result["notes"].append("no index matches this pattern")
            log("%s: NO INDEX MATCHES THIS PATTERN; nothing to export" % pattern)
        else:
            result["reconciled"] = True
            result["notes"].append("no index matches this pattern; the agents report no such "
                                   "inventory")
            log("%s: no index matches this pattern; noted" % pattern)
        return result
    digest = hashlib.sha256()
    ids = set()
    rows = 0
    scroll_id = None
    try:
        body = indexer.first_page(pattern, page_size)
        scroll_id = body.get("_scroll_id")
        result["snapshot_total"] = _total(body)
        log("%s: snapshot total %d" % (pattern, result["snapshot_total"]))
        pages = 0
        while True:
            hits = body["hits"]["hits"]
            if not hits:
                break
            for hit in hits:
                values = flatten(hit.get("_source") or {})
                unknown = sorted(set(values) - fields)
                if unknown:
                    raise CollectError(
                        "field %s is in a document but not in the index mapping; refusing to "
                        "guess a column for it" % unknown[0])
                line = _csv_line([hit["_index"], hit["_id"]]
                                 + [values.get(c, "") for c in columns])
                entry.write(line)
                digest.update(line)
                ids.add((hit["_index"], hit["_id"]))
            rows += len(hits)
            pages += 1
            if pages % PROGRESS_EVERY_PAGES == 0:
                log("%s: %d of %d rows" % (pattern, rows, result["snapshot_total"]))
            body = indexer.next_page(scroll_id)
            scroll_id = body.get("_scroll_id") or scroll_id
    finally:
        result["rows_written"] = rows
        result["distinct_ids"] = len(ids)
        result["sha256"] = digest.hexdigest()
        if scroll_id:
            try:
                status, answer = indexer.free(scroll_id)
                if status != 200:
                    log("%s: the search context was already gone when released (HTTP %s): %s"
                        % (pattern, status, answer))
            except CollectError as exc:
                log("%s: WARNING: could not release the search context; it expires by itself "
                    "after %s: %s" % (pattern, KEEP_ALIVE, exc))

    result["count_after"] = indexer.count(pattern)
    total = result["snapshot_total"]
    problems = []
    if rows != total:
        problems.append("%d rows written but the snapshot total is %d" % (rows, total))
    if len(ids) != rows:
        problems.append("%d rows written but only %d distinct document ids" % (rows, len(ids)))
    result["reconciled"] = not problems
    result["notes"].extend(problems)
    if result["count_before"] != total or result["count_after"] != total:
        note = ("counts moved during the run: before %d, snapshot %d, after %d"
                % (result["count_before"], total, result["count_after"]))
        result["notes"].append(note)
        log("%s: note: %s" % (pattern, note))
    if problems:
        log("%s: DID NOT RECONCILE: %s" % (pattern, "; ".join(problems)))
    else:
        log("%s: reconciled, %d rows" % (pattern, rows))
    return result


def collect_indexer(indexer, zf, page_size, manifest, log):
    """Every document of the six patterns, as one CSV in the Reporting CSV's column form."""
    surveyed = [survey_pattern(indexer, pattern, log) for _, pattern in PATTERNS]
    columns = sorted(set().union(*(fields for _, fields in surveyed)))
    header = _csv_line(["_index", "_id"] + [SOURCE_PREFIX + c for c in columns])
    digest = hashlib.sha256(header)
    with zf.open(CSV_ENTRY, "w", force_zip64=True) as entry:
        entry.write(header)
        for result, fields in surveyed:
            manifest["patterns"].append(result)
            export_pattern(indexer, result, fields, columns,
                           _Tee(entry, digest), page_size, log)
    manifest["items"].append({"entry": CSV_ENTRY, "columns": len(columns) + 2,
                              "rows": sum(r["rows_written"] for r, _ in surveyed),
                              "sha256": digest.hexdigest(),
                              "reconciled": all(r["reconciled"] for r, _ in surveyed),
                              "notes": []})


class _Tee:
    """Writes to a zip entry and a running digest together."""

    def __init__(self, entry, digest):
        self.entry, self.digest = entry, digest

    def write(self, data):
        self.entry.write(data)
        self.digest.update(data)


# -- manager part --------------------------------------------------------------------------------


def _write_json(zf, name, value, manifest, rows, reconciled, notes):
    data = (json.dumps(value, indent=1, sort_keys=True) + "\n").encode("utf-8")
    zf.writestr(name, data)
    manifest["items"].append({"entry": name, "rows": rows,
                              "sha256": hashlib.sha256(data).hexdigest(),
                              "reconciled": reconciled, "notes": notes})


def agent_ids(db_dir):
    ids = []
    for name in os.listdir(db_dir):
        match = AGENT_DB.match(name)
        if match and int(match.group(1)) != 0:
            ids.append(match.group(1))
    return sorted(ids)


def collect_manager(wazuh_dir, config, version, zf, manifest, log, hostname):
    socket_path = os.path.join(wazuh_dir, "queue", "db", "wdb")
    role = config["role"]
    started = utc_now()
    node = {"hostname": hostname, "role": role, "cluster": config["cluster"],
            "cluster_blocks": config["cluster_blocks"], "manager_version": version,
            "clock_utc": iso(started), "clock_epoch": int(started.timestamp())}
    notes = []
    if config["cluster_blocks"] > 1:
        notes.append("ossec.conf has %d <cluster> blocks; the last was read"
                     % config["cluster_blocks"])
    _write_json(zf, "manager/node.json", node, manifest, 1, True, notes)
    log("manager: node %s, role %s, Wazuh %s" % (hostname, role, version.get("version")))

    if role in ("master", "standalone"):
        log("manager: reading the agent table")
        result, rows = read_table(socket_path, GLOBAL_COUNT, GLOBAL_PAGE, "id", log)
        log("manager: agent table, %d rows%s" % (
            result["rows"], "" if result["reconciled"] else
            "; DID NOT RECONCILE: " + "; ".join(result["notes"])))
        _write_json(zf, "manager/agents.json", rows, manifest, result["rows"],
                    result["reconciled"], result["notes"])

    db_dir = os.path.join(wazuh_dir, "queue", "db")
    try:
        ids = agent_ids(db_dir)
    except OSError as exc:
        raise CollectError("listing the agent databases in %s: %s" % (db_dir, exc))
    log("manager: %d agent databases on this node" % len(ids))
    sync, scans, failures = [], [], []
    for agent in ids:
        try:
            result, rows = read_table(socket_path, SYNC_COUNT, SYNC_PAGE, "component", log,
                                      agent=agent)
            sync.append({"agent": agent, "rows": rows, "reconciled": result["reconciled"],
                         "notes": result["notes"]})
            if not result["reconciled"]:
                failures.append("agent %s sync_info: %s" % (agent, "; ".join(result["notes"])))
        except CollectError as exc:
            sync.append({"agent": agent, "rows": [], "reconciled": False, "error": str(exc)})
            failures.append("agent %s sync_info: %s" % (agent, exc))
            log("manager: agent %s sync_info: ERROR: %s" % (agent, exc))
        for table in SCAN_TABLES:
            try:
                rows = wdb_query(socket_path, SCAN_TIME.format(agent=agent, table=table))
                row = rows[0] if rows else {}
                scans.append({"agent": agent, "table": table,
                              "max_scan_time": row.get("max_scan_time"), "rows": row.get("n")})
            except (CollectError, _TooBig) as exc:
                text = str(exc) or "the answer reached wazuh-db's size limit"
                scans.append({"agent": agent, "table": table, "error": text})
                failures.append("agent %s %s: %s" % (agent, table, text))
                log("manager: agent %s %s: ERROR: %s" % (agent, table, text))
    _write_json(zf, "manager/sync_info.json", sync, manifest,
                sum(len(s["rows"]) for s in sync), not any("sync_info" in f for f in failures),
                [f for f in failures if "sync_info" in f])
    _write_json(zf, "manager/scan_times.json", scans, manifest, len(scans),
                not any("sync_info" not in f for f in failures),
                [f for f in failures if "sync_info" not in f])

    data = (config["vulnerability_detection"] + "\n").encode("utf-8")
    zf.writestr("manager/vulnerability-detection.conf", data)
    manifest["items"].append({"entry": "manager/vulnerability-detection.conf",
                              "rows": data.count(b"\n"),
                              "sha256": hashlib.sha256(data).hexdigest(), "reconciled": True,
                              "notes": [] if config["vulnerability_detection"] else
                              ["no <vulnerability-detection> block in ossec.conf"]})
    collect_scanner_log(wazuh_dir, zf, manifest, log)


def collect_scanner_log(wazuh_dir, zf, manifest, log):
    digest = hashlib.sha256()
    lines, notes = 0, []
    logs = os.path.join(wazuh_dir, "logs")
    with zf.open("manager/vulnerability-scanner.log", "w", force_zip64=True) as entry:
        for path in scanner_log_files(wazuh_dir):
            relative = os.path.relpath(path, logs)
            opener = gzip.open if path.endswith(".gz") else open
            try:
                with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if SCANNER_LOG_TAG in line:
                            data = ("%s: %s\n" % (relative, line.rstrip("\n"))).encode("utf-8")
                            entry.write(data)
                            digest.update(data)
                            lines += 1
            except (OSError, EOFError) as exc:
                notes.append("could not read %s: %s" % (path, exc))
                log("manager: could not read %s: %s" % (path, exc))
    log("manager: %d vulnerability scanner log lines" % lines)
    manifest["items"].append({"entry": "manager/vulnerability-scanner.log", "rows": lines,
                              "sha256": digest.hexdigest(), "reconciled": not notes,
                              "notes": notes})


# -- encryption and upload -----------------------------------------------------------------------


def encrypt_package(data, certificate_pem):
    """The package as CMS enveloped data (DER) for the recipient, and what it was encrypted to."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import pkcs7
    except ImportError as exc:
        raise NotEncrypted("this Python has no usable cryptography library (%s)" % exc)
    cert = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    not_after = getattr(cert, "not_valid_after_utc", None) or \
        cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    if not_after <= utc_now():
        raise CollectError("the recipient certificate in this script expired at %s; ask 4am "
                           "Labs for a current copy of the script" % iso(not_after))
    blob, cipher = envelope(data, cert, certificate_pem,
                            getattr(pkcs7, "PKCS7EnvelopeBuilder", None))
    return blob, {"recipient_sha256": cert.fingerprint(hashes.SHA256()).hex(),
                  "recipient_subject": cert.subject.rfc4514_string(),
                  "recipient_not_after": iso(not_after), "content_cipher": cipher}


def envelope(data, cert, certificate_pem, builder):
    """CMS enveloped data (DER) for the certificate, and the content cipher used.

    The manager's own library decides the route. From Wazuh 4.14 its builder lets the cipher be
    chosen, and AES-256 is asked for. From 4.10 to 4.13 the builder offers no choice, and its
    default, AES-128, is used. In 4.8 and 4.9 the library has no CMS encryption (builder is
    None), and the host's openssl encrypts to AES-256 instead."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs7
    if builder is None:
        return openssl_envelope(data, certificate_pem)
    enveloped = builder().set_data(data).add_recipient(cert)
    if hasattr(enveloped, "set_content_encryption_algorithm"):
        from cryptography.hazmat.primitives.ciphers import algorithms
        enveloped = enveloped.set_content_encryption_algorithm(algorithms.AES256)
        cipher = "aes-256-cbc"
    else:
        cipher = "aes-128-cbc"
    return enveloped.encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary]), cipher


def openssl_envelope(data, certificate_pem):
    """CMS enveloped data from the host's openssl, AES-256, and the cipher it names.

    The certificate is written to a private temporary directory for openssl to read, and removed
    with it; the package goes in on standard input and comes back on standard output."""
    openssl = shutil.which("openssl")
    if openssl is None:
        raise NotEncrypted("this Python's cryptography library has no CMS encryption, and no "
                           "openssl program was found on PATH to encrypt with instead")
    work = tempfile.mkdtemp(prefix="wazuh-collect-")
    try:
        recipient = os.path.join(work, "recipient.pem")
        with open_private(recipient, "w") as fh:
            fh.write(certificate_pem)
        proc = subprocess.run([openssl, "cms", "-encrypt", "-binary", "-aes256", "-outform",
                               "DER", recipient], input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if proc.returncode != 0 or not proc.stdout:
        raise NotEncrypted("%s cms -encrypt failed (exit %d): %s" % (
            openssl, proc.returncode,
            proc.stderr.decode("utf-8", "replace").strip() or "no message"))
    return proc.stdout, "aes-256-cbc (openssl at %s)" % openssl


SYSTEM_CA_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                     "/etc/ssl/ca-bundle.pem", "/etc/pki/ca-trust/extracted/pem/"
                     "tls-ca-bundle.pem", "/etc/ssl/cert.pem")


def upload_context(ca_file=None):
    """A verifying TLS context for the receiver, and where its CA certificates came from."""
    if ca_file is None:
        paths = ssl.get_default_verify_paths()
        if paths.cafile and os.path.isfile(paths.cafile):
            ca_file = paths.cafile
        elif paths.capath and os.path.isdir(paths.capath) and os.listdir(paths.capath):
            context = tls_context(None)
            return context, "this Python's default CA directory %s" % paths.capath
        else:
            try:
                import certifi
                ca_file = certifi.where()
            except ImportError:
                ca_file = next((p for p in SYSTEM_CA_BUNDLES if os.path.isfile(p)), None)
        if ca_file is None:
            raise CollectError("no CA certificates found to verify the receiver with: this "
                               "Python has no default CA file or directory, no certifi, and "
                               "none of %s exists" % ", ".join(SYSTEM_CA_BUNDLES))
    return tls_context(ca_file), ca_file


def check_upload(method, url):
    parts = urllib.parse.urlsplit(url)
    if (method != "PUT" or parts.scheme != "https" or parts.path != "/v1/upload"
            or parts.query or parts.fragment or parts.username or parts.password):
        raise CollectError("refused to send %s %s: it is not the one upload this script "
                           "makes" % (method, url))


class _KeepEarlyAnswer:
    """Mixed into the upload's HTTPS connection. Once the request head is out, a write error on
    the body is held back rather than raised, so an answer the receiver sent before it stopped
    reading (a refused token, say) is still read. What was sent, and the error, are kept for the
    message when no answer arrives."""
    head_sent = False
    body_sent = 0
    body_interrupted = None

    def send(self, data):
        if self.body_interrupted is not None:
            return
        if not self.head_sent:
            super().send(data)
            self.head_sent = bytes(data[:4]) == b"PUT "
            return
        try:
            super().send(data)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError) as exc:
            self.body_interrupted = exc
            return
        self.body_sent += len(data)


class _UploadHandler(urllib.request.HTTPSHandler):
    """HTTPS for the upload, keeping the connection it opens so its state can be reported."""
    connection = None

    def do_open(self, http_class, req, **kwargs):
        handler = self

        class Connection(_KeepEarlyAnswer, http_class):
            def __init__(self, *args, **kw):
                http_class.__init__(self, *args, **kw)
                handler.connection = self

        return urllib.request.HTTPSHandler.do_open(self, Connection, req, **kwargs)


def _closed_without_answer(handler, exc, total):
    """The message for a receiver that closed the connection after the request went out and sent
    no answer, or None when that is not what happened."""
    conn = handler.connection
    reason = getattr(exc, "reason", exc)
    if conn is None or not conn.head_sent or not isinstance(
            reason, (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError)):
        return None
    sent = total if conn.body_interrupted is None else conn.body_sent
    return ("upload: the receiver closed the connection without answering, after %d of %d bytes "
            "were sent (%s). The usual cause is a token it refused: already used, expired, or "
            "too small for this package. Contact 4am Labs with this run's log."
            % (sent, total, conn.body_interrupted or reason))


UPLOAD_REFUSALS = {
    401: "the token was not accepted: it is unknown or has expired. Ask 4am Labs for a new "
         "one.",
    409: "this token has already been used for an upload. Ask 4am Labs for a new one.",
    411: "the receiver needs the length of the upload.",
    413: "the package is larger than this token allows. Contact 4am Labs.",
    422: "what arrived did not match the package's SHA-256, so the receiver kept nothing. The "
         "token can be used again: run the command again.",
}


def upload(url, token, name, body, context, log):
    """Send the encrypted package in one request. Returns the receiver's receipt."""
    check_upload("PUT", url)
    sha256 = hashlib.sha256(body).hexdigest()
    req = urllib.request.Request(url, data=body, method="PUT")
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header("Content-Length", str(len(body)))
    req.add_header("X-Content-SHA256", sha256)
    req.add_header("X-Package-Name", name)
    req.add_header("Accept", "application/json")
    proxy = proxy_in_use(url)
    log("upload: PUT %s, %d bytes, SHA-256 %s, proxy %s" % (url, len(body), sha256,
                                                           proxy or "none"))
    handler = _UploadHandler(context=context)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(), handler,
                                         _RefuseRedirect())
    try:
        with opener.open(req, timeout=UPLOAD_TIMEOUT_SECONDS) as resp:
            status, raw = resp.getcode(), resp.read()
    except urllib.error.HTTPError as exc:
        try:
            text = exc.read().decode("utf-8", "replace")
        finally:
            exc.close()
        raise CollectError("upload: the receiver answered HTTP %s. %s Response: %s"
                           % (exc.code, UPLOAD_REFUSALS.get(exc.code, ""), text[:2000]))
    except urllib.error.URLError as exc:
        raise CollectError(_closed_without_answer(handler, exc, len(body))
                           or _describe_unreachable("upload", exc.reason))
    except (ssl.SSLError, ssl.CertificateError, socket.timeout, OSError) as exc:
        raise CollectError(_closed_without_answer(handler, exc, len(body))
                           or _describe_unreachable("upload", exc))
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise CollectError("upload: HTTP %s, but the receipt is not JSON (%s): %s"
                           % (status, exc, raw[:2000].decode("utf-8", "replace")))
    if not isinstance(receipt, dict) or receipt.get("sha256") != sha256 \
            or receipt.get("size") != len(body):
        raise CollectError("upload: the receipt does not match what was sent (sent %d bytes, "
                           "SHA-256 %s; receipt %s). Contact 4am Labs before running again."
                           % (len(body), sha256, receipt))
    return receipt


# -- the run -------------------------------------------------------------------------------------


def check_url(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        raise UsageError("--url must start with https:// (got %r)" % url)
    if parts.username or parts.password:
        raise UsageError("--url must not contain credentials; the script asks for them")
    if not parts.hostname:
        raise UsageError("--url has no host name: %r" % url)
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise UsageError("--url must be the indexer's address only, such as "
                         "https://127.0.0.1:9200 (got %r)" % url)
    return "https://" + parts.netloc


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        epilog="Full description: the text at the top of this file.")
    parser.add_argument("--send", metavar="TOKEN",
                        help="send the encrypted package with this upload token")
    parser.add_argument("--url", help="the Wazuh indexer, such as https://127.0.0.1:9200 "
                                      "(default: the first host in ossec.conf's <indexer>)")
    parser.add_argument("--ca-file", help="the CA certificate the indexer's certificate is "
                                          "issued from (default: the first <ca> in ossec.conf's "
                                          "<indexer>)")
    parser.add_argument("--user", help="indexer username (asked for if not given)")
    parser.add_argument("--out-dir", default=".",
                        help="where to write the package (default: the current directory)")
    parser.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE,
                        help="indexer documents per request (default %d). This changes only how "
                             "many requests are made, not what is collected." % DEFAULT_PAGE_SIZE)
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    return parser.parse_args(argv)


def script_sha256():
    with open(os.path.abspath(__file__), "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _safe_name(text):
    return re.sub(r"[^A-Za-z0-9.-]", "_", text)[:64] or "host"


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _finish(partial_path, final_path, complete, manifest, log):
    """Add the manifest and the log so far, and leave exactly one zip behind."""
    with zipfile.ZipFile(partial_path, "a") as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2) + "\n")
        zf.write(log.path, "collect.log")
    if complete:
        os.replace(partial_path, final_path)
        return
    with open_private(final_path, "wb") as out, \
            zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst, \
            zipfile.ZipFile(partial_path) as src:
        for info in src.infolist():
            name = info.filename
            if name.endswith(".csv"):
                name += ".incomplete"
            with src.open(info) as reader, dst.open(name, "w", force_zip64=True) as writer:
                shutil.copyfileobj(reader, writer)
    os.remove(partial_path)


def setup(args, wazuh_dir, token_given):
    """Everything decided before anything is written: the role and the indexer to read."""
    socket_path = os.path.join(wazuh_dir, "queue", "db", "wdb")
    plan = {"manager": os.path.exists(socket_path), "config": None, "url": None, "ca": None}
    if not os.path.isdir(args.out_dir):
        raise UsageError("--out-dir %s is not a directory" % args.out_dir)
    if args.page_size < 1:
        raise UsageError("--page-size must be at least 1")
    if token_given and not TOKEN.match(args.send):
        raise UsageError("--send needs the 43-character upload token exactly as it was given")
    if plan["manager"]:
        try:
            plan["config"] = read_config(wazuh_dir)
        except OSError as exc:
            raise UsageError("cannot read ossec.conf: %s" % exc)
    role = plan["config"]["role"] if plan["config"] else None
    plan["indexer"] = role != "worker"
    if plan["indexer"]:
        config = plan["config"] or {}
        url = args.url or config.get("indexer_host")
        ca = args.ca_file or config.get("indexer_ca")
        if not url or not ca:
            raise UsageError("give --url and --ca-file for the Wazuh indexer%s" % (
                "" if plan["manager"] else ": this host is not a Wazuh manager (no %s), so "
                "there is no ossec.conf to take them from" % socket_path))
        plan["url"] = check_url(url)
        if not os.path.isfile(ca):
            raise UsageError("the indexer CA file %s is not a readable file" % ca)
        tls_context(ca)
        plan["ca"] = ca
    return plan


def main(argv=None, prompt=getpass.getpass, ask=input, wazuh_dir=WAZUH_DIR,
         upload_url=UPLOAD_URL, upload_ca=None, recipient=None, encrypt=encrypt_package,
         hostname=None):
    args = parse_args(argv)
    recipient = RECIPIENT_CERTIFICATE if recipient is None else recipient
    try:
        if args.send is not None and not recipient:
            raise UsageError("this copy of the script carries no recipient certificate, so it "
                             "cannot send; ask 4am Labs for the current copy")
        plan = setup(args, wazuh_dir, args.send is not None)
    except (UsageError, ssl.SSLError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    user = password = None
    if plan["indexer"]:
        user = args.user or ask("Indexer username: ").strip()
        password = prompt("Password for %s: " % user)

    node = hostname or socket.gethostname()
    started = utc_now()
    stem = os.path.join(args.out_dir, "wazuh-collect-%s-%s" % (
        _safe_name(node), started.strftime("%Y%m%dT%H%M%SZ")))
    partial_path = stem + ".zip.partial"
    try:
        log = Log(stem + ".log")
        partial_fh = open_private(partial_path, "wb")
    except OSError as exc:
        print("error: cannot create the output files: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    role = plan["config"]["role"] if plan["config"] else "not a manager"
    manifest = {"script_version": VERSION, "script_sha256": script_sha256(),
                "started": iso(started), "finished": None, "node": node, "role": role,
                "indexer": plan["url"], "indexer_version": None, "proxy": None,
                "page_size": args.page_size, "result": None, "error": None, "items": [],
                "patterns": []}
    log("wazuh-collect %s on %s (%s)%s" % (VERSION, node, role, (
        ", indexer %s, user %s" % (plan["url"], user)) if plan["indexer"] else
        "; a worker node: the indexer is read by the master's run"))
    if not plan["manager"]:
        log("no wazuh-db socket at %s: not a Wazuh manager, so only the indexer is read"
            % os.path.join(wazuh_dir, "queue", "db", "wdb"))
    elif not plan["indexer"] and (args.url or args.ca_file or args.user):
        log("note: --url, --ca-file and --user are not used on a worker node")
    failure = None
    try:
        with zipfile.ZipFile(partial_fh, "w", zipfile.ZIP_DEFLATED) as zf:
            if plan["manager"]:
                version, why = read_version(wazuh_dir)
                if why:
                    log("manager: version unknown: %s" % why)
                collect_manager(wazuh_dir, plan["config"], version, zf, manifest, log, node)
            if plan["indexer"]:
                indexer = Indexer(plan["url"], plan["ca"], user, password)
                manifest["proxy"] = proxy_in_use(plan["url"])
                log("indexer proxy: %s" % (manifest["proxy"] or "none"))
                found, why = indexer.version()
                manifest["indexer_version"] = found or "unknown"
                log("indexer version: %s" % (found or "unknown (%s)" % why))
                collect_indexer(indexer, zf, args.page_size, manifest, log)
    except CollectError as exc:
        failure = str(exc)
    except KeyboardInterrupt:
        failure = "interrupted"
    finally:
        partial_fh.close()
    password = None

    patterns_done = not plan["indexer"] or len(manifest["patterns"]) == len(PATTERNS)
    complete = failure is None and patterns_done and all(
        item["reconciled"] for item in manifest["items"]) and all(
        p["reconciled"] for p in manifest["patterns"])
    manifest["error"] = failure
    manifest["result"] = "complete" if complete else "incomplete"
    manifest["finished"] = iso(utc_now())
    final_path = stem + (".zip" if complete else "-INCOMPLETE.zip")
    if failure:
        log("ERROR: %s" % failure)
    for item in manifest["items"] + manifest["patterns"]:
        if not item["reconciled"]:
            log("not reconciled: %s: %s" % (item.get("entry") or item.get("pattern"),
                                             "; ".join(item["notes"])))
    log("result: %s; writing %s" % (manifest["result"].upper(), os.path.basename(final_path)))
    try:
        _finish(partial_path, final_path, complete, manifest, log)
    except (OSError, zipfile.BadZipFile) as exc:
        log("ERROR: could not finish the zip: %s; the partial files are left as %s and %s"
            % (exc, partial_path, log.path))
        log.close()
        return EXIT_ERROR
    left = [final_path, log.path]
    log("package: %s, SHA-256 %s" % (final_path, _sha256_file(final_path)))
    code = EXIT_COMPLETE if complete else EXIT_INCOMPLETE
    if failure:
        code = EXIT_ERROR
        if args.send is not None:
            log("NOT SENT: the run stopped, so nothing was sent and the token is still unused; "
                "correct the error above and run the command again")
    elif recipient:
        try:
            code = _encrypt_and_send(args, final_path, recipient, encrypt, upload_url,
                                     upload_ca, left, log, code)
        except KeyboardInterrupt:
            log("ERROR: interrupted before the upload finished")
            code = EXIT_ERROR
    log("to remove what this run left here: rm -- %s" % " ".join(shlex.quote(p) for p in left))
    log.close()
    return code


def _encrypt_and_send(args, final_path, recipient, encrypt, upload_url, upload_ca, left, log,
                      code):
    with open(final_path, "rb") as fh:
        data = fh.read()
    try:
        blob, info = encrypt(data, recipient)
    except NotEncrypted as exc:
        log("NOT ENCRYPTED: %s. Nothing was sent; return %s to 4am Labs by another channel "
            "they agree with you" % (exc, final_path))
        return EXIT_ERROR if args.send is not None else code
    except (CollectError, ValueError) as exc:
        log("ERROR: could not encrypt the package: %s. Nothing was sent" % exc)
        return EXIT_ERROR
    encrypted_path = final_path + ".p7m"
    with open_private(encrypted_path, "wb") as fh:
        fh.write(blob)
    left.insert(1, encrypted_path)
    log("encrypted: %s, %d bytes, SHA-256 %s, %s to %s (certificate SHA-256 %s, valid to %s)"
        % (encrypted_path, len(blob), hashlib.sha256(blob).hexdigest(), info["content_cipher"],
           info["recipient_subject"], info["recipient_sha256"], info["recipient_not_after"]))
    if args.send is None:
        log("not sent: no --send given")
        return code
    if len(blob) > MAX_UPLOAD_BYTES:
        log("NOT SENT: the encrypted package is %d bytes, over the %d-byte upload limit. "
            "Contact 4am Labs to return %s another way" % (len(blob), MAX_UPLOAD_BYTES,
                                                         encrypted_path))
        return EXIT_ERROR
    try:
        context, source = upload_context(upload_ca)
        log("upload: verifying the receiver against %s" % source)
        receipt = upload(upload_url, args.send, os.path.basename(encrypted_path), blob,
                         context, log)
    except CollectError as exc:
        log("NOT SENT: %s" % exc)
        return EXIT_ERROR
    log("sent: the receiver holds %s, %s bytes, SHA-256 %s, received %s"
        % (receipt.get("name"), receipt.get("size"), receipt.get("sha256"),
           receipt.get("received_at")))
    return code


if __name__ == "__main__":
    sys.exit(main())
