"""A stand-in Wazuh indexer for tests: HTTPS with a throwaway CA, scroll paging, and faults.

Its documents are generated for all six data sets from Wazuh 4.14.8's own index mappings
(fixtures/mappings-4.14.8.json, copied from Wazuh's source tree; each entry names the template it
came from). Synthetic values only.
"""

import base64
import fnmatch
import json
import os
import socket
import socketserver
import ssl
import subprocess
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "fixtures", "mappings-4.14.8.json"), encoding="utf-8") as _fh:
    FIXTURE = json.load(_fh)

VULN_PATTERN = "wazuh-states-vulnerabilities-*"
PATTERNS = sorted(FIXTURE["patterns"])

CNF = """
[req]
distinguished_name = dn
prompt = no
[dn]
CN = {cn}
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = {san}
[recipient]
basicConstraints = critical,CA:FALSE
keyUsage = critical,keyEncipherment
subjectKeyIdentifier = hash
[client]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""


def _openssl(args, cwd):
    proc = subprocess.run(["openssl"] + args, cwd=cwd, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, universal_newlines=True)
    if proc.returncode != 0:
        raise RuntimeError("openssl %s failed: %s%s" % (args[0], proc.stdout, proc.stderr))


def make_ca(directory, name):
    """A CA certificate and key: <name>.pem, <name>.key."""
    cnf = os.path.join(directory, name + ".cnf")
    with open(cnf, "w") as fh:
        fh.write(CNF.format(cn="Test CA " + name, san="DNS:unused"))
    _openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-config", cnf,
              "-extensions", "ca", "-keyout", name + ".key", "-out", name + ".pem"], directory)
    return os.path.join(directory, name + ".pem"), os.path.join(directory, name + ".key")


def make_server_cert(directory, ca_name, name, san):
    """A server certificate issued by CA <ca_name>: <name>.pem, <name>.key."""
    cnf = os.path.join(directory, name + ".cnf")
    with open(cnf, "w") as fh:
        fh.write(CNF.format(cn=name, san=san))
    _openssl(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-config", cnf,
              "-keyout", name + ".key", "-out", name + ".csr"], directory)
    _openssl(["x509", "-req", "-in", name + ".csr", "-CA", ca_name + ".pem", "-CAkey",
              ca_name + ".key", "-CAcreateserial", "-days", "2", "-extfile", cnf,
              "-extensions", "server", "-out", name + ".pem"], directory)
    return os.path.join(directory, name + ".pem"), os.path.join(directory, name + ".key")


def make_client_cert(directory, ca_name, name):
    """A client certificate issued by CA <ca_name>, CN <name>: <name>.pem, <name>.key."""
    cnf = os.path.join(directory, name + ".cnf")
    with open(cnf, "w") as fh:
        fh.write(CNF.format(cn=name, san="DNS:unused"))
    _openssl(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-config", cnf,
              "-keyout", name + ".key", "-out", name + ".csr"], directory)
    _openssl(["x509", "-req", "-in", name + ".csr", "-CA", ca_name + ".pem", "-CAkey",
              ca_name + ".key", "-CAcreateserial", "-days", "2", "-extfile", cnf,
              "-extensions", "client", "-out", name + ".pem"], directory)
    return os.path.join(directory, name + ".pem"), os.path.join(directory, name + ".key")


def make_recipient(directory, name):
    """A self-signed recipient certificate and key for CMS: <name>.pem, <name>.key."""
    cnf = os.path.join(directory, name + ".cnf")
    with open(cnf, "w") as fh:
        fh.write(CNF.format(cn="Test recipient " + name, san="DNS:unused"))
    _openssl(["req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "2", "-config", cnf,
              "-extensions", "recipient", "-keyout", name + ".key", "-out", name + ".pem"],
             directory)
    return os.path.join(directory, name + ".pem"), os.path.join(directory, name + ".key")


def make_certs(directory):
    """good CA + localhost cert, a cert for another host name, an unrelated CA, recipients."""
    make_ca(directory, "ca")
    make_ca(directory, "otherca")
    return {
        "ca": os.path.join(directory, "ca.pem"),
        "otherca": os.path.join(directory, "otherca.pem"),
        "localhost": make_server_cert(directory, "ca", "localhost", "DNS:localhost,IP:127.0.0.1"),
        "wronghost": make_server_cert(directory, "ca", "wronghost", "DNS:other.example"),
        "rogue": make_server_cert(directory, "otherca", "rogue", "DNS:localhost,IP:127.0.0.1"),
        "recipient": make_recipient(directory, "recipient"),
        # The indexer's admin certificate, and one an unrelated CA issued with the same name.
        "admin": make_client_cert(directory, "ca", "admin"),
        "rogueadmin": make_client_cert(directory, "otherca", "rogueadmin"),
    }


def fields_of(pattern):
    """(name, type) for every leaf field of a pattern's mapping."""
    def walk(properties, prefix):
        for name, spec in sorted(properties.items()):
            if "properties" in spec:
                for leaf in walk(spec["properties"], prefix + name + "."):
                    yield leaf
            else:
                yield prefix + name, spec.get("type")
    return list(walk(FIXTURE["patterns"][pattern]["mappings"]["properties"], ""))


def nest(flat):
    out = {}
    for name, value in flat.items():
        node = out
        parts = name.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return out


SPECIAL = {
    "agent.id": lambda a, n: "%03d" % (a + 1),
    "agent.name": lambda a, n: "agent-%03d" % (a + 1),
    "package.name": lambda a, n: "pkg-%04d" % n,
    "package.version": lambda a, n: "1.0.%d" % n,
    "package.description": lambda a, n: "synthetic package, with a comma and \"quotes\"",
    "package.hotfix.name": lambda a, n: "KB50%05d" % n,
    "vulnerability.id": lambda a, n: "CVE-2026-%05d" % n,
    "vulnerability.severity": lambda a, n: "High",
    "vulnerability.score.version": lambda a, n: "3.1",
    "vulnerability.scanner.condition": lambda a, n: "Package less than 1.0.%d" % (n + 1),
    "vulnerability.category": lambda a, n: ["Packages"],
    "vulnerability.reference": lambda a, n: "https://example.org/a, https://example.org/b",
    "host.os.full": lambda a, n: "Ubuntu 22.04.4 LTS (Jammy Jellyfish)",
    "host.os.name": lambda a, n: "Ubuntu",
    "host.os.version": lambda a, n: "22.04.4",
    "host.os.platform": lambda a, n: "ubuntu",
    "host.os.type": lambda a, n: "linux",
    "host.os.kernel": lambda a, n: "6.8.0-142-generic",
    "host.os.kernel.release": lambda a, n: "6.8.0-142-generic",
    "host.cpu.name": lambda a, n: "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz",
}
BY_TYPE = {
    "keyword": lambda name, a, n: "%s-%d" % (name.rsplit(".", 1)[-1], n),
    "ip": lambda name, a, n: "10.%d.%d.%d" % (a % 250, n // 250 % 250, n % 250 + 1),
    "long": lambda name, a, n: 1024 + n,
    "short": lambda name, a, n: 4,
    "scaled_float": lambda name, a, n: 0.5,
    "float": lambda name, a, n: 7.5,
    "date": lambda name, a, n: "2026-10-01T14:34:06.349Z",
    "boolean": lambda name, a, n: False,
}


def docs_for(pattern, agents, per_agent, prefix="d"):
    """Synthetic documents with every mapped field filled, by type or by a fixed rule."""
    fields = fields_of(pattern)
    docs = []
    for a in range(agents):
        for n in range(per_agent):
            flat = {}
            for name, kind in fields:
                rule = SPECIAL.get(name)
                flat[name] = rule(a, n) if rule else BY_TYPE[kind](name, a, n)
            docs.append({"_id": "%s-%d-%d" % (prefix, a, n), "_source": nest(flat)})
    return docs


def index_name(pattern, suffix="wazuh"):
    """A data set's index as Wazuh names it: after the cluster (here "wazuh", as the test
    managers' clusters are named) or the host."""
    return pattern.replace("*", suffix)


class Faults:
    """Behaviour switches; all off by default."""

    def __init__(self):
        self.drop_page = None        # this page number is skipped (of the first pattern served)
        self.repeat_page = None      # this page is served twice (extra rows)
        self.replace_page = None     # this page is replaced by the previous one (same row count)
        self.total_offset = 0        # added to the snapshot total
        self.total_relation = "eq"   # "gte" reports the total as a lower bound
        self.count_drift = 0         # added to every _count after the first per pattern
        self.version_status = None   # HTTP status for GET /
        self.status = {}             # (method, path suffix) -> (code, body)
        self.redirect_path = None    # path answered with a 302
        self.extra_field_at = None   # (pattern, doc number) given an unmapped field
        self.object_list_at = None   # (pattern, doc number) given a list of objects
        self.fault_pattern = VULN_PATTERN  # the pattern page faults apply to
        self.hold_after_pages = None # stop answering scroll requests after this many pages,
                                     # until `release` is set
        self.release = threading.Event()


class FakeIndexer:
    def __init__(self, certs, user, password, cert="localhost"):
        self.user, self.password = user, password
        self.indices = {}            # index name -> (mapping, docs)
        self.faults = Faults()
        self.requests = []           # (method, path, query, authorization header)
        self.client_cns = []         # the verified client certificate's CN of each, or None
        self.user_agents = []        # the User-Agent header of each request, in order
        self.freed = []
        self.held = threading.Event()   # set once a scroll request is being held
        self.scrolls = {}
        self._counted = set()
        self._lock = threading.Lock()
        handler = self._handler_class()

        class Server(socketserver.ThreadingMixIn, HTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass  # a client that rejects our certificate is expected in some tests

        self.server = Server(("127.0.0.1", 0), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*certs[cert])
        # A client certificate is optional; one that is presented must come from the test CA,
        # and CN "admin" signs in as the indexer's admin, as the real indexer's admin_dn does.
        context.verify_mode = ssl.CERT_OPTIONAL
        context.load_verify_locations(certs["ca"])
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.url = "https://localhost:%d" % self.port
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def add_index(self, pattern, docs, suffix="wazuh"):
        mapping = {"mappings": FIXTURE["patterns"][pattern]["mappings"]}
        self.indices[index_name(pattern, suffix)] = (mapping, docs)

    def add_all(self, agents, per_agent, skip=()):
        """One index per data set, every one filled."""
        for pattern in PATTERNS:
            if pattern not in skip:
                self.add_index(pattern, docs_for(pattern, agents, per_agent,
                                                 prefix=pattern.split("-")[2][:4]))

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.faults.release.set()
        self.server.shutdown()
        self.server.server_close()

    # -- request handling ------------------------------------------------------------------

    def _matching(self, pattern):
        return [n for n in sorted(self.indices) if fnmatch.fnmatchcase(n, pattern)]

    def _hits(self, pattern):
        hits = []
        for name in self._matching(pattern):
            for number, doc in enumerate(self.indices[name][1]):
                source = doc["_source"]
                if self._at(self.faults.extra_field_at, pattern, number):
                    source = dict(source, unmapped_field="x")
                if self._at(self.faults.object_list_at, pattern, number):
                    source = dict(source, objects=[{"a": 1}])
                hits.append({"_index": name, "_id": doc["_id"], "_source": source})
        return hits

    @staticmethod
    def _at(fault, target, number):
        """Whether a (pattern, document number) fault applies to this request's document."""
        return bool(fault) and fnmatch.fnmatchcase(target, fault[0]) and fault[1] == number

    def _faulted(self, target):
        """Whether the faults apply to a request naming this pattern or index."""
        return fnmatch.fnmatchcase(target, self.faults.fault_pattern)

    def _pages(self, pattern, hits, size):
        pages = [hits[i:i + size] for i in range(0, len(hits), size)]
        f = self.faults
        if not self._faulted(pattern):
            return pages
        if f.replace_page is not None and 0 < f.replace_page < len(pages):
            pages[f.replace_page] = pages[f.replace_page - 1]
        if f.repeat_page is not None and f.repeat_page < len(pages):
            pages.insert(f.repeat_page + 1, pages[f.repeat_page])
        if f.drop_page is not None and f.drop_page < len(pages):
            del pages[f.drop_page]
        return pages

    def handle(self, method, path, query, headers, body, client_cn=None):
        """Returns (status, payload dict, extra headers). client_cn is the CN of a verified
        client certificate, or None."""
        with self._lock:
            self.requests.append((method, path, query, headers.get("Authorization")))
            self.client_cns.append(client_cn)
            self.user_agents.append(headers.get("User-Agent"))
        expected = "Basic " + base64.b64encode(
            ("%s:%s" % (self.user, self.password)).encode()).decode()
        if headers.get("Authorization") != expected and client_cn != "admin":
            return 401, {"error": "Unauthorized"}, {}
        for (m, suffix), (code, payload) in self.faults.status.items():
            if m == method and path.endswith(suffix):
                return code, payload, {}
        if self.faults.redirect_path == path:
            return 302, {}, {"Location": "https://localhost:%d/elsewhere" % self.port}
        pattern = urllib.parse.unquote(path.split("/")[1]) if path != "/" else None
        if method == "GET" and path == "/":
            if self.faults.version_status:
                return self.faults.version_status, {"error": "no permission"}, {}
            return 200, {"version": {"number": "7.10.2", "distribution": "opensearch"}}, {}
        if method == "GET" and path.endswith("/_mapping"):
            return 200, {n: self.indices[n][0] for n in self._matching(pattern)}, {}
        if method == "GET" and path.endswith("/_count"):
            count = len(self._hits(pattern))
            if pattern in self._counted:
                count += self.faults.count_drift if self._faulted(pattern) else 0
            self._counted.add(pattern)
            return 200, {"count": count}, {}
        if method == "POST" and path.endswith("/_search") and "scroll" in query:
            hits = self._hits(pattern)
            pages = self._pages(pattern, hits, body["size"])
            scroll_id = "scroll-%d" % len(self.scrolls)
            self.scrolls[scroll_id] = [pages, 0]
            offset = self.faults.total_offset if self._faulted(pattern) else 0
            relation = self.faults.total_relation if self._faulted(pattern) else "eq"
            total = {"value": len(hits) + offset, "relation": relation}
            return 200, self._page(scroll_id, total), {}
        if method == "POST" and path == "/_search/scroll":
            held = self.faults.hold_after_pages
            if held is not None and self.scrolls[body["scroll_id"]][1] >= held:
                self.held.set()
                self.faults.release.wait(60)
            return 200, self._page(body["scroll_id"], None), {}
        if method == "DELETE" and path == "/_search/scroll":
            self.freed.extend(body["scroll_id"])
            return 200, {"succeeded": True, "num_freed": len(body["scroll_id"])}, {}
        return 400, {"error": "fake indexer does not handle %s %s" % (method, path)}, {}

    def _page(self, scroll_id, total):
        state = self.scrolls[scroll_id]
        pages, position = state
        hits = pages[position] if position < len(pages) else []
        state[1] = position + 1
        answer = {"_scroll_id": scroll_id, "hits": {"hits": hits}}
        if total is not None:
            answer["hits"]["total"] = total
        return answer

    def _handler_class(self):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _serve(self):
                parts = urllib.parse.urlsplit(self.path)
                query = dict(urllib.parse.parse_qsl(parts.query))
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                body = json.loads(raw.decode()) if raw else None
                peer = self.connection.getpeercert() or {}
                cn = next((v for rdn in peer.get("subject", ()) for k, v in rdn
                           if k == "commonName"), None)
                status, payload, extra = fake.handle(self.command, parts.path, query,
                                                     self.headers, body, client_cn=cn)
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in extra.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_DELETE = do_PUT = _serve

        return Handler


class ConnectProxy:
    """An HTTP CONNECT proxy. With a rogue certificate it answers TLS itself instead of
    tunnelling, as an intercepting proxy would."""

    def __init__(self, rogue_cert=None):
        self.connects = []
        self.rogue = None
        if rogue_cert:
            self.rogue = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.rogue.load_cert_chain(*rogue_cert)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.url = "http://127.0.0.1:%d" % self.sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.sock.close()

    def _accept(self):
        while True:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client):
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = client.recv(4096)
                if not chunk:
                    return
                head += chunk
            target = head.split(b" ")[1].decode()
            self.connects.append(target)
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            if self.rogue:
                try:
                    self.rogue.wrap_socket(client, server_side=True).close()
                except (ssl.SSLError, OSError):
                    pass
                return
            host, port = target.rsplit(":", 1)
            upstream = socket.create_connection((host, int(port)))
            threading.Thread(target=self._pipe, args=(upstream, client), daemon=True).start()
            self._pipe(client, upstream)
        except OSError:
            pass

    @staticmethod
    def _pipe(source, sink):
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                sink.sendall(data)
        except OSError:
            pass
        finally:
            for s in (source, sink):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                s.close()
