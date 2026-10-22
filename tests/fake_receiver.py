"""A stand-in upload receiver for tests: the receiver as the script sees it.

What the real receiver does that a client can see: only PUT /v1/upload; the token checked before
the body is read (known, unexpired, unused, length within its limit); Transfer-Encoding refused
with 411; the hash header 64 lower-case hex; a hash mismatch answered 422 with the token left
usable; a receipt {name, size, sha256, received_at}. Tokens are held only as their SHA-256, as
the real receiver holds them. HTTPS with a throwaway certificate.
"""

import hashlib
import json
import re
import socketserver
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HASH = re.compile(r"^[0-9a-f]{64}$")


class FakeReceiver:
    def __init__(self, certs, cert="localhost"):
        self.tokens = {}         # sha256 of token -> {"state", "limit", "expired"}
        self.received = []       # (name, body)
        self.requests = []       # (method, path, headers as a dict)
        self.faults = {"receipt_sha256": None, "redirect": False, "status": None,
                       "mismatch": False, "close_without_answer": False}
        self._lock = threading.Lock()

        class Server(socketserver.ThreadingMixIn, HTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass

        self.server = Server(("127.0.0.1", 0), self._handler_class())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*certs[cert])
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.url = "https://localhost:%d/v1/upload" % self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def mint(self, token, limit=95000000, expired=False):
        self.tokens[hashlib.sha256(token.encode()).hexdigest()] = {
            "state": "unused", "limit": limit, "expired": expired}

    def state(self, token):
        return self.tokens[hashlib.sha256(token.encode()).hexdigest()]["state"]

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def decide(self, method, path, headers):
        """Everything checked before the body is read: (status, payload) or None to read it."""
        if self.faults["status"]:
            return self.faults["status"]
        if self.faults["redirect"]:
            return 302, {"location": "https://localhost:1/elsewhere"}
        if method != "PUT" or path != "/v1/upload":
            return 404, {"error": "not found"}
        auth = headers.get("Authorization") or ""
        if not auth.startswith("Bearer "):
            return 401, {"error": "no token"}
        token = self.tokens.get(hashlib.sha256(auth[len("Bearer "):].encode()).hexdigest())
        if token is None or token["expired"]:
            return 401, {"error": "unknown or expired token"}
        if token["state"] != "unused":
            return 409, {"error": "token already used"}
        if headers.get("Transfer-Encoding") or not headers.get("Content-Length"):
            return 411, {"error": "length required"}
        if int(headers["Content-Length"]) > token["limit"]:
            return 413, {"error": "over the limit"}
        if not HASH.match(headers.get("X-Content-SHA256") or ""):
            return 400, {"error": "bad hash header"}
        return None

    def _handler_class(self):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _answer(self, status, payload):
                data = json.dumps(payload).encode()
                self.send_response(status)
                if status == 302:
                    self.send_header("Location", payload["location"])
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _serve(self):
                headers = {k: v for k, v in self.headers.items()}
                with fake._lock:
                    fake.requests.append((self.command, self.path, headers))
                    refusal = fake.decide(self.command, self.path, self.headers)
                    token = None
                    if refusal is None:
                        key = hashlib.sha256(
                            self.headers["Authorization"][len("Bearer "):].encode()).hexdigest()
                        token = fake.tokens[key]
                        token["state"] = "reserved"
                if fake.faults["close_without_answer"]:
                    self.close_connection = True
                    return
                if refusal is not None:
                    self._answer(*refusal)
                    # As the real receiver: the refused body is read and discarded, so a client
                    # still sending reaches the answer instead of a reset.
                    length = self.headers.get("Content-Length") or ""
                    if length.isdigit() and self.headers.get("Expect", "").lower() != "100-continue":
                        try:
                            self.rfile.read(int(length))
                        except OSError:
                            pass
                    return
                body = self.rfile.read(int(self.headers["Content-Length"]))
                sha256 = hashlib.sha256(body).hexdigest()
                # "mismatch" stands for a body changed in transit, which a client cannot cause.
                if fake.faults["mismatch"] or sha256 != self.headers["X-Content-SHA256"]:
                    token["state"] = "unused"
                    self._answer(422, {"error": "hash mismatch"})
                    return
                token["state"] = "used"
                name = self.headers.get("X-Package-Name")
                fake.received.append((name, body))
                self._answer(200, {"name": "rx-%s" % name, "size": len(body),
                                   "sha256": fake.faults["receipt_sha256"] or sha256,
                                   "received_at": "2026-10-22T12:00:00Z"})

            do_GET = do_POST = do_PUT = do_DELETE = _serve

        return Handler
