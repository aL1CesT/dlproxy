"""Local test fixtures: a real HTTP origin server plus an app harness.

The origin server is a genuine socket-level ``http.server`` rather than an ASGI
mock, because the whole point of these tests is to exercise the *real* httpx
transport, the real SSRF backend and real chunked reads.
"""
from __future__ import annotations

import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

os.environ.setdefault("DLPROXY_SECRET_KEY", "test-secret-key-for-pytest")

BLOB = bytes(range(256)) * 4096          # 1 MiB, deterministic


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _Handler(BaseHTTPRequestHandler):
    """Minimal origin: files, ranges, redirects, gzip, slow bodies."""

    protocol_version = "HTTP/1.1"
    server_version = "testorigin"

    def log_message(self, *args):        # silence
        pass

    # -- helpers ------------------------------------------------------------

    def _send(self, status: int, body: bytes, headers: dict[str, str] | None = None):
        self.send_response(status)
        base = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(body)),
            "Accept-Ranges": "bytes",
        }
        if headers:
            base.update(headers)
        for key, value in base.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _range(self):
        header = self.headers.get("Range")
        if not header or not header.startswith("bytes="):
            return None
        spec = header[len("bytes="):].split(",")[0]
        start_s, _, end_s = spec.partition("-")
        total = len(BLOB)
        if start_s == "":
            length = int(end_s)
            return total - length, total - 1
        start = int(start_s)
        end = int(end_s) if end_s else total - 1
        return start, min(end, total - 1)

    # -- routes -------------------------------------------------------------

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if self.path.startswith("/redirecting.git/") and \
                self.path.endswith("/git-upload-pack"):
            # A receiving endpoint that answers 302 is legal HTTP. The proxy
            # must refuse rather than replay the (single-use) request body:
            # an async iterator yields its chunks exactly once, so the next hop
            # would go out with Content-Length but no bytes.
            self.send_response(302)
            self.send_header("Location", "/repo.git/git-upload-pack")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.endswith("/git-upload-pack"):
            ctype = self.headers.get("Content-Type", "")
            if "application/x-git-upload-pack-request" in ctype:
                self._send(200, b"packfile:" + body,
                           {"Content-Type": "application/x-git-upload-pack-result"})
                return
        self._send(404, b"nope")

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/blob":
            rng = self._range()
            if rng is None:
                self._send(200, BLOB)
            else:
                start, end = rng
                self._send(206, BLOB[start:end + 1], {
                    "Content-Range": f"bytes {start}-{end}/{len(BLOB)}",
                })
            return

        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/blob")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/redirect-loop":
            self.send_response(302)
            self.send_header("Location", "/redirect-loop")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/redirect-internal":
            # A public host bouncing us to the metadata service: the proxy must
            # re-vet every hop and refuse it.
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/slow":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(BLOB)))
            self.end_headers()
            try:
                for i in range(0, len(BLOB), 64 * 1024):
                    self.wfile.write(BLOB[i:i + 64 * 1024])
                    self.wfile.flush()
                    time.sleep(0.02)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        if path == "/cookie":
            self._send(200, b"ok", {
                "Set-Cookie": "a=b; Path=/",
                "ETag": '"abc"',
                "Cache-Control": "max-age=60",
            })
            return

        if path == "/echo-headers":
            import json
            payload = json.dumps(dict(self.headers)).encode()
            self._send(200, payload, {"Content-Type": "application/json"})
            return

        if path == "/empty":
            self._send(200, b"")
            return

        self._send(404, b"not found")


@pytest.fixture(scope="session")
def origin():
    port = _free_port()
    # The app under test only permits 80/443 by default; the fixture origin binds
    # an ephemeral port, so the port is advertised to the app factory below.
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def app_client(tmp_path: Path, origin: str, monkeypatch):
    """A TestClient wired to a temp database and an SSRF-opened policy.

    ``allow_private_upstream=True`` only relaxes the *address* rule so the local
    fixture origin is reachable; every other code path (raw URL recovery, token
    checks, redirect re-vetting, metering) is the production one.
    """
    from fastapi.testclient import TestClient

    from app.main import create_app

    # Bootstrap writes the initial admin password next to the app by default,
    # which for a checkout is the repository root. Point it at the temp dir so
    # a test run never drops a live password file into the working tree.
    monkeypatch.setenv("DLPROXY_INIT_FILE", str(tmp_path / "INITIAL_ADMIN.txt"))

    security = tmp_path / "security.log"
    origin_port = int(origin.rsplit(":", 1)[1])
    app = create_app(
        db_path_override=str(tmp_path / "app.db"),
        allow_private_upstream=True,
        allowed_ports=frozenset({80, 443, origin_port}),
        security_log_path=security,
    )
    # base_url must be https: the session cookie is issued with Secure (the app
    # assumes it sits behind the TLS terminator), and httpx's cookie jar refuses
    # to send a Secure cookie over a plain-http origin. Testing over https is
    # also closer to what production does.
    with TestClient(app, base_url="https://testserver") as client:
        client.security_path = security          # type: ignore[attr-defined]
        yield client
