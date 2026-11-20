"""tools/e2e_full.py — the whole chain on one machine: nginx → dlproxy → origin.

This is the test the other suites cannot give you. pytest talks to the ASGI app
directly, so it never exercises the Nginx hop; ``e2e_nginx.py`` exercises Nginx
but stops at a recording stub. Here a real uvicorn instance sits behind a real
nginx, and the origin is a real HTTP server, so a download makes the full trip:

    client → nginx:PORT ──raw URI──> uvicorn:PORT ──httpx+SSRF──> origin

What it asserts
---------------
1. A file fetched through the accelerated link is byte-identical (sha256).
2. A 16-way Range download reassembles correctly and collapses into exactly one
   history row whose ``bytes_sent`` equals the file size.
3. Internal targets (169.254.169.254, 10/8, ::1) get 403 through the whole chain.
4. A bad token gets 404 — not 403 — so token existence is not confirmed.
5. The client closing the connection mid-download still books the bytes it got.

    python tools/e2e_full.py --nginx /path/to/nginx [--keep]

Needs only what the project already requires. The nginx binary is the only
external piece; pass ``--nginx nginx`` to use one from PATH.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import nginxbin

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"


def _force_utf8() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_for_port(port: int, timeout: float = 25.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

BLOB = bytes(range(256)) * 8192          # 2 MiB


def start_origin() -> tuple[int, subprocess.Popen]:
    """A real origin server in a subprocess, so it cannot share an event loop."""
    code = r'''
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BLOB = bytes(range(256)) * 8192

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_HEAD(self): self.do_GET()
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path != "/blob":
            self.send_response(404); self.send_header("Content-Length","4"); self.end_headers()
            if self.command != "HEAD": self.wfile.write(b"nope")
            return
        rng = self.headers.get("Range")
        if rng and rng.startswith("bytes="):
            spec = rng[6:].split(",")[0]
            a, _, b = spec.partition("-")
            total = len(BLOB)
            start = int(a) if a else 0
            end = int(b) if b else total - 1
            body = BLOB[start:end+1]
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{total}")
        else:
            body = BLOB
            self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()
        if self.command != "HEAD":
            try: self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError): pass

srv = ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H)
srv.daemon_threads = True
srv.serve_forever()
'''
    port = free_port()
    script = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                         encoding="utf-8")
    script.write(code)
    script.close()
    proc = subprocess.Popen([sys.executable, script.name, str(port)])
    if not wait_for_port(port):
        proc.kill()
        raise RuntimeError("origin server 启动失败")
    return port, proc


def start_app(db_path: Path, app_port: int, log_path: Path,
              origin_port: int) -> subprocess.Popen:
    """uvicorn with the private-network guard relaxed for the local origin.

    The relaxation is a *port* allowance plus allow_private, both of which the
    app factory accepts explicitly for this purpose; production paths never set
    them.
    """
    code = f'''
import os, sys
sys.path.insert(0, {str(ROOT)!r})
os.environ.setdefault("DLPROXY_SECRET_KEY", "e2e-secret")
# Bootstrap writes the initial admin password next to app/ by default, i.e.
# into the checkout. Keep the rehearsal's copy inside its temp dir.
os.environ["DLPROXY_INIT_FILE"] = {str(db_path.parent / "INITIAL_ADMIN.txt")!r}
import uvicorn
from app.main import create_app

app = create_app(
    db_path_override={str(db_path)!r},
    allow_private_upstream=True,
    allowed_ports=frozenset({{80, 443, {origin_port}}}),
    security_log_path=__import__("pathlib").Path({str(log_path)!r}),
)
uvicorn.run(app, host="127.0.0.1", port={app_port}, log_level="warning",
            access_log=False)
'''
    port_holder = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                              encoding="utf-8")
    port_holder.write(code)
    port_holder.close()
    proc = subprocess.Popen([sys.executable, port_holder.name])
    if not wait_for_port(app_port):
        proc.kill()
        raise RuntimeError("应用启动失败")
    return proc


def start_nginx(binary: Path, workdir: Path, listen: int, app_port: int) -> subprocess.Popen:
    for sub in ("conf", "logs", "temp"):
        (workdir / sub).mkdir(parents=True, exist_ok=True)
    for sub in ("client_body_temp", "proxy_temp", "fastcgi_temp",
                "uwsgi_temp", "scgi_temp"):
        (workdir / "temp" / sub).mkdir(parents=True, exist_ok=True)
    prefix = workdir.as_posix()
    conf = f"""worker_processes 1;
error_log {prefix}/logs/error.log warn;
pid {prefix}/logs/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_header_buffer_size 8k;
    large_client_header_buffers 8 32k;
    proxy_buffering off;
    proxy_read_timeout 300s;
    server {{
        listen {listen};
        server_name _;
        location / {{
            proxy_pass http://127.0.0.1:{app_port};
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }}
    }}
}}
"""
    (workdir / "conf" / "nginx.conf").write_text(conf, encoding="utf-8")
    proc = subprocess.Popen(
        [str(binary), "-p", str(workdir) + os.sep,
         "-c", str(workdir / "conf" / "nginx.conf")],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if not wait_for_port(listen):
        proc.kill()
        raise RuntimeError("nginx 启动失败:\n" +
                           (workdir / "logs" / "error.log").read_text(errors="replace"))
    return proc


# ---------------------------------------------------------------------------
# HTTP helpers (plain http to nginx — TLS is nginx's job, not the app's)
# ---------------------------------------------------------------------------

def get(url: str, headers: dict | None = None, timeout: int = 60
        ) -> tuple[int, dict, bytes]:
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------

def run(nginx_binary: Path, keep: bool) -> int:
    workdir = Path(tempfile.mkdtemp(prefix="dlproxy-e2e-"))
    db_path = workdir / "app.db"
    log_path = workdir / "security.log"
    origin_port, origin_proc = start_origin()
    app_port = free_port()
    nginx_port = free_port()
    app_proc = app_proc = start_app(db_path, app_port, log_path, origin_port)
    ngx_proc = start_nginx(nginx_binary, workdir / "ngx", nginx_port, app_port)

    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, evidence: str) -> None:
        results.append((name, ok, evidence))
        print(f"  {PASS if ok else FAIL}  {name}: {evidence}")

    try:
        # Create a user and read its token straight from the database — the CLI
        # is exercised by tests/test_cli.py, this script only needs the value.
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO users(username, pwd_hash, token, token_active, disabled, "
            "is_admin, created_at) VALUES(?,?,?,1,0,0,?)",
            ("e2e", "x", "E2E" + hashlib.sha256(b"e2e").hexdigest()[:28],
             "2026-01-01T00:00:00.000Z"),
        )
        token = conn.execute("SELECT token FROM users WHERE username='e2e'"
                             ).fetchone()[0]
        conn.commit()

        base = f"http://127.0.0.1:{nginx_port}"
        link = f"{base}/u/{token}/http://127.0.0.1:{origin_port}/blob"

        print("==> 1. 完整下载经 nginx → 应用 → 上游")
        status, headers, body = get(link)
        ok = status == 200 and hashlib.sha256(body).hexdigest() == \
            hashlib.sha256(BLOB).hexdigest()
        check("整链下载", ok,
              f"HTTP {status}, {len(body)} 字节, sha256 一致={ok}, "
              f"Accept-Ranges={headers.get('accept-ranges')}")

        print("==> 2. 16 线程 Range 下载 → 一条历史")
        conn.execute("DELETE FROM transfers")
        conn.commit()
        total = len(BLOB)
        chunk = total // 16
        parts: list[bytes | None] = [None] * 16
        errors: list[str] = []

        def worker(i: int) -> None:
            start = i * chunk
            end = total - 1 if i == 15 else start + chunk - 1
            try:
                st, _h, data = get(link, headers={"Range": f"bytes={start}-{end}"})
                if st not in (200, 206):
                    errors.append(f"段{i} HTTP {st}")
                parts[i] = data
            except Exception as exc:                    # noqa: BLE001
                errors.append(f"段{i} {type(exc).__name__}: {exc}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
        t0 = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.monotonic() - t0
        reassembled = b"".join(p for p in parts if p is not None)
        bytes_ok = hashlib.sha256(reassembled).hexdigest() == \
            hashlib.sha256(BLOB).hexdigest()
        rows = conn.execute(
            "SELECT bytes_sent, range_hit, status_code FROM transfers "
            "ORDER BY id").fetchall()
        agg_ok = len(rows) == 1 and rows[0][0] == total and rows[0][1] == 1
        check("16 线程 Range 重组", bytes_ok and not errors,
              f"{len(reassembled)}/{total} 字节, {elapsed:.2f}s, 错误={errors or '无'}")
        check("历史聚合为 1 条", agg_ok,
              f"记录数={len(rows)}, bytes_sent={rows[0][0] if rows else 'n/a'}, "
              f"range_hit={rows[0][1] if rows else 'n/a'} (期望 1 条 / {total} / 1)")

        print("==> 3. SSRF 拦截（经整条链）")
        blocked = []
        for target in ("http://169.254.169.254/latest/meta-data/",
                       "http://10.0.0.1/", "http://[::1]/"):
            st, _h, b = get(f"{base}/u/{token}/{target}", timeout=15)
            leaked = any(w in b.lower() for w in (b"169.254", b"blocked", b"private"))
            blocked.append((target, st, leaked))
        ok = all(st == 403 and not leaked for _t, st, leaked in blocked)
        check("SSRF 403 且不泄露", ok,
              ", ".join(f"{t.split('//')[1][:18]}={st}" for t, st, _ in blocked))

        print("==> 4. token 门禁")
        st_missing, _, _ = get(f"{base}/u/{token}x/http://127.0.0.1:{origin_port}/blob")
        # A token with the wrong length/shape still has to be a clean 404.
        check("未知 token = 404", st_missing == 404, f"HTTP {st_missing}")

        print("==> 5. 客户端中断仍入账")
        conn.execute("DELETE FROM transfers")
        conn.execute("DELETE FROM counters")
        conn.commit()
        # Ask for the whole 2 MiB, read one chunk and hang up.
        parsed = urllib.parse.urlsplit(link)
        sock = socket.create_connection((parsed.hostname, parsed.port), timeout=10)
        sock.sendall(f"GET {parsed.path} HTTP/1.1\r\nHost: {parsed.hostname}\r\n"
                     f"Connection: close\r\n\r\n".encode())
        received = b""
        while len(received) < 200_000:
            chunk_in = sock.recv(16384)
            if not chunk_in:
                break
            received += chunk_in
        sock.close()
        time.sleep(1.5)          # let the server notice and finalise the row
        row = conn.execute(
            "SELECT bytes_sent, status_code FROM transfers ORDER BY id DESC LIMIT 1"
        ).fetchone()
        counter = conn.execute("SELECT COALESCE(SUM(bytes),0) FROM counters").fetchone()[0]
        ok = row is not None and row[0] > 0 and counter > 0
        check("中断后字节仍入账", ok,
              f"收到 {len(received)} 字节(含header), 记录 bytes_sent="
              f"{row[0] if row else 'n/a'}, status={row[1] if row else 'n/a'}, "
              f"counters={counter}")

        print("==> 6. 安全日志有记录")
        log_text = log_path.read_text(encoding="utf-8", errors="replace") \
            if log_path.exists() else ""
        check("安全日志", "ssrf_block" in log_text,
              f"{len(log_text)} 字节, 含 ssrf_block={'ssrf_block' in log_text}")

        conn.close()
    finally:
        # nginx first, and gracefully: terminating its master orphans the
        # worker, which keeps the listening port and breaks the next run.
        # The prefix is workdir/"ngx" — start_nginx() was given that path.
        ngx_dir = workdir / "ngx"
        pidfile = ngx_dir / "logs" / "nginx.pid"
        subprocess.run(
            [str(nginx_binary), "-p", str(ngx_dir) + os.sep,
             "-c", str(ngx_dir / "conf" / "nginx.conf"), "-s", "quit"],
            capture_output=True, timeout=15,
        )
        for proc in (ngx_proc, app_proc, origin_proc):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        if pidfile.exists():
            try:
                pid = int(pidfile.read_text().strip())
                if os.name == "nt":
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                                   capture_output=True)
                else:
                    os.kill(pid, 9)
            except (OSError, ValueError):
                pass
        if not keep:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print(f"==> 保留工作目录 {workdir}")

    failed = [r for r in results if not r[1]]
    print()
    print(f"==> 结果: {len(results) - len(failed)} PASS / {len(failed)} FAIL")
    return 1 if failed else 0


def main() -> int:
    _force_utf8()
    parser = argparse.ArgumentParser()
    parser.add_argument("--nginx", default=None)
    parser.add_argument("--keep", action="store_true", help="保留临时目录便于排查")
    args = parser.parse_args()
    binary = nginxbin.resolve(args.nginx)
    if binary is None:
        print("找不到可用的 nginx 可执行文件；用 --nginx /path/to/nginx 指定")
        return 1
    return run(binary, args.keep)


if __name__ == "__main__":
    import urllib.parse
    sys.exit(main())
