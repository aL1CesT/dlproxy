"""tools/e2e_nginx_conf.py — validate deploy/nginx.conf itself.

``e2e_nginx.py`` proves that a *minimal* nginx relays raw URIs. This one goes
further and loads the actual template that ships in ``deploy/``, substituting
only the certificate paths and the listen ports, so the file that reaches the
server is the file that was tested.

Four behaviours are asserted:

1. ``/.well-known/acme-challenge/<token>`` on :80 is served from the webroot —
   without this, every renewal fails and the site dies in six days.
2. Any other :80 path 301s to https.
3. The HTTPS block relays the raw URI, ``//`` included.
4. ``proxy_pass`` in the template carries no URI component (a text assertion —
   it is the one line whose absence breaks everything).

    python tools/e2e_nginx_conf.py --nginx /path/to/nginx
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import http2spell
import nginxbin

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "deploy" / "nginx.conf"

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


def port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def wait_for_ports(ports: list[int], timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(port_open(p) for p in ports):
            return True
        time.sleep(0.05)
    return False


def _port_closed(port: int) -> bool:
    return not port_open(port)


def _kill_tree(pid: int) -> None:
    """Kill nginx together with its workers. nginx runs as a master that
    forks workers; killing the master alone leaves the workers holding the
    listening sockets on Windows, so the port stays busy forever."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                       capture_output=True)
    else:
        try:
            os.kill(pid, 9)
        except OSError:
            pass


RECORDER = r'''
import socket, sys, threading

out = open(sys.argv[2], "ab", buffering=0)
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(32)


def handle(c):
    with c:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = c.recv(65536)
            if not chunk:
                return
            data += chunk
        out.write(data.split(b"\r\n", 1)[0] + b"\n")
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n"
                  b"Connection: close\r\n\r\nhello world")


while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
'''


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):        # noqa: ANN002, ANN003
        return None


def main() -> int:
    _force_utf8()
    parser = argparse.ArgumentParser()
    parser.add_argument("--nginx", default=None)
    args = parser.parse_args()
    binary = nginxbin.resolve(args.nginx)
    if binary is None:
        print("找不到可用的 nginx 可执行文件；用 --nginx /path/to/nginx 指定")
        return 1

    work = Path(tempfile.mkdtemp(prefix="dlproxy-ngxconf-"))
    http_port = free_port()
    https_port = free_port()
    upstream_port = free_port()
    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, evidence: str) -> None:
        results.append((name, ok, evidence))
        print(f"  {PASS if ok else FAIL}  {name}: {evidence}")

    procs: list[subprocess.Popen] = []
    try:
        # --- static assertions on the template -------------------------------
        text = TEMPLATE.read_text(encoding="utf-8")
        # Strip comments before looking for proxy_pass, or the warning comment
        # about the wrong form would be mistaken for the wrong form itself.
        code = re.sub(r"#.*", "", text)
        bad = re.findall(r"proxy_pass\s+http://[^;\s]+/;", code)
        good = re.findall(r"proxy_pass\s+http://127\.0\.0\.1:8080;", code)
        check("proxy_pass 不带 URI", not bad and bool(good),
              f"发现带斜杠的写法={len(bad)}, 正确写法={len(good)}")
        check("有 ACME location", "/.well-known/acme-challenge/" in code,
              "存在" if "/.well-known/acme-challenge/" in code else "缺失")
        check("关闭 proxy_buffering", "proxy_buffering off;" in code,
              "存在" if "proxy_buffering off;" in code else "缺失")

        # --- build a runnable instance ---------------------------------------
        for sub in ("conf", "logs", "temp", "www/certbot", "certs"):
            (work / sub).mkdir(parents=True, exist_ok=True)
        for sub in ("client_body_temp", "proxy_temp", "fastcgi_temp",
                    "uwsgi_temp", "scgi_temp"):
            (work / "temp" / sub).mkdir(parents=True, exist_ok=True)

        cert = work / "certs" / "cert.pem"
        key = work / "certs" / "priv.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "2",
             "-keyout", str(key), "-out", str(cert), "-subj", "/CN=dlproxy-test"],
            check=True, capture_output=True,
        )

        site = (text
                .replace("__CERT_FULLCHAIN__", cert.as_posix())
                .replace("__CERT_PRIVKEY__", key.as_posix())
                .replace("__DEFAULT_SERVER__", "")
                .replace("__SERVER_NAME__", "_")
                .replace("listen 80;", f"listen {http_port};")
                .replace("listen [::]:80;", f"listen [::]:{http_port};")
                .replace("listen 443 ssl;", f"listen {https_port} ssl;")
                .replace("listen [::]:443 ssl;", f"listen [::]:{https_port} ssl;")
                .replace("root /var/www/certbot;",
                         f"root {(work / 'www' / 'certbot').as_posix()};")
                .replace("proxy_pass http://127.0.0.1:8080;",
                         f"proxy_pass http://127.0.0.1:{upstream_port};"))
        (work / "conf" / "site.conf").write_text(site, encoding="utf-8")
        # nginx 1.24 (Ubuntu 24.04) cannot parse `http2 on;`; let the shipped
        # script pick the spelling rather than guessing here.
        http2spell.apply(work / "conf" / "site.conf", binary)

        recorder = work / "rec.py"
        recorder.write_text(RECORDER, encoding="utf-8")
        rec_file = work / "rec.txt"
        procs.append(subprocess.Popen([sys.executable, str(recorder),
                                       str(upstream_port), str(rec_file)]))

        (work / "conf" / "nginx.conf").write_text(
            f"worker_processes 1;\n"
            f"error_log {(work / 'logs' / 'error.log').as_posix()} warn;\n"
            f"pid {(work / 'logs' / 'nginx.pid').as_posix()};\n"
            f"events {{ worker_connections 64; }}\n"
            f"http {{\n"
            f"  access_log off;\n"
            f"  include {(work / 'conf' / 'site.conf').as_posix()};\n"
            f"}}\n",
            encoding="utf-8",
        )
        procs.append(subprocess.Popen(
            [str(binary), "-p", str(work) + os.sep,
             "-c", str(work / "conf" / "nginx.conf")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT))
        if not wait_for_ports([http_port, https_port]):
            err = (work / "logs" / "error.log")
            print("nginx 启动失败:\n" + (err.read_text(errors="replace") if err.exists() else ""))
            return 1

        # --- 1. ACME challenge served from the webroot ----------------------
        challenge = work / "www" / "certbot" / ".well-known" / "acme-challenge" / "tok123"
        challenge.parent.mkdir(parents=True, exist_ok=True)
        challenge.write_text("challenge-body-ok", encoding="utf-8")
        url = f"http://127.0.0.1:{http_port}/.well-known/acme-challenge/tok123"
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = resp.read().decode()
        check("ACME 路径直接返回", resp.status == 200 and body == "challenge-body-ok",
              f"HTTP {resp.status}, body={body!r}")

        # --- 2. everything else on :80 redirects ----------------------------
        opener = urllib.request.build_opener(NoRedirect)
        try:
            opener.open(f"http://127.0.0.1:{http_port}/anything", timeout=5)
            check("HTTP 强制跳 HTTPS", False, "没有发生重定向")
        except urllib.error.HTTPError as exc:
            location = exc.headers.get("Location", "")
            check("HTTP 强制跳 HTTPS", exc.code == 301 and location.startswith("https://"),
                  f"HTTP {exc.code} -> {location}")

        # --- 3. HTTPS relays the raw URI ------------------------------------
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        target = (f"https://127.0.0.1:{https_port}"
                  f"/u/TOK/https://e.com/a//b.zip?x=1&y=2")
        with urllib.request.urlopen(target, timeout=10, context=ctx) as resp:
            payload = resp.read()
        time.sleep(0.3)
        lines = rec_file.read_text().strip().splitlines() if rec_file.exists() else []
        seen = lines[-1] if lines else ""
        expected = "GET /u/TOK/https://e.com/a//b.zip?x=1&y=2 HTTP/1.1"
        check("HTTPS 原样转发 URI", seen == expected and payload == b"hello world",
              f"上游收到 {seen!r}")
    finally:
        # Ask nginx to shut itself down before killing anything. Terminating
        # the master orphans its worker on Windows; the worker keeps the two
        # listening sockets and the next run cannot bind.
        pidfile = work / "logs" / "nginx.pid"
        subprocess.run(
            [str(binary), "-p", str(work) + os.sep,
             "-c", str(work / "conf" / "nginx.conf"), "-s", "quit"],
            capture_output=True, timeout=15,
        )
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not all(
                _port_closed(p) for p in (http_port, https_port)):
            time.sleep(0.05)

        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        if pidfile.exists():
            try:
                _kill_tree(int(pidfile.read_text().strip()))
            except (OSError, ValueError):
                pass
        shutil.rmtree(work, ignore_errors=True)

    failed = [r for r in results if not r[1]]
    print()
    if failed:
        print(f"{FAIL} {len(failed)} 项失败")
        return 1
    print(f"{PASS} 全部 {len(results)} 项通过 — deploy/nginx.conf 模板本身已验证")
    return 0


if __name__ == "__main__":
    sys.exit(main())
