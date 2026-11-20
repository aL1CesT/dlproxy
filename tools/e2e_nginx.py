"""tools/e2e_nginx.py — assert that nginx relays the request URI byte for byte.

Why this exists
---------------
The service's link format is

    https://<host>/u/<token>/https://upstream.example/path/file.zip

so the *raw* request URI has to survive the reverse proxy untouched, including
the ``//`` inside ``https://``. nginx rewrites the URI before proxying whenever
``proxy_pass`` carries a URI component (a trailing slash counts), which collapses
``//`` and turns ``https://`` into ``https:/``. That single character difference
silently breaks every link.

This script starts a throwaway nginx and a recording upstream, fires the awkward
URL shapes at it, and compares the request line the upstream actually received.
It also runs a negative control with the wrong ``proxy_pass`` form, to prove the
assertions can fail.

    python3 tools/e2e_nginx.py --nginx /path/to/nginx [--listen 18200]

Exit code 0 only when every case matches and the control misbehaves as expected.
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import nginxbin

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
RST = ""


def _force_utf8() -> None:
    """Windows consoles default to GBK, which cannot encode the check marks.
    Reconfiguring stdout is enough; if the stream has no reconfigure (odd pipes),
    fall back to plain ASCII markers rather than crashing mid-run."""
    global PASS, FAIL
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        PASS, FAIL = "PASS", "FAIL"

# (description, request path, expected path as seen by the upstream)
CASES: list[tuple[str, str, str]] = [
    ("plain https", "/u/TOK/https://e.com/a.zip", "/u/TOK/https://e.com/a.zip"),
    ("double slash", "/u/TOK/https://e.com/a//b.zip", "/u/TOK/https://e.com/a//b.zip"),
    ("triple slash", "/u/TOK/https://e.com/a///b.zip", "/u/TOK/https://e.com/a///b.zip"),
    ("encoded slash", "/u/TOK/https://e.com/x%2Fy.zip", "/u/TOK/https://e.com/x%2Fy.zip"),
    ("space escape", "/u/TOK/https://e.com/sp%20ace.zip", "/u/TOK/https://e.com/sp%20ace.zip"),
    ("utf8 escape", "/u/TOK/https://e.com/%e4%b8%ad%e6%96%87.zip",
     "/u/TOK/https://e.com/%e4%b8%ad%e6%96%87.zip"),
    ("query kept", "/u/TOK/https://e.com/p?a=1&b=2", "/u/TOK/https://e.com/p?a=1&b=2"),
    ("uppercase scheme", "/u/TOK/HTTPS://E.COM/A.ZIP", "/u/TOK/HTTPS://E.COM/A.ZIP"),
    ("dot segment", "/u/TOK/https://e.com/a/./b.zip", "/u/TOK/https://e.com/a/./b.zip"),
    ("dotdot segment", "/u/TOK/https://e.com/../x.zip", "/u/TOK/https://e.com/../x.zip"),
    ("userinfo kept", "/u/TOK/https://user:pass@e.com/a.zip",
     "/u/TOK/https://user:pass@e.com/a.zip"),
    ("high port kept", "/u/TOK/https://e.com:8443/a.zip",
     "/u/TOK/https://e.com:8443/a.zip"),
]


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_port(port: int, *, host: str = "127.0.0.1", timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if port_open(port, host):
            return True
        time.sleep(0.05)
    return False


def wait_for_port_gone(port: int, *, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not port_open(port):
            return True
        time.sleep(0.05)
    return False


class RecordingUpstream:
    """Accepts connections, records the request line, answers 200 ok."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self._lock = threading.Lock()
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self.port = int(self._sock.getsockname()[1])
        self._sock.listen(64)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> "RecordingUpstream":
        self._thread.start()
        return self

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                data += chunk
            line = data.split(b"\r\n", 1)[0].decode("latin-1")
            with self._lock:
                self.lines.append(line)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                         b"Connection: close\r\n\r\nok")

    def last_path(self) -> str:
        with self._lock:
            if not self.lines:
                return ""
            return self.lines[-1].split(" ")[1]

    def clear(self) -> None:
        with self._lock:
            self.lines.clear()

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass


class Nginx:
    def __init__(self, binary: Path, workdir: Path, listen: int, upstream: int) -> None:
        self.binary = binary
        self.workdir = workdir
        self.listen = listen
        self.upstream = upstream
        self.proc: subprocess.Popen | None = None
        self._prepare()

    def _prepare(self) -> None:
        for sub in ("conf", "logs", "temp"):
            (self.workdir / sub).mkdir(parents=True, exist_ok=True)
        for sub in ("client_body_temp", "proxy_temp", "fastcgi_temp",
                    "uwsgi_temp", "scgi_temp"):
            (self.workdir / "temp" / sub).mkdir(parents=True, exist_ok=True)

    def _conf_text(self, location: str) -> str:
        prefix = self.workdir.as_posix()
        return f"""worker_processes 1;
error_log {prefix}/logs/error.log warn;
pid {prefix}/logs/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_header_buffer_size 8k;
    large_client_header_buffers 8 32k;
    server {{
        listen {self.listen};
        server_name _;
        {location}
    }}
}}
"""

    def write_conf(self, location: str) -> None:
        (self.workdir / "conf" / "nginx.conf").write_text(
            self._conf_text(location), encoding="utf-8")

    def good_location(self) -> str:
        # THE RULE UNDER TEST: no URI component, no trailing slash.
        return (f"location / {{ proxy_pass http://127.0.0.1:{self.upstream}; "
                f"proxy_http_version 1.1; proxy_set_header Connection \"\"; }}")

    def bad_location(self) -> str:
        # Negative control. nginx picks the longest matching prefix, so /bad/...
        # always hits this block and never the good one.
        return f"location /bad/ {{ proxy_pass http://127.0.0.1:{self.upstream}/; }}"

    def both_locations(self) -> str:
        """Both blocks in one config: restarting nginx mid-run proved flaky on
        Windows (the old instance can keep the port), and a single boot with two
        locations tests exactly the same contrast."""
        return self.good_location() + "\n        " + self.bad_location()

    def start(self) -> None:
        self.proc = subprocess.Popen(
            [str(self.binary),
             "-p", str(self.workdir) + os.sep,
             "-c", str(self.workdir / "conf" / "nginx.conf")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if not wait_for_port(self.listen):
            out = b""
            if self.proc.poll() is not None and self.proc.stdout is not None:
                out = self.proc.stdout.read()
            raise RuntimeError(
                f"nginx 启动失败:\n{out.decode('utf-8', 'replace')}\n"
                f"{(self.workdir / 'logs' / 'error.log').read_text(errors='replace') if (self.workdir / 'logs' / 'error.log').exists() else ''}")

    def stop(self) -> None:
        # Graceful first: `-s quit` tells the master to shut its workers down.
        # Terminating the master instead (what this used to do) orphans the
        # worker process on Windows — it keeps the listening socket, the next
        # run fails with "端口已被占用", and nothing in the output says why.
        pidfile = self.workdir / "logs" / "nginx.pid"
        if pidfile.exists():
            subprocess.run(
                [str(self.binary), "-p", str(self.workdir) + os.sep,
                 "-c", str(self.workdir / "conf" / "nginx.conf"), "-s", "quit"],
                capture_output=True, timeout=15,
            )
            wait_for_port_gone(self.listen, timeout=8)

        if port_open(self.listen):
            if self.proc is not None and self.proc.poll() is None:
                self._kill_tree(self.proc.pid)
            if pidfile.exists():
                try:
                    self._kill_tree(int(pidfile.read_text().strip()))
                except (OSError, ValueError):
                    pass
            wait_for_port_gone(self.listen, timeout=8)

        if self.proc is not None and self.proc.poll() is None:
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        self.proc = None
        if pidfile.exists():
            try:
                pidfile.unlink()
            except OSError:
                pass

    @staticmethod
    def _kill_tree(pid: int) -> None:
        if os.name == "nt":
            # nginx is a master plus one or more workers; /T takes the children.
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                           capture_output=True)
        else:
            try:
                os.kill(pid, 9)
            except OSError:
                pass


def fetch(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            resp.read()
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except OSError:
        return 0


def run(nginx_binary: Path, listen: int) -> int:
    if port_open(listen):
        print(f"端口 {listen} 已被占用，请先停掉相关进程")
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="dlproxy-nginx-"))
    upstream = RecordingUpstream().start()
    ngx = Nginx(nginx_binary, workdir, listen, upstream.port)
    passed = failed = 0
    try:
        print(f"==> 工作目录 {workdir}")
        print(f"==> nginx {nginx_binary}")
        print(f"==> 记录上游 127.0.0.1:{upstream.port}")

        ngx.write_conf(ngx.both_locations())
        ngx.start()
        print(f"==> nginx 就绪 :{listen}")
        print("==> 逐例比对 nginx 转发的请求行")

        for desc, request_path, expected in CASES:
            upstream.clear()
            status = fetch(f"http://127.0.0.1:{listen}{request_path}")
            got = ""
            for _ in range(40):
                got = upstream.last_path()
                if got:
                    break
                time.sleep(0.05)
            if got == expected:
                passed += 1
                print(f"  {PASS}✓{RST} {desc:<16} {got}")
            else:
                failed += 1
                print(f"  {FAIL}✗{RST} {desc:<16} (HTTP {status})")
                print(f"      期望: {expected}")
                print(f"      实收: {got}")

        # Negative control: the same request through the wrong proxy_pass form.
        # Same nginx instance, different location block.
        print("==> 反证：proxy_pass 带斜杠时必须改写 URL")
        upstream.clear()
        fetch(f"http://127.0.0.1:{listen}/bad/u/TOK/https://e.com/a//b.zip")
        mangled = ""
        for _ in range(40):
            mangled = upstream.last_path()
            if mangled:
                break
            time.sleep(0.05)
        if "https://" in mangled:
            failed += 1
            print(f"  {FAIL}✗{RST} 反证未生效，本测试失去意义: {mangled}")
        else:
            passed += 1
            print(f"  {PASS}✓{RST} 带斜杠的写法确实改写了 URL: {mangled}")
    finally:
        ngx.stop()
        upstream.close()
        shutil.rmtree(workdir, ignore_errors=True)

    print()
    if failed == 0:
        print(f"{PASS}全部 {passed} 项通过{RST} — nginx 原样转发请求 URI，链接形态安全")
        return 0
    print(f"{FAIL}{failed} 项失败{RST} — 检查 proxy_pass 是否带上了 URI 部分")
    return 1


def main() -> int:
    _force_utf8()
    parser = argparse.ArgumentParser()
    parser.add_argument("--nginx", default=None, help="nginx 可执行文件路径")
    parser.add_argument("--listen", type=int, default=18200)
    args = parser.parse_args()

    binary = nginxbin.resolve(args.nginx)
    if binary is None:
        print("找不到可用的 nginx 可执行文件；用 --nginx /path/to/nginx 指定")
        return 1
    return run(binary, args.listen)


if __name__ == "__main__":
    sys.exit(main())
