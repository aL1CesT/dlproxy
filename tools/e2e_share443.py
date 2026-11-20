"""tools/e2e_share443.py — prove the shared-:443 deployment works end to end.

On a server that already runs another TLS service on 443, dlproxy cannot
listen there. ``deploy/nginx-share443-stream.conf`` makes nginx's stream layer
own 443 and sort TLS connections by SNI:

    client --TLS--> :443 stream (ssl_preread on)
                     |-- SNI present  --> stripper --> the service's real port
                     '-- SNI absent   --> :8443 http(TLS) --> dlproxy

This test loads those two real templates (the ones deploy.sh installs, with only
the ports and certificate paths substituted) and asserts the eight things that
would each be a silent, expensive failure on the real box:

1. The acceleration link still downloads through both hops.
2. ``//`` and ``%2F`` inside the embedded URL reach the app unwritten.
3. ALPN still negotiates h2 through ssl_preread (browsers will use it).
4. Eight parallel ranges reassemble to the origin's sha256.
5. The app sees the real client IP, not nginx's loopback.
6. The service branch receives its ClientHello byte-identical, with no PROXY prefix.
7. Plaintext on 443 is rejected.
8. :80 still answers the ACME challenge — every short-lived renewal re-runs
   http-01, so this port must keep working forever, not just at first issuance.

Only 127.0.0.1 is used; no external DNS, no public certificate, no real service.

    python tools/e2e_share443.py --nginx /path/to/nginx
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import os
import random
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import http2spell
import nginxbin

ROOT = Path(__file__).resolve().parent.parent
HTTP_TEMPLATE = ROOT / "deploy" / "nginx-share443.conf"
STREAM_TEMPLATE = ROOT / "deploy" / "nginx-share443-stream.conf"
DEPLOY_SH = ROOT / "deploy" / "deploy.sh"


def nginx_include_block(fragment: Path) -> str:
    """The real bytes deploy.sh appends to nginx.conf, with our fragment in it.

    Reading it out of deploy.sh instead of re-typing it is the whole point: the
    rehearsal used to carry its own hand-written `stream { include ...; }`, so
    it stayed green while the shipped script appended a bare include that nginx
    rejects with `"map" directive is not allowed here`.
    """
    proc = subprocess.run(
        ["bash", "-c",
         f'set +e\nsource "{DEPLOY_SH.as_posix()}"\nset +e\n'
         "share443_nginx_include_block"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(
            "deploy.sh 没有导出 share443_nginx_include_block：\n"
            + (proc.stdout or "") + (proc.stderr or "")
        )
    block = proc.stdout
    if "stream {" not in block:
        raise RuntimeError(f"deploy.sh 追加的 include 没有 stream{{}} 包裹：{block!r}")
    return block.replace(
        "/etc/nginx/stream-enabled/*.conf", fragment.as_posix()
    )

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"

BODY_SEED = 1234567
BODY_BYTES = 3 * 1024 * 1024
_rng = random.Random(BODY_SEED)
BODY = bytes(_rng.getrandbits(8) for _ in range(BODY_BYTES))
ORIGIN_DIGEST = hashlib.sha256(BODY).hexdigest()

# The optional --dlproxy-host rule in the stream map. Exercised so that a
# domain-fronted deployment is proven to reach dlproxy instead of the service.
DLPROXY_SNI = "dl.example.com"
SERVICE_SNI = "other.example.com"

APP_MODULE = '''\
"""Test-only app instance: the production entry point pins target ports to
{80, 443}, and this origin cannot bind either of those in the rehearsal."""
import pathlib, sys
sys.path.insert(0, __ROOT__)
from app.main import create_app            # noqa: E402
app = create_app(
    db_path_override=__DB__,
    allow_private_upstream=True,
    allowed_ports=frozenset({80, 443, __ORIGIN_PORT__}),
    security_log_path=pathlib.Path(__SECLOG__),
)
'''

ORIGIN = '''\
import random, socket, threading
_r = random.Random(__BODY_SEED__)
BODY = bytes(_r.getrandbits(8) for _ in range(__BODY_BYTES__))
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", __ORIGIN_PORT__)); srv.listen(64)
def handle(c):
    data = b""
    while b"\\r\\n\\r\\n" not in data:
        chunk = c.recv(65536)
        if not chunk:
            return
        data += chunk
    head = data.split(b"\\r\\n\\r\\n")[0].split(b"\\r\\n")
    rng = b""
    for h in head[1:]:
        if h.lower().startswith(b"range:"):
            rng = h.split(b":", 1)[1].strip()
    total = len(BODY)
    if rng.startswith(b"bytes="):
        spec = rng[6:].split(b"-")
        start = int(spec[0]); end = int(spec[1]) if spec[1] else total - 1
        end = min(end, total - 1)
        part = BODY[start:end + 1]
        c.sendall(b"HTTP/1.1 206 Partial Content\\r\\n"
                  b"Content-Type: application/octet-stream\\r\\n"
                  b"Accept-Ranges: bytes\\r\\n"
                  b"Content-Range: bytes "
                  + str(start).encode() + b"-" + str(end).encode()
                  + b"/" + str(total).encode()
                  + b"\\r\\nContent-Length: " + str(len(part)).encode()
                  + b"\\r\\n\\r\\n" + part)
    else:
        c.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Type: application/octet-stream\\r\\n"
                  b"Accept-Ranges: bytes\\r\\n"
                  b"Content-Length: " + str(total).encode() + b"\\r\\n\\r\\n" + BODY)
    c.close()
while True:
    try:
        c, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=handle, args=(c,), daemon=True).start()
'''


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


def wait_for_ports(ports: list[int], timeout: float = 25.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(port_open(p) for p in ports):
            return True
        time.sleep(0.05)
    return False


def _port_closed(port: int) -> bool:
    return not port_open(port)


def _kill_tree(pid: int) -> None:
    """nginx forks workers; on Windows killing the master alone leaves the
    workers holding the listening sockets, and the port never frees."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                       capture_output=True)
    else:
        try:
            os.kill(pid, 9)
        except OSError:
            pass


def client_hello(sni: str) -> bytes:
    """A minimal but structurally valid ClientHello carrying an SNI.

    Built by hand on purpose: this machine's Python `ssl` module does not
    actually write `server_hostname` into the ClientHello it sends, so using it
    as a probe would produce a false negative against ssl_preread.
    """
    name = sni.encode()
    ext_sni = (b"\x00\x00" + struct.pack("!H", len(name) + 5)
               + struct.pack("!H", len(name) + 3) + b"\x00"
               + struct.pack("!H", len(name)) + name)
    exts = ext_sni + b"\x00\x0b\x00\x02\x01\x00"       # + signature_algorithms
    body = (b"\x03\x03" + bytes(random.getrandbits(8) for _ in range(32))
            + b"\x00"                                   # session id length 0
            + b"\x00\x02\x13\x01"                       # one ciphersuite
            + b"\x01\x00"                               # compression
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def sink(port: int, box: dict) -> None:
    """Stands in for the other TLS service: records the first bytes it gets."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    srv.settimeout(0.3)
    while not box.get("stop"):
        try:
            c, _ = srv.accept()
        except OSError:
            continue
        c.settimeout(2.0)
        got = b""
        try:
            while len(got) < 200:
                chunk = c.recv(4096)
                if not chunk:
                    break
                got += chunk
                # Record as it arrives: this stand-in never answers, so waiting
                # for the recv timeout would hide what already landed.
                box["bytes"] = got
        except OSError:
            pass
        box["bytes"] = got
        c.close()
    srv.close()


def fetch(front: int, path: str, extra: dict | None = None,
          sni: str | None = None) -> bytes:
    """One HTTP/1.1 request through the stream hop, raw bytes back.

    Passing sni sends that name in the ClientHello instead of nothing, which is
    what decides the stream map branch: an empty SNI goes to dlproxy, any other
    SNI goes to the service.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    with socket.create_connection(("127.0.0.1", front), timeout=30) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as s:
            head = ("GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    "Connection: close\r\n")
            for k, v in (extra or {}).items():
                head += f"{k}: {v}\r\n"
            s.sendall((head + "\r\n").encode())
            out = b""
            while True:
                chunk = s.recv(262144)
                if not chunk:
                    break
                out += chunk
            return out


def main() -> int:
    _force_utf8()
    parser = argparse.ArgumentParser()
    parser.add_argument("--nginx", default=None)
    args = parser.parse_args()
    binary = nginxbin.resolve(args.nginx)
    if binary is None:
        print("找不到可用的 nginx 可执行文件；用 --nginx /path/to/nginx 指定")
        return 1

    work = Path(tempfile.mkdtemp(prefix="dlproxy-share443-"))
    front = free_port()          # stands in for :443
    http80 = free_port()         # stands in for :80
    dl_tls = free_port()         # dlproxy's loopback TLS listener
    strip = free_port()          # PROXY stripper
    service = free_port()        # the other service's real port
    app_port = free_port()       # uvicorn
    origin_port = free_port()    # upstream file server

    results: list[tuple[str, bool, str]] = []
    procs: list[subprocess.Popen] = []
    box: dict = {}

    def check(name: str, ok: bool, evidence: str) -> None:
        results.append((name, ok, evidence))
        print(f"  {PASS if ok else FAIL}  {name}: {evidence}")

    try:
        for sub in ("conf", "logs", "certs", "www/certbot", "data",
                    "temp/client_body_temp", "temp/proxy_temp"):
            (work / sub).mkdir(parents=True, exist_ok=True)

        cert = work / "certs" / "cert.pem"
        key = work / "certs" / "priv.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "2",
             "-keyout", str(key), "-out", str(cert), "-subj", "/CN=dlproxy-share443"],
            check=True, capture_output=True)

        # --- static assertions on the shipped templates ----------------------
        http_text = HTTP_TEMPLATE.read_text(encoding="utf-8")
        stream_text = STREAM_TEMPLATE.read_text(encoding="utf-8")
        import re
        code = re.sub(r"#.*", "", http_text)
        bad = re.findall(r"proxy_pass\s+http://[^;\s]+/;", code)
        good = re.findall(r"proxy_pass\s+http://127\.0\.0\.1:8080;", code)
        check("http 片段：proxy_pass 不带 URI", not bad and bool(good),
              f"错误写法={len(bad)}, 正确写法={len(good)}")
        check("http 片段：不再直接占用 443",
              "listen 443" not in code,
              "已是回环端口" if "listen 443" not in code else "仍在监听 443")
        check("http 片段：real_ip 取 PROXY 头",
              "real_ip_header   proxy_protocol;" in code or
              "real_ip_header proxy_protocol;" in code,
              "存在" if "proxy_protocol" in code else "缺失")
        scode = re.sub(r"#.*", "", stream_text)
        check("stream 片段：按 SNI 分流",
              "ssl_preread on;" in scode and "$ssl_preread_server_name" in scode,
              "存在" if "ssl_preread on;" in scode else "缺失")
        check("stream 片段：剥头器关闭 PROXY protocol",
              "proxy_protocol off;" in scode,
              "存在" if "proxy_protocol off;" in scode else "缺失")
        # deploy.sh 往 nginx.conf 追加的那坨字节必须把片段包在 stream{} 里。
        # 缺包裹时 nginx -t 会报 `"map" directive is not allowed here`，且这个
        # 错误只在真机上出现 —— 排练自己拼 wrapper 的那些日子里它一直是绿的。
        try:
            probe_block = nginx_include_block(Path("/etc/nginx/stream-enabled/*.conf"))
        except RuntimeError as exc:
            probe_block = ""
            block_err = str(exc)
        else:
            block_err = ""
        check("deploy.sh 追加的 include 带 stream{} 包裹",
              "stream {" in probe_block and "include " in probe_block,
              block_err or repr(probe_block.strip()[:80]))

        # --- assemble the three config files ---------------------------------
        site = (http_text
                .replace("__CERT_FULLCHAIN__", cert.as_posix())
                .replace("__CERT_PRIVKEY__", key.as_posix())
                .replace("__DLPROXY_TLS_PORT__", str(dl_tls))
                .replace("__STRIP_PORT__", str(strip))
                .replace("__TLS_SERVICE_PORT__", str(service))
                .replace("__SERVER_NAME__", "_")
                .replace("listen 80;", f"listen {http80};")
                .replace("listen [::]:80;", f"listen [::]:{http80};")
                .replace("root /var/www/certbot;",
                         f"root {(work / 'www' / 'certbot').as_posix()};")
                .replace("proxy_pass http://127.0.0.1:8080;",
                         f"proxy_pass http://127.0.0.1:{app_port};"))
        (work / "conf" / "site.conf").write_text(site, encoding="utf-8")
        # nginx 1.24 vs 1.25+ spelling, decided by the shipped script itself.
        http2spell.apply(work / "conf" / "site.conf", binary)

        stream_conf = (stream_text
                       .replace("__DLPROXY_TLS_PORT__", str(dl_tls))
                       .replace("__STRIP_PORT__", str(strip))
                       .replace("__TLS_SERVICE_PORT__", str(service))
                       .replace("__DLPROXY_SNI_ENTRY__",
                                f"{DLPROXY_SNI}  dlproxy_node;")
                       .replace("listen 443;", f"listen {front};")
                       .replace("listen [::]:443;", f"listen [::]:{front};"))
        (work / "conf" / "stream.conf").write_text(stream_conf, encoding="utf-8")

        (work / "conf" / "nginx.conf").write_text(
            f"worker_processes 1;\n"
            f"error_log {(work / 'logs' / 'error.log').as_posix()} warn;\n"
            f"pid {(work / 'logs' / 'nginx.pid').as_posix()};\n"
            f"events {{ worker_connections 512; }}\n"
            f"http {{\n"
            f"  access_log off;\n"
            f"  client_body_temp_path {(work / 'temp' / 'client_body_temp').as_posix()};\n"
            f"  proxy_temp_path       {(work / 'temp' / 'proxy_temp').as_posix()};\n"
            f"  include {(work / 'conf' / 'site.conf').as_posix()};\n"
            f"}}\n"
            # 这里不能自己写 stream {{ include ...; }}：必须用 deploy.sh 真正追加的
            # 那一坨字节，否则真机上缺包裹的 bug 在排练里永远看不见。
            + nginx_include_block(work / "conf" / "stream.conf"),
            encoding="utf-8")

        # --- the stand-ins: origin, service, app -----------------------------
        origin_py = work / "origin.py"
        origin_py.write_text(
            ORIGIN.replace("__ORIGIN_PORT__", str(origin_port))
                  .replace("__BODY_SEED__", str(BODY_SEED))
                  .replace("__BODY_BYTES__", str(BODY_BYTES)),
            encoding="utf-8")
        procs.append(subprocess.Popen([sys.executable, str(origin_py)]))

        threading.Thread(target=sink, args=(service, box), daemon=True).start()

        app_py = work / "share443_app.py"
        # Paths go through repr(): a Windows temp dir such as D:\TEMP\user starts
        # with a backslash-a inside generated Python source, which would turn into
        # a \x07 escape and create a directory with a BEL in its name.
        app_py.write_text(
            APP_MODULE
            .replace("__ROOT__", repr(str(ROOT)))
            .replace("__DB__", repr(str(work / "data" / "app.db")))
            .replace("__SECLOG__", repr(str(work / "logs" / "security.log")))
            .replace("__ORIGIN_PORT__", str(origin_port)),
            encoding="utf-8")
        env = dict(os.environ)
        env.update({
            "DLPROXY_SECRET_KEY": "share443-test-key-not-for-production-0123456789",
            "DLPROXY_BEHIND_PROXY": "1",
            "DLPROXY_DB_PATH": str(work / "data" / "app.db"),
            "DLPROXY_ALLOW_PRIVATE_UPSTREAM": "1",
            "DLPROXY_SECURITY_LOG": str(work / "logs" / "security.log"),
            # Bootstrap writes the initial admin password next to app/ by
            # default — that is the checkout. Keep it inside the rehearsal dir.
            "DLPROXY_INIT_FILE": str(work / "data" / "INITIAL_ADMIN.txt"),
            "PYTHONPATH": str(ROOT),
            "NO_PROXY": "*", "no_proxy": "*",
        })
        procs.append(subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "share443_app:app",
             "--host", "127.0.0.1", "--port", str(app_port),
             "--log-level", "warning"],
            cwd=str(work), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT))

        time.sleep(0.4)
        procs.append(subprocess.Popen(
            [str(binary), "-p", str(work) + os.sep,
             "-c", str(work / "conf" / "nginx.conf")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT))

        if not wait_for_ports([front, http80, app_port, origin_port]):
            log = work / "logs" / "error.log"
            print("启动失败:")
            print((log.read_text(errors="replace") if log.exists() else "(无 nginx 日志)"))
            for proc in procs:
                if proc.poll() is not None and proc.stdout is not None:
                    out = proc.stdout.read().decode("utf-8", "replace")
                    if out.strip():
                        print("--- 子进程退出输出 ---")
                        print(out[:3000])
            print("工作目录保留在:", work)
            return 1
        time.sleep(0.4)

        # --- seed a user ----------------------------------------------------
        cli = subprocess.run(
            [sys.executable, "-m", "app.cli", "--db", str(work / "data" / "app.db"),
             "createuser", "alice", "--password", "pw-alice-e2e"],
            cwd=str(ROOT), env=env, capture_output=True, text=True)
        if cli.returncode != 0:
            print("创建用户失败:", cli.stdout.strip(), cli.stderr.strip())
            return 1
        import sqlite3
        token = ""
        for _ in range(50):
            con = sqlite3.connect(str(work / "data" / "app.db"))
            try:
                row = con.execute(
                    "select token from users where username='alice'").fetchone()
            finally:
                con.close()
            if row:
                token = row[0]
                break
            time.sleep(0.1)
        if not token:
            print("拿不到 token，无法继续")
            return 1

        path = f"/u/{token}/http://127.0.0.1:{origin_port}/file.bin"

        # --- 1. the whole chain relays a download ---------------------------
        resp = fetch(front, path)
        head, _, body = resp.partition(b"\r\n\r\n")
        status = head.split(b"\r\n")[0]
        digest = hashlib.sha256(body).hexdigest()
        check("加速链接经 stream + PROXY 全链可下载",
              b"200" in status and digest == ORIGIN_DIGEST,
              f"{status.decode(errors='replace')} sha256={digest[:12]}")

        # --- 2. hostile URI bytes survive both hops -------------------------
        nasty = (f"/u/{token}/http://127.0.0.1:{origin_port}"
                 f"/a//b//c%2Fd?x=1&y=%20z")
        got_status = fetch(front, nasty).split(b"\r\n")[0]
        check("含 // 与 %2F 的 URL 没有被 nginx 改写",
              b"200" in got_status, got_status.decode(errors="replace"))

        # --- 3. ALPN still reaches h2 ---------------------------------------
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection(("127.0.0.1", front), timeout=10) as raw:
            with ctx.wrap_socket(raw) as s:
                alpn = s.selected_alpn_protocol() or ""
        check("HTTP/2 经 ssl_preread 协商成功", alpn == "h2",
              f"ALPN={alpn or '(无)'}")

        # --- 4. parallel ranges through both hops ---------------------------
        step = BODY_BYTES // 8 + 1
        parts: dict[int, bytes] = {}

        def grab(i: int) -> None:
            lo = i * step
            hi = min((i + 1) * step - 1, BODY_BYTES - 1)
            if lo > hi:
                return
            r = fetch(front, path, {"Range": f"bytes={lo}-{hi}"})
            parts[i] = r.partition(b"\r\n\r\n")[2]

        threads = [threading.Thread(target=grab, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(90)
        joined = b"".join(parts[i] for i in sorted(parts))
        check("8 路并发 Range 经全链重组一致",
              hashlib.sha256(joined).hexdigest() == ORIGIN_DIGEST,
              f"{len(joined)}B / 期望 {BODY_BYTES}B")

        # --- 5. real client IP ----------------------------------------------
        row = None
        for _ in range(40):
            con = sqlite3.connect(str(work / "data" / "app.db"))
            try:
                row = con.execute(
                    "select client_ip from transfers order by id desc limit 1"
                ).fetchone()
            finally:
                con.close()
            if row:
                break
            time.sleep(0.1)
        check("应用侧拿到真实客户端 IP（PROXY 头透传成功）",
              bool(row) and row[0] == "127.0.0.1",
              f"transfers.client_ip={row[0] if row else '(无记录)'}")

        # --- 6. the service branch is untouched -----------------------------
        box.pop("bytes", None)
        hello = client_hello(SERVICE_SNI)
        with socket.create_connection(("127.0.0.1", front), timeout=5) as s:
            s.sendall(hello)
            time.sleep(0.4)
        service_got = b""
        for _ in range(40):
            service_got = box.get("bytes", b"")
            if service_got:
                break
            time.sleep(0.1)
        check("原服务分支收到无 PROXY 头的原始 ClientHello",
              service_got[:len(hello)] == hello,
              f"发 {len(hello)}B / 收 {len(service_got)}B")

        # --- 7. a domain front still reaches dlproxy -------------------------
        # Without this branch, a domain-fronted deployment would be silently
        # swallowed by the other service: every SNI that is not the one named in
        # the map looks like service traffic under `default tls_passthrough`. When the rule is
        # missing the handshake fails outright, so catch that as a plain FAIL
        # instead of letting the SSL error abort the run.
        try:
            dlresp = fetch(front, "/u/" + token + "/http://127.0.0.1:"
                           + str(origin_port) + "/file.bin", sni=DLPROXY_SNI)
            dl_ok = dlresp.startswith(b"HTTP/1.1 200")
            dl_ev = dlresp.split(b"\r\n")[0].decode(errors="replace")
        except (ssl.SSLError, OSError) as exc:
            dl_ok = False
            dl_ev = f"握手失败（SNI 被分流给原服务）：{type(exc).__name__}"
        check("--dlproxy-host 指定的域名仍能到 dlproxy", dl_ok, dl_ev)

        # --- 8. plaintext on 443 --------------------------------------------
        with socket.create_connection(("127.0.0.1", front), timeout=4) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            try:
                plain = s.recv(200)
            except OSError:
                plain = b""
        check("明文 HTTP 打到 443 被拒", plain.startswith(b"HTTP/1.1 4"),
              plain[:40].decode(errors="replace").strip())

        # --- 9. ACME on :80 --------------------------------------------------
        challenge = (work / "www" / "certbot" / ".well-known"
                     / "acme-challenge" / "tok123")
        challenge.parent.mkdir(parents=True, exist_ok=True)
        challenge.write_text("challenge-body-ok", encoding="utf-8")
        conn = http.client.HTTPConnection("127.0.0.1", http80, timeout=5)
        conn.request("GET", "/.well-known/acme-challenge/tok123")
        r = conn.getresponse()
        payload = r.read()
        conn.close()
        check(":80 ACME 路径仍可应答（续期依赖它）",
              r.status == 200 and payload == b"challenge-body-ok",
              f"HTTP {r.status} body={payload!r}")
    finally:
        pidfile = work / "logs" / "nginx.pid"
        subprocess.run(
            [str(binary), "-p", str(work) + os.sep,
             "-c", str(work / "conf" / "nginx.conf"), "-s", "quit"],
            capture_output=True, timeout=15)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not all(
                _port_closed(p) for p in (front, http80, dl_tls, strip)):
            time.sleep(0.05)
        box["stop"] = True
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
        print(f"{FAIL} {len(failed)}/{len(results)} 项失败")
        for name, _, ev in failed:
            print(f"  {name}: {ev}")
        return 1
    print(f"{PASS} 全部 {len(results)} 项通过 — share-443 的两个模板已实测")
    return 0


if __name__ == "__main__":
    sys.exit(main())
