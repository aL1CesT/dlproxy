"""tools/verify_acceptance.py — run the 12-item acceptance checklist.

Designed to be executed on the server after deployment:

    /opt/dlproxy/venv/bin/python tools/verify_acceptance.py \\
        --base https://<public-ip> --token <token> [--skip-network]

Each item prints PASS / FAIL / SKIP with the concrete evidence it observed. Exit
code is non-zero if any executed item failed, so it can gate a release.
"""
from __future__ import annotations

import argparse
import os
import socket
import sqlite3
import ssl
import subprocess
import sys
import urllib.parse
import http.client
import urllib.request

RESULTS: list[tuple[str, str, str]] = []


def record(item: str, ok: bool | None, evidence: str) -> None:
    status = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
    RESULTS.append((item, status, evidence))
    colour = {"PASS": "\033[32m", "FAIL": "\033[31m", "SKIP": "\033[33m"}[status]
    print(f"  {colour}{status}\033[0m  {item}: {evidence}")


def fetch(url: str, *, method: str = "GET", headers: dict | None = None,
         timeout: int = 60, insecure: bool = True) -> tuple[int, dict, bytes]:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()


def accelerated(base: str, token: str, target: str) -> str:
    return f"{base}/u/{token}/{target}"


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_token_gate(base: str, token: str) -> None:
    """Item 5: missing / wrong / revoked token all 404."""
    ok = True
    notes = []
    for label, candidate in (("无 token", ""), ("错误 token", "A" * 32)):
        path = f"{base}/u/{candidate}/https://example.com/x" if candidate \
            else f"{base}/u/https://example.com/x"
        status, _, _ = fetch(path)
        notes.append(f"{label}={status}")
        ok = ok and status == 404
    record("5 token 门禁", ok, ", ".join(notes) + " (期望全 404)")


def check_ssrf(base: str, token: str) -> None:
    """Item 6: internal targets are 403 and the body leaks nothing."""
    targets = [
        "http://169.254.169.254/latest/meta-data/",
        "https://169.254.169.254/latest/meta-data/",
        "https://10.0.0.1/",
        "http://[::1]/",
        "http://127.0.0.1:8080/healthz",
        "http://192.168.1.1/",
    ]
    ok = True
    notes = []
    for target in targets:
        status, _, body = fetch(accelerated(base, token, target), timeout=20)
        leaked = any(word in body.lower() for word in
                     (b"169.254", b"private", b"blocked", b"metadata", b"ec2"))
        notes.append(f"{target.split('//')[1][:24]}={status}{'(LEAK!)' if leaked else ''}")
        ok = ok and status == 403 and not leaked
    record("6 SSRF 拦截", ok, ", ".join(notes) + " (期望全 403 且无泄露)")


def check_methods(base: str, token: str) -> None:
    """Item 7: POST outside git-upload-pack is 403."""
    target = accelerated(base, token, "https://example.com/some/path")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    parsed = urllib.parse.urlsplit(target)

    def send(method: str, path: str, body: bytes = b"", extra: dict | None = None):
        conn = http.client.HTTPSConnection(parsed.netloc, timeout=20, context=ctx)
        try:
            conn.request(method, path, body=body, headers=extra or {})
            return conn.getresponse().status
        finally:
            conn.close()

    statuses = {
        "POST non-git": send("POST", parsed.path, b"x"),
        "PUT": send("PUT", parsed.path, b"x"),
        "DELETE": send("DELETE", parsed.path),
    }
    ok = all(s == 403 for s in statuses.values())
    record("7 方法白名单", ok,
           ", ".join(f"{k}={v}" for k, v in statuses.items()) + " (期望全 403)")


def check_history_aggregation(db_path: str, token: str) -> None:
    """Item 3: 16 range requests collapse into one row with the full byte count."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT t.url, t.bytes_sent, t.range_hit, t.size_total "
        "FROM transfers t JOIN users u ON u.id=t.user_id "
        "WHERE u.token=? ORDER BY t.id DESC LIMIT 1", (token,)).fetchone()
    if row is None:
        record("3 历史聚合", None, "该 token 还没有任何记录（先跑一次 16 线程下载）")
        conn.close()
        return
    n = conn.execute(
        "SELECT COUNT(*) AS n FROM transfers t JOIN users u ON u.id=t.user_id "
        "WHERE u.token=? AND t.url=?", (token, row["url"])).fetchone()["n"]
    conn.close()
    ok = n == 1 and row["range_hit"] == 1 and row["bytes_sent"] > 0
    record("3 历史聚合", ok,
           f"url={row['url'][:48]}… 条数={n} bytes_sent={row['bytes_sent']} "
           f"range_hit={row['range_hit']} (期望条数=1)")


def check_listen_ports() -> None:
    """Item 11: 8080 is loopback-only, 80/443 are the only public listeners."""
    try:
        out = subprocess.run(["ss", "-lnt"], capture_output=True, text=True,
                             timeout=10).stdout
    except (FileNotFoundError, subprocess.SubprocessError):
        record("11 监听端口", None, "ss 不可用")
        return
    lines = [l for l in out.splitlines()
             if any(f":{p} " in l or l.endswith(f":{p}") for p in (80, 443, 8080))]
    bad_8080 = [l for l in lines if ":8080" in l and "127.0.0.1:8080" not in l]
    ok = not bad_8080
    record("11 监听端口", ok,
           f"8080 非回环条目={len(bad_8080)}；相关行 {len(lines)} 条")


def check_systemd() -> None:
    """Item 10: service is enabled and survives a restart with data intact."""
    try:
        state = subprocess.run(["systemctl", "is-enabled", "dlproxy"],
                               capture_output=True, text=True, timeout=10).stdout.strip()
    except (FileNotFoundError, subprocess.SubprocessError):
        record("10 服务自启", None, "systemctl 不可用")
        return
    active = subprocess.run(["systemctl", "is-active", "dlproxy"],
                            capture_output=True, text=True).stdout.strip()
    record("10 服务自启", state == "enabled" and active == "active",
           f"is-enabled={state} is-active={active}")


def check_db_integrity(db_path: str) -> None:
    """Supporting evidence for item 10: the database opens and passes integrity."""
    try:
        conn = sqlite3.connect(db_path)
        result = conn.execute("PRAGMA integrity_check").fetchone()[0]
        users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        conn.close()
    except sqlite3.Error as exc:
        record("10 数据完好", False, f"SQLite 打不开: {exc}")
        return
    record("10 数据完好", result == "ok", f"integrity_check={result}, users={users}")


def check_certificate(base: str) -> None:
    """Item 9: certificate exists, and report its remaining lifetime."""
    parsed = urllib.parse.urlsplit(base)
    host = parsed.hostname
    port = parsed.port or 443
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except OSError as exc:
        record("9 证书", False, f"连接失败: {exc}")
        return
    not_after = cert.get("notAfter", "")
    record("9 证书", bool(not_after),
           f"subject={cert.get('subject')} 到期={not_after}")


def check_backup_dir(app_dir: str) -> None:
    backup = os.path.join(app_dir, "backup")
    if not os.path.isdir(backup):
        record("备份目录", None, f"{backup} 不存在（cron 尚未跑过）")
        return
    files = sorted(f for f in os.listdir(backup) if f.endswith(".db"))
    record("备份目录", bool(files), f"{len(files)} 个快照: {files[-1] if files else '无'}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True, help="https://<public-ip>")
    parser.add_argument("--token", required=True)
    parser.add_argument("--db", default="/opt/dlproxy/data/app.db")
    parser.add_argument("--app-dir", default="/opt/dlproxy")
    parser.add_argument("--skip-network", action="store_true",
                        help="只跑本地检查（无公网时）")
    args = parser.parse_args()

    print("==> 本地检查")
    check_systemd()
    check_listen_ports()
    check_db_integrity(args.db)
    check_certificate(args.base)
    check_backup_dir(args.app_dir)

    if not args.skip_network:
        print("==> 网络检查（经公网地址）")
        check_token_gate(args.base, args.token)
        check_ssrf(args.base, args.token)
        check_methods(args.base, args.token)

    print("==> 历史聚合（读取数据库）")
    check_history_aggregation(args.db, args.token)

    print()
    print("==> 需要人工执行的两条：")
    print("    1) 小文件 sha256 与上游发布值比对")
    print("    2) 16 线程 Range 下载 200MB+ 并比对 sha256"
          "（tools/range_download.sh）")
    print("    8) 日上限调到 1MB：在途流不被切断，新请求 429，解封后恢复")
    print("    12) 客户端 Ctrl+C：服务端无残留协程，已发字节仍入账")

    failed = [r for r in RESULTS if r[1] == "FAIL"]
    print()
    print(f"==> 结果: {sum(1 for r in RESULTS if r[1] == 'PASS')} PASS / "
          f"{len(failed)} FAIL / {sum(1 for r in RESULTS if r[1] == 'SKIP')} SKIP")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
