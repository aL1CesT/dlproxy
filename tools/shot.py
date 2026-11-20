"""tools/shot.py — render the UI to PNGs for visual review.

The pages are the only part of this project a person actually looks at, so they
get a screenshot pass rather than only an assertion pass: start the app on a
throwaway database, log in through the real form, and capture login / home /
admin / breaker at desktop and phone widths.

    python tools/shot.py [--out DIR] [--keep]

Writes to ``shots/`` next to the repo root by default.
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_for_port(port: int, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(ROOT / "shots"))
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="dlproxy-shots-"))
    db_path = work / "app.db"
    port = free_port()

    # Seed: an admin with a known password, one normal user, some history rows,
    # and a quota that is close to its limit so the progress bars are not empty.
    seed = f'''
import sys
sys.path.insert(0, {str(ROOT)!r})
from app import auth, db, history, quota

conn = db.init_db({str(db_path)!r})
conn.execute("DELETE FROM users")
conn.execute("DELETE FROM transfers")
conn.execute("DELETE FROM counters")
conn.execute(
    "INSERT INTO users(username, pwd_hash, token, token_active, disabled,"
    " is_admin, created_at) VALUES(?,?,?,1,0,1,?)",
    ("admin", auth.hash_password("demo-password-123"),
     "aB3dEfGh1JkLmNoP2qRsTuVwXyZ45678", "2026-11-01T00:00:00.000Z"))
conn.execute(
    "INSERT INTO users(username, pwd_hash, token, token_active, disabled,"
    " is_admin, created_at) VALUES(?,?,?,1,0,0,?)",
    ("alice", auth.hash_password("demo-password-123"),
     "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp", "2026-11-02T00:00:00.000Z"))
conn.execute(
    "INSERT INTO users(username, pwd_hash, token, token_active, disabled,"
    " is_admin, created_at) VALUES(?,?,?,1,0,1,?)",
    ("bob", auth.hash_password("demo-password-123"),
     "Mm1Nn2Bb3Vv4Cc5Xx6Zz7Ll8Kk9Jj0Hh", "2026-11-03T00:00:00.000Z"))

uid = conn.execute("SELECT id FROM users WHERE username='alice'").fetchone()["id"]
rows = [
    ("https://github.com/torvalds/linux/releases/download/v6.12/linux-6.12.tar.gz",
     200, 2147483648, 2147483648, "2026-11-18T02:11:04.120Z", 0, 184320),
    ("https://mirrors.tuna.tsinghua.edu.cn/ubuntu-releases/24.04/ubuntu-24.04.1-live-server-arm64.iso",
     206, 3221225472, 3221225472, "2026-11-18T03:42:11.004Z", 1, 631400),
    ("https://example.com/assets/dataset-2026.tar.zst",
     200, 524288000, 524288000, "2026-11-17T22:05:51.900Z", 0, 41200),
    ("https://cdn.example.org/firmware/device-1.4.2.img",
     499, None, 18874368, "2026-11-17T20:31:02.500Z", 1, 3050),
    ("https://github.com/owner/repo/archive/refs/heads/main.zip",
     404, None, 0, "2026-11-17T19:12:44.000Z", 0, 240),
    ("https://example.net/big/archive-2026-11.tar",
     200, 10737418240, 10737418240, "2026-11-17T16:44:10.000Z", 1, 1802400),
]
for url, status, size, sent, started, rng, dur in rows:
    conn.execute(
        "INSERT INTO transfers(user_id, url, status_code, size_total, bytes_sent,"
        " started_at, last_at, range_hit, client_ip, user_agent, xff_raw, duration_ms)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (uid, url, status, size, sent, started, started, rng, "203.0.113.42",
         "aria2/1.37.0", "", dur))
    conn.execute(
        "INSERT INTO counters(day, bytes) VALUES(?,?)"
        " ON CONFLICT(day) DO UPDATE SET bytes=bytes+excluded.bytes",
        (started[:10], sent))

db.set_setting(conn, "daily_limit_bytes", str(100 * 1024**3))
db.set_setting(conn, "monthly_limit_bytes", str(2000 * 1024**3))
db.set_setting(conn, "admin_path", "f3a91c07b58d42e6a0c1d9f4b27e8a56")
conn.commit()
print("seeded", db.get_setting(conn, "admin_path"))
'''
    subprocess.run([sys.executable, "-c", seed], check=True, cwd=str(ROOT))

    env = dict(os.environ)
    env["DLPROXY_SECRET_KEY"] = "shots-secret-key"
    env["DLPROXY_BEHIND_PROXY"] = "0"
    app_code = f'''
import sys
sys.path.insert(0, {str(ROOT)!r})
import uvicorn
from app.main import create_app
app = create_app(db_path_override={str(db_path)!r},
                 allow_private_upstream=True,
                 security_log_path=__import__("pathlib").Path({str(work / "sec.log")!r}))
uvicorn.run(app, host="127.0.0.1", port={port}, log_level="error", access_log=False)
'''
    app_file = work / "serve.py"
    app_file.write_text(app_code, encoding="utf-8")
    proc = subprocess.Popen([sys.executable, str(app_file)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_for_port(port):
        proc.kill()
        print("应用启动失败")
        return 1

    admin_path = "f3a91c07b58d42e6a0c1d9f4b27e8a56"
    base = f"http://127.0.0.1:{port}"
    shots: list[tuple[str, str, str, int, int]] = [
        # (name, url, auth as, width, height)
        ("01-login", f"{base}/login", "", 1280, 900),
        ("02-home", f"{base}/", "admin", 1280, 1200),
        ("03-home-mobile", f"{base}/", "admin", 390, 1000),
        ("04-admin", f"{base}/{admin_path}", "admin", 1280, 2000),
        ("05-admin-mobile", f"{base}/{admin_path}", "admin", 390, 1400),
        ("06-history", f"{base}/{admin_path}/history/2", "admin", 1280, 900),
        ("07-login-mobile", f"{base}/login", "", 390, 800),
    ]

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            for name, url, who, width, height in shots:
                context = browser.new_context(viewport={"width": width,
                                                        "height": height},
                                              device_scale_factor=2)
                page = context.new_page()
                if who:
                    page.goto(f"{base}/login", wait_until="networkidle")
                    page.fill('input[name="username"]', who)
                    page.fill('input[name="password"]', "demo-password-123")
                    page.click('button[type="submit"]')
                    page.wait_for_load_state("networkidle")
                page.goto(url, wait_until="networkidle")
                page.wait_for_timeout(300)
                target = out / f"{name}.png"
                page.screenshot(path=str(target), full_page=(height > 1200))
                print(f"  {target.name}  {width}x{height}")
                context.close()

            # The breaker page is reached by exhausting the quota, so it gets its
            # own context rather than a URL.
            context = browser.new_context(viewport={"width": 1280, "height": 700},
                                          device_scale_factor=2)
            page = context.new_page()
            page.goto(f"{base}/login", wait_until="networkidle")
            page.fill('input[name="username"]', "admin")
            page.fill('input[name="password"]', "demo-password-123")
            page.click('button[type="submit"]')
            page.wait_for_load_state("networkidle")
            import sqlite3
            conn = sqlite3.connect(db_path)
            conn.execute("INSERT INTO counters(day, bytes) VALUES(?, ?) "
                         "ON CONFLICT(day) DO UPDATE SET bytes=excluded.bytes",
                         (time.strftime("%Y-%m-%d"), 200 * 1024**3))
            conn.commit()
            conn.close()
            page.goto(f"{base}/u/Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp/https://example.com/x",
                      wait_until="networkidle")
            page.screenshot(path=str(out / "08-breaker.png"))
            print("  08-breaker.png  1280x700")
            context.close()
            browser.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if not args.keep:
            import shutil
            shutil.rmtree(work, ignore_errors=True)

    print(f"==> 截图写入 {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
