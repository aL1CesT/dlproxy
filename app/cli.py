"""Command-line tools: ``python -m dlproxy <command>``.

    createadmin <username>     create an admin account, printing a random password
    createuser <username>      create a normal account
    setpassword <username>     reset a password
    showtoken <username>       print the current access token
    listusers                  list accounts with usage
    backup                     safe VACUUM-free SQLite backup via the backup API
    menu                       interactive menu (this is what bare `dlproxy` runs)
    set-site <url>             record the public base URL used in printed links
    alert-cert --left-hours N  mail the certificate alert (called by cert-check.sh)

Everything here runs against the same database the service uses, so it is safe
while the service is running (WAL mode, short-lived connections).
"""
from __future__ import annotations

import argparse
import asyncio
import secrets
import sqlite3
import sys

from . import auth, db, history, mailer, quota


def _find(username: str) -> sqlite3.Row | None:
    return CONN.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()


CONN: sqlite3.Connection


def cmd_create(args: argparse.Namespace) -> int:
    if _find(args.username) is not None:
        print(f"账号 {args.username} 已存在", file=sys.stderr)
        return 1
    password = args.password or secrets.token_urlsafe(12)
    token = auth.new_token()
    is_admin = 1 if args.role == "admin" else 0
    CONN.execute(
        "INSERT INTO users(username, pwd_hash, token, token_active, disabled, "
        "is_admin, created_at) VALUES(?,?,?,1,0,?,?)",
        (args.username, auth.hash_password(password), token, is_admin, db.iso_now()),
    )
    print(f"已创建{'管理员' if is_admin else '普通账号'} {args.username}")
    print(f"  密码:  {password}")
    print(f"  token: {token}")
    return 0


def cmd_setpassword(args: argparse.Namespace) -> int:
    row = _find(args.username)
    if row is None:
        print("账号不存在", file=sys.stderr)
        return 1
    password = args.password or secrets.token_urlsafe(12)
    CONN.execute("UPDATE users SET pwd_hash=? WHERE id=?",
                 (auth.hash_password(password), row["id"]))
    print(f"{args.username} 的新密码：{password}")
    return 0


def cmd_showtoken(args: argparse.Namespace) -> int:
    row = _find(args.username)
    if row is None:
        print("账号不存在", file=sys.stderr)
        return 1
    state = "有效" if row["token_active"] else "已失效"
    print(f"{args.username}\t{row['token']}\t{state}")
    return 0


def cmd_listusers(_args: argparse.Namespace) -> int:
    state = quota.check_quota(CONN)
    print(f"今日 {state.day}：{state.day_bytes} / {state.daily_limit} bytes")
    print(f"本月 {state.month}：{state.month_bytes} / {state.monthly_limit} bytes")
    print(f"{'id':>3}  {'username':<20} {'admin':<5} {'disabled':<8} {'token':<34} {'hist':>5}")
    for row in CONN.execute("SELECT * FROM users ORDER BY id"):
        n = history.count_for_user(CONN, int(row["id"]))
        print(f"{row['id']:>3}  {row['username']:<20} "
              f"{'yes' if row['is_admin'] else '-':<5} "
              f"{'yes' if row['disabled'] else '-':<8} "
              f"{row['token']:<34} {n:>5}")
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    import pathlib
    target = pathlib.Path(args.dest)
    target.parent.mkdir(parents=True, exist_ok=True)
    dst = sqlite3.connect(str(target))
    with dst:
        CONN.backup(dst)        # the sqlite backup API, never `cp`
    dst.close()
    print(f"已备份至 {target}")
    return 0


def cmd_menu(args: argparse.Namespace) -> int:
    from . import menu                     # imported lazily: the service never needs it
    return menu.run(CONN)


def cmd_setsite(args: argparse.Namespace) -> int:
    """Record the public base URL used by every printed link."""
    raw = (args.url or "").strip()
    if not raw:
        current = db.public_base(CONN)
        print(f"当前站点地址：{current}")
        return 0
    if not raw.lower().startswith(("http://", "https://")):
        raw = "https://" + raw
    raw = raw.rstrip("/")
    host = raw.split("://", 1)[-1]
    if not host or " " in raw or "/" in host:
        print("该值不是有效的站点地址（只填写协议与主机，不含路径）", file=sys.stderr)
        return 1
    db.set_setting(CONN, "public_base", raw)
    db.set_setting(CONN, "public_host", host)
    print(f"站点地址已记录：{raw}")
    return 0


def cmd_alert_cert(args: argparse.Namespace) -> int:
    """Mail the certificate alert, once per state change.

    ``cert-check.sh`` runs every six hours. A certificate that stays critical for
    two days would otherwise mail eight times, so the last state we mailed about
    is stored in ``settings.cert_alert_state`` and an unchanged state exits
    without sending. The threshold comes from ``settings.cert_warn_days`` — the
    same row the admin page writes — so that field finally drives something.

    Exit codes line up with cert-check.sh: 0 healthy or suppressed, 2 warn, 3
    critical.
    """
    conn = CONN
    left_h = float(args.left_hours)
    warn_days = db.get_int_setting(conn, "cert_warn_days", 3)
    # The script speaks hours because a 160-hour certificate makes days too
    # coarse; convert here so the panel keeps speaking days.
    warn_h = max(1, warn_days * 24)
    crit_h = max(1, warn_h // 2)

    reasons: list[str] = []
    level = 0
    if left_h <= 0:
        level = 3
        reasons.append("证书已过期")
    elif left_h <= crit_h:
        level = 3
        reasons.append(f"证书剩余 {left_h:.0f} 小时，低于 {crit_h} 小时的严重阈值")
    elif left_h <= warn_h:
        level = 2
        reasons.append(f"证书剩余 {left_h:.0f} 小时，低于 {warn_h} 小时的告警阈值")
    if getattr(args, "stamp_broken", False):
        level = 3
        reasons.append("续期自动化疑似失灵：成功签发时间戳超过 96 小时未更新")

    # The key carries both facts, so "critical because of expiry" and "critical
    # because renewals stopped" are separate events and each alerts once.
    state = f"{level}{'s' if getattr(args, 'stamp_broken', False) else ''}" \
        if level else ""
    label = "；".join(reasons) if reasons else "证书正常"

    previous = db.get_setting(conn, "cert_alert_state", "")
    if state == previous:
        if not state:
            print(f"alert-cert: 证书正常（剩余 {left_h:.0f} 小时），无需告警")
        else:
            print(f"alert-cert: {label}，状态未变，不重复发送")
        return level

    db.set_setting(conn, "cert_alert_state", state)
    if not state:
        print("alert-cert: 证书已恢复正常，状态已复位" if previous
              else f"alert-cert: {label}（剩余 {left_h:.0f} 小时），无需告警")
        return 0

    body = (
        f"{label}\n"
        f"剩余约 {left_h:.0f} 小时；告警阈值 {warn_days} 天（{warn_h} 小时），"
        f"严重阈值 {crit_h} 小时。\n\n"
        "检查续期： systemctl list-timers --all | grep certbot\n"
        "查看日志： journalctl -u snap.certbot.renew --since '-3 days'\n"
    )
    ok = asyncio.run(mailer.send_now(conn, subject="dlproxy 证书告警", body=body))
    if ok:
        print(f"alert-cert: {label}，邮件已发送")
    elif not mailer.is_configured(conn):
        print(f"alert-cert: {label}，但告警通道未配置，仅写入本日志")
    else:
        print(f"alert-cert: {label}，邮件发送失败（见 security.log）")
    return level


def _hoist_db(argv: list[str]) -> list[str]:
    """Move ``--db PATH`` in front of the sub-command, wherever it was typed.

    argparse only accepts global options before the sub-command, but
    ``--db`` reads more naturally at the end (``dlproxy listusers --db x``).
    Hoisting it keeps both spellings working instead of rejecting one with
    "unrecognized arguments".
    """
    out: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--db" and i + 1 < len(argv):
            out[0:0] = ["--db", argv[i + 1]]
            i += 2
            continue
        if argv[i].startswith("--db="):
            out[0:0] = [argv[i]]
            i += 1
            continue
        out.append(argv[i])
        i += 1
    return out


def main(argv: list[str] | None = None) -> int:
    global CONN
    parser = argparse.ArgumentParser(prog="python -m dlproxy")
    parser.add_argument("--db", default=None, help="override database path")
    sub = parser.add_subparsers(dest="cmd", required=True)

    for name, aliases in (("createadmin", ["admin"]), ("createuser", ["user"])):
        p = sub.add_parser(name, aliases=aliases)
        p.add_argument("username")
        p.add_argument("--password", default=None)
        p.set_defaults(
            func=cmd_create,
            role="admin" if name == "createadmin" else "user",
        )

    p = sub.add_parser("setpassword")
    p.add_argument("username")
    p.add_argument("--password", default=None)
    p.set_defaults(func=cmd_setpassword)

    p = sub.add_parser("showtoken")
    p.add_argument("username")
    p.set_defaults(func=cmd_showtoken)

    p = sub.add_parser("listusers")
    p.set_defaults(func=cmd_listusers)

    p = sub.add_parser("backup")
    p.add_argument("dest")
    p.set_defaults(func=cmd_backup)

    p = sub.add_parser("menu")
    p.set_defaults(func=cmd_menu)

    p = sub.add_parser("alert-cert", aliases=["alertcert"])
    p.add_argument("--left-hours", type=float, required=True,
                   help="证书剩余小时数，由 cert-check.sh 计算")
    p.add_argument("--stamp-broken", action="store_true",
                   help="续期自动化时间戳过旧（由 cert-check.sh 的 Signal B 判定）")
    p.set_defaults(func=cmd_alert_cert)

    p = sub.add_parser("set-site", aliases=["setsite"])
    p.add_argument("url", nargs="?", default="",
                   help="公网地址，例如 https://1.2.3.4；省略则打印当前值")
    p.set_defaults(func=cmd_setsite)

    args = parser.parse_args(_hoist_db(list(sys.argv[1:] if argv is None else argv)))
    CONN = db.init_db(args.db)
    try:
        return args.func(args)
    finally:
        CONN.close()


if __name__ == "__main__":                       # pragma: no cover
    raise SystemExit(main())
