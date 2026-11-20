"""Interactive console menu — what you get when you type ``dlproxy`` bare.

The service never enters this module. systemd runs ``python -m app`` with no
arguments, and ``app/__main__.py`` turns that into uvicorn; only the ``menu``
sub-command lands here. The ``/usr/local/bin/dlproxy`` wrapper supplies that
sub-command when it is called with no arguments, so typing ``dlproxy`` opens
the menu while ``dlproxy createuser alice`` still does the obvious thing.

Everything runs against the live database through the same helpers the web
admin page uses, so a change made here appears on the admin page immediately
and vice versa. Nothing here requires stopping the service: the connection is
short-lived and SQLite runs in WAL mode.

Design constraint: a terminal menu must survive anything. Every action is
wrapped, ``Ctrl-C`` exits cleanly, and EOF on stdin (``dlproxy < /dev/null``)
falls through to a plain exit rather than a traceback.
"""
from __future__ import annotations

import argparse
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import unicodedata
from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path
from typing import TextIO

from . import auth, db, history, quota

BANNER = "dlproxy 管理控制台"

# Menu geometry. The box is drawn at MENU_WIDTH columns of *display* width, so
# every row stays aligned no matter how many two-column characters a label has.
MENU_MIN_WIDTH = 40
MENU_MAX_WIDTH = 60
MENU_WIDTH = 46

# Colour is opt-in, and only when a human is actually looking: a 256-colour
# escape in a log file is noise, and `TERM=dumb` means the terminal cannot even
# move the cursor. `_display_width` strips these before measuring, so painting a
# label can never shift the box.
_ANSI = re.compile(r"\033\[[0-9;]*m")
DIM = "\033[2m"
BOLD = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"


class _Quit(Exception):
    """Raised when the input stream ends without an answer."""


class _Cancel(Exception):
    """Raised when a required field is left blank; abandons just this action."""


# ---------------------------------------------------------------------------
# Console plumbing
# ---------------------------------------------------------------------------

class Console:
    """Input/output indirection so tests can script a session."""

    def __init__(self, stdin: TextIO | None = None, stdout: TextIO | None = None,
                 *, colour: bool | None = None):
        self._in = stdin if stdin is not None else sys.stdin
        self.out: TextIO = stdout if stdout is not None else sys.stdout
        self._interactive = bool(getattr(self._in, "isatty", lambda: False)())
        # Colour needs three things: a terminal on stdout (not just stdin — the
        # menu is often piped through `tee`), no NO_COLOR, and a TERM that can
        # actually render attributes. Deploy scripts run under systemd with
        # TERM unset, where escape codes would end up in journald verbatim.
        if colour is None:
            target = stdout if stdout is not None else sys.stdout
            colour = (
                bool(getattr(target, "isatty", lambda: False)())
                and not os.environ.get("NO_COLOR")
                and os.environ.get("TERM", "") not in ("", "dumb")
            )
        self.colour = bool(colour)

    def write(self, text: str = "") -> None:
        self.out.write(text + "\n")

    def paint(self, text: str, code: str) -> str:
        """Wrap ``text`` in ``code`` when colour is on, else return it as-is."""
        if not self.colour or not code:
            return text
        return f"{code}{text}{RESET}"

    def ask(self, prompt: str, default: str = "", *, allow_empty: bool = False) -> str:
        suffix = f"[{default}] " if default else ""
        self.out.write(f"{prompt}{suffix}")
        self.out.flush()
        line = self._in.readline()
        if line == "":                      # EOF: the caller treats it as a quit
            raise _Quit
        # A terminal echoes the user's Enter; a pipe does not, so the next line
        # of output would be glued onto the prompt. Emit that newline ourselves
        # when input is not interactive (scripted sessions, `printf | dlproxy`).
        if not self._interactive:
            self.out.write("\n")
        answer = line.strip()
        if answer == "":
            if default or allow_empty:
                return default
            raise _Cancel
        return answer


def _display_width(text: str) -> int:
    """Terminal columns used by ``text``.

    Chinese characters occupy two columns. ``len()`` counts one, so every table
    built with ``str.ljust`` misaligns the moment a label is Chinese — which is
    all of them here. East-Asian Width W/F = 2, combining marks = 0.
    """
    width = 0
    for ch in _ANSI.sub("", text):
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


def _pad(text: str, width: int, *, align: str = "left") -> str:
    """Pad ``text`` to ``width`` display columns."""
    gap = max(0, width - _display_width(text))
    if align == "right":
        return " " * gap + text
    if align == "center":
        left = gap // 2
        return " " * left + text + " " * (gap - left)
    return text + " " * gap


def _rule(width: int, ch: str = "─") -> str:
    return ch * width


ELLIPSIS = "…"


def _fit(text: str, width: int) -> str:
    """Truncate ``text`` to ``width`` display columns, marking the cut.

    ``_pad`` only ever adds spaces, so every field it laid out assumed it was
    already short enough. ``settings.public_base`` is not: it holds whatever the
    operator typed into menu item 11 or passed to ``dlproxy set-site``, and a
    long hostname pushed the one line that is *input* two columns past every
    border around it. Truncation belongs here rather than at the write, because
    a value stored short is a value lost.
    """
    if _display_width(text) <= width:
        return text
    keep = max(0, width - _display_width(ELLIPSIS))
    out = ""
    used = 0
    for ch in _ANSI.sub("", text):
        step = 0 if unicodedata.combining(ch) else (
            2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1)
        if used + step > keep:
            break
        out += ch
        used += step
    return out + ELLIPSIS


def menu_width() -> int:
    """Box width in display columns, clamped to a range that always fits.

    A 30-column box wraps the longest label ("服务状态与管理入口" is 20 columns
    plus 8 of indent, so 40 is the floor). Wider than 60 and the menu stops
    looking like one object.

    The number returned is the count of ``─`` between the corners, so the drawn
    box is two columns wider; the docs quote 42–62 for that reason. ``shutil``
    answers 80 when stdout is not a terminal, which is why the fallback below
    has to be supplied explicitly — without it every piped run would grow.
    """
    try:
        # fallback keeps the documented 46 columns when stdout is not a
        # terminal; without it shutil answers 80 and every piped run grows.
        columns = shutil.get_terminal_size(fallback=(MENU_WIDTH + 4, 24)).columns
    except (OSError, ValueError):           # pragma: no cover - defensive
        columns = MENU_WIDTH + 4
    return max(MENU_MIN_WIDTH, min(MENU_MAX_WIDTH, columns - 4))


def _section(con: Console, title: str) -> None:
    """Print ``── 标题 ───────`` sized to the box, so every section agrees."""
    span = menu_width() - 2
    head = f"── {title} "
    con.write("  " + head + _rule(max(0, span - _display_width(head)), "─"))


def _field(con: Console, name: str, value: str, *, indent: int = 2) -> None:
    """Aligned ``名称    值`` row; names are padded to 8 display columns."""
    con.write(" " * indent + _pad(name, 8) + value)


def human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{n} B"                          # pragma: no cover - loop always returns


def _find(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()


def site_base(conn: sqlite3.Connection) -> tuple[str, bool]:
    """``(base_url, is_placeholder)`` for links printed by the console."""
    base = db.public_base(conn)
    return base, db.is_placeholder_base(base)


def init_file_path() -> Path:
    """Where ``_bootstrap()`` puts the first-boot password file."""
    override = os.environ.get("DLPROXY_INIT_FILE", "").strip()
    return Path(override) if override else db.APP_ROOT / "INITIAL_ADMIN.txt"


def _link(conn: sqlite3.Connection, suffix: str) -> str:
    return f"{site_base(conn)[0]}/{suffix}"


def _print_placeholder_hint(con: Console) -> None:
    con.write("  站点地址尚未记录（部署脚本未写入数据库）。可执行以下命令补录：")
    con.write("    sudo dlproxy set-site https://<域名或IP>")


def _ask_username(con: Console, prompt: str = "用户名") -> str:
    name = con.ask(prompt).strip()
    if not name:
        raise _Cancel
    return name


def _ask_password(con: Console, conn: sqlite3.Connection) -> str:
    """Password for a new account, or a generated one when left blank."""
    while True:
        raw = con.ask("密码（留空则自动生成，至少 8 位）", allow_empty=True)
        if not raw:
            return secrets.token_urlsafe(12)
        if len(raw) < 8:
            con.write("  密码长度不足 8 位")
            continue
        return raw


# ---------------------------------------------------------------------------
# Actions. Each returns None and prints its own result.
# ---------------------------------------------------------------------------

def action_list(conn: sqlite3.Connection, con: Console) -> None:
    _section(con, "账号列表")
    rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    if not rows:
        con.write("    （尚无账号，请先执行「新建管理员」）")
        return
    headers = ("ID", "用户名", "角色", "状态", "历史")
    cells: list[tuple[str, ...]] = []
    for row in rows:
        role = "管理员" if row["is_admin"] else "普通"
        if row["disabled"]:
            state = "已禁用"
        elif row["token_active"]:
            state = "正常"
        else:
            state = "token停"
        n = history.count_for_user(conn, int(row["id"]))
        cells.append((str(row["id"]), str(row["username"]), role, state, str(n),
                      str(row["token"])))
    widths = [_display_width(h) for h in headers]
    for cell in cells:
        for i in range(len(headers)):
            widths[i] = max(widths[i], _display_width(cell[i]))
    align = ("right", "left", "left", "left", "right")

    con.write("  " + "  ".join(
        _pad(h, widths[i], align=align[i]) for i, h in enumerate(headers)) + "  token")
    con.write("  " + _rule(2 * (sum(widths) + 2 * (len(headers) - 1))))
    for cell in cells:
        con.write("  " + "  ".join(
            _pad(cell[i], widths[i], align=align[i]) for i in range(len(headers)))
            + "  " + cell[-1])


def _create(conn: sqlite3.Connection, con: Console, *, admin: bool) -> None:
    name = _ask_username(con)
    if _find(conn, name) is not None:
        con.write(f"账号 {name} 已存在，未做改动")
        return
    password = _ask_password(con, conn)
    token = auth.new_token()
    conn.execute(
        "INSERT INTO users(username, pwd_hash, token, token_active, disabled, "
        "is_admin, created_at) VALUES(?,?,?,1,0,?,?)",
        (name, auth.hash_password(password), token, 1 if admin else 0, db.iso_now()),
    )
    con.write(f"已创建{'管理员' if admin else '普通账号'} {name}")
    con.write(f"  密码:  {password}")
    con.write(f"  token: {token}")
    base, placeholder = site_base(conn)
    if placeholder:
        con.write(f"  链接:  {base}/u/{token}/<原始链接>")
        _print_placeholder_hint(con)
    else:
        con.write(f"  链接:  {base}/u/{token}/<原始链接>")
        con.write("         （将 <原始链接> 替换为待下载文件的完整地址）")
    con.write("  密码仅在此处显示一次；如需重置请用「重置密码」，token 可随时用「查看 token」查看")


def action_create_user(conn: sqlite3.Connection, con: Console) -> None:
    _create(conn, con, admin=False)


def action_create_admin(conn: sqlite3.Connection, con: Console) -> None:
    _create(conn, con, admin=True)


def action_set_password(conn: sqlite3.Connection, con: Console) -> None:
    row = _find(conn, _ask_username(con))
    if row is None:
        con.write("账号不存在")
        return
    password = con.ask("新密码（留空则自动生成）", allow_empty=True) or secrets.token_urlsafe(12)
    if len(password) < 8:
        con.write("密码长度不足 8 位，未改动")
        return
    conn.execute("UPDATE users SET pwd_hash=? WHERE id=?",
                 (auth.hash_password(password), row["id"]))
    con.write(f"{row['username']} 的新密码：{password}")


def action_show_token(conn: sqlite3.Connection, con: Console) -> None:
    row = _find(conn, _ask_username(con))
    if row is None:
        con.write("账号不存在")
        return
    state = "有效" if row["token_active"] else "已失效"
    base, placeholder = site_base(conn)
    con.write(f"账号   {row['username']}")
    con.write(f"token  {row['token']}  [{state}]")
    con.write(f"链接   {base}/u/{row['token']}/<原始链接>")
    if placeholder:
        _print_placeholder_hint(con)
    else:
        con.write("       将 <原始链接> 替换为待下载文件的完整地址，例如：")
        con.write(f"       {base}/u/{row['token']}/https://example.com/big.iso")


def action_reset_token(conn: sqlite3.Connection, con: Console) -> None:
    row = _find(conn, _ask_username(con))
    if row is None:
        con.write("账号不存在")
        return
    token = auth.reset_token(conn, int(row["id"]))
    base, _placeholder = site_base(conn)
    con.write(f"{row['username']} 的新 token：{token}")
    con.write(f"新链接：{base}/u/{token}/<原始链接>")
    con.write("旧 token 立即失效，此前发出的链接一并失效")


def action_toggle_user(conn: sqlite3.Connection, con: Console) -> None:
    row = _find(conn, _ask_username(con))
    if row is None:
        con.write("账号不存在")
        return
    enable = bool(row["disabled"])
    conn.execute("UPDATE users SET disabled=? WHERE id=?",
                 (0 if enable else 1, row["id"]))
    con.write(f"已{'启用' if enable else '禁用'}账号 {row['username']}")


def action_usage(conn: sqlite3.Connection, con: Console) -> None:
    state = quota.usage(conn)

    def bar(used: int, limit: int) -> str:
        if limit <= 0:
            return "不限"
        return f"{used / limit * 100:.1f}%"

    _section(con, "用量与限额")
    _field(con, "今日", f"{state.day}  {human_bytes(state.day_bytes)} / "
                             f"{human_bytes(state.daily_limit)}  "
                             f"({bar(state.day_bytes, state.daily_limit)})")
    _field(con, "本月", f"{state.month}  {human_bytes(state.month_bytes)} / "
                             f"{human_bytes(state.monthly_limit)}  "
                             f"({bar(state.month_bytes, state.monthly_limit)})")
    if state.bypassed:
        status = con.paint("熔断已临时解除", YELLOW)
        _field(con, "状态", f"{status}，至 {state.bypass_until:%Y-%m-%d %H:%M} UTC")
    elif state.blocked:
        status = con.paint("熔断中", YELLOW)
        _field(con, "状态", f"{status}（{state.reason()}）")
    else:
        _field(con, "状态", con.paint("未触发熔断", GREEN))

    con.write("")
    _section(con, "按账号累计（全部历史，非当日）")
    rows = list(conn.execute("SELECT id, username FROM users ORDER BY id"))
    if not rows:
        con.write("    （尚无账号）")
        return
    name_w = max(6, max(_display_width(str(r["username"])) for r in rows))
    total_w = 12
    for row in rows:
        row_bytes = conn.execute(
            "SELECT COALESCE(SUM(bytes_sent),0) AS b FROM transfers WHERE user_id=?",
            (row["id"],)).fetchone()["b"]
        n = history.count_for_user(conn, int(row["id"]))
        con.write("    " + _pad(str(row["username"]), name_w)
                  + "  " + _pad(human_bytes(int(row_bytes)), total_w, align="right")
                  + "  " + _pad(f"{n} 条", 8, align="right"))


def action_backup(conn: sqlite3.Connection, con: Console) -> None:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    default = str(db.db_path().parent.parent / "backup" / f"app-{stamp}.db")
    dest = con.ask("备份路径", default=default)
    target = Path(dest)
    target.parent.mkdir(parents=True, exist_ok=True)
    dst = sqlite3.connect(str(target))
    try:
        with dst:
            conn.backup(dst)                 # the backup API, never a file copy
    finally:
        dst.close()
    con.write(f"已备份至 {target}（{human_bytes(target.stat().st_size)}）")


def _conn_path(conn: sqlite3.Connection) -> str:
    """The file this connection is actually attached to.

    ``db.db_path()`` reads the environment, which ignores ``--db``. PRAGMA
    ``database_list`` reports what SQLite really opened — right for the menu
    (which can be pointed at any file) and for tests using a temp database.
    """
    for row in conn.execute("PRAGMA database_list"):
        if row["name"] == "main":
            return row["file"] or ":memory:"
    return str(db.db_path())                        # pragma: no cover


def _service_state() -> str:
    if sys.platform != "linux":
        return "非 Linux 环境，已跳过"
    try:
        done = subprocess.run(["systemctl", "is-active", "dlproxy"],
                              capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"无法查询 systemctl：{exc}"
    return (done.stdout or done.stderr).strip() or "unknown"


def action_status(conn: sqlite3.Connection, con: Console) -> None:
    state = quota.usage(conn)
    users = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    admin_path = db.get_setting(conn, "admin_path", "")
    base, placeholder = site_base(conn)
    init_file = init_file_path()

    _section(con, "服务状态")
    state_text = _service_state()
    _field(con, "状态", con.paint(state_text, GREEN if state_text == "active" else YELLOW))
    _field(con, "数据库", _conn_path(conn))

    con.write("")
    _section(con, "访问入口")
    if admin_path:
        _field(con, "管理页", f"{base}/{admin_path}")
        con.write(" " * 10 + "该路径可在管理页重新生成")
    else:
        _field(con, "管理页", "尚未生成，服务启动后写入初始账号文件")
    _field(con, "首页", f"{base}/")
    if placeholder:
        con.write("")
        _print_placeholder_hint(con)

    con.write("")
    _section(con, "用量统计")
    _field(con, "今日", f"{human_bytes(state.day_bytes)} / {human_bytes(state.daily_limit)}")
    _field(con, "本月", f"{human_bytes(state.month_bytes)} / {human_bytes(state.monthly_limit)}")
    _field(con, "账号", f"{users} 个")

    con.write("")
    _section(con, "初始账号文件")
    if init_file.exists():
        _field(con, "路径", f"{init_file}")
        con.write(" " * 10 + con.paint("（仍存在，确认密码后建议删除）", YELLOW))
        _field(con, "查看", f"sudo cat {init_file}")
        _field(con, "删除", f"sudo rm {init_file}")
    else:
        _field(con, "路径", f"{init_file}  （已删除）")


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------

# (key, label, group, handler). The group index travels with the action
# instead of living in a second table beside it: when the two drifted, a new
# item silently re-opened a group header that had already been drawn.
Action = tuple[str, str, int, Callable[[sqlite3.Connection, Console], None]]


def _actions() -> list[Action]:
    actions: list[Action] = [
        ("1", "账号列表", 0, action_list),
        ("2", "新建账号", 0, action_create_user),
        ("3", "新建管理员", 0, action_create_admin),
        ("4", "重置密码", 0, action_set_password),
        ("5", "查看 token 与加速链接", 0, action_show_token),
        ("6", "重置 token", 0, action_reset_token),
        ("7", "启用 / 禁用账号", 0, action_toggle_user),
        ("8", "用量与限额", 1, action_usage),
        ("9", "备份数据库", 2, action_backup),
        ("10", "服务状态与管理入口", 2, action_status),
        ("11", "设置站点地址", 2, action_set_site),
    ]
    _validate_groups(actions)
    return actions


def _validate_groups(actions: list[Action]) -> None:
    """Refuse a table that would draw an item under the wrong header.

    The numbering is contiguous by design, so a group index outside the table
    is a mistake in the list above, not a state the renderer has to survive —
    and it fails here, in one place, rather than as an IndexError halfway
    through drawing the box.
    """
    for _key, label, group, _func in actions:
        if not 0 <= group < len(GROUPS):
            raise ValueError(
                f"action {label!r} is in group {group}, but only "
                f"{len(GROUPS)} groups exist ({', '.join(GROUPS)})")


def action_set_site(conn: sqlite3.Connection, con: Console) -> None:
    """Record the public base URL used by every link this menu prints."""
    current, placeholder = site_base(conn)
    if placeholder:
        con.write("站点地址尚未记录，菜单中的链接将显示占位符")
        current = ""
    else:
        con.write(f"当前站点地址：{current}")
    raw = con.ask("新的站点地址（例如 https://1.2.3.4；留空则不修改）", allow_empty=True).strip()
    if not raw:
        raise _Cancel
    if not raw.lower().startswith(("http://", "https://")):
        raw = "https://" + raw
    raw = raw.rstrip("/")
    if " " in raw or "/" in raw.split("://", 1)[-1]:
        con.write("该值不是有效的站点地址（不应包含路径），未做修改")
        return
    db.set_setting(conn, "public_base", raw)
    db.set_setting(conn, "public_host", raw.split("://", 1)[-1])
    con.write(f"站点地址已记录：{raw}")
    con.write("此后所有链接均使用该地址")


# Groups, in the order they are drawn. Keeping the 1–11 numbering continuous
# means the numbers a user reads in the docs still work after a regroup, and
# `q` still maps to no number at all.
GROUPS = ("账号", "用量", "运维")


def _draw_menu(con: Console, actions: list[Action], conn: sqlite3.Connection) -> None:
    base, placeholder = site_base(conn)
    width = menu_width()
    inner = width - 2

    def row(text: str = "") -> None:
        # _fit, not just _pad: the site line is operator input and an address
        # wider than the box used to push it through both borders.
        con.write("│ " + _pad(_fit(text, inner), inner) + " │")

    con.write("")
    con.write(con.paint("╭" + _rule(width) + "╮", DIM))
    row(con.paint(_pad(BANNER, inner, align="center"), BOLD))
    if not placeholder:
        row(con.paint(_pad(_fit(base, inner), inner, align="center"), DIM))
    con.write(con.paint("├" + _rule(width) + "┤", DIM))

    current = -1
    for key, label, group, _func in actions:
        if group != current:
            if current >= 0:
                row()                       # one blank row between groups
            row(con.paint("  " + GROUPS[group], DIM))
            current = group
        row("    " + _pad(key, 2, align="right") + "  " + label)

    con.write(con.paint("├" + _rule(width) + "┤", DIM))
    row("    " + _pad("q", 2, align="right") + "  " + "退出")
    con.write(con.paint("╰" + _rule(width) + "╯", DIM))


def run(conn: sqlite3.Connection, *, stdin: TextIO | None = None,
        stdout: TextIO | None = None) -> int:
    con = Console(stdin, stdout)
    actions = _actions()
    lookup = {key: func for key, _label, _group, func in actions}
    first = True

    try:
        while True:
            if first and db.is_placeholder_base(db.public_base(conn)):
                con.write("")
                con.write("提示：尚未记录本站公网地址，链接中将显示占位符 <域名或IP>。")
                con.write("      选择 11 填入 https://<服务器IP> 即可，此后链接均为实际地址。")
                first = False
            _draw_menu(con, actions, conn)
            while True:
                try:
                    choice = con.ask("  请输入编号，或 q 退出 > ").lower()
                    break
                except _Cancel:             # a stray Enter just re-asks, no redraw
                    continue
            if choice in ("q", "quit", "exit"):
                con.write("已退出")
                return 0
            handler = lookup.get(choice)
            if handler is None:
                con.write(f"无此选项：{choice}")
                continue
            try:
                handler(conn, con)
            except _Quit:
                raise                       # EOF mid-action: leave, do not report
            except _Cancel:
                con.write("操作已取消")
            except sqlite3.Error as exc:
                con.write(f"数据库错误：{exc}")
            except Exception as exc:        # a menu must never kill the terminal
                con.write(f"操作失败：{type(exc).__name__}: {exc}")
            # A blank line before the pause: without it the prompt lands flush
            # against the last row of the action's output and reads as one of
            # its fields.
            con.write("")
            con.ask("  按回车键返回菜单", allow_empty=True)
    except _Quit:
        return 0
    except KeyboardInterrupt:
        con.write("\n已退出")
        return 0


def main(argv: Iterable[str] | None = None, *, conn: sqlite3.Connection | None = None) -> int:
    """Standalone entry point, mostly for ``python -m app.menu``."""
    parser = argparse.ArgumentParser(prog="dlproxy menu")
    parser.add_argument("--db", default=None, help="override database path")
    args = parser.parse_args(list(argv) if argv is not None else None)
    owned = conn is None
    conn = conn or db.init_db(args.db)
    try:
        return run(conn)
    finally:
        if owned:
            conn.close()
