"""The interactive menu: scripted sessions against a real database."""
from __future__ import annotations

import io
import sqlite3
from pathlib import Path

import pytest

from app import auth, db, menu


class Session:
    """Feeds a fixed script to the menu and collects everything it prints."""

    def __init__(self, *lines: str):
        self.stdin = io.StringIO("".join(line + "\n" for line in lines))
        self.stdout = io.StringIO()

    def run(self, conn) -> tuple[int, str]:
        code = menu.run(conn, stdin=self.stdin, stdout=self.stdout)
        return code, self.stdout.getvalue()


class _Tty(io.StringIO):
    """A StringIO that claims to be a terminal, for the colour branches."""

    def isatty(self) -> bool:                # noqa: D102 - obvious
        return True


@pytest.fixture()
def conn(tmp_path):
    connection = db.init_db(str(tmp_path / "menu.db"))
    yield connection
    connection.close()


def _user(conn, name):
    return conn.execute("SELECT * FROM users WHERE username=?", (name,)).fetchone()


class TestQuit:
    def test_q_exits_zero(self, conn):
        code, out = Session("q").run(conn)
        assert code == 0
        assert "已退出" in out

    def test_all_quit_aliases_work(self, conn):
        for word in ("quit", "exit", "Q"):
            code, out = Session(word).run(conn)
            assert code == 0, word
            assert "已退出" in out

    def test_eof_exits_without_a_traceback(self, conn):
        code, out = Session().run(conn)          # empty stdin
        assert code == 0
        assert "Traceback" not in out

    def test_eof_mid_action_does_not_leave_a_half_user(self, conn):
        # Chose "new user", typed a name, then the stream ended.
        code, out = Session("2", "alice").run(conn)
        assert code == 0
        assert _user(conn, "alice") is None
        assert "Traceback" not in out

    def test_unknown_choice_is_reported_then_loop_continues(self, conn):
        code, out = Session("99", "q").run(conn)
        assert code == 0
        assert "无此选项：99" in out

    def test_bare_enter_reattends_the_prompt(self, conn):
        # A stray Enter used to raise _Cancel out of the main loop and kill the
        # console with a traceback. It must just ask again.
        code, out = Session("", "", "q").run(conn)
        assert code == 0
        assert "已退出" in out
        assert out.count("请输入编号，或 q 退出") == 3   # once per prompt

    def test_bare_enter_after_an_invalid_choice_still_exits(self, conn):
        code, out = Session("99", "", "", "q").run(conn)
        assert code == 0
        assert "无此选项：99" in out
        assert "已退出" in out


class TestMenuIsShown:
    def test_every_action_is_listed(self, conn):
        _, out = Session("q").run(conn)
        for label in ("账号列表", "新建账号", "新建管理员", "重置密码", "查看 token",
                      "重置 token", "启用 / 禁用账号", "用量与限额", "备份数据库",
                      "服务状态与管理入口", "设置站点地址"):
            assert label in out, label

    def test_empty_database_points_at_the_first_step(self, conn):
        _, out = Session("1", "", "q").run(conn)
        assert "尚无账号" in out


class TestCreate:
    def test_create_user(self, conn):
        _, out = Session("2", "alice", "password123", "", "q").run(conn)
        row = _user(conn, "alice")
        assert row is not None
        assert row["is_admin"] == 0
        assert len(row["token"]) == 32
        assert auth.verify_password(row["pwd_hash"], "password123")
        assert "已创建普通账号 alice" in out

    def test_create_admin_sets_the_flag(self, conn):
        _, out = Session("3", "boss", "password123", "", "q").run(conn)
        assert _user(conn, "boss")["is_admin"] == 1
        assert "管理员" in out

    def test_blank_password_generates_one_and_prints_it(self, conn):
        _, out = Session("2", "alice", "", "", "q").run(conn)
        printed = out.split("密码:")[1].split()[0]
        assert auth.verify_password(_user(conn, "alice")["pwd_hash"], printed)

    def test_short_password_is_refused_and_reasked(self, conn):
        _, out = Session("2", "alice", "short", "password123", "", "q").run(conn)
        assert "至少 8 位" in out
        assert auth.verify_password(_user(conn, "alice")["pwd_hash"], "password123")

    def test_existing_user_is_skipped_not_duplicated(self, conn):
        Session("2", "alice", "password123", "", "q").run(conn)
        first = _user(conn, "alice")
        _, out = Session("2", "alice", "", "q").run(conn)
        assert "已存在" in out
        # The original password and token survive: this is a skip, not a replace.
        again = _user(conn, "alice")
        assert again["token"] == first["token"]
        assert auth.verify_password(again["pwd_hash"], "password123")
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1

    def test_blank_username_cancels_cleanly(self, conn):
        _, out = Session("2", "", "", "q").run(conn)
        assert "操作已取消" in out
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


class TestPasswordAndToken:
    def test_set_password(self, conn):
        Session("2", "alice", "password123", "", "q").run(conn)
        _, out = Session("4", "alice", "brandnew123", "", "q").run(conn)
        assert auth.verify_password(_user(conn, "alice")["pwd_hash"], "brandnew123")
        assert "brandnew123" in out

    def test_set_password_for_unknown_user(self, conn):
        _, out = Session("4", "ghost", "", "q").run(conn)
        assert "账号不存在" in out

    def test_show_token_also_prints_a_usable_link(self, conn):
        Session("2", "alice", "password123", "", "q").run(conn)
        token = _user(conn, "alice")["token"]
        _, out = Session("5", "alice", "", "q").run(conn)
        assert token in out
        assert f"/u/{token}/<原始链接>" in out

    def test_reset_token_changes_it(self, conn):
        Session("2", "alice", "password123", "", "q").run(conn)
        old = _user(conn, "alice")["token"]
        _, out = Session("6", "alice", "", "q").run(conn)
        new = _user(conn, "alice")["token"]
        assert new != old
        assert new in out

    def test_toggle_disables_then_enables(self, conn):
        Session("2", "alice", "password123", "", "q").run(conn)
        Session("7", "alice", "", "q").run(conn)
        assert _user(conn, "alice")["disabled"] == 1
        Session("7", "alice", "", "q").run(conn)
        assert _user(conn, "alice")["disabled"] == 0


class TestUsage:
    def test_usage_counts_real_bytes(self, conn):
        Session("2", "alice", "password123", "", "q").run(conn)
        uid = _user(conn, "alice")["id"]
        conn.execute(
            "INSERT INTO transfers(user_id, url, status_code, size_total, "
            "bytes_sent, started_at, last_at) VALUES(?,?,?,?,?,?,?)",
            (uid, "http://e/x", 200, 5000, 5000, db.iso_now(), db.iso_now()))
        conn.execute("INSERT INTO counters(day, bytes) VALUES(?, ?)",
                     (db.day_key(), 5000))
        _, out = Session("8", "", "q").run(conn)
        assert "今日" in out and "本月" in out
        assert "alice" in out

    def test_usage_humanises_bytes(self):
        assert menu.human_bytes(0) == "0 B"
        assert menu.human_bytes(999) == "999 B"
        assert menu.human_bytes(1536) == "1.5 KiB"
        assert menu.human_bytes(100 * 1024**3) == "100.0 GiB"


class TestBackup:
    def test_backup_writes_a_readable_snapshot(self, conn, tmp_path):
        Session("2", "alice", "password123", "", "q").run(conn)
        dest = tmp_path / "out" / "snap.db"
        _, out = Session("9", str(dest), "", "q").run(conn)
        assert dest.is_file()
        assert "已备份至" in out
        snap = sqlite3.connect(str(dest))
        assert snap.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
        assert snap.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        snap.close()


class TestStatus:
    def test_status_shows_the_admin_path(self, conn):
        db.set_setting(conn, "admin_path", "deadbeefcafe")
        _, out = Session("10", "", "q").run(conn)
        assert "deadbeefcafe" in out
        assert "管理入口" in out

    def test_status_survives_a_missing_admin_path(self, conn):
        db.set_setting(conn, "admin_path", "")
        _, out = Session("10", "", "q").run(conn)
        assert "尚未生成" in out
        assert "Traceback" not in out

    def test_status_prints_the_recorded_public_url(self, conn):
        db.set_setting(conn, "admin_path", "abc123")
        db.set_setting(conn, "public_base", "https://203.0.113.9")
        _, out = Session("10", "", "q").run(conn)
        assert "https://203.0.113.9/abc123" in out
        assert "<你的域名或IP>" not in out

    def test_status_falls_back_to_the_placeholder(self, conn):
        db.set_setting(conn, "admin_path", "abc123")
        _, out = Session("10", "", "q").run(conn)
        assert "<你的域名或IP>" in out
        assert "set-site" in out

    def test_status_says_where_the_initial_admin_file_is(self, conn, tmp_path,
                                                         monkeypatch):
        target = tmp_path / "INITIAL_ADMIN.txt"
        target.write_text("密码: xyz\n", encoding="utf-8")
        monkeypatch.setenv("DLPROXY_INIT_FILE", str(target))
        _, out = Session("10", "", "q").run(conn)
        assert str(target) in out
        assert "仍存在" in out
        assert f"sudo rm {target}" in out

    def test_status_marks_a_deleted_initial_admin_file(self, conn, tmp_path,
                                                       monkeypatch):
        monkeypatch.setenv("DLPROXY_INIT_FILE", str(tmp_path / "gone.txt"))
        _, out = Session("10", "", "q").run(conn)
        assert "已删除" in out

    def test_status_reports_the_database_the_connection_uses(self, conn, tmp_path):
        # --db points the menu at any file; the status page must show that one,
        # not whatever DLPROXY_DB_PATH happens to say.
        _, out = Session("10", "", "q").run(conn)
        assert str(tmp_path / "menu.db") in out

    def test_non_linux_skips_systemctl(self, conn, monkeypatch):
        monkeypatch.setattr(menu.sys, "platform", "win32")
        assert menu._service_state() == "非 Linux 环境，已跳过"


class TestSiteBase:
    def test_placeholder_when_nothing_recorded(self, conn):
        base, placeholder = menu.site_base(conn)
        assert base == "<你的域名或IP>"
        assert placeholder is True

    def test_host_alone_is_enough(self, conn):
        db.set_setting(conn, "public_host", "example.com")
        base, placeholder = menu.site_base(conn)
        assert base == "https://example.com"
        assert placeholder is False

    def test_a_trailing_slash_is_not_doubled(self, conn):
        db.set_setting(conn, "public_base", "https://example.com/")
        base, _ = menu.site_base(conn)
        assert base == "https://example.com"

    def test_set_site_action_records_it(self, conn):
        _, out = Session("11", "https://198.51.100.7", "", "q").run(conn)
        assert "站点地址已记录：https://198.51.100.7" in out
        assert db.get_setting(conn, "public_base") == "https://198.51.100.7"
        assert db.get_setting(conn, "public_host") == "198.51.100.7"

    def test_set_site_adds_the_scheme_when_missing(self, conn):
        _, _out = Session("11", "198.51.100.7", "", "q").run(conn)
        assert db.get_setting(conn, "public_base") == "https://198.51.100.7"

    def test_set_site_rejects_a_path(self, conn):
        _, out = Session("11", "https://198.51.100.7/foo", "", "q").run(conn)
        assert "不是有效的站点地址" in out
        assert db.get_setting(conn, "public_base") == ""

    def test_set_site_cancel_leaves_it_alone(self, conn):
        db.set_setting(conn, "public_base", "https://kept.example")
        _, out = Session("11", "", "", "q").run(conn)
        assert "操作已取消" in out
        assert db.get_setting(conn, "public_base") == "https://kept.example"

    def test_the_menu_header_shows_the_url_once_known(self, conn):
        db.set_setting(conn, "public_base", "https://203.0.113.9")
        _, out = Session("q").run(conn)
        assert "https://203.0.113.9" in out

    def test_the_first_run_explains_the_placeholder(self, conn):
        _, out = Session("q").run(conn)
        assert "尚未记录本站公网地址" in out
        assert "选择 11" in out

    def test_the_hint_appears_only_once(self, conn):
        _, out = Session("", "q").run(conn)      # a stray Enter re-asks
        assert out.count("尚未记录本站公网地址") == 1


class TestTokenLinksUseTheRealBase:
    def test_show_token_prints_a_pasteable_link(self, conn):
        db.set_setting(conn, "public_base", "https://203.0.113.9")
        Session("2", "alice", "password123", "", "q").run(conn)
        token = _user(conn, "alice")["token"]
        _, out = Session("5", "alice", "", "q").run(conn)
        assert f"https://203.0.113.9/u/{token}/<原始链接>" in out
        assert f"https://203.0.113.9/u/{token}/https://example.com/big.iso" in out

    def test_show_token_is_honest_when_the_base_is_unknown(self, conn):
        Session("2", "alice", "password123", "", "q").run(conn)
        _, out = Session("5", "alice", "", "q").run(conn)
        assert "<你的域名或IP>" in out
        assert "set-site" in out

    def test_create_user_prints_the_link_with_the_real_base(self, conn):
        db.set_setting(conn, "public_base", "https://203.0.113.9")
        _, out = Session("2", "alice", "password123", "", "q").run(conn)
        token = _user(conn, "alice")["token"]
        assert f"https://203.0.113.9/u/{token}/" in out

    def test_reset_token_prints_the_new_link(self, conn):
        db.set_setting(conn, "public_base", "https://203.0.113.9")
        Session("2", "alice", "password123", "", "q").run(conn)
        _, out = Session("6", "alice", "", "q").run(conn)
        new_token = _user(conn, "alice")["token"]
        assert f"https://203.0.113.9/u/{new_token}/" in out


class TestRendering:
    def test_display_width_counts_chinese_as_two(self):
        assert menu._display_width("abc") == 3
        assert menu._display_width("用户列表") == 8
        assert menu._display_width("a用") == 3

    def test_pad_aligns_by_display_width(self):
        assert menu._pad("用户", 8) == "用户    "
        assert menu._display_width(menu._pad("用户", 8)) == 8
        assert menu._pad("ab", 6, align="right") == "    ab"
        assert menu._pad("ab", 6, align="center") == "  ab  "

    def test_pad_never_truncates(self):
        assert menu._pad("用户列表很长", 4) == "用户列表很长"

    def test_the_user_table_columns_line_up(self, conn):
        Session("2", "alice", "password123", "", "q").run(conn)
        Session("3", "boss", "password123", "", "q").run(conn)
        _, out = Session("1", "", "q").run(conn)
        lines = [ln for ln in out.splitlines() if "alice" in ln or "boss" in ln]
        assert len(lines) == 2
        widths = {menu._display_width(ln.split("  ")[0]) for ln in lines}
        assert len(widths) == 1, lines            # same leading cell width

    def test_the_menu_is_boxed(self, conn):
        _, out = Session("q").run(conn)
        assert "╭" in out and "╯" in out
        assert "╰" in out and "╮" in out

    def test_every_menu_line_is_the_same_width(self, conn):
        _, out = Session("q").run(conn)
        widths = {menu._display_width(ln) for ln in out.splitlines()
                  if ln.startswith(("│", "╭", "├", "╰"))}
        assert len(widths) == 1, widths


class TestGrouping:
    """The eleven items are drawn in three labelled groups.

    The numbering stays 1..11 on purpose: the docs and the wizard both refer to
    "选择 11", and a hierarchical 3.2 scheme would break every one of them.
    """

    def test_the_groups_appear_once_each_and_in_order(self, conn):
        _, out = Session("q").run(conn)
        body = [ln for ln in out.splitlines() if ln.startswith("│")]
        seen = [line[2:-2].strip() for line in body]     # drop the box and its padding
        assert [t for t in seen if t in menu.GROUPS] == list(menu.GROUPS)

    def test_every_item_sits_under_its_group(self, conn):
        _, out = Session("q").run(conn)
        lines = [ln for ln in out.splitlines() if ln.startswith("│")]
        current = None
        placement = {}
        for line in lines:
            text = line[2:-2].strip()          # strip the box and its padding
            if text in menu.GROUPS:
                current = text
                continue
            for key, label, _group, _fn in menu._actions():
                if text.endswith(label):
                    placement[key] = current
        assert placement["1"] == "账号"
        assert placement["8"] == "用量"
        assert placement["11"] == "运维"

    def test_groups_are_separated_by_a_blank_row(self, conn):
        _, out = Session("q").run(conn)
        lines = [ln for ln in out.splitlines() if ln.startswith("│")]
        blanks = [i for i, ln in enumerate(lines) if ln[1:-1].strip() == ""]
        # 1 before each of groups 2 and 3; the header rule is not a │ line.
        assert len(blanks) == 2, lines


class TestTheDocSnapshot:
    """docs/deployment.md shows the menu; that picture must not drift.

    A stale screenshot is worse than none: it teaches a shape the program no
    longer draws, and nobody notices because nothing renders it. Comparing the
    two byte for byte is the only way to keep them honest.
    """

    DOC = Path(__file__).resolve().parent.parent / "docs" / "deployment.md"

    def _documented_box(self) -> list[str]:
        text = self.DOC.read_text(encoding="utf-8")
        start = text.index("```\n╭")
        end = text.index("```", start + 3)
        return [ln for ln in text[start + 4:end].splitlines() if ln.strip()]

    def test_the_documented_menu_is_what_the_menu_draws(self, conn, monkeypatch):
        monkeypatch.setenv("COLUMNS", "50")      # the width the doc was captured at
        db.set_setting(conn, "public_base", "https://203.0.113.9")
        out = io.StringIO()
        menu._draw_menu(menu.Console(io.StringIO(), out), menu._actions(), conn)
        drawn = [ln for ln in out.getvalue().splitlines() if ln.strip()]
        assert drawn == self._documented_box()

    def test_the_documented_box_is_not_ragged(self):
        box = self._documented_box()
        widths = {menu._display_width(ln) for ln in box}
        assert len(widths) == 1, widths


class TestLongValuesDoNotBreakTheBox:
    """The site address is operator input; the box is a fixed shape."""

    def _draw(self, conn) -> list[str]:
        out = io.StringIO()
        menu._draw_menu(menu.Console(io.StringIO(), out), menu._actions(), conn)
        return [ln for ln in out.getvalue().splitlines() if ln.strip()]

    def test_a_long_site_address_is_truncated_not_overflowed(self, conn, monkeypatch):
        monkeypatch.setenv("COLUMNS", "50")
        db.set_setting(conn, "public_base", "https://dlproxy.mycompany.internal.example.com")
        widths = {menu._display_width(ln) for ln in self._draw(conn)}
        assert len(widths) == 1, widths
        assert widths.pop() == 48                # the wide box at COLUMNS=50

    def test_the_longest_address_is_truncated_in_the_narrowest_box(self, conn, monkeypatch):
        # 40 is the floor of menu_width(), so this is the tightest box that
        # can exist: 38 columns between the borders.
        monkeypatch.setenv("COLUMNS", "20")
        db.set_setting(conn, "public_base", "https://" + "a" * 60 + ".example.com")
        lines = self._draw(conn)
        widths = {menu._display_width(ln) for ln in lines}
        assert len(widths) == 1, widths
        assert "…" in "".join(lines)

    def test_an_address_that_fits_is_left_alone(self, conn, monkeypatch):
        monkeypatch.setenv("COLUMNS", "64")
        db.set_setting(conn, "public_base", "https://203.0.113.9")
        text = "\n".join(self._draw(conn))
        assert "https://203.0.113.9" in text
        assert "…" not in text


class TestFit:
    """_fit truncates by display width, never by character count."""

    def test_something_that_fits_is_returned_unchanged(self):
        assert menu._fit("账号列表", 10) == "账号列表"

    def test_exactly_wide_enough_is_unchanged(self):
        assert menu._fit("账号列表", 8) == "账号列表"

    def test_one_column_too_narrow_gets_an_ellipsis(self):
        fitted = menu._fit("账号列表", 7)
        assert fitted.endswith("…")
        assert menu._display_width(fitted) <= 7

    def test_a_wide_character_is_never_cut_in_half(self):
        # '账' is two columns, so a budget of 2 after the ellipsis has exactly
        # no room: the result must be the ellipsis alone, not half a character.
        for width in range(1, 12):
            fitted = menu._fit("账号列表账号列表", width)
            assert menu._display_width(fitted) <= width, (width, fitted)

    def test_ascii_is_cut_by_characters(self):
        assert menu._fit("abcdefghij", 5) == "abcd…"

    def test_zero_width_yields_only_the_ellipsis(self):
        assert menu._fit("账号", 0) == "…"


class TestActionTable:
    """The group index travels with the action, so it cannot drift."""

    def test_every_action_carries_a_valid_group(self):
        for key, label, group, func in menu._actions():
            assert 0 <= group < len(menu.GROUPS), (key, label, group)
            assert callable(func)

    def test_the_groups_are_contiguous_in_key_order(self):
        # A key that jumped back to an earlier group would draw its header a
        # second time; that is what the old side table got wrong.
        groups = [group for _k, _l, group, _f in menu._actions()]
        assert groups == sorted(groups)

    def test_an_out_of_range_group_is_refused(self):
        # The table above is where the mistake would be made, so that is where
        # it has to fail — not halfway through drawing.
        broken = menu._actions() + [("12", "导出报表", 7, lambda *a: None)]
        with pytest.raises(ValueError, match="导出报表"):
            menu._validate_groups(broken)

    def test_a_new_item_added_with_the_right_group_is_accepted(self):
        extended = menu._actions() + [("12", "导出报表", 2, lambda *a: None)]
        menu._validate_groups(extended)          # must not raise


class TestColour:
    """Colour is opt-in, and never disturbs the geometry."""

    def test_a_piped_session_gets_no_escape_codes(self, conn, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("TERM", "xterm-256color")
        con = menu.Console(io.StringIO(), io.StringIO())
        assert con.colour is False               # StringIO is not a tty

    def test_painting_never_changes_the_measured_width(self):
        plain = "用户列表"
        painted = f"{menu.GREEN}{plain}{menu.RESET}"
        assert menu._display_width(painted) == menu._display_width(plain)
        assert menu._display_width(f"{menu.DIM}╭────╮{menu.RESET}") == 6

    def test_pad_ignores_escape_codes_when_padding(self):
        padded = menu._pad(f"{menu.GREEN}用户{menu.RESET}", 8)
        assert menu._display_width(padded) == 8

    def test_each_opt_out_disables_colour_on_a_real_terminal(self, monkeypatch):
        cases = ({"NO_COLOR": "1", "TERM": "xterm-256color"},
                 {"TERM": "dumb"},
                 {"TERM": ""})
        for env in cases:
            monkeypatch.delenv("NO_COLOR", raising=False)
            monkeypatch.setenv("TERM", env.get("TERM", "xterm-256color"))
            if "NO_COLOR" in env:
                monkeypatch.setenv("NO_COLOR", env["NO_COLOR"])
            con = menu.Console(io.StringIO(), _Tty(), colour=None)
            assert con.colour is False, env

    def test_a_tty_without_opt_outs_gets_colour(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("TERM", "xterm-256color")
        con = menu.Console(io.StringIO(), _Tty(), colour=None)
        assert con.colour is True
        assert "\033[" in con.paint("x", menu.GREEN)


class TestWidth:
    """menu_width() is clamped so the box is never too narrow or too wide."""

    @pytest.mark.parametrize("columns,expected", [(20, 40), (30, 40), (46, 42),
                                                  (50, 46), (64, 60), (200, 60)])
    def test_the_box_follows_the_terminal_within_bounds(self, monkeypatch, columns, expected):
        monkeypatch.setenv("COLUMNS", str(columns))
        monkeypatch.setenv("LINES", "24")
        assert menu.menu_width() == expected

    def test_the_clamp_never_shrinks_below_the_longest_label(self):
        # "服务状态与管理入口" is 20 columns plus 6 of indent plus 4 of box.
        longest = max(menu._display_width(label) for _k, label, _g, _f in menu._actions())
        assert menu.MENU_MIN_WIDTH >= longest + 10


class TestFaultTolerance:
    def test_database_error_is_reported_not_raised(self, conn, monkeypatch):
        def boom(*_a, **_k):
            raise sqlite3.OperationalError("database is locked")
        # _actions() builds its table from the module attributes, so patching
        # the function here is enough to route choice "1" into the failure.
        monkeypatch.setattr(menu, "action_list", boom)
        _, out = Session("1", "", "q").run(conn)
        assert "数据库错误" in out
        assert "database is locked" in out
        assert "Traceback" not in out

    def test_unexpected_error_is_reported_not_raised(self, conn, monkeypatch):
        monkeypatch.setattr(menu, "_service_state", lambda: 1 / 0)
        _, out = Session("10", "", "q").run(conn)
        assert "操作失败" in out
        assert "Traceback" not in out


class TestEntryPoints:
    def test_cli_menu_subcommand(self, tmp_path, monkeypatch):
        from app import cli
        db_path = str(tmp_path / "cli.db")
        monkeypatch.setattr("sys.stdin", io.StringIO("q\n"))
        assert cli.main(["--db", db_path, "menu"]) == 0

    def test_menu_main_opens_and_closes_its_own_connection(self, tmp_path, monkeypatch):
        monkeypatch.setattr("sys.stdin", io.StringIO("q\n"))
        assert menu.main(["--db", str(tmp_path / "m.db")]) == 0

    def test_bare_module_dispatch_hands_menu_to_the_cli(self, monkeypatch):
        from app import __main__ as entry
        seen = {}
        monkeypatch.setattr(entry, "cli_main", lambda argv: seen.update(a=argv) or 0)
        assert entry.main(["menu"]) == 0
        assert seen["a"] == ["menu"]


class TestCommandLinePlumbing:
    """The small parser details that broke when the menu was first tried."""

    def test_db_flag_is_accepted_after_the_subcommand(self, tmp_path, monkeypatch):
        # argparse only takes globals before the sub-command, but
        # `dlproxy listusers --db x` reads more naturally.
        from app import cli
        db_path = str(tmp_path / "hoist.db")
        monkeypatch.setattr("sys.stdin", io.StringIO("q\n"))
        assert cli.main(["menu", "--db", db_path]) == 0

    def test_db_flag_is_accepted_before_the_subcommand(self, tmp_path, monkeypatch):
        from app import cli
        monkeypatch.setattr("sys.stdin", io.StringIO("q\n"))
        assert cli.main(["--db", str(tmp_path / "hoist2.db"), "menu"]) == 0

    def test_dispatch_sees_the_command_past_a_leading_db_flag(self, tmp_path, monkeypatch):
        # `python -m app --db X menu` used to fall through to serve() and start
        # uvicorn, which then died on the missing DLPROXY_SECRET_KEY.
        from app import __main__ as entry
        seen = {}
        monkeypatch.setattr(entry, "cli_main", lambda argv: seen.update(a=argv) or 0)
        served = []
        monkeypatch.setattr(entry, "serve", lambda: served.append(1) or 0)
        assert entry.main(["--db", str(tmp_path / "d.db"), "menu"]) == 0
        assert served == []
        assert "menu" in seen["a"]

    def test_bare_invocation_still_starts_the_server(self, monkeypatch):
        from app import __main__ as entry
        served = []
        monkeypatch.setattr(entry, "serve", lambda: served.append(1) or 0)
        assert entry.main([]) == 0
        assert served == [1]

    def test_unknown_leading_option_does_not_start_the_server_by_accident(self, monkeypatch):
        from app import __main__ as entry
        assert entry._first_command(["--help"]) is None
        assert entry._first_command([]) is None
        assert entry._first_command(["--db", "x.db"]) is None
        assert entry._first_command(["--db", "x.db", "menu"]) == "menu"
