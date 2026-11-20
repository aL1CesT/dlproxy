"""Web pages: login, home, admin, token reset, and the admin-path gate."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app import db

from test_proxy import seed_user


def login(app_client, username="alice", password="password123", **kwargs):
    """Log in. Redirects are not followed by default so callers can inspect the
    Set-Cookie / Location headers directly."""
    kwargs.setdefault("follow_redirects", False)
    return app_client.post("/login",
                           data={"username": username, "password": password},
                           **kwargs)


def follow_flash(app_client, response):
    """Consume the one-shot message behind a 303 and return the page body.

    Messages used to ride in the query string. They may carry a freshly minted
    token or password, and nginx logs the full request line, so they now live in
    the flashes table behind a short-lived cookie. Asserting on the redirect
    target therefore proves nothing any more: the text only exists once the
    landing page is rendered.
    """
    location = response.headers["location"]
    assert "?" not in location, location
    page = app_client.get(location)
    assert page.status_code == 200, page.status_code
    return page.text


def _admin_path(app_client) -> str:
    """Seed a known admin, log in as it, and return the current admin path.

    Bootstrap already inserted an "admin" account with a random password, so the
    tests never reuse it: they need an account whose password they know.
    """
    seed_user(app_client, "root", is_admin=True)
    login(app_client, "root")
    return db.get_setting(app_client.app.state.conn, "admin_path")


class TestLoginPage:
    def test_login_page_renders(self, app_client):
        response = app_client.get("/login")
        assert response.status_code == 200
        assert "登录" in response.text
        assert 'name="username"' in response.text

    def test_root_redirects_when_anonymous(self, app_client):
        response = app_client.get("/", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"

    def test_successful_login_sets_a_hardened_cookie(self, app_client):
        seed_user(app_client)
        response = login(app_client)
        assert response.status_code == 303
        cookie = response.headers["set-cookie"]
        assert "HttpOnly" in cookie
        assert "SameSite=lax" in cookie or "SameSite=Lax" in cookie
        assert "Path=/" in cookie

    def test_failure_does_not_reveal_which_field_was_wrong(self, app_client):
        seed_user(app_client)
        wrong_pw = login(app_client, password="bad")
        assert wrong_pw.status_code == 303
        # The message is consumed before the next attempt: the flash id lives in
        # a single cookie, so a second login would overwrite it.
        assert wrong_pw.headers["location"] == "/login"
        assert "用户名或密码错误" in follow_flash(app_client, wrong_pw)

        unknown = login(app_client, username="ghost")
        assert unknown.status_code == 303
        assert unknown.headers["location"] == "/login"
        assert "用户名或密码错误" in follow_flash(app_client, unknown)

    def test_home_renders_after_login(self, app_client, origin):
        uid, token = seed_user(app_client)
        login(app_client)
        response = app_client.get("/")
        assert response.status_code == 200
        assert token in response.text
        assert "今日用量" in response.text

    def test_logout_clears_the_session(self, app_client):
        seed_user(app_client)
        login(app_client)
        assert app_client.get("/").status_code == 200
        app_client.post("/logout", follow_redirects=False)
        assert app_client.get("/", follow_redirects=False).status_code == 303


class TestTokenResetPage:
    def test_reset_changes_the_token_and_says_so(self, app_client):
        uid, token = seed_user(app_client)
        login(app_client)
        response = app_client.post("/token/reset", follow_redirects=False)
        assert response.status_code == 303
        conn = app_client.app.state.conn
        new = conn.execute("SELECT token FROM users WHERE id=?", (uid,)).fetchone()["token"]
        assert new != token
        # The credential reaches the user through the flashes table, and the
        # redirect itself carries nothing worth logging.
        assert new in follow_flash(app_client, response)


class TestAdminGate:
    def _admin(self, app_client):
        uid, token = seed_user(app_client, "root", is_admin=True)
        login(app_client, "root")
        path = db.get_setting(app_client.app.state.conn, "admin_path")
        return uid, path

    def test_admin_path_is_random_32_hex(self, app_client):
        path = db.get_setting(app_client.app.state.conn, "admin_path")
        assert re.fullmatch(r"[0-9a-f]{32}", path), path

    def test_wrong_path_is_404(self, app_client):
        self._admin(app_client)
        assert app_client.get("/deadbeef" * 4).status_code == 404

    def test_non_admin_gets_404_not_403(self, app_client):
        seed_user(app_client, "alice", is_admin=False)
        login(app_client, "alice")
        path = db.get_setting(app_client.app.state.conn, "admin_path")
        response = app_client.get("/" + path)
        assert response.status_code == 404

    def test_anonymous_gets_404(self, app_client):
        path = db.get_setting(app_client.app.state.conn, "admin_path")
        assert app_client.get("/" + path).status_code == 404

    def test_admin_can_reach_the_page(self, app_client):
        _uid, path = self._admin(app_client)
        response = app_client.get("/" + path)
        assert response.status_code == 200
        assert "运行状态" in response.text
        assert "限额与并发" in response.text

    def test_healthz_still_reachable_for_admins(self, app_client):
        self._admin(app_client)
        assert app_client.get("/healthz").status_code == 200


class TestAdminActions:
    def _admin(self, app_client):
        uid, token = seed_user(app_client, "root", is_admin=True)
        login(app_client, "root")
        path = db.get_setting(app_client.app.state.conn, "admin_path")
        return path

    def test_create_user(self, app_client):
        path = self._admin(app_client)
        response = app_client.post(f"/{path}/users",
                                   data={"username": "carol",
                                         "password": "password123"},
                                   follow_redirects=False)
        assert response.status_code == 303
        conn = app_client.app.state.conn
        row = conn.execute("SELECT * FROM users WHERE username='carol'").fetchone()
        assert row is not None and row["is_admin"] == 0
        assert len(row["token"]) == 32

    def test_duplicate_username_is_reported_not_crashed(self, app_client):
        path = self._admin(app_client)
        app_client.post(f"/{path}/users",
                        data={"username": "carol", "password": "password123"})
        response = app_client.post(f"/{path}/users",
                                   data={"username": "carol", "password": "password123"},
                                   follow_redirects=False)
        assert response.status_code == 303
        assert "该用户名已存在" in follow_flash(app_client, response)

    def test_short_password_is_rejected(self, app_client):
        path = self._admin(app_client)
        response = app_client.post(f"/{path}/users",
                                   data={"username": "dave", "password": "short"},
                                   follow_redirects=False)
        assert "密码长度不得少于 8 位" in follow_flash(app_client, response)
        conn = app_client.app.state.conn
        assert conn.execute("SELECT * FROM users WHERE username='dave'").fetchone() is None

    def test_disable_and_enable(self, app_client):
        path = self._admin(app_client)
        uid, _token = seed_user(app_client, "erin")
        conn = app_client.app.state.conn
        app_client.post(f"/{path}/users/{uid}/action", data={"action": "disable"})
        assert conn.execute("SELECT disabled FROM users WHERE id=?", (uid,)).fetchone()[0] == 1
        app_client.post(f"/{path}/users/{uid}/action", data={"action": "enable"})
        assert conn.execute("SELECT disabled FROM users WHERE id=?", (uid,)).fetchone()[0] == 0

    def test_reset_token_shows_the_new_value_once(self, app_client):
        path = self._admin(app_client)
        uid, old = seed_user(app_client, "frank")
        response = app_client.post(f"/{path}/users/{uid}/action",
                                   data={"action": "reset_token"},
                                   follow_redirects=False)
        conn = app_client.app.state.conn
        new = conn.execute("SELECT token FROM users WHERE id=?", (uid,)).fetchone()["token"]
        assert new != old
        assert new in follow_flash(app_client, response)

    def test_reset_password_changes_the_hash(self, app_client):
        path = self._admin(app_client)
        uid, _t = seed_user(app_client, "grace")
        conn = app_client.app.state.conn
        before = conn.execute("SELECT pwd_hash FROM users WHERE id=?", (uid,)).fetchone()[0]
        app_client.post(f"/{path}/users/{uid}/action", data={"action": "reset_password"})
        after = conn.execute("SELECT pwd_hash FROM users WHERE id=?", (uid,)).fetchone()[0]
        assert after != before

    def test_settings_update_limits(self, app_client):
        path = self._admin(app_client)
        conn = app_client.app.state.conn
        app_client.post(f"/{path}/settings",
                        data={"daily_limit_gb": "5",
                              "monthly_limit_gb": "50",
                              "max_active_streams_global": "300",
                              "max_active_streams_per_token": "150"})
        assert db.get_int_setting(conn, "daily_limit_bytes") == 5 * 1024**3
        assert db.get_int_setting(conn, "monthly_limit_bytes") == 50 * 1024**3
        assert db.get_int_setting(conn, "max_active_streams_global") == 300
        assert db.get_int_setting(conn, "max_active_streams_per_token") == 150

    def test_settings_rejects_non_numeric(self, app_client):
        path = self._admin(app_client)
        response = app_client.post(f"/{path}/settings",
                                   data={"daily_limit_gb": "lots"},
                                   follow_redirects=False)
        assert "必须为非负数字" in follow_flash(app_client, response)

    def test_unblock_sets_a_bypass_window(self, app_client):
        path = self._admin(app_client)
        conn = app_client.app.state.conn
        app_client.post(f"/{path}/unblock", data={"hours": "3"})
        from app import quota
        state = quota.usage(conn)
        assert state.bypass_until is not None
        assert state.bypassed is True

    def test_unblock_zero_clears_it(self, app_client):
        path = self._admin(app_client)
        conn = app_client.app.state.conn
        app_client.post(f"/{path}/unblock", data={"hours": "3"})
        app_client.post(f"/{path}/unblock", data={"hours": "0"})
        from app import quota
        assert quota.usage(conn).bypass_until is None

    def test_regenerate_admin_path(self, app_client):
        path = self._admin(app_client)
        conn = app_client.app.state.conn
        response = app_client.post(f"/{path}/regenerate-path", follow_redirects=False)
        assert response.status_code == 303
        new_path = db.get_setting(conn, "admin_path")
        assert new_path != path
        assert app_client.get("/" + path).status_code == 404
        assert app_client.get("/" + new_path).status_code == 200

    def test_history_view_is_read_only(self, app_client, origin):
        path = self._admin(app_client)
        uid, token = seed_user(app_client, "henry")
        app_client.get(f"/u/{token}/{origin}/blob")
        response = app_client.get(f"/{path}/history/{uid}")
        assert response.status_code == 200
        assert "henry" in response.text
        assert "/blob" in response.text

    def test_smtp_test_reports_unconfigured(self, app_client):
        path = self._admin(app_client)
        response = app_client.post(f"/{path}/smtp-test", follow_redirects=False)
        assert response.status_code == 303
        assert "告警通道尚未配置" in follow_flash(app_client, response)


class TestSmtpSettings:
    def test_password_is_not_echoed_into_the_form(self, app_client):
        path = (lambda: (
            seed_user(app_client, "root2", is_admin=True),
            login(app_client, "root2"),
            db.get_setting(app_client.app.state.conn, "admin_path"))[2])()

        conn = app_client.app.state.conn
        db.set_setting(conn, "smtp_pass", "sup3rs3cret")
        db.set_setting(conn, "smtp_host", "smtp.example.com")
        db.set_setting(conn, "smtp_from", "a@example.com")
        db.set_setting(conn, "smtp_to", "b@example.com")
        page = app_client.get("/" + path)
        assert "sup3rs3cret" not in page.text

    def test_blank_password_does_not_erase_the_stored_one(self, app_client):
        seed_user(app_client, "root3", is_admin=True)
        login(app_client, "root3")
        conn = app_client.app.state.conn
        path = db.get_setting(conn, "admin_path")
        db.set_setting(conn, "smtp_pass", "keepme")
        app_client.post(f"/{path}/settings",
                        data={"smtp_host": "smtp.example.com",
                              "smtp_pass": ""})
        assert db.get_setting(conn, "smtp_pass") == "keepme"


class TestPublicBase:
    """The generated link must carry the scheme the site is actually served on.

    uvicorn runs with ``proxy_headers=False``, so ``request.base_url`` is always
    ``http://127.0.0.1:8080`` behind Nginx. The install step records the real
    address; that record has to win, or every link a user copies is http and
    points at the loopback bind address.
    """

    def test_recorded_base_wins_over_the_request(self, app_client):
        seed_user(app_client)
        login(app_client)
        db.set_setting(app_client.app.state.conn, "public_base",
                       "https://203.0.113.9/")
        page = app_client.get("/")
        assert 'const BASE = "https://203.0.113.9";' in page.text
        assert "https://203.0.113.9/u/" in page.text
        assert "http://testserver" not in page.text

    def test_falls_back_to_the_request_when_nothing_is_recorded(self, app_client):
        seed_user(app_client)
        login(app_client)
        page = app_client.get("/")
        assert 'const BASE = "https://testserver";' in page.text

    def test_uses_the_forwarded_scheme_when_nothing_is_recorded(self, app_client):
        """Without a recorded base, Nginx's own headers beat the ASGI scheme.

        ``proxy_headers=False`` means Starlette reports ``http`` even though the
        browser used TLS. The hosted install always records ``public_base``, so
        this only matters for a hand-started instance behind the same Nginx — but
        that instance still has to print a link the user can actually open.
        """
        seed_user(app_client)
        login(app_client)
        page = app_client.get(
            "/", headers={"x-forwarded-proto": "https",
                          "host": "dl.example.com"})
        assert 'const BASE = "https://dl.example.com";' in page.text
        assert "http://dl.example.com" not in page.text

    def test_forwarded_host_is_ignored_when_not_behind_a_proxy(self, app_client,
                                                               monkeypatch):
        """A direct client can send X-Forwarded-* itself; it must not count."""
        monkeypatch.setenv("DLPROXY_BEHIND_PROXY", "0")
        seed_user(app_client)
        login(app_client)
        page = app_client.get(
            "/", headers={"x-forwarded-proto": "https",
                          "x-forwarded-host": "evil.example.net"})
        assert "evil.example.net" not in page.text

    def test_a_bogus_forwarded_scheme_is_ignored(self, app_client):
        seed_user(app_client)
        login(app_client)
        page = app_client.get(
            "/", headers={"x-forwarded-proto": "javascript",
                          "host": "dl.example.com"})
        # Only http/https are accepted; anything else must not reach the page.
        assert "javascript://" not in page.text
        assert 'const BASE = "https://dl.example.com";' in page.text

    def test_admin_page_uses_the_recorded_base_too(self, app_client):
        seed_user(app_client, "root", is_admin=True)
        login(app_client, "root")
        conn = app_client.app.state.conn
        db.set_setting(conn, "public_base", "https://dl.example.com")
        path = db.get_setting(conn, "admin_path")
        assert app_client.get("/" + path).status_code == 200


class TestCopyAffordances:
    def test_home_offers_a_copy_button_for_the_prefix(self, app_client):
        _uid, token = seed_user(app_client)
        login(app_client)
        page = app_client.get("/")
        # One button per copyable value, each pointing at the element to read.
        for target in ("out", "base", "token"):
            assert f'data-copy-target="{target}"' in page.text
        # The prefix input is pre-filled by the server (not assembled by JS), so
        # it is copyable even with JavaScript disabled.
        assert f'value="https://testserver/u/{token}/"' in page.text
        assert token in page.text


class TestFlashMessages:
    """Secrets must not ride in the redirect URL.

    nginx writes the whole request line to its access log, and the browser keeps
    it in history, so a message carrying a fresh token or password is stored
    server-side and collected on the landing page instead.
    """

    def test_the_secret_stays_out_of_the_redirect(self, app_client):
        uid, _token = seed_user(app_client)
        login(app_client)
        response = app_client.post("/token/reset", follow_redirects=False)
        location = response.headers["location"]
        assert location == "/"
        assert "?" not in location
        conn = app_client.app.state.conn
        new = conn.execute("SELECT token FROM users WHERE id=?", (uid,)).fetchone()["token"]
        assert new not in location
        assert "dlproxy_flash" in response.headers["set-cookie"]

    def test_the_message_is_shown_once(self, app_client):
        seed_user(app_client)
        login(app_client)
        response = app_client.post("/token/reset", follow_redirects=False)
        first = follow_flash(app_client, response)
        assert "新 token 已生成" in first
        # The row and the cookie are both consumed: a refresh must not replay it.
        second = app_client.get("/").text
        assert "新 token 已生成" not in second

    def test_a_forged_flash_cookie_renders_nothing(self, app_client):
        seed_user(app_client)
        login(app_client)
        app_client.cookies.set("dlproxy_flash", "0" * 32)
        page = app_client.get("/")
        assert page.status_code == 200
        assert "banner ok" not in page.text


class TestBadInput:
    def test_a_non_numeric_page_is_200_not_500(self, app_client):
        seed_user(app_client)
        login(app_client)
        assert app_client.get("/?page=abc").status_code == 200
        assert app_client.get("/?page=-4").status_code == 200

    def test_an_absurd_limit_is_refused_without_a_500(self, app_client):
        path = _admin_path(app_client)
        conn = app_client.app.state.conn
        before = db.get_setting(conn, "daily_limit_bytes")
        response = app_client.post(f"/{path}/settings",
                                   data={"daily_limit_gb": "1e400"},
                                   follow_redirects=False)
        assert response.status_code == 303
        assert "必须为非负数字" in follow_flash(app_client, response)
        assert db.get_setting(conn, "daily_limit_bytes") == before

    def test_an_absurd_unblock_span_is_clamped(self, app_client):
        path = _admin_path(app_client)
        response = app_client.post(f"/{path}/unblock", data={"hours": "inf"},
                                   follow_redirects=False)
        assert response.status_code == 303
        assert "已临时解封至" in follow_flash(app_client, response)

    def test_negative_limits_are_stored_as_zero(self, app_client):
        path = _admin_path(app_client)
        conn = app_client.app.state.conn
        app_client.post(f"/{path}/settings", data={"daily_limit_gb": "-3"})
        assert db.get_int_setting(conn, "daily_limit_bytes") == 0


class TestHistoryPagination:
    def test_the_admin_history_pages_through_rows(self, app_client, origin):
        path = _admin_path(app_client)
        uid, token = seed_user(app_client, "henry")
        conn = app_client.app.state.conn
        db.set_setting(conn, "history_per_page", "2")
        for i in range(3):
            app_client.get(f"/u/{token}/{origin}/blob{i}")
        first = app_client.get(f"/{path}/history/{uid}")
        assert first.status_code == 200
        assert "第 1 / 2 页" in first.text
        second = app_client.get(f"/{path}/history/{uid}?page=2")
        assert "第 2 / 2 页" in second.text

    def test_a_non_numeric_page_is_200_not_500(self, app_client):
        path = _admin_path(app_client)
        uid, _token = seed_user(app_client, "ivy")
        response = app_client.get(f"/{path}/history/{uid}?page=oops")
        assert response.status_code == 200


class TestChangePassword:
    def test_page_requires_a_session(self, app_client):
        response = app_client.get("/password", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"

    def test_page_renders_when_logged_in(self, app_client):
        seed_user(app_client)
        login(app_client)
        page = app_client.get("/password")
        assert page.status_code == 200
        assert 'name="current"' in page.text

    def test_changes_the_password_and_keeps_the_session(self, app_client):
        seed_user(app_client, "alice", password="password123")
        login(app_client, "alice")
        response = app_client.post("/password", data={
            "current": "password123", "new": "newpassword456",
            "confirm": "newpassword456"}, follow_redirects=False)
        assert response.status_code == 303
        assert "密码已更新" in follow_flash(app_client, response)
        # Still logged in, and the new password really is the live one.
        assert app_client.get("/").status_code == 200
        again = login(app_client, "alice", password="password123")
        assert again.status_code == 303
        assert again.headers["location"] == "/login"
        ok = login(app_client, "alice", password="newpassword456")
        assert ok.status_code == 303
        assert ok.headers["location"] == "/"

    def test_wrong_current_password_is_refused(self, app_client):
        seed_user(app_client, "alice", password="password123")
        login(app_client, "alice")
        response = app_client.post("/password", data={
            "current": "nope", "new": "newpassword456",
            "confirm": "newpassword456"})
        assert response.status_code == 400
        assert "当前密码不正确" in response.text
        conn = app_client.app.state.conn
        row = conn.execute("SELECT pwd_hash FROM users WHERE username='alice'").fetchone()
        from app import auth as _auth
        assert _auth.verify_password(row["pwd_hash"], "password123")

    def test_short_new_password_is_refused(self, app_client):
        seed_user(app_client, "alice", password="password123")
        login(app_client, "alice")
        response = app_client.post("/password", data={
            "current": "password123", "new": "short", "confirm": "short"})
        assert response.status_code == 400
        assert "至少 8 位" in response.text

    def test_mismatched_confirmation_is_refused(self, app_client):
        seed_user(app_client, "alice", password="password123")
        login(app_client, "alice")
        response = app_client.post("/password", data={
            "current": "password123", "new": "newpassword456",
            "confirm": "newpassword789"})
        assert response.status_code == 400
        assert "不一致" in response.text

    def test_reusing_the_same_password_is_refused(self, app_client):
        seed_user(app_client, "alice", password="password123")
        login(app_client, "alice")
        response = app_client.post("/password", data={
            "current": "password123", "new": "password123",
            "confirm": "password123"})
        assert response.status_code == 400
        assert "不能与当前密码相同" in response.text

    def test_a_failed_attempt_is_logged_and_does_not_leak_the_hash(self, app_client):
        seed_user(app_client, "alice", password="password123")
        login(app_client, "alice")
        response = app_client.post("/password", data={
            "current": "nope", "new": "newpassword456",
            "confirm": "newpassword456"})
        # The page explains the scheme by name ("Argon2id"), which is fine; what
        # must never appear is an actual hash string.
        assert "$argon2" not in response.text
        log = app_client.security_path.read_text(encoding="utf-8")
        assert "password_change_failed" in log
        assert "$argon2" not in log

    def test_other_sessions_of_the_same_account_are_dropped(self, app_client):
        uid, _token = seed_user(app_client, "alice", password="password123")
        # Two independent logins for the same account on the same client: the
        # TestClient keeps one cookie jar, so seed the extra rows directly and
        # assert the count that the handler reports.
        conn = app_client.app.state.conn
        secret = app_client.app.state.secret
        from app import auth as _auth
        extra = [_auth.create_session(conn, secret=secret, user_id=uid)
                 for _ in range(3)]
        assert len(extra) == 3
        login(app_client, "alice")
        before = conn.execute("SELECT COUNT(*) AS n FROM sessions WHERE user_id=?",
                              (uid,)).fetchone()["n"]
        response = app_client.post("/password", data={
            "current": "password123", "new": "newpassword456",
            "confirm": "newpassword456"}, follow_redirects=False)
        assert response.status_code == 303
        after = conn.execute("SELECT COUNT(*) AS n FROM sessions WHERE user_id=?",
                             (uid,)).fetchone()["n"]
        assert after < before
        # The session that made the change survives.
        assert app_client.get("/").status_code == 200

    def test_a_flood_of_failed_logins_cannot_grow_the_table_without_bound(
            self, app_client, monkeypatch):
        """``POST /login`` needs no session, so age-based purging alone lets an
        unauthenticated loop fill the disk. The count cap is the real bound."""
        from app import flash

        monkeypatch.setattr(flash, "MAX_ROWS", 10)
        seed_user(app_client)
        for _ in range(25):
            login(app_client, password="wrong-password")
        conn = app_client.app.state.conn
        rows = conn.execute("SELECT COUNT(*) AS n FROM flashes").fetchone()["n"]
        assert rows <= 10, rows

    def test_trim_keeps_the_newest_rows(self, app_client):
        from app import flash

        conn = app_client.app.state.conn
        ids = [flash.put(conn, f"m{i}") for i in range(5)]
        removed = flash.trim(conn, cap=2)
        assert removed == 3
        left = {r["id"] for r in conn.execute("SELECT id FROM flashes")}
        assert left == set(ids[-2:])


class TestAdminPathComparison:
    """The admin path is compared in constant time, like the tokens are.

    It is 128 random bits, so a timing attack is not realistic -- but the rest
    of the project already uses ``hmac.compare_digest`` for secrets, and a plain
    ``!=`` invites someone to copy the pattern for something that is not 128
    bits.
    """

    def test_a_matching_path_passes(self):
        from app.main import admin_path_matches
        assert admin_path_matches("8f3a1c6d94e2b70a5c8d13f6a9b4e072",
                                  "8f3a1c6d94e2b70a5c8d13f6a9b4e072")

    def test_an_empty_expected_path_never_passes(self):
        from app.main import admin_path_matches
        assert not admin_path_matches("", "")
        assert not admin_path_matches("anything", "")

    @pytest.mark.parametrize("given", [
        "8f3a1c6d94e2b70a5c8d13f6a9b4e07",
        "8f3a1c6d94e2b70a5c8d13f6a9b4e0720",
        "8F3A1C6D94E2B70A5C8D13F6A9B4E072",
        "8f3a1c6d94e2b70a5c8d13f6a9b4e073",
    ])
    def test_anything_else_is_rejected(self, given):
        from app.main import admin_path_matches
        assert not admin_path_matches(given, "8f3a1c6d94e2b70a5c8d13f6a9b4e072")


class TestSelfProtection:
    """An admin disabling or deleting themselves leaves no administrator.

    ``_bootstrap`` only runs when the count of admins is zero, so the next
    restart tried to recreate one and hit the username unique constraint:
    measured ``IntegrityError: UNIQUE constraint failed: users.username`` from
    inside the lifespan handler -- the service could not start at all.
    """

    def _self_id(self, app_client, path):
        return int(app_client.get(f"/{path}").context["user"].id)

    def test_an_admin_cannot_delete_themselves(self, app_client):
        uid, _token = seed_user(app_client, "root", is_admin=True)
        login(app_client, "root")
        conn = app_client.app.state.conn
        path = db.get_setting(conn, "admin_path")
        response = app_client.post(f"/{path}/users/{uid}/action",
                                   data={"action": "delete"},
                                   follow_redirects=False)
        assert response.status_code == 303
        assert "不能禁用或删除自己" in follow_flash(app_client, response)
        assert conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() is not None

    def test_an_admin_cannot_disable_themselves(self, app_client):
        uid, _token = seed_user(app_client, "root", is_admin=True)
        login(app_client, "root")
        conn = app_client.app.state.conn
        path = db.get_setting(conn, "admin_path")
        response = app_client.post(f"/{path}/users/{uid}/action",
                                   data={"action": "disable"},
                                   follow_redirects=False)
        assert "不能禁用或删除自己" in follow_flash(app_client, response)
        assert conn.execute("SELECT disabled FROM users WHERE id=?",
                            (uid,)).fetchone()[0] == 0

    def test_the_refusal_is_written_to_the_security_log(self, app_client):
        uid, _token = seed_user(app_client, "root", is_admin=True)
        login(app_client, "root")
        conn = app_client.app.state.conn
        path = db.get_setting(conn, "admin_path")
        app_client.post(f"/{path}/users/{uid}/action", data={"action": "delete"})
        sec = app_client.app.state.security_log
        assert sec is not None
        text = sec.path.read_text(encoding="utf-8")
        assert "admin_action_refused" in text
        assert 'reason=self' in text

    def test_rotating_your_own_token_is_still_allowed(self, app_client):
        """Only the two destructive actions are blocked: a self-service token
        reset must keep working, or the refusal would break normal operation."""
        uid, old = seed_user(app_client, "root", is_admin=True)
        login(app_client, "root")
        conn = app_client.app.state.conn
        path = db.get_setting(conn, "admin_path")
        response = app_client.post(f"/{path}/users/{uid}/action",
                                   data={"action": "reset_token"},
                                   follow_redirects=False)
        assert response.status_code == 303
        new = conn.execute("SELECT token FROM users WHERE id=?", (uid,)).fetchone()[0]
        assert new != old
        assert new in follow_flash(app_client, response)

    def test_an_admin_can_still_delete_someone_else(self, app_client):
        _root, _t = seed_user(app_client, "root", is_admin=True)
        login(app_client, "root")
        conn = app_client.app.state.conn
        path = db.get_setting(conn, "admin_path")
        victim, _v = seed_user(app_client, "victim")
        app_client.post(f"/{path}/users/{victim}/action", data={"action": "delete"})
        assert conn.execute("SELECT * FROM users WHERE id=?",
                            (victim,)).fetchone() is None


class TestBootstrapUsername:
    """``users.username`` is UNIQUE and an ordinary account may hold ``admin``.

    ``dlproxy createuser admin`` is enough to arrange it; the bootstrap then
    crashed the lifespan handler and the service never answered a request.
    """

    def test_the_bootstrap_skips_a_taken_username(self, tmp_path, monkeypatch):
        from app import main as app_main
        init = tmp_path / "INITIAL_ADMIN.txt"
        monkeypatch.setenv("DLPROXY_INIT_FILE", str(init))
        monkeypatch.setenv("DLPROXY_SECRET_KEY", "unit-test-secret")
        path = str(tmp_path / "boot.db")
        conn = db.init_db(path)
        try:
            auth_hash = __import__("app.auth", fromlist=["x"]).hash_password("x" * 12)
            conn.execute(
                "INSERT INTO users(username, pwd_hash, token, token_active, "
                "disabled, is_admin, created_at) VALUES('admin',?,?,1,0,0,?)",
                (auth_hash, "a" * 32, db.iso_now()))
            app_main._bootstrap(conn, app_main.SecurityLog(tmp_path / "sec.log"))
            names = {r["username"] for r in conn.execute(
                "SELECT username FROM users WHERE is_admin=1")}
            assert names == {"admin2"}, names
            assert "用户名：admin2" in init.read_text(encoding="utf-8")
        finally:
            conn.close()

    def test_a_free_username_is_reported_verbatim(self, tmp_path):
        from app import main as app_main
        conn = db.init_db(str(tmp_path / "boot2.db"))
        try:
            assert app_main._free_admin_username(conn) == "admin"
        finally:
            conn.close()

    def test_the_service_starts_with_an_admin_named_account_present(self, tmp_path):
        """End to end: the app comes up, it just picks another admin name."""
        from fastapi.testclient import TestClient
        from app.main import create_app
        path = str(tmp_path / "boom.db")
        boot = db.init_db(path)
        from app import auth as auth_mod
        boot.execute(
            "INSERT INTO users(username, pwd_hash, token, token_active, "
            "disabled, is_admin, created_at) VALUES('admin',?,?,1,0,0,?)",
            (auth_mod.hash_password("password123"), "b" * 32, db.iso_now()))
        boot.close()
        app = create_app(db_path_override=path, allow_private_upstream=True,
                         security_log_path=tmp_path / "sec.log")
        with TestClient(app) as client:
            assert client.get("/healthz").status_code == 200


class TestSettingBounds:
    """The panel's ``min``/``max`` are a browser hint; a hand-written POST has none.

    ``stream_idle_timeout_s=0`` made ``asyncio.wait_for(timeout=0)`` fire
    immediately: every download returned 504 having sent zero bytes.
    ``history_per_user=0`` deleted the history row the instant it was opened.
    """

    @pytest.mark.parametrize("field,value,floor", [
        ("stream_idle_timeout_s", "0", 10),
        ("stream_idle_timeout_s", "9", 10),
        ("history_per_user", "0", 50),
        ("history_per_user", "49", 50),
        ("history_per_page", "0", 5),
        ("max_active_streams_global", "0", 1),
        ("max_active_streams_per_token", "0", 1),
        ("cert_warn_days", "0", 1),
    ])
    def test_a_value_below_its_floor_is_refused(self, app_client, field, value, floor):
        path = _admin_path(app_client)
        conn = app_client.app.state.conn
        before = db.get_setting(conn, field)
        response = app_client.post(f"/{path}/settings", data={field: value},
                                   follow_redirects=False)
        assert response.status_code == 303
        message = follow_flash(app_client, response)
        assert "不能小于" in message, message
        assert str(floor) in message, message
        assert db.get_setting(conn, field) == before

    @pytest.mark.parametrize("field,value,ceiling", [
        ("history_per_page", "201", 200),
        ("stream_idle_timeout_s", "3601", 3600),
        ("max_active_streams_per_token", "257", 256),
        ("cert_warn_days", "91", 90),
    ])
    def test_a_value_above_its_ceiling_is_refused(self, app_client, field, value, ceiling):
        path = _admin_path(app_client)
        conn = app_client.app.state.conn
        before = db.get_setting(conn, field)
        response = app_client.post(f"/{path}/settings", data={field: value},
                                   follow_redirects=False)
        assert "不能大于" in follow_flash(app_client, response)
        assert db.get_setting(conn, field) == before

    def test_a_value_inside_the_range_is_stored(self, app_client):
        path = _admin_path(app_client)
        conn = app_client.app.state.conn
        app_client.post(f"/{path}/settings",
                        data={"stream_idle_timeout_s": "120",
                              "history_per_user": "1000",
                              "history_per_page": "20",
                              "cert_warn_days": "3"})
        assert db.get_int_setting(conn, "stream_idle_timeout_s") == 120
        assert db.get_int_setting(conn, "history_per_user") == 1000
        assert db.get_int_setting(conn, "history_per_page") == 20
        assert db.get_int_setting(conn, "cert_warn_days") == 3

    def test_a_zero_quota_still_means_no_limit(self, app_client):
        """Sizes keep their floor of 0: 0 is how "unlimited" is spelled."""
        path = _admin_path(app_client)
        conn = app_client.app.state.conn
        response = app_client.post(f"/{path}/settings",
                                   data={"daily_limit_gb": "0"}, follow_redirects=False)
        assert response.status_code == 303
        assert db.get_int_setting(conn, "daily_limit_bytes") == 0


class TestLoginUsesAWorkerConnection:
    """The login thread must not touch ``app.state.conn``.

    That connection is already in use by the event loop (``_relay`` calls
    ``meter.add`` after every 64 KiB chunk). pysqlite's statement cache lives on
    the connection and is outside SQLite's mutex, so the two threads corrupt each
    other: measured 73 ``InterfaceError`` in 12196 concurrent logins, each one a
    500 on a page that should have said "password incorrect".
    """

    def test_the_worker_is_handed_the_database_path_not_the_connection(self, app_client, monkeypatch):
        from app import db as db_mod
        seed_user(app_client, "alice")
        seen = []
        original = db_mod.in_worker

        def spy(path, work):
            seen.append(path)
            return original(path, work)

        monkeypatch.setattr(db_mod, "in_worker", spy)
        monkeypatch.setattr("app.main.db.in_worker", spy)
        login(app_client, "alice")
        assert seen, "in_worker was never called"
        assert all(isinstance(p, Path) for p in seen), seen
        assert app_client.app.state.db_path in seen

    def test_a_login_still_works_after_the_change(self, app_client):
        seed_user(app_client, "alice")
        response = login(app_client, "alice")
        assert response.status_code == 303
        assert response.headers["location"] == "/"

    def test_a_wrong_password_still_says_so(self, app_client):
        seed_user(app_client, "alice")
        response = login(app_client, "alice", password="nope")
        assert response.status_code == 303
        assert "用户名或密码错误" in follow_flash(app_client, response)


class TestActiveStreamsOnThePage:
    def test_the_home_page_shows_this_users_own_count(self, app_client):
        seed_user(app_client)
        login(app_client)
        proxy = app_client.app.state.proxy
        token = app_client.app.state.conn.execute(
            "SELECT token FROM users WHERE username='alice'").fetchone()["token"]
        proxy.active_by_token[str(token)] = 3
        proxy.active_global = 3
        try:
            page = app_client.get("/")
            assert page.status_code == 200
            assert "我的活跃流" in page.text
            # The number, not just the label: 3 is the only place it can come from.
            body = page.text.split("我的活跃流", 1)[1][:400]
            assert ">3<" in body.replace(" ", "")
        finally:
            proxy.active_by_token.clear()
            proxy.active_global = 0

    def test_the_home_page_never_shows_another_users_count(self, app_client):
        seed_user(app_client, "alice")
        _bob_id, bob_token = seed_user(app_client, "bob")
        login(app_client, "alice")
        proxy = app_client.app.state.proxy
        proxy.active_by_token[str(bob_token)] = 7
        proxy.active_global = 7
        try:
            text = app_client.get("/").text
            mine = text.split("我的活跃流", 1)[1][:400].replace(" ", "")
            assert ">0<" in mine, "alice has no streams, so the count must be 0"
            assert ">7<" not in mine
        finally:
            proxy.active_by_token.clear()
            proxy.active_global = 0

    def test_the_admin_page_breaks_the_count_down_by_user(self, app_client):
        path = _admin_path(app_client)
        _uid, token = seed_user(app_client, "bob")
        proxy = app_client.app.state.proxy
        proxy.active_by_token[str(token)] = 5
        proxy.active_global = 5
        try:
            page = app_client.get(f"/{path}")
            assert page.status_code == 200
            assert "bob 5" in page.text
        finally:
            proxy.active_by_token.clear()
            proxy.active_global = 0

    def test_the_admin_page_says_so_when_nothing_is_running(self, app_client):
        path = _admin_path(app_client)
        page = app_client.get(f"/{path}")
        assert "当前没有正在传输的连接" in page.text

    def test_an_orphaned_token_reports_its_streams_and_its_token_count(self, app_client):
        """One orphan token holding five streams is five connections, one token.

        The page used to print "另有 1 个", which reads as one connection while
        five were in flight.
        """
        path = _admin_path(app_client)
        seed_user(app_client, "alice")
        proxy = app_client.app.state.proxy
        proxy.active_by_token["deadbeefdeadbeefdeadbeefdeadbeef"] = 5
        proxy.active_global = 5
        try:
            text = app_client.get(f"/{path}").text
            assert "另有 5 条连接来自 1 个已重置的 token" in text
        finally:
            proxy.active_by_token.clear()
            proxy.active_global = 0

    def test_the_admin_page_links_back_to_the_home_page(self, app_client):
        path = _admin_path(app_client)
        page = app_client.get(f"/{path}")
        assert '<a href="/" role="button"' in page.text
        # And the home page is where that link lands.
        assert app_client.get("/").status_code == 200


class TestRequestsPerHistoryRow:
    def test_the_download_count_is_recorded(self, app_client, origin):
        uid, token = seed_user(app_client)
        conn = app_client.app.state.conn
        for _ in range(3):
            app_client.get(f"/u/{token}/{origin}/blob")
        rows = history_rows(conn, uid)
        assert len(rows) == 1
        assert rows[0]["requests"] == 3

    def test_a_single_request_counts_as_one(self, app_client, origin):
        uid, token = seed_user(app_client)
        app_client.get(f"/u/{token}/{origin}/blob")
        assert history_rows(app_client.app.state.conn, uid)[0]["requests"] == 1

    def test_the_home_page_shows_the_column(self, app_client, origin):
        seed_user(app_client)
        login(app_client)
        token = app_client.app.state.conn.execute(
            "SELECT token FROM users WHERE username='alice'").fetchone()["token"]
        app_client.get(f"/u/{token}/{origin}/blob")
        page = app_client.get("/")
        assert ">连接<" in page.text.replace(" ", "")

    def test_the_home_page_renders_the_count_not_the_row_id(self, app_client, origin):
        """A header-only assertion cannot tell ``r.requests`` from ``r.id``.

        Seven requests onto one row means the count is 7 while the id is still
        1, so the two numbers differ and the rendered cell has to be 7.
        """
        seed_user(app_client)
        login(app_client)
        uid = app_client.app.state.conn.execute(
            "SELECT id FROM users WHERE username='alice'").fetchone()["id"]
        token = app_client.app.state.conn.execute(
            "SELECT token FROM users WHERE username='alice'").fetchone()["token"]
        for _ in range(7):
            app_client.get(f"/u/{token}/{origin}/blob")
        row = history_rows(app_client.app.state.conn, uid)[0]
        assert row["requests"] == 7
        assert row["id"] != 7, "the id must differ from the count to tell them apart"
        cell = app_client.get("/").text.split('data-label="连接"', 1)[1][:40]
        assert ">7<" in cell.replace(" ", "")

    def test_the_admin_history_shows_the_column(self, app_client, origin):
        path = _admin_path(app_client)
        _uid, token = seed_user(app_client, "bob")
        app_client.get(f"/u/{token}/{origin}/blob")
        page = app_client.get(f"/{path}/history/{_uid}")
        assert ">连接<" in page.text.replace(" ", "")


class TestAggregateWindowCaption:
    def test_the_caption_reads_the_configured_window(self, app_client):
        seed_user(app_client)
        login(app_client)
        db.set_setting(app_client.app.state.conn, "history_aggregate_window_s", "90")
        text = app_client.get("/").text
        assert "在 90 秒内的请求合并为一条" in text
        assert "在 60 秒内" not in text


def history_rows(conn, user_id):
    from app import history
    return history.recent_for_user(conn, user_id)
