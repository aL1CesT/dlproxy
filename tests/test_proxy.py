"""End-to-end proxy behaviour against a real local origin server."""
from __future__ import annotations

import hashlib
import sqlite3
import threading

import pytest

from app import auth, db, history, quota
from tests.conftest import BLOB


def seed_user(app_client, username="alice", *, is_admin=False,
              password="password123") -> tuple[int, str]:
    conn: sqlite3.Connection = app_client.app.state.conn
    token = auth.new_token()
    cur = conn.execute(
        "INSERT INTO users(username, pwd_hash, token, token_active, disabled, "
        "is_admin, created_at) VALUES(?,?,?,1,0,?,?)",
        (username, auth.hash_password(password), token, 1 if is_admin else 0,
         db.iso_now()),
    )
    return int(cur.lastrowid), token


def url_for(token: str, target: str) -> str:
    return f"/u/{token}/{target}"


class TestBasicProxy:
    def test_downloads_exact_bytes(self, app_client, origin):
        _uid, token = seed_user(app_client)
        response = app_client.get(url_for(token, f"{origin}/blob"))
        assert response.status_code == 200
        assert response.content == BLOB
        assert hashlib.sha256(response.content).hexdigest() == \
            hashlib.sha256(BLOB).hexdigest()

    def test_content_length_is_forwarded(self, app_client, origin):
        _uid, token = seed_user(app_client)
        response = app_client.get(url_for(token, f"{origin}/blob"))
        assert response.headers["content-length"] == str(len(BLOB))
        assert response.headers["accept-ranges"] == "bytes"

    def test_set_cookie_is_stripped(self, app_client, origin):
        _uid, token = seed_user(app_client)
        response = app_client.get(url_for(token, f"{origin}/cookie"))
        assert "set-cookie" not in {k.lower() for k in response.headers}
        # Other headers still pass.
        assert response.headers["etag"] == '"abc"'

    def test_upstream_404_is_relayed(self, app_client, origin):
        _uid, token = seed_user(app_client)
        response = app_client.get(url_for(token, f"{origin}/does-not-exist"))
        assert response.status_code == 404

    def test_empty_body(self, app_client, origin):
        _uid, token = seed_user(app_client)
        response = app_client.get(url_for(token, f"{origin}/empty"))
        assert response.status_code == 200
        assert response.content == b""

    def test_head_is_proxied_but_not_recorded(self, app_client, origin):
        uid, token = seed_user(app_client)
        response = app_client.head(url_for(token, f"{origin}/blob"))
        assert response.status_code == 200
        assert response.headers["content-length"] == str(len(BLOB))
        conn: sqlite3.Connection = app_client.app.state.conn
        assert history.count_for_user(conn, uid) == 0

    def test_query_string_reaches_the_origin(self, app_client, origin):
        _uid, token = seed_user(app_client)
        response = app_client.get(url_for(token, f"{origin}/echo-headers?q=1"))
        assert response.status_code == 200


class TestTokenGate:
    def test_unknown_token_is_404(self, app_client, origin):
        response = app_client.get(url_for("nope", f"{origin}/blob"))
        assert response.status_code == 404

    def test_revoked_token_is_404(self, app_client, origin):
        uid, token = seed_user(app_client)
        conn = app_client.app.state.conn
        conn.execute("UPDATE users SET token_active=0 WHERE id=?", (uid,))
        assert app_client.get(url_for(token, f"{origin}/blob")).status_code == 404

    def test_disabled_user_is_404(self, app_client, origin):
        uid, token = seed_user(app_client)
        conn = app_client.app.state.conn
        conn.execute("UPDATE users SET disabled=1 WHERE id=?", (uid,))
        assert app_client.get(url_for(token, f"{origin}/blob")).status_code == 404

    def test_a_rejected_token_is_not_written_to_the_security_log(
            self, app_client, origin):
        """The log outlives rotation, so a wrong token must not land there."""
        bogus = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        assert app_client.get(url_for(bogus, f"{origin}/blob")).status_code == 404
        text = app_client.security_path.read_text(encoding="utf-8")
        assert "bad_token" in text
        assert bogus not in text
        assert "<token>" in text

    def test_rotated_token_invalidates_the_old_link(self, app_client, origin):
        uid, old = seed_user(app_client)
        new = auth.reset_token(app_client.app.state.conn, uid)
        assert new != old
        assert app_client.get(url_for(old, f"{origin}/blob")).status_code == 404
        assert app_client.get(url_for(new, f"{origin}/blob")).status_code == 200


class TestSsrf:
    @pytest.mark.parametrize("target", [
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://127.0.0.1:1/",
        "http://[::1]/",
        "http://192.168.0.1/",
        "http://0.0.0.0/",
    ])
    def test_internal_targets_are_403(self, app_client, target):
        """The fixture app relaxes allow_private for its own origin, so this
        test builds an app whose policy is the production one."""
        _uid, token = seed_user(app_client)
        # Directly exercise the production policy instead of the fixture's.
        from app.ssrf import SsrfPolicy
        policy = SsrfPolicy()
        host = target.split("//", 1)[1].split("/", 1)[0]
        ip = host.strip("[]").split(":")[0]
        blocked, reason = policy.is_blocked(ip)
        assert blocked, f"{target} should be refused ({reason})"

    def test_ssrf_refusal_does_not_leak_reason(self, app_client, origin):
        """A refused target yields a bare 403 with no detail in the body."""
        _uid, token = seed_user(app_client)
        response = app_client.get(url_for(token, "http://169.254.169.254/x"))
        assert response.status_code == 403
        assert response.text.strip() == "forbidden"

    def test_redirect_to_metadata_is_blocked(self, app_client, origin):
        """A public host bouncing us inward must be caught on hop 2."""
        _uid, token = seed_user(app_client)
        response = app_client.get(url_for(token, f"{origin}/redirect-internal"))
        assert response.status_code == 403


class TestRedirects:
    def test_follows_a_normal_redirect(self, app_client, origin):
        _uid, token = seed_user(app_client)
        response = app_client.get(url_for(token, f"{origin}/redirect"))
        assert response.status_code == 200
        assert response.content == BLOB

    def test_redirect_loop_becomes_502(self, app_client, origin):
        _uid, token = seed_user(app_client)
        response = app_client.get(url_for(token, f"{origin}/redirect-loop"))
        assert response.status_code == 502


class TestMethods:
    def test_post_to_a_non_git_path_is_403(self, app_client, origin):
        _uid, token = seed_user(app_client)
        response = app_client.post(url_for(token, f"{origin}/anything"),
                                   content=b"x")
        assert response.status_code == 403

    def test_put_is_403(self, app_client, origin):
        _uid, token = seed_user(app_client)
        assert app_client.put(url_for(token, f"{origin}/blob")).status_code == 403

    def test_delete_is_403(self, app_client, origin):
        _uid, token = seed_user(app_client)
        assert app_client.delete(url_for(token, f"{origin}/blob")).status_code == 403

    def test_git_upload_pack_post_is_allowed(self, app_client, origin):
        _uid, token = seed_user(app_client)
        response = app_client.post(
            url_for(token, f"{origin}/repo.git/git-upload-pack"),
            content=b"want 0000",
            headers={"Content-Type": "application/x-git-upload-pack-request"},
        )
        assert response.status_code == 200
        assert response.content.startswith(b"packfile:")

    def test_git_upload_pack_with_wrong_content_type_is_403(self, app_client, origin):
        _uid, token = seed_user(app_client)
        response = app_client.post(
            url_for(token, f"{origin}/repo.git/git-upload-pack"),
            content=b"want",
            headers={"Content-Type": "text/plain"},
        )
        assert response.status_code == 403

    def test_a_redirected_git_post_is_refused_instead_of_sent_empty(self, app_client, origin):
        """The request body is an async iterator and can only be consumed once.

        Reusing it for the next hop built the request fine and then sent zero
        bytes, so the upstream answered 400 and the client saw an empty reply
        instead of an error it could act on. Measured at unit level:
        ``hop1 first chunk: b'want-payload'`` / ``hop2: StopAsyncIteration``.

        Status alone cannot tell the two apart — without the guard httpx raises
        ``LocalProtocolError: Too little data for declared Content-Length`` and
        the generic handler turns that into the same 502. The distinguishing
        evidence is the security log: a deliberate refusal never reaches the
        ``upstream_error`` branch.
        """
        _uid, token = seed_user(app_client)
        response = app_client.post(
            url_for(token, f"{origin}/redirecting.git/git-upload-pack"),
            content=b"want 0000",
            headers={"Content-Type": "application/x-git-upload-pack-request"},
            follow_redirects=False,
        )
        assert response.status_code == 502
        log = app_client.security_path.read_text(encoding="utf-8")
        assert "upstream_error" not in log
        # And the failure is recorded on the transfer row, not left blank.
        rows = app_client.app.state.conn.execute(
            "SELECT status_code FROM transfers ORDER BY id DESC LIMIT 1"
        ).fetchall()
        assert rows and rows[0]["status_code"] == 502


class TestRangeAndHistory:
    def test_single_range_request_is_206(self, app_client, origin):
        _uid, token = seed_user(app_client)
        response = app_client.get(url_for(token, f"{origin}/blob"),
                                  headers={"Range": "bytes=0-99"})
        assert response.status_code == 206
        assert response.content == BLOB[:100]
        assert response.headers["content-range"] == f"bytes 0-99/{len(BLOB)}"

    def test_sixteen_ranges_collapse_into_one_history_row(self, app_client, origin):
        """The acceptance criterion: 16 parallel range requests, one row, and
        bytes_sent equal to the whole file."""
        uid, token = seed_user(app_client)
        conn: sqlite3.Connection = app_client.app.state.conn
        chunk = len(BLOB) // 16
        results: list[bytes] = [b""] * 16

        def worker(i: int) -> None:
            start = i * chunk
            end = (len(BLOB) - 1) if i == 15 else (start + chunk - 1)
            r = app_client.get(url_for(token, f"{origin}/blob"),
                               headers={"Range": f"bytes={start}-{end}"})
            results[i] = r.content

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert b"".join(results) == BLOB
        rows = history.recent_for_user(conn, uid)
        assert len(rows) == 1, f"expected 1 aggregate row, got {len(rows)}"
        row = rows[0]
        assert row["range_hit"] == 1
        assert row["bytes_sent"] == len(BLOB)
        assert row["status_code"] in (200, 206)

    def test_separate_urls_are_separate_rows(self, app_client, origin):
        uid, token = seed_user(app_client)
        conn = app_client.app.state.conn
        app_client.get(url_for(token, f"{origin}/blob"))
        app_client.get(url_for(token, f"{origin}/empty"))
        assert history.count_for_user(conn, uid) == 2

    def test_history_cap_trims_oldest(self, app_client, origin):
        uid, token = seed_user(app_client)
        conn = app_client.app.state.conn
        db.set_setting(conn, "history_per_user", "5")
        for i in range(8):
            app_client.get(url_for(token, f"{origin}/echo-headers?i={i}"))
        assert history.count_for_user(conn, uid) == 5

    def test_duration_is_recorded(self, app_client, origin):
        uid, token = seed_user(app_client)
        conn = app_client.app.state.conn
        app_client.get(url_for(token, f"{origin}/blob"))
        row = history.recent_for_user(conn, uid)[0]
        assert row["duration_ms"] is not None
        assert row["duration_ms"] >= 0


class TestQuota:
    def test_bytes_are_counted(self, app_client, origin):
        _uid, token = seed_user(app_client)
        conn = app_client.app.state.conn
        app_client.get(url_for(token, f"{origin}/blob"))
        state = quota.usage(conn)
        assert state.day_bytes == len(BLOB)

    def test_breaker_blocks_new_requests(self, app_client, origin):
        _uid, token = seed_user(app_client)
        conn = app_client.app.state.conn
        db.set_setting(conn, "daily_limit_bytes", "1024")
        conn.execute("INSERT INTO counters(day, bytes) VALUES(?, ?) "
                     "ON CONFLICT(day) DO UPDATE SET bytes=excluded.bytes",
                     (db.day_key(), 4096))
        response = app_client.get(url_for(token, f"{origin}/blob"))
        assert response.status_code == 429

    def test_monthly_limit_also_blocks(self, app_client, origin):
        _uid, token = seed_user(app_client)
        conn = app_client.app.state.conn
        db.set_setting(conn, "daily_limit_bytes", "0")          # unlimited
        db.set_setting(conn, "monthly_limit_bytes", "1024")
        conn.execute("INSERT INTO counters(day, bytes) VALUES(?, ?) "
                     "ON CONFLICT(day) DO UPDATE SET bytes=excluded.bytes",
                     (db.day_key(), 4096))
        response = app_client.get(url_for(token, f"{origin}/blob"))
        assert response.status_code == 429

    def test_bypass_unblocks_without_losing_usage(self, app_client, origin):
        uid, token = seed_user(app_client)
        conn = app_client.app.state.conn
        db.set_setting(conn, "daily_limit_bytes", "1024")
        conn.execute("INSERT INTO counters(day, bytes) VALUES(?, ?) "
                     "ON CONFLICT(day) DO UPDATE SET bytes=excluded.bytes",
                     (db.day_key(), 4096))
        assert app_client.get(url_for(token, f"{origin}/blob")).status_code == 429

        import datetime as dt
        quota.set_bypass(conn, db.utc_now() + dt.timedelta(hours=1))
        before = quota.usage(conn).day_bytes
        response = app_client.get(url_for(token, f"{origin}/blob"))
        assert response.status_code == 200
        # Usage kept growing rather than being zeroed.
        assert quota.usage(conn).day_bytes == before + len(BLOB)

    def test_bypass_expires(self, app_client, origin):
        _uid, token = seed_user(app_client)
        conn = app_client.app.state.conn
        db.set_setting(conn, "daily_limit_bytes", "1024")
        conn.execute("INSERT INTO counters(day, bytes) VALUES(?, ?) "
                     "ON CONFLICT(day) DO UPDATE SET bytes=excluded.bytes",
                     (db.day_key(), 4096))
        import datetime as dt
        quota.set_bypass(conn, db.utc_now() - dt.timedelta(seconds=1))
        assert app_client.get(url_for(token, f"{origin}/blob")).status_code == 429

    def test_zero_limit_means_unlimited(self, app_client, origin):
        _uid, token = seed_user(app_client)
        conn = app_client.app.state.conn
        db.set_setting(conn, "daily_limit_bytes", "0")
        db.set_setting(conn, "monthly_limit_bytes", "0")
        conn.execute("INSERT INTO counters(day, bytes) VALUES(?, ?) "
                     "ON CONFLICT(day) DO UPDATE SET bytes=excluded.bytes",
                     (db.day_key(), 10**12))
        assert app_client.get(url_for(token, f"{origin}/blob")).status_code == 200


class TestConcurrency:
    def test_per_token_cap_returns_503_with_retry_after(self, app_client, origin):
        uid, token = seed_user(app_client)
        conn = app_client.app.state.conn
        db.set_setting(conn, "max_active_streams_per_token", "1")
        proxy = app_client.app.state.proxy
        proxy.active_by_token[token] = 1        # pretend one stream is in flight
        response = app_client.get(url_for(token, f"{origin}/blob"))
        assert response.status_code == 503
        assert response.headers["retry-after"] == "5"
        proxy.active_by_token.clear()

    def test_global_cap_returns_503(self, app_client, origin):
        _uid, token = seed_user(app_client)
        conn = app_client.app.state.conn
        db.set_setting(conn, "max_active_streams_global", "1")
        proxy = app_client.app.state.proxy
        proxy.active_global = 1
        try:
            response = app_client.get(url_for(token, f"{origin}/blob"))
            assert response.status_code == 503
        finally:
            proxy.active_global = 0

    def test_slots_are_released_after_completion(self, app_client, origin):
        _uid, token = seed_user(app_client)
        app_client.get(url_for(token, f"{origin}/blob"))
        snapshot = app_client.app.state.proxy.snapshot()
        assert snapshot["global"] == 0
        assert snapshot["by_token"] == {}

    def test_slots_are_released_on_upstream_error(self, app_client, origin):
        _uid, token = seed_user(app_client)
        app_client.get(url_for(token, "http://127.0.0.1:1/nothing"))
        snapshot = app_client.app.state.proxy.snapshot()
        assert snapshot["global"] == 0


class TestHealth:
    def test_healthz_is_not_swallowed_by_the_admin_route(self, app_client):
        response = app_client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["ok"] is True


class TestBreakerAlert:
    """Spec 4.9 wants a mail when the breaker trips — once per trip.

    Every rejected request reaches the trip branch, so without the stamp in
    ``settings.breaker_alerted_at`` a busy hour would send one mail per request.
    """

    @staticmethod
    def _trip(app_client):
        conn = app_client.app.state.conn
        db.set_setting(conn, "daily_limit_bytes", "1024")
        conn.execute("INSERT INTO counters(day, bytes) VALUES(?, ?) "
                     "ON CONFLICT(day) DO UPDATE SET bytes=excluded.bytes",
                     (db.day_key(), 4096))
        return conn

    def test_the_first_rejected_request_records_the_trip(self, app_client, origin):
        _uid, token = seed_user(app_client)
        conn = self._trip(app_client)
        assert db.get_setting(conn, "breaker_alerted_at", "") == ""

        assert app_client.get(url_for(token, f"{origin}/blob")).status_code == 429
        assert db.get_setting(conn, "breaker_alerted_at", "") != ""

    def test_later_requests_in_the_same_trip_do_not_resend(self, app_client, origin):
        _uid, token = seed_user(app_client)
        conn = self._trip(app_client)

        app_client.get(url_for(token, f"{origin}/blob"))
        stamp = db.get_setting(conn, "breaker_alerted_at", "")
        assert stamp != ""

        for _ in range(3):
            assert app_client.get(url_for(token, f"{origin}/blob")).status_code == 429
        assert db.get_setting(conn, "breaker_alerted_at", "") == stamp

    def test_recovering_clears_the_stamp_so_the_next_trip_alert_again(
            self, app_client, origin):
        _uid, token = seed_user(app_client)
        conn = self._trip(app_client)
        assert app_client.get(url_for(token, f"{origin}/blob")).status_code == 429
        assert db.get_setting(conn, "breaker_alerted_at", "") != ""

        # Raise the limit: the next request finds the breaker clear and must
        # reset the stamp, or every future trip would be silently muted.
        db.set_setting(conn, "daily_limit_bytes", "0")
        assert app_client.get(url_for(token, f"{origin}/blob")).status_code == 200
        assert db.get_setting(conn, "breaker_alerted_at", "") == ""

        # Tip it back over and confirm a fresh stamp appears.
        self._trip(app_client)
        assert app_client.get(url_for(token, f"{origin}/blob")).status_code == 429
        assert db.get_setting(conn, "breaker_alerted_at", "") != ""

    def test_an_alert_is_attempted_only_when_smtp_is_configured(
            self, app_client, origin, monkeypatch):
        """The mailer returns None without SMTP; the trip must still be stamped,
        because the trip itself is the fact worth recording."""
        _uid, token = seed_user(app_client)
        conn = self._trip(app_client)
        calls: list[str] = []

        from app import mailer as mailer_mod

        def fake_send(conn_, *, subject, body, security_log=None):
            calls.append(subject)
            return None                              # unconfigured SMTP

        monkeypatch.setattr(mailer_mod, "send_alert", fake_send)
        assert app_client.get(url_for(token, f"{origin}/blob")).status_code == 429
        assert len(calls) == 1
        assert "熔断" in calls[0]
        assert db.get_setting(conn, "breaker_alerted_at", "") != ""

    def test_the_security_log_records_the_alert(self, app_client, origin, tmp_path):
        _uid, token = seed_user(app_client)
        self._trip(app_client)
        assert app_client.get(url_for(token, f"{origin}/blob")).status_code == 429
        log = (tmp_path / "security.log").read_text(encoding="utf-8")
        assert "breaker_alert" in log


class TestAbandonedStreams:
    """A body that is never pulled still has to close its history row.

    ``proxy()`` returns a StreamingResponse and hands ownership of the row to an
    async generator. A generator's ``finally`` only runs once iteration starts,
    so a disconnect between the headers and the first chunk used to leave
    ``status_code`` NULL -- rendered as a bare ``—`` in both history views.
    """

    def test_a_refused_upstream_still_records_its_status(self, app_client):
        """The 403 is decided before any streaming, so the row must carry it."""
        _uid, token = seed_user(app_client)
        # 203.0.113.0/24 is TEST-NET-3: routable-looking, never answered.
        # Port 80 keeps it inside the allowed-port set, so the request gets
        # past validation and fails at connect time -- which is the path that
        # skips the generator entirely.
        response = app_client.get(
            url_for(token, "http://203.0.113.9/x.zip"),
            follow_redirects=False,
        )
        assert response.status_code in (403, 502)
        rows = app_client.app.state.conn.execute(
            "SELECT status_code FROM transfers ORDER BY id DESC LIMIT 1"
        ).fetchall()
        assert rows, "no history row was written"
        assert rows[0]["status_code"] is not None, rows[0]["status_code"]

    async def test_the_relay_seals_itself_when_never_iterated(self):
        """Unit level: the wrapper, not the generator, is what closes the row."""
        from app.proxy import RelayResponse, RelayStream

        calls = []

        async def gen():
            calls.append("iterated")
            yield b"payload"
            calls.append("finished")

        relay = RelayStream(gen(), lambda: calls.append("seal"))
        response = RelayResponse(relay, relay=relay)

        async def send(_message):
            raise OSError("client went away")

        async def receive():
            return {"type": "http.disconnect"}

        try:
            await response({"type": "http"}, receive, send)
        except OSError:
            pass
        assert calls == ["seal"], calls
        assert relay.sealed and not relay.started
