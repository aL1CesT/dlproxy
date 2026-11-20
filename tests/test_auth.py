"""Passwords, sessions, login lockout, token lifecycle."""
from __future__ import annotations


import pytest

from datetime import timedelta

from app import auth, db

SECRET = "unit-test-secret"


@pytest.fixture()
def conn(tmp_path):
    c = db.init_db(str(tmp_path / "auth.db"))
    yield c
    c.close()


def add_user(conn, username="bob", password="password123", admin=False):
    cur = conn.execute(
        "INSERT INTO users(username, pwd_hash, token, token_active, disabled, "
        "is_admin, created_at) VALUES(?,?,?,1,0,?,?)",
        (username, auth.hash_password(password), auth.new_token(),
         1 if admin else 0, db.iso_now()),
    )
    return int(cur.lastrowid)


class TestPasswords:
    def test_hash_is_argon2id(self):
        digest = auth.hash_password("hunter2")
        assert digest.startswith("$argon2id$")

    def test_verify_roundtrip(self):
        digest = auth.hash_password("hunter2")
        assert auth.verify_password(digest, "hunter2") is True
        assert auth.verify_password(digest, "hunter3") is False

    def test_verify_garbage_hash_is_false_not_crash(self):
        assert auth.verify_password("not-a-hash", "x") is False
        assert auth.verify_password("", "x") is False

    def test_same_password_hashes_differently(self):
        assert auth.hash_password("a") != auth.hash_password("a")


class TestTokens:
    def test_token_is_base62_and_32_chars(self):
        token = auth.new_token()
        assert len(token) == 32
        assert token.isalnum()

    def test_tokens_are_unique(self):
        assert len({auth.new_token() for _ in range(500)}) == 500

    def test_lookup_returns_live_user(self, conn):
        uid = add_user(conn)
        row = conn.execute("SELECT token FROM users WHERE id=?", (uid,)).fetchone()
        assert auth.lookup_token(conn, row["token"]) is not None

    def test_lookup_misses_unknown(self, conn):
        add_user(conn)
        assert auth.lookup_token(conn, "A" * 32) is None

    def test_lookup_rejects_empty_and_oversized(self, conn):
        assert auth.lookup_token(conn, "") is None
        assert auth.lookup_token(conn, "x" * 200) is None

    def test_reset_token_changes_and_invalidates(self, conn):
        uid = add_user(conn)
        old = conn.execute("SELECT token FROM users WHERE id=?", (uid,)).fetchone()["token"]
        new = auth.reset_token(conn, uid)
        assert new != old
        assert auth.lookup_token(conn, old) is None
        assert auth.lookup_token(conn, new) is not None


class TestSessions:
    def test_roundtrip(self, conn):
        uid = add_user(conn)
        cookie = auth.create_session(conn, secret=SECRET, user_id=uid)
        user = auth.load_session(conn, secret=SECRET, cookie=cookie)
        assert user is not None and user.id == uid

    def test_wrong_secret_is_rejected(self, conn):
        uid = add_user(conn)
        cookie = auth.create_session(conn, secret=SECRET, user_id=uid)
        assert auth.load_session(conn, secret="other", cookie=cookie) is None

    def test_tampered_cookie_is_rejected(self, conn):
        uid = add_user(conn)
        cookie = auth.create_session(conn, secret=SECRET, user_id=uid)
        assert auth.load_session(conn, secret=SECRET, cookie=cookie + "x") is None

    def test_db_stores_only_a_hash(self, conn):
        uid = add_user(conn)
        cookie = auth.create_session(conn, secret=SECRET, user_id=uid)
        stored = conn.execute("SELECT token_hash FROM sessions").fetchone()["token_hash"]
        assert len(stored) == 64
        assert cookie.split(".")[0] not in stored

    def test_destroy_invalidates(self, conn):
        uid = add_user(conn)
        cookie = auth.create_session(conn, secret=SECRET, user_id=uid)
        auth.destroy_session(conn, secret=SECRET, cookie=cookie)
        assert auth.load_session(conn, secret=SECRET, cookie=cookie) is None

    def test_expired_session_is_rejected_and_purged(self, conn):
        uid = add_user(conn)
        cookie = auth.create_session(conn, secret=SECRET, user_id=uid)
        conn.execute("UPDATE sessions SET expires_at=?", ("2000-01-01T00:00:00.000Z",))
        assert auth.load_session(conn, secret=SECRET, cookie=cookie) is None
        assert conn.execute("SELECT COUNT(*) AS n FROM sessions").fetchone()["n"] == 0

    def test_disabled_user_cannot_use_an_existing_session(self, conn):
        uid = add_user(conn)
        cookie = auth.create_session(conn, secret=SECRET, user_id=uid)
        conn.execute("UPDATE users SET disabled=1 WHERE id=?", (uid,))
        assert auth.load_session(conn, secret=SECRET, cookie=cookie) is None

    def test_destroy_other_sessions_keeps_the_caller(self, conn):
        uid = add_user(conn)
        keep = auth.create_session(conn, secret=SECRET, user_id=uid)
        auth.create_session(conn, secret=SECRET, user_id=uid)
        auth.create_session(conn, secret=SECRET, user_id=uid)
        dropped = auth.destroy_other_sessions(
            conn, user_id=uid, keep_cookie=keep, secret=SECRET)
        assert dropped == 2
        # The browser that changed the password stays logged in.
        assert auth.load_session(conn, secret=SECRET, cookie=keep) is not None

    def test_an_unparsable_cookie_deletes_nothing(self, conn):
        """A caller we cannot identify must not be logged out as a side effect.

        ``DELETE ... AND token_hash <> ''`` matches every row, so an unparsable
        cookie used to evict the very session that asked for the change.
        """
        uid = add_user(conn)
        keep = auth.create_session(conn, secret=SECRET, user_id=uid)
        dropped = auth.destroy_other_sessions(
            conn, user_id=uid, keep_cookie="not-a-cookie", secret=SECRET)
        assert dropped == 0
        assert auth.load_session(conn, secret=SECRET, cookie=keep) is not None


class TestLogin:
    def test_success(self, conn):
        add_user(conn)
        row = auth.authenticate(conn, username="bob", password="password123",
                                client_ip="1.2.3.4")
        assert row["username"] == "bob"

    def test_wrong_password_is_401_with_vague_message(self, conn):
        add_user(conn)
        with pytest.raises(auth.AuthError) as exc:
            auth.authenticate(conn, username="bob", password="nope",
                              client_ip="1.2.3.4")
        assert exc.value.status == 401
        assert "bob" not in exc.value.detail

    def test_unknown_user_looks_identical_to_wrong_password(self, conn):
        add_user(conn)
        with pytest.raises(auth.AuthError) as exc:
            auth.authenticate(conn, username="nobody", password="nope",
                              client_ip="1.2.3.4")
        assert exc.value.status == 401

    def test_locks_after_five_failures(self, conn):
        add_user(conn)
        for _ in range(auth.MAX_FAILS - 1):
            with pytest.raises(auth.AuthError) as exc:
                auth.authenticate(conn, username="bob", password="bad",
                                  client_ip="9.9.9.9")
            assert exc.value.status == 401
        with pytest.raises(auth.AuthError) as exc:
            auth.authenticate(conn, username="bob", password="bad",
                              client_ip="9.9.9.9")
        assert exc.value.status == 429

    def test_lock_refuses_correct_password(self, conn):
        """Otherwise the lock only punishes the attacker who guesses wrong."""
        add_user(conn)
        for _ in range(auth.MAX_FAILS):
            with pytest.raises(auth.AuthError):
                auth.authenticate(conn, username="bob", password="bad",
                                  client_ip="9.9.9.9")
        with pytest.raises(auth.AuthError) as exc:
            auth.authenticate(conn, username="bob", password="password123",
                              client_ip="9.9.9.9")
        assert exc.value.status == 429

    def test_lockout_is_per_ip(self, conn):
        add_user(conn)
        for _ in range(auth.MAX_FAILS):
            with pytest.raises(auth.AuthError):
                auth.authenticate(conn, username="bob", password="bad",
                                  client_ip="9.9.9.9")
        # A different client is unaffected.
        assert auth.authenticate(conn, username="bob", password="password123",
                                 client_ip="5.5.5.5")["username"] == "bob"

    def test_success_clears_the_counter(self, conn):
        add_user(conn)
        for _ in range(3):
            with pytest.raises(auth.AuthError):
                auth.authenticate(conn, username="bob", password="bad",
                                  client_ip="8.8.8.8")
        auth.authenticate(conn, username="bob", password="password123",
                          client_ip="8.8.8.8")
        assert auth.lock_remaining(conn, "8.8.8.8") == 0
        row = conn.execute("SELECT * FROM login_attempts WHERE client_ip='8.8.8.8'").fetchone()
        assert row is None

    def test_lock_survives_a_restart(self, conn, tmp_path):
        """The counter lives in SQLite, so systemctl restart is not an escape."""
        add_user(conn)
        for _ in range(auth.MAX_FAILS):
            with pytest.raises(auth.AuthError):
                auth.authenticate(conn, username="bob", password="bad",
                                  client_ip="7.7.7.7")
        path = conn.execute("PRAGMA database_list").fetchone()["file"]
        conn.close()
        reopened = db.init_db(path)
        try:
            assert auth.lock_remaining(reopened, "7.7.7.7") > 0
            with pytest.raises(auth.AuthError) as exc:
                auth.authenticate(reopened, username="bob", password="password123",
                                  client_ip="7.7.7.7")
            assert exc.value.status == 429
        finally:
            reopened.close()
        conn = db.init_db(path)          # keep the fixture teardown happy

    def test_disabled_account_cannot_log_in(self, conn):
        uid = add_user(conn)
        conn.execute("UPDATE users SET disabled=1 WHERE id=?", (uid,))
        with pytest.raises(auth.AuthError) as exc:
            auth.authenticate(conn, username="bob", password="password123",
                              client_ip="1.1.1.1")
        assert exc.value.status == 403


class TestLoginAttemptsPruning:
    """``login_attempts`` is keyed by an address the caller chooses.

    Without a sweep, every new IP that ever tried a wrong password kept a row
    forever -- the one dimension an unauthenticated caller fully controls drove
    an unbounded table.
    """

    def test_a_stale_row_is_swept_on_the_next_failure(self, conn):
        add_user(conn)
        stale = db.iso(db.utc_now() - timedelta(seconds=auth.PRUNE_SECONDS + 60))
        conn.execute(
            "INSERT INTO login_attempts(client_ip, fail_count, locked_until, last_seen) "
            "VALUES('1.2.3.4', 3, NULL, ?)", (stale,))
        with pytest.raises(auth.AuthError):
            auth.authenticate(conn, username="bob", password="bad",
                              client_ip="5.6.7.8")
        survivors = {r["client_ip"] for r in
                     conn.execute("SELECT client_ip FROM login_attempts")}
        assert "1.2.3.4" not in survivors
        assert "5.6.7.8" in survivors

    def test_a_fresh_lock_is_not_swept(self, conn):
        add_user(conn)
        for _ in range(auth.MAX_FAILS):
            with pytest.raises(auth.AuthError):
                auth.authenticate(conn, username="bob", password="bad",
                                  client_ip="7.7.7.7")
        # Another address failing must not forget the live lock.
        with pytest.raises(auth.AuthError):
            auth.authenticate(conn, username="bob", password="bad",
                              client_ip="8.8.8.8")
        assert auth.lock_remaining(conn, "7.7.7.7") > 0

    def test_the_sweep_keeps_the_rows_under_the_cap(self, conn):
        add_user(conn)
        stale = db.iso(db.utc_now() - timedelta(seconds=auth.PRUNE_SECONDS + 60))
        for n in range(50):
            conn.execute(
                "INSERT INTO login_attempts(client_ip, fail_count, locked_until, "
                "last_seen) VALUES(?, 1, NULL, ?)", (f"10.0.0.{n}", stale))
        with pytest.raises(auth.AuthError):
            auth.authenticate(conn, username="bob", password="bad",
                              client_ip="192.0.2.1")
        remaining = conn.execute(
            "SELECT COUNT(*) FROM login_attempts").fetchone()[0]
        assert remaining == 1, remaining
