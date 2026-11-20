"""Database schema, additive migrations, and the CLI entry points."""
from __future__ import annotations

import sqlite3

import pytest

from app import auth, cli, db


class TestSchema:
    def test_all_spec_tables_exist(self, tmp_path):
        conn = db.init_db(str(tmp_path / "x.db"))
        tables = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"users", "sessions", "transfers", "counters", "settings",
                "login_attempts"} <= tables
        conn.close()

    def test_users_has_the_agreed_columns(self, tmp_path):
        conn = db.init_db(str(tmp_path / "x.db"))
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
        assert {"id", "username", "pwd_hash", "token", "token_active",
                "disabled", "is_admin", "created_at"} <= cols
        conn.close()

    def test_transfers_has_duration_and_xff(self, tmp_path):
        conn = db.init_db(str(tmp_path / "x.db"))
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(transfers)")}
        assert {"duration_ms", "xff_raw", "range_hit"} <= cols
        conn.close()

    def test_counters_is_keyed_by_day(self, tmp_path):
        conn = db.init_db(str(tmp_path / "x.db"))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO counters(day, bytes) VALUES('2026-01-01', 1)")
            conn.execute("INSERT INTO counters(day, bytes) VALUES('2026-01-01', 2)")
        conn.close()

    def test_defaults_are_written_once(self, tmp_path):
        path = str(tmp_path / "x.db")
        conn = db.init_db(path)
        db.set_setting(conn, "daily_limit_bytes", "123")
        conn.close()
        conn = db.init_db(path)          # simulates a restart
        assert db.get_setting(conn, "daily_limit_bytes") == "123"
        conn.close()

    def test_wal_mode_is_enabled(self, tmp_path):
        conn = db.init_db(str(tmp_path / "x.db"))
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
        conn.close()

    def test_foreign_keys_are_on(self, tmp_path):
        conn = db.init_db(str(tmp_path / "x.db"))
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        conn.close()


class TestMigration:
    def test_adds_missing_columns_to_an_old_database(self, tmp_path):
        """A database created by an earlier build lacks `disabled`/`duration_ms`.

        CREATE TABLE IF NOT EXISTS cannot add columns, so init_db has to detect
        and ALTER. Without this, upgrading in place would fail with
        'no such column: disabled' on the first login.
        """
        path = tmp_path / "old.db"
        conn = sqlite3.connect(str(path))
        conn.executescript("""
            CREATE TABLE users (
              id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
              pwd_hash TEXT NOT NULL, token TEXT UNIQUE NOT NULL,
              token_active INTEGER NOT NULL DEFAULT 1,
              is_admin INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL);
            CREATE TABLE transfers (
              id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, url TEXT NOT NULL,
              status_code INTEGER, size_total INTEGER,
              bytes_sent INTEGER NOT NULL DEFAULT 0,
              started_at TEXT NOT NULL, last_at TEXT NOT NULL,
              range_hit INTEGER NOT NULL DEFAULT 0,
              client_ip TEXT, user_agent TEXT);
        """)
        conn.commit()
        conn.close()

        conn = db.init_db(str(path))
        user_cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
        transfer_cols = {r["name"] for r in conn.execute("PRAGMA table_info(transfers)")}
        assert "disabled" in user_cols
        assert {"duration_ms", "xff_raw", "requests"} <= transfer_cols
        # And the old rows are still there.
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        conn.close()

    def test_an_old_transfer_row_counts_as_one_request(self, tmp_path):
        """``requests`` defaults to 1, so upgraded rows stay truthful.

        A row already means "the same download"; the count was simply not kept.
        Defaulting to 0 would have shown every historical row as zero requests.
        """
        path = tmp_path / "old-req.db"
        conn = sqlite3.connect(str(path))
        conn.executescript("""
            CREATE TABLE transfers (
              id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, url TEXT NOT NULL,
              status_code INTEGER, size_total INTEGER,
              bytes_sent INTEGER NOT NULL DEFAULT 0,
              started_at TEXT NOT NULL, last_at TEXT NOT NULL,
              range_hit INTEGER NOT NULL DEFAULT 0,
              client_ip TEXT, user_agent TEXT);
            INSERT INTO transfers(user_id, url, started_at, last_at)
              VALUES(1, 'https://e.com/a.zip', '2026-01-01T00:00:00.000Z',
                     '2026-01-01T00:00:00.000Z');
        """)
        conn.commit()
        conn.close()

        conn = db.init_db(str(path))
        assert conn.execute(
            "SELECT requests FROM transfers WHERE url='https://e.com/a.zip'"
        ).fetchone()[0] == 1
        conn.close()

    def test_migration_is_idempotent(self, tmp_path):
        path = str(tmp_path / "x.db")
        db.init_db(path).close()
        db.init_db(path).close()          # must not raise
        conn = db.init_db(path)
        assert conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0] > 0
        conn.close()

    def test_an_old_login_attempts_table_gains_last_seen(self, tmp_path):
        """Databases written before the sweep existed have no ``last_seen``.

        ``auth.record_failure`` filters on it, so an un-migrated install would
        raise ``no such column`` on the first wrong password instead of
        recording the failure.
        """
        path = tmp_path / "old-login.db"
        conn = sqlite3.connect(str(path))
        conn.executescript("""
            CREATE TABLE login_attempts (
              client_ip TEXT PRIMARY KEY,
              fail_count INTEGER NOT NULL DEFAULT 0,
              locked_until TEXT);
            INSERT INTO login_attempts(client_ip, fail_count) VALUES('1.2.3.4', 2);
        """)
        conn.commit()
        conn.close()

        conn = db.init_db(str(path))
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(login_attempts)")}
        assert "last_seen" in cols
        # The pre-existing row survives; it simply has no sweep timestamp yet.
        assert conn.execute(
            "SELECT fail_count FROM login_attempts WHERE client_ip='1.2.3.4'"
        ).fetchone()[0] == 2
        conn.close()


class TestWorkerConnections:
    """``db.in_worker`` exists because one connection cannot serve two threads.

    ``connect()`` passes ``check_same_thread=False`` and CPython's pysqlite
    keeps a statement cache on the connection object. SQLite's own mutex covers
    the library, not that cache, so a worker thread running argon2 alongside the
    event loop's ``meter.add()`` corrupts prepared statements: measured 44-66
    ``InterfaceError: bad parameter or other API misuse`` per five seconds,
    dropping to zero with ``cached_statements=0``.
    """

    def test_a_worker_gets_its_own_connection(self, tmp_path):
        path = str(tmp_path / "w.db")
        main = db.init_db(path)
        try:
            seen = []
            db.in_worker(path, lambda worker: seen.append(worker))
            assert seen and seen[0] is not main
        finally:
            main.close()

    def test_the_worker_connection_is_closed_afterwards(self, tmp_path):
        path = str(tmp_path / "w2.db")
        db.init_db(path).close()
        box = {}
        db.in_worker(path, lambda worker: box.setdefault("c", worker))

        def touch():
            try:
                box["c"].execute("SELECT 1").fetchone()
                return "still open"
            except sqlite3.ProgrammingError as exc:
                return str(exc)

        assert "closed" in touch()

    def test_the_worker_connection_is_closed_even_when_work_raises(self, tmp_path):
        path = str(tmp_path / "w3.db")
        db.init_db(path).close()
        box = {}

        def boom(worker):
            box["c"] = worker
            raise RuntimeError("work failed")

        with pytest.raises(RuntimeError):
            db.in_worker(path, boom)
        assert "closed" in self._state(box["c"])

    @staticmethod
    def _state(conn) -> str:
        try:
            conn.execute("SELECT 1").fetchone()
            return "still open"
        except sqlite3.ProgrammingError as exc:
            return str(exc)

    def test_two_threads_hammering_in_worker_stay_clean(self, tmp_path):
        """The shape production has: one writer in the loop, one in a worker.

        Run against ``in_worker`` this is silent; swap it for a shared
        connection and ``InterfaceError`` appears within a few hundred
        iterations. The loop count is fixed rather than time-boxed so the test
        costs the same on a 1-core ARM box as on a workstation.
        """
        import threading

        path = str(tmp_path / "hammer.db")
        main = db.init_db(path)
        main.execute("INSERT INTO counters(day, bytes) VALUES('2026-01-01', 0)")
        errors: list[str] = []
        rounds = 300

        def meter():
            try:
                for _ in range(rounds):
                    main.execute(
                        "UPDATE counters SET bytes = bytes + 1 WHERE day=?",
                        ("2026-01-01",))
            except Exception as exc:            # noqa: BLE001 - that is the point
                errors.append(f"meter: {type(exc).__name__}: {exc}")

        def login():
            try:
                for _ in range(rounds):
                    db.in_worker(path, lambda w: w.execute(
                        "INSERT INTO login_attempts(client_ip, fail_count, last_seen)"
                        " VALUES('9.9.9.9', 1, 'x')"
                        " ON CONFLICT(client_ip) DO UPDATE SET"
                        " fail_count = fail_count + 1").fetchone())
            except Exception as exc:            # noqa: BLE001
                errors.append(f"login: {type(exc).__name__}: {exc}")

        thread = threading.Thread(target=login)
        thread.start()
        meter()
        thread.join(timeout=60)
        main.close()
        assert not thread.is_alive()
        assert errors == [], errors


class TestSettingsHelpers:
    def test_get_int_handles_garbage(self, tmp_path):
        conn = db.init_db(str(tmp_path / "x.db"))
        db.set_setting(conn, "junk", "not-a-number")
        assert db.get_int_setting(conn, "junk", 42) == 42
        conn.close()

    def test_missing_key_returns_default(self, tmp_path):
        conn = db.init_db(str(tmp_path / "x.db"))
        assert db.get_setting(conn, "nope", "fallback") == "fallback"
        conn.close()

    def test_iso_parse_roundtrip(self):
        # Stored timestamps are millisecond-precision on purpose: sub-millisecond
        # digits would only bloat every row and make log comparisons noisy.
        now = db.utc_now()
        parsed = db.parse_iso(db.iso(now))
        assert parsed is not None
        assert abs((parsed - now).total_seconds()) < 0.001

    def test_parse_iso_tolerates_garbage(self):
        assert db.parse_iso("") is None
        assert db.parse_iso("yesterday") is None


class TestCli:
    @pytest.fixture()
    def cli_db(self, tmp_path):
        return str(tmp_path / "cli.db")

    def test_createadmin_prints_a_password_and_token(self, cli_db, capsys):
        assert cli.main(["--db", cli_db, "createadmin", "boss"]) == 0
        out = capsys.readouterr().out
        assert "boss" in out and "密码" in out and "token" in out
        conn = db.init_db(cli_db)
        row = conn.execute("SELECT * FROM users WHERE username='boss'").fetchone()
        assert row["is_admin"] == 1
        assert auth.verify_password(row["pwd_hash"], out.split("密码:")[1].split()[0])
        conn.close()

    def test_createuser_makes_a_non_admin(self, cli_db):
        assert cli.main(["--db", cli_db, "createuser", "bob"]) == 0
        conn = db.init_db(cli_db)
        assert conn.execute("SELECT is_admin FROM users WHERE username='bob'"
                            ).fetchone()[0] == 0
        conn.close()

    def test_duplicate_user_fails(self, cli_db, capsys):
        cli.main(["--db", cli_db, "createuser", "bob"])
        assert cli.main(["--db", cli_db, "createuser", "bob"]) == 1
        assert "已存在" in capsys.readouterr().err

    def test_setpassword(self, cli_db, capsys):
        cli.main(["--db", cli_db, "createuser", "bob"])
        capsys.readouterr()
        assert cli.main(["--db", cli_db, "setpassword", "bob",
                         "--password", "brandnew123"]) == 0
        conn = db.init_db(cli_db)
        row = conn.execute("SELECT pwd_hash FROM users WHERE username='bob'").fetchone()
        assert auth.verify_password(row["pwd_hash"], "brandnew123")
        conn.close()

    def test_showtoken(self, cli_db, capsys):
        cli.main(["--db", cli_db, "createuser", "bob"])
        capsys.readouterr()
        assert cli.main(["--db", cli_db, "showtoken", "bob"]) == 0
        out = capsys.readouterr().out
        assert "bob" in out and "有效" in out

    def test_showtoken_unknown_user(self, cli_db, capsys):
        assert cli.main(["--db", cli_db, "showtoken", "ghost"]) == 1
        assert "不存在" in capsys.readouterr().err

    def test_listusers(self, cli_db, capsys):
        cli.main(["--db", cli_db, "createadmin", "boss"])
        capsys.readouterr()
        assert cli.main(["--db", cli_db, "listusers"]) == 0
        out = capsys.readouterr().out
        assert "boss" in out and "今日" in out

    def test_backup_produces_a_readable_snapshot(self, cli_db, tmp_path):
        cli.main(["--db", cli_db, "createuser", "bob"])
        dest = tmp_path / "backup" / "snap.db"
        assert cli.main(["--db", cli_db, "backup", str(dest)]) == 0
        conn = sqlite3.connect(str(dest))
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        conn.close()

    def test_set_site_records_the_base_url(self, cli_db, capsys):
        assert cli.main(["--db", cli_db, "set-site", "https://203.0.113.9"]) == 0
        assert "已记录" in capsys.readouterr().out
        conn = db.init_db(cli_db)
        assert db.get_setting(conn, "public_base") == "https://203.0.113.9"
        assert db.get_setting(conn, "public_host") == "203.0.113.9"
        conn.close()

    def test_set_site_supplies_the_scheme(self, cli_db):
        cli.main(["--db", cli_db, "set-site", "203.0.113.9"])
        conn = db.init_db(cli_db)
        assert db.get_setting(conn, "public_base") == "https://203.0.113.9"
        conn.close()

    def test_set_site_trailing_slash_is_stripped(self, cli_db):
        cli.main(["--db", cli_db, "set-site", "https://example.com/"])
        conn = db.init_db(cli_db)
        assert db.get_setting(conn, "public_base") == "https://example.com"
        conn.close()

    def test_set_site_rejects_a_path(self, cli_db, capsys):
        assert cli.main(["--db", cli_db, "set-site", "https://e.com/x"]) == 1
        assert "不含路径" in capsys.readouterr().err

    def test_set_site_with_no_argument_prints_the_current_value(self, cli_db, capsys):
        cli.main(["--db", cli_db, "set-site", "https://kept.example"])
        capsys.readouterr()
        assert cli.main(["--db", cli_db, "set-site"]) == 0
        assert "https://kept.example" in capsys.readouterr().out

    def test_public_base_falls_back_to_the_placeholder(self, cli_db):
        conn = db.init_db(cli_db)
        assert db.public_base(conn) == db.PLACEHOLDER_BASE
        assert db.is_placeholder_base(db.public_base(conn)) is True
        conn.close()


class TestPublicBaseHelper:
    def test_host_only_is_promoted_to_https(self, tmp_path):
        conn = db.init_db(str(tmp_path / "x.db"))
        db.set_setting(conn, "public_host", "example.com")
        assert db.public_base(conn) == "https://example.com"
        assert db.is_placeholder_base(db.public_base(conn)) is False
        conn.close()

    def test_base_wins_over_host(self, tmp_path):
        conn = db.init_db(str(tmp_path / "x.db"))
        db.set_setting(conn, "public_base", "https://a.example")
        db.set_setting(conn, "public_host", "b.example")
        assert db.public_base(conn) == "https://a.example"
        conn.close()

    def test_blank_ignores_surrounding_whitespace(self, tmp_path):
        conn = db.init_db(str(tmp_path / "x.db"))
        db.set_setting(conn, "public_base", "   ")
        assert db.public_base(conn) == db.PLACEHOLDER_BASE
        conn.close()


class TestRetiredSettings:
    """Keys that never drove anything must not survive an upgrade.

    Each of these was written in the very first commit; their logic landed
    elsewhere (timeouts in ssrf.py, the soft cap in proxy.py, the cert timestamp
    in /var/lib/certbot/last-success). Leaving the rows behind is worse than
    deleting them: the admin page and the code comments then advertise knobs that
    do nothing.
    """

    def test_init_db_does_not_write_them(self, tmp_path):
        conn = db.init_db(str(tmp_path / "r.db"))
        for key in db.RETIRED_SETTINGS:
            row = conn.execute("SELECT 1 FROM settings WHERE key=?", (key,)).fetchone()
            assert row is None, f"{key} should not exist"
        conn.close()

    def test_an_old_database_is_cleaned_on_the_next_boot(self, tmp_path):
        path = str(tmp_path / "old.db")
        conn = db.init_db(path)
        for key in db.RETIRED_SETTINGS:
            db.set_setting(conn, key, "999")
        conn.close()

        conn = db.init_db(path)                     # the service restarting
        left = conn.execute(
            "SELECT key FROM settings WHERE key IN (%s)"
            % ",".join("?" * len(db.RETIRED_SETTINGS)),
            db.RETIRED_SETTINGS,
        ).fetchall()
        assert [r["key"] for r in left] == []
        conn.close()

    def test_the_keys_that_do_work_are_still_there(self, tmp_path):
        conn = db.init_db(str(tmp_path / "k.db"))
        for key in ("stream_idle_timeout_s", "transfer_soft_cap_bytes",
                    "cert_warn_days", "breaker_alerted_at", "cert_alert_state"):
            assert db.get_setting(conn, key, None) is not None, key
        conn.close()


class TestCertAlertCli:
    """``alert-cert`` is what cert-check.sh calls every six hours."""

    @pytest.fixture()
    def cli_db(self, tmp_path):
        return str(tmp_path / "cert.db")

    def test_a_healthy_certificate_sends_nothing(self, cli_db, capsys):
        assert cli.main(["--db", cli_db, "alert-cert", "--left-hours", "200"]) == 0
        assert "无需告警" in capsys.readouterr().out

    def test_the_warn_band_follows_the_threshold_from_the_database(
            self, cli_db, capsys):
        """73 h left is healthy under the shipped 3-day (72 h) threshold, but a
        warning once the panel raises the threshold to 4 days (96 h)."""
        assert cli.main(["--db", cli_db, "alert-cert", "--left-hours", "73"]) == 0
        assert "无需告警" in capsys.readouterr().out

        conn = db.init_db(cli_db)
        db.set_setting(conn, "cert_warn_days", "4")     # -> 96 h warn, 48 h crit
        conn.close()

        assert cli.main(["--db", cli_db, "alert-cert", "--left-hours", "73"]) == 2
        assert "96 小时" in capsys.readouterr().out

    def test_the_same_state_does_not_mail_twice(self, cli_db, capsys):
        """The cron runs every six hours; a two-day incident must not send eight
        identical messages."""
        assert cli.main(["--db", cli_db, "alert-cert", "--left-hours", "20"]) == 3
        first = capsys.readouterr().out
        assert "仅写入本日志" in first             # SMTP is unconfigured in tests

        assert cli.main(["--db", cli_db, "alert-cert", "--left-hours", "19"]) == 3
        assert "状态未变" in capsys.readouterr().out

    def test_recovering_clears_the_state_so_the_next_incident_alerts(
            self, cli_db, capsys):
        cli.main(["--db", cli_db, "alert-cert", "--left-hours", "20"])
        capsys.readouterr()
        assert cli.main(["--db", cli_db, "alert-cert", "--left-hours", "200"]) == 0
        assert "状态已复位" in capsys.readouterr().out

        conn = db.init_db(cli_db)
        assert db.get_setting(conn, "cert_alert_state", "x") == ""
        conn.close()

        # Now it must alert again, not be treated as a repeat.
        assert cli.main(["--db", cli_db, "alert-cert", "--left-hours", "20"]) == 3
        assert "仅写入本日志" in capsys.readouterr().out

    def test_a_stalled_renewal_is_its_own_state(self, cli_db, capsys):
        """Signal B (stamp too old) is a different event from Signal A (expiry),
        even at the same level, so each alerts once."""
        assert cli.main(["--db", cli_db, "alert-cert", "--left-hours", "200"]) == 0
        capsys.readouterr()

        rc = cli.main(["--db", cli_db, "alert-cert", "--left-hours", "200",
                       "--stamp-broken"])
        assert rc == 3
        assert "续期自动化疑似失灵" in capsys.readouterr().out

        rc = cli.main(["--db", cli_db, "alert-cert", "--left-hours", "200",
                       "--stamp-broken"])
        assert rc == 3
        assert "状态未变" in capsys.readouterr().out

        # Expiry alone is a different state again.
        assert cli.main(["--db", cli_db, "alert-cert", "--left-hours", "20"]) == 3
        assert "仅写入本日志" in capsys.readouterr().out
