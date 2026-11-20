"""Quota accounting, the UTC+8 day bucket, and the meter's flush policy."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import db, quota


@pytest.fixture()
def conn(tmp_path):
    c = db.init_db(str(tmp_path / "quota.db"))
    yield c
    c.close()


class TestDayBucket:
    def test_day_uses_utc_plus_8(self):
        # 2026-01-01 17:00 UTC is already 2026-01-02 in UTC+8.
        moment = datetime(2026, 1, 1, 17, 0, tzinfo=timezone.utc)
        assert db.day_key(moment) == "2026-01-02"

    def test_day_boundary_exactly(self):
        # 16:00 UTC == 00:00 the next day in UTC+8.
        moment = datetime(2026, 1, 1, 16, 0, tzinfo=timezone.utc)
        assert db.day_key(moment) == "2026-01-02"
        moment = datetime(2026, 1, 1, 15, 59, 59, tzinfo=timezone.utc)
        assert db.day_key(moment) == "2026-01-01"

    def test_month_prefix_rolls_over_in_utc_plus_8(self):
        moment = datetime(2026, 1, 31, 17, 0, tzinfo=timezone.utc)
        assert db.month_prefix(moment) == "2026-02"

    def test_system_timezone_is_irrelevant(self, conn):
        """The bucket must not follow the process timezone (cloud hosts boot in UTC)."""
        import os, time
        before = time.tzname
        try:
            os.environ["TZ"] = "America/New_York"
            time.tzset()                                # no-op on Windows
        except (AttributeError, OSError):
            pass
        try:
            moment = datetime(2026, 6, 1, 17, 0, tzinfo=timezone.utc)
            assert db.day_key(moment) == "2026-06-02"
        finally:
            if "TZ" in os.environ:
                del os.environ["TZ"]
            time.tzname = before


class TestUsage:
    def test_empty_db_reports_zero(self, conn):
        state = quota.usage(conn)
        assert state.day_bytes == 0 and state.month_bytes == 0
        assert state.blocked is False

    def test_defaults_match_the_spec(self, conn):
        state = quota.usage(conn)
        assert state.daily_limit == 100 * 1024**3
        assert state.monthly_limit == 2000 * 1024**3

    def test_month_sums_all_days_in_the_bucket(self, conn):
        month = db.month_prefix()
        for day, n in ((f"{month}-01", 100), (f"{month}-02", 250)):
            conn.execute("INSERT INTO counters(day, bytes) VALUES(?,?)", (day, n))
        conn.execute("INSERT INTO counters(day, bytes) VALUES('1999-01-01', 999)")
        state = quota.usage(conn)
        assert state.month_bytes == 350

    def test_limits_are_read_from_settings(self, conn):
        db.set_setting(conn, "daily_limit_bytes", "1024")
        assert quota.usage(conn).daily_limit == 1024

    def test_zero_limit_is_unlimited(self, conn):
        db.set_setting(conn, "daily_limit_bytes", "0")
        db.set_setting(conn, "monthly_limit_bytes", "0")
        conn.execute("INSERT INTO counters(day, bytes) VALUES(?,?)",
                     (db.day_key(), 10**15))
        assert quota.usage(conn).blocked is False

    def test_zero_daily_still_honours_the_monthly_cap(self, conn):
        """The two caps are independent; disabling one must not disable both."""
        db.set_setting(conn, "daily_limit_bytes", "0")
        conn.execute("INSERT INTO counters(day, bytes) VALUES(?,?)",
                     (db.day_key(), 10**15))
        state = quota.usage(conn)
        assert state.day_exceeded is False
        assert state.month_exceeded is True
        assert state.reason() == "monthly"

    def test_reason_names_which_limit(self, conn):
        db.set_setting(conn, "daily_limit_bytes", "10")
        db.set_setting(conn, "monthly_limit_bytes", "10")
        conn.execute("INSERT INTO counters(day, bytes) VALUES(?,?)",
                     (db.day_key(), 100))
        assert quota.usage(conn).reason() == "daily+monthly"


class TestBypass:
    def test_future_bypass_unblocks(self, conn):
        db.set_setting(conn, "daily_limit_bytes", "10")
        conn.execute("INSERT INTO counters(day, bytes) VALUES(?,?)",
                     (db.day_key(), 100))
        assert quota.usage(conn).blocked is True
        quota.set_bypass(conn, db.utc_now() + timedelta(hours=1))
        assert quota.usage(conn).blocked is False

    def test_past_bypass_does_not(self, conn):
        db.set_setting(conn, "daily_limit_bytes", "10")
        conn.execute("INSERT INTO counters(day, bytes) VALUES(?,?)",
                     (db.day_key(), 100))
        quota.set_bypass(conn, db.utc_now() - timedelta(hours=1))
        assert quota.usage(conn).blocked is True

    def test_bypass_does_not_touch_counters(self, conn):
        conn.execute("INSERT INTO counters(day, bytes) VALUES(?,?)",
                     (db.day_key(), 4096))
        quota.set_bypass(conn, db.utc_now() + timedelta(hours=1))
        assert quota.usage(conn).day_bytes == 4096

    def test_clearing_bypass(self, conn):
        quota.set_bypass(conn, db.utc_now() + timedelta(hours=1))
        quota.set_bypass(conn, None)
        assert quota.usage(conn).bypass_until is None


class TestMeter:
    def test_accumulates_and_flushes(self, conn):
        meter = quota.Meter(conn, transfer_id=None, user_id=1,
                            flush_bytes=100)
        meter.add(60)
        assert quota.usage(conn).day_bytes == 0, "below the flush threshold"
        meter.add(60)
        assert quota.usage(conn).day_bytes == 120
        meter.close()
        assert quota.usage(conn).day_bytes == 120

    def test_close_flushes_the_remainder(self, conn):
        meter = quota.Meter(conn, transfer_id=None, user_id=1,
                            flush_bytes=10**9)
        meter.add(7)
        assert meter.close() == 7
        assert quota.usage(conn).day_bytes == 7

    def test_close_is_idempotent(self, conn):
        meter = quota.Meter(conn, transfer_id=None, user_id=1,
                            flush_bytes=10**9)
        meter.add(5)
        assert meter.close() == 5
        assert meter.close() == 5
        assert quota.usage(conn).day_bytes == 5

    def test_add_after_close_is_ignored(self, conn):
        meter = quota.Meter(conn, transfer_id=None, user_id=1,
                            flush_bytes=10**9)
        meter.close()
        meter.add(100)
        assert quota.usage(conn).day_bytes == 0

    def test_updates_the_transfer_row(self, conn):
        conn.execute(
            "INSERT INTO users(id, username, pwd_hash, token, created_at) "
            "VALUES(1,'u','x','tok',?)", (db.iso_now(),))
        cur = conn.execute(
            "INSERT INTO transfers(user_id, url, started_at, last_at) "
            "VALUES(1,'http://x/',?,?)", (db.iso_now(), db.iso_now()))
        tid = int(cur.lastrowid)
        meter = quota.Meter(conn, transfer_id=tid, user_id=1, flush_bytes=10)
        meter.add(50)
        meter.close()
        row = conn.execute("SELECT bytes_sent FROM transfers WHERE id=?", (tid,)).fetchone()
        assert row["bytes_sent"] == 50

    def test_negative_and_zero_adds_are_noops(self, conn):
        meter = quota.Meter(conn, transfer_id=None, user_id=1, flush_bytes=1)
        meter.add(0)
        meter.add(-5)
        assert meter.close() == 0


class TestDayStartBoundary:
    """The admin per-user table used to compare UTC timestamps against a UTC+8
    date string, which put the day boundary eight hours late."""

    def test_day_start_is_eight_hours_before_the_utc_midnight(self):
        from datetime import datetime, timezone
        # 2026-06-01 09:00 UTC == 2026-06-01 17:00 UTC+8, still the 1st.
        moment = datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc)
        start = db.day_start_iso(moment)
        assert start == "2026-05-31T16:00:00.000Z"

    def test_early_morning_utc_plus_8_belongs_to_the_new_day(self):
        from datetime import datetime, timezone
        # 2026-06-01 01:00 UTC+8 == 2026-05-31 17:00 UTC.
        moment = datetime(2026, 6, 1, 1, 0, tzinfo=timezone(timedelta(hours=8)))
        start = db.day_start_iso(moment)
        assert start == "2026-05-31T16:00:00.000Z"
        # 17:00Z is after that boundary, so the transfer counts as "today".
        assert "2026-05-31T17:00:00.000Z" >= start

    def test_month_start_is_the_first_of_the_utc_plus_8_month(self):
        from datetime import datetime, timezone
        moment = datetime(2026, 6, 15, 9, 0, tzinfo=timezone.utc)
        assert db.month_start_iso(moment) == "2026-05-31T16:00:00.000Z"

    def test_boundary_moves_month_at_the_right_instant(self):
        from datetime import datetime, timezone
        # 2026-05-31 16:00Z is 2026-06-01 00:00 UTC+8: the month just rolled.
        moment = datetime(2026, 5, 31, 16, 0, tzinfo=timezone.utc)
        assert db.month_prefix(moment) == "2026-06"
        assert db.month_start_iso(moment) == "2026-05-31T16:00:00.000Z"

    def test_usage_in_the_eight_hour_gap_still_counts(self, conn):
        """A transfer at 17:00Z is 'today' in UTC+8. The old query used
        day_key() + 'T00:00:00Z' and silently missed it."""
        conn.execute(
            "INSERT INTO users(id, username, pwd_hash, token, created_at) "
            "VALUES(1,'u','x','tok',?)", (db.iso_now(),))
        conn.execute(
            "INSERT INTO transfers(user_id, url, started_at, last_at, bytes_sent) "
            "VALUES(1,'http://x/',?,?,?)",
            (db.day_start_iso(), db.day_start_iso(), 4096))
        # Reproduce the query the admin page runs.
        row = conn.execute(
            "SELECT COALESCE(SUM(bytes_sent),0) AS b FROM transfers "
            "WHERE user_id=? AND started_at >= ?",
            (1, db.day_start_iso())).fetchone()
        assert row["b"] == 4096
        # And the old boundary would have missed it.
        old = db.day_key() + "T00:00:00.000Z"
        row = conn.execute(
            "SELECT COALESCE(SUM(bytes_sent),0) AS b FROM transfers "
            "WHERE user_id=? AND started_at >= ?", (1, old)).fetchone()
        assert row["b"] == 0, "the old boundary misses the first 8 hours of the day"
