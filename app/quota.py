"""Byte accounting and the two-tier circuit breaker.

The rules, and the reasoning behind each:

* Only response-body bytes actually written to the client are counted. Headers,
  origin-side traffic and 30x hop bodies are not.
* ``counters`` is bucketed by **UTC+8 calendar day**, hardcoded, never read from
  the system timezone. The monthly figure is the sum of the current month's days.
* The breaker is checked when a request *enters*; a stream already in flight is
  never cut. That is deliberate: killing a 40 GB download at 99 % to enforce a
  quota accomplishes nothing except wasting 40 GB of someone's bandwidth.
* Manual unblock sets ``settings.bypass_until`` (ISO-8601 UTC). While that
  timestamp is in the future *both* the daily and the monthly test are skipped
  and no counter is modified, so usage stays truthful. Metering continues.
"""
from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime

from . import db

__all__ = ["Meter", "QuotaState", "check_quota", "usage", "set_bypass"]


@dataclass(frozen=True)
class QuotaState:
    day: str
    day_bytes: int
    month: str
    month_bytes: int
    daily_limit: int
    monthly_limit: int
    bypass_until: datetime | None

    @property
    def day_exceeded(self) -> bool:
        return self.daily_limit > 0 and self.day_bytes >= self.daily_limit

    @property
    def month_exceeded(self) -> bool:
        return self.monthly_limit > 0 and self.month_bytes >= self.monthly_limit

    @property
    def bypassed(self) -> bool:
        return self.bypass_until is not None and self.bypass_until > db.utc_now()

    @property
    def blocked(self) -> bool:
        if self.bypassed:
            return False
        return self.day_exceeded or self.month_exceeded

    def reason(self) -> str:
        if self.bypassed or not self.blocked:
            return ""
        parts = []
        if self.day_exceeded:
            parts.append("daily")
        if self.month_exceeded:
            parts.append("monthly")
        return "+".join(parts)


def usage(conn: sqlite3.Connection, when: datetime | None = None) -> QuotaState:
    day = db.day_key(when)
    month = db.month_prefix(when)
    row = conn.execute("SELECT bytes FROM counters WHERE day=?", (day,)).fetchone()
    day_bytes = int(row["bytes"]) if row else 0
    row = conn.execute(
        "SELECT COALESCE(SUM(bytes),0) AS b FROM counters WHERE day LIKE ?",
        (month + "-%",),
    ).fetchone()
    month_bytes = int(row["b"]) if row else 0
    return QuotaState(
        day=day,
        day_bytes=day_bytes,
        month=month,
        month_bytes=month_bytes,
        daily_limit=db.get_int_setting(conn, "daily_limit_bytes", 100 * 1024**3),
        monthly_limit=db.get_int_setting(conn, "monthly_limit_bytes", 2000 * 1024**3),
        bypass_until=db.parse_iso(db.get_setting(conn, "bypass_until", "")),
    )


def check_quota(conn: sqlite3.Connection) -> QuotaState:
    return usage(conn)


def set_bypass(conn: sqlite3.Connection, until: datetime | None) -> None:
    db.set_setting(conn, "bypass_until", db.iso(until) if until else "")


class Meter:
    """Accumulates bytes for one transfer and flushes them to SQLite.

    Flushing on every chunk would put the write lock on the hot path of a
    multi-gigabyte download. Instead we accumulate and flush when either 1 MiB
    or 2 s of wall time has passed, and always flush in ``close()`` — which the
    proxy calls from a ``finally`` block, so a client Ctrl+C, an upstream error
    and a normal completion all book the bytes that really left the socket.
    """

    FLUSH_BYTES = 1024 * 1024
    FLUSH_SECONDS = 2.0

    def __init__(self, conn: sqlite3.Connection, *, transfer_id: int | None,
                 user_id: int, flush_bytes: int | None = None) -> None:
        self._conn = conn
        self._transfer_id = transfer_id
        self._user_id = user_id
        self._flush_bytes = flush_bytes or self.FLUSH_BYTES
        self._pending = 0
        self.total = 0
        self._closed = False
        self._lock = threading.Lock()
        self._last_flush = db.utc_now()

    # -- accounting ---------------------------------------------------------

    def add(self, n: int) -> None:
        if n <= 0 or self._closed:
            return
        with self._lock:
            self._pending += n
            self.total += n
            now = db.utc_now()
            due = (
                self._pending >= self._flush_bytes
                or (now - self._last_flush).total_seconds() >= self.FLUSH_SECONDS
            )
            if due:
                self._flush_locked(now)

    def flush(self) -> None:
        with self._lock:
            self._flush_locked(db.utc_now())

    def _flush_locked(self, now: datetime) -> None:
        if self._pending <= 0:
            self._last_flush = now
            return
        n = self._pending
        self._pending = 0
        self._last_flush = now
        self._conn.execute(
            "INSERT INTO counters(day, bytes) VALUES(?, ?) "
            "ON CONFLICT(day) DO UPDATE SET bytes = bytes + excluded.bytes",
            (db.day_key(now), n),
        )
        if self._transfer_id is not None:
            self._conn.execute(
                "UPDATE transfers SET bytes_sent = bytes_sent + ?, last_at = ? WHERE id = ?",
                (n, db.iso(now), self._transfer_id),
            )

    def close(self) -> int:
        """Flush and mark closed. Idempotent; returns total bytes accounted."""
        with self._lock:
            if self._closed:
                return self.total
            self._flush_locked(db.utc_now())
            self._closed = True
            return self.total
