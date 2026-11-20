"""Transfer history: 60-second session aggregation with a 1000-row cap.

A 16-thread aria2 download is 16 separate HTTP requests. They must appear as one
row, or the history page is unreadable and the byte column is useless.

Aggregation key: ``(user_id, url, client_ip)`` plus a 60 s window on ``last_at``.
A new request either extends the most recent matching row or opens a new one.

The row is opened *before* the upstream request so that a client that
disconnects mid-body still leaves a record; the proxy closes it in ``finally``
with the real byte count and status (499 for client aborts, matching nginx's
convention).
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import timedelta

from . import db

__all__ = [
    "TransferRow",
    "open_transfer",
    "close_transfer",
    "recent_for_user",
    "trim_user",
]

CLIENT_CLOSED_STATUS = 499       # nginx's "client closed request"


@dataclass
class TransferRow:
    id: int
    aggregated: bool             # True when an existing row was reused


def open_transfer(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    url: str,
    client_ip: str,
    user_agent: str,
    range_hit: bool,
    window_s: int = 60,
    per_user_cap: int = 1000,
    xff_raw: str | None = None,
) -> TransferRow:
    """Reuse a recent matching row, or insert a new one."""
    now = db.utc_now()
    now_iso = db.iso(now)
    window_start = db.iso(now.replace(microsecond=0))
    # Compute the window boundary in ISO space so the comparison is index-friendly.
    cutoff = db.iso(now - timedelta(seconds=window_s))
    del window_start

    row = conn.execute(
        "SELECT id FROM transfers "
        "WHERE user_id=? AND url=? AND IFNULL(client_ip,'')=? AND last_at >= ? "
        "ORDER BY id DESC LIMIT 1",
        (user_id, url, client_ip or "", cutoff),
    ).fetchone()

    if row is not None:
        conn.execute(
            "UPDATE transfers SET last_at=?, "
            "range_hit = MAX(range_hit, ?), "
            "requests = requests + 1, "
            "user_agent = COALESCE(NULLIF(user_agent,''), ?) "
            "WHERE id=?",
            (now_iso, 1 if range_hit else 0, user_agent, row["id"]),
        )
        return TransferRow(id=int(row["id"]), aggregated=True)

    cur = conn.execute(
        "INSERT INTO transfers(user_id, url, status_code, size_total, bytes_sent, "
        "started_at, last_at, range_hit, client_ip, user_agent, xff_raw, duration_ms, "
        "requests) "
        "VALUES(?,?,NULL,NULL,0,?,?,?,?,?,?,NULL,1)",
        (user_id, url, now_iso, now_iso, 1 if range_hit else 0, client_ip,
         user_agent, xff_raw),
    )
    transfer_id = int(cur.lastrowid)
    trim_user(conn, user_id, per_user_cap)
    return TransferRow(id=transfer_id, aggregated=False)


def close_transfer(
    conn: sqlite3.Connection,
    transfer_id: int,
    *,
    status_code: int | None,
    size_total: int | None,
    duration_ms: int | None,
    range_hit: bool,
) -> None:
    conn.execute(
        "UPDATE transfers SET status_code=?, "
        "size_total=COALESCE(?, size_total), "
        "duration_ms=COALESCE(?, duration_ms), "
        "range_hit=MAX(range_hit, ?), "
        "last_at=? "
        "WHERE id=?",
        (
            status_code,
            size_total,
            duration_ms,
            1 if range_hit else 0,
            db.iso(db.utc_now()),
            transfer_id,
        ),
    )


def trim_user(conn: sqlite3.Connection, user_id: int, cap: int = 1000) -> int:
    """Delete the oldest rows beyond ``cap``. Called after every insert."""
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM transfers WHERE user_id=?", (user_id,)
    ).fetchone()
    excess = int(row["n"]) - cap
    if excess <= 0:
        return 0
    cur = conn.execute(
        "DELETE FROM transfers WHERE id IN ("
        "  SELECT id FROM transfers WHERE user_id=? ORDER BY id ASC LIMIT ?"
        ")",
        (user_id, excess),
    )
    return cur.rowcount or 0


def recent_for_user(
    conn: sqlite3.Connection, user_id: int, *, limit: int = 50, offset: int = 0
) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            "SELECT * FROM transfers WHERE user_id=? ORDER BY id DESC LIMIT ? OFFSET ?",
            (user_id, limit, offset),
        )
    )


def count_for_user(conn: sqlite3.Connection, user_id: int) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM transfers WHERE user_id=?", (user_id,)
    ).fetchone()
    return int(row["n"])
