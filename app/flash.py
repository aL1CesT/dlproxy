"""One-shot messages that must not travel in the URL.

Every POST handler in this app ends with a redirect, and the message it wants to
show ("密码已更新", "bob 的新 token：…") used to ride along as ``?msg=``. That is
wrong for two reasons:

* Nginx writes the whole request line to its access log. A rotated password or a
  freshly minted token would sit in ``/var/log/nginx/access.log`` for a week.
* The URL also lands in browser history, and in whatever the admin pastes into
  a chat window when asking for help.

So the message is stored server-side, keyed by an unguessable id, and the id is
handed over in a short-lived cookie. The next rendered page pops the row and
deletes the cookie: read once, then gone.

Rows are keyed by the id alone rather than by user, because a failed login has
no session to attach to and the id is 128 random bits.
"""
from __future__ import annotations

import secrets
import sqlite3
from datetime import timedelta

from . import db

__all__ = [
    "COOKIE_NAME",
    "COOKIE_MAX_AGE",
    "KIND_MESSAGE",
    "KIND_ERROR",
    "MAX_ROWS",
    "put",
    "take",
    "purge_stale",
    "trim",
]

COOKIE_NAME = "dlproxy_flash"
COOKIE_MAX_AGE = 120                # seconds; one redirect hop, generously

KIND_MESSAGE = "msg"
KIND_ERROR = "err"

# Rows are removed when read, so leftovers only exist when a client never
# followed the redirect. An hour is far beyond any legitimate hop.
_STALE_AFTER = timedelta(hours=1)

# Age alone is not a bound: ``POST /login`` puts a row on every failed attempt
# and needs no session, so a loop can mint rows faster than they expire. The
# table is capped by count as well, oldest first. 5000 rows is roughly 750 KiB
# of text — enough that no legitimate sequence of redirects ever hits it, small
# enough that the damage of a flood stays bounded.
MAX_ROWS = 5000


def purge_stale(conn: sqlite3.Connection) -> int:
    """Drop rows nobody came back for. Cheap enough to run on every put."""
    cutoff = db.iso(db.utc_now() - _STALE_AFTER)
    cur = conn.execute("DELETE FROM flashes WHERE created_at < ?", (cutoff,))
    return int(cur.rowcount or 0)


def trim(conn: sqlite3.Connection, cap: int = MAX_ROWS) -> int:
    """Delete the oldest rows until at most ``cap`` remain.

    Called from :func:`put` so an unauthenticated flood cannot grow the table
    without bound. ``LIMIT`` + ``OFFSET`` rather than a sub-query on ``rowid``
    because SQLite resolves the former directly against the primary key.
    """
    row = conn.execute("SELECT COUNT(*) AS n FROM flashes").fetchone()
    excess = int(row["n"]) - cap
    if excess <= 0:
        return 0
    cur = conn.execute(
        "DELETE FROM flashes WHERE id IN "
        "(SELECT id FROM flashes ORDER BY created_at LIMIT ?)",
        (excess,),
    )
    return int(cur.rowcount or 0)


def put(conn: sqlite3.Connection, message: str, kind: str = KIND_MESSAGE) -> str:
    """Store ``message`` and return the id to put in the cookie."""
    purge_stale(conn)
    flash_id = secrets.token_hex(16)
    conn.execute(
        "INSERT INTO flashes(id, kind, message, created_at) VALUES(?,?,?,?)",
        (flash_id, kind, message, db.iso_now()),
    )
    # Trim after the insert, so the table never holds more than ``MAX_ROWS``
    # rows even for a single moment. The value is passed explicitly rather than
    # relying on ``trim``'s default: defaults are bound at def time, so a
    # monkeypatched cap would otherwise be ignored.
    trim(conn, MAX_ROWS)
    return flash_id


def take(conn: sqlite3.Connection, flash_id: str) -> tuple[str, str] | None:
    """Pop the flash. Returns ``(kind, message)`` or None.

    Deleting before returning is the point: a page refresh must not replay a
    password that was shown exactly once.
    """
    if not flash_id:
        return None
    row = conn.execute(
        "SELECT kind, message FROM flashes WHERE id=?", (flash_id,)
    ).fetchone()
    if row is None:
        return None
    conn.execute("DELETE FROM flashes WHERE id=?", (flash_id,))
    return str(row["kind"]), str(row["message"])
