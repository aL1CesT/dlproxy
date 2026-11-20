"""SQLite schema, migrations and connection helpers.

Beyond the core tables there are two columns worth calling out:

  users.disabled      -- soft-disable an account without deleting history
  transfers.duration_ms -- first-byte-to-last-byte span (not a sum of chunk
                           latencies), used by the history page

Dates are stored as ISO-8601 text in UTC. The *quota* date bucket is a separate
concern: ``quota.day_key()`` hardcodes UTC+8 regardless of the system timezone.
"""
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, TypeVar

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

APP_ROOT = Path(__file__).resolve().parent.parent          # /opt/dlproxy
DEFAULT_DB_PATH = APP_ROOT / "data" / "app.db"


def db_path() -> Path:
    return Path(os.environ.get("DLPROXY_DB_PATH", str(DEFAULT_DB_PATH)))


def resolve_path(path: Path | str | None = None) -> Path:
    """The absolute on-disk path ``connect()`` would open."""
    p = Path(path) if path is not None else db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p.resolve()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  pwd_hash      TEXT NOT NULL,
  token         TEXT UNIQUE NOT NULL,
  token_active  INTEGER NOT NULL DEFAULT 1,
  disabled      INTEGER NOT NULL DEFAULT 0,
  is_admin      INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL,
  expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_hash ON sessions(token_hash);

CREATE TABLE IF NOT EXISTS transfers (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  url           TEXT NOT NULL,
  status_code   INTEGER,
  size_total    INTEGER,
  bytes_sent    INTEGER NOT NULL DEFAULT 0,
  started_at    TEXT NOT NULL,
  last_at       TEXT NOT NULL,
  range_hit     INTEGER NOT NULL DEFAULT 0,
  client_ip     TEXT,
  user_agent    TEXT,
  xff_raw       TEXT,
  duration_ms   INTEGER,
  requests      INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_transfers_user ON transfers(user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_transfers_agg
  ON transfers(user_id, url, last_at);

CREATE TABLE IF NOT EXISTS counters (
  day    TEXT NOT NULL,
  bytes  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day)
);

CREATE TABLE IF NOT EXISTS settings (
  key    TEXT PRIMARY KEY,
  value  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
  client_ip   TEXT PRIMARY KEY,
  fail_count  INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  last_seen   TEXT
);

-- One-shot messages. Kept here rather than in the URL: the query string ends up
-- in nginx's access log and in browser history, and these messages can carry a
-- freshly rotated password or token. See app/flash.py.
CREATE TABLE IF NOT EXISTS flashes (
  id          TEXT PRIMARY KEY,
  kind        TEXT NOT NULL,
  message     TEXT NOT NULL,
  created_at  TEXT NOT NULL
);
"""

# Defaults written on first boot only (INSERT OR IGNORE), so an admin edit is
# never clobbered by a restart.
DEFAULT_SETTINGS = {
    "daily_limit_bytes": str(100 * 1024**3),        # 100 GB
    "monthly_limit_bytes": str(2000 * 1024**3),     # 2000 GB
    "max_active_streams_global": "256",
    "max_active_streams_per_token": "128",
    "stream_idle_timeout_s": "120",
    "max_redirects": "5",
    "max_url_bytes": "8192",
    "history_per_user": "1000",
    "history_per_page": "20",                       # rows shown per history page
    "history_aggregate_window_s": "60",
    "transfer_soft_cap_bytes": str(50 * 1024**3),
    "admin_path": "",                                # filled at first boot
    "bypass_until": "",                              # ISO-8601 UTC or empty
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_user": "",
    "smtp_pass": "",
    "smtp_from": "",
    "smtp_to": "",
    "smtp_tls": "1",
    # Certificate WARN threshold, in days. deploy/cert-check.sh reads this row
    # and derives its own hour-based threshold from it; the panel writes the
    # same key, so the field in the admin page really is the threshold.
    "cert_warn_days": "3",
    # Alert de-duplication. A breaker that trips during a busy hour would
    # otherwise send one mail per rejected request, and a cert that stays
    # critical for two days would send one every six hours.
    "breaker_alerted_at": "",      # ISO-8601 UTC while the breaker is tripped
    "cert_alert_state": "",        # "2" = warned, "3" = critical, "" = healthy
    # Public base URL, e.g. "https://203.0.113.9". deploy.sh writes this once it
    # knows the certificate identity, so the console menu can print a clickable
    # link instead of the "<你的域名或IP>" placeholder. Empty means "unknown".
    "public_base": "",
    "public_host": "",
}


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

def connect(path: Path | str | None = None) -> sqlite3.Connection:
    """Open a connection with the pragmas this workload wants.

    WAL keeps the reader (admin pages) from blocking the writer (transfer
    accounting). ``synchronous=NORMAL`` is the documented safe pairing with WAL.

    ``check_same_thread=False``: the test client runs the app on its own thread,
    so the Python-side guard has to come off.

    **One connection is still used by one thread at a time.** ``sqlite3``
    reports ``threadsafety == 3``, which is true of the SQLite library, but
    CPython's ``pysqlite`` keeps a statement cache *on the connection object*
    and that cache is not covered by SQLite's mutex. Two threads sharing one
    connection therefore corrupt each other's prepared statements and raise
    ``sqlite3.InterfaceError: bad parameter or other API misuse`` — measured at
    44-66 failures per five seconds when a login raced a metered download, and
    zero with the statement cache disabled, which is how the cache (not SQLite)
    was identified as the culprit.

    Callers that hand a connection to a worker thread must use
    :func:`in_worker` instead, which gives that thread a connection of its own
    and closes it afterwards.
    """
    p = Path(path) if path is not None else db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(p), timeout=15.0, isolation_level=None, check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


# A connection per worker-thread call, not a per-thread cache: the app is
# long-lived but tests spin up hundreds of apps against hundreds of temporary
# databases, and a cache keyed by path would hold every one of them open.
def in_worker(path: Path | str | None, work: Callable[[sqlite3.Connection], T]) -> T:
    """Run ``work`` against a connection this thread owns, then close it.

    Opening a SQLite handle costs a few hundred microseconds; the argon2
    verification this wraps costs ~40 ms, so the connection is noise. What it
    buys is that the event loop's connection is never touched from a second
    thread, which is what produced ``sqlite3.InterfaceError`` under load.
    """
    conn = connect(path)
    try:
        return work(conn)
    finally:
        conn.close()


# Columns added after the first release. ``CREATE TABLE IF NOT EXISTS`` cannot
# add a column to an existing table, so each entry is checked against
# PRAGMA table_info and applied with ALTER TABLE when missing.
ADDITIVE_COLUMNS = {
    "users": {"disabled": "INTEGER NOT NULL DEFAULT 0"},
    "transfers": {
        "duration_ms": "INTEGER",
        "xff_raw": "TEXT",
        # A row already means "these requests were the same download", but the
        # count itself was thrown away: 16 aria2 threads and one curl looked
        # identical. Default 1 so the existing rows stay truthful.
        "requests": "INTEGER NOT NULL DEFAULT 1",
    },
    # Added so ``auth.record_failure`` can sweep stale rows: a single wrong
    # password from a new address used to leave a row behind forever.
    "login_attempts": {"last_seen": "TEXT"},
}


def _migrate(conn: sqlite3.Connection) -> None:
    for table, columns in ADDITIVE_COLUMNS.items():
        present = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in columns.items():
            if name not in present:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


# Keys that used to exist and never drove anything. ``init_db`` deletes them so
# an upgraded database cannot keep a row that looks adjustable but is not: the
# four here were written in the first commit, before their logic landed
# elsewhere (timeouts in ``ssrf.py``, the soft cap in ``proxy.py``, the cert
# timestamp in ``/var/lib/certbot/last-success``).
RETIRED_SETTINGS = (
    "single_request_soft_limit_bytes",
    "upstream_connect_timeout_s",
    "upstream_read_timeout_s",
    "last_cert_check",
)


def init_db(path: Path | str | None = None) -> sqlite3.Connection:
    conn = connect(path)
    conn.executescript(SCHEMA)
    _migrate(conn)
    for key, value in DEFAULT_SETTINGS.items():
        conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?,?)",
                     (key, value))
    if RETIRED_SETTINGS:
        conn.executemany("DELETE FROM settings WHERE key=?",
                         [(k,) for k in RETIRED_SETTINGS])
    return conn


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

UTC = timezone.utc
# Quota day bucket. Hardcoded +08:00 — deliberately NOT the system timezone:
# a cloud instance boots in UTC and a stray `timedatectl set-timezone` must not
# silently shift a user's daily allowance.
QUOTA_TZ = timezone(timedelta(hours=8))


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def iso_now() -> str:
    return iso(utc_now())


def parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError:
        pass
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def day_key(ts: datetime | None = None) -> str:
    """UTC+8 calendar day, e.g. '2026-11-18'."""
    return (ts or utc_now()).astimezone(QUOTA_TZ).strftime("%Y-%m-%d")


def month_prefix(ts: datetime | None = None) -> str:
    return (ts or utc_now()).astimezone(QUOTA_TZ).strftime("%Y-%m")


def day_start_iso(ts: datetime | None = None) -> str:
    """The UTC instant at which the current UTC+8 day began, as stored ISO text.

    Transfer timestamps are stored in UTC, so comparing them against the bare
    string '2026-11-18T00:00:00Z' would put the boundary eight hours late: a
    download at 01:00 UTC+8 (= 17:00Z the previous day) belongs to today but
    sorts before that string. Anything that filters transfers by "today" must
    use this value, not day_key() + 'T00:00:00Z'.
    """
    moment = (ts or utc_now()).astimezone(QUOTA_TZ)
    start = moment.replace(hour=0, minute=0, second=0, microsecond=0)
    return iso(start)


def month_start_iso(ts: datetime | None = None) -> str:
    """Same idea for the first instant of the current UTC+8 month."""
    moment = (ts or utc_now()).astimezone(QUOTA_TZ)
    start = moment.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return iso(start)


# ---------------------------------------------------------------------------
# Settings accessors
# ---------------------------------------------------------------------------

def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row is not None else default


def get_int_setting(conn: sqlite3.Connection, key: str, default: int = 0) -> int:
    raw = get_setting(conn, key, "")
    if raw == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings(key, value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def all_settings(conn: sqlite3.Connection) -> dict[str, str]:
    return {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM settings")}


PLACEHOLDER_BASE = "<你的域名或IP>"


def public_base(conn: sqlite3.Connection) -> str:
    """The site's public base URL, or a placeholder when nobody has told us.

    ``deploy.sh`` fills ``settings.public_base`` with ``https://<the cert
    identity>`` at install time. The console menu runs outside any request, so
    without this it has no way to turn the admin path into something you can
    paste into a browser — the very first thing a new install needs.

    Falls back to ``https://<PUBLIC_HOST>`` when only the bare host is known,
    so a hand-edited row still reads correctly.
    """
    raw = get_setting(conn, "public_base", "").strip().rstrip("/")
    if not raw:
        host = get_setting(conn, "public_host", "").strip()
        raw = f"https://{host}" if host else ""
    return raw or PLACEHOLDER_BASE


def is_placeholder_base(base: str) -> bool:
    return base == PLACEHOLDER_BASE
