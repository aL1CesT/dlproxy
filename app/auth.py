"""Authentication: argon2id passwords, signed-cookie sessions, login lockout.

Session design
--------------
The cookie carries ``<session-id>.<hmac>`` produced by itsdangerous. The session
id itself is *not* a credential we trust — every request hashes it with SHA-256
and looks the hash up in ``sessions``. That means:

* rotating ``DLPROXY_SECRET_KEY`` invalidates every cookie (tamper detection),
* deleting a row in ``sessions`` invalidates one session immediately,
* the database never holds a value that can be replayed as a cookie.

Login lockout
-------------
Per ``client_ip``, 5 consecutive failures lock for 15 minutes. While locked, even
a correct password is refused — otherwise the lock only slows down the attacker
who guesses wrong. The counter lives in SQLite rather than memory so a
``systemctl restart`` cannot be used to clear it.

The access-token (``/u/<token>/...``) path is a completely separate credential:
it is compared against ``users.token`` with a constant-time compare, requires
``token_active=1`` and ``disabled=0``, and returns 404 (never 403) so the
existence of a token is not confirmed.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import string
from dataclasses import dataclass
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from itsdangerous import BadSignature, URLSafeTimedSerializer

from . import db

__all__ = [
    "AuthError",
    "SessionUser",
    "hash_password",
    "verify_password",
    "new_token",
    "create_session",
    "load_session",
    "destroy_session",
    "session_id_from_cookie",
    "destroy_other_sessions",
    "authenticate",
    "lookup_token",
    "reset_token",
    "MAX_FAILS",
    "LOCK_SECONDS",
    "PRUNE_SECONDS",
]

MAX_FAILS = 5
LOCK_SECONDS = 15 * 60
# How long an expired lock row is kept before ``record_failure`` sweeps it. Far
# longer than LOCK_SECONDS on purpose: the sweep must never delete a lock that
# is still doing its job.
PRUNE_SECONDS = 7 * 24 * 60 * 60
SESSION_DAYS = 30
TOKEN_LEN = 32

_TOKEN_ALPHABET = string.ascii_letters + string.digits      # base62

_hasher = PasswordHasher()          # argon2id, library defaults (RFC 9106)


class AuthError(Exception):
    """Maps to a 4xx at the HTTP layer."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass(frozen=True)
class SessionUser:
    id: int
    username: str
    is_admin: bool
    token: str


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    except Exception:                       # malformed hash in the DB
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

def new_token(length: int = TOKEN_LEN) -> str:
    """Cryptographically random base62 token."""
    return "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(length))


def token_matches(stored: str, candidate: str) -> bool:
    return hmac.compare_digest(stored.encode(), candidate.encode())


def reset_token(conn: sqlite3.Connection, user_id: int) -> str:
    token = new_token()
    conn.execute("UPDATE users SET token=? WHERE id=?", (token, user_id))
    return token


def lookup_token(conn: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    """Return the user row for a live token, or None.

    Constant-time compare on top of the indexed lookup: the query narrows to one
    row, then we re-verify with ``compare_digest`` so a timing side channel on
    the index cannot be used to walk the token space.
    """
    if not token or len(token) > 64:
        return None
    row = conn.execute(
        "SELECT id, username, token, token_active, disabled, is_admin "
        "FROM users WHERE token=?",
        (token,),
    ).fetchone()
    if row is None:
        # Burn a comparable amount of time so a miss is not obviously faster.
        hmac.compare_digest(token, token)
        return None
    if not token_matches(str(row["token"]), token):
        return None
    if int(row["token_active"]) != 1 or int(row["disabled"]) != 0:
        return None
    return row


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def _serializer(secret: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key=secret, salt="dlproxy-session")


def _session_id_hash(session_id: str) -> str:
    return hashlib.sha256(session_id.encode()).hexdigest()


def create_session(
    conn: sqlite3.Connection, *, secret: str, user_id: int, days: int = SESSION_DAYS
) -> str:
    """Insert a session row and return the cookie value."""
    session_id = secrets.token_urlsafe(32)
    expires = db.utc_now() + timedelta(days=days)
    conn.execute(
        "INSERT INTO sessions(user_id, token_hash, expires_at) VALUES(?,?,?)",
        (user_id, _session_id_hash(session_id), db.iso(expires)),
    )
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (db.iso_now(),))
    return _serializer(secret).dumps(session_id)


def load_session(
    conn: sqlite3.Connection, *, secret: str, cookie: str, max_age: int = SESSION_DAYS * 86400
) -> SessionUser | None:
    if not cookie:
        return None
    try:
        session_id = _serializer(secret).loads(cookie, max_age=max_age)
    except BadSignature:
        return None
    except Exception:
        return None
    row = conn.execute(
        "SELECT s.id AS sid, s.expires_at, u.id, u.username, u.token, u.is_admin, u.disabled "
        "FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash=?",
        (_session_id_hash(session_id),),
    ).fetchone()
    if row is None:
        return None
    exp = db.parse_iso(str(row["expires_at"]))
    if exp is None or exp <= db.utc_now():
        conn.execute("DELETE FROM sessions WHERE id=?", (row["sid"],))
        return None
    if int(row["disabled"]) != 0:
        return None
    return SessionUser(
        id=int(row["id"]),
        username=str(row["username"]),
        is_admin=bool(int(row["is_admin"])),
        token=str(row["token"]),
    )


def destroy_session(conn: sqlite3.Connection, *, secret: str, cookie: str) -> None:
    if not cookie:
        return
    try:
        session_id = _serializer(secret).loads(cookie, max_age=SESSION_DAYS * 86400)
    except Exception:
        return
    conn.execute("DELETE FROM sessions WHERE token_hash=?", (_session_id_hash(session_id),))


def session_id_from_cookie(*, secret: str, cookie: str) -> str | None:
    """Return the session id carried by ``cookie``, or None if it is unusable."""
    if not cookie:
        return None
    try:
        return _serializer(secret).loads(cookie, max_age=SESSION_DAYS * 86400)
    except Exception:
        return None


def destroy_other_sessions(
    conn: sqlite3.Connection, *, user_id: int, keep_cookie: str, secret: str
) -> int:
    """Drop every session of ``user_id`` except the one behind ``keep_cookie``.

    Called after a password change: a leaked password means someone else may be
    holding a live cookie, and rotating the hash alone would leave that session
    working until it expired. The session that performed the change survives so
    the user is not logged out of the browser they are already using.

    When the caller's own cookie cannot be parsed there is no hash to exclude,
    so ``token_hash <> ''`` would match every row and log the caller out of the
    browser they are using. Nothing is deleted in that case: the caller could
    not prove which session is theirs, and logging them out is the one outcome
    this function exists to avoid.
    """
    keep_hash = ""
    session_id = session_id_from_cookie(secret=secret, cookie=keep_cookie)
    if session_id is not None:
        keep_hash = _session_id_hash(session_id)
    if not keep_hash:
        return 0
    cur = conn.execute(
        "DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (user_id, keep_hash))
    return int(cur.rowcount or 0)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

def lock_remaining(conn: sqlite3.Connection, client_ip: str) -> int:
    row = conn.execute(
        "SELECT locked_until FROM login_attempts WHERE client_ip=?", (client_ip,)
    ).fetchone()
    if row is None or not row["locked_until"]:
        return 0
    until = db.parse_iso(str(row["locked_until"]))
    if until is None:
        return 0
    remaining = int((until - db.utc_now()).total_seconds())
    return max(0, remaining)


def record_failure(conn: sqlite3.Connection, client_ip: str) -> tuple[int, bool]:
    """Return (fail_count, now_locked)."""
    row = conn.execute(
        "SELECT fail_count FROM login_attempts WHERE client_ip=?", (client_ip,)
    ).fetchone()
    count = (int(row["fail_count"]) if row else 0) + 1
    # A row only matters while the address that produced it is still trying.
    # ``create_session`` prunes expired sessions on the same principle; without
    # it here every IP that ever tried a wrong password keeps a row forever, and
    # the one dimension an unauthenticated caller fully controls (their own
    # address) drives an unbounded table. The cutoff is far longer than
    # LOCK_SECONDS so a locked-but-quiet client is never forgotten early.
    now = db.utc_now()
    conn.execute(
        "DELETE FROM login_attempts WHERE last_seen IS NULL OR last_seen < ?",
        (db.iso(now - timedelta(seconds=PRUNE_SECONDS)),),
    )
    locked_until = None
    if count >= MAX_FAILS:
        locked_until = db.iso(now + timedelta(seconds=LOCK_SECONDS))
    conn.execute(
        "INSERT INTO login_attempts(client_ip, fail_count, locked_until, last_seen) "
        "VALUES(?,?,?,?) "
        "ON CONFLICT(client_ip) DO UPDATE SET fail_count=excluded.fail_count, "
        "locked_until=excluded.locked_until, last_seen=excluded.last_seen",
        (client_ip, count, locked_until, db.iso(now)),
    )
    return count, locked_until is not None


def clear_failures(conn: sqlite3.Connection, client_ip: str) -> None:
    conn.execute("DELETE FROM login_attempts WHERE client_ip=?", (client_ip,))


def authenticate(
    conn: sqlite3.Connection, *, username: str, password: str, client_ip: str
) -> sqlite3.Row:
    """Verify credentials. Raises AuthError with a deliberately vague message."""
    locked = lock_remaining(conn, client_ip)
    if locked > 0:
        raise AuthError(429, f"尝试次数过多，请等待 {locked // 60 + 1} 分钟后重试")

    row = conn.execute(
        "SELECT id, username, pwd_hash, token, token_active, disabled, is_admin "
        "FROM users WHERE username=?",
        (username,),
    ).fetchone()

    ok = row is not None and verify_password(str(row["pwd_hash"]), password)
    if not ok:
        _count, now_locked = record_failure(conn, client_ip)
        raise AuthError(
            429 if now_locked else 401,
            "用户名或密码错误" if not now_locked
            else f"尝试次数过多，请等待 {LOCK_SECONDS // 60} 分钟后重试",
        )

    if int(row["disabled"]) != 0:
        raise AuthError(403, "该账号已被禁用")

    clear_failures(conn, client_ip)
    if needs_rehash(str(row["pwd_hash"])):
        conn.execute("UPDATE users SET pwd_hash=? WHERE id=?",
                     (hash_password(password), row["id"]))
    return row
