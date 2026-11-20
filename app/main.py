"""FastAPI application: page routes, admin routes, and the proxy dispatch.

The proxy is dispatched from a raw ASGI middleware rather than a FastAPI route.
Starlette routes match on ``scope["path"]``, which is the *decoded* path —
``%2F`` has already become ``/`` and repeated slashes are not guaranteed to
survive. Since the target URL must reach the origin byte-for-byte, ``/u/...``
requests are intercepted before routing ever sees them, using ``raw_path``.

CSRF: every state-changing route in this file is ``POST``-only, and the session
cookie is ``SameSite=Lax``, so a cross-site form cannot reach them with a live
session. Do not add a state-changing ``GET`` — that invariant is the only thing
standing in for a CSRF token.
"""
from __future__ import annotations

import asyncio
import hmac
import html
import logging
import os
import secrets
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import auth, db, flash, history, mailer, quota, urls
from .filters import register_filters
from .proxy import BreakerOpen, Busy, ProxyService
from .ssrf import SsrfPolicy, ssrf_safe_client

log = logging.getLogger("dlproxy")

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# The bootstrap administrator's preferred name. ``_free_admin_username`` falls
# back to admin2, admin3… when an ordinary account already claimed it.
ADMIN_USERNAME = "admin"

SECURITY_LOG_PATH = Path(
    os.environ.get("DLPROXY_SECURITY_LOG", "/var/log/dlproxy/security.log")
)

COOKIE_NAME = "dlproxy_session"


# ---------------------------------------------------------------------------
# Security log
# ---------------------------------------------------------------------------

class SecurityLog:
    """Append-only event log. Never raises: logging must not break a download."""

    def __init__(self, path: Path = SECURITY_LOG_PATH) -> None:
        self.path = path
        self._enabled = True
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            self._enabled = False

    def __call__(self, event: str, **fields) -> None:
        if not self._enabled:
            return
        parts = [db.iso_now(), event]
        for key, value in fields.items():
            text = str(value).replace("\n", " ").replace("\t", " ")
            parts.append(f"{key}={text}")
        line = "\t".join(parts) + "\n"
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            self._enabled = False
        log.info("security %s", line.strip())


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def secret_key() -> str:
    value = os.environ.get("DLPROXY_SECRET_KEY", "").strip()
    if not value:
        raise RuntimeError(
            "DLPROXY_SECRET_KEY is not set. Run deploy.sh or copy deploy/env.example "
            "to .env and fill it in."
        )
    return value


def behind_proxy() -> bool:
    return os.environ.get("DLPROXY_BEHIND_PROXY", "1") not in ("0", "false", "no")


def client_ip_of(request: Request) -> str:
    """Trusted client IP.

    Behind Nginx the only trustworthy source is ``X-Real-IP``, which the Nginx
    template overwrites with ``$remote_addr``. A client-supplied
    ``X-Forwarded-For`` is recorded separately (``xff_raw``) for forensics but is
    never used for decisions — anyone can send that header.
    """
    if behind_proxy():
        real = request.headers.get("x-real-ip")
        if real:
            return real.strip()
    client = request.client
    return client.host if client else ""


def create_app(*, db_path_override: str | None = None,
               allow_private_upstream: bool = False,
               allowed_ports: frozenset[int] = frozenset(urls.ALLOWED_PORTS),
               security_log_path: Path | None = None) -> FastAPI:
    sec_log = SecurityLog(security_log_path or SECURITY_LOG_PATH)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        conn = db.init_db(db_path_override)
        _bootstrap(conn, sec_log)
        client, backend = ssrf_safe_client(
            policy=SsrfPolicy(allow_private=allow_private_upstream),
            max_connections=db.get_int_setting(conn, "max_active_streams_global", 256) + 8,
            max_keepalive_connections=16,
        )
        app.state.conn = conn
        # Worker threads (argon2 verification and anything else handed to
        # asyncio.to_thread) must not touch state.conn: pysqlite's statement
        # cache lives on the connection object and is not covered by SQLite's
        # mutex. See db.in_worker.
        app.state.db_path = db.resolve_path(db_path_override)
        app.state.client = client
        app.state.backend = backend
        app.state.proxy = ProxyService(client, backend, conn, security_log=sec_log,
                                       allowed_ports=allowed_ports)
        app.state.secret = secret_key() if not allow_private_upstream else (
            os.environ.get("DLPROXY_SECRET_KEY") or "test-secret")
        app.state.security_log = sec_log
        try:
            yield
        finally:
            await client.aclose()
            conn.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
    register_filters(templates)
    app.state.templates = templates

    # -- raw-path proxy dispatch -------------------------------------------

    @app.middleware("http")
    async def proxy_dispatch(request: Request, call_next):
        raw = request.scope.get("raw_path", b"")
        if not raw.startswith(b"/u/"):
            return await call_next(request)
        request.state.client_ip = client_ip_of(request)
        request.state.xff_raw = request.headers.get("x-forwarded-for", "")
        service: ProxyService = request.app.state.proxy
        try:
            return await service.proxy(request)
        except urls.UrlError as exc:
            return _proxy_error(exc.status, exc.detail)
        except Busy as exc:
            return PlainTextResponse(
                "并发数已达上限，请稍后重试。\n", status_code=503,
                headers={"Retry-After": str(exc.retry_after)},
            )
        except BreakerOpen as exc:
            return templates.TemplateResponse(
                request, "breaker.html",
                {"state": exc.state, "user": None, "admin_path": ""},
                status_code=429,
            )

    _register_page_routes(app, templates, sec_log)
    return app


def admin_path_matches(given: str, expected: str) -> bool:
    """Constant-time comparison for the admin URL segment.

    The path is 128 random bits, so a timing attack is not realistic — but the
    token lookup next door already uses ``hmac.compare_digest``, and having two
    different comparison disciplines for two equally secret strings invites
    someone to copy the wrong one. Both arguments are compared as bytes so a
    non-ASCII path cannot raise.
    """
    if not expected:
        return False
    return hmac.compare_digest(given.encode("utf-8"), expected.encode("utf-8"))


def _proxy_error(status: int, detail: str) -> Response:
    """Proxy errors disclose nothing about why a target was refused."""
    if status == 403:
        return PlainTextResponse("forbidden\n", status_code=403)
    if status == 404:
        return PlainTextResponse("not found\n", status_code=404)
    if status == 413:
        return PlainTextResponse("request too large\n", status_code=413)
    if status == 414:
        return PlainTextResponse("target URL too long\n", status_code=414)
    if status == 502:
        return PlainTextResponse("upstream error\n", status_code=502)
    return PlainTextResponse(f"{detail}\n", status_code=status)


# ---------------------------------------------------------------------------
# First-boot bootstrap
# ---------------------------------------------------------------------------

def _bootstrap(conn: sqlite3.Connection, sec_log: SecurityLog) -> None:
    """Create the admin path, and the first admin account if none exists.

    The password is written to ``INITIAL_ADMIN.txt`` (mode 0600) *and* printed to
    stdout once. The file is what makes this usable over SSH; the banner on the
    admin page nags until the file is deleted.
    """
    if not db.get_setting(conn, "admin_path", ""):
        db.set_setting(conn, "admin_path", secrets.token_hex(16))

    row = conn.execute("SELECT COUNT(*) AS n FROM users WHERE is_admin=1").fetchone()
    if int(row["n"]) > 0:
        return

    # ``users.username`` is UNIQUE, and an ordinary account may already be
    # called ``admin`` — ``dlproxy createuser admin`` is enough to arrange it.
    # Inserting blindly raised IntegrityError from inside the lifespan handler,
    # which took the whole service down before it could answer one request
    # (measured: "UNIQUE constraint failed: users.username    <-- the service
    # cannot start"). Pick a name the insert can actually use instead.
    username = _free_admin_username(conn)
    if username is None:                          # pragma: no cover - absurd
        sec_log("bootstrap_failed", reason="no free username for the bootstrap admin")
        log.error("bootstrap: every candidate username is taken; run "
                  "'dlproxy createadmin' to add one by hand")
        return

    password = secrets.token_urlsafe(18)          # ~24 chars, URL-safe alphabet
    token = auth.new_token()
    try:
        conn.execute(
            "INSERT INTO users(username, pwd_hash, token, token_active, disabled, "
            "is_admin, created_at) VALUES(?,?,?,1,0,1,?)",
            (username, auth.hash_password(password), token, db.iso_now()),
        )
    except sqlite3.IntegrityError as exc:
        # Reached only if something inserted between the check and the write.
        # Losing the bootstrap account is survivable; losing the service is not.
        sec_log("bootstrap_failed", reason=str(exc))
        log.error("bootstrap: could not create the admin account (%s); run "
                  "'dlproxy createadmin' to add one by hand", exc)
        return
    notice = (
        "dlproxy 初始管理员账号\n"
        "======================\n"
        f"用户名：{username}\n"
        f"密码：  {password}\n"
        "管理入口：/" + db.get_setting(conn, "admin_path") + "\n\n"
        "请于首次登录后立即修改密码，并删除本文件。\n"
    )
    target = Path(os.environ.get("DLPROXY_INIT_FILE",
                                 str(BASE_DIR.parent / "INITIAL_ADMIN.txt")))
    try:
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(notice)
    except OSError as exc:                        # pragma: no cover
        log.warning("could not write initial admin file: %s", exc)
    print(notice, flush=True)
    sec_log("bootstrap_admin", username=username)


def _free_admin_username(conn: sqlite3.Connection) -> str | None:
    """``admin``, or the first ``admin2``, ``admin3``… not already taken."""
    taken = {str(r["username"]) for r in conn.execute("SELECT username FROM users")}
    if ADMIN_USERNAME not in taken:
        return ADMIN_USERNAME
    for n in range(2, 100):
        candidate = f"{ADMIN_USERNAME}{n}"
        if candidate not in taken:
            return candidate
    return None


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

def _register_page_routes(app: FastAPI, templates: Jinja2Templates,
                          sec_log: SecurityLog) -> None:

    def current_user(request: Request):
        return auth.load_session(
            request.app.state.conn,
            secret=request.app.state.secret,
            cookie=request.cookies.get(COOKIE_NAME, ""),
        )

    def public_base_of(request: Request) -> str:
        """The site's public base URL, preferring what deploy.sh recorded.

        ``request.base_url`` cannot be trusted for this: uvicorn runs with
        ``proxy_headers=False``, so behind Nginx it always reports ``http://``
        and the container's own bind address. The install step records the real
        scheme and host in ``settings.public_base``; only a hand-started instance
        that never went through install falls back to the request.
        """
        recorded = db.public_base(request.app.state.conn)
        if not db.is_placeholder_base(recorded):
            return recorded
        # Nothing recorded — a hand-started instance that never went through
        # install. Nginx still knows the original scheme and Host; consult them
        # only in behind-proxy mode, because a direct client can forge both.
        #
        # X-Forwarded-Host is not sent by the bundled nginx.conf (it forwards
        # the real Host instead), so that branch only fires behind a CDN that
        # rewrites Host. It is kept for that case and is harmless otherwise.
        if behind_proxy():
            proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
            host = (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
            host = host or request.headers.get("host", "").strip()
            # Both values are interpolated into a page and into JS, so the scheme
            # is checked against a literal whitelist rather than "not empty".
            if proto in ("http", "https") and host:
                return f"{proto}://{host}"
        return str(request.base_url).rstrip("/")

    def redirect_with(request: Request, location: str, *,
                      msg: str = "", err: str = "") -> RedirectResponse:
        """303 to ``location``, carrying one message out of band.

        The message goes into the ``flashes`` table, not into the query string:
        nginx logs the full request line, and these messages can contain a
        freshly rotated password or token. The id rides in a short-lived cookie
        that ``render()`` consumes and clears.
        """
        conn = request.app.state.conn
        flash_id = ""
        if msg:
            flash_id = flash.put(conn, msg, flash.KIND_MESSAGE)
        elif err:
            flash_id = flash.put(conn, err, flash.KIND_ERROR)
        response = RedirectResponse(location, status_code=303)
        if flash_id:
            _set_flash_cookie(response, flash_id)
        return response

    def _set_flash_cookie(response: Response, flash_id: str) -> None:
        response.set_cookie(
            flash.COOKIE_NAME, flash_id, max_age=flash.COOKIE_MAX_AGE,
            httponly=True, secure=behind_proxy(), samesite="lax", path="/",
        )

    def render(request: Request, name: str, ctx: dict, status_code: int = 200):
        conn = request.app.state.conn
        pending = request.cookies.get(flash.COOKIE_NAME, "")
        popped = flash.take(conn, pending)
        msg = err = ""
        if popped is not None:
            kind, text = popped
            if kind == flash.KIND_ERROR:
                err = text
            else:
                msg = text
        base = {
            "request": request,
            "user": getattr(request.state, "user", None),
            "admin_path": db.get_setting(conn, "admin_path", ""),
            "public_base": public_base_of(request),
            "smtp_configured": mailer.is_configured(conn),
            "init_file_present": Path(os.environ.get(
                "DLPROXY_INIT_FILE", str(BASE_DIR.parent / "INITIAL_ADMIN.txt"))
            ).exists(),
            "msg": msg,
            "err": err,
        }
        base.update(ctx)
        response = templates.TemplateResponse(request, name, base, status_code=status_code)
        if pending:
            # One read only: drop the cookie even when the row was already gone.
            response.delete_cookie(flash.COOKIE_NAME, path="/")
        return response

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        user = current_user(request)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        conn = request.app.state.conn
        state = quota.check_quota(conn)
        # A hand-edited or crawler-supplied ?page= must not turn a 200 into a 500.
        try:
            page = int(request.query_params.get("page", "1") or 1)
        except (TypeError, ValueError):
            page = 1
        page = max(1, page)
        per_page = max(1, db.get_int_setting(conn, "history_per_page", 20))
        rows = history.recent_for_user(conn, user.id, limit=per_page,
                                       offset=(page - 1) * per_page)
        total = history.count_for_user(conn, user.id)
        request.state.user = user
        snapshot = request.app.state.proxy.snapshot()
        return render(request, "home.html", {
            "state": state,
            "rows": rows,
            "page": page,
            "pages": max(1, (total + per_page - 1) // per_page),
            "total": total,
            "snapshot": snapshot,
            # The caption under the table quotes this number, so it has to come
            # from the same place the aggregator reads it.
            "aggregate_window_s": db.get_int_setting(
                conn, "history_aggregate_window_s", 60),
            # Only this user's slice: the full map would tell one user how busy
            # the others are, and a token is a credential.
            "my_streams": int(snapshot["by_token"].get(user.token, 0)),
        })

    @app.get("/login", response_class=HTMLResponse)
    async def login_form(request: Request):
        if current_user(request) is not None:
            return RedirectResponse("/", status_code=303)
        return render(request, "login.html", {})

    @app.post("/login")
    async def login_submit(request: Request, username: str = Form(""),
                           password: str = Form("")):
        conn = request.app.state.conn
        ip = client_ip_of(request)
        try:
            # argon2id costs ~40 ms per verification on a 1-core ARM box. Run it
            # off the event loop: while it blocks, every in-flight download in
            # _relay() stops reading from its upstream.
            #
            # The worker gets its own connection via db.in_worker. Handing it
            # state.conn instead races the relay's meter.add(): pysqlite keeps
            # a statement cache on the connection, outside SQLite's mutex, and
            # the two threads corrupt each other's prepared statements. That
            # surfaced as InterfaceError on maybe one login in 200, and — much
            # worse — as a truncated download when the meter blew up after a
            # chunk had already been written to the client.
            row = await asyncio.to_thread(
                db.in_worker, request.app.state.db_path,
                lambda worker: auth.authenticate(
                    worker, username=username, password=password, client_ip=ip),
            )
        except auth.AuthError as exc:
            sec_log("login_failed", ip=ip, username=username[:64], status=exc.status)
            if exc.status == 429:
                # send_alert is fire-and-forget and returns None when SMTP is
                # not configured; awaiting it unconditionally would raise.
                alert = mailer.send_alert(conn, subject="登录连续失败已锁定",
                                          body=f"IP {ip} 因连续登录失败被锁定。\n",
                                          security_log=sec_log)
                if alert is not None:
                    await alert
            return redirect_with(request, "/login", err=exc.detail)
        cookie = auth.create_session(conn, secret=request.app.state.secret,
                                     user_id=int(row["id"]))
        sec_log("login_ok", ip=ip, user=row["username"])
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            COOKIE_NAME, cookie, max_age=auth.SESSION_DAYS * 86400,
            httponly=True, secure=behind_proxy(), samesite="lax", path="/",
        )
        return response

    @app.post("/logout")
    async def logout(request: Request):
        auth.destroy_session(request.app.state.conn, secret=request.app.state.secret,
                             cookie=request.cookies.get(COOKIE_NAME, ""))
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(COOKIE_NAME, path="/")
        return response

    @app.post("/token/reset")
    async def reset_my_token(request: Request):
        user = current_user(request)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        new = auth.reset_token(request.app.state.conn, user.id)
        sec_log("token_reset", user=user.username)
        # The token is a credential: it must not appear in the redirect URL.
        return redirect_with(request, "/", msg=f"新 token 已生成：{new}（原链接已失效）")

    @app.get("/password", response_class=HTMLResponse)
    async def password_form(request: Request):
        user = current_user(request)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        request.state.user = user
        return render(request, "password.html", {})

    @app.post("/password")
    async def password_submit(request: Request,
                              current: str = Form(""),
                              new: str = Form(""),
                              confirm: str = Form("")):
        conn = request.app.state.conn
        user = current_user(request)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        ip = client_ip_of(request)
        request.state.user = user

        def fail(detail: str):
            sec_log("password_change_failed", ip=ip, user=user.username,
                    reason=detail)
            return render(request, "password.html", {"err": detail}, status_code=400)

        row = conn.execute("SELECT pwd_hash FROM users WHERE id=?",
                           (user.id,)).fetchone()
        # Both argon2 calls cost ~40 ms of CPU each. Off the event loop, or a
        # password change stalls every download currently being relayed.
        current_ok = await asyncio.to_thread(
            auth.verify_password, str(row["pwd_hash"]) if row else "", current)
        if row is None or not current_ok:
            return fail("当前密码不正确")
        if len(new) < 8:
            return fail("新密码长度不得少于 8 位")
        if new != confirm:
            return fail("两次输入的新密码不一致")
        if new == current:
            return fail("新密码不能与当前密码相同")

        new_hash = await asyncio.to_thread(auth.hash_password, new)
        conn.execute("UPDATE users SET pwd_hash=? WHERE id=?", (new_hash, user.id))
        # Other browsers holding a cookie for this account must not survive a
        # password change; the session that performed it stays usable.
        dropped = auth.destroy_other_sessions(
            conn, user_id=user.id, keep_cookie=request.cookies.get(COOKIE_NAME, ""),
            secret=request.app.state.secret)
        sec_log("password_changed", ip=ip, user=user.username, others=dropped)
        note = "密码已更新"
        if dropped:
            note += f"，并已注销其他 {dropped} 个登录会话"
        return redirect_with(request, "/", msg=note)

    # -- health -------------------------------------------------------------
    # Registered before the /{admin_path} catch-all: Starlette matches in
    # registration order, so a later catch-all would swallow this path.
    @app.get("/healthz")
    async def healthz(request: Request):
        """Liveness probe, deliberately unauthenticated and deliberately dull.

        It answers whether the database file is readable, nothing else. The two
        figures it returns are aggregate counters that reveal no account, no URL
        and no token; the admin page remains the place to see per-user usage.
        """
        conn = request.app.state.conn
        conn.execute("SELECT 1").fetchone()
        return JSONResponse({
            "ok": True,
            "active_streams": request.app.state.proxy.active_global,
            "day": db.day_key(),
        })

    # -- admin --------------------------------------------------------------

    def require_admin(request: Request):
        user = current_user(request)
        if user is None or not user.is_admin:
            return None
        return user

    @app.get("/{admin_path}", response_class=HTMLResponse)
    async def admin_page(request: Request, admin_path: str):
        conn = request.app.state.conn
        expected = db.get_setting(conn, "admin_path", "")
        user = require_admin(request)
        # A wrong path and a non-admin both look like 404: the admin URL itself
        # is a secret, so "exists but forbidden" would leak it.
        if user is None or not admin_path_matches(admin_path, expected):
            return PlainTextResponse("not found\n", status_code=404)
        request.state.user = user
        users = list(conn.execute(
            "SELECT id, username, token, token_active, disabled, is_admin, created_at "
            "FROM users ORDER BY id"))
        state = quota.check_quota(conn)
        usage_rows = []
        for u in users:
            usage_rows.append({
                "user": u,
                "today": _user_bytes(conn, int(u["id"]), "day"),
                "month": _user_bytes(conn, int(u["id"]), "month"),
            })
        snapshot = request.app.state.proxy.snapshot()
        # Join the live counts to usernames here, not in the template: a token
        # that no longer belongs to anyone (rotated mid-download) would
        # otherwise render as a bare secret on the page.
        by_token = snapshot["by_token"]
        active_rows = [
            {"username": str(u["username"]), "streams": int(by_token.get(str(u["token"]), 0))}
            for u in users
            if int(by_token.get(str(u["token"]), 0)) > 0
        ]
        return render(request, "admin.html", {
            "users": users,
            "usage_rows": usage_rows,
            "state": state,
            "settings": db.all_settings(conn),
            "snapshot": snapshot,
            "active_rows": active_rows,
            # Two numbers, because they answer two different questions: how many
            # streams are running under a token nobody owns any more, and how
            # many such tokens there are. Reporting only the second reads as
            # "1 connection" when five are in flight.
            "orphan_streams": sum(
                n for tok, n in by_token.items()
                if n and tok not in {str(u["token"]) for u in users}
            ),
            "orphan_tokens": sum(
                1 for tok, n in by_token.items()
                if n and tok not in {str(u["token"]) for u in users}
            ),
        })

    @app.post("/{admin_path}/users")
    async def admin_create_user(request: Request, admin_path: str,
                                username: str = Form(""),
                                password: str = Form(""),
                                is_admin: str = Form("")):
        conn = request.app.state.conn
        user = require_admin(request)
        if user is None or not admin_path_matches(
                admin_path, db.get_setting(conn, "admin_path", "")):
            return PlainTextResponse("not found\n", status_code=404)
        username = username.strip()
        if not username or len(password) < 8:
            return redirect_with(request, "/" + admin_path,
                                 err="用户名不能为空，密码长度不得少于 8 位")
        pwd_hash = await asyncio.to_thread(auth.hash_password, password)
        try:
            conn.execute(
                "INSERT INTO users(username, pwd_hash, token, token_active, disabled, "
                "is_admin, created_at) VALUES(?,?,?,1,0,?,?)",
                (username, pwd_hash, auth.new_token(),
                 1 if is_admin else 0, db.iso_now()),
            )
        except sqlite3.IntegrityError:
            return redirect_with(request, "/" + admin_path, err="该用户名已存在")
        sec_log("admin_create_user", by=user.username, username=username)
        return redirect_with(request, "/" + admin_path, msg="已创建 " + username)

    @app.post("/{admin_path}/users/{user_id}/action")
    async def admin_user_action(request: Request, admin_path: str, user_id: int,
                                action: str = Form("")):
        conn = request.app.state.conn
        user = require_admin(request)
        if user is None or not admin_path_matches(
                admin_path, db.get_setting(conn, "admin_path", "")):
            return PlainTextResponse("not found\n", status_code=404)
        target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if target is None:
            return redirect_with(request, "/" + admin_path, err="账号不存在")
        # Disabling or deleting yourself leaves the install with no usable
        # administrator. Nothing in the UI can undo that: the next restart tries
        # to recreate the bootstrap admin and either fails on the username
        # unique constraint (the service cannot start) or silently claims the
        # name. Rotating your own token or password is harmless, so only these
        # two are refused.
        if user_id == user.id and action in ("disable", "delete"):
            sec_log("admin_action_refused", by=user.username, action=action,
                    target=user_id, reason="self")
            return redirect_with(request, "/" + admin_path,
                                 err="不能禁用或删除自己，请让另一个管理员来做")
        msg = ""
        if action == "disable":
            conn.execute("UPDATE users SET disabled=1 WHERE id=?", (user_id,))
            msg = f"已禁用 {target['username']}"
        elif action == "enable":
            conn.execute("UPDATE users SET disabled=0 WHERE id=?", (user_id,))
            msg = f"已启用 {target['username']}"
        elif action == "reset_token":
            token = auth.reset_token(conn, user_id)
            # A freshly minted token is a credential: it travels through the
            # flashes table, never through the redirect URL.
            msg = f"{target['username']} 的新 token：{token}"
        elif action == "toggle_token":
            conn.execute("UPDATE users SET token_active = 1 - token_active WHERE id=?",
                         (user_id,))
            msg = f"已切换 {target['username']} 的 token 启用状态"
        elif action == "reset_password":
            new_pw = secrets.token_urlsafe(12)
            new_hash = await asyncio.to_thread(auth.hash_password, new_pw)
            conn.execute("UPDATE users SET pwd_hash=? WHERE id=?",
                         (new_hash, user_id))
            msg = f"{target['username']} 的新密码：{new_pw}"
        elif action == "delete":
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            msg = f"已删除 {target['username']}"
        else:
            return redirect_with(request, "/" + admin_path, err="无效操作")
        sec_log("admin_action", by=user.username, action=action, target=user_id)
        return redirect_with(request, "/" + admin_path, msg=msg)

    @app.post("/{admin_path}/settings")
    async def admin_settings(request: Request, admin_path: str):
        conn = request.app.state.conn
        user = require_admin(request)
        if user is None or not admin_path_matches(
                admin_path, db.get_setting(conn, "admin_path", "")):
            return PlainTextResponse("not found\n", status_code=404)
        form = await request.form()
        # field name -> (settings key, scale, low, high). The panel carries the
        # same numbers as ``min``/``max`` attributes, but those are a hint to a
        # browser: a hand-written POST reaches this handler without one. Two of
        # them bite hard if they land on 0 — stream_idle_timeout_s=0 turns every
        # download into an instant 504 with no bytes sent, and history_per_user=0
        # makes the row disappear the moment the transfer is opened.
        numeric = {
            "daily_limit_gb": ("daily_limit_bytes", 1024**3, 0, 10240),
            "monthly_limit_gb": ("monthly_limit_bytes", 1024**3, 0, 102400),
            "max_active_streams_global": ("max_active_streams_global", 1, 1, 4096),
            "max_active_streams_per_token": ("max_active_streams_per_token", 1, 1, 256),
            "stream_idle_timeout_s": ("stream_idle_timeout_s", 1, 10, 3600),
            "history_per_user": ("history_per_user", 1, 50, 5000),
            "history_per_page": ("history_per_page", 1, 5, 200),
            "cert_warn_days": ("cert_warn_days", 1, 1, 90),
        }
        # A negative size means "no limit" and has always been stored as 0, so
        # the two size fields keep a floor of zero. Everything else has a floor
        # that is not zero and is refused rather than silently clamped: an
        # operator who typed 0 into the idle timeout needs to be told, not
        # quietly upgraded to 10.
        for field_name, (key, scale, low, high) in numeric.items():
            raw = str(form.get(field_name, "")).strip()
            if raw == "":
                continue
            # ValueError covers letters, OverflowError covers "1e400" and "inf":
            # both are reachable from a hand-edited form and neither may 500.
            try:
                value = int(max(0.0, float(raw)) * scale)
            except (ValueError, OverflowError):
                return redirect_with(request, "/" + admin_path,
                                     err=f"{field_name} 必须为非负数字")
            # low/high are in the unit the form shows (MiB, seconds, …); the
            # stored value is already scaled.
            if value < low * scale:
                return redirect_with(
                    request, "/" + admin_path,
                    err=f"{field_name} 不能小于 {low}（收到 {raw}）")
            if value > high * scale:
                return redirect_with(
                    request, "/" + admin_path,
                    err=f"{field_name} 不能大于 {high}（收到 {raw}）")
            db.set_setting(conn, key, str(value))
        for key in ("smtp_host", "smtp_port", "smtp_user", "smtp_from", "smtp_to"):
            if key in form:
                db.set_setting(conn, key, str(form.get(key, "")).strip())
        if "smtp_pass" in form and str(form.get("smtp_pass", "")):
            db.set_setting(conn, "smtp_pass", str(form.get("smtp_pass")))
        db.set_setting(conn, "smtp_tls",
                       "1" if str(form.get("smtp_tls", "")) else "0")
        sec_log("admin_settings", by=user.username)
        return redirect_with(request, "/" + admin_path, msg="设置已保存")

    @app.post("/{admin_path}/unblock")
    async def admin_unblock(request: Request, admin_path: str,
                            hours: str = Form("24")):
        conn = request.app.state.conn
        user = require_admin(request)
        if user is None or not admin_path_matches(
                admin_path, db.get_setting(conn, "admin_path", "")):
            return PlainTextResponse("not found\n", status_code=404)
        import datetime as _dt
        try:
            span = max(0.0, float(hours))
        except (ValueError, OverflowError):
            span = 24.0
        # datetime.timedelta raises OverflowError for absurd spans, so clamp to
        # a year before building one.
        span = min(span, 24.0 * 366)
        until = db.utc_now() + _dt.timedelta(hours=span) if span > 0 else None
        quota.set_bypass(conn, until)
        sec_log("admin_unblock", by=user.username, hours=span)
        note = f"已临时解封至 {until:%Y-%m-%d %H:%M} UTC" if until else "已取消解封"
        return redirect_with(request, "/" + admin_path, msg=note)

    @app.post("/{admin_path}/smtp-test")
    async def admin_smtp_test(request: Request, admin_path: str):
        conn = request.app.state.conn
        user = require_admin(request)
        if user is None or not admin_path_matches(
                admin_path, db.get_setting(conn, "admin_path", "")):
            return PlainTextResponse("not found\n", status_code=404)
        ok, message = await mailer.send_test(conn)
        sec_log("admin_smtp_test", by=user.username, ok=ok)
        if ok:
            return redirect_with(request, "/" + admin_path, msg=message)
        return redirect_with(request, "/" + admin_path, err=message)

    @app.post("/{admin_path}/regenerate-path")
    async def admin_regenerate(request: Request, admin_path: str):
        conn = request.app.state.conn
        user = require_admin(request)
        if user is None or not admin_path_matches(
                admin_path, db.get_setting(conn, "admin_path", "")):
            return PlainTextResponse("not found\n", status_code=404)
        new_path = secrets.token_hex(16)
        db.set_setting(conn, "admin_path", new_path)
        sec_log("admin_path_rotated", by=user.username)
        return redirect_with(request, "/" + new_path, msg="管理路径已更新，原路径立即失效")

    @app.get("/{admin_path}/history/{user_id}", response_class=HTMLResponse)
    async def admin_history(request: Request, admin_path: str, user_id: int):
        conn = request.app.state.conn
        user = require_admin(request)
        if user is None or not admin_path_matches(
                admin_path, db.get_setting(conn, "admin_path", "")):
            return PlainTextResponse("not found\n", status_code=404)
        request.state.user = user
        target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if target is None:
            return PlainTextResponse("not found\n", status_code=404)
        try:
            page = int(request.query_params.get("page", "1") or 1)
        except (TypeError, ValueError):
            page = 1
        page = max(1, page)
        per_page = max(1, db.get_int_setting(conn, "history_per_page", 20))
        rows = history.recent_for_user(conn, user_id, limit=per_page,
                                       offset=(page - 1) * per_page)
        total = history.count_for_user(conn, user_id)
        return render(request, "admin_history.html", {
            "target": target, "rows": rows,
            "page": page,
            "pages": max(1, (total + per_page - 1) // per_page),
            "total": total,
        })


def _user_bytes(conn: sqlite3.Connection, user_id: int, scope: str) -> int:
    """Per-user usage for the admin table.

    The boundary comes from db.day_start_iso()/month_start_iso() rather than from
    a bare date string: transfer timestamps are UTC while the accounting day is
    UTC+8, and mixing the two shifts the window by eight hours.
    """
    since = db.day_start_iso() if scope == "day" else db.month_start_iso()
    row = conn.execute(
        "SELECT COALESCE(SUM(bytes_sent),0) AS b FROM transfers "
        "WHERE user_id=? AND started_at >= ?",
        (user_id, since),
    ).fetchone()
    return int(row["b"]) if row else 0


_ = html  # re-exported for templates that need escaping helpers
app = create_app()
