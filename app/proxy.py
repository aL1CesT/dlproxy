"""Streaming reverse proxy: URL recovery, SSRF-vetted upstream, byte accounting.

Request flow
------------
1. ``urls.extract_from_raw`` splits ``/u/<token>/<absolute-url>?<query>`` at the
   byte level, so ``%2F``, ``//`` and ``?`` inside the target survive untouched.
2. The token is looked up with a constant-time compare. Unknown, revoked or
   disabled tokens get 404 — never 403 — so token existence is not confirmed.
3. The breaker is consulted *before* any upstream socket is opened.
4. Concurrency slots are taken. Hitting either cap yields 503 + ``Retry-After``,
   which is deliberately distinct from the breaker's 429.
5. Redirects are walked by hand, max 5 hops, and **every hop is re-vetted** by the
   SSRF backend. ``follow_redirects=True`` would only vet the first destination.
6. The body is relayed in 64 KiB chunks. Bytes are booked after they have been
   handed to the client, so a client that disconnects is not charged for data it
   never received. A ``finally`` closes the upstream stream, flushes the meter and
   seals the history row on every exit path.

``Content-Length`` when we decode
---------------------------------
``Content-Encoding`` is stripped from the relayed response, and httpx's
``aiter_bytes`` decompresses based on that same header. Relaying a
compressed ``Content-Length`` next to identity bytes truncates downloads, so
when an encoding was actually present we drop both headers and let the client
fall back to connection-close framing. For the identity case — every binary
download, every Range request — both headers pass through untouched.
"""
from __future__ import annotations

import asyncio
import logging
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urljoin

import httpx
from starlette.responses import StreamingResponse

from . import auth, db, history, mailer, quota, urls
from .ssrf import classify_denial

__all__ = [
    "ProxyService",
    "BreakerOpen",
    "Busy",
    "CHUNK_SIZE",
    "PASS_RESPONSE_HEADERS",
    "STRIP_RESPONSE_HEADERS",
]

log = logging.getLogger("dlproxy.proxy")

CHUNK_SIZE = 64 * 1024

# Relayed from the upstream response.
PASS_RESPONSE_HEADERS = (
    "content-type",
    "content-length",
    "content-range",
    "accept-ranges",
    "etag",
    "last-modified",
    "cache-control",
)
# Never relayed.
STRIP_RESPONSE_HEADERS = frozenset({"set-cookie", "transfer-encoding", "connection",
                                    "content-encoding"})

# Relayed from the client request.
PASS_REQUEST_HEADERS = ("user-agent", "range", "accept", "accept-encoding")

GIT_UPLOAD_PACK = "/git-upload-pack"
GIT_CONTENT_TYPES = frozenset({
    "application/x-git-upload-pack-request",
    "application/x-git-upload-pack-request-negotiate",
})


class Busy(Exception):
    """A concurrency cap was hit. Distinct from the quota breaker."""

    def __init__(self, retry_after: int, scope: str) -> None:
        super().__init__(scope)
        self.retry_after = retry_after
        self.scope = scope


class BreakerOpen(Exception):
    """Daily or monthly quota exhausted and no bypass window is active."""

    def __init__(self, state: quota.QuotaState) -> None:
        super().__init__("quota exceeded")
        self.state = state


@dataclass
class StreamResult:
    status_code: int | None = None
    size_total: int | None = None
    bytes_sent: int = 0
    duration_ms: int | None = None
    range_hit: bool = False
    client_aborted: bool = False
    upstream_peer: str | None = None
    notes: list[str] = field(default_factory=list)


class RelayStream:
    """Async iterator that knows whether Starlette ever pulled a chunk.

    ``proxy()`` hands the body of a 200 to an async generator and returns. From
    that moment the generator owns the concurrency slot and the history row, and
    its ``finally`` is what releases both. But a generator's ``finally`` only
    runs once iteration *begins*: if the response is torn down before the first
    ``__anext__``, nothing inside it ever executes and the row would be left with
    a NULL status forever.

    This wrapper keeps that knowledge outside the generator so the two exits are
    covered explicitly: iteration started (the generator's own ``finally`` wins)
    or the response was sealed without it (``abandon()`` writes the status the
    proxy had already decided on).
    """

    __slots__ = ("_gen", "_on_abandon", "started", "sealed")

    def __init__(self, gen, on_abandon) -> None:
        self._gen = gen
        self._on_abandon = on_abandon
        self.started = False
        self.sealed = False

    def __aiter__(self) -> "RelayStream":
        return self

    async def __anext__(self):
        self.started = True
        return await self._gen.__anext__()

    async def aclose(self) -> None:
        self.sealed = True
        await self._gen.aclose()

    def abandon(self) -> None:
        """Seal the row when the body was never iterated."""
        if self.started or self.sealed:
            return
        self.sealed = True
        self._on_abandon()


class RelayResponse(StreamingResponse):
    """``StreamingResponse`` that also seals the history row when the body was
    never pulled.

    Starlette tears a response down in three different ways depending on the
    ASGI spec version and whether the client disconnects mid-flight. Rather than
    reason about each one, this subclass wraps the whole call in ``try/finally``
    and asks the relay whether it ever got to run. If it did, the relay's own
    ``finally`` has already written the row; if it did not, ``abandon()`` writes
    the status the proxy had decided on so the history table never shows a bare
    ``—``.
    """

    def __init__(self, content, relay: "RelayStream", **kwargs) -> None:
        super().__init__(content, **kwargs)
        self.relay = relay

    async def __call__(self, scope, receive, send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            self.relay.abandon()


class ProxyService:
    """Owns the long-lived httpx client and the live-stream counters."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        backend: Any,
        conn: sqlite3.Connection,
        *,
        security_log: Callable[..., None] | None = None,
        allowed_ports: frozenset[int] = frozenset(urls.ALLOWED_PORTS),
    ) -> None:
        self.client = client
        self.backend = backend
        self.conn = conn
        self.security_log = security_log or (lambda *a, **k: None)
        # {80, 443} in production. The local test suite adds its ephemeral
        # origin port, because binding 80/443 on a dev box is not reasonable.
        self.allowed_ports = allowed_ports
        self.active_global = 0
        self.active_by_token: dict[str, int] = {}

    def _alert_breaker(self, state: quota.QuotaState) -> None:
        """Send one alert per trip, not one per rejected request.

        Spec 4.9 wants a mail when the breaker trips. During a busy hour every
        rejected request would reach this line, so the stamp in
        ``settings.breaker_alerted_at`` gates it: the first rejected request of a
        trip mails, the rest are silent. It is cleared once a request finds the
        breaker clear again.
        """
        conn = self.conn
        if db.get_setting(conn, "breaker_alerted_at", ""):
            return
        db.set_setting(conn, "breaker_alerted_at", db.iso_now())
        body = (
            f"流量熔断已触发：{state.reason()}\n"
            f"当日 {state.day_bytes} / {state.daily_limit or '不限'} 字节\n"
            f"本月 {state.month_bytes} / {state.monthly_limit or '不限'} 字节\n"
            "新的下载请求将返回 429，已在传输中的流不受影响。\n"
            "如需临时放行，请在管理页使用「临时解封」。\n"
        )
        alert = mailer.send_alert(
            conn, subject="dlproxy 流量熔断已触发", body=body,
            security_log=self.security_log,
        )
        # send_alert returns None when SMTP is unconfigured and a Task otherwise.
        # Non-None here means a loop is running, which is always the case from
        # inside a request handler.
        if alert is not None:
            alert.add_done_callback(lambda _t: None)
        self.security_log("breaker_alert", reason=state.reason())

    # -- concurrency --------------------------------------------------------

    def limits(self) -> tuple[int, int]:
        g = db.get_int_setting(self.conn, "max_active_streams_global", 256)
        t = db.get_int_setting(self.conn, "max_active_streams_per_token", 128)
        return max(1, g), max(1, t)

    def snapshot(self) -> dict[str, Any]:
        g, t = self.limits()
        return {
            "global": self.active_global,
            "global_cap": g,
            "token_cap": t,
            "by_token": dict(self.active_by_token),
        }

    def _enter(self, token: str) -> None:
        # No ``await`` between the test and the increment: the event loop is the
        # only writer, so check-then-act is atomic here and no lock is needed.
        g, t = self.limits()
        if self.active_global >= g:
            raise Busy(5, "global")
        if self.active_by_token.get(token, 0) >= t:
            raise Busy(5, "token")
        self.active_global += 1
        self.active_by_token[token] = self.active_by_token.get(token, 0) + 1

    def _leave(self, token: str) -> None:
        self.active_global = max(0, self.active_global - 1)
        remaining = self.active_by_token.get(token, 0) - 1
        if remaining <= 0:
            self.active_by_token.pop(token, None)
        else:
            self.active_by_token[token] = remaining

    # -- header shaping -----------------------------------------------------

    @staticmethod
    def _upstream_request_headers(request, *, include_content_type: bool = False
                                  ) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for name in PASS_REQUEST_HEADERS:
            value = request.headers.get(name)
            if value:
                out.append((name, value))
        if include_content_type:
            # git-upload-pack is identified by its Content-Type on both ends, so a
            # gated POST has to carry it. Nothing else gets a body at all.
            ctype = request.headers.get("content-type")
            if ctype:
                out.append(("content-type", ctype))
            length = request.headers.get("content-length")
            if length:
                out.append(("content-length", length))
        if not any(n == "accept-encoding" for n, _ in out):
            # Ask for identity so Range responses are never gzip-wrapped.
            out.append(("accept-encoding", "identity"))
        return out

    @staticmethod
    def _response_headers(response: httpx.Response) -> dict[str, str]:
        headers: dict[str, str] = {}
        encoded = bool(response.headers.get("content-encoding"))
        for name in PASS_RESPONSE_HEADERS:
            value = response.headers.get(name)
            if value is None:
                continue
            if name == "content-length" and encoded:
                continue            # length no longer describes what we emit
            headers[name] = value
        for name in STRIP_RESPONSE_HEADERS:
            headers.pop(name, None)
        return headers

    @staticmethod
    def _is_git_post(method: str, upstream_path: str, content_type: str) -> bool:
        if method != "POST":
            return False
        if not upstream_path.endswith(GIT_UPLOAD_PACK):
            return False
        ctype = (content_type or "").split(";")[0].strip().lower()
        return ctype in GIT_CONTENT_TYPES

    # -- redirects ----------------------------------------------------------

    async def _open_upstream(
        self,
        method: str,
        target_bytes: bytes,
        headers: list[tuple[str, str]],
        body: Any,
        max_redirects: int,
        on_hop: Callable[[int, str], None] | None = None,
    ) -> tuple[httpx.Response, str]:
        current = target_bytes
        for hop in range(max_redirects + 1):
            text = urls.parse_target(current, self.allowed_ports)   # re-vet every hop
            if on_hop is not None:
                on_hop(hop, text)
            request = self.client.build_request(
                method, text, headers=headers, content=body
            )
            response = await self.client.send(
                request, stream=True, follow_redirects=False
            )
            if response.is_redirect:
                location = response.headers.get("location", "")
                await response.aclose()
                if not location:
                    raise urls.UrlError(502, "redirect without Location")
                if hop >= max_redirects:
                    raise urls.UrlError(502, "too many redirects")
                # ``body`` is an async iterator (a git-upload-pack request
                # stream), and an iterator can only be consumed once. Reusing it
                # on the next hop built the request successfully and then sent
                # zero bytes — the upstream answered 400 and the client saw an
                # empty reply instead of the "pushed back" error. Measured:
                # hop1 first chunk b'want-payload' / hop2 StopAsyncIteration.
                # Refusing is honest: nobody redirects a receive-pack endpoint
                # in practice, and buffering 10 MB to guess is not worth it.
                if body is not None:
                    raise urls.UrlError(502, "redirected POST")
                try:
                    current = urljoin(text, location).encode("latin-1", "strict")
                except (UnicodeEncodeError, ValueError):
                    raise urls.UrlError(502, "unusable redirect target") from None
                continue
            return response, text
        raise urls.UrlError(502, "too many redirects")     # pragma: no cover

    # -- main entry ---------------------------------------------------------

    async def proxy(self, request) -> StreamingResponse:
        """Validate, connect, and return a streaming response to the caller.

        All policy failures raise ``urls.UrlError`` (or ``Busy``/``BreakerOpen``)
        before a socket is opened; the router maps them to status codes.
        """
        conn = self.conn
        max_url_bytes = db.get_int_setting(conn, "max_url_bytes", 8192)
        target = urls.extract_from_raw(
            request.scope.get("raw_path", b""),
            request.scope.get("query_string", b""),
            max_url_bytes=max_url_bytes,
        )

        user = auth.lookup_token(conn, target.token)
        if user is None:
            # The security log is rotated but still readable by anyone who can
            # read /var/log/dlproxy; a rejected request must not write a
            # candidate token into it in full. Keep the shape, drop the secret.
            raw = bytes(request.scope.get("raw_path", b""))[:160]
            self.security_log(
                "bad_token",
                token_prefix=target.token[:6],
                path=raw.replace(target.token.encode("latin-1", "replace"), b"<token>")
                .decode("latin-1", "replace"),
            )
            raise urls.UrlError(404, "not found")
        user_id = int(user["id"])

        method = request.method.upper()
        upstream_text = urls.parse_target(target.url, self.allowed_ports)
        upstream_path = httpx.URL(upstream_text).path
        git_post = self._is_git_post(
            method, upstream_path, request.headers.get("content-type", ""))
        if method not in ("GET", "HEAD") and not git_post:
            raise urls.UrlError(403, "method not allowed")

        state = quota.check_quota(conn)
        if state.blocked:
            self.security_log("breaker_open", user_id=user_id, reason=state.reason(),
                              day_bytes=state.day_bytes, month_bytes=state.month_bytes)
            self._alert_breaker(state)
            raise BreakerOpen(state)

        # The breaker is clear again. Clearing the stamp on the way out means the
        # next trip is a fresh event and alerts again; leaving it set would mute
        # every future trip until someone visited the admin page.
        if db.get_setting(conn, "breaker_alerted_at", ""):
            db.set_setting(conn, "breaker_alerted_at", "")

        self._enter(target.token)
        entered = True
        transfer_id: int | None = None
        result = StreamResult()
        try:
            headers = self._upstream_request_headers(
                request, include_content_type=git_post)
            body = None
            if method == "POST":
                async def _body():                       # noqa: ANN202
                    async for chunk in request.stream():
                        yield chunk
                body = _body()

            range_hit = bool(request.headers.get("range"))
            if method != "HEAD":
                window = db.get_int_setting(conn, "history_aggregate_window_s", 60)
                cap = db.get_int_setting(conn, "history_per_user", 1000)
                row = history.open_transfer(
                    conn,
                    user_id=user_id,
                    url=upstream_text,
                    client_ip=getattr(request.state, "client_ip", "") or "",
                    user_agent=(request.headers.get("user-agent") or "")[:512],
                    range_hit=range_hit,
                    window_s=window,
                    per_user_cap=cap,
                    xff_raw=(getattr(request.state, "xff_raw", "") or "")[:512],
                )
                transfer_id = row.id

            try:
                response, _final = await self._open_upstream(
                    method, target.url, headers, body,
                    db.get_int_setting(conn, "max_redirects", 5),
                )
            except Exception as exc:
                denial = classify_denial(exc)
                if denial is not None:
                    self.security_log("ssrf_block", user_id=user_id,
                                      host=denial.host, ip=denial.ip,
                                      reason=denial.reason)
                    # Record what the client will actually see, so the history
                    # row is not left with a NULL status.
                    result.status_code = 403
                    raise urls.UrlError(403, "forbidden") from None
                if isinstance(exc, urls.UrlError):
                    result.status_code = exc.status
                    raise
                self.security_log("upstream_error", user_id=user_id,
                                  error=f"{type(exc).__name__}: {exc}"[:300])
                result.status_code = 502
                raise urls.UrlError(502, "upstream error") from None

            if response.status_code == 206 or response.headers.get("content-range"):
                range_hit = True

            result.status_code = response.status_code
            result.size_total = _safe_int(response.headers.get("content-length"))
            result.range_hit = range_hit
            result.upstream_peer = _peer_ip(response)
            response_headers = self._response_headers(response)

            if method == "HEAD":
                await response.aclose()
                self._leave(target.token)
                entered = False
                return StreamingResponse(
                    iter(()), status_code=response.status_code,
                    headers=response_headers,
                )

            generator = self._relay(
                response, result, token=target.token,
                transfer_id=transfer_id, user_id=user_id,
            )
            relay = RelayStream(
                generator,
                self._seal_abandoned(transfer_id, result, target.token),
            )
            entered = False          # ownership passes to the relay
            return RelayResponse(
                relay, relay=relay,
                status_code=response.status_code,
                headers=response_headers,
            )
        finally:
            if entered:
                # Nothing was handed off: this frame still owns the slot, the
                # history row and the upstream connection (already closed by
                # _open_upstream on its own failure paths).
                self._seal_abandoned(transfer_id, result, target.token)()

    def _seal_abandoned(self, transfer_id: int | None, result: StreamResult, token: str):
        """Build the callback that closes the books for a body nobody pulled.

        ``result`` already carries the status the proxy decided on before it
        handed the body off, so a request that dies between ``response.start``
        and the first chunk still records something meaningful instead of a
        NULL. Slot release lives here too: the relay only releases it when its
        own ``finally`` runs, which is exactly the case this callback excludes.
        """

        def seal() -> None:
            self._leave(token)
            if transfer_id is None:
                return
            try:
                history.close_transfer(
                    self.conn, transfer_id,
                    status_code=result.status_code,
                    size_total=result.size_total,
                    duration_ms=result.duration_ms,
                    range_hit=result.range_hit,
                )
            except Exception:                            # pragma: no cover
                log.exception("history close failed")

        return seal

    # -- relay --------------------------------------------------------------

    async def _relay(
        self,
        response: httpx.Response,
        result: StreamResult,
        *,
        token: str,
        transfer_id: int | None,
        user_id: int,
    ):
        conn = self.conn
        idle = float(db.get_int_setting(conn, "stream_idle_timeout_s", 120))
        soft_cap = db.get_int_setting(conn, "transfer_soft_cap_bytes", 50 * 1024**3)
        meter = quota.Meter(conn, transfer_id=transfer_id, user_id=user_id)
        started = db.utc_now()
        first_byte_at = None
        try:
            iterator = response.aiter_bytes(CHUNK_SIZE).__aiter__()
            while True:
                try:
                    chunk = await asyncio.wait_for(iterator.__anext__(), timeout=idle)
                except StopAsyncIteration:
                    break
                except asyncio.TimeoutError:
                    result.status_code = 504
                    result.notes.append(f"idle>{idle:.0f}s")
                    self.security_log("idle_timeout", transfer_id=transfer_id,
                                      idle_s=idle)
                    break
                if first_byte_at is None:
                    first_byte_at = db.utc_now()
                if result.bytes_sent + len(chunk) > soft_cap:
                    result.status_code = 413
                    self.security_log("soft_cap", transfer_id=transfer_id,
                                      soft_cap=soft_cap)
                    break
                yield chunk
                result.bytes_sent += len(chunk)
                meter.add(len(chunk))
        except (GeneratorExit, asyncio.CancelledError):
            result.client_aborted = True
            result.status_code = history.CLIENT_CLOSED_STATUS
            raise
        except httpx.HTTPError as exc:
            result.status_code = 502
            self.security_log("upstream_error", transfer_id=transfer_id,
                              error=f"{type(exc).__name__}: {exc}"[:300])
        finally:
            end = db.utc_now()
            anchor = first_byte_at or started
            result.duration_ms = int((end - anchor).total_seconds() * 1000)
            try:
                await response.aclose()
            except Exception:                            # pragma: no cover
                pass
            try:
                meter.close()
            except Exception:                            # pragma: no cover
                log.exception("meter close failed")
            if transfer_id is not None:
                try:
                    history.close_transfer(
                        conn, transfer_id,
                        status_code=result.status_code,
                        size_total=result.size_total,
                        duration_ms=result.duration_ms,
                        range_hit=result.range_hit,
                    )
                except Exception:                        # pragma: no cover
                    log.exception("history close failed")
            self._leave(token)


def _peer_ip(response: httpx.Response) -> str | None:
    try:
        stream = response.extensions.get("network_stream")
        if stream is None:
            return None
        addr = stream.get_extra_info("server_addr")
        if isinstance(addr, tuple):
            return str(addr[0])
        return str(addr) if addr else None
    except Exception:                                    # pragma: no cover
        return None


def _safe_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
