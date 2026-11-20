"""Byte-level URL recovery from the raw request line.

This is the single most breakage-prone part of the service, so it is isolated
here and covered by tests/test_urls.py.

Why bytes and not ``request.url.path``
--------------------------------------
Starlette decodes and normalises ``path``: ``%2F`` becomes ``/``, ``%20``
becomes a space, repeated slashes may be collapsed. The upstream URL must
survive verbatim, so we read ``scope["raw_path"]`` (percent-encoded, exactly as
sent) and ``scope["query_string"]`` (already separate — uvicorn strips it from
raw_path), then re-join them with a literal ``?``.

Measured behaviour this module compensates for
----------------------------------------------
* nginx answers 400 for a bare ``%`` and for ``%00`` before the app ever runs,
  but it happily forwards ``%ff`` (invalid UTF-8), ``%2e%2e``, ``../``,
  ``user:pass@``, ``:8443`` and URLs over 16 KB. All of those are rejected here.
* A fragment is never sent by the browser, so ``#`` in a pasted link arrives as
  a literal ``#``. It is stripped rather than guessed at.
* ``raw_path`` keeps ``https://`` intact only because Nginx is configured with a
  URI-less ``proxy_pass``. That is a hard constraint on deploy/nginx.conf.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

__all__ = [
    "UrlError",
    "Target",
    "extract_from_raw",
    "parse_target",
    "UPSTREAM_PREFIXES",
]

UPSTREAM_PREFIXES = (b"http://", b"https://")

# Percent-escapes must be exactly two hex digits. Everything else is malformed
# and gets a 400 rather than being silently re-encoded.
_BAD_PERCENT = re.compile(rb"%(?![0-9A-Fa-f]{2})")
# Escapes that decode to a C0 control byte or DEL. Nginx already answers 400 for
# %00 today, but 8080 is reachable directly on the box, so the app enforces it too.
_CONTROL_ESCAPE = re.compile(
    rb"%(?:0[0-9A-Fa-f]|1[0-9A-Fa-f]|7[Ff])"
)

ALLOWED_PORTS = {80, 443}


class UrlError(Exception):
    """Request-shaping problem, mapped to an HTTP status by the caller."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass(frozen=True)
class Target:
    token: str
    url: bytes            # exact bytes to hand to httpx (decode with latin-1 later)
    has_query: bool


def extract_from_raw(
    raw_path: bytes,
    query_string: bytes,
    *,
    max_url_bytes: int = 8192,
) -> Target:
    """Split ``/u/<token>/<absolute-url>[?<query>]`` into its parts.

    ``raw_path`` is the percent-encoded path *without* the query (uvicorn puts
    the query in a separate scope key). We re-attach it byte for byte so a
    ``?``, ``&`` or ``=`` inside the upstream URL is never re-interpreted.
    """
    if _BAD_PERCENT.search(raw_path) or _BAD_PERCENT.search(query_string):
        raise UrlError(400, "malformed percent-encoding")
    if _CONTROL_ESCAPE.search(raw_path) or _CONTROL_ESCAPE.search(query_string):
        raise UrlError(400, "control characters are not allowed in the target URL")

    if not raw_path.startswith(b"/u/"):
        raise UrlError(404, "not found")

    after = raw_path[len(b"/u/"):]
    slash = after.find(b"/")
    if slash <= 0:
        # No token, or a token with no target after it.
        raise UrlError(404, "not found")
    token_bytes = after[:slash]
    rest = after[slash + 1:]

    try:
        token = token_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise UrlError(404, "not found") from None
    if not token or not token.isalnum():
        raise UrlError(404, "not found")

    if not rest:
        raise UrlError(404, "not found")
    if not rest.startswith(UPSTREAM_PREFIXES):
        raise UrlError(400, "target must be an absolute http(s) URL")

    url = rest + (b"?" + query_string if query_string else b"")
    if len(url) > max_url_bytes:
        raise UrlError(414, "target URL too long")

    return Target(token=token, url=url, has_query=bool(query_string))


def parse_target(url: bytes, allowed_ports: frozenset[int] = frozenset(ALLOWED_PORTS)) -> str:
    """Validate the upstream URL and return it as text ready for httpx.

    Rejects: non-http(s) schemes, userinfo, ports other than
    80/443, empty host, embedded whitespace/control bytes.

    ``allowed_ports`` exists for two callers only: the local test suite, whose
    origin server cannot bind 80/443, and any future deliberate widening. The
    production default is  80 and 443 only.
    """
    if _BAD_PERCENT.search(url):
        raise UrlError(400, "malformed percent-encoding")
    if _CONTROL_ESCAPE.search(url):
        raise UrlError(400, "control characters are not allowed in the target URL")

    # A fragment is never transmitted by browsers; if one arrives it came from a
    # pasted string. Drop it at the first '#', which is what the user meant.
    hash_at = url.find(b"#")
    if hash_at != -1:
        url = url[:hash_at]

    # httpx wants text. The bytes are already percent-encoded, so latin-1 is a
    # loss-free byte->codepoint mapping; httpx re-encodes as UTF-8 on the wire,
    # which is what the origin server expects for a pre-encoded path.
    try:
        text = url.decode("latin-1")
    except UnicodeDecodeError:                       # pragma: no cover - latin-1 is total
        raise UrlError(400, "target URL is not decodable") from None

    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in text):
        raise UrlError(400, "target URL contains control or space characters")

    try:
        parts = urlsplit(text)
    except ValueError as exc:
        raise UrlError(400, f"unparseable target URL: {exc}") from None

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise UrlError(400, "only http and https are proxied")
    if parts.username is not None or parts.password is not None:
        raise UrlError(400, "userinfo in target URL is not allowed")
    if not parts.hostname:
        raise UrlError(400, "target URL has no host")

    port = parts.port                       # raises ValueError on garbage, caught above
    if port is not None and port not in allowed_ports:
        raise UrlError(400, "only ports 80 and 443 are proxied")

    return text
