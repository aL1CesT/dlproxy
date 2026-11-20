"""SSRF defence: DNS pinning + peer re-verification, at the httpcore TCP layer.

Why this design
---------------
Two things have to hold at once: "resolve, then vet every answer", and "after
connecting, re-check the peer address to defeat DNS rebinding". httpx offers no
hook for either, so the vetting happens inside a custom
``httpcore.AsyncNetworkBackend``:

  resolve -> vet EVERY answer -> connect to a vetted literal IP
          -> re-read getpeername() and assert it equals the vetted IP

The URL host is never rewritten, so the Host header, TLS SNI, certificate
verification and the connection-pool key all keep using the real hostname. This
is strictly better than the "swap URL host for an IP + set Host + sni_hostname"
trick, which silently reuses a pooled connection under the wrong SNI.

Injection point: ``httpcore.AsyncConnectionPool(network_backend=...)`` is public
API since httpcore 0.17.3. httpx's own ``AsyncHTTPTransport`` has no such
parameter, so we build the pool ourselves and attach it.

Measured facts this file encodes (see tools/e2e_ssrf.py for the harness)
-----------------------------------------------------------------------
* ``response.extensions["network_stream"].get_extra_info("server_addr")`` is a
  public API and works, but only *before* the body is iterated when
  ``max_keepalive_connections=0``. We take the peer inside the backend instead,
  so it cannot go stale.
* ``ipaddress`` reports NAT64/6to4/IPv4-mapped IPv6 forms as global while they
  can reach private space. All three are unwrapped before judging.
* IDNs arrive at the backend as punycode. Vetting is done on whatever string
  httpcore hands us, so no punycode table is needed here.
* Proxies defeat the whole scheme (httpcore hardcodes the proxy host as the SNI
  target), therefore ``trust_env=False`` everywhere and HTTP(S)_PROXY is ignored.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from collections.abc import Iterable
from typing import Any

import httpcore
import httpx

__all__ = [
    "SsrfDenied",
    "SsrfPolicy",
    "SsrfBackend",
    "ssrf_safe_client",
    "classify_denial",
]

# Well-known transition prefixes that smuggle an IPv4 address inside an IPv6 one.
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
_SIX_TO_FOUR = ipaddress.IPv6Network("2002::/16")

# IPv4 ranges that must never be reachable. Kept explicit (rather than relying
# on ``is_global``) so the behaviour is auditable line by line.
BLOCKED_V4 = tuple(
    ipaddress.IPv4Network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
    )
)
BLOCKED_V6 = tuple(
    ipaddress.IPv6Network(n) for n in ("::1/128", "fe80::/10", "fc00::/7")
)


class SsrfDenied(httpcore.ConnectError):
    """Target refused by policy. Subclasses ConnectError so httpcore's retry
    loop treats it as terminal rather than a transient network fault."""

    def __init__(self, message: str, *, host: str = "", ip: str = "",
                 reason: str = "") -> None:
        super().__init__(message)
        self.host = host
        self.ip = ip
        self.reason = reason


class SsrfPolicy:
    """Vetting rules. ``allow_private`` exists solely for the local test suite,
    which has to reach 127.0.0.1 fixtures; production never sets it."""

    def __init__(
        self,
        *,
        allow_private: bool = False,
        allow_hosts: Iterable[str] = (),
        allow_ports: Iterable[int] | None = None,
        resolver: Any = None,
    ) -> None:
        self.allow_private = allow_private
        self.allow_hosts = {h.lower() for h in allow_hosts}
        self.allow_ports = set(allow_ports) if allow_ports is not None else None
        self._resolver = resolver

    # -- address judgement ---------------------------------------------------

    @staticmethod
    def _unwrap(addr: ipaddress.IPv4Address | ipaddress.IPv6Address):
        """Reduce an IPv6 address that embeds an IPv4 to that IPv4 address."""
        if isinstance(addr, ipaddress.IPv6Address):
            if addr.ipv4_mapped is not None:
                return addr.ipv4_mapped
            if addr in _NAT64:
                return ipaddress.IPv4Address(addr.packed[-4:])
            if addr in _SIX_TO_FOUR:
                return ipaddress.IPv4Address(addr.packed[2:6])
        return addr

    def is_blocked(self, ip: str, *, host: str = "") -> tuple[bool, str]:
        """Return (blocked, reason). Reason is for the security log only."""
        if self.allow_private or host.lower() in self.allow_hosts:
            return False, ""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True, "unparseable address"
        addr = self._unwrap(addr)
        if addr.version == 4:
            for net in BLOCKED_V4:
                if addr in net:
                    return True, f"ipv4 {net}"
        else:
            for net in BLOCKED_V6:
                if addr in net:
                    return True, f"ipv6 {net}"
        if addr.is_multicast:
            return True, "multicast"
        if not addr.is_global:
            return True, "not globally routable"
        return False, ""

    def vet(self, ip: str, *, host: str = "") -> None:
        blocked, reason = self.is_blocked(ip, host=host)
        if blocked:
            raise SsrfDenied(f"blocked {host or ip}", host=host, ip=ip, reason=reason)

    def vet_port(self, host: str, port: int) -> None:
        if self.allow_ports is not None and port not in self.allow_ports:
            raise SsrfDenied(f"blocked port {port}", host=host, reason="port")

    # -- resolution ----------------------------------------------------------

    async def resolve(self, host: str, port: int) -> list[str]:
        try:
            ipaddress.ip_address(host)
            return [host]                       # already a literal, nothing to resolve
        except ValueError:
            pass
        if self._resolver is not None:
            return list(await self._resolver(host, port))
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(
            host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
        out: list[str] = []
        for info in infos:
            ip = str(info[4][0]).split("%", 1)[0]   # strip IPv6 scope id
            if ip not in out:
                out.append(ip)
        return out


class SsrfBackend(httpcore.AsyncNetworkBackend):
    """httpcore backend: resolve -> vet all -> connect literal IP -> verify peer."""

    def __init__(
        self,
        policy: SsrfPolicy | None = None,
        inner: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self.policy = policy or SsrfPolicy()
        self._inner = inner or httpcore.AnyIOBackend()
        # (host, pinned_ip, peer) triples; the security log drains this.
        self.events: list[tuple[str, str, Any]] = []
        # Denials observed during the most recent connect, for log attribution.
        self.last_denial: SsrfDenied | None = None

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.last_denial = None
        try:
            self.policy.vet_port(host, port)
            addrs = await self.policy.resolve(host, port)
            if not addrs:
                raise SsrfDenied(f"no address for {host}", host=host, reason="nxdomain")
            for ip in addrs:                    # every answer, not just the first
                self.policy.vet(ip, host=host)
        except SsrfDenied as exc:
            self.last_denial = exc
            raise

        last_exc: Exception | None = None
        for pin in addrs:
            try:
                stream = await self._inner.connect_tcp(
                    pin,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError) as exc:
                last_exc = exc
                continue
            peer = stream.get_extra_info("server_addr")
            peer_ip = peer[0] if isinstance(peer, tuple) else (str(peer) if peer else None)
            # Re-check the address the kernel actually connected us to. This is
            # the anti-rebinding step: the resolver could have lied, or a
            # transparent proxy could have redirected us.
            try:
                same = peer_ip is not None and (
                    ipaddress.ip_address(peer_ip) == ipaddress.ip_address(pin)
                )
            except ValueError:
                same = False
            if not same:
                await stream.aclose()
                denied = SsrfDenied(
                    f"peer mismatch: vetted {pin}, connected {peer_ip}",
                    host=host, ip=pin, reason="peer-mismatch",
                )
                self.last_denial = denied
                raise denied
            self.events.append((host, pin, peer))
            return stream

        raise SsrfDenied(f"connect failed for {host}: {last_exc}", host=host,
                         reason="connect")

    async def connect_unix_socket(
        self, *args: Any, **kwargs: Any
    ) -> httpcore.AsyncNetworkStream:
        raise SsrfDenied("unix sockets disabled", reason="unix")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def _build_ssl_context(verify: bool | ssl.SSLContext, cert: Any) -> ssl.SSLContext:
    """Avoid httpx's private ``create_ssl_context`` whose signature changed
    between 0.27 and 0.28. Rebuilding it by hand is three lines and stable."""
    if isinstance(verify, ssl.SSLContext):
        return verify
    ctx = ssl.create_default_context()
    if verify is False:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if cert is not None:
        if isinstance(cert, str):
            ctx.load_cert_chain(cert)
        else:
            ctx.load_cert_chain(*cert)
    return ctx


def ssrf_safe_client(
    *,
    policy: SsrfPolicy | None = None,
    verify: bool | ssl.SSLContext = True,
    cert: Any = None,
    http2: bool = False,
    max_connections: int = 64,
    max_keepalive_connections: int = 16,
    keepalive_expiry: float = 5.0,
    retries: int = 0,
    timeout: Any = None,
) -> tuple[httpx.AsyncClient, SsrfBackend]:
    """Return ``(client, backend)``. The backend is exposed so callers can read
    ``backend.events`` / ``backend.last_denial`` for the security log."""
    if timeout is None:
        timeout = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0)
    ssl_context = _build_ssl_context(verify, cert)
    backend = SsrfBackend(policy)
    pool = httpcore.AsyncConnectionPool(
        ssl_context=ssl_context,
        max_connections=max_connections,
        max_keepalive_connections=max_keepalive_connections,
        keepalive_expiry=keepalive_expiry,
        http1=True,
        http2=http2,
        retries=retries,
        network_backend=backend,            # public kwarg, httpcore >= 0.17.3
    )
    transport = httpx.AsyncHTTPTransport(
        verify=verify, cert=cert, http2=http2, trust_env=False
    )
    transport._pool = pool                  # httpx exposes no network_backend hook
    client = httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        trust_env=False,                    # ignore HTTP(S)_PROXY / NO_PROXY entirely
        follow_redirects=False,             # we walk redirects ourselves, hop by hop
    )
    return client, backend


def classify_denial(exc: BaseException) -> SsrfDenied | None:
    """Walk ``__cause__``/``__context__`` because httpcore wraps failures in
    ``ConnectError("All connection attempts failed")`` and loses the real cause
    one level down."""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, SsrfDenied):
            return cur
        cur = cur.__cause__ or cur.__context__
    return None
