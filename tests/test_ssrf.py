"""SSRF policy unit tests — pure address logic, no sockets."""
from __future__ import annotations

import pytest

from app.ssrf import SsrfBackend, SsrfDenied, SsrfPolicy, classify_denial


@pytest.fixture()
def policy():
    return SsrfPolicy()


BLOCKED = [
    "127.0.0.1",
    "10.0.0.1",
    "172.16.5.4",
    "192.168.1.1",
    "169.254.169.254",       # the cloud metadata service
    "0.0.0.0",
    "100.64.0.1",            # CGNAT
    "::1",
    "fe80::1",
    "fd00::1",
    "::ffff:169.254.169.254",   # IPv4-mapped
    "64:ff9b::a9fe:a9fe",       # NAT64-wrapped 169.254.169.254
    "2002:a9fe:a9fe::1",        # 6to4-wrapped 169.254.169.254
    "224.0.0.1",                # multicast
]

ALLOWED = [
    "1.1.1.1",
    "8.8.8.8",
    "140.82.121.4",          # github.com
    "2606:4700:4700::1111",
]


@pytest.mark.parametrize("ip", BLOCKED)
def test_blocked(policy, ip):
    blocked, reason = policy.is_blocked(ip)
    assert blocked, f"{ip} should be refused"
    assert reason


@pytest.mark.parametrize("ip", ALLOWED)
def test_allowed(policy, ip):
    blocked, reason = policy.is_blocked(ip)
    assert not blocked, f"{ip} should be allowed, got {reason}"


def test_vet_raises_with_attribution(policy):
    with pytest.raises(SsrfDenied) as exc:
        policy.vet("169.254.169.254", host="metadata.example")
    assert exc.value.host == "metadata.example"
    assert exc.value.ip == "169.254.169.254"
    assert exc.value.reason


def test_private_allowed_only_when_opted_in():
    relaxed = SsrfPolicy(allow_private=True)
    assert relaxed.is_blocked("127.0.0.1") == (False, "")


def test_allow_hosts_is_exact_not_suffix():
    p = SsrfPolicy(allow_hosts=["internal.test"])
    assert p.is_blocked("127.0.0.1", host="internal.test")[0] is False
    assert p.is_blocked("127.0.0.1", host="evil.internal.test")[0] is True


def test_port_vetting():
    p = SsrfPolicy(allow_ports={80, 443})
    p.vet_port("e.com", 443)
    with pytest.raises(SsrfDenied):
        p.vet_port("e.com", 8080)


def test_scope_id_is_not_a_bypass(policy):
    blocked, _ = policy.is_blocked("fe80::1")
    assert blocked


def test_garbage_address_is_blocked(policy):
    assert policy.is_blocked("not-an-ip")[0] is True


@pytest.mark.asyncio
async def test_resolve_literal_returns_itself(policy):
    assert await policy.resolve("1.2.3.4", 443) == ["1.2.3.4"]


@pytest.mark.asyncio
async def test_resolve_localhost_name(policy):
    addrs = await policy.resolve("localhost", 80)
    assert addrs, "getaddrinfo should return something for localhost"
    assert all(a for a in addrs)


class _RecordingInner:
    """Fake inner backend that records which literal IP was dialled."""

    def __init__(self, peer_override: str | None = None):
        self.dialled: list[str] = []
        self.peer_override = peer_override

    async def connect_tcp(self, host, port, timeout=None, local_address=None,
                          socket_options=None):
        self.dialled.append(host)

        class _Stream:
            def __init__(self, peer):
                self._peer = peer
                self.closed = False

            def get_extra_info(self, key):
                if key == "server_addr":
                    return (self._peer, 443)
                return None

            async def aclose(self):
                self.closed = True

        return _Stream(self.peer_override or host)

    async def connect_unix_socket(self, *a, **k):       # pragma: no cover
        raise AssertionError("unix sockets must never be dialled")

    async def sleep(self, seconds):
        return None


@pytest.mark.asyncio
async def test_backend_refuses_before_dialling():
    inner = _RecordingInner()
    backend = SsrfBackend(SsrfPolicy(), inner)          # type: ignore[arg-type]
    with pytest.raises(SsrfDenied):
        await backend.connect_tcp("169.254.169.254", 80)
    assert inner.dialled == [], "must not open a socket to a blocked address"
    assert backend.last_denial is not None
    assert backend.last_denial.reason


@pytest.mark.asyncio
async def test_backend_pins_and_verifies_peer():
    inner = _RecordingInner()
    backend = SsrfBackend(SsrfPolicy(), inner)          # type: ignore[arg-type]
    stream = await backend.connect_tcp("1.1.1.1", 443)
    assert inner.dialled == ["1.1.1.1"]
    assert backend.events[0][1] == "1.1.1.1"
    await stream.aclose()                                # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_backend_catches_peer_mismatch():
    """The rebinding case: resolver says 1.1.1.1, socket lands on 127.0.0.1."""
    inner = _RecordingInner(peer_override="127.0.0.1")
    backend = SsrfBackend(SsrfPolicy(), inner)          # type: ignore[arg-type]
    with pytest.raises(SsrfDenied) as exc:
        await backend.connect_tcp("1.1.1.1", 443)
    assert exc.value.reason == "peer-mismatch"


@pytest.mark.asyncio
async def test_unix_socket_backend_disabled():
    backend = SsrfBackend(SsrfPolicy(), _RecordingInner())   # type: ignore[arg-type]
    with pytest.raises(SsrfDenied):
        await backend.connect_unix_socket("/var/run/x.sock")


def test_classify_denial_walks_the_cause_chain():
    try:
        try:
            raise SsrfDenied("inner", reason="test")
        except SsrfDenied as inner:
            raise OSError("wrapper") from inner
    except OSError as outer:
        found = classify_denial(outer)
    assert found is not None and found.reason == "test"


def test_classify_denial_returns_none_for_plain_errors():
    assert classify_denial(ValueError("x")) is None
