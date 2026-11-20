"""Background SMTP alerts.

Three events raise an alert: certificate expiry, circuit-breaker trip, and
account lockout after repeated login failures. Request handlers use
``send_alert`` (fire-and-forget); one-shot processes such as
``python -m app alert-cert`` use ``send_now``, which awaits delivery.

Design constraints:
  * an unconfigured SMTP block must not block startup — the service runs, the
    admin page shows a yellow "alert channel not configured" banner;
  * sending happens in a background task and can never fail the main flow;
  * failures are written to the security log, not to the user.

SMTP credentials live in the ``settings`` table and nowhere else. ``.env`` holds
only the session signing key. One fact, one owner.
"""
from __future__ import annotations

import asyncio
import logging
import smtplib
import sqlite3
import ssl
from dataclasses import dataclass
from email.message import EmailMessage

from . import db

__all__ = [
    "SmtpConfig",
    "load_config",
    "is_configured",
    "send_alert",
    "send_now",
    "send_test",
]

log = logging.getLogger("dlproxy.mailer")

CONNECT_TIMEOUT = 15.0


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int
    user: str
    password: str
    sender: str
    recipient: str
    use_tls: bool

    @property
    def usable(self) -> bool:
        return bool(self.host and self.sender and self.recipient)


def load_config(conn: sqlite3.Connection) -> SmtpConfig:
    get = lambda k, d="": db.get_setting(conn, k, d)          # noqa: E731
    try:
        port = int(get("smtp_port", "587") or 587)
    except ValueError:
        port = 587
    # The panel accepts anything that parses; smtplib only fails at connect
    # time, which then reads as a generic "send failed". Clamp here so the
    # number that reaches it is always a usable TCP port.
    port = min(65535, max(1, port))
    return SmtpConfig(
        host=get("smtp_host").strip(),
        port=port,
        user=get("smtp_user").strip(),
        password=get("smtp_pass"),
        sender=get("smtp_from").strip(),
        recipient=get("smtp_to").strip(),
        use_tls=get("smtp_tls", "1") in ("1", "true", "True", "on"),
    )


def is_configured(conn: sqlite3.Connection) -> bool:
    return load_config(conn).usable


# ---------------------------------------------------------------------------
# Blocking sender (runs inside a worker thread)
# ---------------------------------------------------------------------------

def _send_blocking(cfg: SmtpConfig, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = cfg.sender
    msg["To"] = cfg.recipient
    msg["Subject"] = f"[dlproxy] {subject}"
    msg.set_content(body)

    if cfg.port == 465:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=CONNECT_TIMEOUT,
                              context=ctx) as smtp:
            if cfg.user:
                smtp.login(cfg.user, cfg.password)
            smtp.send_message(msg)
        return

    with smtplib.SMTP(cfg.host, cfg.port, timeout=CONNECT_TIMEOUT) as smtp:
        smtp.ehlo()
        if cfg.use_tls:
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
        if cfg.user:
            smtp.login(cfg.user, cfg.password)
        smtp.send_message(msg)


async def _deliver(cfg: SmtpConfig, subject: str, body: str) -> bool:
    try:
        await asyncio.to_thread(_send_blocking, cfg, subject, body)
        return True
    except Exception as exc:                     # noqa: BLE001 - must never escape
        log.warning("smtp delivery failed: %s: %s", type(exc).__name__, exc)
        return False


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def send_alert(
    conn: sqlite3.Connection,
    *,
    subject: str,
    body: str,
    security_log=None,
) -> asyncio.Task | None:
    """Fire-and-forget alert. Returns the task so tests can await it.

    The config is snapshotted *now*: the connection object may be closed by the
    time the worker thread runs.
    """
    cfg = load_config(conn)
    if not cfg.usable:
        return None

    async def runner() -> None:
        ok = await _deliver(cfg, subject, body)
        if not ok and security_log is not None:
            security_log("smtp_failed", subject=subject)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return None
    return loop.create_task(runner())


async def send_now(
    conn: sqlite3.Connection,
    *,
    subject: str,
    body: str,
) -> bool:
    """Deliver one message and await it. Returns whether it went out.

    ``send_alert`` is fire-and-forget because a request handler must never block
    on SMTP. A cron invocation is the opposite case: ``python -m app
    alert-cert`` exits immediately after the call, so if the sender does not
    wait here the message is lost when the process is torn down.
    """
    cfg = load_config(conn)
    if not cfg.usable:
        return False
    return await _deliver(cfg, subject, body)


async def send_test(conn: sqlite3.Connection) -> tuple[bool, str]:
    """Admin-page "send test mail". Returns (ok, message) for inline display."""
    cfg = load_config(conn)
    if not cfg.usable:
        return False, "告警通道尚未配置：请先填写 SMTP 主机、发件人与收件人。"
    ok = await _deliver(
        cfg,
        "测试邮件",
        "本邮件由 dlproxy 发送，用于验证告警通道。收到即表示通道可用。\n",
    )
    if ok:
        return True, f"已发送至 {cfg.recipient}。"
    return False, "发送失败，详情见 /var/log/dlproxy/security.log 与 journalctl。"
