"""``python -m dlproxy ...`` — dispatches between the CLI tools and the server.

With no sub-command this starts uvicorn directly, which is handy for a quick
local run without systemd: ``python -m dlproxy serve``.
"""
from __future__ import annotations

import os
import sys

from .cli import main as cli_main

CLI_COMMANDS = {
    "createadmin", "admin", "createuser", "user",
    "setpassword", "showtoken", "listusers", "backup", "menu",
    "alert-cert", "alertcert", "set-site", "setsite",
}


def serve() -> int:
    import uvicorn

    host = os.environ.get("DLPROXY_HOST", "127.0.0.1")
    port = int(os.environ.get("DLPROXY_PORT", "8080"))
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        # The proxy is one long-lived streaming response per request; the access
        # log would gain one line per multi-gigabyte download and nothing else.
        access_log=False,
        log_level=os.environ.get("DLPROXY_LOG_LEVEL", "info"),
        # No keep-alive timeout: a Range request can legitimately hold a socket
        # for an hour, and Nginx is the only peer.
        timeout_keep_alive=75,
        proxy_headers=False,
        server_header=False,
    )
    return 0


def _first_command(argv: list[str]) -> str | None:
    """The sub-command, looking past the global ``--db PATH`` option.

    Only ``--db`` may precede it, so the scan is deliberately narrow: a bare
    ``python -m app`` (which is what systemd runs) must still reach uvicorn.
    """
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--db":
            i += 2
            continue
        if token.startswith("-"):
            return None
        return token
    return None


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if _first_command(argv) in CLI_COMMANDS:
        return cli_main(argv)
    return serve()


if __name__ == "__main__":                       # pragma: no cover
    raise SystemExit(main())
