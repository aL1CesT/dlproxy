"""Locate the nginx executable for the e2e scripts.

Shared because three scripts each grew their own copy of

    binary = Path(args.nginx) if args.nginx else Path(shutil.which("nginx") or "")
    if not binary or not binary.exists(): ...

which is wrong in a way that only shows up once nginx is missing: ``Path("")``
is ``Path(".")``, a directory that exists and is truthy, so the guard passes and
``CreateProcess`` is handed a directory. Windows reports that as

    PermissionError: [WinError 5] 拒绝访问

which names neither nginx nor the missing PATH entry. ``is_file()`` is the only
test that rejects it.
"""
from __future__ import annotations

import shutil
from pathlib import Path


def resolve(explicit: str | None) -> Path | None:
    """Return an nginx executable path, or None when nothing usable was found."""
    if explicit:
        candidate = Path(explicit)
        return candidate if candidate.is_file() else None
    found = shutil.which("nginx")
    if not found:
        return None
    candidate = Path(found)
    return candidate if candidate.is_file() else None
