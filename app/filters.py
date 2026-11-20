"""Jinja filters and small helpers shared by the templates."""
from __future__ import annotations

UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")


def humanbytes(value) -> str:
    """Render a byte count the way a person reads it (binary units)."""
    if value is None:
        return "—"
    try:
        n = float(value)
    except (TypeError, ValueError):
        return "—"
    sign = "-" if n < 0 else ""
    n = abs(n)
    if n < 1024:
        return f"{sign}{int(n)} B"
    for unit in UNITS[1:]:
        n /= 1024.0
        if n < 1024 or unit == UNITS[-1]:
            return f"{sign}{n:.1f} {unit}"
    return f"{sign}{n:.1f} {UNITS[-1]}"        # pragma: no cover


def register_filters(templates) -> None:
    templates.env.filters["humanbytes"] = humanbytes
