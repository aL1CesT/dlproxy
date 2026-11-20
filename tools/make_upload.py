"""Build the upload archive with executable bits intact.

Two things this has to get right, both of which bit us before:

  * Windows has no x bit. `git archive` honours the mode recorded in the index
    (`git update-index --chmod=+x`), but nothing on this side of an NTFS copy
    does. The installer is invoked as `sudo ./deploy.sh`, so a lost bit is a
    hard "permission denied" on the far side.
  * bsdtar's zip writer drops the unix mode entirely — every entry comes out
    -rw-rw-rw-. Python's zipfile exposes the mode in the top 16 bits of
    `external_attr`, which unzip, Info-ZIP and Ubuntu's `unzip` all honour.

Usage:  python tools/make_upload.py [--out DIR] [--keep DIR]

`--keep` leaves the staged tree in place instead of deleting it, so the user
can `scp -r` a plain folder. Both artefacts come from the same file list and
the same chmod pass, so they cannot drift.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Files that must arrive executable on the server. deploy.sh is run directly;
# the rest are run by systemd, cron or by hand.
EXECUTABLE = {
    "install.sh",
    "deploy.sh",
    "deploy/deploy.sh",
    "deploy/install.sh",
    "deploy/uninstall.sh",
    "deploy/backup.sh",
    "deploy/cert-check.sh",
    "deploy/renewal-hook.sh",
    "deploy/dlproxy-cli.sh",
    "tools/verify_all.sh",
    "tools/e2e_nginx.sh",
    "tools/range_download.sh",
}

# Never ship: local database, secrets, screenshots, caches. .gitignore covers
# most of this, but `git ls-files` is the real source of truth below.
# `screenshots` is tracked (docs/ references it) yet has no business on a server.
SKIP_DIRS = {"__pycache__", ".pytest_cache", "shots", "screenshots", "data", "backup"}


def tracked_files() -> list[str]:
    """Every file git knows about. Anything untracked is not part of the tree."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
        ).stdout
    except FileNotFoundError:
        # The server-side install path does not need this tool at all: fetch the
        # tarball instead. Reaching here means someone tried to run it on a box
        # without git, and a bare traceback would look like a bug in the project.
        print(
            "make_upload 需要 git（它用 git ls-files 取文件清单）。\n"
            "  在服务器上装：   sudo apt-get install -y git\n"
            "  不需要打包的话： 直接从 GitHub 下载 tarball，见 docs/deployment.md",
            file=sys.stderr,
        )
        raise SystemExit(2)
    files = [p.decode() for p in out.split(b"\0") if p]
    return [f for f in files if not (set(Path(f).parts) & SKIP_DIRS)]


def stage(target: Path, files: list[str]) -> None:
    """Copy the tree into <target>/dlproxy/ so an upload yields one folder."""
    if target.exists():
        shutil.rmtree(target)
    base = target / "dlproxy"
    for rel in files:
        dst = base / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dst)


def write_zip(source: Path, out: Path) -> int:
    count = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(source.rglob("*")):
            if path.is_dir():
                continue
            rel = path.relative_to(source).as_posix()
            info = zipfile.ZipInfo(rel)
            info.date_time = (2024, 1, 1, 0, 0, 0)      # reproducible
            # The archive root is already dlproxy/, so strip it for the lookup.
            mode_key = rel.split("/", 1)[1] if "/" in rel else rel
            mode = 0o755 if mode_key in EXECUTABLE else 0o644
            # unix mode lives in the high 16 bits; the low bit says "not DOS".
            info.external_attr = (mode << 16) | 0o100000
            # ZipInfo defaults create_system from sys.platform, so a zip built on
            # Windows says "MS-DOS" — and unzip only reads external_attr when the
            # entry claims to come from Unix. Without this line the archive is
            # correct and unzip still writes 0666, which turns `sudo ./install.sh`
            # into "Permission denied" on the very machine it was packed for.
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, path.read_bytes())
            count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(ROOT.parent), help="where to put the archives")
    ap.add_argument(
        "--keep",
        metavar="DIR",
        help="also leave an uploadable folder here (default: discard the staging tree)",
    )
    args = ap.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    files = tracked_files()
    if not files:
        print(
            "git ls-files returned nothing — run this from a checkout of the repo",
            file=sys.stderr,
        )
        return 1

    keep = Path(args.keep) if args.keep else None
    staging = keep if keep else out_dir / "_upload_staging"
    stage(staging, files)
    # chmod as well, so a plain `scp -r` of the staging dir also works.
    for rel in EXECUTABLE:
        p = staging / "dlproxy" / rel
        if p.exists():
            os.chmod(p, 0o755)

    zip_path = out_dir / "dlproxy-upload.zip"
    n = write_zip(staging, zip_path)
    if keep:
        print(f"folder: {staging} (scp -r this)")
    else:
        shutil.rmtree(staging)

    total = sum((ROOT / f).stat().st_size for f in files)
    print(f"{n} files, {total} bytes uncompressed")
    print(f"zip: {zip_path} ({zip_path.stat().st_size} bytes)")
    print(f"executable: {len(EXECUTABLE)} entries pinned to 0755")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
