"""Tests for the two forwarders in the repository root.

Why they exist at all: every document says `sudo ./install.sh` and
`sudo ./deploy.sh`, but the real scripts live one level down in deploy/. For a
long time those commands simply failed — `./install.sh: No such file or
directory` — because nothing was there. The fix was a two-line forwarder rather
than moving the wizard, because deploy/install.sh sources deploy/deploy.sh out
of its own directory and the pair has to stay together.

So what is worth testing is exactly what could regress:

  * the arguments arrive unchanged (including none at all),
  * a broken/unpacked checkout fails with a sentence, not a bash stack,
  * the scripts stay executable *and* keep the shebang, since the whole point
    is `sudo ./install.sh` working without a `bash` in front of it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINTS = ("install.sh", "deploy.sh")

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="the entrypoints are bash"
)


def run(path: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(path), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        cwd=str(path.parent),
        stdin=subprocess.DEVNULL,
    )


@pytest.mark.parametrize("name", ENTRYPOINTS)
def test_the_root_entrypoint_exists_and_is_executable(name: str) -> None:
    """`sudo ./install.sh` needs the x bit; bash -c says nothing about that."""
    path = ROOT / name
    assert path.is_file(), f"{name} should be in the repository root"
    assert os.access(path, os.X_OK) or os.name == "nt", (
        f"{name} must keep its executable bit — the docs run it as ./{name}"
    )
    assert path.read_bytes().startswith(b"#!/usr/bin/env bash"), name


@pytest.mark.parametrize("name", ENTRYPOINTS)
def test_the_root_entrypoint_parses(name: str) -> None:
    r = subprocess.run(
        ["bash", "-n", str(ROOT / name)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        stdin=subprocess.DEVNULL,
    )
    assert r.returncode == 0, r.stderr


def test_install_help_comes_from_the_wizard() -> None:
    """The forwarder must not invent its own help text."""
    r = run(ROOT / "install.sh", "--help")
    assert r.returncode == 0, r.stderr
    assert "--dry-run" in r.stdout
    assert "--yes" in r.stdout
    # A phrase that only deploy/install.sh prints.
    assert "不做任何安装动作" in r.stdout


def test_deploy_help_comes_from_the_installer() -> None:
    r = run(ROOT / "deploy.sh", "--help")
    assert r.returncode == 0, r.stderr
    assert "--stage" in r.stdout
    assert "--share-443" in r.stdout
    # A phrase that only deploy/deploy.sh prints.
    assert "只跑某个阶段" in r.stdout


def test_an_unknown_flag_is_reported_by_the_real_script() -> None:
    """Proves the arguments reach deploy.sh rather than dying in the forwarder."""
    r = run(ROOT / "deploy.sh", "--not-a-flag")
    assert r.returncode != 0
    combined = r.stdout + r.stderr
    assert "--not-a-flag" in combined
    # deploy.sh's own wording for this, not the forwarder's.
    assert "未知参数" in combined


@pytest.mark.parametrize("name", ENTRYPOINTS)
def test_a_half_unpacked_checkout_says_what_is_missing(
    name: str, tmp_path: Path
) -> None:
    """Copy the forwarder alone: the target is absent, and that must be a sentence.

    This is the shape of a mistake people actually make — grabbing one file out
    of the tree, or extracting only the root level. Without this guard bash
    would report `deploy/install.sh: No such file or directory` from inside the
    exec, which reads like a bug in the project.
    """
    lonely = tmp_path / name
    shutil.copy2(ROOT / name, lonely)
    r = run(lonely)
    assert r.returncode == 1, (r.stdout, r.stderr)
    assert "[x] 找不到" in r.stderr
    assert "整个仓库目录完整" in r.stderr
    # No half-run installer output.
    assert "==>" not in r.stdout


def test_the_forwarders_point_at_the_real_scripts() -> None:
    for name, target in (("install.sh", "deploy/install.sh"),
                         ("deploy.sh", "deploy/deploy.sh")):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert f'"$here/{target}"' in text, name
        assert 'exec bash "$target" "$@"' in text, name


def test_the_dev_requirements_are_pinned() -> None:
    """CONTRIBUTING tells people to install this file; an unpinned file is a lie.

    `asyncio_mode = auto` in pytest.ini is what every async test relies on, and
    a floating pytest-asyncio is exactly the thing that reinterprets it.
    """
    text = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    deps = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert deps, "requirements-dev.txt has no requirements"
    for dep in deps:
        assert "==" in dep, f"{dep} is not pinned"
    joined = " ".join(deps)
    for needed in ("pytest", "pytest-asyncio", "playwright"):
        assert needed in joined, f"{needed} missing from requirements-dev.txt"


def test_the_server_requirements_stay_free_of_test_tools() -> None:
    """Pin the separation: whatever is in dev must not leak into the runtime file."""
    runtime = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    for name in ("pytest", "playwright"):
        assert name not in runtime, f"{name} belongs in requirements-dev.txt"


def test_the_packer_marks_both_entrypoints_executable() -> None:
    """The zip pins modes from this set; a missing name ships a dead entrypoint."""
    from tools import make_upload

    assert {"install.sh", "deploy.sh"} <= make_upload.EXECUTABLE


def test_the_packer_explains_itself_without_git(tmp_path: Path) -> None:
    """On a server there is no git; a bare FileNotFoundError would look like a bug.

    The check is written against a PATH with neither git nor a fallback in it,
    because that is the only way to reach the branch from a developer machine.
    """
    empty = tmp_path / "bin"
    empty.mkdir()
    env = dict(os.environ)
    env["PATH"] = str(empty)
    r = subprocess.run(
        [os.sys.executable, str(ROOT / "tools" / "make_upload.py"),
         "--out", str(tmp_path / "out")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=env,
        cwd=str(ROOT),
        stdin=subprocess.DEVNULL,
    )
    assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)
    assert "git" in r.stderr
    assert "Traceback" not in r.stderr
    assert not (tmp_path / "out" / "dlproxy-upload.zip").exists()


def test_the_packed_zip_claims_to_come_from_unix(tmp_path: Path) -> None:
    """`unzip` only reads external_attr when the entry says Unix.

    This was a real defect: the archive carried the right 0755 bits, but every
    ZipInfo defaulted `create_system` from `sys.platform`, so a zip packed on
    Windows said MS-DOS and Ubuntu's unzip ignored the mode — `sudo ./install.sh`
    then failed with "Permission denied". Reading `external_attr` back is not
    enough to catch it; the flag has to be asserted too.
    """
    import zipfile

    from tools import make_upload

    src = tmp_path / "dlproxy"
    (src / "deploy").mkdir(parents=True)
    (src / "README.md").write_text("x\n", encoding="utf-8")
    (src / "install.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    (src / "deploy" / "install.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")

    out = tmp_path / "out.zip"
    make_upload.write_zip(src, out)

    with zipfile.ZipFile(out) as zf:
        for name in ("install.sh", "deploy/install.sh", "README.md"):
            info = zf.getinfo(name)
            assert info.create_system == 3, f"{name} would be unpacked by unzip as MS-DOS"
        assert (zf.getinfo("install.sh").external_attr >> 16) & 0o777 == 0o755
        assert (zf.getinfo("README.md").external_attr >> 16) & 0o777 == 0o644


def test_every_subprocess_in_the_suite_has_a_deadline() -> None:
    """A child that hangs must not hang the suite.

    A full run once sat at 12% for 34 minutes: one `bash deploy/cert-check.sh`
    never returned, and because none of the fifteen `subprocess.run` calls in
    `tests/` passed `timeout=`, nothing could break the wait. The call is cheap
    to add and turns "the suite is stuck, kill it" into a named failure.
    """
    import ast

    offenders: list[str] = []
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute) or func.attr != "run":
                continue
            module = func.value
            if not isinstance(module, ast.Name) or module.id not in ("subprocess", "sp"):
                continue
            keywords = {kw.arg for kw in node.keywords}
            if "timeout" not in keywords:
                offenders.append(f"{path.name}:{node.lineno} has no timeout=")
            # Inheriting the suite's stdin is the other half of the same bug: a
            # child that reads it waits for input that never comes. `input=`
            # counts because it closes the pipe for the child.
            if "stdin" not in keywords and "input" not in keywords:
                offenders.append(f"{path.name}:{node.lineno} inherits stdin")
    assert not offenders, (
        "a child process could hang the suite: " + ", ".join(offenders)
    )
