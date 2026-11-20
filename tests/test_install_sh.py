"""Tests for deploy/install.sh — the interactive front end for deploy.sh.

The wizard's whole value is in the questions it asks and the flags it builds, so
these tests feed it whole scripts of answers on stdin and assert on the command
line it would have handed to deploy.sh.

Three things are stubbed out so a run is deterministic and fast:

* `PROC_NET_DIR` points port_listening at a fake /proc/net table (deploy.sh
  already honours it).
* a fake `ss` on PATH answers the "who owns this port" question. Without it the
  fallback walks every /proc/*/fd on the machine, which takes seconds per call
  and varies by host.
* deploy.sh is replaced by a stub that only records its argv, so a bug in the
  wizard can never install anything on the machine running the tests.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

BASE = Path(__file__).resolve().parent.parent
INSTALL = BASE / "deploy" / "install.sh"
DEPLOY = BASE / "deploy" / "deploy.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="deploy scripts are bash"
)


# ---------------------------------------------------------------------------
# A fake /proc/net the wizard can be pointed at
# ---------------------------------------------------------------------------
# One LISTEN row per port. Layout (whitespace separated):
#   sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
# st == 0A means LISTEN; port_listening looks at fields 2 and 4, port_owner's
# fallback reads field 10, so the rows stay well formed.
def _row(port: int, inode: int, state: str = "0A") -> str:
    return (
        f"  0: 00000000:{port:04X} 00000000:0000 {state} "
        f"00000000:00000000 00:00000000 00000000 0 0 {inode} 1 00000000"
    )


def proc_net(root: Path, listening: list[int]) -> Path:
    d = root / "net"
    d.mkdir(parents=True, exist_ok=True)
    header = (
        "  sl  local_address rem_address   st tx_queue rx_queue "
        "tr tm->when retrnsmt   uid  timeout inode"
    )
    (d / "tcp").write_text(
        header + "\n" + "\n".join(_row(p, 1000 + i) for i, p in enumerate(listening)) + "\n",
        encoding="utf-8",
    )
    (d / "tcp6").write_text(header + "\n", encoding="utf-8")
    return d


# ---------------------------------------------------------------------------
# Fake tools
# ---------------------------------------------------------------------------
# `ss` is asked two questions: "is anything listening on :N" (an argument of the
# form `sport = :N`) and "is anything listening at all". Both are answered from
# FAKE_LISTENING.
#
# FAKE_OWNERS is an optional "port=owner" list so different ports can answer
# differently. That matters because the wizard now decides things from the
# *process name* -- "xray on 443" and "systemd-resolve on 53" must not be
# confused -- and a single blanket owner cannot express that.
#
# FAKE_ADDRS is the same idea for the bind address ("port=addr"), because the
# wizard distinguishes 0.0.0.0:11111 (reachable) from 127.0.0.1:11111 (not).
#
# The wizard prefers `ss` whenever it exists, so without this stub every probe
# would fall through to /proc/net (slow) or, worse, answer "nothing is listening"
# and send the conversation down the wrong branch.
FAKE_SS = r"""#!/usr/bin/env bash
set -u
default="${FAKE_OWNER:-unknown}"
want=""
for a in "$@"; do
  case "$a" in
    *sport*) want="${a##*:}" ;;
  esac
done
owner_for() {
  local p="$1" pair
  for pair in ${FAKE_OWNERS:-}; do
    if [[ "${pair%%=*}" == "$p" ]]; then printf '%s' "${pair#*=}"; return; fi
  done
  printf '%s' "$default"
}
addr_for() {
  local p="$1" pair
  for pair in ${FAKE_ADDRS:-}; do
    if [[ "${pair%%=*}" == "$p" ]]; then printf '%s' "${pair#*=}"; return; fi
  done
  printf '0.0.0.0'
}
emit() { printf 'LISTEN 0 511 %s:%s 0.0.0.0:* users:(("%s",pid=1,fd=3))\n' "$(addr_for "$1")" "$1" "$(owner_for "$1")"; }
for p in ${FAKE_LISTENING:-}; do
  if [[ -z "$want" || "$p" == "$want" ]]; then emit "$p"; fi
done
exit 0
"""

FAKE_SYSTEMCTL = """#!/usr/bin/env bash
set -u
[[ "${1:-}" == "is-active" ]] && exit "${FAKE_SYSTEMCTL_RC:-1}"
exit 0
"""


def fake_bin(
    root: Path,
    *,
    listening: list[int],
    owner: str,
    dlproxy_active: bool,
    owners: dict[int, str] | None = None,
    addrs: dict[int, str] | None = None,
) -> tuple[Path, dict[str, str]]:
    """Create the stubs and the environment that makes them answer."""
    d = root / "bin"
    d.mkdir(parents=True, exist_ok=True)
    (d / "ss").write_text(FAKE_SS, encoding="utf-8")
    (d / "systemctl").write_text(FAKE_SYSTEMCTL, encoding="utf-8")
    return d, {
        "FAKE_LISTENING": " ".join(str(p) for p in listening),
        "FAKE_OWNER": owner,
        "FAKE_OWNERS": " ".join(f"{p}={o}" for p, o in (owners or {}).items()),
        "FAKE_ADDRS": " ".join(f"{p}={a}" for p, a in (addrs or {}).items()),
        "FAKE_SYSTEMCTL_RC": "0" if dlproxy_active else "1",
    }


# ---------------------------------------------------------------------------
# A sandbox copy of deploy/ so `exec bash deploy.sh` never touches the real one
# ---------------------------------------------------------------------------
def sandbox(root: Path) -> Path:
    """Copy install.sh next to a deploy.sh stub that records its argv."""
    d = root / "deploy"
    d.mkdir(parents=True, exist_ok=True)
    shutil.copy2(INSTALL, d / "install.sh")
    (d / "deploy.sh").write_text(
        "#!/usr/bin/env bash\n"
        f'. "{DEPLOY.as_posix()}"\n'
        # install.sh sources this for the helpers with DLPROXY_LIB_ONLY set;
        # only the exec'd copy is allowed to do anything.
        'if [[ -z "${DLPROXY_LIB_ONLY:-}" ]]; then\n'
        '  echo "EXEC: $*"\n'
        "  exit 0\n"
        "fi\n",
        encoding="utf-8",
    )
    return d / "install.sh"


def run(
    tmp_path: Path,
    answers: str,
    *,
    argv: list[str] | None = None,
    listening: list[int] | None = None,
    owner: str = "nginx",
    dlproxy_active: bool = False,
    owners: dict[int, str] | None = None,
    addrs: dict[int, str] | None = None,
    os_release: str | None = None,
    arch: str = "aarch64",
    cores: str = "2",
) -> subprocess.CompletedProcess:
    """Drive the wizard inside a sandbox, so it can never run the real deploy.sh."""
    install = sandbox(tmp_path)
    table = list(listening or [])
    bin_dir, extra = fake_bin(
        tmp_path,
        listening=table,
        owner=owner,
        dlproxy_active=dlproxy_active,
        owners=owners,
        addrs=addrs,
    )

    env = dict(os.environ)
    env.update(extra)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["PROC_NET_DIR"] = str(proc_net(tmp_path, table))
    env.pop("DLPROXY_LIB_ONLY", None)
    # The banner prints PRETTY_NAME from /etc/os-release; on the machine running
    # the tests that is the developer's OS, so pin it here.
    release = tmp_path / "os-release"
    release.write_text(f'PRETTY_NAME="{os_release or "Ubuntu 24.04.5 LTS"}"\n',
                       encoding="utf-8", newline="\n")
    env["OS_RELEASE_FILE"] = str(release)
    # Same reason: the banner reports the machine it runs on. These two let a
    # capture describe the host the documentation talks about.
    env["HOST_ARCH"] = arch
    env["HOST_CORES"] = cores
    return subprocess.run(
        ["bash", str(install), *(argv or [])],
        input=answers,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=str(tmp_path),
        timeout=120,
    )


def exec_line(out: str) -> str:
    return next(l for l in out.splitlines() if l.startswith("EXEC:"))


# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------
def test_help_lists_the_options_and_exits(tmp_path):
    r = run(tmp_path, "", argv=["--help"])
    assert r.returncode == 0, r.stderr
    for flag in ("--yes", "--dry-run", "install.sh", "sudo"):
        assert flag in r.stdout
    # --help must not start a conversation: no banner, no questions.
    assert "dlproxy 安装向导" not in r.stdout
    assert "?  " not in r.stdout


def test_unknown_option_is_rejected(tmp_path):
    r = run(tmp_path, "", argv=["--nope"])
    assert r.returncode != 0
    assert "未知参数" in r.stderr


# ---------------------------------------------------------------------------
# 443 free — the plain path
# ---------------------------------------------------------------------------
def test_free_443_builds_a_plain_command(tmp_path):
    r = run(tmp_path, "y\nn\nn\n", argv=["--dry-run"])
    assert r.returncode == 0, r.stderr
    assert "443 空闲" in r.stdout
    assert "--share-443" not in r.stdout
    assert "--stage all" in r.stdout
    assert "仅预览" in r.stdout


def test_dry_run_really_does_not_exec(tmp_path):
    r = run(tmp_path, "y\nn\nn\n", argv=["--dry-run"])
    assert "EXEC:" not in r.stdout


# ---------------------------------------------------------------------------
# 443 busy — the whole point of the wizard
# ---------------------------------------------------------------------------
def test_shared_443_asks_for_the_service_port_and_the_internal_ports(tmp_path):
    r = run(
        tmp_path,
        # share? y · service port · dlproxy host? n · cert? y · partial? n · start? y
        "y\n10443\nn\ny\nn\nn\ny\n",
        listening=[22, 443, 10443],
        owner="xray",
    )
    assert r.returncode == 0, r.stderr
    assert "443 当前被 xray 占用" in r.stdout
    line = exec_line(r.stdout)
    assert "--share-443" in line
    assert "--tls-service-port 10443" in line
    assert "--tls-port 8443" in line
    assert "--strip-port 8441" in line
    assert "--stage all" in line
    assert "--skip-cert" not in line


def test_declining_shared_443_changes_nothing(tmp_path):
    r = run(tmp_path, "n\n", listening=[443], owner="xray")
    assert r.returncode != 0
    assert "已取消" in r.stderr
    assert "EXEC:" not in r.stdout


def test_a_service_that_has_not_moved_yet_stops_before_installing(tmp_path):
    """Choosing a port the service is not on must not reach deploy.sh.

    deploy.sh refuses in preflight ("端口 10443 当前无监听"), so handing it
    the command produces a failure the operator has to decode. The wizard knows
    the same fact already, so it says what to do and exits clean.
    """
    r = run(tmp_path, "y\n10443\nn\ny\nn\nn\ny\n", listening=[443], owner="xray")
    assert r.returncode == 0, r.stderr
    assert "10443 当前空闲" in r.stdout
    assert "现在安装会在预检阶段中止" in r.stdout
    assert "将原服务的监听端口改为 10443" in r.stdout
    assert "EXEC:" not in r.stdout
    assert "未做任何改动" in r.stdout


def test_a_port_held_by_something_else_is_refused(tmp_path):
    """Anything that is not a known TLS service could never bind it."""
    r = run(
        tmp_path,
        # share y · 10443 holds a web server → re-ask · 20000 free
        # · host n · cert y · partial n · start y
        "y\n10443\n20000\nn\ny\nn\nn\ny\n",
        listening=[443, 10443, 20000],
        owners={10443: "nginx"},
        owner="xray",
    )
    assert r.returncode == 0, r.stderr
    assert "已被 nginx 占用" in r.stdout
    assert "--tls-service-port 20000" in exec_line(r.stdout)


def test_a_port_held_by_the_service_itself_is_accepted(tmp_path):
    """xray already on 10443 is the *good* case, not a conflict."""
    r = run(
        tmp_path,
        "y\n10443\nn\ny\nn\nn\ny\n",
        listening=[443, 10443],
        owners={443: "xray", 10443: "xray"},
        owner="xray",
    )
    assert r.returncode == 0, r.stderr
    assert "已被 xray 占用，原服务无法绑定" not in r.stdout
    assert "10443 已处于监听状态" in r.stdout
    assert "--tls-service-port 10443" in exec_line(r.stdout)


def test_a_privileged_service_port_is_refused(tmp_path):
    r = run(
        tmp_path,
        "y\n53\n20000\nn\ny\nn\nn\ny\n",
        listening=[443, 20000],
        owner="xray",
    )
    assert r.returncode == 0, r.stderr
    assert "1024 以下为特权端口" in r.stdout
    assert "--tls-service-port 20000" in exec_line(r.stdout)


def test_occupied_internal_ports_are_skipped(tmp_path):
    r = run(
        tmp_path,
        "y\n10443\nn\ny\nn\nn\ny\n",
        listening=[443, 10443, 8443, 8441],
        owner="xray",
    )
    assert r.returncode == 0, r.stderr
    line = exec_line(r.stdout)
    assert "--tls-port 8444" in line
    assert "--strip-port 8442" in line


def test_other_listeners_are_named_as_system_ports_not_the_service(tmp_path):
    """The service is on 443, i.e. exactly the port that is excluded.

    So the remaining listeners are system services (systemd-resolved on 53,
    rpcbind on 111). Presenting them as "your service is probably in here" and then
    defaulting to the lowest one suggested moving xray onto DNS.
    """
    r = run(
        tmp_path,
        "y\n20000\nn\ny\nn\ny\n",
        listening=[22, 53, 111, 443],
        owners={53: "systemd-resolve", 111: "rpcbind", 443: "xray"},
        owner="unknown",
    )
    assert r.returncode == 0, r.stderr
    assert "与本次选择无关" in r.stdout
    assert "节点很可能就在其中" not in r.stdout
    # 53 is a system resolver, not our service -- it must not become the default,
    # and since 20000 is not listening yet the wizard stops instead of exec'ing.
    assert "[53]" not in r.stdout
    assert "20000 当前空闲" in r.stdout
    assert "EXEC:" not in r.stdout


def test_dlproxy_host_is_validated_and_forwarded(tmp_path):
    r = run(
        tmp_path,
        # share y · port · host y · bad value · good value · cert y · partial n · start y
        "y\n10443\ny\nnot_a_domain\ndl.example.com\ny\nn\nn\ny\n",
        listening=[443, 10443],
        owner="xray",
    )
    assert r.returncode == 0, r.stderr
    assert "不是有效域名" in r.stdout
    assert "--dlproxy-host dl.example.com" in exec_line(r.stdout)


def test_the_resulting_listeners_are_spelled_out(tmp_path):
    r = run(tmp_path, "y\n10443\nn\ny\nn\nn\ny\n", listening=[443, 10443], owner="xray")
    # The port column is fixed with printf %-8s, so 443 and 10443 start their
    # description at the same column. The hand counted spaces used to leave
    # the five digit port one column to the right of the three digit one.
    lines = [ln for ln in r.stdout.splitlines() if "nginx stream" in ln or "dlproxy（回环" in ln]
    starts = {ln.index(txt) for ln in lines for txt in ("nginx stream", "dlproxy（回环") if txt in ln}
    assert starts == {14}, lines            # 4 indent + %-8s + 2 spaces + text
    assert "443" in r.stdout and "10443" in r.stdout


def test_the_suggested_port_is_the_one_the_service_already_listens_on(tmp_path):
    """When a proxy-like process already has a port, that IS the answer.

    The real port is by definition busy, so "first free port from 10443"
    can never find it -- and suggesting a free port means telling the operator
    to move a service that is already exactly where it should be.
    """
    r = run(
        tmp_path,
        "",
        argv=["--dry-run", "--yes"],
        listening=[443, 10443],
        owner="xray",
    )
    assert r.returncode == 0, r.stderr
    assert "[10443]" in r.stdout
    assert "--tls-service-port 10443" in r.stdout


def test_without_a_moved_service_the_default_is_the_first_free_port(tmp_path):
    """Nothing proxy-like outside 443, so fall back to the first free port."""
    r = run(
        tmp_path,
        "",
        argv=["--dry-run", "--yes"],
        listening=[443, 10443, 10444],
        owners={10443: "nginx", 10444: "nginx"},
        owner="xray",
    )
    assert r.returncode == 0, r.stderr
    assert "[10445]" in r.stdout


def test_an_already_moved_service_is_detected_even_with_443_free(tmp_path):
    """443 free plus a TLS service on 10443 -- the state right after moving it.

    Installing in exclusive mode here would take 443 for dlproxy and quietly cut
    the service off, so the wizard offers to keep it reachable instead.
    """
    r = run(
        tmp_path,
        # keep the service reachable? y · service port (suggested) · host? n ·
        # cert? y · partial? n · start? y
        "y\n10443\nn\ny\nn\nn\ny\n",
        listening=[22, 10443],
        owners={10443: "xray"},
        owner="unknown",
    )
    assert r.returncode == 0, r.stderr
    assert "443 空闲" not in r.stdout
    assert "原服务已完成迁移" in r.stdout
    assert "原服务当前直接监听 10443" in r.stdout
    assert "--share-443" in exec_line(r.stdout)
    assert "--tls-service-port 10443" in exec_line(r.stdout)


def test_declining_the_share_here_installs_exclusive_and_says_so(tmp_path):
    """Saying no must not imply the service becomes unreachable.

    After the move the clients connect straight to its own port, so an
    exclusive install only means 443 belongs to dlproxy -- it keeps
    serving where it already is.
    """
    r = run(
        tmp_path,
        "n\ny\nn\nn\ny\n",
        listening=[10443],
        owners={10443: "xray"},
        owner="unknown",
    )
    assert r.returncode == 0, r.stderr
    assert "原服务继续仅在 10443 上服务" in r.stdout
    assert "不再对外可达" not in r.stdout
    line = exec_line(r.stdout)
    assert "--share-443" not in line
    # --tls-service-port means nothing without share-443; passing it would suggest
    # the service is still part of the routing.
    assert "--tls-service-port" not in line


def test_the_port_actually_in_use_is_offered_as_the_default(tmp_path):
    """The suggested port is the service's real port, not a blind 10443."""
    r = run(
        tmp_path,
        "y\n\nn\ny\nn\nn\ny\n",
        listening=[10443],
        owners={10443: "xray"},
        owner="unknown",
    )
    assert r.returncode == 0, r.stderr
    assert "[10443]" in r.stdout
    assert "--tls-service-port 10443" in exec_line(r.stdout)


def test_reinstall_on_a_working_host_skips_the_443_question(tmp_path):
    """443 held by our own nginx plus a live dlproxy unit is a reinstall."""
    r = run(
        tmp_path,
        "y\nn\nn\n",
        argv=["--dry-run"],
        listening=[80, 443, 8080],
        owner="nginx",
        dlproxy_active=True,
    )
    assert r.returncode == 0, r.stderr
    assert "按重装处理" in r.stdout
    assert "是否与已有的 TLS 服务共用" not in r.stdout


def test_a_foreign_owner_on_443_is_still_treated_as_a_clash(tmp_path):
    r = run(tmp_path, "n\n", listening=[443], owner="xray", dlproxy_active=True)
    assert r.returncode != 0
    assert "443 当前被 xray 占用" in r.stdout


# ---------------------------------------------------------------------------
# Certificate and stage questions
# ---------------------------------------------------------------------------
def test_skipping_the_certificate_adds_the_flag(tmp_path):
    r = run(tmp_path, "n\nn\ny\n")
    assert r.returncode == 0, r.stderr
    assert "--skip-cert" in exec_line(r.stdout)


def test_a_single_stage_can_be_chosen(tmp_path):
    r = run(tmp_path, "y\nn\ny\ncert\ny\n")
    assert r.returncode == 0, r.stderr
    assert "--stage cert" in exec_line(r.stdout)


def test_unknown_stage_is_asked_again(tmp_path):
    r = run(tmp_path, "y\nn\ny\nbogus\nfinal\ny\n")
    assert r.returncode == 0, r.stderr
    assert "无此阶段" in r.stdout
    assert "--stage final" in exec_line(r.stdout)


def test_backing_out_at_the_confirmation_installs_nothing(tmp_path):
    r = run(tmp_path, "y\nn\nn\nn\n")
    assert r.returncode == 0, r.stderr
    assert "已取消" in r.stdout
    assert "EXEC:" not in r.stdout


# ---------------------------------------------------------------------------
# Question primitives
# ---------------------------------------------------------------------------
def test_yes_no_rejects_garbage_then_accepts_a_valid_answer(tmp_path):
    r = run(tmp_path, "maybe\nn\nn\ny\n")
    assert r.returncode == 0, r.stderr
    assert "请输入 y 或 n" in r.stdout
    assert "--skip-cert" in exec_line(r.stdout)


def test_eof_cancels_instead_of_accepting_defaults(tmp_path):
    r = run(tmp_path, "")  # stdin closed immediately
    assert r.returncode != 0
    assert "输入已结束" in r.stderr
    assert "EXEC:" not in r.stdout


def test_port_must_be_a_number_in_range(tmp_path):
    r = run(
        tmp_path,
        "y\nabc\n70000\n10443\nn\ny\nn\nn\ny\n",
        listening=[443, 10443],
        owner="xray",
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.count("端口必须是 1 至 65535 之间的整数") >= 2
    assert "--tls-service-port 10443" in exec_line(r.stdout)


def test_empty_answer_takes_the_default(tmp_path):
    # cert? [empty → Y] · partial? n · start? y
    r = run(tmp_path, "\nn\nn\ny\n")
    assert r.returncode == 0, r.stderr
    assert "--skip-cert" not in exec_line(r.stdout)


def test_yes_mode_takes_every_default(tmp_path):
    # --yes with 443 held by xray and the service already on 10443: share=yes,
    # service port=10443 (its own port), host=no, cert=yes, partial=no.
    r = run(tmp_path, "", argv=["--dry-run", "--yes"], listening=[443, 10443], owner="xray")
    assert r.returncode == 0, r.stderr
    assert "（--yes）" in r.stdout
    assert "--share-443" in r.stdout
    assert "--tls-service-port 10443" in r.stdout


# ---------------------------------------------------------------------------
# The helpers, called directly
# ---------------------------------------------------------------------------
def _bash(
    tmp_path: Path,
    script: str,
    *,
    listening: list[int],
    addrs: dict[int, str] | None = None,
) -> subprocess.CompletedProcess:
    """Source install.sh (its main() is behind a BASH_SOURCE guard) and probe."""
    bin_dir, extra = fake_bin(
        tmp_path,
        listening=listening,
        owner="nginx",
        dlproxy_active=False,
        addrs=addrs,
    )
    env = dict(os.environ)
    env.update(extra)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["PROC_NET_DIR"] = str(proc_net(tmp_path, listening))
    env.pop("DLPROXY_LIB_ONLY", None)
    prelude = (
        "set +e\n"
        f'source "{INSTALL.as_posix()}"\n'
        "set +e\n"
    )
    return subprocess.run(
        ["bash", "-c", prelude + script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=str(tmp_path),
        timeout=120,
        stdin=subprocess.DEVNULL,
    )


def test_free_port_from_skips_taken_ports(tmp_path):
    r = _bash(tmp_path, "free_port_from 8441; echo", listening=[8441, 8442, 8443])
    assert r.stdout.strip() == "8444", r.stdout


def test_describe_port_names_the_owner_when_it_can(tmp_path):
    r = _bash(tmp_path, "describe_port 9999", listening=[9999])
    assert "占用" in r.stdout


def test_describe_port_says_free_when_nothing_listens(tmp_path):
    r = _bash(tmp_path, "describe_port 9999", listening=[])
    assert "空闲" in r.stdout


def test_listening_ports_lists_the_fixture_table(tmp_path):
    r = _bash(tmp_path, "listening_ports", listening=[80, 443, 10443])
    assert r.stdout.split() == ["80", "443", "10443"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))


def test_port_bind_scope_spots_a_loopback_bind(tmp_path):
    """The real host had 127.0.0.1:11111 — reachable from the box, not outside."""
    r = _bash(
        tmp_path, "port_bind_scope 11111", listening=[11111], addrs={11111: "127.0.0.1"}
    )
    assert r.stdout.strip() == "loopback", r.stdout


def test_port_bind_scope_spots_a_wildcard_bind(tmp_path):
    r = _bash(tmp_path, "port_bind_scope 11111", listening=[11111])
    assert r.stdout.strip() == "wildcard", r.stdout


def test_port_bind_scope_is_empty_when_nothing_listens(tmp_path):
    r = _bash(tmp_path, "port_bind_scope 11111", listening=[])
    assert r.stdout.strip() == "", r.stdout


def test_listening_with_addrs_keeps_ipv6_literals_whole(tmp_path):
    """`ss` prints [::]:443; splitting on ":" twice would mangle it."""
    r = _bash(
        tmp_path, "listening_with_addrs", listening=[443], addrs={443: "[::]"}
    )
    assert r.stdout.split() == ["443", "[::]"], r.stdout


def test_a_loopback_bound_service_does_not_get_the_reassuring_line(tmp_path):
    """The wizard used to promise the link was fine; on a loopback bind it is not."""
    r = run(
        tmp_path,
        "n\ny\nn\nn\ny\n",
        argv=["--dry-run"],
        listening=[11111],
        owners={11111: "xray-linux-arm64"},
        addrs={11111: "127.0.0.1"},
    )
    assert r.returncode == 0, r.stderr
    assert "两种方案都不影响现有的 域名:11111 链接" not in r.stdout, r.stdout
    assert "仅绑定在 127.0.0.1，外网无法访问" in r.stdout, r.stdout


def test_a_wildcard_bound_service_still_gets_the_reassuring_line(tmp_path):
    r = run(
        tmp_path,
        "n\ny\nn\nn\ny\n",
        argv=["--dry-run"],
        listening=[11111],
        owners={11111: "xray-linux-arm64"},
    )
    assert r.returncode == 0, r.stderr
    assert "两种方案都不影响现有的 域名:11111 链接" in r.stdout, r.stdout
    assert "仅绑定在 127.0.0.1" not in r.stdout, r.stdout

# ---------------------------------------------------------------------------
# The wizard must not let the operator answer eight questions and only then
# discover that :80 is held by something deploy.sh cannot adopt.
# ---------------------------------------------------------------------------


def test_the_wizard_says_nginx_on_80_will_be_adopted(tmp_path):
    r = run(
        tmp_path, "", argv=["--dry-run", "--yes"], listening=[80], owner="nginx"
    )
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "80 端口上的 nginx 将被接管并 reload" in r.stdout
    assert "拒绝继续" not in r.stdout


def test_the_wizard_warns_before_asking_about_a_foreign_holder_on_80(tmp_path):
    r = run(
        tmp_path, "", argv=["--dry-run", "--yes"], listening=[80], owner="python3"
    )
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "80 端口已被 python3 占用" in r.stdout
    assert "将在预检阶段中止" in r.stdout
    # it warns, it does not abort: deploy.sh is the one that decides
    assert "仅预览" in r.stdout


# ---------------------------------------------------------------------------
# Domain certificate
# ---------------------------------------------------------------------------
def test_a_domain_certificate_is_forwarded_and_doubles_as_the_dlproxy_host(tmp_path):
    """Answering "use a domain" must reach deploy.sh as --domain.

    The same name also has to end up in --dlproxy-host: in share-443 mode any
    SNI the map does not name goes to the service, so a certificate issued for a
    name that is not pulled back would never be served by dlproxy.
    """
    r = run(
        tmp_path,
        "y\n10443\nn\ny\ny\ndl.example.com\nn\ny\n",
        listening=[443, 10443],
        owner="xray",
    )
    assert r.returncode == 0, r.stderr
    line = exec_line(r.stdout)
    assert "--domain dl.example.com" in line, line
    assert "--dlproxy-host dl.example.com" in line, line


def test_a_domain_is_lowercased_before_it_reaches_deploy_sh(tmp_path):
    r = run(
        tmp_path,
        "y\n10443\nn\ny\ny\nDL.Example.COM\nn\ny\n",
        listening=[443, 10443],
        owner="xray",
    )
    assert r.returncode == 0, r.stderr
    line = exec_line(r.stdout)
    assert "--domain dl.example.com" in line, line
    assert "DL.Example.COM" not in line, line


def test_a_bad_domain_is_asked_again(tmp_path):
    r = run(
        tmp_path,
        "y\n10443\nn\ny\ny\nnot a domain\ndl.example.com\nn\ny\n",
        listening=[443, 10443],
        owner="xray",
    )
    assert r.returncode == 0, r.stderr
    assert "请输入完整域名" in r.stdout
    assert "--domain dl.example.com" in exec_line(r.stdout)


def test_declining_the_domain_keeps_the_ip_certificate(tmp_path):
    r = run(
        tmp_path,
        "y\n10443\nn\ny\nn\nn\ny\n",
        listening=[443, 10443],
        owner="xray",
    )
    assert r.returncode == 0, r.stderr
    line = exec_line(r.stdout)
    assert "--domain" not in line, line
    assert "--skip-cert" not in line, line


def test_skipping_the_certificate_never_asks_about_a_domain(tmp_path):
    r = run(
        tmp_path,
        "y\n10443\nn\nn\nn\ny\n",
        listening=[443, 10443],
        owner="xray",
    )
    assert r.returncode == 0, r.stderr
    assert "是否用域名申请证书" not in r.stdout
    assert "--skip-cert" in exec_line(r.stdout)


# ---------------------------------------------------------------------------
# Terminal presentation
#
# The wizard and deploy.sh run for minutes; a question that looks exactly like a
# progress line gets lost in the scroll-back. These pin the two things that keep
# them apart: a four column `?  ` prefix on every question (the same 4 columns
# `==> ` occupies), and `━` rules between sections instead of 62 `=` characters.
# ---------------------------------------------------------------------------


def test_every_question_carries_the_four_column_prompt_prefix(tmp_path):
    r = run(tmp_path, "n\nn\nn\nn\n", listening=[], owner="")
    asked = [ln for ln in r.stdout.splitlines() if "[Y/n]" in ln or "[y/N]" in ln]
    assert asked, r.stdout
    for line in asked:
        assert line.startswith("?  "), line
        # '?  ' and '==> ' are both four columns, so questions and progress
        # reports share a left margin without looking alike.
        assert line[3] != " ", line


def test_an_automatic_answer_is_logged_with_the_same_prefix(tmp_path):
    """`grep '^?'` has to find every question, answered or not."""
    r = run(tmp_path, "", argv=["--yes"], listening=[], owner="")
    answered = [ln for ln in r.stdout.splitlines() if "（--yes）" in ln]
    assert answered, r.stdout
    for line in answered:
        assert line.startswith("?  "), line


def test_the_two_banners_use_the_same_heavy_rule(tmp_path):
    r = run(tmp_path, "n\nn\nn\nn\n", listening=[], owner="")
    rules = [ln for ln in r.stdout.splitlines() if ln.startswith("━")]
    assert len(rules) == 2, r.stdout
    assert len(set(rules)) == 1


def test_no_line_of_equal_signs_survives(tmp_path):
    """62 `=` was the old banner; two different rules in one script look wrong."""
    r = run(tmp_path, "n\nn\nn\nn\n", listening=[], owner="")
    assert "=====" not in r.stdout, r.stdout


def test_a_section_header_precedes_the_questions_it_belongs_to(tmp_path):
    r = run(tmp_path, "n\nn\nn\nn\n", listening=[], owner="")
    lines = r.stdout.splitlines()
    heads = [ln.strip() for ln in lines if ln.strip().startswith("── ")]
    assert any("443" in h for h in heads), heads
    assert any("证书" in h for h in heads), heads
    # The certificate section header must come before the certificate question.
    head_at = next(i for i, ln in enumerate(lines) if ln.strip().startswith("── 证书"))
    ask_at = next(i for i, ln in enumerate(lines) if "现在申请正式证书" in ln)
    assert head_at < ask_at, (head_at, ask_at)


# ---------------------------------------------------------------------------
# The transcript in docs/deployment.md is a capture, not a sketch
# ---------------------------------------------------------------------------
DOC = BASE / "docs" / "deployment.md"


def documented_transcript() -> list[str]:
    """The wizard block in the deployment guide, without the fence."""
    text = DOC.read_text(encoding="utf-8")
    start = text.index("```\n━") + 4
    end = text.index("```", start)
    lines = text[start:end].splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def test_the_documented_transcript_is_what_the_wizard_prints(tmp_path):
    """A hand-written sample drifts the moment a prompt is reworded.

    This compares the guide against a real run of the wizard, so a reworded
    question either updates the document or fails here. Only the absolute path
    of deploy.sh differs between the two, and that is masked on both sides.
    """
    r = run(
        tmp_path,
        # share? y · service port · domain? n · cert? y · domain cert? n
        # · partial? n · start? n (--dry-run never asks the last one)
        "y\n10443\nn\ny\nn\nn\n",
        argv=["--dry-run"],
        listening=[443, 10443, 8080],
        owners={443: "xray", 10443: "xray", 8080: "python"},
        addrs={10443: "0.0.0.0"},
    )
    assert r.returncode == 0, r.stderr

    def mask(lines):
        out = []
        for line in lines:
            if "sudo bash " in line:
                line = "  sudo bash <DIR>/deploy.sh" + line.split("deploy.sh", 1)[1]
            out.append(line.rstrip())
        return out

    printed = r.stdout.splitlines()
    while printed and not printed[0].strip():
        printed.pop(0)
    while printed and not printed[-1].strip():
        printed.pop()
    assert mask(printed) == mask(documented_transcript())


def test_the_documented_transcript_has_no_machine_specific_leftovers():
    """No developer paths, no placeholder host, nothing this machine invented."""
    block = "\n".join(documented_transcript())
    # `<IP>` and `<服务器IP>` are the wizard's own wording, not a stand-in for a
    # value the capture should have filled in; a drive letter or home directory
    # is what a real leak looks like.
    for leaked in ("/d/.DSH", "D:\\", "/home/", "C:/", "\\_cap", "_pkgcheck"):
        assert leaked not in block, f"{leaked!r} leaked into the guide"


def test_the_documented_stage_headers_match_the_real_ones():
    """The guide shows what 阶段 N/6 looks like; it must be the real shape."""
    text = DOC.read_text(encoding="utf-8")
    assert "阶段 1/6  环境预检 ━" in text, text[text.index("阶段 1/6") - 200:][:400]


# ---------------------------------------------------------------------------
# 443 held by the box's own nginx
#
# Reported from a real host: `./install.sh` on a machine where nginx served both
# :80 and :443 answered "443 已被占用（nginx），且该进程不是 TLS 代理" and then
# defaulted to "n" — cancelling the install. nginx is a TLS server, and
# deploy.sh had already decided to reload it, so the two halves of the installer
# disagreed about the same fact. The branch below is the one that has to answer
# differently from "some unknown process is squatting on 443".
# ---------------------------------------------------------------------------


def test_443_held_by_nginx_is_taken_over_not_refused(tmp_path: Path) -> None:
    r = run(
        tmp_path,
        "y\nn\nn\nn\nn\n",
        listening=[80, 443],
        owners={80: "nginx", 443: "nginx"},
        dlproxy_active=False,
    )
    assert "443 由 nginx 监听" in r.stdout, r.stdout
    assert "接管该实例并 reload" in r.stdout
    assert "不是 TLS 代理" not in r.stdout
    # And it must not stop for an answer: the wizard has to walk on to the
    # certificate questions.
    assert "是否现在申请正式证书" in r.stdout, r.stdout


def test_443_held_by_nginx_does_not_ask_about_share443(tmp_path: Path) -> None:
    """share-443 would take :443 away from that very nginx — the wrong tool."""
    r = run(
        tmp_path,
        "y\nn\nn\nn\nn\n",
        listening=[80, 443],
        owners={80: "nginx", 443: "nginx"},
        dlproxy_active=False,
    )
    assert "共用 443" not in r.stdout, r.stdout
    assert "--share-443" not in r.stdout, r.stdout


def test_443_held_by_something_else_still_warns(tmp_path: Path) -> None:
    r = run(
        tmp_path,
        "y\nn\nn\nn\nn\n",
        listening=[80, 443],
        owners={80: "nginx", 443: "some-random-daemon"},
    )
    assert "无法接管" in r.stdout, r.stdout
    assert "接管该实例并 reload" not in r.stdout


def test_a_reinstall_with_dlproxy_running_skips_the_443_question(tmp_path: Path) -> None:
    """The first branch must still win: nginx on 443 plus a live dlproxy."""
    r = run(
        tmp_path,
        "n\nn\nn\nn\n",
        listening=[80, 443],
        owners={80: "nginx", 443: "nginx"},
        dlproxy_active=True,
    )
    assert "按重装处理" in r.stdout, r.stdout
    assert "接管该实例并 reload" not in r.stdout
