"""Tests for the two functions in deploy/deploy.sh that decide whether the
installer runs at all.

Both were written because the first real deployment died in preflight with
"本机 nginx 未编译 stream 模块" on a host that had no nginx installed yet.
Two separate bugs produced that one message:

  * preflight ran before `apt-get install nginx`
  * the check asked `nginx -V | grep --with-stream`, which cannot tell
    "not installed" from "installed without stream", and on Ubuntu the module
    is dynamic anyway, so a perfectly working nginx prints
    `--with-stream=dynamic` and would still be rejected by a naive grep.

so the function now probes nginx itself. These tests pin the probe's verdict
on both outcomes, and pin the /proc/net/tcp parser that stands in for `ss` on
minimal images.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import subprocess as sp
import sys
import tempfile
import time
from pathlib import Path

import pytest

DEPLOY_SH = Path(__file__).resolve().parent.parent / "deploy" / "deploy.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="bash is required to source deploy.sh"
)


@pytest.fixture(scope="session")
def nginx_binary() -> str | None:
    """A real nginx if one can be found, else None (the caller skips).

    Resolution order mirrors tools/nginxbin.py: explicit env var, then PATH,
    then the scratch build the e2e tests use on Windows.
    """
    explicit = os.environ.get("DLPROXY_NGINX_BIN")
    if explicit and Path(explicit).is_file():
        return explicit
    found = shutil.which("nginx")
    if found and Path(found).is_file():
        return found
    scratch = DEPLOY_SH.parent.parent.parent / "_scratch" / "nginx-1.28.3" / "nginx.exe"
    if scratch.is_file():
        return str(scratch)
    return None


def bash(script: str, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    full_env.pop("PROC_NET_DIR", None)
    if env:
        full_env.update(env)
    # deploy.sh ends with `set -euo pipefail`; re-disable errexit AFTER sourcing,
    # otherwise a function returning 1 or 2 kills the shell before the caller can
    # print the code it wanted to assert on.
    return subprocess.run(
        ["bash", "-c", f'set +e\nsource "{DEPLOY_SH.as_posix()}"\nset +e\n{script}'],
        capture_output=True,
        text=True,
        # deploy.sh prints Chinese; Windows defaults to GBK for child pipes and
        # blows up mid-read, leaving stdout None.
        encoding="utf-8",
        errors="replace",
        env=full_env,
        timeout=60,
        stdin=subprocess.DEVNULL,
    )


# /proc/net/tcp fixture. Field 2 is HEXIP:HEXPORT, field 4 is the state.
# 1F90 = 8080, 2328 = 9000, 0050 = 80, 2710 = 10000.
PROC_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1
   1: 0100007F:2328 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1
   2: 00000000:0050 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 12347 1
"""

# 32 hex digits then :port — the v6 rows are longer, which is what broke the
# first, offset-based parser.
PROC_TCP6 = """\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:2329 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1
"""


@pytest.fixture
def proc_net(tmp_path: Path) -> Path:
    d = tmp_path / "net"
    d.mkdir()
    (d / "tcp").write_text(PROC_TCP)
    (d / "tcp6").write_text(PROC_TCP6)
    return d


def test_proc_net_sees_an_ipv4_listener(proc_net: Path) -> None:
    r = bash("port_listening 8080 && echo yes || echo no", env={"PROC_NET_DIR": str(proc_net)})
    assert r.stdout.strip() == "yes", r.stderr


def test_proc_net_sees_an_ipv6_listener(proc_net: Path) -> None:
    r = bash("port_listening 9001 && echo yes || echo no", env={"PROC_NET_DIR": str(proc_net)})
    assert r.stdout.strip() == "yes", r.stderr


def test_proc_net_ignores_non_listen_states(proc_net: Path) -> None:
    """Port 80 is present but its state is 01 (ESTABLISHED), not 0A."""
    r = bash("port_listening 80 && echo yes || echo no", env={"PROC_NET_DIR": str(proc_net)})
    assert r.stdout.strip() == "no", r.stderr


def test_proc_net_ignores_absent_ports(proc_net: Path) -> None:
    r = bash("port_listening 1234 && echo yes || echo no", env={"PROC_NET_DIR": str(proc_net)})
    assert r.stdout.strip() == "no", r.stderr


def test_proc_net_does_not_match_a_prefix_of_a_longer_port(proc_net: Path) -> None:
    """2710 (10000) must not be found just because 1F90 (8080) is present."""
    r = bash("port_listening 10000 && echo yes || echo no", env={"PROC_NET_DIR": str(proc_net)})
    assert r.stdout.strip() == "no", r.stderr


def test_missing_proc_files_are_not_an_error(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    r = bash("port_listening 8080 && echo yes || echo no", env={"PROC_NET_DIR": str(empty)})
    assert r.stdout.strip() == "no"
    assert r.returncode == 0


def test_nginx_probe_reports_missing_nginx(tmp_path: Path) -> None:
    """rc 2 means 'no nginx here' — distinct from 'nginx cannot do stream'."""
    empty = tmp_path / "emptybin"
    empty.mkdir()
    r = bash("nginx_stream_ready; echo rc=$?", env={"PATH": f"{empty}:/usr/bin:/bin"})
    assert "rc=2" in r.stdout, (r.stdout, r.stderr)


def test_nginx_probe_accepts_a_working_nginx(nginx_binary: str | None) -> None:
    if nginx_binary is None:
        pytest.skip("no nginx binary available")
    r = bash("nginx_stream_ready; echo rc=$?", env={"PATH": f"{Path(nginx_binary).parent}:{os.environ['PATH']}"})
    assert "rc=0" in r.stdout, (r.stdout, r.stderr)


def test_nginx_probe_rejects_nginx_without_stream(nginx_binary: str | None, tmp_path: Path) -> None:
    """A fake nginx that rejects stream{} must yield rc=1, not a pass.

    This is the reverse check: without it, a probe that always returns 0 would
    look green and share-443 would fail later with a bare nginx -t error.
    """
    fake = _fake_nginx(tmp_path, supports_stream=False)
    r = bash("nginx_stream_ready; echo rc=$?", env={"PATH": f"{fake}:{os.environ['PATH']}"})
    assert "rc=1" in r.stdout, (r.stdout, r.stderr)
    assert "unknown directive" in r.stderr


def _fake_nginx(tmp_path: Path, *, supports_stream: bool) -> Path:
    """A stand-in for nginx that accepts or rejects stream{} on demand."""
    fake = tmp_path / "bin"
    fake.mkdir(exist_ok=True)
    script = fake / "nginx"
    if supports_stream:
        body = "exit 0\n"
    else:
        body = (
            'if grep -q "stream {" "$3" 2>/dev/null; then\n'
            '  echo \'nginx: [emerg] unknown directive "stream" in probe.conf:5\' >&2\n'
            "  exit 1\n"
            "fi\n"
            "exit 0\n"
        )
    script.write_text("#!/usr/bin/env bash\n" + body)
    script.chmod(0o755)
    return fake


# ---------------------------------------------------------------------------
# share443_preflight — the gate that produced the user's error message.
#
# Reported symptom (Ubuntu 24.04 arm64, fresh host):
#   [x] 本机 nginx 未编译 stream 模块，无法共用 443。
#   ...请安装 nginx-full 或官方 nginx 包后重试。
# on a machine that had no nginx at all yet, because preflight ran before
# stage_deps and read `nginx -V` (which fails when the binary is absent).
# ---------------------------------------------------------------------------


def _preflight_env(fake_bin: Path | None, proc_net: Path) -> dict[str, str]:
    if fake_bin is None:
        # A PATH with the usual tools but no nginx anywhere. The empty bin dir
        # has to be built without splitting the string on ":" — on Windows the
        # first component is "D:\...", so `${path%:*}` style parsing yields a
        # bare "D" and mkdir creates a stray D/ directory in the repo root.
        empty_bin = proc_net.parent / "no-nginx-bin"
        empty_bin.mkdir(parents=True, exist_ok=True)
        path = f"{empty_bin.as_posix()}:/usr/bin:/bin"
    else:
        path = f"{fake_bin}:{os.environ['PATH']}"
    return {"PATH": path, "PROC_NET_DIR": str(proc_net)}


PREFLIGHT = (
    "SHARE443=1; TLS_SERVICE_PORT=8080; DLPROXY_TLS_PORT=8443; STRIP_PORT=8441\n"
    # die() ends with `exit 1`, which leaves the shell — run the function in a
    # subshell so rc can still be read afterwards.
    "( share443_preflight ); echo rc=$?"
)


def test_preflight_passes_when_nginx_is_absent(tmp_path: Path, proc_net: Path) -> None:
    """The reported bug: a fresh host has no nginx, and that is not a failure.

    8080 is LISTEN in the fixture, 443/8443/8441 are not, so every other check
    in preflight is satisfied and only the nginx branch decides the outcome.
    """
    r = bash(PREFLIGHT, env=_preflight_env(None, proc_net))
    assert "rc=0" in r.stdout, (r.stdout, r.stderr)
    assert "尚未安装 nginx" in r.stdout
    assert "--with-stream" not in r.stderr


def test_preflight_refuses_nginx_without_stream(tmp_path: Path, proc_net: Path) -> None:
    """If nginx IS on the box and cannot do stream, refusing is correct."""
    fake = _fake_nginx(tmp_path, supports_stream=False)
    r = bash(PREFLIGHT, env=_preflight_env(fake, proc_net))
    assert "rc=1" in r.stdout, (r.stdout, r.stderr)
    assert "libnginx-mod-stream" in r.stderr


def test_preflight_accepts_nginx_with_stream(tmp_path: Path, proc_net: Path) -> None:
    fake = _fake_nginx(tmp_path, supports_stream=True)
    r = bash(PREFLIGHT, env=_preflight_env(fake, proc_net))
    assert "rc=0" in r.stdout, (r.stdout, r.stderr)


def test_preflight_refuses_when_the_service_port_is_not_listening(tmp_path: Path, proc_net: Path) -> None:
    fake = _fake_nginx(tmp_path, supports_stream=True)
    env = _preflight_env(fake, proc_net)
    r = bash(
        "SHARE443=1; TLS_SERVICE_PORT=10443; DLPROXY_TLS_PORT=8443; STRIP_PORT=8441\n"
        "( share443_preflight ); echo rc=$?",
        env=env,
    )
    assert "rc=1" in r.stdout, (r.stdout, r.stderr)
    assert "10443" in r.stderr


def test_probe_pulls_in_the_distro_module_list(tmp_path: Path) -> None:
    """Ubuntu ships stream as a dynamic module.

    `nginx -t -c <probe>` replaces the distro nginx.conf, so its load_module
    lines disappear and a *working* host would report 'unknown directive
    stream'. The probe has to include modules-enabled/ itself; assert it does
    when that directory exists.
    """
    mods = tmp_path / "modules-enabled"
    mods.mkdir()
    (mods / "50-mod-stream.conf").write_text("load_module modules/ngx_stream_module.so;\n")

    seen = tmp_path / "seen.conf"
    fake = tmp_path / "bin"
    fake.mkdir()
    script = fake / "nginx"
    # Record what the probe handed to nginx, then accept it.
    script.write_text(f'#!/usr/bin/env bash\ncp "$3" "{seen.as_posix()}"\nexit 0\n')
    script.chmod(0o755)

    r = bash(
        "nginx_stream_ready; echo rc=$?",
        env={
            "PATH": f"{fake}:{os.environ['PATH']}",
            "NGINX_MODULES_GLOB": f"{mods.as_posix()}/*.conf",
        },
    )
    assert "rc=0" in r.stdout, (r.stdout, r.stderr)
    assert f"include {mods.as_posix()}/*.conf;" in seen.read_text(encoding="utf-8")


def test_probe_omits_the_include_when_no_module_dir(tmp_path: Path) -> None:
    seen = tmp_path / "seen.conf"
    fake = tmp_path / "bin"
    fake.mkdir()
    script = fake / "nginx"
    script.write_text(f'#!/usr/bin/env bash\ncp "$3" "{seen.as_posix()}"\nexit 0\n')
    script.chmod(0o755)
    r = bash(
        "nginx_stream_ready; echo rc=$?",
        env={
            "PATH": f"{fake}:{os.environ['PATH']}",
            "NGINX_MODULES_GLOB": f"{(tmp_path / 'absent').as_posix()}/*.conf",
        },
    )
    assert "rc=0" in r.stdout, (r.stdout, r.stderr)
    assert "include" not in seen.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The stream fragment must reach nginx.conf wrapped in `stream {}`.
#
# A bare include at the top level of nginx.conf makes nginx abort with
#   [emerg] "map" directive is not allowed here
# because the fragment is a main-context config (map/upstream/server). This
# was shipped once and only showed up on a real server, because
# tools/e2e_share443.py carried its own hand-written wrapper.
# ---------------------------------------------------------------------------

INCLUDE_BLOCK = "share443_nginx_include_block"


def test_include_block_wraps_the_fragment_in_stream(tmp_path: Path) -> None:
    r = bash(f"{INCLUDE_BLOCK}")
    assert r.returncode == 0, r.stderr
    text = r.stdout
    assert "stream {" in text, text
    assert "include /etc/nginx/stream-enabled/*.conf;" in text, text
    # The include has to sit INSIDE the block, not after the closing brace.
    open_at = text.index("stream {")
    close_at = text.index("}", open_at)
    assert open_at < text.index("include ") < close_at, text


def test_include_block_is_valid_nginx_config(nginx_binary: str | None) -> None:
    """Feed the real appended text to a real nginx -t.

    The map/upstream/server directives live in the fragment, so the fragment
    itself is stubbed out here — what is under test is whether the appended
    wrapper puts the include in a stream{} context. `map` is legal inside
    stream{} and illegal at the top level, so a `map` standing in for the
    fragment is an exact probe for the failure mode.
    """
    if nginx_binary is None:
        pytest.skip("no nginx binary available")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for sub in ("logs", "conf", "temp/client_body_temp", "temp/proxy_temp",
                    "temp/fastcgi_temp", "temp/uwsgi_temp", "temp/scgi_temp"):
            (root / sub).mkdir(parents=True, exist_ok=True)
        (root / "conf" / "fragment.conf").write_text(
            "map $ssl_preread_server_name $dlproxy_backend {\n"
            '    "" dlproxy_node;\n'
            "    default dlproxy_node;\n"
            "}\n",
            encoding="utf-8",
        )
        r = bash(f"{INCLUDE_BLOCK}")
        block = r.stdout.replace(
            "/etc/nginx/stream-enabled/*.conf", (root / "conf" / "fragment.conf").as_posix()
        )
        (root / "nginx.conf").write_text(
            f"pid {root.as_posix()}/nginx.pid;\n"
            "error_log stderr;\n"
            "events { worker_connections 16; }\n"
            "http { server { listen 127.0.0.1:18099; return 204; } }\n"
            + block,
            encoding="utf-8",
        )
        proc = subprocess.run(
            [nginx_binary, "-t", "-c", str(root / "nginx.conf"), "-p", root.as_posix() + "/"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
            stdin=subprocess.DEVNULL,
        )
        detail = (proc.stdout or "") + (proc.stderr or "")
        assert proc.returncode == 0, detail
        assert "syntax is ok" in detail, detail


def test_bare_include_is_still_rejected_so_the_test_above_is_meaningful(
    nginx_binary: str | None,
) -> None:
    """Negative control: the OLD bytes really do break nginx.

    Without this, the previous test would keep passing even if nginx started
    tolerating a top-level `map`, and we would not notice the guard had gone
    dead.
    """
    if nginx_binary is None:
        pytest.skip("no nginx binary available")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for sub in ("logs", "conf", "temp/client_body_temp", "temp/proxy_temp",
                    "temp/fastcgi_temp", "temp/uwsgi_temp", "temp/scgi_temp"):
            (root / sub).mkdir(parents=True, exist_ok=True)
        (root / "conf" / "fragment.conf").write_text(
            "map $ssl_preread_server_name $dlproxy_backend { default dlproxy_node; }\n",
            encoding="utf-8",
        )
        (root / "nginx.conf").write_text(
            f"pid {root.as_posix()}/nginx.pid;\n"
            "error_log stderr;\n"
            "events { worker_connections 16; }\n"
            "http { server { listen 127.0.0.1:18099; return 204; } }\n"
            f'\n# dlproxy share-443\ninclude {(root / "conf" / "fragment.conf").as_posix()};\n',
            encoding="utf-8",
        )
        proc = subprocess.run(
            [nginx_binary, "-t", "-c", str(root / "nginx.conf"), "-p", root.as_posix() + "/"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
            stdin=subprocess.DEVNULL,
        )
        detail = (proc.stdout or "") + (proc.stderr or "")
        assert proc.returncode != 0, detail
        assert '"map" directive is not allowed here' in detail, detail


# ---------------------------------------------------------------------------
# http2 spelling. The first real deployment died here:
#   [emerg] unknown directive "http2" in /etc/nginx/sites-enabled/dlproxy:39
# Ubuntu 24.04 ships nginx 1.24.0, which only knows `listen ... ssl http2`;
# the standalone `http2 on;` appears in 1.25.1. Both templates used to hardcode
# the newer spelling, so the site failed to load on exactly the target distro.
# ---------------------------------------------------------------------------


def test_the_templates_leave_the_http2_spelling_to_the_script() -> None:
    """Neither template may hardcode a spelling: the host decides."""
    for name in ("nginx.conf", "nginx-share443.conf"):
        text = (DEPLOY_SH.parent / name).read_text(encoding="utf-8")
        assert "__HTTP2_DIRECTIVE__" in text, name
        assert "http2 on;" not in text, f"{name} still hardcodes the 1.25.1+ form"


def test_both_templates_keep_tokens_out_of_the_access_log() -> None:
    """The access token is part of the path (/u/<token>/...).

    nginx logs the request line by default, and logrotate keeps it a week, so a
    shared download link would sit in /var/log/nginx/access.log in plaintext.
    """
    for name in ("nginx.conf", "nginx-share443.conf"):
        text = (DEPLOY_SH.parent / name).read_text(encoding="utf-8")
        server = text.split("server {")[-1]
        assert "access_log off;" in server, f"{name} still logs /u/<token>/..."


def test_both_templates_send_a_content_security_policy() -> None:
    """No inline event handlers are added, but a CSP still bounds the damage."""
    for name in ("nginx.conf", "nginx-share443.conf"):
        text = (DEPLOY_SH.parent / name).read_text(encoding="utf-8")
        assert "Content-Security-Policy" in text, name
        csp = text.split('Content-Security-Policy "', 1)[1].split('"', 1)[0]
        assert "default-src 'self'" in csp, name
        assert "object-src 'none'" in csp, name
        # The pages carry small inline scripts and inline confirm() guards.
        assert "script-src 'self' 'unsafe-inline'" in csp, name


def test_http2_probe_accepts_a_modern_nginx(nginx_binary: str | None) -> None:
    """A 1.25+ binary parses the standalone directive, so the probe says yes."""
    if nginx_binary is None:
        pytest.skip("no nginx binary available")
    r = bash(
        "http2_supports_standalone; echo rc=$?",
        env={"PATH": f"{Path(nginx_binary).parent}:{os.environ['PATH']}"},
    )
    assert "rc=0" in r.stdout, (r.stdout, r.stderr)


def test_http2_probe_rejects_nginx_that_only_knows_the_listen_flag() -> None:
    """nginx 1.24 rejects `http2 on;`, so the probe must return 1.

    Forcing the branch through DLPROXY_HTTP2 rather than stubbing nginx: on
    this Windows/MSYS host a stub on PATH cannot be exec'd reliably, and the
    subprocess then hangs until the pytest timeout instead of failing.
    """
    r = bash("http2_supports_standalone; echo rc=$?", env={"DLPROXY_HTTP2": "listen"})
    assert "rc=1" in r.stdout, (r.stdout, r.stderr)


def _render(
    template: str,
    tmp_path: Path,
    *,
    standalone: bool,
    server_name: str = "_",
    default_server: bool = True,
) -> str:
    """Render one real template and run apply_http2_spelling over it.

    A stub nginx decides the branch, so the whole path from template bytes to
    final site is the same one stage_nginx takes — only root and openssl are
    left out.
    """
    site = tmp_path / "site.conf"
    text = (DEPLOY_SH.parent / template).read_text(encoding="utf-8")
    for placeholder, value in (
        ("__CERT_FULLCHAIN__", "/tmp/none.pem"),
        ("__CERT_PRIVKEY__", "/tmp/none.key"),
        ("__TLS_SERVICE_PORT__", "11111"),
        ("__STRIP_PORT__", "8441"),
        ("__DLPROXY_TLS_PORT__", "8443"),
        ("__DEFAULT_SERVER__", " default_server" if default_server else ""),
        ("__SERVER_NAME__", server_name),
    ):
        text = text.replace(placeholder, value)
    # write_bytes, not write_text: on Windows write_text translates "\n" to
    # "\r\n", the sed patterns anchor on "$" and stop matching, and the test
    # then fails for a reason that cannot happen on the Linux target (where
    # `sed ... > site` from an LF template produces LF).
    site.write_bytes(text.encode("utf-8"))

    r = bash(
        f'apply_http2_spelling "{site.as_posix()}"',
        env={"DLPROXY_HTTP2": "standalone" if standalone else "listen"},
    )
    assert r.returncode == 0, (r.stdout, r.stderr)
    return site.read_text(encoding="utf-8")


TLS_LISTENS = {
    "nginx.conf": ["listen 443 ssl default_server;", "listen [::]:443 ssl default_server;"],
    "nginx-share443.conf": ["listen 127.0.0.1:8443 ssl proxy_protocol;"],
}


@pytest.mark.parametrize("template", sorted(TLS_LISTENS))
def test_modern_nginx_gets_the_standalone_directive(template: str, tmp_path: Path) -> None:
    body = _render(template, tmp_path, standalone=True)
    assert "__HTTP2_DIRECTIVE__" not in body
    assert "    http2 on;" in body
    for line in TLS_LISTENS[template]:
        assert line in body, (template, line, body)
    assert "http2;" not in body.replace("http2 on;", "")


@pytest.mark.parametrize("template", sorted(TLS_LISTENS))
def test_nginx_1_24_gets_the_flag_on_every_tls_listen(template: str, tmp_path: Path) -> None:
    """Ubuntu 24.04 ships 1.24: no standalone directive, flag on the listen."""
    body = _render(template, tmp_path, standalone=False)
    assert "__HTTP2_DIRECTIVE__" not in body
    assert "http2 on;" not in body
    for line in TLS_LISTENS[template]:
        assert line[:-1] + " http2;" in body, (template, line, body)


def test_the_share443_listen_pattern_survives_proxy_protocol(tmp_path: Path) -> None:
    """Regression: an exact `ssl;` pattern misses `ssl proxy_protocol;`.

    The share-443 template listens with `ssl proxy_protocol`, so a sed pinned to
    the bare `ssl;` spelling would silently leave that host on nginx 1.24 with
    no http2 at all instead of failing loudly.
    """
    body = _render("nginx-share443.conf", tmp_path, standalone=False)
    assert "listen 127.0.0.1:8443 ssl proxy_protocol http2;" in body, body


# ---------------------------------------------------------------------------
# port_owner / exclusive_preflight
#
# The third real deployment died with "[x] 端口 80 已被占用" on a host where
# `ss -tlnp | grep :80` showed nothing but nginx — the very server stage_nginx
# reconfigures and reloads. preflight read "the port is listening" as "the port
# is in the way", so the installer refused to upgrade its own web server and
# every re-run on a live host was blocked. What decides the outcome is *who*
# holds the port, so these tests pin the owner lookup and the four verdicts.
# ---------------------------------------------------------------------------

FAKE_SS = r"""#!/usr/bin/env bash
set -u
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
  printf '%s' "${FAKE_OWNER:-unknown}"
}
for p in ${FAKE_LISTENING:-}; do
  if [[ -z "$want" || "$p" == "$want" ]]; then
    printf 'LISTEN 0 511 0.0.0.0:%s 0.0.0.0:* users:(("%s",pid=1,fd=3))\n' "$p" "$(owner_for "$p")"
  fi
done
exit 0
"""

# What real ss prints without root: the LISTEN row is there, the users:(...)
# column is not. port_listening must still say "busy", and port_owner has to
# reach for the inode walk instead of concluding the port is free.
SILENT_SS = r"""#!/usr/bin/env bash
set -u
want=""
for a in "$@"; do
  case "$a" in
    *sport*) want="${a##*:}" ;;
  esac
done
for p in ${FAKE_LISTENING:-}; do
  if [[ -z "$want" || "$p" == "$want" ]]; then
    printf 'LISTEN 0 511 0.0.0.0:%s 0.0.0.0:*\n' "$p"
  fi
done
exit 0
"""


def _ss_env(
    tmp_path: Path,
    *,
    listening: list[int],
    owners: dict[int, str] | None = None,
    silent: bool = False,
    proc_net: Path | None = None,
    proc_root: Path | None = None,
) -> dict[str, str]:
    d = tmp_path / "bin"
    d.mkdir(parents=True, exist_ok=True)
    (d / "ss").write_text(SILENT_SS if silent else FAKE_SS, encoding="utf-8")
    env = {
        "PATH": f"{d.as_posix()}:{os.environ['PATH']}",
        "FAKE_LISTENING": " ".join(str(p) for p in listening),
        "FAKE_OWNERS": " ".join(f"{p}={o}" for p, o in (owners or {}).items()),
    }
    # as_posix(): the inode walk globs "$PROC_ROOT"/[0-9]*, and a Windows path
    # with backslashes makes bash treat them as escapes — the glob then matches
    # nothing and port_owner silently returns empty.
    if proc_net is not None:
        env["PROC_NET_DIR"] = proc_net.as_posix()
    if proc_root is not None:
        env["PROC_ROOT"] = proc_root.as_posix()
    return env


def _proc_net_for(tmp_path: Path, rows: list[tuple[int, int]]) -> Path:
    """Write a /proc/net/tcp holding one LISTEN row per (port, inode)."""
    d = tmp_path / "net-inode"
    d.mkdir(parents=True, exist_ok=True)
    lines = [
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
        "retrnsmt   uid  timeout inode"
    ]
    for i, (port, inode) in enumerate(rows):
        lines.append(
            f"   {i}: 00000000:{port:04X} 00000000:0000 0A 00000000:00000000 "
            f"00:00000000 00000000     0        0 {inode} 1"
        )
    (d / "tcp").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (d / "tcp6").write_text("", encoding="utf-8")
    return d


def _proc_root_for(tmp_path: Path, sockets: dict[int, str]) -> Path:
    """Build a fake /proc with <pid>/fd/<n> -> socket:[inode] and <pid>/comm."""
    root = tmp_path / "proc-inode"
    root.mkdir(parents=True, exist_ok=True)
    for pid, name in enumerate(sockets.values(), start=4000):
        pdir = root / str(pid)
        (pdir / "fd").mkdir(parents=True, exist_ok=True)
        (pdir / "comm").write_text(name + "\n", encoding="utf-8")
    for i, inode in enumerate(sockets, start=1):
        pid = 4000 + i - 1
        (root / str(pid) / "fd" / "5").symlink_to(f"socket:[{inode}]")
    return root


def test_port_owner_uses_ss_when_it_names_the_holder(tmp_path: Path) -> None:
    env = _ss_env(tmp_path, listening=[80], owners={80: "nginx"})
    r = bash("port_owner 80", env=env)
    assert r.stdout.strip() == "nginx", (r.stdout, r.stderr)


def test_port_owner_falls_back_to_the_inode_walk(tmp_path: Path) -> None:
    """ss present but silent: the answer must come from /proc, not "nobody"."""
    net = _proc_net_for(tmp_path, [(80, 55555)])
    root = _proc_root_for(tmp_path, {55555: "nginx"})
    env = _ss_env(tmp_path, listening=[80], silent=True, proc_net=net, proc_root=root)
    r = bash("port_owner 80", env=env)
    assert r.stdout.strip() == "nginx", (r.stdout, r.stderr)


def test_port_owner_is_empty_when_nobody_can_be_identified(tmp_path: Path) -> None:
    net = _proc_net_for(tmp_path, [(80, 55555)])
    root = tmp_path / "proc-empty"
    root.mkdir()
    env = _ss_env(tmp_path, listening=[], silent=True, proc_net=net, proc_root=root)
    r = bash("port_owner 80", env=env)
    assert r.stdout.strip() == "", (r.stdout, r.stderr)
    assert r.returncode == 0, r.stderr


def test_port_owner_resolves_a_thread_to_its_process(tmp_path: Path) -> None:
    """A thread's comm is its own name, so uvicorn reported itself as MainThread.

    /proc/[0-9]* matches thread ids as well as process ids. Reading comm from a
    thread directory answers "MainThread" or "asyncio_0", which is not the name
    of anything the operator can find with ps — and it silently broke the 8080
    check, which only recognises python/uvicorn.
    """
    net = _proc_net_for(tmp_path, [(8080, 55555)])
    root = tmp_path / "proc-thread"
    # The socket is held by a thread (4200) whose process is 4199.
    (root / "4200" / "fd").mkdir(parents=True, exist_ok=True)
    (root / "4200" / "comm").write_text("MainThread\n", encoding="utf-8")
    (root / "4200" / "status").write_text(
        "Name:\tMainThread\nTgid:\t4199\nPid:\t4200\n", encoding="utf-8"
    )
    (root / "4199" / "fd").mkdir(parents=True, exist_ok=True)
    (root / "4199" / "comm").write_text("python\n", encoding="utf-8")
    (root / "4200" / "fd" / "5").symlink_to("socket:[55555]")
    env = _ss_env(tmp_path, listening=[], silent=True, proc_net=net, proc_root=root)
    r = bash("port_owner 8080", env=env)
    assert r.stdout.strip() == "python", (r.stdout, r.stderr)


EXCLUSIVE = "( exclusive_preflight ); echo rc=$?"


def test_exclusive_preflight_adopts_nginx_on_80(tmp_path: Path) -> None:
    """The reported bug: a live host's nginx on :80 is the target, not a clash."""
    env = _ss_env(tmp_path, listening=[80, 443], owners={80: "nginx", 443: "nginx"})
    r = bash(EXCLUSIVE, env=env)
    assert "rc=0" in r.stdout, (r.stdout, r.stderr)
    assert "接管该实例并 reload" in r.stdout
    assert "已被占用" not in r.stderr


def test_exclusive_preflight_refuses_a_foreign_holder_on_80(tmp_path: Path) -> None:
    env = _ss_env(tmp_path, listening=[80], owners={80: "apache2-helper"})
    r = bash(EXCLUSIVE, env=env)
    assert "rc=1" in r.stdout, (r.stdout, r.stderr)
    assert "apache2-helper" in r.stderr
    assert "不会停止其他服务" in r.stderr


def test_exclusive_preflight_refuses_when_the_holder_is_unknown(tmp_path: Path) -> None:
    """Unknown owner must stop the run: nginx may not be able to bind later.

    ss is present but names nobody, and the inode walk finds no process — the
    case of a non-root run that cannot see another user's socket. Treating this
    as "free" is what leaves a host with a dead :80 after the install.
    """
    net = _proc_net_for(tmp_path, [(80, 55555)])
    empty_root = tmp_path / "proc-nobody"
    empty_root.mkdir()
    env = _ss_env(tmp_path, listening=[80], silent=True, proc_net=net, proc_root=empty_root)
    r = bash(EXCLUSIVE, env=env)
    assert "rc=1" in r.stdout, (r.stdout, r.stderr)
    assert "无法确认占用进程" in r.stderr
    assert "ss -lntp" in r.stderr


def test_exclusive_preflight_reads_python_on_8080_as_our_own_service(tmp_path: Path) -> None:
    env = _ss_env(tmp_path, listening=[8080], owners={8080: "python"})
    r = bash(EXCLUSIVE, env=env)
    assert "rc=0" in r.stdout, (r.stdout, r.stderr)
    assert "判断为本服务实例" in r.stdout
    assert "8080 已被" not in r.stderr


def test_exclusive_preflight_warns_about_a_foreign_holder_on_8080(tmp_path: Path) -> None:
    """8080 held by something else is a warning, never a stop."""
    env = _ss_env(tmp_path, listening=[8080], owners={8080: "node"})
    r = bash(EXCLUSIVE, env=env)
    assert "rc=0" in r.stdout, (r.stdout, r.stderr)
    # warn() prints to stdout; only die() goes to stderr.
    assert "node" in r.stdout


# ---------------------------------------------------------------------------
# record_public_base / saved_public_base
#
# The console menu runs outside a request, so it cannot derive the site address
# from request.base_url the way the web pages do. deploy.sh knows the
# certificate identity and records it; without that row every link printed by
# `dlproxy` stays the "<你的域名或IP>" placeholder, which is what the first real
# deployment hit.
# ---------------------------------------------------------------------------


APP_TREE = Path(__file__).resolve().parent.parent


@pytest.fixture()
def app_env(tmp_path: Path) -> dict[str, str]:
    """A scratch APP_DIR with a venv/bin/python that is just this interpreter.

    APP_PY_RUNNER is emptied so no `sudo -u dlproxy` is attempted; APP_DIR
    points at the scratch tree so the snippet imports the real `app` package
    from this checkout but writes to a throwaway database.
    """
    app_dir = tmp_path / "opt"
    (app_dir / "venv" / "bin").mkdir(parents=True)
    (app_dir / "data").mkdir()
    shim = app_dir / "venv" / "bin" / "python"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    shim.chmod(0o755)
    return {
        # as_posix(): bash's `-x` test cannot stat a Windows path with
        # backslashes once it is glued to "/venv/bin/python".
        "T_APP_DIR": app_dir.as_posix(),
        # The real sudo -u cannot work in a test, and on Windows it does not
        # exist at all. The callers empty the array themselves.
        "DLPROXY_DB_PATH": (app_dir / "data" / "app.db").as_posix(),
        "PYTHONPATH": APP_TREE.as_posix(),
    }


# deploy.sh assigns APP_DIR/APP_PY_RUNNER when it is sourced, so the test has to
# set them AFTER `source` — an env var set beforehand is overwritten.
PRELUDE = (
    'APP_DIR="$T_APP_DIR"\n'
    'export APP_DIR\n'
    'APP_PY_RUNNER=()\n'
    'export APP_PY_RUNNER\n'
)

RECORD = PRELUDE + '( record_public_base "$BASE" ); echo rc=$?'
SAVED = PRELUDE + 'saved_public_base'


def test_record_public_base_writes_both_keys(app_env: dict[str, str]) -> None:
    env = dict(app_env, BASE="https://203.0.113.9")
    r = bash(f'{RECORD}\n{SAVED}', env=env)
    assert "rc=0" in r.stdout, (r.stdout, r.stderr)
    assert "https://203.0.113.9" in r.stdout, r.stdout


def test_saved_public_base_is_empty_before_anything_is_recorded(app_env: dict[str, str]) -> None:
    r = bash(SAVED, env=app_env)
    assert r.stdout.strip() == "", (r.stdout, r.stderr)


def test_record_public_base_ignores_an_empty_argument(app_env: dict[str, str]) -> None:
    env = dict(app_env, BASE="")
    r = bash(f'{RECORD}\n{SAVED}', env=env)
    assert "rc=0" in r.stdout
    assert "已写入站点地址" not in r.stdout
    assert r.stdout.strip().endswith("rc=0")


def test_record_public_base_is_skipped_without_a_venv(app_env: dict[str, str], tmp_path: Path) -> None:
    """stage_app has not run yet — recording must be a no-op, not a crash."""
    empty = tmp_path / "empty"
    empty.mkdir()
    env = dict(app_env, T_APP_DIR=empty.as_posix(), BASE="https://203.0.113.9")
    r = bash(RECORD, env=env)
    assert "rc=0" in r.stdout, (r.stdout, r.stderr)
    assert "已写入站点地址" not in r.stdout


def test_saved_public_base_hides_the_placeholder(app_env: dict[str, str]) -> None:
    """A stored placeholder must read back as "unknown", not as a real answer.

    The row is written directly rather than through record_public_base: MSYS
    mangles non-ASCII through argv/env, and what this test pins is the readback
    rule, not the Windows argv encoding.
    """
    env = dict(os.environ, **app_env)
    subprocess.run(
        [sys.executable, "-c",
         "from app import db\n"
         "conn = db.init_db()\n"
         "db.set_setting(conn, 'public_base', db.PLACEHOLDER_BASE)\n"
         "db.set_setting(conn, 'public_host', '')\n"
         "conn.close()\n"],
        check=True, capture_output=True, env=env, timeout=60,
        stdin=subprocess.DEVNULL,
    )
    r = bash(SAVED, env=app_env)
    assert r.stdout.strip() == "", (r.stdout, r.stderr)


# ---------------------------------------------------------------------------
# print_next_steps
#
# This is the only place the install tells the operator the site address and
# where INITIAL_ADMIN.txt lives. It shipped as a bare "<你的域名或IP>"
# placeholder for two rounds without anyone noticing, because nothing pinned
# the wording.
# ---------------------------------------------------------------------------


def _next_steps(
    tmp_path: Path,
    base: str,
    admin_path: str | None,
    *,
    init_file: str | None = None,
) -> str:
    """Render print_next_steps against a scratch APP_DIR.

    admin_path goes into the database, not into INITIAL_ADMIN.txt: that file only
    exists on the very first boot, and reading the admin path out of it is what
    made a reinstall claim the file was there while telling you to delete it.
    """
    app_dir = tmp_path / "opt"
    (app_dir / "venv" / "bin").mkdir(parents=True)
    (app_dir / "data").mkdir()
    shim = app_dir / "venv" / "bin" / "python"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    shim.chmod(0o755)

    if admin_path is not None:
        subprocess.run(
            [sys.executable, "-c",
             "import sys\n"
             "from app import db\n"
             "conn = db.init_db()\n"
             "db.set_setting(conn, 'admin_path', sys.argv[1])\n"
             "conn.close()\n",
             admin_path.strip("/")],
            check=True, capture_output=True, timeout=60,
            env=dict(os.environ, PYTHONPATH=APP_TREE.as_posix(),
                     DLPROXY_DB_PATH=(app_dir / "data" / "app.db").as_posix()),
            stdin=subprocess.DEVNULL,
        )

    if init_file is not None:
        (app_dir / "INITIAL_ADMIN.txt").write_text(init_file, encoding="utf-8")

    script = (
        f'APP_DIR="{app_dir.as_posix()}"\n'
        'APP_PY_RUNNER=()\n'
        f'print_next_steps "{base}"\n'
    )
    # Same DLPROXY_DB_PATH as the write above; db.init_db() reads the env when
    # no path is given. PYTHONPATH is needed too: app_python runs with
    # `cd "$APP_DIR"`, which is not the checkout, so `from app import db` has to
    # be told where the package is.
    return bash(script, env={
        "DLPROXY_DB_PATH": (app_dir / "data" / "app.db").as_posix(),
        "PYTHONPATH": APP_TREE.as_posix(),
    }).stdout


def test_next_steps_names_the_real_site_address(tmp_path: Path) -> None:
    out = _next_steps(tmp_path, "https://203.0.113.9", "/abc123", init_file="x")
    assert "https://203.0.113.9" in out
    assert "<你的域名或IP>" not in out


def test_next_steps_builds_the_full_admin_url(tmp_path: Path) -> None:
    out = _next_steps(tmp_path, "https://203.0.113.9", "abc123", init_file="x")
    assert "https://203.0.113.9/abc123" in out


def test_next_steps_gives_the_absolute_path_of_the_password_file(tmp_path: Path) -> None:
    out = _next_steps(tmp_path, "https://203.0.113.9", "/abc123", init_file="x")
    assert "INITIAL_ADMIN.txt" in out
    assert f"sudo cat {tmp_path.as_posix()}/opt/INITIAL_ADMIN.txt" in out
    assert f"sudo rm  {tmp_path.as_posix()}/opt/INITIAL_ADMIN.txt" in out


def test_next_steps_tells_you_to_type_dlproxy(tmp_path: Path) -> None:
    out = _next_steps(tmp_path, "https://203.0.113.9", "/abc123", init_file="x")
    assert "输入 dlproxy 后回车" in out


def test_next_steps_admits_an_unknown_address_instead_of_faking_one(tmp_path: Path) -> None:
    out = _next_steps(tmp_path, "", "/abc123", init_file="x")
    assert "地址未记录" in out
    assert "dlproxy set-site" in out
    # The admin path is still printed, just without a host to prefix it.
    assert "/abc123" in out


def test_next_steps_still_prints_the_admin_url_without_the_password_file(tmp_path: Path) -> None:
    """The fifth real deployment: a reinstall, so no INITIAL_ADMIN.txt.

    The install printed "2) 管理页  见下面的 INITIAL_ADMIN.txt" and then told the
    operator to `cat` a file that does not exist. Both came from reading the
    admin path out of that file. The row is in the database either way.
    """
    out = _next_steps(tmp_path, "https://203.0.113.9", "/a1b2c3d4", init_file=None)
    assert "https://203.0.113.9/a1b2c3d4" in out
    assert "INITIAL_ADMIN.txt" not in out.replace("INITIAL_ADMIN.txt'", "")


def test_next_steps_does_not_promise_a_password_file_that_is_absent(tmp_path: Path) -> None:
    out = _next_steps(tmp_path, "https://203.0.113.9", "/a1b2c3d4", init_file=None)
    assert "sudo cat" not in out
    assert "本次未生成" in out
    assert "重置密码" in out


def test_next_steps_says_so_when_even_the_admin_path_is_missing(tmp_path: Path) -> None:
    out = _next_steps(tmp_path, "https://203.0.113.9", None, init_file=None)
    assert "admin_path" in out


def test_next_steps_does_not_leak_a_closing_border(tmp_path: Path) -> None:
    """Mixed CJK/ASCII widths make a right-hand │ impossible to align; the
    block uses a left rule instead, and must not reintroduce the box."""
    out = _next_steps(tmp_path, "https://203.0.113.9", "/abc123")
    assert "╭" not in out and "│" not in out


# ---------------------------------------------------------------------------
# cert-check.sh
# ---------------------------------------------------------------------------

_CERT_CHECK = (APP_TREE / "deploy" / "cert-check.sh").read_text(encoding="utf-8")


def test_cert_check_has_no_hardcoded_threshold() -> None:
    """The old script pinned 56/32 hours, so the panel's cert_warn_days was a
    field that changed a number nobody read."""
    assert "THRESHOLD_WARN_H=56" not in _CERT_CHECK
    assert "THRESHOLD_CRIT_H=32" not in _CERT_CHECK
    assert "cert_warn_days" in _CERT_CHECK


def test_cert_check_has_a_delivery_channel() -> None:
    """Spec 4.9 lists three alerts; only lockout used to send mail."""
    assert "alert-cert" in _CERT_CHECK
    assert "--stamp-broken" in _CERT_CHECK


def test_cert_check_derives_the_critical_band_from_the_warn_band() -> None:
    assert "THRESHOLD_CRIT_H=$(( THRESHOLD_WARN_H / 2 ))" in _CERT_CHECK


def test_cert_check_does_not_run_python_as_root() -> None:
    """Root-owned -wal/-shm files would leave the service unable to write."""
    assert "runuser -u" in _CERT_CHECK or "sudo -u" in _CERT_CHECK
    assert 'if [[ "$(id -u)" == "0" ]]' in _CERT_CHECK


def test_cert_check_keeps_running_when_logger_is_absent() -> None:
    """MSYS and slim containers have no `logger`; before the guard that hit
    `exit 127` and skipped the exit code the cron job watches."""
    lines = [ln for ln in _CERT_CHECK.splitlines() if "logger -t" in ln]
    assert lines
    for ln in lines:
        assert "2>/dev/null || true" in ln, ln


def _cert_check_run(tmp_path: Path, *, cert_days: int, warn_days: int | None,
                    stamp_age_h: int | None,
                    alert_rc: int = 0,
                    tag: str = "",
                    certs: dict[str, int] | None = None,
                    public_base: str | None = None,
                    nginx_cert: str | None = None) -> tuple[str, int, list[str]]:
    """Run the real script against a fake cert, a fake database and a fake python.

    ``tag`` lets one test run the same script twice with different settings;
    the sandbox lives under it so the two runs cannot see each other.
    ``alert_rc`` is what the stubbed ``app alert-cert`` exits with -- the real
    command exits with the *alert level* (0/2/3), not with success/failure.

    ``certs`` maps lineage name -> days of validity, defaulting to one IP-named
    lineage. Several lineages is the case that matters: a box can hold a domain
    certificate next to a leftover IP one, and the check has to pick the one
    nginx serves.
    ``public_base`` answers the settings row of the same name; ``nginx_cert``
    points the fake site config at a certificate, mirroring what deploy.sh
    writes into sites-available/dlproxy.

    Returns (stdout, exit code, argv it tried to run).
    """
    work = tmp_path / (f"cc-{tag}" if tag else "cc")
    (work / "venv" / "bin").mkdir(parents=True)
    (work / "data").mkdir()
    # The script only consults sqlite3 when the database file is readable;
    # without this it silently falls back to the 3-day default and the test
    # proves nothing about the row the panel writes.
    (work / "data" / "app.db").write_text("", encoding="utf-8")
    argv_log = work / "argv.txt"

    # A stub interpreter that records its arguments and exits 0.
    stub = work / "venv" / "bin" / "python"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\n" "$@" > {argv_log.as_posix()}\n'
        f"exit {alert_rc}\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)

    # sqlite3 stub: answers the two queries the script makes, and only those.
    bin_dir = work / "bin"
    bin_dir.mkdir()
    sqlite3_stub = bin_dir / "sqlite3"
    warn_answer = f"printf '%s\\n' '{warn_days}'" if warn_days is not None else "exit 1"
    base_answer = (
        f"printf '%s\\n' '{public_base}'" if public_base is not None else "exit 0"
    )
    sqlite3_stub.write_text(
        "#!/usr/bin/env bash\n"
        'case "$*" in\n'
        f"  *public_base*) {base_answer} ;;\n"
        f"  *cert_warn_days*) {warn_answer} ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    sqlite3_stub.chmod(0o755)

    # Real certificates, so `openssl x509` does what production does.
    lineage = certs if certs is not None else {"203.0.113.9": cert_days}
    for name, days in lineage.items():
        cert_dir = work / "live" / name
        cert_dir.mkdir(parents=True)
        sp.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(work / f"k-{name}.pem"),
             "-out", str(cert_dir / "fullchain.pem"),
             "-days", str(days), "-subj", f"/CN={name}"],
            # A hung subprocess would stall the whole suite forever; the suite
            # is the only thing standing between a change and a bad release, so
            # every child gets a deadline.
            check=True, capture_output=True, timeout=120,
            stdin=subprocess.DEVNULL,
        )

    # Where deploy.sh would have written the ssl_certificate line. Absent unless
    # the test asks for it, so the ground-truth source is opt-in.
    site = work / "nginx-site.conf"
    if nginx_cert is not None:
        site.write_text(
            "server {\n"
            "    listen 443 ssl;\n"
            f"    ssl_certificate     {nginx_cert};\n"
            "    ssl_certificate_key /nowhere/privkey.pem;\n"
            "}\n",
            encoding="utf-8",
        )

    stamp = work / "last-success"
    stamp.write_text("x", encoding="utf-8")
    if stamp_age_h is not None:
        old = time.time() - stamp_age_h * 3600
        os.utime(stamp, (old, old))

    # openssl lives outside /usr/bin on this host; without its directory the
    # script takes the "cannot read certificate" branch and the test proves
    # nothing about thresholds.
    openssl = shutil.which("openssl")
    extra = Path(openssl).parent.as_posix() if openssl else ""
    env = {
        "PATH": f"{bin_dir.as_posix()}:/usr/bin:/bin:{extra}",
        "APP_DIR": work.as_posix(),
        "DB_PATH": (work / "data" / "app.db").as_posix(),
        "APP_USER": "nobody",
        "STAMP": stamp.as_posix(),
        "CERT_DIR": (work / "live").as_posix(),
        # Pinned even when the test does not use it: on a real Linux host
        # /etc/nginx/sites-available/dlproxy may well exist, and the check would
        # then report on whatever this machine's nginx serves.
        "NGINX_SITE": site.as_posix(),
        "HOME": work.as_posix(),
    }
    # stdin is never the right input for this script, and inheriting the suite's
    # stdin means a child that reads it blocks until the test process is killed
    # — a full run once sat at 12% for 34 minutes that way.
    proc = sp.run(
        ["bash", str(APP_TREE / "deploy" / "cert-check.sh")],
        stdin=sp.DEVNULL,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env=env, timeout=120,
    )
    argv = []
    if argv_log.exists():
        argv = argv_log.read_text(encoding="utf-8").split()
    return proc.stdout + proc.stderr, proc.returncode, argv


def test_cert_check_calls_the_alert_cli_on_a_healthy_certificate(
        tmp_path: Path) -> None:
    """Called even when healthy: that is what clears cert_alert_state, so the
    next incident is not swallowed as a repeat."""
    out, rc, argv = _cert_check_run(tmp_path, cert_days=30, warn_days=3,
                                    stamp_age_h=1)
    assert rc == 0, out
    assert "alert-cert" in argv
    assert "--left-hours" in argv


def test_cert_check_reads_the_threshold_out_of_the_database(
        tmp_path: Path) -> None:
    out, _rc, _argv = _cert_check_run(tmp_path, cert_days=30, warn_days=3,
                                      stamp_age_h=1)
    assert "72 小时" in out

    out, _rc, _argv = _cert_check_run(tmp_path, cert_days=30, warn_days=5,
                                      stamp_age_h=1, tag="five-days")
    assert "120 小时" in out
    assert "60 小时" in out                       # critical band = warn / 2


def test_cert_check_falls_back_when_the_row_is_missing(tmp_path: Path) -> None:
    out, _rc, _argv = _cert_check_run(tmp_path, cert_days=30, warn_days=None,
                                      stamp_age_h=1)
    assert "72 小时" in out                       # 3 days, the shipped default


def test_cert_check_flags_a_short_certificate(tmp_path: Path) -> None:
    """A 1-day certificate is inside the 36-hour CRIT band of the default."""
    out, rc, _argv = _cert_check_run(tmp_path, cert_days=1, warn_days=3,
                                     stamp_age_h=1)
    assert rc == 3, out
    assert "CRIT" in out


def test_cert_check_warns_before_it_escalates(tmp_path: Path) -> None:
    """2 days left: past the 72-hour warn bar but not the 36-hour crit bar."""
    out, rc, _argv = _cert_check_run(tmp_path, cert_days=2, warn_days=3,
                                     stamp_age_h=1)
    assert rc == 2, out
    assert "WARN" in out


def test_cert_check_passes_stamp_broken_through(tmp_path: Path) -> None:
    out, rc, argv = _cert_check_run(tmp_path, cert_days=30, warn_days=3,
                                    stamp_age_h=200)
    assert rc == 3, out
    assert "--stamp-broken" in argv


def test_cert_check_omits_stamp_broken_when_renewals_are_fresh(
        tmp_path: Path) -> None:
    _out, _rc, argv = _cert_check_run(tmp_path, cert_days=30, warn_days=3,
                                      stamp_age_h=1)
    assert "--stamp-broken" not in argv


# ---------------------------------------------------------------------------
# Which certificate the check watches. On a host that ran an IP certificate
# before a domain one existed, both lineages sit in /etc/letsencrypt/live and
# only one of them is actually served. Reporting on the other one is worse than
# reporting on nothing: it either raises a false alarm or, worse, stays quiet
# while the served certificate runs out.
# ---------------------------------------------------------------------------
def test_cert_check_watches_the_certificate_nginx_serves(tmp_path: Path) -> None:
    """Ground truth first. The IP certificate expires sooner, so any rule that
    sorts by expiry picks the wrong one -- exactly the reported bug: a fresh
    domain certificate (90 days) is watched through the stale IP one (5 days)."""
    work = tmp_path / "cc"
    domain_cert = (work / "live" / "dl.example.com" / "fullchain.pem")
    out, rc, _argv = _cert_check_run(
        tmp_path,
        cert_days=5,
        warn_days=3,
        stamp_age_h=1,
        certs={"dl.example.com": 90, "203.0.113.9": 5},
        public_base="https://dl.example.com",
        nginx_cert=domain_cert.as_posix(),
    )
    assert rc == 0, out
    assert "dl.example.com/fullchain.pem" in out
    assert "203.0.113.9/fullchain.pem" not in out
    assert "nginx 站点配置" in out


def test_cert_check_falls_back_to_public_base_without_a_site_config(
        tmp_path: Path) -> None:
    """No readable site file (hand-rolled nginx layout, or the check running
    before stage_nginx): the database still knows what was intended."""
    out, rc, _argv = _cert_check_run(
        tmp_path,
        cert_days=5,
        warn_days=3,
        stamp_age_h=1,
        certs={"dl.example.com": 90, "203.0.113.9": 5},
        public_base="https://dl.example.com",
    )
    assert rc == 0, out
    assert "dl.example.com/fullchain.pem" in out
    assert "public_base" in out


def test_cert_check_reports_which_rule_picked_the_certificate(
        tmp_path: Path) -> None:
    """When this ever picks wrong again, the mail has to say why."""
    out, _rc, _argv = _cert_check_run(
        tmp_path, cert_days=30, warn_days=3, stamp_age_h=1,
        certs={"dl.example.com": 90},
    )
    assert "检查对象来源" in out
    assert "扫描" in out          # nothing else could answer


def test_cert_check_ignores_a_site_config_pointing_at_nothing(
        tmp_path: Path) -> None:
    """A stale ssl_certificate line must not become the answer: fall through to
    the next source instead of failing."""
    out, rc, _argv = _cert_check_run(
        tmp_path,
        cert_days=90,
        warn_days=3,
        stamp_age_h=1,
        certs={"dl.example.com": 90},
        nginx_cert="/etc/letsencrypt/live/deleted-lineage/fullchain.pem",
    )
    assert rc == 0, out
    assert "扫描" in out
    assert "deleted-lineage" not in out


def test_cert_check_lowercases_the_public_base_host(tmp_path: Path) -> None:
    """certbot names the lineage in lowercase; a public_base typed with capitals
    must still find it."""
    out, rc, _argv = _cert_check_run(
        tmp_path,
        cert_days=90,
        warn_days=3,
        stamp_age_h=1,
        certs={"dl.example.com": 90},
        public_base="https://DL.Example.COM",
    )
    assert rc == 0, out
    assert "dl.example.com/fullchain.pem" in out


# ---------------------------------------------------------------------------
# --domain: one identifier drives the certificate name, the lineage path and the
# server_name. A half-done switch (new certificate, old server_name) is exactly
# the failure this set of tests exists to prevent.
# ---------------------------------------------------------------------------
def bash_with_domain(
    script: str,
    env: dict[str, str] | None = None,
    *,
    domain: str = "",
) -> subprocess.CompletedProcess[str]:
    """Source deploy.sh, then exercise its domain helpers.

    The script is sourced, never stubbed: an earlier version of this helper
    pasted its own copies of cert_id/server_name_value into the shell, so those
    tests stayed green no matter what deploy.sh actually did. deploy.sh has a
    `[[ "${BASH_SOURCE[0]}" == "$0" ]]` guard on main(), so sourcing is free of
    side effects.

    `domain` is applied *after* sourcing: deploy.sh initialises DOMAIN="" at the
    top of the file, so putting it in the environment only gets it overwritten.
    """
    base = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": str(Path.home()),
        **{k: v for k, v in os.environ.items() if k in ("SYSTEMROOT", "TEMP", "TMP")},
    }
    base.update(env or {})
    body = (
        "set +e\n"
        f'source "{DEPLOY_SH.as_posix()}"\n'
        "set +e\n"
        + f'DOMAIN={domain!r}\n'
        + script
    )
    return sp.run(
        ["bash", "-c", body],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        env=base,
        timeout=60,
        stdin=subprocess.DEVNULL,
    )


def test_server_name_stays_a_catch_all_without_a_domain(tmp_path: Path) -> None:
    body = _render("nginx.conf", tmp_path, standalone=True)
    assert "server_name _;" in body
    assert "__SERVER_NAME__" not in body


def test_a_domain_becomes_the_server_name(tmp_path: Path) -> None:
    body = _render("nginx.conf", tmp_path, standalone=True,
                   server_name="dl.example.com")
    assert "server_name dl.example.com;" in body
    assert "server_name _;" not in body


def test_the_share443_template_also_carries_the_domain(tmp_path: Path) -> None:
    body = _render("nginx-share443.conf", tmp_path, standalone=True,
                   server_name="dl.example.com")
    assert body.count("server_name dl.example.com;") == 2   # :80 block + TLS block


def test_cert_id_follows_the_domain_and_falls_back_to_the_ip() -> None:
    r = bash_with_domain(
        'cert_id; echo; DOMAIN="" PUBLIC_IP=203.0.113.7 cert_id; echo',
        domain="DL.Example.COM",
    )
    assert r.returncode == 0, (r.stdout, r.stderr)
    lines = r.stdout.split()
    assert lines[0] == "dl.example.com", r.stdout          # lowercased
    assert lines[-1] == "203.0.113.7", r.stdout            # IP when no domain


def test_server_name_value_is_an_underscore_only_without_a_domain() -> None:
    r = bash_with_domain(
        'server_name_value; echo; DOMAIN=Dl.Example.com server_name_value; echo',
        domain="",
    )
    assert r.returncode == 0, (r.stdout, r.stderr)
    lines = r.stdout.split()
    assert lines[0] == "_"
    assert lines[-1] == "dl.example.com"


def test_a_domain_certificate_does_not_repeat_the_short_lived_warning() -> None:
    """An IP certificate needs a fresh http-01 every renewal (7-hour authz
    reuse vs a 160-hour lifetime); a domain certificate does not. Printing the
    IP advice on a domain install is wrong, and wrong advice in the final
    summary is how people learn to skip the summary."""
    r = bash_with_domain('renewal_reminder', domain="dl.example.com")
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "90 天" in r.stdout
    assert "http-01" not in r.stdout
    assert "短命证书" not in r.stdout


def test_an_ip_certificate_keeps_the_short_lived_warning() -> None:
    r = bash_with_domain('renewal_reminder', domain="", env={"PUBLIC_IP": "203.0.113.9"})
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "短命证书" in r.stdout
    assert "80 端口" in r.stdout


@pytest.mark.parametrize(
    "bad",
    ["example", "http://dl.example.com", "dl.example.com/x", "-dl.example.com",
     "dl..example.com", "dl.example.com:443", ""],
)
def test_validate_domain_rejects_anything_that_is_not_a_hostname(bad: str) -> None:
    """The real validator from deploy.sh, not the stub."""
    body = (
        "set +e\n"
        f'source "{DEPLOY_SH.as_posix()}"\n'
        "set +e\n"
        "die() { printf '%s' \"$*\" >&2; exit 1; }\n"
        f'validate_domain "{bad}" && echo ACCEPTED\n'
    )
    r = sp.run(
        ["bash", "-c", body],
        capture_output=True, encoding="utf-8", errors="replace",
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(Path.home()),
             **{k: os.environ[k] for k in ("SYSTEMROOT", "TEMP", "TMP") if k in os.environ}},
        timeout=60,
        stdin=subprocess.DEVNULL,
    )
    assert "ACCEPTED" not in r.stdout, (bad, r.stdout, r.stderr)
    assert r.returncode == 1


@pytest.mark.parametrize("good", ["dl.example.com", "a.b", "dl-1.example.co.uk", "x.y.z"])
def test_validate_domain_accepts_real_hostnames(good: str) -> None:
    body = (
        "set +e\n"
        f'source "{DEPLOY_SH.as_posix()}"\n'
        "set +e\n"
        "die() { printf '%s' \"$*\" >&2; exit 1; }\n"
        f'validate_domain "{good}" && echo ACCEPTED\n'
    )
    r = sp.run(
        ["bash", "-c", body],
        capture_output=True, encoding="utf-8", errors="replace",
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(Path.home()),
             **{k: os.environ[k] for k in ("SYSTEMROOT", "TEMP", "TMP") if k in os.environ}},
        timeout=60,
        stdin=subprocess.DEVNULL,
    )
    assert "ACCEPTED" in r.stdout, (good, r.stdout, r.stderr)

# The alert CLI exits with the level it decided on (0 healthy, 2 warning,
# 3 critical), not with success/failure. `notify()` therefore has to treat all
# three as a completed call -- otherwise every genuine warning is echoed as a
# mail failure, and a real SMTP outage becomes indistinguishable from routine
# operation.
@pytest.mark.parametrize("alert_rc", [0, 2, 3])
def test_a_decided_alert_level_is_not_reported_as_a_mail_failure(
        tmp_path: Path, alert_rc: int) -> None:
    out, _rc, _argv = _cert_check_run(
        tmp_path, cert_days=2, warn_days=3, stamp_age_h=0, alert_rc=alert_rc,
        tag=f"rc{alert_rc}",
    )
    assert "邮件告警调用失败" not in out, (alert_rc, out)


def test_a_broken_alert_cli_is_still_reported(tmp_path: Path) -> None:
    """Anything outside the decided levels is a real failure and must show up."""
    out, _rc, _argv = _cert_check_run(
        tmp_path, cert_days=2, warn_days=3, stamp_age_h=0, alert_rc=7, tag="rc7",
    )
    assert "邮件告警调用失败" in out, out


# ---------------------------------------------------------------------------
# Terminal presentation
#
# Two properties are load-bearing and neither was checked before:
#
#   * an escape sequence must not reach a file. `sudo ./deploy.sh > deploy.log`
#     used to write raw \033[32m into the log for every line, and the whole
#     install transcript of a failed run was unreadable.
#   * `==>` alone, repeated 70 times with no boundary, reads as one wall. The
#     stage header exists to break it, and it has to be the same width as
#     print_next_steps() so the output looks like it came from one program.
# ---------------------------------------------------------------------------


def _width(text: str) -> int:
    import unicodedata
    total = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        total += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return total


def test_a_redirected_run_writes_no_escape_sequences(tmp_path: Path) -> None:
    """Colour is a terminal feature; a log file gets bytes it can grep."""
    r = bash('info "示例"; warn "示例"; die "示例" || true',
             env={"NO_COLOR": "", "TERM": "xterm-256color"})
    # stdout of a pipe is not a tty, so every variable is empty.
    assert "\033" not in r.stdout, repr(r.stdout)
    assert "\033" not in r.stderr, repr(r.stderr)
    assert "==> 示例" in r.stdout
    assert "[!] 示例" in r.stdout


def test_the_gate_checks_all_three_conditions() -> None:
    """A pipe is only one of the three ways colour would be wrong.

    systemd sets no TERM at all, and NO_COLOR is the documented opt-out; the
    gate has to ask about all of them, not just "is stdout a terminal". There is
    no `script(1)` here to build a pty from, so this pins the source instead of
    a behaviour that cannot be produced on this host.
    """
    text = DEPLOY_SH.read_text(encoding="utf-8")
    gate = next(ln for ln in text.splitlines() if ln.startswith("if [[ -t 1"))
    assert "-t 1" in gate
    assert "NO_COLOR" in gate
    assert '"dumb"' in gate


def test_every_stage_header_is_the_same_width() -> None:
    titles = ["环境预检", "安装系统依赖", "写入环境文件与环境",
              "安装 nginx 站点配置", "证书", "安装 logrotate 与 cron"]
    script = "".join(f'stage_banner {i} "{t}"\n' for i, t in enumerate(titles, 1))
    r = bash(script, env={"NO_COLOR": "1"})
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    assert len(lines) == len(titles), lines
    widths = {_width(ln) for ln in lines}
    assert widths == {56}, [(w, ln) for ln in lines for w in [_width(ln)]]


def test_the_stage_numbers_are_positions_in_the_whole_run() -> None:
    """`--stage cert` is stage 5 of 6, not 1 of 1: the operator needs to know
    how much of the install is still ahead."""
    r = bash('echo "$STAGE_TOTAL"; stage_banner 5 "证书"', env={"NO_COLOR": "1"})
    assert r.stdout.splitlines()[0].strip() == "6"
    assert "阶段 5/6" in r.stdout


def test_a_phase_header_is_lighter_than_a_stage_header() -> None:
    """Otherwise the two levels are indistinguishable and the hierarchy is lost."""
    r = bash('stage_banner 3 "写入环境文件"; phase_banner "前置检查"',
             env={"NO_COLOR": "1"})
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    assert "━" in lines[0] and "━" not in lines[1]
    assert lines[1].startswith("  ── 前置检查")
    assert _width(lines[1]) == 56


def test_the_banner_survives_a_title_with_no_room_left() -> None:
    """A long title must not make the fill negative and crash the shell."""
    long_title = "极长的阶段标题" * 6
    r = bash(f'phase_banner "{long_title}"; echo AFTER', env={"NO_COLOR": "1"})
    assert "AFTER" in r.stdout, r.stderr


def test_the_helper_scripts_do_not_colour_a_log_file_either() -> None:
    """uninstall/verify_all/range_download/e2e_nginx are run by hand too.

    Each carried its own copy of the colour block, so the gate has to be in all
    of them; e2e_nginx.sh did not even define YEL, which is how the copies
    drifted apart in the first place.
    """
    base = DEPLOY_SH.parent.parent
    for name in ("deploy/uninstall.sh", "tools/verify_all.sh",
                 "tools/range_download.sh", "tools/e2e_nginx.sh"):
        text = (base / name).read_text(encoding="utf-8")
        assert "NO_COLOR" in text, name
        assert '"-t 1"' in text or "-t 1" in text, name
        assert '"dumb"' in text, name
        assert "\033[32m" not in text.replace("$'\\033[32m'", ""), name


def test_the_cli_wrapper_does_not_colour_a_log_file() -> None:
    base = DEPLOY_SH.parent.parent
    text = (base / "deploy/dlproxy-cli.sh").read_text(encoding="utf-8")
    assert "NO_COLOR" in text
    assert "-t 1" in text
    assert '"[31m"' not in text, "an inline escape slipped back in"

def test_the_documented_stage_block_keeps_its_widths():
    """The guide's 阶段 block is a capture; both rules must stay 56 columns.

    A banner that is one character short looks like a typo and a banner that is
    one character long wraps in an 80-column terminal, so the width is part of
    the design, not a coincidence. This pins the numbers in the guide against
    the widths the script is required to produce, without running deploy.sh.
    """
    doc = (APP_TREE / "docs" / "deployment.md").read_text(encoding="utf-8")
    block = doc[doc.index("阶段 1/6"):]
    block = block[:block.index("```")]
    lines = [ln for ln in block.splitlines() if ln.strip()]

    widths = {_width(ln) for ln in lines if "━" in ln or ln.lstrip().startswith("──")}
    assert widths == {56}, [(_width(ln), ln) for ln in lines]


def test_the_documented_stage_block_pairs_headers_with_the_stage_that_prints_them():
    """A 小节 header must sit under the stage that actually prints it.

    `── 前置检查 ──` is emitted by stage_cert, which is 阶段 5/6; the first
    draft of the guide showed it under 阶段 3/6 because the capture had been
    stitched together by hand. A reader who trusts it goes looking for the
    port probe in the wrong stage.
    """
    doc = (APP_TREE / "docs" / "deployment.md").read_text(encoding="utf-8")
    block = doc[doc.index("阶段 1/6"):]
    block = block[:block.index("```")]

    # Which stage is in force when each phase header appears?
    stage = None
    for line in block.splitlines():
        if line.startswith("阶段 "):
            stage = line.split()[1]              # e.g. "5/6"
        elif "── 前置检查" in line:
            assert stage == "5/6", (stage, line)
    # The jump from 1/6 to 5/6 has to be announced, or it reads as a capture
    # that lost three stages.
    assert "省略阶段 2" in block


# ---------------------------------------------------------------------------
# default_server: does an IP-direct share link still reach dlproxy?
#
# Measured on nginx 1.28.3 with six vhost pairings (each block on its own CN so
# the handshake says who answered): when another server on the same listen holds
# the default, a request with no SNI is answered by that server, and
# `server_name _` does not change it. So installing onto a box that already
# serves a site silently breaks https://<IP>/u/<token>/... — everything works
# until the operator tries the link form that has no domain in it.
#
# Claiming the default is the fix, and it is only safe when nobody else has:
# two `default_server` on one listen is `[x] a duplicate default server` at
# `nginx -t`, which would abort the install. Hence the probe.
# ---------------------------------------------------------------------------


def _sites_env(tmp_path: Path, files: dict[str, str]) -> dict[str, str]:
    """A sites-available directory plus a path for our own site inside it."""
    d = tmp_path / "sites-available"
    d.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        (d / name).write_text(body, encoding="utf-8")
    return {"SITES_AVAILABLE_DIR": d.as_posix(), "DLPROXY_SITE_FILE": (d / "dlproxy").as_posix()}


def test_the_default_server_is_claimed_when_the_field_is_free(tmp_path: Path) -> None:
    env = _sites_env(tmp_path, {"other": "server {\n    listen 443 ssl;\n}\n"})
    r = bash("claim_default_server", env=env)
    assert r.stdout == " default_server", (r.stdout, r.stderr)
    assert r.returncode == 0, r.stderr


def test_an_occupied_default_server_is_left_alone(tmp_path: Path) -> None:
    """Claiming it anyway is `[emerg] a duplicate default server`, not a warning."""
    env = _sites_env(tmp_path, {"other": "server {\n    listen 443 ssl default_server;\n}\n"})
    r = bash("claim_default_server", env=env)
    assert r.stdout == "", (r.stdout, r.stderr)
    assert "已声明 default_server" in r.stderr, (r.stdout, r.stderr)
    assert "IP 直连" in r.stderr


def test_our_own_site_is_not_mistaken_for_a_holder(tmp_path: Path) -> None:
    """A re-run reads the site we wrote last time; it must not block itself."""
    env = _sites_env(
        tmp_path,
        {"dlproxy": "server {\n    listen 443 ssl default_server;\n}\n"},
    )
    r = bash("claim_default_server", env=env)
    assert r.stdout == " default_server", (r.stdout, r.stderr)


def test_a_default_server_on_another_port_does_not_count(tmp_path: Path) -> None:
    """Only the 443 listen matters; 8443 is a different socket entirely."""
    env = _sites_env(tmp_path, {"other": "server {\n    listen 8443 ssl default_server;\n}\n"})
    r = bash("claim_default_server", env=env)
    assert r.stdout == " default_server", (r.stdout, r.stderr)
