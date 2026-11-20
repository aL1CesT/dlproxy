#!/usr/bin/env bash
# deploy.sh — idempotent installer for dlproxy on Ubuntu 24.04 arm64 (minimal).
#
#   sudo ./deploy.sh              do everything
#   sudo ./deploy.sh --stage deps     apt packages, venv, python deps
#   sudo ./deploy.sh --stage app      files, unit, database
#   sudo ./deploy.sh --stage nginx    nginx site + reload
#   sudo ./deploy.sh --stage cert     certbot (IP certificate) + renewal
#   sudo ./deploy.sh --stage final    logrotate, cron, health checks
#
# Every stage is safe to re-run: nothing is deleted, files are rewritten in
# place, and the database is created only if absent.
#
# Deliberate choices, each of which cost a bug somewhere:
#   * ufw is never touched. Cloud vendors warn that enabling ufw on an instance
#     can make it unreachable; firewall changes belong in the cloud firewall.
#   * iptables is only installed when INPUT policy is DROP, because on a
#     default-accept host it would add a dependency and fix nothing.
#   * certbot comes from snap. Ubuntu's apt certbot is 2.9, which predates IP
#     identifier support — the whole certificate plan needs >= 5.
#   * the venv is created with --system-site-packages OFF and pip is never run
#     as root outside it (PEP 668 is enforced by libpython3.12-stdlib).
set -euo pipefail

APP_DIR="/opt/dlproxy"
APP_USER="dlproxy"
SERVICE="dlproxy"
NGINX_SITE="/etc/nginx/sites-available/dlproxy"
LOG_DIR="/var/log/dlproxy"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# How to run python as the service user. Root has to drop privileges or the
# -wal/-shm files it creates make the service itself unable to write. Kept in
# an array so the tests can swap in a no-op and point APP_DIR at a scratch tree.
APP_PY_RUNNER=(sudo -u "$APP_USER")

STAGE="all"
SHARE443=0
SKIP_CERT=0
TLS_SERVICE_PORT=""
DLPROXY_TLS_PORT="8443"
STRIP_PORT="8441"
DLPROXY_HOST=""
# TLS 标识用的是域名而不是 IP。空 = 走 IP 证书（默认）。
DOMAIN=""

# Colour is opt-in. Under systemd, in a pipe, or with NO_COLOR set there is
# nobody to interpret an escape sequence, and `sudo ./deploy.sh > log` used to
# write raw \033[32m into the log. One place decides, every helper asks it.
if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-}" != "dumb" ]]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIMC=$'\033[2m'; RST=$'\033[0m'
else
  RED=''; GRN=''; YEL=''; DIMC=''; RST=''
fi

usage() {
  cat <<'EOF'
用法: sudo ./deploy.sh [选项]

  --stage all|deps|app|nginx|cert|final   只跑某个阶段（默认 all）
  --share-443                             与已占用 443 的其他 TLS 服务共存（按 SNI 分流）
  --tls-service-port N                    --share-443 时原服务的监听端口（必填）
  --domain HOST                           用域名签发证书（默认用 IP 证书）
  --dlproxy-host HOST                     share-443 时把某个域名的 SNI 抢回 dlproxy
  --tls-port N                            share-443 时 dlproxy 的回环 TLS 端口（默认 8443）
  --strip-port N                          share-443 时 PROXY 剥头器的端口（默认 8441）
  --skip-cert                             跳过证书签发，先用临时自签证书跑起来
  -h, --help                              显示本帮助

不带参数时行为与以前完全一致（等价于 --stage all）。想被逐条询问请用
  sudo ./install.sh
EOF
}

# Sourcing this file for its helpers (deploy/install.sh does that) must not run
# the argument parser: $@ then belongs to the caller and an unknown option would
# exit the wrong process.
if [[ -z "${DLPROXY_LIB_ONLY:-}" ]]; then
  _args=("$@")
  for ((i = 0; i < ${#_args[@]}; i++)); do
    case "${_args[i]}" in
      --stage)        STAGE="${_args[i+1]:-all}"; i=$((i + 1)) ;;
      --share-443)    SHARE443=1 ;;
      --tls-service-port) TLS_SERVICE_PORT="${_args[i+1]:-}"; i=$((i + 1)) ;;
      --tls-port)     DLPROXY_TLS_PORT="${_args[i+1]:-8443}"; i=$((i + 1)) ;;
      --strip-port)   STRIP_PORT="${_args[i+1]:-8441}"; i=$((i + 1)) ;;
      --dlproxy-host) DLPROXY_HOST="${_args[i+1]:-}"; i=$((i + 1)) ;;
      --domain)       DOMAIN="${_args[i+1]:-}"; i=$((i + 1)) ;;
      --skip-cert)    SKIP_CERT=1 ;;
      -h|--help)      usage; exit 0 ;;
      *)
        printf '%s[x]%s 未知参数：%s（可用 --help 查看用法）\n' "$RED" "$RST" "${_args[i]}" >&2
        exit 1 ;;
    esac
  done
  unset _args
fi

info() { printf '%s==>%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YEL" "$RST" "$*"; }
die()  { printf '%s[x]%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }

# A stage header, sized like the rest of the terminal output.
#
# 70 lines of `==>` with no boundary read as one undifferentiated wall; the
# certificate stage alone emits 32 of them. `━` rather than `─` because the
# lighter line disappears next to the `==>` arrows it is supposed to separate.
# Width is 56 columns, matching print_next_steps(), and deliberately has no
# right-hand border — paths and CJK labels make that impossible to align.
STAGE_TOTAL=6

# A second-level header inside a long stage, indented two spaces and using the
# lighter line, so it cannot be confused with a stage banner.
phase_banner() {
  # banner_width counts every multi-byte character as two columns, which is
  # right for the CJK titles but wrong for the box-drawing prefix itself — so
  # the prefix is kept out of the measurement and added at a fixed offset.
  local text="$1 "
  local cols pad fill="" i
  cols=$(banner_width "$text")
  pad=$(( 51 - cols ))                 # 2 indent + 3 for "── " + text + fill = 56
  (( pad < 0 )) && pad=0
  for (( i = 0; i < pad; i++ )); do fill+="─"; done
  printf '  %s%s%s%s%s\n' "$DIMC" "── " "$text" "$fill" "$RST"
}

# Display width of a string: 2 for every character built from multi-byte UTF-8,
# 1 per ASCII byte. Deliberately not `wc -L`: that reads the locale, and in the
# C locale a GNU wc treats every high byte as a zero-width non-printing
# character, which would silently make every banner the wrong length on a host
# that never set LANG. Decoding the bytes ourselves has no such dependency.
#
# One `od` for the whole string — the first version forked dd+od+tr per byte,
# which cost 57 processes per banner and made a plain `--stage deps` take
# several visible seconds before printing anything.
banner_width() {
  local text="$1" line c total=0
  while IFS= read -r line; do
    for c in $line; do
      if (( c >= 128 )); then
        # Continuation bytes (10xxxxxx) belong to a character already counted.
        (( (c & 0xC0) == 0x80 )) && continue
        total=$(( total + 2 ))
      else
        total=$(( total + 1 ))
      fi
    done
  done < <(printf '%s' "$text" | od -An -tu1 -v)
  printf '%s' "$total"
}

stage_banner() {
  local index="$1" title="$2"
  local head="阶段 ${index}/${STAGE_TOTAL}  ${title} "
  local cols pad
  # Display width, not byte length: every character here is 3 bytes.
  cols=$(banner_width "$head")
  pad=$(( 56 - cols ))
  (( pad < 0 )) && pad=0
  local fill=""
  # tr cannot build this: '━' is three bytes and tr works byte-wise, which
  # yields a run of \342. Concatenating in a loop is the only portable way.
  local i
  for (( i = 0; i < pad; i++ )); do fill+="━"; done
  # The trailing blank line belongs to the banner, not to the caller: a stage
  # that prints nothing of its own still ends up with air around the header.
  printf '\n%s%s%s%s\n\n' "$DIMC" "$head" "$fill" "$RST"
}

# Is anything listening on a TCP port?
#
# `ss` lives in iproute2, which a *minimal* Ubuntu image does not ship. Using it
# bare makes `ss: command not found` look exactly like "nothing is listening" —
# which made the share-443 branch claim the other TLS service was down on a
# healthy host. Fall back to /proc/net/tcp{,6} when ss is absent.
# /proc/net/tcp row parser, kept separate so a test can feed it a fixture file.
# The awk field layout is easy to get subtly wrong and impossible to eyeball on
# a live host. st 0A == LISTEN; field 2 is HEXIP:HEXPORT (32 hex digits for v6).
_proc_net_listening() {
  local hexport="$1"
  shift
  awk -v p="$hexport" '$4 == "0A" { n = split($2, a, ":"); if (a[n] == p) found = 1 } END { exit !found }' "$@"
}

port_listening() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -lntH "sport = :$port" 2>/dev/null | grep -q .
    return
  fi
  # /proc/net/tcp format: sl local_address rem_address st ...
  # local_address is HEXIP:HEXPORT and st 0A means LISTEN. Split on ':' and
  # compare the last field: an offset-based substr() is off by one and silently
  # reports "not listening" for real ports.
  local hexport dir
  hexport=$(printf '%04X' "$port")
  dir="${PROC_NET_DIR:-/proc/net}"
  _proc_net_listening "$hexport" "$dir/tcp" "$dir/tcp6" 2>/dev/null
}

need_root() { [[ $EUID -eq 0 ]] || die "需要 root 权限，请以 sudo 运行：sudo ./deploy.sh"; }

# `http2 on;` is a standalone directive added in nginx 1.25.1. Ubuntu 24.04
# ships 1.24.0, where the same statement is an *unknown directive* and
# `nginx -t` aborts with `unknown directive "http2"` — which is exactly how the
# first real deployment died. 1.24 does support the older form
# `listen ... ssl http2`, still accepted (with a deprecation warning) by 1.25+.
#
# So ask nginx which spelling it accepts rather than sniffing the version
# string: the answer depends only on the binary that will actually parse the
# generated site. Returns 0 when `http2 on;` is understood, 1 when the older
# `listen ... ssl http2` form is the one to emit.
http2_supports_standalone() {
  # Escape hatch, and the only sane way to test both branches on a host whose
  # nginx cannot be swapped out: DLPROXY_HTTP2=standalone|listen forces the
  # answer. Anything else falls through to the probe.
  case "${DLPROXY_HTTP2:-}" in
    standalone) return 0 ;;
    listen) return 1 ;;
  esac
  local probe rc=0
  probe=$(mktemp -d)
  mkdir -p "$probe/logs" "$probe/t1" "$probe/t2" "$probe/t3" "$probe/t4" "$probe/t5"
  cat > "$probe/probe.conf" <<PROBE
pid $probe/nginx.pid;
error_log stderr;
events { worker_connections 8; }
http {
    client_body_temp_path $probe/t1;
    proxy_temp_path $probe/t2;
    fastcgi_temp_path $probe/t3;
    uwsgi_temp_path $probe/t4;
    scgi_temp_path $probe/t5;
    server { listen 127.0.0.1:45997; http2 on; }
}
PROBE
  nginx -t -c "$probe/probe.conf" -p "$probe/" >/dev/null 2>&1 || rc=$?
  rm -rf "$probe"
  (( rc == 0 ))
}

# Rewrite the __HTTP2_DIRECTIVE__ placeholder in a rendered site into whatever
# this nginx understands. Split out of stage_nginx so it can be tested against
# the real templates without a root shell, a venv or a certificate.
apply_http2_spelling() {
  local site="$1"
  if http2_supports_standalone; then
    sed -i "s|^[[:space:]]*__HTTP2_DIRECTIVE__[[:space:]]*\$|    http2 on;|" "$site"
    return 0
  fi
  info "当前 nginx 不支持独立的 http2 指令（版本 < 1.25.1），改用 listen ... ssl http2"
  # Drop the placeholder line entirely, then hang `http2` on every listen line
  # that carries the ssl flag. The share-443 template listens with
  # `ssl proxy_protocol` rather than a bare `ssl;`, so match the flag anywhere
  # on the line instead of pinning one exact spelling.
  sed -i "/^[[:space:]]*__HTTP2_DIRECTIVE__[[:space:]]*\$/d" "$site"
  sed -i "s|^\([[:space:]]*listen [^;]*ssl[^;]*\)\;\$|\1 http2;|" "$site"
}


# Probe the *capability*, not the version string.
#
# `nginx -V` is the obvious check and the wrong one: on a fresh minimal image
# nginx is not installed yet, the command fails, and grep sees no
# --with-stream, so the script claims "your nginx lacks the stream module" on a
# machine that has no nginx at all. It is also wrong the other way round — the
# Debian/Ubuntu package builds stream as a *dynamic* module, so `nginx -V`
# shows --with-stream=dynamic and the module is only live once
# modules-enabled/50-mod-stream.conf is loaded.
#
# So we ask nginx itself: feed it a three-line stream{} config and read the
# verdict. This exercises the module, its load_module line and ssl_preread in
# one shot, and works the same whether stream is built in or dynamic.
nginx_stream_ready() {
  command -v nginx >/dev/null 2>&1 || return 2
  local probe
  probe=$(mktemp -d)
  mkdir -p "$probe/logs"
  # `-c <probe>` replaces the distro's nginx.conf wholesale, so the load_module
  # lines in it are gone too. On Ubuntu stream IS a dynamic module, so without
  # this include the probe reports "unknown directive stream" on a perfectly
  # configured host — the same false negative in new clothing.
  local mods=""
  local mods_glob="${NGINX_MODULES_GLOB:-/etc/nginx/modules-enabled/*.conf}"
  if compgen -G "$mods_glob" >/dev/null 2>&1; then
    mods="include $mods_glob;"
  fi
  # error_log/pid are pinned inside the temp dir: nginx tries to open
  # <prefix>/logs/error.log before it even parses the config, and a failure
  # there makes `nginx -t` exit 1 for a reason that has nothing to do with
  # stream support. Port 45999 is never bound — `nginx -t` only parses.
  cat > "$probe/probe.conf" <<PROBE
# probe only — nothing ever starts this server, `nginx -t` does the work.
# If stream{} or ssl_preread is unavailable, nginx -t rejects it here.
$mods
pid $probe/nginx.pid;
error_log stderr;
events { worker_connections 16; }
stream {
    server {
        listen 127.0.0.1:45999;
        ssl_preread on;
        proxy_pass 127.0.0.1:45998;
    }
}
PROBE
  local out rc=0
  out=$(nginx -t -c "$probe/probe.conf" -p "$probe/" 2>&1) || rc=$?
  rm -rf "$probe"
  if (( rc == 0 )); then
    return 0
  fi
  # Distinguish "nginx has no stream support" from every other reason a probe
  # can fail (bad path, missing logs dir, ...). Only an unknown directive or a
  # module that failed to load is a capability failure.
  if printf '%s' "$out" | grep -qE 'unknown directive "(stream|ssl_preread|proxy_pass)"|unknown "stream"|module .* is not binary compatible|dlopen\(\) .* failed'; then
    printf '%s\n' "$out" >&2
    return 1
  fi
  # Config was rejected for a mundane reason (permissions, temp dir). That is
  # not a capability problem — stay out of the way and let stage_nginx fail
  # loudly if it really cannot write its site.
  return 0
}

# Install the dynamic stream module if the running nginx needs it. Debian and
# Ubuntu ship `stream` as libnginx-mod-stream, whose file list contains
# /usr/share/nginx/modules-available/mod-stream.conf; nginx only loads it after
# a symlink appears in modules-enabled/. `apt-get install nginx` does NOT pull
# it in.
ensure_nginx_stream() {
  local mod_conf="/etc/nginx/modules-enabled/50-mod-stream.conf"
  local avail="/usr/share/nginx/modules-available/mod-stream.conf"

  if nginx_stream_ready; then
    return 0
  fi

  info "nginx 缺少 stream/ssl_preread 能力，尝试安装 libnginx-mod-stream"
  apt-get install -y --no-install-recommends libnginx-mod-stream >/dev/null 2>&1 || true

  if [[ -f "$avail" && ! -e "$mod_conf" ]]; then
    ln -sf "$avail" "$mod_conf"
    info "已启用 $mod_conf"
  fi

  nginx_stream_ready && return 0

  die "nginx 仍不具备 stream + ssl_preread 能力，无法共用 443。
  排查：nginx -V 2>&1 | tr ' ' '\n' | grep -i stream
  若只有 --with-stream=dynamic，说明动态模块没被加载，检查 /etc/nginx/modules-enabled/。"
}

# ---------------------------------------------------------------------------
# Domain or IP
#
# One identifier decides three things at once: the certbot lineage name, the
# /etc/letsencrypt/live/<id>/ path nginx points at, and the server_name. Deriving
# all three from one function is what stops a half-done domain switch (new
# certificate, old server_name) from shipping.
# ---------------------------------------------------------------------------
validate_domain() {
  local d="$1"
  [[ "$d" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] \
    || die "--domain 只接受完整域名（例如 dl.example.com），收到：$d"
}

# Lowercased domain when --domain was given, otherwise the public IP. This is
# both the certbot lineage name and the host part of public_base.
cert_id() {
  if [[ -n "${DOMAIN:-}" ]]; then
    printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]'
  else
    printf '%s' "${PUBLIC_IP:-}"
  fi
}

# nginx server_name: the domain when there is one, otherwise the catch-all "_"
# (an IP certificate cannot be matched by name, so the site stays a catch-all).
server_name_value() {
  if [[ -n "${DOMAIN:-}" ]]; then
    cert_id
  else
    printf '_'
  fi
}

# What the operator has to remember about renewals. The two certificate types
# differ enough that a single sentence cannot cover both:
#
# An IP certificate lives 160 hours, so its authorization reuse period (7 h) is
# far shorter than the renewal interval and every renewal needs a fresh http-01
# challenge -- port 80 has to stay reachable permanently. A domain certificate
# lives ~90 days and reuses its authorization, so repeating the same warning
# there would be noise, and noise is what teaches people to skip the summary.
renewal_reminder() {
  local id="${1:-$(cert_id)}"
  if [[ -n "${DOMAIN:-}" ]]; then
    info "提醒：$id 的证书有效期约 90 天，由 snap 定时器自动续期"
  else
    info "提醒：短命证书每次续期都要重跑 http-01，80 端口必须长期对公网开放"
  fi
}

# ---------------------------------------------------------------------------
# Stage 0 — preflight facts
# ---------------------------------------------------------------------------
# Which process is holding a listening port?
#
# preflight used to treat "port 80 is busy" as a hard conflict. On every host
# that already serves a site — i.e. every re-run of this script — the thing
# holding :80 is nginx, which is exactly the service stage_nginx reconfigures
# and reloads. So the installer refused to upgrade its own web server, and the
# operator saw "[x] 端口 80 已被占用" while `ss -tlnp` showed nothing but nginx.
#
# What matters is *who* holds the port: nginx rebinds fine on reload, anything
# else means nginx can never bind and the install would leave the box with a
# dead :80. Empty output means "listening but the owner is unknown".
port_owner() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    local via_ss
    via_ss=$(ss -lntpH "sport = :$port" 2>/dev/null \
      | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -1)
    [[ -n "$via_ss" ]] && { printf '%s\n' "$via_ss"; return 0; }
    # ss may be present but unable to name the owner (older iproute2, or a
    # socket held by a different user). Fall through to the inode walk rather
    # than reporting "nobody", which would be read as "port is free".
  fi
  local dir="${PROC_NET_DIR:-/proc/net}" root="${PROC_ROOT:-/proc}"
  local inodes pid fd target inode name tgid
  inodes=$(
    { cat "$dir/tcp"; cat "$dir/tcp6"; } 2>/dev/null \
      | awk -v p="$(printf '%04X' "$port")" '$4 == "0A" { n = split($2, a, ":"); if (a[n] == p) print $10 }'
  ) || true
  [[ -n "$inodes" ]] || return 0
  for pid in "$root"/[0-9]*; do
    for fd in "$pid"/fd/*; do
      target=$(readlink "$fd" 2>/dev/null) || continue
      [[ "$target" == socket:\[*\] ]] || continue
      # readlink gives "socket:[12345]"; the inode column is bare, so both the
      # "socket:[" prefix and the "]" suffix have to come off. Stripping only
      # the prefix leaves "12345]" and never matches.
      inode=${target#socket:[}
      inode=${inode%]}
      if grep -qxF "$inode" <<<"$inodes" 2>/dev/null; then
        # /proc/[0-9]* matches thread ids too, and a thread's comm is its own
        # name — uvicorn's reader threads are "MainThread", not "python". That
        # made the 8080 check below think a python process was a stranger.
        # Tgid is the process every thread belongs to, so resolve through it.
        tgid=$(awk '/^Tgid:/ { print $2; exit }' "${pid}/status" 2>/dev/null || true)
        name=""
        if [[ -n "$tgid" && -r "${root}/${tgid}/comm" ]]; then
          name=$(cat "${root}/${tgid}/comm" 2>/dev/null || true)
        fi
        [[ -n "$name" ]] || name=$(cat "${pid}/comm" 2>/dev/null || true)
        [[ -n "$name" ]] && { printf '%s\n' "$name"; return 0; }
      fi
    done
  done
  return 0
}

# Servers this script is allowed to take the port from. They are all reconfigured
# in place, so "already listening" is the normal state, not a conflict.
ADOPTABLE_RE='^(nginx|httpd|apache2|caddy|openresty)$'

# Should our :443 block claim `default_server`?
#
# Measured against nginx 1.28.3 (see the note above stage_nginx): when another
# vhost on the same listen holds the default, a request with no SNI — i.e. the
# IP-direct form https://203.0.113.9/u/<token>/... — is answered by *that* site,
# not by us. `server_name _` does not help; `_` only wins when nothing else
# matches, and the default server always matches. So an install on a box that
# already serves a site silently breaks every IP-based share link.
#
# Claiming it is only safe when nobody else has: two `default_server` on one
# listen is `[emerg] a duplicate default server for 0.0.0.0:443` at `nginx -t`,
# which would abort the install. Hence the probe rather than a fixed choice.
default_server_suffix() {
  local dir="${SITES_AVAILABLE_DIR:-/etc/nginx/sites-available}"
  # NGINX_SITE is assigned unconditionally near the top of this file, so an env
  # override never reaches it; DLPROXY_SITE_FILE exists so a test (or a capture)
  # can point the probe at a scratch directory.
  local ours="${DLPROXY_SITE_FILE:-$NGINX_SITE}"
  local f mine
  # Two command substitutions inside one [[ ]] trip a parser bug in the MSYS
  # build of bash 5.3 ("unexpected EOF while looking for matching `)'"), so the
  # target is resolved once, before the loop.
  mine=$(readlink -f "$ours" 2>/dev/null || printf '%s' "$ours")
  for f in "$dir"/*; do
    [[ -f "$f" ]] || continue
    [[ "$(readlink -f "$f" 2>/dev/null || printf '%s' "$f")" == "$mine" ]] && continue
    # The port has to be 443, not 8443: `[^0-9]` on both sides of the number is
    # what makes the difference, and it still matches `[::]:443`.
    if grep -Eq '^[[:space:]]*listen[^;]*[^0-9]443[^0-9][^;]*default_server' "$f" 2>/dev/null; then
      printf '%s\n' "$f"
      return 0
    fi
  done
  return 1
}

# Claim the default server when the field is free, and say so plainly when it is
# not — the operator needs to know that IP-based links will answer with the
# other site, because nothing else in this installer will.
claim_default_server() {
  local holder
  if holder=$(default_server_suffix); then
    # stdout of this function is the value substituted into the template, so
    # every diagnostic has to go to stderr — a plain warn() would be captured
    # by the caller's $(...) and end up inside nginx.conf.
    {
      warn "$holder 已声明 default_server，本服务无法再声明（nginx 只允许一个）。"
      warn "  影响：无 SNI 的 IP 直连（https://<IP>/u/...）将由该站点应答，不是本服务。"
      warn "  建议：用 --domain 部署，加速链接用 域名 而非 IP。"
    } >&2
    printf '%s' ""
    return 1
  fi
  printf '%s' " default_server"
  return 0
}

exclusive_preflight() {
  local port owner
  for port in 80 443; do
    port_listening "$port" || continue
    owner=$(port_owner "$port")
    if [[ "$owner" =~ $ADOPTABLE_RE ]]; then
      info "端口 $port 当前由 $owner 监听，本脚本将接管该实例并 reload"
      continue
    fi
    if [[ -z "$owner" ]]; then
      die "端口 $port 已被占用，但无法确认占用进程（非 root 时看不到其他用户创建的 socket）。
  为避免留下无法绑定的 nginx，安装已中止。
  查看占用：ss -lntp | grep :$port     （若无 ss：cat /proc/net/tcp）"
    fi
    die "端口 $port 已被 $owner 占用，nginx 无法绑定该端口。
  本脚本不会停止其他服务。请先停止 $owner 后重试。
  查看占用：ss -lntp | grep :$port"
  done

  if port_listening 8080; then
    local o8080
    o8080=$(port_owner 8080)
    if [[ "$o8080" == "python"* || "$o8080" == "uvicorn"* ]]; then
      info "8080 由 $o8080 监听，判断为本服务实例，stage app 将重启它"
    else
      warn "8080 已被 ${o8080:-未知进程} 占用；若非本服务，stage app 将无法绑定"
    fi
  fi
  info "80 / 443 / 8080 端口检查通过"
}

preflight() {
  [[ -r /etc/os-release ]] && . /etc/os-release
  info "系统：${PRETTY_NAME:-unknown} / $(uname -m) / $(nproc) 核"
  [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]] \
    || warn "当前架构不是 aarch64，安装将继续"

  local free_kb
  free_kb=$(df -Pk / | awk 'NR==2 {print $4}')
  info "根分区可用空间：$((free_kb / 1024)) MiB"
  (( free_kb > 512 * 1024 )) || warn "磁盘余量不足 512 MiB，下载内容不落盘，仍建议关注日志目录占用"

  # --domain only changes the certificate identifier, so it is validated here
  # where every stage still gets the answer, not deep inside stage_cert.
  [[ -n "${DOMAIN:-}" ]] && validate_domain "$DOMAIN"

  if (( SHARE443 )); then
    share443_preflight
  else
    exclusive_preflight
  fi
}

# ---------------------------------------------------------------------------
# share-443 — coexist with another TLS service that already owns :443
#
# The node already owns 443, so "port 443 is busy" is the expected state, not an
# error. What must be checked instead is that (a) the stream module is compiled
# in, (b) the node's port is actually listening, and (c) 443 is held by something
# we can preempt at nginx start — nginx will fail to bind otherwise.
# ---------------------------------------------------------------------------
share443_preflight() {
  (( SHARE443 )) || return 0

  # Capability check happens here, but only when nginx is already on the box.
  # On a fresh machine preflight runs before stage_deps installs anything, so a
  # missing nginx is "not yet", not "broken". stage_deps installs it and
  # stage_nginx calls ensure_nginx_stream again once it exists.
  if command -v nginx >/dev/null 2>&1; then
    nginx_stream_ready \
      || die "本机 nginx 缺少 stream 与 ssl_preread 能力，无法共用 443。
  若 nginx -V 中包含 --with-stream=dynamic，说明动态模块未加载：
  apt-get install -y libnginx-mod-stream && ln -sf /usr/share/nginx/modules-available/mod-stream.conf /etc/nginx/modules-enabled/50-mod-stream.conf"
    info "nginx stream 与 ssl_preread 能力检查通过"
  else
    info "本机尚未安装 nginx，stage deps 阶段将安装 libnginx-mod-stream"
  fi

  [[ -n "$TLS_SERVICE_PORT" ]] || die "--share-443 必须同时指定原服务的监听端口，例如：
    sudo ./deploy.sh --share-443 --tls-service-port 10443
  可用 ss -lntp 查看原服务实际监听端口。"

  if ! port_listening "$TLS_SERVICE_PORT"; then
    die "端口 $TLS_SERVICE_PORT 当前无监听，443 尚不能交给 nginx。

  请按以下顺序操作后重跑本脚本：
    1. 将原服务的监听端口改为 $TLS_SERVICE_PORT 并重启
    2. 执行 ss -lntp | grep $TLS_SERVICE_PORT，确认端口已监听
    3. 客户端仍连接 域名:443，确认原服务可正常使用
    4. 重新运行本脚本

  若原服务实际监听其他端口，请以该端口重跑：
    sudo ./deploy.sh --share-443 --tls-service-port <实际端口>"
  fi
  info "端口 $TLS_SERVICE_PORT 已处于监听状态"

  for port in "$DLPROXY_TLS_PORT" "$STRIP_PORT"; do
    if port_listening "$port"; then
      die "内部端口 $port 已被占用，请用 --tls-port 指定其他端口（当前 $DLPROXY_TLS_PORT）。"
    fi
  done
  info "内部端口 $DLPROXY_TLS_PORT / $STRIP_PORT 均空闲"

  # If :443 is held by the node itself, nginx cannot bind and the switchover
  # would leave the box with no working 443 at all. Refuse instead of guessing.
  if port_listening 443; then
    warn "443 当前被占用（预期为原服务监听在此）。"
    warn "启用 share-443 后 443 必须交给 nginx，原服务需迁移至 --tls-service-port 指定的端口。"
    warn "顺序：先将原服务改为监听 $TLS_SERVICE_PORT，确认它仍可用后再运行本脚本。"
    warn "本脚本不会修改其他服务的配置。"
    die "请先将原服务从 443 迁至 $TLS_SERVICE_PORT，再重跑本脚本。"
  fi
  info "443 空闲，可以交给 nginx stream 层"
}

# ---------------------------------------------------------------------------
# Stage 1 — dependencies
# ---------------------------------------------------------------------------
stage_deps() {
  export DEBIAN_FRONTEND=noninteractive

  # universe is where python3-venv and certbot live on a minimal image.
  if ! grep -rqE '^\s*deb .*ubuntu\.com.*\buniverse\b' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
    warn "未检测到 universe 源，尝试补充"
    if command -v add-apt-repository >/dev/null; then
      add-apt-repository -y universe
    else
      apt-get install -y software-properties-common >/dev/null
      add-apt-repository -y universe
    fi
  fi

  apt-get update -qq
  apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    nginx libnginx-mod-stream sqlite3 openssl ca-certificates curl \
    logrotate cron iproute2

  # `apt-get install nginx` does not pull the stream module in: on noble it
  # lives in libnginx-mod-stream and only becomes active once
  # modules-enabled/50-mod-stream.conf exists. share-443 needs it; verify by
  # probing nginx rather than by reading --with-stream out of a version string.
  if (( SHARE443 )); then
    ensure_nginx_stream
    info "nginx stream + ssl_preread 能力已就绪"
  fi

  # iptables only where the INPUT policy is already DROP — otherwise it is an
  # unused dependency on a host the cloud firewall already protects.
  if command -v iptables >/dev/null; then
    local policy
    policy=$(iptables -S INPUT 2>/dev/null | head -1 | awk '{print $3}' || true)
    [[ "$policy" == "DROP" ]] || info "INPUT 策略为 ${policy:-ACCEPT}，跳过 iptables 规则"
  fi

  info "Python: $(python3 -V)"

  info "创建服务账号 ${APP_USER}"
  id -u "$APP_USER" >/dev/null 2>&1 || \
    useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"

  info "同步应用文件到 $APP_DIR"
  install -d -m 0755 "$APP_DIR"
  install -d -m 0750 -o "$APP_USER" -g "$APP_USER" "$APP_DIR/data" "$APP_DIR/backup"
  install -d -m 0750 -o "$APP_USER" -g "$APP_USER" "$LOG_DIR"

  # rsync-like copy without rsync (minimal images do not ship it).
  cp -a "$SRC_DIR/app" "$APP_DIR/"
  install -m 0644 "$SRC_DIR/requirements.txt" "$APP_DIR/requirements.txt"
  install -d -m 0755 "$APP_DIR/deploy"
  cp -a "$SRC_DIR/deploy/." "$APP_DIR/deploy/" 2>/dev/null || true
  chown -R "$APP_USER:$APP_USER" "$APP_DIR/app"

  info "创建 venv 并安装依赖（arm64 均有预编译 wheel，无需编译器）"
  if [[ ! -x "$APP_DIR/venv/bin/python" ]]; then
    python3 -m venv "$APP_DIR/venv"
  fi
  "$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
  "$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
  "$APP_DIR/venv/bin/python" - <<'PY'
import fastapi, httpx, jinja2, argon2, itsdangerous, uvicorn
print("  依赖就绪: fastapi", fastapi.__version__, "| httpx", httpx.__version__,
      "| uvicorn", uvicorn.__version__)
PY
  chown -R "$APP_USER:$APP_USER" "$APP_DIR/venv"
}

# ---------------------------------------------------------------------------
# Stage 2 — environment file, database, systemd unit
# ---------------------------------------------------------------------------
stage_app() {
  umask 077
  if [[ ! -f "$APP_DIR/.env" ]]; then
    install -m 0600 -o "$APP_USER" -g "$APP_USER" \
      "$SRC_DIR/deploy/env.example" "$APP_DIR/.env"
    local key
    key=$(openssl rand -hex 32)
    sed -i "s|^DLPROXY_SECRET_KEY=.*|DLPROXY_SECRET_KEY=${key}|" "$APP_DIR/.env"
    info "已生成 DLPROXY_SECRET_KEY"
  else
    info ".env 已存在，沿用原有密钥"
  fi
  chmod 0600 "$APP_DIR/.env"
  chown "$APP_USER:$APP_USER" "$APP_DIR/.env"

  info "初始化数据库"
  cd "$APP_DIR"
  sudo -u "$APP_USER" "$APP_DIR/venv/bin/python" - <<'PY'
import sys
sys.path.insert(0, "/opt/dlproxy")
from app import db
conn = db.init_db()
n = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
print(f"  数据库就绪，现有用户 {n} 个")
conn.close()
PY

  info "安装 systemd 单元"
  install -m 0644 "$SRC_DIR/deploy/dlproxy.service" "/etc/systemd/system/${SERVICE}.service"
  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null
  systemctl restart "$SERVICE"
  sleep 2
  systemctl is-active --quiet "$SERVICE" || {
    journalctl -u "$SERVICE" -n 40 --no-pager || true
    die "服务启动失败，详见上方 journalctl 输出"
  }
  info "服务已启动"

  for _ in $(seq 1 20); do
    if curl -fsS --max-time 2 http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
      info "健康检查通过"
      break
    fi
    sleep 1
  done

  if [[ -f "$APP_DIR/INITIAL_ADMIN.txt" ]]; then
    echo
    warn "初始管理员凭据（请立即记录，然后删除该文件）"
    cat "$APP_DIR/INITIAL_ADMIN.txt"
    echo
    warn "删除命令： sudo rm $APP_DIR/INITIAL_ADMIN.txt"
  fi
}

# ---------------------------------------------------------------------------
# Stage 3 — nginx
# ---------------------------------------------------------------------------
stage_nginx() {
  install -d -m 0755 /var/www/certbot

  # Bootstrap problem: the site block references ssl_certificate files that do
  # not exist until stage_cert runs, and `nginx -t` refuses to load a config
  # pointing at nothing. The usual fix is a throwaway self-signed certificate so
  # nginx can start and answer the ACME http-01 challenge on port 80. stage_cert
  # then rewrites the path to the real lineage and reloads.
  if [[ ! -f /etc/ssl/private/dlproxy-bootstrap.key ]]; then
    info "生成临时自签证书（仅用于让 nginx 先行启动，stage_cert 阶段将替换）"
    openssl req -x509 -nodes -newkey rsa:2048 -days 2 \
      -keyout /etc/ssl/private/dlproxy-bootstrap.key \
      -out /etc/ssl/certs/dlproxy-bootstrap.pem \
      -subj "/CN=dlproxy-bootstrap" >/dev/null 2>&1
    chmod 0600 /etc/ssl/private/dlproxy-bootstrap.key
  fi

  local template="$SRC_DIR/deploy/nginx.conf"
  if (( SHARE443 )); then
    template="$SRC_DIR/deploy/nginx-share443.conf"
    info "使用 share-443 模板：443 由 stream 层接管，原服务端口 $TLS_SERVICE_PORT"
  fi

  # nginx 1.24 (Ubuntu 24.04) has no standalone `http2` directive; it wants the
  # flag on the listen line instead. Probe rather than guess: the first real
  # deployment died on `unknown directive "http2"` because 1.25.1+ syntax was
  # hardcoded into the template.
  # Only the exclusive template owns :443 directly. Under share-443 the stream
  # layer holds the port and routes an empty SNI to us already, so claiming a
  # default server here would warn about a problem that mode does not have.
  local default_server=""
  if (( ! SHARE443 )); then
    default_server="$(claim_default_server)"
  fi

  sed -e "s|__CERT_FULLCHAIN__|/etc/ssl/certs/dlproxy-bootstrap.pem|g" \
      -e "s|__CERT_PRIVKEY__|/etc/ssl/private/dlproxy-bootstrap.key|g" \
      -e "s|__TLS_SERVICE_PORT__|$TLS_SERVICE_PORT|g" \
      -e "s|__STRIP_PORT__|$STRIP_PORT|g" \
      -e "s|__DLPROXY_TLS_PORT__|$DLPROXY_TLS_PORT|g" \
      -e "s|__DEFAULT_SERVER__|$default_server|g" \
      -e "s|__SERVER_NAME__|$(server_name_value)|g" \
      "$template" > "$NGINX_SITE"
  apply_http2_spelling "$NGINX_SITE"
  chmod 0644 "$NGINX_SITE"
  ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/dlproxy
  rm -f /etc/nginx/sites-enabled/default

  if (( SHARE443 )); then
    install_share443_stream
  fi

  nginx -t || die "nginx 配置校验失败，未执行 reload"
  systemctl reload nginx 2>/dev/null || systemctl restart nginx
  info "nginx 已启动（当前为临时证书，待 stage_cert 阶段替换）"
}

# The exact bytes appended to /etc/nginx/nginx.conf to pull in the stream
# fragment. It must be wrapped in `stream {}`: the fragment is a main-context
# config (map/upstream/server), and a bare include at the top level makes nginx
# abort with `"map" directive is not allowed here`. Kept as its own function so
# tests and tools/e2e_share443.py can assert on the real text instead of
# re-typing it.
share443_nginx_include_block() {
  printf '\n# dlproxy share-443 (stream)\nstream {\n    include /etc/nginx/stream-enabled/*.conf;\n}\n'
}

# Stream-level fragment for share-443. It lives in stream-enabled/ because
# sites-enabled/ is included inside the http{} block, where a `stream {}` block
# is a syntax error. The include block is appended to nginx.conf once.
install_share443_stream() {
  local stream_dir="/etc/nginx/stream-enabled"
  local stream_site="$stream_dir/dlproxy.conf"
  install -d -m 0755 "$stream_dir"

  # Which SNI names belong to dlproxy rather than to the node. Two sources:
  #   --domain        the name the certificate is issued for; without an entry
  #                   here its traffic would be routed to the node and never
  #                   reach the site the certificate was bought for.
  #   --dlproxy-host  an extra name to pull back from the node.
  local sni_entry=""
  local sni_seen=""
  local sni_host
  for sni_host in ${DOMAIN:-} ${DLPROXY_HOST:-}; do
    [[ "$sni_host" =~ ^[A-Za-z0-9.-]+$ ]] \
      || die "SNI 主机名只接受字母/数字/点/连字符，收到：$sni_host"
    # nginx 的 map 里 SNI 是小写比较，统一转小写避免大小写不匹配。
    sni_host="$(printf '%s' "$sni_host" | tr '[:upper:]' '[:lower:]')"
    # --domain and --dlproxy-host may name the same host; map keys must be unique.
    case " $sni_seen " in
      *" $sni_host "*) continue ;;
    esac
    sni_seen="${sni_seen}${sni_host} "
    sni_entry="${sni_entry}    ${sni_host}  dlproxy_node;"$'\n'
  done

  sed -e "s|__TLS_SERVICE_PORT__|$TLS_SERVICE_PORT|g" \
      -e "s|__STRIP_PORT__|$STRIP_PORT|g" \
      -e "s|__DLPROXY_TLS_PORT__|$DLPROXY_TLS_PORT|g" \
      "$SRC_DIR/deploy/nginx-share443-stream.conf" > "$stream_site"

  # 没有 --domain 也没有 --dlproxy-host 时整行删掉，否则 map 里会留下空 SNI 键。
  if [[ -n "$sni_entry" ]]; then
    # The replacement spans one or two lines, so it cannot go through s|..|..|.
    # Read the fragment, swap the placeholder line for the entries, write back.
    local tmp_site
    tmp_site=$(mktemp)
    awk -v entry="$sni_entry" '
      /__DLPROXY_SNI_ENTRY__/ { printf "%s", entry; next }
      { print }
    ' "$stream_site" > "$tmp_site"
    cat "$tmp_site" > "$stream_site"
    rm -f "$tmp_site"
    sed -i '/← 这一整行会被替换成/d' "$stream_site"
  else
    sed -i '/__DLPROXY_SNI_ENTRY__/d' "$stream_site"
    sed -i '/← 这一整行会被替换成/d; /deploy.sh 会把下面含/d; /不给就整行删掉/d' "$stream_site"
  fi
  chmod 0644 "$stream_site"

  # Idempotent, keyed on our own marker rather than on "is there any stream{}
  # block", because the operator may already run their own stream block for
  # something else. An earlier build appended the include WITHOUT the wrapper,
  # which aborts nginx with `"map" directive is not allowed here`; that older
  # form is detected and rewritten instead of being left broken.
  local marker='# dlproxy share-443 (stream)'
  local legacy='# dlproxy share-443'
  if grep -qF -- "$marker" /etc/nginx/nginx.conf; then
    : # already in the current form
  else
    cp -a /etc/nginx/nginx.conf "/etc/nginx/nginx.conf.bak.$(date +%Y%m%d%H%M%S)"
    if grep -qxF -- "$legacy" /etc/nginx/nginx.conf; then
      sed -i -e '\|^# dlproxy share-443$|d' \
             -e '\|^\s*include /etc/nginx/stream-enabled/\*\.conf;$|d' \
             /etc/nginx/nginx.conf
      warn "检测到旧版在顶层裸 include stream 片段，已改为 stream{} 包裹（原文件已备份）"
    else
      info "已将 stream 片段 include 至 /etc/nginx/nginx.conf（原文件已备份）"
    fi
    share443_nginx_include_block >> /etc/nginx/nginx.conf
  fi

  # Debian/Ubuntu ship stream as a dynamic module (libnginx-mod-stream); the
  # module is inert until a conf in modules-enabled/ loads it. Delegate that to
  # ensure_nginx_stream, which decides by probing nginx instead of by parsing
  # --with-stream out of `nginx -V` (that string says "dynamic" on this distro
  # even when the module is perfectly usable).
  ensure_nginx_stream
  info "stream 片段已安装：$stream_site"
  warn "原服务必须改为监听 $TLS_SERVICE_PORT（本脚本不改动它），否则它经 443 的连接将中断。"
}

# Print what the operator does next. Split out from stage_final so the wording
# can be pinned by a test — this block is the only place the install tells you
# the site address and where INITIAL_ADMIN.txt lives, and it shipped as a bare
# placeholder for two rounds before anyone could see it.
print_next_steps() {
  local base="${1:-}" admin_line
  echo
  # No right-hand border: the content mixes CJK (2 columns), ASCII (1 column)
  # and paths of arbitrary length, so a closing │ can only be placed correctly
  # by measuring every rendered line. A left rule carries the same visual
  # grouping and cannot drift.
  echo "  ── 后续步骤 ──────────────────────────────────────────"
  echo
  if [[ -n "$base" ]]; then
    echo "  1) 访问站点      $base"
  else
    echo "  1) 访问站点      （地址未记录，可先执行： sudo dlproxy set-site https://<服务器IP>）"
  fi
  admin_line="$(saved_admin_path)"
  if [[ -n "$base" && -n "$admin_line" ]]; then
    echo "  2) 管理页        ${base}${admin_line}"
  elif [[ -n "$admin_line" ]]; then
    echo "  2) 管理页        ${admin_line}  （需在前面拼接站点地址）"
  else
    echo "  2) 管理页        （数据库中尚无 admin_path，服务启动后自动生成）"
  fi
  # The password file only exists on the first boot. Saying "cat it" on a
  # reinstall sends people after a file that was never written.
  if [[ -f "$APP_DIR/INITIAL_ADMIN.txt" ]]; then
    echo "  3) 初始账号文件  ${APP_DIR}/INITIAL_ADMIN.txt"
    echo "     查看          sudo cat ${APP_DIR}/INITIAL_ADMIN.txt"
    echo "     用后删除      sudo rm  ${APP_DIR}/INITIAL_ADMIN.txt"
  else
    echo "  3) 初始密码      本次未生成（库中已存在管理员，密码仅在首次安装时写入）"
    echo "     如需重置      sudo dlproxy   → 选择 4（重置密码）"
  fi
  echo
  echo "  4) 账号与加速链接：输入 dlproxy 后回车进入交互菜单"
  echo "     （也可用 sudo dlproxy；菜单第 5 项可直接取得完整链接）"
  echo
}

# ---------------------------------------------------------------------------
# Public base URL — the console menu and CLI print this in every link
#
# The menu runs outside any request, so it cannot derive "https://<host>" the
# way the web pages do from request.base_url. Without this row it can only show
# the "<你的域名或IP>" placeholder — which is exactly what the first real
# deployment hit. deploy.sh knows the certificate identity, so it records it.
# ---------------------------------------------------------------------------

# Run a snippet of Python inside the app environment, as the service user.
# Kept in one place so the tests can point it at a throwaway tree instead of
# /opt/dlproxy (which does not exist until stage_app has run).
app_python() {
  local code="$1"; shift
  ( cd "$APP_DIR" && "${APP_PY_RUNNER[@]}" "$APP_DIR/venv/bin/python" - "$@" <<<"$code" )
}

record_public_base() {
  local base="$1"
  [[ -n "$base" ]] || return 0
  [[ -x "$APP_DIR/venv/bin/python" ]] || return 0
  info "已写入站点地址：$base"
  app_python '
import sys
sys.path.insert(0, sys.argv[1])
from app import db
base = sys.argv[2]
conn = db.init_db()
db.set_setting(conn, "public_base", base)
db.set_setting(conn, "public_host", base.split("://", 1)[-1])
conn.close()
' "$APP_DIR" "$base" \
    || warn "站点地址写入失败，稍后可执行： sudo dlproxy set-site $base"
}

# Read the recorded base back, so stage_final can print a real URL.
# The admin path, straight from the database.
#
# print_next_steps used to grep it out of INITIAL_ADMIN.txt — but that file only
# exists on the very first boot. On a reinstall the database already has an
# admin, _bootstrap() returns early, nothing is written, and the grep comes back
# empty: the install then tells a working host that its admin page is
# "见下面的 INITIAL_ADMIN.txt" — a file it just said to delete. Read the row.
saved_admin_path() {
  [[ -x "$APP_DIR/venv/bin/python" ]] || return 0
  app_python '
import sys
sys.path.insert(0, sys.argv[1])
from app import db
conn = db.init_db()
value = db.get_setting(conn, "admin_path", "")
conn.close()
print("/" + value if value else "")
' "$APP_DIR" 2>/dev/null || true
}

saved_public_base() {
  [[ -x "$APP_DIR/venv/bin/python" ]] || return 0
  app_python '
import sys
sys.path.insert(0, sys.argv[1])
from app import db
conn = db.init_db()
value = db.get_setting(conn, "public_base", "")
conn.close()
print(value if value and not db.is_placeholder_base(value) else "")
' "$APP_DIR" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Stage 4 — certificate
# ---------------------------------------------------------------------------
stage_cert() {
  if (( SKIP_CERT )); then
    warn "已指定 --skip-cert：保留临时自签证书，浏览器将提示证书不受信任"
    if [[ -n "${DOMAIN:-}" ]]; then
      record_public_base "https://$(cert_id)"
    else
      local guess="${PUBLIC_IP:-${DLPROXY_HOST:-$(curl -fsS --max-time 5 https://api.ipify.org || true)}}"
      [[ -n "$guess" ]] && record_public_base "https://${guess}"
    fi
    warn "需要正式证书时执行：sudo ./deploy.sh --stage cert"
    return 0
  fi
  if [[ -n "${DOMAIN:-}" ]]; then
    echo "  有效期约 90 天，剩余 30 天自动续期（Let's Encrypt 域名证书）"
  else
    echo "  有效期 6 天，每 80 小时自动续期（Let's Encrypt IP 证书）"
  fi
  PUBLIC_IP="${PUBLIC_IP:-$(curl -fsS --max-time 5 https://api.ipify.org || true)}"
  [[ -n "$PUBLIC_IP" ]] || die "无法确定公网 IP，请用 PUBLIC_IP=x.x.x.x sudo ./deploy.sh --stage cert"

  local CERT_ID
  CERT_ID="$(cert_id)"
  if [[ -n "${DOMAIN:-}" ]]; then
    if [[ "$DOMAIN" != "$CERT_ID" ]]; then
      info "证书标识: $CERT_ID（域名，已转小写；DNS 不区分大小写，证书只认小写）"
    else
      info "证书标识: $CERT_ID（域名）"
    fi
    info "公网 IP: $PUBLIC_IP"
    echo "  前提：$CERT_ID 的 A/AAAA 记录已指向这台机器。"
    echo "  验证：dig +short $CERT_ID   （应包含 $PUBLIC_IP）"
  else
    info "证书标识: $CERT_ID（IP）"
    info "公网 IP: $PUBLIC_IP"
  fi
  phase_banner "前置检查"
  info "探测 80 端口公网可达性（ACME HTTP-01 需要）"
  # Must not use `curl -f` on a body: the :80 server block answers 301 for
  # everything except the ACME path, so a body-based check sees zero bytes and
  # reports a false failure. Any HTTP status proves nginx is reachable.
  if command -v curl >/dev/null; then
    local code
    code=$(curl -s -o /dev/null --max-time 8 \
      -w '%{http_code}' "http://${CERT_ID}/" 2>/dev/null || echo 000)
    if [[ "$code" == "000" ]]; then
      warn "从本机访问 http://${CERT_ID}/ 没有响应（连 TCP 都没通）。"
      if [[ -n "${DOMAIN:-}" ]]; then
        warn "两种可能：云防火墙没有放行 80 端口，或者 $CERT_ID 没有解析到这台机器。"
      else
        warn "这通常意味着云防火墙没有放行 80 端口。"
      fi
      warn "请到云控制台的安全组 / 防火墙，添加 0.0.0.0/0 的 TCP 80 与 443 入站规则。"
      die "放行后重新运行：sudo ./deploy.sh --stage cert"
    fi
    info "80 端口可达（HTTP $code）"
  fi

  phase_banner "申请"
  if ! command -v certbot >/dev/null; then
    info "通过 snap 安装 certbot（apt 版本过旧，不支持 IP 证书）"
    if ! command -v snap >/dev/null; then
      apt-get install -y snapd
    fi
    timeout 600 snap install --classic certbot
    ln -sf /snap/bin/certbot /usr/bin/certbot
  fi
  certbot --version

  # --preferred-profile over --required-profile: "required" has no fallback, so a
  # server-side profile change turns into a hard renewal failure. "preferred"
  # degrades to the next acceptable profile instead.
  #
  # The identifier flag is --ip-address (certbot >= 5.3). -d also works but
  # --ip-address is explicit about the identifier type and is what the IP
  # certificate documentation uses.
  #
  # webroot is the only ACME plugin that supports IP identifiers besides
  # manual/standalone: the nginx and apache installers refuse them, so the
  # certificate is fetched here and nginx.conf is pointed at the files below.
  if [[ ! -f "/etc/letsencrypt/live/${CERT_ID}/fullchain.pem" ]]; then
    if [[ -n "${DOMAIN:-}" ]]; then
      info "签发域名证书（certbot --domain $CERT_ID）"
    # No --deploy-hook here: the directory hook under
    # /etc/letsencrypt/renewal-hooks/deploy/ covers issuance *and* renewal, and
    # also stamps the freshness file. Passing one here too would reload nginx
    # twice and would only survive in the renewal config by certbot's
    # set_by_user bookkeeping.
      # No --preferred-profile here: "shortlived" is the IP-identifier profile.
      # A domain certificate gets the default profile (~90 days, renewed at 30),
      # which is both longer-lived and the one every other tool expects.
      certbot certonly --webroot -w /var/www/certbot \
        --cert-name "$CERT_ID" \
        --domain "$CERT_ID" \
        --non-interactive --agree-tos --register-unsafely-without-email \
        || die "签发失败。常见原因：$CERT_ID 没有解析到本机，或 80 端口从公网不可达（云防火墙）。
  自查：dig +short $CERT_ID ；curl -I http://$CERT_ID/.well-known/acme-challenge/x"
    else
      info "签发 IP 证书（profile=shortlived, 有效期约 160 小时）"
      certbot certonly --webroot -w /var/www/certbot \
        --cert-name "$CERT_ID" \
        --ip-address "$CERT_ID" \
        --preferred-profile shortlived \
        --non-interactive --agree-tos --register-unsafely-without-email \
        || die "签发失败。常见原因：80 端口从公网不可达（云防火墙），或 certbot 版本不支持 --ip-address（需 >= 5.3）"
    fi
  else
    info "证书已存在，跳过签发"
  fi

  # Certificate files first, then the site that references them: sed-ing the
  # cert path into a site that is already live would make `nginx -t` fail on the
  # missing files if the order were reversed.
  info "把站点从临时证书切换到真证书"
  sed -i -e "s|/etc/ssl/certs/dlproxy-bootstrap.pem|/etc/letsencrypt/live/${CERT_ID}/fullchain.pem|" \
         -e "s|/etc/ssl/private/dlproxy-bootstrap.key|/etc/letsencrypt/live/${CERT_ID}/privkey.pem|" \
         "$NGINX_SITE"
  if ! grep -q "letsencrypt/live/${CERT_ID}/fullchain.pem" "$NGINX_SITE"; then
    warn "未能把证书路径写进 $NGINX_SITE，请手工确认"
  fi
  nginx -t && systemctl reload nginx
  if [[ -f /etc/ssl/certs/dlproxy-bootstrap.pem ]]; then
    info "删除临时自签证书"
    rm -f /etc/ssl/certs/dlproxy-bootstrap.pem \
          /etc/ssl/private/dlproxy-bootstrap.key
  fi

  record_public_base "https://${CERT_ID}"

  info "安装续期钩子（deploy 目录，随 certbot 一起对每张证书生效）"
  install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
  install -m 0755 "$SRC_DIR/deploy/renewal-hook.sh" \
    /etc/letsencrypt/renewal-hooks/deploy/dlproxy.sh
  install -d -m 0755 /var/lib/certbot
  # Seed the freshness stamp so the check does not scream until the first
  # renewal, which on a 160-hour certificate is up to 80 hours away.
  date -u +%Y-%m-%dT%H:%M:%SZ > /var/lib/certbot/last-success
  # Run the hook once now so nginx picks up the freshly issued certificate
  # through the same code path that renewals will use.
  RENEWED_LINEAGE="/etc/letsencrypt/live/${CERT_ID}" \
  RENEWED_DOMAINS="$CERT_ID" \
    /etc/letsencrypt/renewal-hooks/deploy/dlproxy.sh || warn "续期钩子执行有告警，见 journalctl -t dlproxy-cert"

  phase_banner "验证"
  info "续期演练"
  # --dry-run uses the staging endpoint and does not touch the live
  # certificate. It does prove that http-01 still works from the public
  # internet, which is the failure mode that actually bites.
  if certbot renew --dry-run --cert-name "$CERT_ID" 2>&1 | tail -5; then
    info "certbot renew --dry-run 通过"
  else
    warn "certbot renew --dry-run 失败：80 端口可能不再从公网可达。"
    if [[ -z "${DOMAIN:-}" ]]; then
      warn "短命证书每次续期都要重跑 http-01（授权复用期只有 7 小时，远短于 80 小时的续期间隔）。"
    fi
  fi

  info "安装续期定时器"
  # Do NOT add a cron job that runs `certbot renew` on a fixed schedule.
  #
  # snap ships apps.renew.timer, which fires roughly twice a day with jitter.
  # That is exactly what a 160-hour certificate needs: Let's Encrypt's guidance
  # is to check ARI at least twice a day, and certbot >= 4.0 already renews at
  # half of a short-lived certificate's lifetime (80 h here). A hand-rolled
  # 2-3 day cron would either duplicate that or fight it.
  #
  # Also never put --force-renewal on a timer: the "5 per 7 days per exact set of
  # identifiers" limit has no override and a loop would lock the IP out for a week.
  if systemctl list-timers --all 2>/dev/null | grep -q 'snap.certbot.renew.timer'; then
    info "snap 续期定时器已就位（每日约 2 次，随机偏移）"
  else
    warn "未检测到 snap.certbot.renew.timer，请检查： systemctl list-timers --all | grep certbot"
  fi

  # An IP certificate lives 160 hours, so its authorization reuse period (7 h)
  # is far shorter than the renewal interval and every renewal needs a fresh
  # http-01 challenge -- port 80 has to stay reachable permanently. A domain
  # certificate lives ~90 days and reuses its authorization, so the same warning
  # would just be noise that teaches people to ignore the summary.
  renewal_reminder "$CERT_ID"
}

# ---------------------------------------------------------------------------
# Stage 5 — logrotate, cron, verification
# ---------------------------------------------------------------------------
stage_final() {
  install -m 0644 "$SRC_DIR/deploy/logrotate.conf" /etc/logrotate.d/dlproxy
  install -m 0755 "$SRC_DIR/deploy/cert-check.sh" /usr/local/bin/dlproxy-cert-check
  install -m 0755 "$SRC_DIR/deploy/backup.sh" /usr/local/bin/dlproxy-backup
  install -m 0755 "$SRC_DIR/deploy/dlproxy-cli.sh" /usr/local/bin/dlproxy
  install -m 0644 "$SRC_DIR/deploy/cron" /etc/cron.d/dlproxy
  chmod 0644 /etc/cron.d/dlproxy
  systemctl enable --now cron >/dev/null 2>&1 || true

  info "证书自检"
  /usr/local/bin/dlproxy-cert-check || true

  info "核对监听端口"
  ss -lntp | grep -E ':(80|443|8080)\b' || warn "没有看到预期的监听端口"
  if (( SHARE443 )); then
    info "share-443 模式下的预期监听："
    echo "    443        nginx stream（按 SNI 分流）"
    echo "    $DLPROXY_TLS_PORT       nginx http（dlproxy，仅回环）"
    echo "    $STRIP_PORT       nginx stream（PROXY 剥头器，仅回环）"
    echo "    $TLS_SERVICE_PORT      原服务（你自己的 TLS 服务）"
    port_listening 443 || warn "443 没有在监听：nginx stream 没起来？"
  fi
  if ss -lntH 'sport = :8080' 2>/dev/null | grep -qv '127.0.0.1:8080'; then
    warn "8080 似乎绑定在非回环地址上，请检查 .env 的 DLPROXY_HOST"
  else
    info "8080 仅监听 127.0.0.1 ✓"
  fi

  echo
  info "部署完成"
  local base admin_line
  base="$(saved_public_base)"
  print_next_steps "$base"

  echo "  服务状态： systemctl status $SERVICE"
  echo "  实时日志： journalctl -u $SERVICE -f"
  echo "  安全日志： tail -f $LOG_DIR/security.log"
  echo
  warn "首次登录后：改密码、配 SMTP、删除 $APP_DIR/INITIAL_ADMIN.txt"
}

main() {
  need_root
  # The numbering is the position in the whole run, even when only one stage is
  # asked for: `--stage cert` is still step 5 of 6, and saying so is what tells
  # the operator how much of the install they have already done.
  case "$STAGE" in
    all)
      stage_banner 1 "环境预检";                 preflight
      stage_banner 2 "安装系统依赖";             stage_deps
      stage_banner 3 "写入环境文件";             stage_app
      stage_banner 4 "安装 nginx 站点配置";      stage_nginx
      stage_banner 5 "准备 HTTPS 证书";          stage_cert
      stage_banner 6 "安装 logrotate 与 cron";   stage_final
      ;;
    deps)
      stage_banner 1 "环境预检";                 preflight
      stage_banner 2 "安装系统依赖";             stage_deps
      ;;
    app)
      stage_banner 3 "写入环境文件";             stage_app
      ;;
    nginx)
      stage_banner 4 "安装 nginx 站点配置";      stage_nginx
      ;;
    cert)
      stage_banner 5 "准备 HTTPS 证书";          stage_cert
      ;;
    final)
      stage_banner 6 "安装 logrotate 与 cron";   stage_final
      ;;
    *)       die "未知阶段: $STAGE（可选 all|deps|app|nginx|cert|final）" ;;
  esac
}

# Sourced by tests/test_deploy_sh.py, which calls port_listening and
# nginx_stream_ready directly; only run the installer when executed.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
