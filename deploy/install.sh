#!/usr/bin/env bash
# install.sh — 交互式安装向导，负责问清楚 deploy.sh 需要的每一个决定，然后把
# 参数拼好交给它。它自己**不做任何安装动作**，只是把一堆容易记错的 flag 变成
# 几个 y/n 问题。
#
#   sudo ./install.sh                 逐条询问
#   sudo ./install.sh --yes           全部取推荐值（CI / 重装用）
#   sudo ./install.sh --dry-run       只打印将要执行的命令，不执行
#
# 设计上的两个坚持：
#   * 复用 deploy.sh 的探测函数而不是另写一套 —— 端口判定那种事一旦有两份实现，
#     迟早会有一份说谎。用 DLPROXY_LIB_ONLY=1 source 它，可以只拿函数不跑参数解析。
#   * 任何"要不要覆盖/抢占"的决定都不替用户做。443 被占用时只给出选项和后果，
#     选错了是操作者的事，脚本不猜。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Reuse port_listening / nginx_stream_ready / 颜色与 info/warn/die，但**不要**
# 让 deploy.sh 解析 $@ —— 那些参数是 install.sh 自己的。
DLPROXY_LIB_ONLY=1 . "$SCRIPT_DIR/deploy.sh"

ASSUME_YES=0
DRY_RUN=0
_args=("$@")
for ((i = 0; i < ${#_args[@]}; i++)); do
  case "${_args[i]}" in
    -y|--yes)   ASSUME_YES=1 ;;
    --dry-run)  DRY_RUN=1 ;;
    -h|--help)
      sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) die "未知参数：${_args[i]}（可用 --help 查看用法）" ;;
  esac
done
unset _args

# ---------------------------------------------------------------------------
# 提问原语
#
# 全部走 stdin 而不是 /dev/tty，这样 pytest 可以用管道把整场会话喂进来。
# 读到 EOF 一律当作"取消"，而不是当作空回答 —— 否则 `yes '' | install.sh`
# 会静默地把所有默认值全接受一遍。
# ---------------------------------------------------------------------------
ask_yn() {
  local prompt="$1" default="${2:-n}" answer hint
  [[ "$default" == "y" ]] && hint="[Y/n]" || hint="[y/N]"
  if (( ASSUME_YES )); then
    printf '?  %s %s -> %s（--yes）\n' "$prompt" "$hint" "$default"
    [[ "$default" == "y" ]]
    return
  fi
  while true; do
    # '?  ' is four columns, exactly like '==> ': questions and progress
    # reports line up on the same margin but never look alike.
    printf '?  %s %s ' "$prompt" "$hint"
    if ! IFS= read -r answer; then
      printf '\n'
      die "输入已结束，安装已取消（未做任何改动）"
    fi
    # A terminal echoes the Enter the user pressed; a pipe does not, so the next
    # line of output would be glued onto the end of the question. Same reason
    # the Python menu writes its own newline when stdin is not a tty.
    [[ -t 0 ]] || printf '\n'
    answer="${answer#"${answer%%[![:space:]]*}"}"     # ltrim
    answer="${answer%"${answer##*[![:space:]]}"}"     # rtrim
    case "${answer,,}" in
      "")     [[ "$default" == "y" ]]; return ;;
      y|yes)  return 0 ;;
      n|no)   return 1 ;;
      *)      printf '     请输入 y 或 n\n' ;;
    esac
  done
}

# 把回答放进 REPLY，不污染调用者的变量。
ask_value() {
  local prompt="$1" default="${2:-}"
  if (( ASSUME_YES )); then
    printf '?  %s [%s] -> %s（--yes）\n' "$prompt" "$default" "$default"
    REPLY="$default"
    return
  fi
  if [[ -n "$default" ]]; then
    printf '?  %s [%s] ' "$prompt" "$default"
  else
    printf '?  %s ' "$prompt"
  fi
  if ! IFS= read -r REPLY; then
    printf '\n'
    die "输入已结束，安装已取消（未做任何改动）"
  fi
  [[ -t 0 ]] || printf '\n'
  REPLY="${REPLY#"${REPLY%%[![:space:]]*}"}"
  REPLY="${REPLY%"${REPLY##*[![:space:]]}"}"
  [[ -n "$REPLY" ]] || REPLY="$default"
}

ask_port() {
  local prompt="$1" default="$2"
  while true; do
    ask_value "$prompt" "$default"
    if [[ "$REPLY" =~ ^[0-9]+$ ]] && (( REPLY >= 1 && REPLY <= 65535 )); then
      return
    fi
    printf '     端口必须是 1 至 65535 之间的整数\n'
  done
}

# ---------------------------------------------------------------------------
# 环境探测
# ---------------------------------------------------------------------------
# port_owner() comes from deploy.sh (sourced above). It used to be duplicated
# here, and the two copies drifted: only the deploy.sh one falls back to the
# socket-inode walk when `ss` exists but cannot name the owner. Keeping one
# implementation means the wizard and the preflight can never disagree about
# who holds :80.

listening_ports() {
  if command -v ss >/dev/null 2>&1; then
    ss -lntH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un
    return
  fi
  local dir="${PROC_NET_DIR:-/proc/net}"
  { cat "$dir/tcp"; cat "$dir/tcp6"; } 2>/dev/null \
    | awk '$4 == "0A" { n = split($2, a, ":"); print a[n] }' \
    | while read -r hexport; do printf '%d\n' "0x$hexport"; done \
    | sort -un
}

# 从一个候选起点开始找空闲端口，避免和其他服务抢。
free_port_from() {
  local port="$1"
  while (( port <= 65000 )); do
    port_listening "$port" || { printf '%s\n' "$port"; return 0; }
    port=$((port + 1))
  done
  die "未找到空闲端口（自 $1 起已尝试上万个端口，均被占用）"
}

describe_port() {
  local port="$1" owner
  if port_listening "$port"; then
    owner=$(port_owner "$port")
    printf '占用（%s）' "${owner:-进程未知}"
  else
    printf '空闲'
  fi
}

# Tell the operator up front when the other service's port cannot be reached
# from the internet. This is a warning, never a stop: dlproxy does not own that
# service's config, and in share-443 mode the 443 entry point works regardless
# of its bind address. But a silent "your existing link is fine" on a loopback
# bind is a lie, and it has already happened once on a real host.
note_bind_scope() {
  local port="$1" scope
  scope=$(port_bind_scope "$port")
  case "$scope" in
    loopback)
      warn "注意：$port 仅绑定在 127.0.0.1，外网无法访问 域名:$port。"
      echo "        若需 域名:$port 直接可用，请将该服务的监听地址改为 0.0.0.0。"
      echo "        仅使用 443 入口时不受影响：nginx 通过本机回环连接该端口。"
      return 1
      ;;
    specific)
      warn "注意：$port 绑定了具体网卡地址；若该地址不是公网网卡，域名:$port 将无法连接。"
      return 1
      ;;
  esac
  return 0
}

# Well-known TLS service process names. Looking a service up by *process name*
# is far more reliable than guessing by port: the operator picks the port, not
# the binary, so "is this port busy" says nothing about who owns it.
#
# This list is only a hint for the wizard: when the process holding 443 does
# not match, the wizard still offers to share the port, it just cannot
# pre-select the port the service is already listening on. Add your own
# binary name here if you want that shortcut. Keep nginx out of it -- the
# wizard treats a match as "the service I am about to displace" and nginx is
# what it is about to install.
SERVICE_PROC_RE='xray|v2ray|sing-box|sing_box|hysteria|trojan|naive|tuic|mihomo|clash'

proxy_like() {
  [[ -n "${1:-}" ]] && grep -qiE "$SERVICE_PROC_RE" <<<"$1"
}

# "PORT OWNER" for every listening TCP socket, in one pass.
#
# With ss this is one call. Without ss (a minimal image has no iproute2) the
# naive fallback -- calling port_owner per port -- walks /proc/*/fd once *per
# port*, which took seconds each on the real host. So walk it once and invert
# the inode map instead. PROC_ROOT/PROC_NET_DIR exist so tests can feed a
# fixture tree.
listening_with_owners() {
  if command -v ss >/dev/null 2>&1; then
    ss -lntpH 2>/dev/null \
      | sed -n 's/^.*:\([0-9][0-9]*\)[[:space:]].*users:(("\([^"]*\)".*/\1 \2/p'
    return 0
  fi
  local root="${PROC_ROOT:-/proc}" dir="${PROC_NET_DIR:-/proc/net}"
  local hexport inode pid fd target comm p
  declare -A inode_port=()
  declare -A owners=()
  while read -r hexport inode; do
    [[ -n "$hexport" && -n "$inode" ]] && inode_port["$inode"]=$((16#$hexport))
  done < <({ cat "$dir/tcp"; cat "$dir/tcp6"; } 2>/dev/null \
             | awk '$4 == "0A" { n = split($2, a, ":"); print a[n], $10 }')
  for pid in "$root"/[0-9]*; do
    comm=$(cat "$pid/comm" 2>/dev/null) || continue
    for fd in "$pid"/fd/*; do
      target=$(readlink "$fd" 2>/dev/null) || continue
      [[ "$target" == socket:\[*\] ]] || continue
      inode="${target#socket:[}"; inode="${inode%]}"
      p="${inode_port[$inode]:-}"
      [[ -n "$p" ]] && owners["$p"]="$comm"
    done
  done
  for p in "${!owners[@]}"; do printf '%s %s\n' "$p" "${owners[$p]}"; done
}

# "PORT ADDR" for every listening TCP socket.
#
# This exists because a listening port is not the same as a reachable port. On
# a real host the node was found on 127.0.0.1:11111 -- the wizard said "your
# existing  domain:11111 link is unaffected", which was false: a loopback
# socket is unreachable from outside, so the link had already been broken by
# whoever set the listen address.
listening_with_addrs() {
  if command -v ss >/dev/null 2>&1; then
    # last ":NNN" is the port; what precedes it is the bind address. Doing it
    # with sub() rather than -F: keeps IPv6 literals ("[::]:443") intact.
    ss -lntH 2>/dev/null \
      | awk '{
          addr = $4
          port = $4
          sub(/:[0-9]+$/, "", addr)
          sub(/.*:/, "", port)
          if (port != "") print port, addr
        }'
    return 0
  fi
  # /proc/net/tcp stores the address little-endian in hex. Only the two
  # wildcard/loopback spellings matter for the warning; everything else is
  # treated as "some specific address" and left alone.
  local dir="${PROC_NET_DIR:-/proc/net}" hexport addr
  while read -r hexaddr hexport; do
    case "${#hexaddr}" in
      8)
        case "$hexaddr" in
          00000000) addr="0.0.0.0" ;;
          0100007F) addr="127.0.0.1" ;;
          *) addr="0.0.0.0" ;;
        esac
        ;;
      32)
        case "$hexaddr" in
          00000000000000000000000000000000) addr="[::]" ;;
          00000000000000000000000001000000) addr="[::1]" ;;
          *) addr="[::]" ;;
        esac
        ;;
      *) continue ;;
    esac
    printf '%s %s\n' "$((16#$hexport))" "$addr"
  done < <({ cat "$dir/tcp"; cat "$dir/tcp6"; } 2>/dev/null \
             | awk '$4 == "0A" { n = split($2, a, ":"); print a[1], a[n] }')
}

# loopback | wildcard | specific | "" (not listening)
port_bind_scope() {
  local port="$1" line addr found=""
  while read -r p addr; do
    [[ "$p" == "$port" ]] || continue
    case "$addr" in
      127.*|'[::1]'*) printf 'loopback\n'; return 0 ;;
      0.0.0.0|'*'|'[::]') [[ -z "$found" ]] && found="wildcard" ;;
      *) [[ -z "$found" ]] && found="specific" ;;
    esac
  done < <(listening_with_addrs)
  printf '%s\n' "$found"
}

# Ports held by something that looks like a TLS proxy.
proxy_like_ports() {
  local port owner
  while read -r port owner; do
    [[ -z "$port" ]] && continue
    proxy_like "$owner" && printf '%s\n' "$port"
  done < <(listening_with_owners) || true
  return 0
}

# The share-443 branch collects four answers. They live in globals because a
# function cannot return a tuple, and threading them through REPLY would be
# worse than a small amount of shared state in a 300-line wizard.
W_SHARE=0
W_STOP=0
W_SERVICE_PORT=""
W_TLS=8443
W_STRIP=8441
W_HOST=""
W_DOMAIN=""

# Ask everything share-443 needs. $1, when given, is a port the caller has
# already established as the other service's -- it is not re-validated for
# occupancy, because it is occupied by that service itself.
setup_share443() {
  local hint="${1:-}"
  W_SHARE=1
  echo
  phase_banner "共用 443 的参数"
  echo "  共用模式下由 nginx 接管 443 并执行 SNI 分流。同一端口不能由两个进程监听，"
  echo "  因此 443 交由 nginx，原服务改在自身端口上等待 nginx 转发。"
  if [[ -n "$hint" ]]; then
    # 原服务已经搬好了：客户端此刻连的是新端口，不是 443。
    if note_bind_scope "$hint"; then
      echo "  原服务继续在 $hint 上提供服务，现有的 域名:$hint 链接不受影响；"
      echo "  本层仅为**额外**入口：域名:443 亦可到达原服务（带 SNI 转发至原服务，IP 直连转发至 dlproxy）。"
    else
      echo "  本层将 域名:443 接入原服务；在 $hint 仅绑回环的情况下，"
      echo "  这也是当前唯一可从外部接入的入口。"
    fi
  else
    echo "  **客户端无需改动**：仍连接 域名:443，由 nginx 按 SNI 转发至原服务的新端口。"
  fi
  echo
  if [[ -z "$hint" ]]; then
    local others
    others=$(listening_ports | grep -vxE '22|80|443' | paste -sd' ' - 2>/dev/null || true)
    if [[ -n "$others" ]]; then
      echo "  当前还有以下端口处于监听状态（与本次选择无关，列出以免误以为原服务在其中）："
      echo "    $others"
      echo
    fi
  fi
  local suggested
  if [[ -n "$hint" ]]; then
    suggested="$hint"
  else
    # Prefer a port that service is already on -- that is the answer 90% of the
    # time, and it is invisible to "first free port" because it is by definition
    # busy.
    suggested=$(proxy_like_ports | grep -vx 443 | head -1 || true)
    [[ -n "$suggested" ]] || suggested=$(free_port_from 10443)
  fi
  while true; do
    ask_port "原服务在哪个端口对外提供服务？" "$suggested"
    W_SERVICE_PORT="$REPLY"
    if (( W_SERVICE_PORT < 1024 )); then
      warn "1024 以下为特权端口，绑定需 root 权限，且容易与系统服务冲突"
      continue
    fi
    if (( W_SERVICE_PORT == 443 )); then
      warn "443 即将交由 nginx 使用，原服务必须改用其他端口"
      continue
    fi
    if [[ -n "$hint" ]]; then
      break
    fi
    local occupant
    occupant=$(port_owner "$W_SERVICE_PORT")
    if [[ -n "$occupant" ]] && ! proxy_like "$occupant"; then
      warn "$W_SERVICE_PORT 已被 $occupant 占用，原服务无法绑定该端口"
      continue
    fi
    break
  done
  if port_listening "$W_SERVICE_PORT"; then
    info "$W_SERVICE_PORT 已处于监听状态，原服务就位"
  else
    warn "$W_SERVICE_PORT 当前空闲，原服务尚未迁移至该端口。"
    # 这时把命令交出去，deploy.sh 的预检会拦下，而且剩下的问题全白答。
    if (( ! DRY_RUN )); then
      echo
      warn "现在安装会在预检阶段中止，不会做任何改动。请先完成以下两步："
      echo "    1. 将原服务的监听端口改为 $W_SERVICE_PORT 并重启"
      echo "    2. 执行 ss -lntp | grep $W_SERVICE_PORT，确认端口已监听且客户端仍可连接"
      echo "  然后重跑本脚本，向导会自动识别原服务已就位。"
      info "已停止，未做任何改动"
      W_STOP=1
      return 0
    fi
    warn "（--dry-run：继续列出完整命令，供你确认）"
  fi
  W_TLS=$(free_port_from 8443)
  W_STRIP=$(free_port_from 8441)
  if (( W_STRIP == W_TLS )); then W_STRIP=$(free_port_from $((W_TLS + 1))); fi
  info "dlproxy 回环 TLS 端口：$W_TLS，PROXY 剥头器：$W_STRIP"
  echo
  echo "  默认仅 https://<IP>/... 可访问 dlproxy —— 因为 IP 不参与 SNI。"
  echo "  若有域名同样指向本机，可将其分配给 dlproxy，"
  echo "  否则该域名将继续转发至原服务。"
  if ask_yn "是否给 dlproxy 分配一个域名？" n; then
    local v
    while true; do
      ask_value "域名（例如 dl.example.com）" ""
      v="$REPLY"
      if [[ "$v" =~ ^[A-Za-z0-9.-]+$ && "$v" == *.* ]]; then
        W_HOST="$v"; break
      fi
      printf '     该值不是有效域名，请重新输入\n'
    done
  fi
}

# ---------------------------------------------------------------------------
# 向导主体
# ---------------------------------------------------------------------------
main() {
  need_root
  local os_name arch
  # Same override pattern as PROC_NET_DIR: a test (or a capture for the docs)
  # has to be able to say what the host looks like without owning /etc.
  local os_release="${OS_RELEASE_FILE:-/etc/os-release}"
  [[ -r "$os_release" ]] && . "$os_release"
  os_name="${PRETTY_NAME:-unknown}"
  # Same reason as OS_RELEASE_FILE above: a capture for the docs (or a test)
  # must be able to describe the documented host, not the one it runs on.
  arch="${HOST_ARCH:-$(uname -m)}"
  local cores="${HOST_CORES:-$(nproc)}"

  local rule='━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'
  echo
  echo "$rule"
  echo "  dlproxy 安装向导"
  echo "$rule"
  printf '  系统      %s / %s / %s 核\n' "$os_name" "$arch" "$cores"
  printf '  安装目录  %s\n' "$APP_DIR"
  echo

  # ---- 事实 ---- 
  phase_banner "当前状态"
  printf '  80        %s\n' "$(describe_port 80)"
  printf '  443       %s\n' "$(describe_port 443)"
  printf '  8080      %s\n' "$(describe_port 8080)"
  if command -v nginx >/dev/null 2>&1; then
    printf '  nginx     %s\n' "$(nginx -v 2>&1 | sed 's/^nginx version: //')"
  else
    printf '  nginx     尚未安装（stage deps 阶段安装）\n'
  fi

  # 说清楚 80/443 上"被占用"是不是问题：占用者是 nginx/httpd/caddy 时，
  # deploy.sh 会接管并 reload 它（reload 不中断现有站点），所以那不是冲突。
  # 占用者是别的东西时 deploy.sh 会拒绝继续 —— 提前讲，别等问完八个问题才失败。
  local p80
  if port_listening 80; then
    p80=$(port_owner 80)
    # ADOPTABLE_RE 与 deploy.sh 的预检共用，两边不会说法不一。
    if [[ "$p80" =~ $ADOPTABLE_RE ]]; then
      echo "  80 端口上的 $p80 将被接管并 reload，现有站点不受影响。"
    elif [[ -n "$p80" ]]; then
      warn "80 端口已被 $p80 占用，它不属于本脚本可接管的 Web 服务器。"
      echo "     deploy.sh 将在预检阶段中止，请先停止 $p80 后重试。"
    fi
  fi
  echo

  local -a args=()
  local skip_cert=0 stage="all"
  W_SHARE=0; W_SERVICE_PORT=""; W_TLS=8443; W_STRIP=8441; W_HOST=""; W_DOMAIN=""

  # ---- 443 归谁 ----
  phase_banner "443 归谁"
  local owner443 service_ports
  owner443=$(port_owner 443)
  service_ports=$(proxy_like_ports | grep -vx 443 || true)

  if [[ "$owner443" == "nginx" ]] && systemctl is-active --quiet dlproxy 2>/dev/null; then
    info "443 由本机 nginx 监听且 dlproxy 正在运行 —— 按重装处理，无需 share-443"
  elif proxy_like "$owner443"; then
    warn "443 当前被 $owner443 占用。若要独占 443，需先停止该服务。"
    echo "  可选方案："
    echo "    y = 共用 443（nginx 按 SNI 分流；客户端仍连接 443，配置无需改动）"
    echo "    n = 不共用，退出；请自行停止 $owner443 后重试"
    if ask_yn "是否与已有的 TLS 服务共用 443？" y; then
      setup_share443 ""
    else
      echo
      die "已取消。释放 443 后请重跑：sudo ./install.sh"
    fi
  elif [[ "$owner443" =~ $ADOPTABLE_RE ]]; then
    # nginx/httpd/caddy holding :443 is the same situation as :80 — this script
    # is about to reload it, so nothing has to move and share-443 does not
    # apply (its stream layer would take the port away from that very server).
    info "443 由 $owner443 监听 —— 本脚本会接管该实例并 reload，现有站点不受影响"
    echo "  按独占模式安装：在同一个 nginx 上新增 dlproxy 站点，不触碰其它 server 块。"
  elif port_listening 443; then
    warn "443 已被占用（${owner443:-进程未知}），且该进程不是 Web 服务器，本脚本无法接管。"
    echo "  共用 443 只适用于以 TLS 对外服务、且能改端口的服务（xray / v2ray / sing-box 等），"
    echo "  nginx 自己的站点属于上一种情况，不走这里。"
    if ask_yn "仍然尝试共用 443？" n; then
      setup_share443 ""
    else
      echo
      die "已取消。释放 443 后请重跑：sudo ./install.sh"
    fi
  elif [[ -n "$service_ports" ]]; then
    W_SERVICE_PORT=$(head -1 <<<"$service_ports")
    local np_owner
    np_owner=$(listening_with_owners | awk -v p="$W_SERVICE_PORT" '$1 == p { print $2; exit }')
    info "443 已空闲，$W_SERVICE_PORT 上为 ${np_owner:-其他进程} —— 原服务已完成迁移。"
    echo "  原服务当前直接监听 $W_SERVICE_PORT，客户端连接的是 域名:$W_SERVICE_PORT。"
    echo "  443 当前空闲，有两种选择："
    echo "    y = nginx 接管 443，带域名的 TLS 请求转发至原服务（它因此多一个 443 入口），"
    echo "        不带 SNI 的请求（IP 直连）转发至 dlproxy"
    echo "    n = 443 仅供 dlproxy，原服务保持 $W_SERVICE_PORT 单一入口，配置最简"
    if note_bind_scope "$W_SERVICE_PORT"; then
      echo "  **两种方案都不影响现有的 域名:$W_SERVICE_PORT 链接**（前提是安全组已放行 $W_SERVICE_PORT）。"
    fi
    if ask_yn "是否让 443 也可访问原服务（共用模式）？" y; then
      setup_share443 "$W_SERVICE_PORT"
    else
      info "按独占模式安装：443 归 dlproxy，原服务继续仅在 $W_SERVICE_PORT 上服务"
    fi
  else
    info "443 空闲，采用独占模式（配置最简，无需 stream 分流）"
  fi
  (( W_STOP )) && return 0

  # ---- 证书 ----
  echo
  phase_banner "证书"
  echo "  Let's Encrypt 有两种证书：IP 证书（约 6 天，每次续期都要重跑 http-01）"
  echo "  与域名证书（约 90 天，剩余 30 天自动续期）。有域名时优先用域名证书。"
  echo "  前提：公网 80 端口可达（需在云防火墙放行 TCP 80 与 443）。"
  echo "  跳过申请则保留临时自签证书，浏览器会提示证书不受信任，但服务可正常使用。"
  if ! ask_yn "是否现在申请正式证书？" y; then
    skip_cert=1
  elif ask_yn "是否用域名申请证书（否则用 IP 证书）？" n; then
    local dv
    while true; do
      ask_value "域名（例如 dl.example.com）" "${W_HOST:-}"
      dv="${REPLY,,}"
      if [[ "$dv" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]; then
        W_DOMAIN="$dv"; break
      fi
      printf '  请输入完整域名（例如 dl.example.com），不含 http:// 与路径\n'
    done
    # The certificate name and the SNI split have to agree, otherwise the very
    # name on the certificate is routed to the other service, not to dlproxy.
    if [[ -z "$W_HOST" ]]; then
      W_HOST="$W_DOMAIN"
      echo "  已将 $W_DOMAIN 一并分配给 dlproxy（share-443 时自动加 SNI 分流）。"
    elif [[ "${W_HOST,,}" != "$W_DOMAIN" ]]; then
      echo "  注意：证书域名 $W_DOMAIN 与分配给 dlproxy 的 ${W_HOST} 不同。"
      echo "        两者都会在 share-443 下被分流到 dlproxy。"
    fi
    echo "  域名证书约 90 天有效期，续期由 certbot 自带定时器完成。"
  else
    echo "  IP 证书约 6 天有效期，每次续期都要重跑 http-01（80 端口必须长期开放）。"
  fi

  # ---- 执行范围 ----
  echo
  phase_banner "执行范围"
  echo "  all = 依赖 → 应用 → nginx → 证书 → 收尾（全新机器选此项）"
  if ask_yn "是否只执行某一阶段（调试或续跑用）？" n; then
    echo "  可选：deps / app / nginx / cert / final"
    while true; do
      ask_value "阶段" "final"
      case "$REPLY" in
        deps|app|nginx|cert|final) stage="$REPLY"; break ;;
        *) printf '  无此阶段\n' ;;
      esac
    done
  fi

  # ---- 组装 ---- 
  (( W_SHARE )) && args+=(--share-443)
  # --tls-service-port 只在 share-443 时有意义；独占模式带上它只会让人以为原服务还参与分流。
  (( W_SHARE )) && [[ -n "$W_SERVICE_PORT" ]] && args+=(--tls-service-port "$W_SERVICE_PORT")
  [[ -n "$W_DOMAIN" ]] && args+=(--domain "$W_DOMAIN")
  [[ -n "$W_HOST" ]] && args+=(--dlproxy-host "$W_HOST")
  (( W_SHARE )) && args+=(--tls-port "$W_TLS" --strip-port "$W_STRIP")
  (( skip_cert )) && args+=(--skip-cert)
  args+=(--stage "$stage")

  echo
  phase_banner "即将执行的命令"
  printf '  sudo bash %s/deploy.sh' "$SCRIPT_DIR"
  (( ${#args[@]} )) && printf ' %s' "${args[@]}"
  echo
  if (( W_SHARE )); then
    echo
    phase_banner "安装完成后的预期监听"
    # printf %-8s keeps the port column fixed: 443/8443/8441/11111 have
    # different widths and the hand counted spaces had the last one a column off.
    printf '    %-8s  %s\n' "443" "nginx stream（按 SNI 分流）"
    printf '    %-8s  %s\n' "$W_TLS" "dlproxy（回环，仅接受 stream 层转来的连接）"
    printf '    %-8s  %s\n' "$W_STRIP" "PROXY 剥头器（回环）"
    printf '    %-8s  %s\n' "$W_SERVICE_PORT" "原服务（你自己的 TLS 服务）"
  fi
  echo
  if (( DRY_RUN )); then
    info "--dry-run：仅预览，未执行任何安装动作"
    return 0
  fi
  if ! ask_yn "开始安装？" y; then
    info "已取消，未做任何改动"
    return 0
  fi

  echo
  exec bash "$SCRIPT_DIR/deploy.sh" "${args[@]}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
