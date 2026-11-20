#!/usr/bin/env bash
# tools/verify_all.sh — one command that runs everything provable on this host.
#
#   tools/verify_all.sh [/path/to/nginx]
#   tools/verify_all.sh --nginx /path/to/nginx
#
# The nginx argument is optional; without it the nginx-dependent checks are
# skipped with a clear message rather than failing, because the box that builds
# the project is not necessarily the box that serves it.
#
# Both spellings are accepted on purpose. `--nginx` reads like the other tools'
# flag and is what the docs used to advertise, while a bare path is what a shell
# user types. Accepting only one of them meant the other silently disabled four
# of the five sections and still exited 0 — a green run that proved nothing.
set -uo pipefail

cd "$(dirname "$0")/.."

NGINX=""
while (( $# )); do
  case "$1" in
    --nginx)   NGINX="${2:-}"; shift 2 || shift ;;
    --nginx=*) NGINX="${1#--nginx=}"; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    -*)        printf 'verify_all: 未知参数 %s\n' "$1" >&2; exit 2 ;;
    *)         NGINX="$1"; shift ;;
  esac
done
NGINX="${NGINX:-$(command -v nginx || true)}"

# Colour only when a person is watching: a redirection to a log file should not
# collect escape sequences, and NO_COLOR / TERM=dumb are the usual opt-outs.
if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-}" != "dumb" ]]; then
  GRN=$'\033[32m'
  RED=$'\033[31m'
  YEL=$'\033[33m'
  RST=$'\033[0m'
else
  GRN=''
  RED=''
  YEL=''
  RST=''
fi
fail=0

section() { printf '\n%s==> %s%s\n' "$GRN" "$1" "$RST"; }
failed() { printf '%s[x] %s%s\n' "$RED" "$1" "$RST"; fail=$((fail + 1)); }
skipped() { printf '%s[~] %s%s\n' "$YEL" "$1" "$RST"; }

# An explicit path that is not executable is a typo, not a host without nginx.
# Failing loudly beats printing a summary that looks complete.
if [[ -n "$NGINX" && ! -x "$NGINX" ]]; then
  printf '%s[x] 指定的 nginx 不可执行： %s%s\n' "$RED" "$NGINX" "$RST" >&2
  printf '    不跳过 —— 否则这次运行会假装通过。\n' >&2
  exit 2
fi

section "1/5 Python 单元与集成测试（不需要 nginx）"
if python -m pytest tests/ -q; then
  printf '%s单元测试通过%s\n' "$GRN" "$RST"
else
  failed "pytest 失败"
fi

if [[ -z "$NGINX" ]]; then
  skipped "找不到 nginx：跳过 4 项真实 nginx 验证"
  skipped "  （在服务器上跑： tools/verify_all.sh /usr/sbin/nginx）"
else
  section "2/5 原始 URI 契约（nginx 必须原样转发 /u/.../https://...）"
  if python tools/e2e_nginx.py --nginx "$NGINX"; then
    printf '%s通过%s\n' "$GRN" "$RST"
  else
    failed "e2e_nginx.py 失败 —— 链接形态不可用"
  fi

  section "3/5 deploy/nginx.conf 模板本身"
  if python tools/e2e_nginx_conf.py --nginx "$NGINX"; then
    printf '%s通过%s\n' "$GRN" "$RST"
  else
    failed "e2e_nginx_conf.py 失败"
  fi

  section "4/5 整链：nginx → 应用 → 上游"
  if python tools/e2e_full.py --nginx "$NGINX"; then
    printf '%s通过%s\n' "$GRN" "$RST"
  else
    failed "e2e_full.py 失败"
  fi

  section "5/5 443 与其他 TLS 服务共存（stream SNI 分流 + PROXY 剥头器）"
  if python tools/e2e_share443.py --nginx "$NGINX"; then
    printf '%s通过%s\n' "$GRN" "$RST"
  else
    failed "e2e_share443.py 失败 —— share-443 方案不可用"
  fi
fi

printf '\n'
if (( fail == 0 )); then
  printf '%s全部验证通过%s\n' "$GRN" "$RST"
  exit 0
fi
printf '%s%d 项失败%s\n' "$RED" "$fail" "$RST"
exit 1
