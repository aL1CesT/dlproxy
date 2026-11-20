#!/usr/bin/env bash
# uninstall.sh — reverse what deploy.sh did.
#
#   sudo ./uninstall.sh            stop and remove the service, keep the data
#   sudo ./uninstall.sh --purge    also delete data/, backup/ and .env
#
# Data is kept by default on purpose: uninstalling a proxy is usually "I want it
# gone from port 443", not "erase every user and every transfer record".
set -euo pipefail

APP_DIR="/opt/dlproxy"
APP_USER="dlproxy"
SERVICE="dlproxy"
PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1

# Colour only when a person is watching: a redirection to a log file should not
# collect escape sequences, and NO_COLOR / TERM=dumb are the usual opt-outs.
if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-}" != "dumb" ]]; then
  RED=$'\033[31m'
  GRN=$'\033[32m'
  YEL=$'\033[33m'
  RST=$'\033[0m'
else
  RED=''
  GRN=''
  YEL=''
  RST=''
fi
info() { printf '%s==>%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YEL" "$RST" "$*"; }

die() { printf '%s[x]%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "需要 root 权限，请以 sudo 运行" 

info "停止并禁用服务"
systemctl stop "$SERVICE" 2>/dev/null || true
systemctl disable "$SERVICE" 2>/dev/null || true
rm -f "/etc/systemd/system/${SERVICE}.service"
systemctl daemon-reload
systemctl reset-failed "$SERVICE" 2>/dev/null || true

info "移除 nginx 站点配置"
rm -f /etc/nginx/sites-enabled/dlproxy
rm -f /etc/nginx/sites-available/dlproxy
if [[ -f /etc/nginx/stream-enabled/dlproxy.conf ]]; then
  info "移除 share-443 的 stream 片段"
  rm -f /etc/nginx/stream-enabled/dlproxy.conf
  rmdir /etc/nginx/stream-enabled 2>/dev/null || true
  # 顶层 stream{} 只包我们这一个 include；删掉它，否则 nginx.conf 里会留下
  # 一个空 stream 块（合法，但会让人以为 dlproxy 还没卸干净）。
  if grep -qF '# dlproxy share-443 (stream)' /etc/nginx/nginx.conf; then
    cp -a /etc/nginx/nginx.conf "/etc/nginx/nginx.conf.bak.$(date +%Y%m%d%H%M%S)"
    if command -v python3 >/dev/null 2>&1; then
      python3 - "/etc/nginx/nginx.conf" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
# 精确删掉 deploy.sh 追加的那一段，别的 stream 配置不动。
text = re.sub(
    r"\n# dlproxy share-443 \(stream\)\nstream \{\n"
    r"    include /etc/nginx/stream-enabled/\*\.conf;\n\}\n",
    "\n",
    text,
)
open(path, "w", encoding="utf-8").write(text)
PY
    else
      warn "未找到 python3，请手动删除 nginx.conf 中 '# dlproxy share-443 (stream)' 那段"
    fi
  fi
fi
if nginx -t 2>/dev/null; then
  systemctl reload nginx 2>/dev/null || true
else
  warn "nginx 配置校验失败（可能已被其他改动影响），已跳过 reload"
fi

info "移除 cron / logrotate / 辅助脚本"
rm -f /etc/cron.d/dlproxy
rm -f /etc/logrotate.d/dlproxy
rm -f /usr/local/bin/dlproxy-backup
rm -f /usr/local/bin/dlproxy-cert-check
rm -f /usr/local/bin/dlproxy

info "移除证书"
if command -v certbot >/dev/null; then
  for name in $(certbot certificates 2>/dev/null | awk '/Certificate Name:/ {print $3}'); do
    certbot delete --cert-name "$name" --non-interactive 2>/dev/null || true
  done
fi

if [[ $PURGE -eq 1 ]]; then
  warn "删除数据目录 $APP_DIR/data 与 $APP_DIR/backup"
  # The .env holds the session signing key. Losing it just invalidates cookies,
  # but it is still a secret file — say so out loud before deleting.
  if [[ -f "$APP_DIR/.env" ]]; then
    warn "$APP_DIR/.env 含会话签名密钥，即将一并删除"
  fi
  rm -rf "$APP_DIR/data" "$APP_DIR/backup" "$APP_DIR/.env" \
         "$APP_DIR/INITIAL_ADMIN.txt"
  rm -rf "$APP_DIR/app" "$APP_DIR/venv" "$APP_DIR/deploy" \
         "$APP_DIR/requirements.txt"
  rmdir "$APP_DIR" 2>/dev/null || true
  info "已全部清除"
else
  warn "已保留：$APP_DIR/data（数据库）、$APP_DIR/backup（备份）、$APP_DIR/.env"
  warn "如需彻底删除，请重新运行： sudo ./uninstall.sh --purge"
fi

info "已保留日志目录： /var/log/dlproxy（可手动删除）"
if id "$APP_USER" >/dev/null 2>&1; then
  info "服务账号 $APP_USER 仍然存在；如需删除： userdel $APP_USER"
fi
