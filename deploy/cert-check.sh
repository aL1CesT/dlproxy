#!/usr/bin/env bash
# dlproxy-cert-check — two independent certificate health signals.
#
# Signal A: remaining lifetime.
#   A Let's Encrypt IP certificate issued with the `shortlived` profile lives
#   ~160 hours. certbot renews it at half of that lifetime, i.e. around 80 hours,
#   so anything under the warn threshold means a renewal window was missed, and
#   under half of it means browsers will start refusing connections soon.
#   Thresholds are expressed in hours rather than days because days are too
#   coarse at this timescale — and because the same numbers keep working when the
#   profile moves to 45-day or 64-day certificates.
#
#   The warn threshold is **read from the database** (settings.cert_warn_days),
#   which is the same row the admin page writes. Before this the script had 56/32
#   hardcoded and the panel field drove nothing.
#
# Signal B: automation freshness.
#   A deploy hook touches $STAMP after every successful issuance/renewal. If that
#   file is older than 96 hours, renewal is broken *even if the current
#   certificate still has days left* — this fires roughly 64 hours earlier than
#   the expiry warning would. It is the signal that actually catches a stuck
#   certbot loop.
#
# Both signals are delivered by mail through `python -m app alert-cert`, which
# reuses the SMTP settings and de-duplicates by state: this script runs every six
# hours, so a certificate that stays critical for two days would otherwise send
# eight identical mails.
#
# Exit codes: 0 = healthy, 1 = missing/unreadable, 2 = warn, 3 = critical.
set -euo pipefail

STAMP="${STAMP:-/var/lib/certbot/last-success}"
STAMP_MAX_AGE_H="${STAMP_MAX_AGE_H:-96}"
APP_DIR="${APP_DIR:-/opt/dlproxy}"
DB_PATH="${DB_PATH:-$APP_DIR/data/app.db}"
APP_USER="${APP_USER:-dlproxy}"
CERT_DIR="${CERT_DIR:-/etc/letsencrypt/live}"

# `openssl x509 -enddate` prints "Nov 20 05:14:47 2026 GMT". GNU date handles
# that, but busybox date and the MSYS build do not — they only accept a numeric
# or ISO-8601 date. Rebuilding it as ISO keeps the script portable without
# pulling in a dependency the target host may not have.
epoch_from_openssl_date() {
  local raw="$1" mon day clock year mon_num
  read -r mon day clock year _ <<<"$raw"
  case "$mon" in
    Jan) mon_num=01 ;; Feb) mon_num=02 ;; Mar) mon_num=03 ;;
    Apr) mon_num=04 ;; May) mon_num=05 ;; Jun) mon_num=06 ;;
    Jul) mon_num=07 ;; Aug) mon_num=08 ;; Sep) mon_num=09 ;;
    Oct) mon_num=10 ;; Nov) mon_num=11 ;; Dec) mon_num=12 ;;
    *) return 1 ;;
  esac
  date -u -d "$year-$mon_num-$day $clock" +%s
}

# Threshold override for tests and for operators who want to try a value without
# touching the database. Empty means "read settings.cert_warn_days".
THRESHOLD_WARN_H="${THRESHOLD_WARN_H:-}"

read_warn_days() {
  # sqlite3 is installed by deploy.sh; if it is missing we fall back rather than
  # fail the whole check over a threshold lookup.
  command -v sqlite3 >/dev/null 2>&1 || return 1
  [[ -r "$DB_PATH" ]] || return 1
  sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='cert_warn_days';" 2>/dev/null
}

if [[ -z "$THRESHOLD_WARN_H" ]]; then
  WARN_DAYS="$(read_warn_days || true)"
  if [[ "$WARN_DAYS" =~ ^[0-9]+$ ]] && (( WARN_DAYS > 0 )); then
    THRESHOLD_WARN_H=$(( WARN_DAYS * 24 ))
  else
    THRESHOLD_WARN_H=72           # 3 days, the shipped default
  fi
fi
THRESHOLD_CRIT_H=$(( THRESHOLD_WARN_H / 2 ))

# Which certificate to watch.
#
# The check must watch the certificate nginx actually serves. Three sources, in
# descending order of authority:
#
#   1. the `ssl_certificate` line in the site nginx loads -- ground truth;
#   2. the lineage named by settings.public_base -- what the operator intended;
#   3. the earliest-expiring lineage in the tree -- a guess, and a dangerous one.
#
# Until this was ordered properly, (3) was the only branch that ever ran: on a
# box holding both a domain certificate (~90 days) and a leftover IP certificate
# (~5 days) it reported on the IP one every time, warning about a file nginx had
# stopped loading hours earlier. An alert about the wrong certificate is worse
# than no alert: it teaches the operator to trust the mail.
#
# Nginx site config, overridable so tests do not need /etc.
NGINX_SITE="${NGINX_SITE:-/etc/nginx/sites-available/dlproxy}"
read_public_host() {
  command -v sqlite3 >/dev/null 2>&1 || return 1
  [[ -r "$DB_PATH" ]] || return 1
  local base
  base=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='public_base';" 2>/dev/null) || return 1
  # https://dl.example.com -> dl.example.com ; ignore placeholder or empty rows.
  base="${base#https://}"
  base="${base#http://}"
  base="${base%%/*}"
  # certbot always lowercases the lineage directory; a hand-written public_base
  # may not. Compare like with like.
  base="$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  [[ -n "$base" ]] || return 1
  # This line is the whole point: called as `$(read_public_host)`, a function
  # whose last statement is a test returns nothing on stdout, so EXPECTED_HOST
  # was always empty and the branch below never ran. The script then scanned
  # every lineage and picked the earliest-expiring one -- which on a box with
  # both a domain certificate (90 days) and an IP certificate (5 days) is
  # always the IP one. It reported on a certificate nginx may not even load.
  printf '%s\n' "$base"
}

CERT=""
CERT_SOURCE=""

# Source 1: whatever the live nginx site points at. This is the only answer that
# cannot be wrong -- if nginx is serving it, the expiry of that file is what
# users will hit.
nginx_cert_path() {
  [[ -r "$NGINX_SITE" ]] || return 1
  # `ssl_certificate     /etc/letsencrypt/live/dl.example.com/fullchain.pem;`
  local line
  line=$(sed -n 's|^[[:space:]]*ssl_certificate[[:space:]][[:space:]]*\([^;]*\);.*|\1|p' \
           "$NGINX_SITE" 2>/dev/null | head -1)
  line="${line%"${line##*[![:space:]]}"}"   # trim trailing blanks
  [[ -n "$line" ]]
  printf '%s\n' "$line"
}

NGINX_CERT="$(nginx_cert_path || true)"
if [[ -n "$NGINX_CERT" && -r "$NGINX_CERT" ]]; then
  CERT="$NGINX_CERT"
  CERT_SOURCE="nginx 站点配置"
fi

# Source 2: the lineage settings.public_base names.
if [[ -z "$CERT" ]]; then
  EXPECTED_HOST="$(read_public_host || true)"
  if [[ -n "$EXPECTED_HOST" && -r "$CERT_DIR/$EXPECTED_HOST/fullchain.pem" ]]; then
    CERT="$CERT_DIR/$EXPECTED_HOST/fullchain.pem"
    CERT_SOURCE="public_base ($EXPECTED_HOST)"
  fi
fi

# Source 3: last resort. Several lineages and nothing to disambiguate: watch the
# one that expires first, because that is the one that will break first.
# No `local` here: this loop is at file scope, not inside a function.
if [[ -z "$CERT" ]]; then
  candidate=
  candidate_end=
  candidate_epoch=
  CERT_EPOCH=
  for candidate in "$CERT_DIR"/*/fullchain.pem; do
    [[ -r "$candidate" ]] || continue
    candidate_end=$(openssl x509 -enddate -noout -in "$candidate" 2>/dev/null | cut -d= -f2) || continue
    candidate_epoch=$(epoch_from_openssl_date "$candidate_end" 2>/dev/null) || continue
    if [[ -z "$CERT" || "$candidate_epoch" -lt "$CERT_EPOCH" ]]; then
      CERT="$candidate"
      CERT_EPOCH="$candidate_epoch"
    fi
  done
  [[ -n "$CERT" ]] && CERT_SOURCE="扫描 $CERT_DIR（最早到期）"
fi

if [[ -z "$CERT" ]]; then
  echo "cert-check: CRIT 没有找到证书（$NGINX_SITE 未指向可读证书，$CERT_DIR/*/fullchain.pem 也没有）"
  logger -t dlproxy-cert "CRIT 没有找到证书" 2>/dev/null || true
  exit 1
fi

# Say where the answer came from. When this ever picks the wrong certificate the
# operator needs to know which of the three rules decided, not just the result.
echo "cert-check: 检查对象来源：$CERT_SOURCE"

if ! END_DATE=$(openssl x509 -enddate -noout -in "$CERT" 2>/dev/null | cut -d= -f2); then
  echo "cert-check: CRIT 无法读取 $CERT"
  logger -t dlproxy-cert "CRIT 无法读取 $CERT" 2>/dev/null || true
  exit 1
fi

if ! END_EPOCH=$(epoch_from_openssl_date "$END_DATE"); then
  echo "cert-check: CRIT 无法解析到期时间（$END_DATE）"
  logger -t dlproxy-cert "CRIT 无法解析到期时间：$END_DATE" 2>/dev/null || true
  exit 1
fi
NOW_EPOCH=$(date -u +%s)
LEFT_H=$(( (END_EPOCH - NOW_EPOCH) / 3600 ))
LEFT_D=$(( LEFT_H / 24 ))

echo "cert-check: $CERT 剩余 ${LEFT_H} 小时（${LEFT_D} 天），到期 $END_DATE"
echo "cert-check: 告警阈值 ${THRESHOLD_WARN_H} 小时（WARN），${THRESHOLD_CRIT_H} 小时（CRIT）"

status=0
if (( LEFT_H <= 0 )); then
  echo "cert-check: CRIT 证书已过期"
  logger -t dlproxy-cert "CRIT 证书已过期：$CERT" 2>/dev/null || true
  status=3
elif (( LEFT_H <= THRESHOLD_CRIT_H )); then
  echo "cert-check: CRIT 剩余不足 ${THRESHOLD_CRIT_H} 小时，浏览器即将拒绝连接"
  logger -t dlproxy-cert "CRIT 证书剩余 ${LEFT_H} 小时" 2>/dev/null || true
  status=3
elif (( LEFT_H <= THRESHOLD_WARN_H )); then
  echo "cert-check: WARN 剩余不足 ${THRESHOLD_WARN_H} 小时，续期窗口已过"
  logger -t dlproxy-cert "WARN 证书剩余 ${LEFT_H} 小时" 2>/dev/null || true
  status=2
fi

# Signal B: has anything been issued lately?
stamp_broken=0
if [[ -e "$STAMP" ]]; then
  STAMP_EPOCH=$(date -u -r "$STAMP" +%s 2>/dev/null || stat -c %Y "$STAMP")
  AGE_H=$(( (NOW_EPOCH - STAMP_EPOCH) / 3600 ))
  echo "cert-check: 上次成功签发/续期在 ${AGE_H} 小时前"
  if (( AGE_H > STAMP_MAX_AGE_H )); then
    echo "cert-check: CRIT 续期自动化疑似失灵（${AGE_H}h > ${STAMP_MAX_AGE_H}h）"
    echo "           检查： systemctl list-timers --all | grep certbot"
    echo "           日志： journalctl -u snap.certbot.renew --since '-3 days'"
    logger -t dlproxy-cert "CRIT 续期自动化失灵，上次成功在 ${AGE_H} 小时前" 2>/dev/null || true
    status=3
    stamp_broken=1
  fi
else
  echo "cert-check: 续期时间戳 $STAMP 不存在"
  echo "           （deploy.sh 会安装 renewal-hooks/deploy/ 下的 touch 钩子；"
  echo "             若刚刚首次签发，下一次续期后会创建）"
fi

# Deliver by mail. The CLI is invoked as the service account: running it as root
# would leave root-owned -wal/-shm files next to the database and the service
# would lose the ability to write.
#
# Exit code semantics: `app alert-cert` exits with the *alert level* it decided
# on (0 healthy, 2 warning, 3 critical), not with success/failure. Treating a
# non-zero exit as "mail failed" would print a bogus failure line on every real
# warning, drowning out the one signal that matters when SMTP is actually down.
# notify therefore maps the three decided levels to success and lets anything
# else through.
notify() {
  local py="$APP_DIR/venv/bin/python"
  if [[ ! -x "$py" ]]; then
    echo "cert-check: $py 不存在，跳过邮件告警"
    return 0
  fi
  local -a argv=("$py" -m app --db "$DB_PATH" alert-cert --left-hours "$LEFT_H")
  (( stamp_broken )) && argv+=(--stamp-broken)
  local rc=0
  # Root must drop privileges, or the -wal/-shm files it creates leave the
  # service unable to write its own database.
  if [[ "$(id -u)" == "0" ]] && id -u "$APP_USER" >/dev/null 2>&1; then
    if command -v runuser >/dev/null 2>&1; then
      ( cd "$APP_DIR" && runuser -u "$APP_USER" -- "${argv[@]}" ) || rc=$?
    else
      ( cd "$APP_DIR" && sudo -u "$APP_USER" -- "${argv[@]}" ) || rc=$?
    fi
  else
    ( cd "$APP_DIR" && "${argv[@]}" ) || rc=$?
  fi
  case "$rc" in
    0|2|3) return 0 ;;   # a decided level, delivered or logged — not a failure
    *)     return "$rc" ;;
  esac
}

# Called on every run, healthy or not: a healthy certificate is what clears
# settings.cert_alert_state, so the next incident is not treated as a repeat.
notify || echo "cert-check: 邮件告警调用失败（服务仍会照常运行）"

exit "$status"
