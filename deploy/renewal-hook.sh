#!/usr/bin/env bash
# /etc/letsencrypt/renewal-hooks/deploy/dlproxy.sh
#
# certbot runs every executable in renewal-hooks/deploy/ once per successfully
# issued certificate, including on renewal. That makes it the documented place
# for "the certificate changed, do something" — and it is more robust than
# passing --deploy-hook on the command line, because:
#
#   * a command-line hook is only written into the renewal config if it was
#     given at first issuance (certbot's `set_by_user` filter), so a hook added
#     later is silently absent from renewals;
#   * the conf key it lands in is `renew_hook`, not `deploy_hook` — a naming
#     quirk certbot keeps for downgrade compatibility, and an easy thing to
#     "fix" wrongly when hand-editing;
#   * a directory hook applies to every certificate on the host, including ones
#     reissued with a different --cert-name.
#
# Deliberately NOT a --post-hook: post-hooks run even when renewal *failed*,
# which would turn this timestamp into a liar.
set -euo pipefail

STAMP="${STAMP:-/var/lib/certbot/last-success}"
DOMAIN="${RENEWED_LINEAGE:-unknown}"
NAMES="${RENEWED_DOMAINS:-}"

install -d -m 0755 "$(dirname "$STAMP")"
date -u +%Y-%m-%dT%H:%M:%SZ > "$STAMP"

logger -t dlproxy-cert "证书已更新：${NAMES:-$DOMAIN}"

# Nginx must be reloaded by hand: certbot's nginx/apache installers do not
# support IP identifiers, so the certificate was fetched with webroot and nginx
# is pointing at the files directly.
if systemctl is-active --quiet nginx; then
  # Test before reloading. A broken config plus a reload drops the site; a
  # broken config without one only delays the new certificate.
  if nginx -t 2>/dev/null; then
    systemctl reload nginx
    logger -t dlproxy-cert "nginx 已重载"
  else
    logger -t dlproxy-cert "ERROR nginx 配置校验失败，未重载。新证书已落盘，修复配置后手动 systemctl reload nginx"
  fi
fi
