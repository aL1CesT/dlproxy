#!/bin/sh
# dlproxy — thin wrapper so the box has one obvious command.
#
#   sudo dlproxy              → the interactive menu
#   sudo dlproxy createuser alice
#   sudo dlproxy listusers
#
# Every action talks to the same SQLite file the service uses, so it is safe
# while the service is running. The database is owned by the unprivileged
# `dlproxy` system user (mode 0750 on data/), so this wrapper always drops
# privileges before touching it — running the Python module as root would
# create root-owned -wal/-shm files and the service would lose write access.
set -eu

APP_DIR="/opt/dlproxy"
APP_USER="dlproxy"
VENV_PY="$APP_DIR/venv/bin/python"

# `python -m app` resolves the package from the current directory, which only
# works because the systemd unit sets WorkingDirectory. A human typing
# `sudo dlproxy` from ~ would get "No module named app", so cd first. This also
# puts data/app.db at the path the service uses.
cd "$APP_DIR"

# `python -m app` with no sub-command starts the server. That is right for the
# systemd unit and wrong for a human typing `dlproxy`, so default to the menu.
if [ "$#" -eq 0 ]; then
    set -- menu
fi

# Same rule as the other scripts: an escape sequence in a log file is noise.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
    RED="$(printf '\033')[31m"; RST="$(printf '\033')[0m"
else
    RED=""; RST=""
fi

if [ ! -x "$VENV_PY" ]; then
    printf '%s[x]%s 没找到 %s\n' "$RED" "$RST" "$VENV_PY" >&2
    printf '    先跑 deploy.sh 的 deps/app 阶段。\n' >&2
    exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
    if ! id "$APP_USER" >/dev/null 2>&1; then
        printf '%s[x]%s 系统用户 %s 不存在，服务未部署？\n' \
            "$RED" "$RST" "$APP_USER" >&2
        exit 1
    fi
    # -H so pip/python do not leave root's HOME pointing into /root, and so the
    # menu is run with the same working directory the unit uses.
    exec sudo -u "$APP_USER" -H -- "$VENV_PY" -m app "$@"
fi

if [ "$(id -un)" = "$APP_USER" ]; then
    exec "$VENV_PY" -m app "$@"
fi

printf '%s[x]%s 请用 sudo 运行：sudo dlproxy\n' \
    "$RED" "$RST" >&2
exit 1
