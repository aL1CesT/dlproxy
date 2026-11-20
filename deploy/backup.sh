#!/usr/bin/env bash
# dlproxy-backup — daily SQLite snapshot, 7-day retention.
#
# `cp app.db backup.db` is wrong for two independent reasons: the database runs
# in WAL mode (recent commits live in app.db-wal, not in app.db), and a copy
# taken mid-write can capture a torn page. The Python sqlite3 backup API asks
# SQLite itself for a consistent snapshot, run by the live connection.
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/dlproxy}"
DB="${DLPROXY_DB_PATH:-$APP_DIR/data/app.db}"
DEST_DIR="${APP_DIR}/backup"
KEEP_DAYS=7
STAMP="$(date +%F)"

[[ -r "$DB" ]] || { echo "数据库不存在: $DB"; exit 1; }
install -d -m 0750 "$DEST_DIR"
umask 077

DEST="$DEST_DIR/app_${STAMP}.db"

# Run as the dlproxy user so the file ownership matches the service, and so a
# future permission tightening on the app directory does not break backups.
if id dlproxy >/dev/null 2>&1; then
  RUN=(sudo -u dlproxy)
else
  RUN=()
fi

"${RUN[@]}" /opt/dlproxy/venv/bin/python - "$DB" "$DEST" <<'PY'
import sqlite3, sys
src_path, dst_path = sys.argv[1], sys.argv[2]
src = sqlite3.connect(src_path)
dst = sqlite3.connect(dst_path)
with dst:
    src.backup(dst)          # consistent, page-level snapshot
dst.close()
src.close()
print(f"backup ok: {dst_path}")
PY

# Verify the snapshot actually opens and has the expected table.
/opt/dlproxy/venv/bin/python - "$DEST" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
missing = {"users", "transfers", "counters", "settings"} - tables
if missing:
    raise SystemExit(f"备份损坏，缺少表: {missing}")
n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
print(f"backup verified: {n} users")
conn.close()
PY

# Retention: keep the newest KEEP_DAYS daily snapshots.
find "$DEST_DIR" -maxdepth 1 -name 'app_*.db' -type f -printf '%T@ %p\n' \
  | sort -rn \
  | awk -v keep="$KEEP_DAYS" 'NR>keep {sub(/^[^ ]+ /, ""); print}' \
  | while read -r old; do
      echo "prune: $old"
      rm -f -- "$old"
    done
