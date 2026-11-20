#!/usr/bin/env bash
# tools/e2e_nginx.sh — prove the URL shape survives nginx, on this machine.
#
# The entire link format (https://host/u/<token>/https://upstream/path) depends
# on nginx relaying the request URI byte for byte. That is true only when
# proxy_pass has no URI component. This script starts a throwaway nginx and a
# recording upstream, throws the awkward cases at it, and fails loudly if any
# byte changed.
#
#   tools/e2e_nginx.sh [path-to-nginx-binary]
#
# Exits 0 only if every case matches exactly.
#
# For the full nginx → app → origin chain with real downloads, see
# tools/e2e_full.py instead.
set -uo pipefail

NGINX="${1:-}"
WORK="$(mktemp -d)"
LISTEN="${LISTEN:-18200}"
UPSTREAM="${UPSTREAM:-18201}"
RECORD="$WORK/recorded.txt"

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
pass=0; fail=0

# nginx is a native binary even under MSYS/Cygwin, so paths handed to it must be
# Windows-style there. cygpath is absent on Linux, hence the fallback.
NGX_WORK="$WORK"
if command -v cygpath >/dev/null 2>&1; then
  NGX_WORK="$(cygpath -m "$WORK")"
fi

port_open() {
  # Wrapped in a child bash so the connect error message is discarded with the
  # whole child's stderr; redirecting the `exec` alone still leaks it.
  bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" >/dev/null 2>&1
}

wait_for_port() {
  for _ in $(seq 1 "${2:-60}"); do
    port_open "$1" && return 0
    sleep 0.1
  done
  return 1
}

cleanup() {
  if [[ -n "${NGINX_PID:-}" ]]; then
    kill "$NGINX_PID" 2>/dev/null
    [[ -r "$WORK/logs/nginx.pid" ]] && kill "$(cat "$WORK/logs/nginx.pid")" 2>/dev/null
  fi
  [[ -n "${REC_PID:-}" ]] && kill "$REC_PID" 2>/dev/null
  sleep 0.2
  rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT

# Reuse an nginx that is already running on the ports? Refuse — the assertions
# would then be testing someone else's configuration.
if port_open "$LISTEN" || port_open "$UPSTREAM"; then
  echo "端口 $LISTEN/$UPSTREAM 已被占用，请先停掉相关进程"; exit 1
fi

if [[ -z "$NGINX" ]]; then
  NGINX=$(command -v nginx || true)
fi
[[ -n "$NGINX" && -x "$NGINX" ]] || {
  echo "找不到 nginx 可执行文件；用法: $0 /path/to/nginx"; exit 1; }

echo "==> 工作目录 $WORK"
echo "==> nginx: $NGINX"

# --- recording upstream ------------------------------------------------------
cat > "$WORK/record.py" <<'PY'
import socket, sys, threading

out = open(sys.argv[2], "ab", buffering=0)
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(64)


def handle(c):
    with c:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = c.recv(65536)
            if not chunk:
                return
            data += chunk
        out.write(data.split(b"\r\n", 1)[0] + b"\n")
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                  b"Connection: close\r\n\r\nok")


while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PY
python3 "$WORK/record.py" "$UPSTREAM" "$RECORD" >/dev/null 2>&1 &
REC_PID=$!
wait_for_port "$UPSTREAM" || { echo "记录服务器启动失败"; exit 1; }
echo "==> 记录服务器就绪（:$UPSTREAM）"

# --- throwaway nginx ---------------------------------------------------------
# nginx creates its temp dirs under the prefix; pre-creating them keeps the run
# quiet on hosts where the default prefix directories do not exist.
mkdir -p "$WORK/conf" "$WORK/logs" \
         "$WORK/temp/client_body_temp" "$WORK/temp/proxy_temp" \
         "$WORK/temp/fastcgi_temp" "$WORK/temp/uwsgi_temp" "$WORK/temp/scgi_temp"

write_conf() {
  cat > "$WORK/conf/nginx.conf" <<EOF
worker_processes 1;
error_log $NGX_WORK/logs/error.log warn;
pid $NGX_WORK/logs/nginx.pid;
events { worker_connections 64; }
http {
    access_log off;
    client_header_buffer_size 8k;
    large_client_header_buffers 8 32k;
    server {
        listen $LISTEN;
        server_name _;
        $1
    }
}
EOF
}

write_conf 'location / { proxy_pass http://127.0.0.1:'"$UPSTREAM"'; proxy_http_version 1.1; proxy_set_header Connection ""; }'

"$NGINX" -p "$NGX_WORK/" -c "$NGX_WORK/conf/nginx.conf"
NGINX_PID=$!
if ! wait_for_port "$LISTEN"; then
  echo "nginx 启动失败："; tail -5 "$WORK/logs/error.log" 2>/dev/null; exit 1
fi
echo "==> nginx 就绪（:$LISTEN）"

# --- cases -------------------------------------------------------------------
# Format: <description>|<request path>|<path nginx should relay verbatim>
CASES=(
  "plain https|/u/TOK/https://e.com/a.zip|/u/TOK/https://e.com/a.zip"
  "double slash|/u/TOK/https://e.com/a//b.zip|/u/TOK/https://e.com/a//b.zip"
  "triple slash|/u/TOK/https://e.com/a///b.zip|/u/TOK/https://e.com/a///b.zip"
  "encoded slash|/u/TOK/https://e.com/x%2Fy.zip|/u/TOK/https://e.com/x%2Fy.zip"
  "space escape|/u/TOK/https://e.com/sp%20ace.zip|/u/TOK/https://e.com/sp%20ace.zip"
  "utf8 escape|/u/TOK/https://e.com/%e4%b8%ad%e6%96%87.zip|/u/TOK/https://e.com/%e4%b8%ad%e6%96%87.zip"
  "query kept|/u/TOK/https://e.com/p?a=1&b=2|/u/TOK/https://e.com/p?a=1&b=2"
  "uppercase scheme|/u/TOK/HTTPS://E.COM/A.ZIP|/u/TOK/HTTPS://E.COM/A.ZIP"
  "dot segment|/u/TOK/https://e.com/a/./b.zip|/u/TOK/https://e.com/a/./b.zip"
  "dotdot segment|/u/TOK/https://e.com/../x.zip|/u/TOK/https://e.com/../x.zip"
  "userinfo kept|/u/TOK/https://user:pass@e.com/a.zip|/u/TOK/https://user:pass@e.com/a.zip"
  "high port kept|/u/TOK/https://e.com:8443/a.zip|/u/TOK/https://e.com:8443/a.zip"
)

echo "==> 逐例比对 nginx 转发的请求行"
: > "$RECORD"
for case in "${CASES[@]}"; do
  desc="${case%%|*}"
  rest="${case#*|}"
  req="${rest%%|*}"
  want="${rest#*|}"
  curl -s --noproxy '*' --max-time 5 -o /dev/null "http://127.0.0.1:$LISTEN$req" || true
  for _ in $(seq 1 30); do
    got=$(tail -1 "$RECORD" 2>/dev/null | awk '{print $2}')
    [[ -n "$got" ]] && break
    sleep 0.05
  done
  if [[ "$got" == "$want" ]]; then
    printf '  %s✓%s %-16s %s\n' "$GRN" "$RST" "$desc" "$got"
    pass=$((pass + 1))
  else
    printf '  %s✗%s %-16s\n      期望: %s\n      实收: %s\n' "$RED" "$RST" "$desc" "$want" "$got"
    fail=$((fail + 1))
  fi
  : > "$RECORD"
done

# --- negative control --------------------------------------------------------
# Same request against a proxy_pass WITH a URI: this must mangle the URL, which
# is what proves the assertion above is testing something real.
echo "==> 反证：proxy_pass 带斜杠时应改写 URL"
kill "$NGINX_PID" 2>/dev/null
[[ -r "$WORK/logs/nginx.pid" ]] && kill "$(cat "$WORK/logs/nginx.pid")" 2>/dev/null
sleep 0.4
write_conf 'location /bad/ { proxy_pass http://127.0.0.1:'"$UPSTREAM"'/; }'
"$NGINX" -p "$NGX_WORK/" -c "$NGX_WORK/conf/nginx.conf"
NGINX_PID=$!
wait_for_port "$LISTEN" || { echo "nginx 重启失败"; exit 1; }
: > "$RECORD"
curl -s --noproxy '*' --max-time 5 -o /dev/null \
  "http://127.0.0.1:$LISTEN/bad/u/TOK/https://e.com/a//b.zip" || true
for _ in $(seq 1 30); do
  mangled=$(tail -1 "$RECORD" 2>/dev/null | awk '{print $2}')
  [[ -n "$mangled" ]] && break
  sleep 0.05
done
if [[ "$mangled" == *"https://"* ]]; then
  printf '  %s✗%s 反证未生效，本测试失去意义\n' "$RED" "$RST"
  fail=$((fail + 1))
else
  printf '  %s✓%s 带斜杠的写法确实改写了 URL: %s\n' "$GRN" "$RST" "$mangled"
  pass=$((pass + 1))
fi

echo
if (( fail == 0 )); then
  echo "${GRN}全部 $pass 项通过${RST} — nginx 原样转发请求 URI，链接形态安全"
  exit 0
fi
echo "${RED}$fail 项失败${RST} — 检查 proxy_pass 是否被写成了带 URI 的形式"
exit 1
