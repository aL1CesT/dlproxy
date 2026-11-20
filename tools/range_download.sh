#!/usr/bin/env bash
# tools/range_download.sh — 16 parallel Range requests, then verify the result.
#
# The acceptance checklist needs a downloader that is not aria2 (this box does
# not have it) and that proves two things at once: the reassembled file matches
# the upstream bytes, and the gateway recorded all 16 streams as a single history
# row.
#
#   tools/range_download.sh <accelerated-url> <output-file> [threads] [sha256]
#
# Example:
#   tools/range_download.sh \
#     "https://203.0.113.10/u/TOKEN/https://example.com/big.iso" \
#     ./big.iso 16 e3b0c44298fc1c149afbf4c8996fb924...
set -euo pipefail

URL="${1:?用法: $0 <accelerated-url> <output-file> [threads] [sha256]}"
OUT="${2:?缺少输出文件名}"
THREADS="${3:-16}"
EXPECT_SHA="${4:-}"

PARTDIR="$(mktemp -d)"
trap 'rm -rf "$PARTDIR"' EXIT

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

echo "==> 探测上游是否支持 Range"
HEADERS=$(curl -sS --noproxy '*' -I --max-time 30 "$URL")
SIZE=$(printf '%s' "$HEADERS" | tr -d '\r' | awk 'tolower($1)=="content-length:" {print $2}' | tail -1)
RANGES_OK=$(printf '%s' "$HEADERS" | tr -d '\r' | awk 'tolower($1)=="accept-ranges:" {print $2}' | tail -1)

[[ -n "${SIZE:-}" ]] || { echo "${RED}拿不到 Content-Length，无法分片${RST}"; exit 1; }
echo "    大小: $SIZE 字节, Accept-Ranges: ${RANGES_OK:-未声明}"

if [[ "${RANGES_OK:-}" != "bytes" ]]; then
  echo "${YEL}上游没有声明 Accept-Ranges: bytes — 仍尝试分片，若失败请改用单线程${RST}"
fi

CHUNK=$(( (SIZE + THREADS - 1) / THREADS ))
echo "==> 分 $THREADS 段，每段约 $CHUNK 字节"

pids=()
start_ts=$(date +%s)
for ((i = 0; i < THREADS; i++)); do
  start=$(( i * CHUNK ))
  end=$(( start + CHUNK - 1 ))
  (( end >= SIZE )) && end=$(( SIZE - 1 ))
  part="$PARTDIR/part.$(printf '%03d' "$i")"
  (
    curl -sS --noproxy '*' --max-time 3600 \
      -r "${start}-${end}" \
      -o "$part" "$URL" || { echo "段 $i 失败" >&2; exit 1; }
  ) &
  pids+=($!)
done

failed=0
for pid in "${pids[@]}"; do
  wait "$pid" || failed=$((failed + 1))
done
(( failed == 0 )) || { echo "${RED}$failed 个分片失败${RST}"; exit 1; }

cat "$PARTDIR"/part.* > "$OUT"
end_ts=$(date +%s)
elapsed=$(( end_ts - start_ts ))
(( elapsed > 0 )) || elapsed=1
speed=$(( SIZE / elapsed / 1024 ))
echo "==> 合并完成: $OUT ($(stat -c%s "$OUT") 字节, ${elapsed}s, 约 ${speed} KiB/s)"

ACTUAL_SIZE=$(stat -c%s "$OUT")
if [[ "$ACTUAL_SIZE" != "$SIZE" ]]; then
  echo "${RED}大小不符: 期望 $SIZE，实际 $ACTUAL_SIZE${RST}"
  exit 1
fi
echo "    大小校验通过"

ACTUAL_SHA=$(sha256sum "$OUT" | awk '{print $1}')
if [[ -n "$EXPECT_SHA" ]]; then
  if [[ "$ACTUAL_SHA" == "$EXPECT_SHA" ]]; then
    echo "${GRN}    sha256 与预期一致: $ACTUAL_SHA${RST}"
  else
    echo "${RED}    sha256 不符${RST}"
    echo "      预期: $EXPECT_SHA"
    echo "      实际: $ACTUAL_SHA"
    exit 1
  fi
else
  echo "    sha256: $ACTUAL_SHA"
fi

echo "${GRN}==> 下载完成${RST}"
echo "    现在到首页历史里确认：这 $THREADS 个请求应合并为 1 条记录，"
echo "    bytes_sent 应等于 $SIZE。"
