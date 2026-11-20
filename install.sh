#!/usr/bin/env bash
# install.sh — 仓库根目录的入口，只做一件事：把参数原样交给 deploy/install.sh。
#
#   sudo ./install.sh                  逐条询问
#   sudo ./install.sh --yes            全部取推荐值
#   sudo ./install.sh --dry-run        只打印将要执行的命令
#
# 为什么要有这么一个转发脚本，而不是把 deploy/install.sh 挪到根目录：向导用
# `DLPROXY_LIB_ONLY=1 . "$SCRIPT_DIR/deploy.sh"` 复用安装器的探测函数，两个文件
# 必须留在同一个目录里。README 与文档一直写 `sudo ./install.sh`，而根目录没有
# 这个文件时那条命令直接 404 —— 转发一行比让每个读者自己发现要便宜。
#
# 注意：这个脚本**必须被当作文件执行**，不能 `curl … | bash`。管道里
# BASH_SOURCE[0] 是空串，dirname 会得到 "."，`deploy/install.sh` 就找不到了。
# 下载 tarball 再执行，别把安装脚本喂给 stdin。
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="$here/deploy/install.sh"

if [[ ! -f "$target" ]]; then
  echo "[x] 找不到 $target" >&2
  echo "    这个脚本要求整个仓库目录完整：请解开 tarball 或 git clone 之后在仓库根目录执行。" >&2
  echo "    如果你是把脚本通过管道喂给 bash 的，改用文件：curl -fLO … && bash install.sh" >&2
  exit 1
fi

exec bash "$target" "$@"
