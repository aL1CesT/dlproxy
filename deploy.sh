#!/usr/bin/env bash
# deploy.sh — 仓库根目录的入口，只做一件事：把参数原样交给 deploy/deploy.sh。
#
#   sudo ./deploy.sh --stage all
#   sudo ./deploy.sh --domain dl.example.com
#   sudo ./deploy.sh --share-443 --tls-service-port 10443
#
# 存在的理由和根目录的 install.sh 一样：文档里每一处都写 `sudo ./deploy.sh`，
# 而安装器其实在 deploy/ 里。少一层让人自己发现的路径。
#
# 安装器内部用 BASH_SOURCE 定位自己的源码根（deploy/deploy.sh:30），所以从这里
# 转发进去之后它仍然指向正确的目录，行为与直接调用完全一致。
#
# 装完之后也可以直接用装好的那一份（源码目录可以删）：
#   sudo /opt/dlproxy/deploy/deploy.sh --stage cert --domain dl.example.com
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="$here/deploy/deploy.sh"

if [[ ! -f "$target" ]]; then
  echo "[x] 找不到 $target" >&2
  echo "    这个脚本要求整个仓库目录完整：请解开 tarball 或 git clone 之后在仓库根目录执行。" >&2
  exit 1
fi

exec bash "$target" "$@"
