#!/bin/sh
# 比对 tpk_installer.py 的三个副本是否同源。
#
# 这个应用有两份运行代码，改一处忘另一处会出很难查的问题：
#   1. 本地源码          —— app/tpk_installer.py（改这个）
#   2. 容器运行版        —— 应用中心装的 appinstall 容器实际在用
#   3. 主机兜底版        —— 容器被卸载时，systemd 服务会用它接替
# 第 3 份最容易漏：漏了的话，卸掉容器后闸门和包库管理会一起消失。
#
# 连接信息一律从环境变量读，不写死在脚本里（避免把内网地址带进公开仓库）：
#   NAS_HOST=你的NAS地址 [NAS_PORT=22] [NAS_KEY=~/.ssh/id_ed25519] ./check_sync.sh
set -e

: "${NAS_HOST:?用法: NAS_HOST=... [NAS_PORT=22] [NAS_KEY=...] tools/check_sync.sh}"
NAS_PORT="${NAS_PORT:-22}"
NAS_USER="${NAS_USER:-root}"

SSH="ssh -p $NAS_PORT -o StrictHostKeyChecking=no"
[ -n "$NAS_KEY" ] && SSH="$SSH -i $NAS_KEY"

HERE=$(cd "$(dirname "$0")" && pwd)
LOCAL="$HERE/../app/tpk_installer.py"
APP_DIR="${APP_DIR:-/volume1/@appstore/com.centerm.docker.appinstall}"
HOST_COPY="${HOST_COPY:-/userdata/tpk_local/tpk_installer.py}"

[ -f "$LOCAL" ] || { echo "找不到本地源码: $LOCAL"; exit 2; }

md5of() { md5sum "$1" 2>/dev/null | cut -d' ' -f1; }

L=$(md5of "$LOCAL")
C=$($SSH "$NAS_USER@$NAS_HOST" "md5sum '$APP_DIR/app/tpk_installer.py'" 2>/dev/null | cut -d' ' -f1)
H=$($SSH "$NAS_USER@$NAS_HOST" "md5sum '$HOST_COPY'" 2>/dev/null | cut -d' ' -f1)

echo "本地源码    ${L:-读取失败}"
echo "容器运行版  ${C:-读取失败}"
echo "主机兜底版  ${H:-读取失败}"
echo

if [ -n "$L" ] && [ "$L" = "$C" ] && [ "$L" = "$H" ]; then
    echo "结论: 三处一致"
    exit 0
fi

echo "结论: 存在漂移，按下面两条同步即可"
echo "  scp \"$LOCAL\" $NAS_USER@$NAS_HOST:'$APP_DIR/app/tpk_installer.py'"
echo "  scp \"$LOCAL\" $NAS_USER@$NAS_HOST:'$HOST_COPY'"
echo "  # 容器版改完记得重建容器让代码生效："
echo "  #   cd $APP_DIR && docker compose -p appinstall up -d"
exit 1
