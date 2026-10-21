#!/bin/sh
# Cross-build spdm-req-tool for the BMC and copy it over SSH.
#   BMC=root@10.0.0.120 BMC_PASS=0penBmc scripts/deploy.sh [dest-dir]
set -e
cd "$(dirname "$0")/.."

BMC=${BMC:-root@10.0.0.120}
DEST=${1:-/tmp}
BUILD=${BUILD:-build-aarch64}

if [ ! -f "$BUILD/CMakeCache.txt" ]; then
    cmake -S . -B "$BUILD" -DCMAKE_TOOLCHAIN_FILE="$PWD/cmake/aarch64-linux-gnu.cmake" \
        -DCMAKE_BUILD_TYPE=Release
fi
cmake --build "$BUILD" -j
aarch64-linux-gnu-strip -o "$BUILD/spdm-req-tool.stripped" "$BUILD/spdm-req-tool"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
if [ -n "$BMC_PASS" ]; then
    SCP="sshpass -p $BMC_PASS scp"
else
    SCP="scp"
fi
# BusyBox/dropbear targets often lack sftp-server, so force the legacy protocol.
$SCP -O $SSH_OPTS "$BUILD/spdm-req-tool.stripped" "$BMC:$DEST/spdm-req-tool"
echo "deployed to $BMC:$DEST/spdm-req-tool"
