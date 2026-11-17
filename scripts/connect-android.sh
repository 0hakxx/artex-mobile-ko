#!/usr/bin/env bash
# BlueStacks adb-over-TCP 연결 (§9). Windows 호스트 IP:포트로 TCP 연결.
# 값은 config/device_profiles.yaml 의 android.bluestacks_host_port 에서 읽음.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
need adb

HOSTPORT="$(grep -E '^\s*bluestacks_host_port:' "${REPO_ROOT}/config/device_profiles.yaml" | head -1 | sed 's/.*:[[:space:]]*//' | tr -d '"')"
[[ -z "$HOSTPORT" ]] && die "config/device_profiles.yaml 의 android.bluestacks_host_port 를 먼저 설정하라 (예: <windows-host-ip>:5555)."

log "adb connect ${HOSTPORT}"
adb connect "$HOSTPORT"
adb devices -l
ok "연결 시도 완료. 'frida-ls-devices' 로 기기 ID 확인(§7)."
