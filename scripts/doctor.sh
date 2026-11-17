#!/usr/bin/env bash
# 환경 점검 (§7 상태머신의 CLI 버전, §12). 동적 단계 전 검증.
# 컨테이너 상태 / frida 버전·arch 일치 / 기기 연결. 읽기 전용(변경 없음).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
load_env

FAIL=0
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else warn "$1 — 실패"; FAIL=$((FAIL+1)); fi; }

echo "=== 정적 플레인 ==="
check "docker 사용 가능"            "command -v docker"
check "MobSF 컨테이너 Up"           "docker ps --format '{{.Names}}' | grep -q mobile-artex-mobsf"
check "MobSF HTTP 응답"             "curl -fsS -o /dev/null ${MOBSF_URL:-http://localhost:8010}/"
if [[ -n "${MOBSF_API_KEY:-}" ]]; then ok "MOBSF_API_KEY 설정됨"; else warn "MOBSF_API_KEY 비어있음 — setup-static.sh 재실행"; FAIL=$((FAIL+1)); fi

echo "=== 동적 플레인 (없으면 정적만 사용 가능) ==="
FRIDA_VER_CFG="$(grep -E '^\s*version:' "${REPO_ROOT}/config/device_profiles.yaml" | head -1 | awk '{print $2}' | tr -d '"')"
if command -v frida >/dev/null 2>&1; then
  HOST_VER="$(frida --version 2>/dev/null || true)"
  if [[ "$HOST_VER" == "$FRIDA_VER_CFG" ]]; then
    ok "frida 호스트 버전 ${HOST_VER} == config ${FRIDA_VER_CFG}"
  else
    warn "frida 버전 불일치: 호스트=${HOST_VER} config=${FRIDA_VER_CFG} (동적 실패 1순위)"
  fi
else
  warn "frida 호스트 미설치 — setup-dynamic.sh"
fi

ANDROID_TGT="$(grep -A4 '^android:' "${REPO_ROOT}/config/device_profiles.yaml" | grep -E '^\s*target:' | head -1 | sed 's/.*:[[:space:]]*//' | tr -d '"')"
if command -v frida-ls-devices >/dev/null 2>&1; then
  echo "--- frida-ls-devices (-U 미사용) ---"
  frida-ls-devices 2>/dev/null || warn "기기 목록 조회 실패"
  if [[ -n "$ANDROID_TGT" ]]; then
    frida-ls-devices 2>/dev/null | grep -q "$ANDROID_TGT" && ok "android.target(${ANDROID_TGT}) 연결됨" || warn "android.target(${ANDROID_TGT}) 미연결"
  else
    warn "android.target 미설정 (동적 미사용시 무시)"
  fi
fi
command -v adb >/dev/null 2>&1 && ok "adb 사용 가능" || warn "adb 미설치"
command -v idevice_id >/dev/null 2>&1 && ok "libimobiledevice 사용 가능" || warn "libimobiledevice 미설치 (iOS 동적시 필요)"

echo "============================"
if [[ $FAIL -eq 0 ]]; then ok "정적 플레인 핵심 점검 통과."; else warn "핵심 점검 ${FAIL}건 실패 — 위 메시지 확인."; fi
exit 0
