#!/usr/bin/env bash
# frida-server 부트스트랩 (§7, §9-2): 기기 arch 감지 → 버전 매칭 바이너리 push·실행
# → frida-ls-devices 로 해당 기기 ID 확인. 멱등.
# config/device_profiles.yaml 의 frida.version / android.target / android.arch 사용.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
need adb; need curl

cfg() { grep -E "^\s*$1:" "${REPO_ROOT}/config/device_profiles.yaml" | head -1 | sed 's/.*:[[:space:]]*//' | tr -d '"'; }

FRIDA_VERSION="$(cfg version)"; FRIDA_VERSION="${FRIDA_VERSION:-16.1.4}"
SERIAL="$(cfg target)"
[[ -z "$SERIAL" ]] && die "android.target(adb serial) 미설정 — config/device_profiles.yaml 참고(§7). -U 금지."

# 기기 arch 감지 (config 값보다 실측 우선)
ABI="$(adb -s "$SERIAL" shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')"
case "$ABI" in
  x86_64|x86) FA="x86";   [[ "$ABI" == x86_64 ]] && FA="x86_64" ;;
  arm64-v8a)  FA="arm64" ;;
  armeabi*)   FA="arm" ;;
  *) die "알 수 없는 ABI: '$ABI' (기기 연결 확인)" ;;
esac
log "기기 ${SERIAL} ABI=${ABI} → frida-server arch=${FA}, version=${FRIDA_VERSION}"

CACHE="${REPO_ROOT}/.cache/frida"
mkdir -p "$CACHE"
BIN="${CACHE}/frida-server-${FRIDA_VERSION}-android-${FA}"
if [[ ! -f "$BIN" ]]; then
  XZ="${BIN}.xz"
  URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-${FA}.xz"
  log "다운로드: $URL"
  curl -fsSL -o "$XZ" "$URL" || die "frida-server 다운로드 실패 (버전/arch 확인)."
  xz -df "$XZ"
fi

log "기기로 push·실행..."
adb -s "$SERIAL" push "$BIN" /data/local/tmp/frida-server >/dev/null
adb -s "$SERIAL" shell "chmod 755 /data/local/tmp/frida-server"
adb -s "$SERIAL" shell "su -c 'killall frida-server 2>/dev/null; /data/local/tmp/frida-server &' >/dev/null 2>&1 &" || \
  adb -s "$SERIAL" shell "/data/local/tmp/frida-server &" >/dev/null 2>&1 &
sleep 2

log "frida-ls-devices 확인(§7, -U 미사용):"
if command -v frida-ls-devices >/dev/null 2>&1; then
  frida-ls-devices || warn "frida 호스트 미설치/비활성 — setup-dynamic.sh 먼저."
else
  warn "frida-ls-devices 없음 — 'source .venv-dynamic/bin/activate' 후 재시도."
fi
ok "frida-server(${FRIDA_VERSION}/${FA}) 부트스트랩 완료."
