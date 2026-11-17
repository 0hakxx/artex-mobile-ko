#!/usr/bin/env bash
# 동적 플레인 호스트 의존성 설치 (§9·§10). 컨테이너 아님 — WSL2 호스트에.
# frida/objection/libimobiledevice. 멱등.
# 디바이스 없는 머신에서는 안 돌려도 정적은 가동됨.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

load_env
FRIDA_VERSION="$(grep -E '^\s*version:' "${REPO_ROOT}/config/device_profiles.yaml" | head -1 | awk '{print $2}' | tr -d '"')"
FRIDA_VERSION="${FRIDA_VERSION:-16.1.4}"

log "호스트 동적 의존성 설치 (frida-tools==${FRIDA_VERSION} 기준)"

# Python 가상환경 (호스트 전역 오염 방지)
VENV="${REPO_ROOT}/.venv-dynamic"
if [[ ! -d "$VENV" ]]; then
  need python3
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "${VENV}/bin/activate"

pip install --quiet --upgrade pip
# 파이프라인 런타임(스키마/설정 로더)도 동적 venv 에 필요.
pip install --quiet pydantic PyYAML
# frida 버전 고정 — 호스트/서버 불일치 방지(§2). frida-tools 는 호환 frida 끌어옴.
pip install --quiet "frida==${FRIDA_VERSION}" "frida-tools" objection || \
  warn "frida/objection 설치 일부 실패 — 네트워크/빌드 의존성 확인."

# libimobiledevice (iOS, apt). 설치 안 돼 있으면 안내만 (sudo 필요).
if ! command -v idevice_id >/dev/null 2>&1; then
  warn "libimobiledevice 미설치. iOS 동적을 쓰려면:"
  warn "  sudo apt-get install -y libimobiledevice6 libimobiledevice-utils usbmuxd"
fi

# adb 확인
command -v adb >/dev/null 2>&1 || warn "adb 미설치 (Android 동적 필요). android-tools-adb 설치 권장."

ok "동적 의존성 설치 단계 완료. 가상환경: ${VENV}"
ok "활성화: source ${VENV}/bin/activate"
