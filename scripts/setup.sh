#!/usr/bin/env bash
# 진입점 (§3, §14-1): clone 후 한 방 셋업. static 먼저, 그다음 dynamic.
# 디바이스 없는 머신은 `scripts/setup-static.sh` 만 돌려도 됨.
#
#   ./scripts/setup.sh            # 정적 + 동적
#   ./scripts/setup.sh --static   # 정적만
set -euo pipefail
HERE="$(dirname "${BASH_SOURCE[0]}")"
source "${HERE}/lib.sh"

ensure_env

"${HERE}/setup-static.sh"

if [[ "${1:-}" == "--static" ]]; then
  ok "정적만 셋업 완료 (--static)."
  exit 0
fi

log "동적 의존성 셋업 시도 (실패해도 정적은 유효)..."
"${HERE}/setup-dynamic.sh" || warn "동적 셋업 일부 실패 — 정적 파이프라인은 사용 가능."

ok "setup.sh 완료. 상태 점검: ./scripts/doctor.sh"
