#!/usr/bin/env bash
# 정적 플레인 기동: docker compose up + MobSF 헬스체크 + API 키 추출 (§8, §14-1).
# 디바이스 없는 머신에서도 이 스크립트만으로 정적 파이프라인 가동.
# 멱등: 재실행해도 안전.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

need docker; need curl
load_env

log "정적 보강 도구 이미지 빌드(apkid/semgrep/LIEF)..."
dc --profile tools build tools

log "정적 플레인(compose) 기동..."
dc up -d

PORT="${MOBSF_PORT:-8010}"
URL="http://localhost:${PORT}"

log "MobSF 헬스 대기 (${URL}) ..."
for i in $(seq 1 40); do
  if curl -fsS -o /dev/null "${URL}/" 2>/dev/null; then
    ok "MobSF 응답 OK (${i}회 시도)"
    break
  fi
  [[ $i -eq 40 ]] && die "MobSF 가 시간 내 안 떴다. 'docker logs mobile-artex-mobsf' 확인."
  sleep 5
done

# API 키 자동 추출 (.env 에 비어 있을 때만). MobSF 는 기동 로그에 REST API Key 출력.
if [[ -z "${MOBSF_API_KEY:-}" ]]; then
  log "MOBSF_API_KEY 미설정 → 컨테이너 로그에서 추출 시도..."
  # MobSF 로그는 ANSI 볼드 코드로 키를 감싼다 → sed 로 제거 후 64-hex 추출.
  # grep 미스가 set -e 로 스크립트를 죽이지 않게 `|| true`.
  KEY="$(docker logs mobile-artex-mobsf 2>&1 | sed 's/\x1b\[[0-9;]*m//g' \
        | grep -oiE 'REST API Key: [a-f0-9]{64}' | tail -1 | awk '{print $NF}' || true)"
  if [[ -n "$KEY" ]]; then
    # .env 의 MOBSF_API_KEY= 라인 교체 (멱등)
    if grep -q '^MOBSF_API_KEY=' "$ENV_FILE"; then
      sed -i "s|^MOBSF_API_KEY=.*|MOBSF_API_KEY=${KEY}|" "$ENV_FILE"
    else
      echo "MOBSF_API_KEY=${KEY}" >> "$ENV_FILE"
    fi
    ok "API 키를 .env 에 기록했다."
  else
    warn "로그에서 API 키를 못 찾았다. MobSF 웹 UI 에서 확인 후 .env 에 수동 입력하라."
  fi
else
  ok "MOBSF_API_KEY 이미 설정됨."
fi

ok "정적 플레인 준비 완료: ${URL}"
