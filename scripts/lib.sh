#!/usr/bin/env bash
# 공통 헬퍼 (모든 스크립트가 source). 하드코딩 금지 — 값은 .env / config 에서.
set -euo pipefail

# 레포 루트 (이 파일 위치 기준, 어디서 호출하든 안전)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export REPO_ROOT

COMPOSE_FILE="${REPO_ROOT}/docker/docker-compose.yml"
ENV_FILE="${REPO_ROOT}/.env"

log()  { printf '\033[0;36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[0;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[0;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# .env 가 없으면 예제에서 생성 (멱등)
ensure_env() {
  if [[ ! -f "$ENV_FILE" ]]; then
    cp "${REPO_ROOT}/.env.example" "$ENV_FILE"
    warn ".env 가 없어 .env.example 에서 생성했다. 필요시 값을 편집하라: $ENV_FILE"
  fi
}

# .env 로드 (주석/빈 줄 무시)
load_env() {
  ensure_env
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
}

need() { command -v "$1" >/dev/null 2>&1 || die "필수 명령 없음: $1"; }

# docker compose 래퍼 (v2 / v1 호환)
dc() {
  if docker compose version >/dev/null 2>&1; then
    docker compose -f "$COMPOSE_FILE" "$@"
  else
    docker-compose -f "$COMPOSE_FILE" "$@"
  fi
}
