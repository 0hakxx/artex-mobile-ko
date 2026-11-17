# Mobile ARTEX

APK/IPA 자동 정적 분석 → (디바이스 연결 시) 동적 검증 → MASTG/전자금융 매핑 리포트.
성숙한 오픈소스(MobSF·jadx·semgrep·Frida·objection 등)를 에이전트 호출용 어댑터로
감싸 오케스트레이션한다. 분석 엔진은 새로 만들지 않는다. 설계 전체는 [PLAN.md](PLAN.md).

> **이 레포만으로 설정 가능 (self-contained).** 외부 ARTEX 서비스에 의존하지 않는다.
> MobSF 는 Docker Hub 공개 이미지, 보강 도구·웹 UI 는 레포 내 `Dockerfile.tools` 로
> 빌드된다. `git clone` 후 아래 3줄이면 브라우저에서 바로 분석 가능.

## 빠른 시작 (clone → 웹 UI 접속)

```bash
git clone https://github.com/0hakxx/artex-mobile-ko.git && cd artex-mobile-ko
cp .env.example .env            # (선택) 포트 등 편집. setup 이 없으면 자동 생성.
./scripts/setup-static.sh       # MobSF + 보강도구 이미지 빌드 + API 키 자동 추출
docker compose -f docker/docker-compose.yml up -d web   # 웹 UI 기동
```

→ 브라우저에서 **http://localhost:8020** 접속 → APK/IPA 드래그&드롭 → MASTG/전자금융 리포트.

CLI 로 바로 돌리려면:

```bash
docker compose -f docker/docker-compose.yml run --rm tools \
  run_static.py tests/samples/<앱>.apk --fresh
```

동적(Frida/디바이스)까지 셋업: `./scripts/setup.sh` · 환경 점검: `./scripts/doctor.sh`

> 포트 기본값: MobSF `8010`, 웹 UI `8020` (호스트 8000/8787 충돌 회피). `.env` 에서 변경.
> 테스트 APK/IPA 는 `.gitignore` 로 제외 — 공개 샘플(InsecureBankv2, DVIA-v2)은 직접 받는다.

## 토폴로지 (§3)

- **정적 플레인 = Docker compose.** MobSF 등 디바이스를 안 건드리는 도구. `docker/docker-compose.yml`.
- **동적 플레인 = WSL2 호스트 프로세스.** adb·frida·objection·libimobiledevice. 컨테이너 밖.
- **seam = findings store.** 양쪽이 공유 마운트 경로(`store/`)의 같은 findings 에 적재.

## 디렉터리 (§12)

| 경로 | 역할 |
|---|---|
| `schema/` | findings 스키마(Pydantic) + config 로더 |
| `mappings/` | 도구 네이티브 분류 → MASTG/MASVS 매핑 테이블 |
| `adapters/` | 도구별 래퍼 (mobsf, semgrep, apkid, lief, adb, frida ...) |
| `normalizers/` | 각 도구 출력 → findings 변환기 |
| `store/` | findings 저장 (JSONL → SQLite) |
| `pipeline/` | 순차 오케스트레이터 (1단계) |
| `orchestrator/` | Planner/Worker (2단계, 나중) |
| `report/` | MASTG/전자금융 템플릿·렌더러 |
| `config/` | 도구 경로, frida 버전·arch, device_profiles.yaml |
| `docker/` | 정적 플레인 compose |
| `scripts/` | 환경 셋업·부트스트랩 (멱등) |
| `tests/` | 골든 APK/IPA 회귀 테스트 |

## 스크립트 (§12)

| 스크립트 | 역할 |
|---|---|
| `setup.sh` | 진입점: static + dynamic 호출 |
| `setup-static.sh` | compose 기동, MobSF 헬스체크, API 키 추출 |
| `setup-dynamic.sh` | 호스트 의존성(frida, objection, libimobiledevice) 설치 |
| `bootstrap-frida.sh` | 기기 arch 감지 → frida-server 버전 매칭 push/실행 |
| `connect-android.sh` | BlueStacks adb-over-TCP 연결 |
| `doctor.sh` | 환경 점검(frida 버전·arch, 기기 연결, 컨테이너 상태) |

모든 스크립트는 멱등(`set -euo pipefail`), 값은 `config/`·`.env` 에서만 읽는다.

## 현재 상태

- [x] **Phase 0** — 레포 골격 + compose(정적) + setup 스크립트
- [x] **Phase 1** — 정적 파이프라인 완료. **MobSF·apkid·LIEF·semgrep(jadx 디컴파일)** 전부 라이브·self-contained.
  APK/IPA 분기, 교차 도구 dedup+confidence 병합, MASTG/전자금융 리포트, 웹 UI.
  - 실행: `docker compose -f docker/docker-compose.yml run --rm tools run_static.py <apk|ipa> --fresh --decompile`
- [ ] Phase 2 — Android 동적
- [ ] Phase 3 — iOS 동적
- [ ] Phase 4 — 리포트 자동화 / 패커(백로그)
