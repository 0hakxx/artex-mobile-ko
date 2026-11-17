# 모바일 ARTEX 작업 계획서 (v3)

2026-11-17 · @Cho

## 1. 개요와 목표

APK/IPA를 입력받아 자동으로 정적 분석을 수행하고, 디바이스가 연결돼 있으면 동적 검증까지 진행한 뒤 MASTG/전자금융 기준에 매핑된 취약점 리포트를 산출한다. 기존 ARTEX의 Planner/Worker 오케스트레이션 구조를 모바일 앱 진단에 적용한 "모바일 ARTEX"가 목표다.

핵심 원칙은 분석 엔진을 새로 만들지 않는 것. MobSF·jadx·semgrep·Frida·objection 등 성숙한 오픈소스를 재사용하고, 이들을 에이전트가 호출 가능한 어댑터로 감싸 오케스트레이션하는 데 집중한다. 두 번째 원칙은 모든 환경 셋업을 재현 가능한 셸 스크립트+Docker로 자동화해, GitHub에서 clone 후 한 번에 구동되게 하는 것. 세 번째는 ARTEX 기존 UI(APK 업로드·작업 조회 등)를 최대한 재사용해 사용자 친화적으로 올리는 것(§15).

최종 산출물은 두 가지다. 모든 도구 출력을 하나로 정규화한 findings(JSON), 그리고 거기서 생성되는 사람이 읽는 리포트(MASTG/전자금융 매핑).

**성공 기준**: APK 한 개를 입력하면 사람 개입 없이 정적 분석 → 정규화된 findings → MASTG 매핑 리포트까지 나오고, 디바이스가 연결된 경우 동적 점검 결과가 같은 findings에 합쳐진다.

## 2. 전제 환경과 제약

구현 에이전트가 반드시 가정해야 하는 환경. 이 전제를 벗어나는 설계(예: 맥 전용 도구 가정)는 금지한다.

| 항목 | 값 | 함의 |
|---|---|---|
| OS | Windows + WSL2 | WSL2에 Docker Engine 직접 설치(Docker Desktop 불필). 리눅스 도구는 WSL2 |
| 배포·실행 | WSL2 | 정적=Docker compose, 동적=WSL2 호스트 프로세스 |
| 맥 | 없음 | class-dump 등 맥 전용 배제, iOS는 Frida/libimobiledevice로 우회 |
| Android | BlueStacks(x86) 또는 루팅 실단말(arm64) | 에뮬=adb-over-TCP(Windows 호스트 포트), 실단말=usbipd USB 또는 adb; frida-server arch 자동 매칭 |
| iOS | 실단말(탈옥) | usbipd-win으로 WSL2에 USB 연동, 재서명·설치 불가·런타임 후킹 가능 |
| Frida | 16.1.4 (호스트) | 디바이스 frida-server를 버전+arch(x86/arm64) 모두 맞춰야 함 |
| 연결 MCP | Burp, IDA Pro, Jadx | 에이전트 툴로 재활용 — 재구현 금지 |
| 인원 | 1인 | 순차 구조 우선, 과설계 금지 |

**주의**: frida-server와 호스트 Frida의 버전·아키텍처 불일치는 동적 단계에서 가장 흔한 실패 원인이다. 셋업 스크립트가 시작 전 버전·arch를 확인하고 안 맞으면 중단·보고하도록 한다(§12 doctor.sh).

## 3. 배포 토폴로지와 자동화 원칙

호스팅은 Windows 네이티브가 아니라 WSL2 위다. WSL2에 Docker Engine을 직접 올리고(Docker Desktop 불필), 리눅스 도구는 WSL2에서, 디바이스는 usbipd-win(iOS)·adb-over-TCP(Android)로 WSL2에서 접근한다.

**토폴로지 — 디바이스를 만지느냐로 가른다.**

- **정적 플레인 = Docker compose 하나.** MobSF·jadx·semgrep·apkid·LIEF·store·리포트는 디바이스를 안 건드리므로 전부 컨테이너. `docker compose up` 한 방으로 올라간다.
- **동적 플레인 = WSL2 호스트 프로세스.** adb·frida·objection·libimobiledevice는 디바이스에 붙어야 하므로 컨테이너 밖 호스트에서 실행한다. usbipd-win은 USB 장치를 WSL2 배포판 커널에 붙여줄 뿐 컨테이너로 자동 주입하지 않아, 디바이스 레이어를 compose에 넣으면 실패 지점만 늘어난다.
- **두 플레인의 seam은 findings store.** 양쪽이 같은 store(마운트된 경로)에만 적재하면 되므로 분리돼 있어도 통합된다. UI(§15)는 이 store/리포트를 읽는 세 번째 소비자다.

**자동화 원칙 — GitHub clone 후 한 방 셋업.**

- 모든 환경 셋업은 재현 가능한 셸 스크립트 + docker compose로. 수작업 설치 단계를 문서로만 남기지 않는다.
- `git clone` → `scripts/setup.sh` 한 번 → (정적) compose 기동 + (동적) 호스트 의존성 설치까지. 스크립트는 멱등하게 — 재실행해도 깨지지 않게.
- 가변값(frida 버전·arch, 디바이스 ID, 도구 경로)은 config YAML과 `.env`로 분리, 스크립트는 거기서 읽는다. 시크릿은 커밋 금지.
- 정적/동적 셋업 스크립트를 분리(`setup-static.sh`, `setup-dynamic.sh`)해 디바이스 없는 머신에서도 정적은 바로 돌게 한다.

## 4. 아키텍처 원칙

에이전트는 모바일 타깃을 직접 만지지 않는다. 중간에 어댑터 레이어를 두고 모든 도구를 "호출 가능한 액션 + 파싱 가능한 출력"으로 감싼다. Jadx MCP가 디컴파일을 텍스트로 넘겨주는 것처럼 나머지 도구도 같은 형태로 만든다.

세 가지 설계 원칙을 고정한다.

1. **공통 스키마 먼저.** 코드를 짜기 전에 findings JSON 스키마(§5)를 확정한다. 모든 도구 출력은 이 한 스키마로 수렴한다. 그래야 도구를 추가해도 리포트 로직을 안 건드린다.
2. **순차 스크립트 먼저, Planner/Worker는 나중.** 1단계는 멀티에이전트 없이 순차 스크립트(도구 호출 → 파싱 → findings 적재)로 돌린다. 툴 어댑터가 안정된 뒤에만 오케스트레이션 계층을 올린다.
3. **어댑터는 멱등·관찰 가능하게.** 각 어댑터는 입력(파일 경로/기기 ID)과 출력(정규화 JSON)이 명확하고, 실패 시 상태를 구조화된 error 필드로 반환한다. 에이전트가 상태를 보고 복구/중단을 판단할 수 있어야 한다.

**승격 후 구조(2단계)**: Planner가 단계를 결정하고(triage → 정적 → 패커 탐지 → 동적 준비 → 런타임 점검 → 리포트), Worker는 도구별 어댑터 하나에 바인딩된 특화 에이전트다. 모든 Worker 결과는 findings store 한 곳으로 모인다.

## 5. 공통 Findings 스키마 (MASTG 매핑)

이 스키마가 전체 도구의 계약이다. 모든 어댑터는 네이티브 출력을 이 형태의 레코드 리스트로 변환해 반환한다. 코드 첫 줄은 이 스키마를 Pydantic/dataclass로 고정하는 일이다.

```json
{
  "finding_id": "string (uuid)",
  "title": "string",
  "severity": "critical|high|medium|low|info",
  "confidence": "confirmed|firm|tentative",
  "category": "string (OWASP MASVS 카테고리)",
  "mastg_ids": ["MASTG-TEST-0xxx"],
  "masvs_ids": ["MASVS-STORAGE-1"],
  "source_tool": "mobsf|jadx|semgrep|apkid|frida|objection|manual",
  "analysis_type": "static|dynamic",
  "target": {"platform": "android|ios", "package": "string", "sha256": "string"},
  "location": {"file": "string", "class": "string", "method": "string", "line": 0},
  "evidence": "string (원문 snippet 또는 로그)",
  "description": "string",
  "recommendation": "string",
  "raw": {}
}
```

**설계 규칙**

- MASTG/MASVS ID가 매핑의 기준점. 도구별 매핑 테이블(예: MobSF 출력 키 → MASTG-TEST ID)을 따로 두고 어댑터가 변환 시 참조한다.
- 중복 제거는 `mastg_id + file + class + method` 기준. line은 디컴파일러 버전에 따라 흔들리므로 dedup 키에서 제외하고 location/evidence에만 남긴다. 정적·동적이 같은 취약점을 각각 발견하면 confidence만 올려 합친다(static tentative + dynamic confirmed → confirmed).
- raw 필드에 도구 원문을 그대로 보관해 매핑을 나중에 고쳐도 원본 추적이 가능하게.
- confidence는 분석 유형과 연동. 정적 단독은 tentative/firm, 동적으로 재현된 것만 confirmed.

findings store는 초기에 단순 JSONL 1개로, 규모가 커지면 SQLite로 옮긴다. 리포트 생성기는 오직 이 store만 읽는다. 정적(컨테이너)과 동적(호스트)이 공유하도록 마운트된 경로에 둔다.

## 6. 오픈소스 도구 인벤토리

재사용할 도구와 각자의 역할·래핑 방식. 원칙은 CLI나 REST가 있는 도구만 고르고, 파싱 가능한 출력이 없는 GUI 전용 도구는 제외한다. 정적 도구는 컨테이너(§8), 동적 도구는 호스트 프로세스(§9·§10)로 돌린다.

| 도구 | 역할 | 입·출력 | 래핑 방식 | 실행 위치 |
|---|---|---|---|---|
| MobSF | 정적 코어(APK+IPA) | 파일 → JSON | REST API | 컨테이너 |
| jadx / Jadx MCP | 디컴파일, 클래스·메서드 조회 | APK → Java/텍스트 | 이미 MCP 연결됨 | 호스트/MCP |
| semgrep | 소스 패턴 룰 검사 | 소스 → JSON | CLI --json | 컨테이너 |
| apkid | 컴파일·패커 탐지 | APK → JSON | CLI --json | 컨테이너 |
| LIEF | Mach-O/ELF·entitlements | 바이너리 → 구조체 | Python 라이브러리 | 컨테이너 |
| apktool | 리소스·매니페스트 디코딩 | APK → smali/xml | CLI | 컨테이너 |
| adb | Android 기기 제어 | 명령 → 텍스트 | CLI 래퍼 | 호스트 |
| Frida | 동적 후킹(양 플랫폼) | 스크립트 → 로그 | frida-python, 기기 ID 타겟팅 | 호스트 |
| objection | Frida 기반 런타임 점검 | 명령 → 텍스트 | CLI/스크립팅 | 호스트 |
| libimobiledevice | iOS USB 제어(맥 없이) | idevice* → 텍스트 | CLI 래퍼 | 호스트 |
| rizin / r2 | 바이너리 분석·심볼 | 바이너리 → 텍스트/JSON | r2pipe | 컨테이너 |
| Burp / IDA MCP | 프록시, 심층 리버싱 | — | 이미 MCP 연결됨 | MCP |

맥 없는 iOS 정적은 class-dump만 맥 의존이고, Mach-O·entitlements·plist·ATS 파싱은 LIEF+rizin으로 WSL2에서 처리한다. MobSF가 IPA 정적도 상당 부분 커버하므로 우선 의존한다.

## 7. 기기 식별과 세션 상태 관리

Android 에뮬과 iOS 실단말이 동시에 연결될 수 있으므로, 동적 단계의 모든 어댑터는 기기를 ID로 명시 타겟팅한다. 이 섹션이 §9·§10 공통 전제다.

**기기 식별 규칙**

- `frida-ls-devices`로 연결 기기 목록을 뽑아 각 기기의 ID를 얻는다. `-U`(USB 셀렉터)는 쓰지 않는다 — adb 에뮬레이터도 "usb" 타입으로 잡혀 타겟이 모호해진다.
- config/device_profiles.yaml에 `android.target`(adb serial)과 `ios.target`(UDID)을 분리해 박아두고, 어댑터가 플랫폼별로 정확한 기기를 집는다. 동시 연결돼 있어도 안전.
- frida-server 바이너리는 버전+아키텍처를 함께 관리: 에뮬 x86, iOS 실단말 arm64. config에 `frida.version`과 플랫폼별 `arch`를 둔다(§12 bootstrap-frida.sh가 자동 처리).

**세션 상태머신** — 동적 단계의 핵심 난이도는 코드가 아니라 상태 관리다. 어댑터가 다음을 관찰하고 구조화된 error로 노출한다.

- 기기가 붙었는가 (목록에 target ID가 있는가)
- frida-server가 떠 있고 버전·arch가 호스트와 맞는가
- 타겟 앱이 설치·실행 중인가

불일치·미연결이면 복구(frida-server 재기동, 재연결)를 시도하고, 안 되면 중단·보고한다. 이 점검 로직은 `doctor.sh`(§12)로도 수동 호출 가능하게 둔다.

## 8. Phase 1 — 정적 분석 (Docker compose)

디바이스 없이 100% 자동화 가능한 단계. 전부 컨테이너라 `docker compose up` 한 방으로 뜨고, 여기부터 돌게 만들어야 전체 골격이 검증된다.

**구축 순서**

1. findings 스키마(§5)를 Pydantic/dataclass로 고정.
2. MobSF를 compose 서비스로 띄우고 REST API를 3개 툴로 래핑: upload(file), scan(hash), report_json(hash). scan은 비동기이므로 완료 폴링을 어댑터에 넣고, 완료 전 report_json 호출 금지.
3. MobSF JSON → findings 변환기 작성(도구별 매핑 테이블 사용).
4. 보강 도구 래핑: apkid, semgrep(모바일 룰셋), jadx MCP, LIEF(IPA Mach-O·entitlements).
5. 순차 오케스트레이터: APK/IPA 입력 → 각 도구 호출 → findings 적재 → 중복 제거(§5 키).
6. MASTG 매핑 리포트 출력(§11 공유).

**산출물**: APK/IPA 한 개를 넣으면 정규화된 findings JSONL과 MASTG 매핑 리포트가 나온다. 디바이스 없는 머신에서 `setup-static.sh`만으로 즉시 가동.

**완료 기준**

- [ ] 임의 APK → 사람 개입 없이 findings JSONL 생성
- [ ] 같은 취약점을 여러 도구가 짚어도 중복 제거 후 1건으로 합쳐짐
- [ ] 모든 finding에 mastg_id가 채워지거나 미매핑은 별도 버킷으로 분류
- [ ] IPA 입력 시에도 맥 없이 MobSF+LIEF 경로로 findings 생성

**숨은 공수 주의**: 도구별 네이티브 분류 → MASTG-TEST ID 매핑 테이블 작성이 이 Phase의 실질 노동량 대부분이다. 코드는 금방이지만 MobSF 출력 키 수십 개를 수작업 매핑하는 데 시간이 간다. 미매핑 버킷으로 점진 보완한다.

## 9. Phase 2 — Android 동적 (호스트 프로세스)

동적 어댑터는 컨테이너 밖 WSL2 호스트에서 실행된다. 타깃은 BlueStacks(x86) 또는 루팅 실단말(arm64) 둘 다. BlueStacks는 adb를 TCP로 여니 WSL2에서 `adb connect <windows-host-ip>:<port>`로 붙고, 루팅 실단말은 usbipd-win으로 WSL2에 USB attach(또는 adb). 기기 식별·세션 규칙은 §7.

**구축 순서**

1. adb 래퍼: connect, install, shell, pull — 각각 구조화 출력. 기기는 §7의 adb serial로 타겟팅. `connect-android.sh`가 Windows 호스트 IP·포트로 TCP 연결.
2. frida-server 부트스트랩: `bootstrap-frida.sh`가 기기 arch(x86/arm64) 감지 → 16.1.4 바이너리 push·실행 → `frida-ls-devices`로 해당 기기 ID 확인.
3. objection/Frida 스크립트 래핑: SSL 피닝 바이패스, 루팅 탐지, 암호화 API 후킹, 클립보드/로그 누출 등 MASTG 항목별 런타임 체크.
4. 런타임 로그 → findings 변환기(analysis_type=dynamic, confidence=confirmed). 공유 store에 적재.

**완료 기준**

- [ ] BlueStacks가 꺼져 있거나 포트가 안 열려 있으면 "기기 미연결"을 구조화해 보고하고 멈춤
- [ ] frida-server 버전·arch 불일치를 감지해 메시지로 알림
- [ ] SSL 피닝 바이패스 후 Burp로 트래픽이 잡히고 결과가 findings에 dynamic으로 적재
- [ ] 같은 취약점의 정적·동적 finding이 합쳐져 confidence가 confirmed로 상승

## 10. Phase 3 — iOS 동적 (맥 없이)

맥 없이 Windows + 탈옥 실단말로 런타임 점검. usbipd-win으로 단말 USB를 WSL2에 연동하고, 어댑터는 컨테이너 밖 호스트에서 실행한다(usbmuxd·frida를 컨테이너에 넣으면 불안정). 재서명·설치·Xcode 디버깅은 불가, 런타임 후킹에 집중. 환경 세팅이 코드보다 오래 걸려 별도 트랙으로 분리. 기기 식별·세션 규칙은 §7.

**구축 순서**

1. libimobiledevice를 WSL2/Windows에 설치 → idevice_id, ideviceinfo, ideviceinstaller 래핑.
2. usbipd-win으로 단말을 WSL2에 attach, USB 드라이버 확인·페어링.
3. 탈옥 단말에 frida-server 설치(arm64, 16.1.4) → `frida-ls-devices`로 UDID 기준 연결 확인.
4. SSH over USB(포트 포워딩)로 파일시스템 접근 → 앱 컨테이너, keychain, plist 수집.
5. Frida 스크립트로 SSL 피닝 바이패스·탈옥 탐지·민감 API 후킹 → findings 변환.

**환경 세팅 주의점** (여기서 시간 제일 많이 날린다)

- frida-server 버전을 호스트 16.1.4와 정확히 맞추지 않으면 연결이 끊어진다.
- 단말 아키텍처(arm64)용 바이너리를 받아야 한다.
- usbipd/usbmuxd USB 스택이 불안정하면 Windows 호스트 libimobiledevice 직접 경로를 폴백으로 쓴다.

**완료 기준**

- [ ] `frida-ls-devices`로 탈옥 단말(UDID)이 보인다
- [ ] SSH로 앱 컨테이너를 덤프하고 plist/keychain을 수집해 findings로 적재
- [ ] SSL 피닝 바이패스 후 Burp로 iOS 앱 트래픽이 잡힌다
- [ ] 환경 세팅이 스크립트+문서로 재현 가능하다

## 11. Phase 4 — 리포트 자동화와 패커 언패킹

두 트랙은 성격이 다르다. 리포트 자동화는 MVP에 포함(정적 플레인 안), 패커 언패킹은 끝없는 R&D라 백로그로 분리한다.

**리포트 자동화 (MVP 포함)**

- findings store → MASTG/MASVS 매핑 리포트(HTML/Markdown) 생성.
- 전자금융 감독규정·금융보안 기준과 MASTG 항목을 매핑한 템플릿을 따로 두고, 같은 findings에서 두 포맷(MASTG, 전자금융)을 뽑는다.
- 심각도·증거·권고가 finding에 이미 들어 있으므로 리포트는 정렬·그룹핑·템플릿 렌더링만 담당.

**패커 언패킹 (백로그 R&D)**

- 대상: AppSealing, nProtect, TouchEn 등 국내 앱 보호 솔루션.
- 오픈소스로 커버 안 되고 개별 분석 필요, 버전 올라갈 때마다 깨진다. 기간 산정하지 말고 하나씩 백로그에서 처리.
- 접근: Frida 런타임 메모리 덤프(복호화된 dex/바이너리 추출) → jadx/IDA 재분석. 정적 해제보다 동적 덤프가 현실적.
- 차별화 포인트이지만 MVP를 막는 요소로 두지 않는다.

**완료 기준**

- [ ] 동일 findings로 MASTG·전자금융 두 리포트가 모두 나옴
- [ ] 리포트가 심각도별·MASVS 카테고리별로 그룹핑
- [ ] (백로그) 최소 한 개 보호 솔루션에 대해 런타임 덤프 → 재분석 PoC

## 12. 디렉터리와 기술 스택, 셸 스크립트

**기술 스택**: Python(도구 래핑·에이전트), 정적 도구는 Docker compose로 고정, 동적은 WSL2 호스트 Python 프로세스. 환경 셋업은 전부 셸 스크립트. LLM 호출·툴 스키마는 MCP에 맞춘다.

```
mobile-artex/
  schema/            # findings 스키마(Pydantic), MASTG 매핑 테이블
  adapters/          # 도구별 래퍼 (mobsf, jadx, semgrep, apkid, lief, adb, frida, objection, imobiledevice)
  normalizers/       # 각 도구 출력 → findings 변환기
  store/             # findings 저장 (JSONL → SQLite)
  pipeline/          # 순차 오케스트레이터 (1단계)
  orchestrator/      # Planner/Worker (2단계, 나중)
  report/            # MASTG/전자금융 템플릿·렌더러
  config/            # 도구 경로, frida 버전·arch, device_profiles.yaml
  docker/
    docker-compose.yml   # 정적 플레인(MobSF 등) + store 볼륨
  scripts/           # 셸 스크립트 (환경 셋업·부트스트랩)
    setup.sh             # 진입점: static + dynamic 호출
    setup-static.sh      # docker compose 기동, MobSF 헬스체크
    setup-dynamic.sh     # 호스트 의존성(frida, objection, libimobiledevice) 설치
    bootstrap-frida.sh   # 기기 arch 감지 → frida-server 버전 매칭 push/실행
    connect-android.sh   # BlueStacks adb-over-TCP 연결
    doctor.sh            # 환경 점검(frida 버전·arch, 기기 연결, 컨테이너 상태)
  .env.example       # MobSF API 키 등 (복사해서 .env로)
  tests/             # 골든 APK/IPA 샘플 회귀 테스트
```

**셸 스크립트 원칙**

- 전부 멱등: 재실행 안전, 이미 된 단계는 건너뜀. `set -euo pipefail` 기본.
- `doctor.sh`가 동적 단계 전 환경을 검증(frida 버전·arch 일치, 기기 ID 연결, frida-server 상태) — §7 상태머신의 CLI 버전.
- 스크립트는 config/·.env에서만 값을 읽고 하드코딩 금지.

**GitHub 배포**

- `git clone` → `cp .env.example .env` 편집 → `scripts/setup.sh` → 정적 compose 기동 + 동적 의존성 설치 완료.
- 디바이스 없는 머신: `setup-static.sh`만 돌리면 정적 파이프라인 즉시 가동.
- 시크릿(.env)과 골든 샘플은 .gitignore. config/는 커밋, 값만 분리.

## 13. 마일스톤과 일정

혼자, 저녁·주말 작업 기준의 현실 추정. MVP는 정적+Android 동적까지, iOS와 패커는 그 위에 얹는 별도 트랙.

| 단계 | 범위 | 기간 | 비고 |
|---|---|---|---|
| Phase 0 | 레포 골격 + compose + setup 스크립트 | 2~3일 | 자동화 토대 먼저 |
| Phase 1 | 정적 파이프라인(MobSF+findings) | 1~2주 | 매핑 테이블 작성이 시간 요인 |
| Phase 2 | Android 동적(adb+Frida+objection) | +1~2주 | 세션 상태 관리가 시간 요인 |
| Phase 3 | iOS 동적(usbipd+libimobiledevice+Frida) | +2~4주 | 변동 큼, 환경 세팅 삽질 |
| Phase 4-리포트 | MASTG/전자금융 리포트 | Phase 1에 포함 | findings 스키마 재사용 |
| Phase 4-패커 | 국내 패커 언패킹 | 백로그/상시 R&D | 기간 산정 안 함 |

**정적+Android 동적 MVP = 3~5주**가 현실적. iOS와 언패킹은 MVP 완성 후 올리는 트랙.

시간을 줄이는 세 가지: (1) 순차 스크립트로 먼저(멀티에이전트는 나중), (2) findings 스키마를 가장 먼저 고정, (3) 셋업을 처음부터 스크립트화해 재구축 비용을 0으로.

## 14. 구현 착수 지침

구현 세션에 넘길 때 아래를 명시한다.

**구현 착수 순서 (반드시 이 순서)**

1. 레포 골격 + `docker-compose.yml`(정적) + `scripts/setup*.sh` 먼저 — "clone → setup.sh"가 돌게.
2. schema/ findings 스키마 + MASTG 매핑 테이블.
3. MobSF 어댑터 + normalizer + 순차 pipeline으로 "APK → findings" (scan 폴링 포함).
4. 보강 정적 도구(apkid/semgrep/jadx/LIEF) 붙이기.
5. 리포트 렌더러.
6. 기기 식별·세션(§7) + bootstrap/doctor 스크립트 → Android 동적 → iOS 동적 → 오케스트레이션 승격.

단계별로 멈추고 수용 기준(§8~11)을 통과했는지 확인한 뒤 다음으로. 한 번에 전체를 구현하게 하지 말 것.

**하지 말 것**

- 처음부터 Planner/Worker 멀티에이전트로 짜지 말 것 — 순차 pipeline 먼저.
- 분석 엔진을 직접 구현하지 말 것 — 오픈소스 래핑만.
- 맥 전용 도구 가정 금지(Windows+WSL2, 맥 없음).
- 동적(디바이스) 어댑터를 컨테이너에 넣지 말 것 — WSL2 호스트 프로세스로. 정적만 compose.
- 도구 출력을 스키마 없이 바로 리포트로 쓰지 말 것 — 반드시 정규화 경유.
- Frida `-U`로 기기를 묶지 말 것 — 기기 ID로 명시 타겟팅(§7).
- 셋업을 수작업 문서로만 남기지 말 것 — 셸 스크립트로.
- 패커 언패킹을 MVP 블로커로 두지 말 것 — 별도 백로그.

**전제로 깔고 시작**: Windows+WSL2(Docker Engine 직접), 맥 없음, BlueStacks(adb-over-TCP) 또는 루팅 실단말(arm64), 탈옥 실단말(usbipd-win), Frida 16.1.4(arch 플랫폼별), Burp/IDA/Jadx MCP 연결됨, 1인 작업.

## 15. UI / 사용자 인터페이스

원칙은 새 프론트를 만들지 않고 ARTEX 기존 웹 UI를 최대한 재사용하는 것 — 업로드 플로우, 작업(job) 조회, 인증, 결과 화면을 그대로 쓴다.

**꽂는 방식**

- 모바일을 ARTEX에 "모바일 분석 잡 타입" 하나로 추가한다: UI에서 APK/IPA 업로드 → 잡 생성 → 파이프라인(§8~§10) 실행 → findings/리포트를 ARTEX 기존 결과 화면에 렌더.
- UI는 findings store와 리포트만 읽는다(§5 계약). 백엔드 내부(어댑터·컨테이너/호스트 분리)를 UI가 몰라도 되게 해 결합을 최소화한다.

**사용자 친화 요소 (기존 UI 위에 얹기)**

- APK/IPA 드래그&드롭 업로드 — ARTEX 업로드 컴포넌트 재사용.
- 진행 상태 표시: 정적 → 동적 단계와 §7 세션 상태머신의 error/상태를 그대로 노출(기기 미연결, frida 불일치 등).
- 결과 뷰: 심각도·MASVS 카테고리 필터, MASTG·전자금융 리포트 열람·다운로드.
- 톤·레이아웃을 기존 ARTEX 화면과 맞춘다.

**재사용 범위와 폴백 (확인 필요)**

- 실제 재사용 정도는 ARTEX 프론트가 findings/job 모델과 얼마나 분리돼 있느냐에 달렸다. 착수 전 ARTEX 프론트·잡 모델을 열어 "모바일 잡 타입 추가 + 결과 렌더"만으로 끼워지는지 확인한다.
- 강결합이라 끼우기 어려우면 폴백: findings store 위에 얇은 웹 뷰(FastAPI + 간단 프론트)로 업로드·상태·리포트만 제공. 어느 쪽이든 §5 findings/리포트가 계약이라 백엔드는 안 바뀐다.

**토폴로지상 위치**: UI는 ARTEX 셸(기존 서비스) 재사용이므로, 그 서비스가 compose에 있으면 정적 플레인과 같이 뜨고, 모바일 백엔드(정적 컨테이너·동적 호스트)와는 findings store로만 연결된다.

**완료 기준**

- [ ] UI에서 APK 업로드 → 잡 진행 상태가 보임
- [ ] 끝나면 findings·MASTG/전자금융 리포트를 UI에서 열람·다운로드
- [ ] 화면 톤이 기존 ARTEX와 일치
- [ ] UI는 findings store/리포트만 읽고 백엔드 내부에 의존하지 않음
