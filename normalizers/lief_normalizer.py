"""LIEF IPA 분석 결과 → Finding 리스트 (§8-4, iOS 정적).

맥 없이 얻는 iOS 정적 신호를 MASTG 에 매핑:
  - ATS NSAllowsArbitraryLoads=true   → MASVS-NETWORK (평문/약한 TLS 허용)
  - Mach-O PIE 미설정                 → MASVS-RESILIENCE (ASLR 무력화)
  - crypt_id=0 (암호화 안 됨)         → 정보성 (사이드로드/복호화 바이너리)
  - 커스텀 URL scheme                 → MASVS-PLATFORM (딥링크 입력 검증 필요)
"""
from __future__ import annotations

from typing import Any

from schema.findings import (
    AnalysisType,
    Confidence,
    Finding,
    Location,
    Severity,
    SourceTool,
    Target,
)


def normalize(data: dict[str, Any], sha256: str = "") -> list[Finding]:
    if not data or "error" in data:
        return []
    target = Target(platform="ios", package=data.get("bundle_id", ""), sha256=sha256)
    exe = data.get("executable", "")
    out: list[Finding] = []

    def add(title, sev, conf, mastg, masvs, cat, evidence, desc, rec="", loc_file=""):
        out.append(Finding(
            title=title, severity=sev, confidence=conf,
            category=cat, mastg_ids=mastg, masvs_ids=masvs,
            source_tool=SourceTool.lief, analysis_type=AnalysisType.static,
            target=target, location=Location(file=loc_file or "Info.plist"),
            evidence=str(evidence), description=desc, recommendation=rec,
            raw={"section": "lief_ipa"},
        ))

    ats = data.get("ats") or {}
    if ats.get("NSAllowsArbitraryLoads") is True:
        add("ATS 전역 비활성 (NSAllowsArbitraryLoads=true)", Severity.high, Confidence.firm,
            ["MASTG-TEST-0070"], ["MASVS-NETWORK-1"], "MASVS-NETWORK",
            "NSAppTransportSecurity.NSAllowsArbitraryLoads=true",
            "앱이 임의 HTTP(평문)·약한 TLS 연결을 전역 허용한다.",
            "ATS 를 활성화하고 도메인별 예외만 최소 허용하라.")

    macho = data.get("macho") or {}
    if macho.get("pie") is False:
        add("Mach-O PIE 미설정 (ASLR 무력화)", Severity.medium, Confidence.firm,
            ["MASTG-TEST-0085"], ["MASVS-RESILIENCE-1"], "MASVS-RESILIENCE",
            f"executable={exe}", "PIE 가 꺼져 ASLR 이 적용되지 않는다.",
            "-fPIE -pie 로 빌드하라.", loc_file=exe)
    if macho.get("crypt_id") == 0:
        add("바이너리 미암호화 (crypt_id=0)", Severity.info, Confidence.firm,
            [], [], "MASVS-RESILIENCE",
            f"executable={exe}, crypt_id=0",
            "Mach-O 가 암호화되지 않음(사이드로드/복호화 바이너리). 정적 리버싱 용이.",
            loc_file=exe)

    schemes = data.get("url_schemes") or []
    if schemes:
        add(f"커스텀 URL scheme 등록: {', '.join(schemes)}", Severity.info, Confidence.tentative,
            ["MASTG-TEST-0075"], ["MASVS-PLATFORM-3"], "MASVS-PLATFORM",
            ", ".join(schemes), "커스텀 스킴은 외부 입력 경로 — 딥링크 파라미터 검증 필요.")

    return out
