"""apkid JSON → Finding 리스트 (§8-4).

apkid 는 컴파일러/패커/안티분석 신호를 범주별로 낸다. 대부분 정보성(info).
- packer/protector      → MASVS-RESILIENCE (보호 솔루션 탐지)
- anti_vm/anti_debug/anti_disassembly → RESILIENCE (방어 기법 존재; 정보성)
- compiler/manipulator/abnormal 등    → 미매핑 버킷(info)
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

# apkid 범주 → (mastg, masvs, category, severity)
_CAT = {
    "packer":           (["MASTG-TEST-0070"], ["MASVS-RESILIENCE-4"], "MASVS-RESILIENCE", Severity.info),
    "protector":        (["MASTG-TEST-0070"], ["MASVS-RESILIENCE-4"], "MASVS-RESILIENCE", Severity.info),
    "anti_vm":          (["MASTG-TEST-0050"], ["MASVS-RESILIENCE-3"], "MASVS-RESILIENCE", Severity.info),
    "anti_debug":       (["MASTG-TEST-0050"], ["MASVS-RESILIENCE-2"], "MASVS-RESILIENCE", Severity.info),
    "anti_disassembly": (["MASTG-TEST-0050"], ["MASVS-RESILIENCE-3"], "MASVS-RESILIENCE", Severity.info),
}


def normalize(apkid_json: dict[str, Any], target: Target) -> list[Finding]:
    if not apkid_json or "error" in apkid_json:
        return []
    findings: list[Finding] = []
    for entry in apkid_json.get("files", []):
        fname = entry.get("filename", "")
        for category, matches in (entry.get("matches") or {}).items():
            mastg, masvs, cat, sev = _CAT.get(category, ([], [], "", Severity.info))
            findings.append(Finding(
                title=f"apkid: {category} — {', '.join(matches)[:120]}",
                severity=sev,
                confidence=Confidence.firm if mastg else Confidence.tentative,
                category=cat, mastg_ids=mastg, masvs_ids=masvs,
                source_tool=SourceTool.apkid, analysis_type=AnalysisType.static,
                target=target,
                location=Location(file=fname.split("!")[-1] if "!" in fname else fname,
                                  **{"class": category}),
                evidence=", ".join(matches),
                description=f"apkid 범주 '{category}' 매칭.",
                raw={"category": category, "matches": matches},
            ))
    return findings
