"""Frida 런타임 메시지 → Finding 리스트 (§9-4).

동적으로 재현된 것만 confidence=confirmed (§5). 정적 finding 과 store 에서
같은 dedup_key(mastg+file+class+method)로 만나면 confidence 가 confirmed 로 상승.
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

_SEV = {"critical": Severity.critical, "high": Severity.high, "medium": Severity.medium,
        "low": Severity.low, "info": Severity.info}


def normalize(messages: list[dict[str, Any]], target: Target,
              source_tool: SourceTool = SourceTool.frida) -> list[Finding]:
    out: list[Finding] = []
    for m in messages:
        check = m.get("check", "")
        # 정보성·진단 메시지(후킹 설치/환경/오류)는 finding 아님
        if check in ("hooks_installed", "env") or check.endswith("_err"):
            continue
        # mastg 없고 info 심각도 = 진단성 → 스킵 (실제 동적 finding 아님)
        if not m.get("mastg") and m.get("severity", "info") == "info":
            continue
        mastg = [m["mastg"]] if m.get("mastg") else []
        masvs = [m["masvs"]] if m.get("masvs") else []
        cat = (m.get("masvs", "").rsplit("-", 1)[0] if str(m.get("masvs", "")).startswith("MASVS") else "")
        out.append(Finding(
            title=m.get("title", check)[:160],
            severity=_SEV.get(m.get("severity", "info"), Severity.info),
            confidence=Confidence.confirmed,  # 동적 재현 = confirmed (§5)
            category=cat, mastg_ids=mastg, masvs_ids=masvs,
            source_tool=source_tool, analysis_type=AnalysisType.dynamic,
            target=target,
            location=Location(method=check),
            evidence=m.get("evidence", ""),
            description=f"런타임 후킹으로 재현된 동적 점검: {check}",
            raw={"section": "frida_runtime", "check": check, "orig": m},
        ))
    return out
