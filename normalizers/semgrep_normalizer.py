"""semgrep JSON → Finding 리스트 (§8-4).

semgrep result 의 check_id / extra.metadata(owasp, masvs, references)로 매핑.
mappings 테이블(semgrep)에 명시 매핑이 있으면 우선, 없으면 metadata, 없으면 unmapped.
"""
from __future__ import annotations

from typing import Any

from mappings.loader import lookup
from schema.findings import (
    AnalysisType,
    Confidence,
    Finding,
    Location,
    Severity,
    SourceTool,
    Target,
)

_SEV = {"ERROR": Severity.high, "WARNING": Severity.medium, "INFO": Severity.info}


def _short_rule(check_id: str) -> str:
    # "rules.android.weak-hash" → "weak-hash"
    return check_id.rsplit(".", 1)[-1]


def normalize(semgrep_json: dict[str, Any], target: Target) -> list[Finding]:
    if not semgrep_json or "error" in semgrep_json:
        return []
    out: list[Finding] = []
    for r in semgrep_json.get("results", []):
        check_id = r.get("check_id", "")
        rule_short = _short_rule(check_id)
        meta = (r.get("extra") or {}).get("metadata", {}) or {}

        m = lookup(rule_short, tool="semgrep")
        if m.mapped:
            mastg, masvs, cat = m.mastg_ids, m.masvs_ids, m.category
        else:
            masvs_raw = meta.get("masvs") or ""
            mastg = [meta["mastg"]] if meta.get("mastg") else []
            masvs = [masvs_raw] if masvs_raw else []
            cat = masvs_raw.rsplit("-", 1)[0] if str(masvs_raw).startswith("MASVS") else ""

        sev = _SEV.get((r.get("extra") or {}).get("severity", "INFO"), Severity.info)
        out.append(Finding(
            title=(meta.get("shortDescription") or rule_short)[:160],
            severity=sev,
            confidence=Confidence.firm if (mastg or masvs) else Confidence.tentative,
            category=cat, mastg_ids=mastg, masvs_ids=masvs,
            source_tool=SourceTool.semgrep, analysis_type=AnalysisType.static,
            target=target,
            location=Location(
                file=r.get("path", ""),
                line=(r.get("start") or {}).get("line", 0),
            ),
            evidence=(r.get("extra") or {}).get("lines", "")[:300],
            description=(r.get("extra") or {}).get("message", ""),
            recommendation=", ".join(meta.get("references", []))[:300],
            raw={"check_id": check_id, "metadata": meta},
        ))
    return out
