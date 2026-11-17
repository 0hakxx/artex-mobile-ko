"""공통 Findings 스키마 (§5) — 전체 도구의 계약.

모든 어댑터/normalizer 는 네이티브 출력을 이 Finding 레코드 리스트로 변환해 반환한다.
리포트 생성기는 오직 이 스키마만 읽는다. 도구를 추가해도 리포트 로직은 불변.
"""
from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(str, Enum):
    # §5: 정적 단독 = tentative/firm, 동적으로 재현된 것만 confirmed
    confirmed = "confirmed"
    firm = "firm"
    tentative = "tentative"


class SourceTool(str, Enum):
    mobsf = "mobsf"
    jadx = "jadx"
    semgrep = "semgrep"
    apkid = "apkid"
    lief = "lief"
    frida = "frida"
    objection = "objection"
    manual = "manual"


class AnalysisType(str, Enum):
    static = "static"
    dynamic = "dynamic"


class Platform(str, Enum):
    android = "android"
    ios = "ios"


# confidence 상승 규칙용 서열 (§5: static tentative + dynamic confirmed → confirmed)
_CONFIDENCE_RANK = {
    Confidence.tentative: 0,
    Confidence.firm: 1,
    Confidence.confirmed: 2,
}


class Target(BaseModel):
    platform: Platform
    package: str = ""
    sha256: str = ""


class Location(BaseModel):
    file: str = ""
    class_: str = Field(default="", alias="class")
    method: str = ""
    line: int = 0

    model_config = {"populate_by_name": True}


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    severity: Severity
    confidence: Confidence
    category: str = ""  # OWASP MASVS 카테고리
    mastg_ids: list[str] = Field(default_factory=list)
    masvs_ids: list[str] = Field(default_factory=list)
    source_tool: SourceTool
    analysis_type: AnalysisType
    target: Target
    location: Location = Field(default_factory=Location)
    evidence: str = ""
    description: str = ""
    recommendation: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True, "use_enum_values": False}

    def dedup_key(self) -> str:
        """중복 제거 키 (§5): mastg_id + file + class + method.

        line 은 디컴파일러 버전에 따라 흔들리므로 제외(location/evidence 에만 남김).
        mastg_ids 는 정렬된 첫 ID 사용(미매핑이면 title 폴백 → 과도한 병합 방지).
        """
        mastg = sorted(self.mastg_ids)
        anchor = mastg[0] if mastg else f"UNMAPPED:{self.title}"
        raw = f"{anchor}|{self.location.file}|{self.location.class_}|{self.location.method}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def is_mapped(self) -> bool:
        return bool(self.mastg_ids)


def merge_findings(existing: Finding, incoming: Finding) -> Finding:
    """같은 dedup_key 를 가진 두 finding 병합 (§5).

    - confidence 는 더 높은 쪽으로 상승 (static tentative + dynamic confirmed → confirmed).
    - severity 는 더 심각한 쪽 유지.
    - source_tool/analysis_type 출처는 raw.merged_from 에 누적 기록.
    - evidence/location 은 더 풍부한(동적·confirmed) 쪽 우선, 없으면 기존 유지.
    """
    hi_conf = max(existing.confidence, incoming.confidence, key=lambda c: _CONFIDENCE_RANK[c])

    sev_order = [Severity.info, Severity.low, Severity.medium, Severity.high, Severity.critical]
    hi_sev = max(existing.severity, incoming.severity, key=lambda s: sev_order.index(s))

    # 동적/confirmed 쪽을 "주" 레코드로 — 증거가 더 강하다
    primary, secondary = existing, incoming
    if (_CONFIDENCE_RANK[incoming.confidence] > _CONFIDENCE_RANK[existing.confidence]) or (
        incoming.analysis_type == AnalysisType.dynamic
        and existing.analysis_type == AnalysisType.static
    ):
        primary, secondary = incoming, existing

    merged_from = list(primary.raw.get("merged_from", []))
    for f in (existing, incoming):
        tag = f"{f.source_tool.value}:{f.analysis_type.value}:{f.confidence.value}"
        if tag not in merged_from:
            merged_from.append(tag)

    merged_raw = dict(primary.raw)
    merged_raw["merged_from"] = merged_from

    return primary.model_copy(
        update={
            "confidence": hi_conf,
            "severity": hi_sev,
            "mastg_ids": sorted(set(existing.mastg_ids) | set(incoming.mastg_ids)),
            "masvs_ids": sorted(set(existing.masvs_ids) | set(incoming.masvs_ids)),
            "evidence": primary.evidence or secondary.evidence,
            "recommendation": primary.recommendation or secondary.recommendation,
            "description": primary.description or secondary.description,
            "raw": merged_raw,
        }
    )
