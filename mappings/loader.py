"""매핑 테이블 로더 (§5). 도구 네이티브 분류 → MASTG/MASVS ID.

해석 우선순위 (normalizer 가 사용):
  1) 이 매핑 테이블의 명시 매핑
  2) (MobSF 등) 도구 자체 metadata 폴백 — normalizer 에서 처리
  3) 둘 다 없으면 unmapped 버킷 (§8: 미매핑은 별도 분류)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

MAPPINGS_DIR = Path(__file__).resolve().parent


@dataclass
class MastgMapping:
    mastg_ids: list[str] = field(default_factory=list)
    masvs_ids: list[str] = field(default_factory=list)
    category: str = ""

    @property
    def mapped(self) -> bool:
        return bool(self.mastg_ids)


UNMAPPED = MastgMapping()


@lru_cache(maxsize=None)
def _table(tool: str = "mobsf") -> dict[str, MastgMapping]:
    """도구 매핑 YAML 을 평탄화한 {rule_id: MastgMapping} 로 로드.

    여러 섹션(rules/manifest/certificate/network ...)을 하나의 평면 사전으로 합친다.
    동일 키가 여러 섹션에 있으면 뒤 섹션이 우선(현재는 충돌 없음).
    """
    path = MAPPINGS_DIR / f"{tool}_mastg.yaml"
    data = yaml.safe_load(path.read_text()) or {}
    flat: dict[str, MastgMapping] = {}
    for section, entries in data.items():
        if section in ("version",) or not isinstance(entries, dict):
            continue
        for key, m in entries.items():
            if not isinstance(m, dict):
                continue
            flat[key] = MastgMapping(
                mastg_ids=list(m.get("mastg_ids", [])),
                masvs_ids=list(m.get("masvs_ids", [])),
                category=m.get("category", ""),
            )
    return flat


def lookup(rule_id: str, tool: str = "mobsf") -> MastgMapping:
    """rule_id 에 대한 매핑 반환. 없으면 UNMAPPED."""
    if not rule_id:
        return UNMAPPED
    return _table(tool).get(rule_id, UNMAPPED)
