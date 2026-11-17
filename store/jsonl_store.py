"""Findings store (§5) — 정적(컨테이너)·동적(호스트)이 공유하는 seam (§3).

초기 구현은 JSONL 1개. 규모가 커지면 SQLite 로 교체(인터페이스 유지).
리포트 생성기는 오직 이 store 만 읽는다.

적재 시 dedup_key(§5) 로 중복을 합치고 confidence 를 상승시킨다.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Iterable

from schema.config import REPO_ROOT, load_config
from schema.findings import Finding, merge_findings


def _default_path() -> Path:
    rel = load_config("tools").get("store", {}).get("path", "store/findings.jsonl")
    return (REPO_ROOT / rel).resolve()


class FindingsStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path).resolve() if path else _default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # --- 읽기 ---
    def all(self) -> list[Finding]:
        if not self.path.exists():
            return []
        out: list[Finding] = []
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if line:
                out.append(Finding.model_validate_json(line))
        return out

    def _index(self) -> dict[str, Finding]:
        return {f.dedup_key(): f for f in self.all()}

    # --- 쓰기 (dedup + merge) ---
    def add(self, findings: Iterable[Finding]) -> dict[str, int]:
        """findings 적재. 기존과 dedup_key 충돌 시 merge. 통계 반환."""
        index = self._index()
        stats = {"new": 0, "merged": 0}
        for f in findings:
            key = f.dedup_key()
            if key in index:
                index[key] = merge_findings(index[key], f)
                stats["merged"] += 1
            else:
                index[key] = f
                stats["new"] += 1
        self._rewrite(index.values())
        return stats

    def _rewrite(self, findings: Iterable[Finding]) -> None:
        """원자적 재작성 (정적·동적 동시 쓰기 충돌 최소화)."""
        tmp_fd, tmp_name = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w") as fh:
                for f in findings:
                    fh.write(f.model_dump_json(by_alias=True) + "\n")
            os.replace(tmp_name, self.path)
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)
