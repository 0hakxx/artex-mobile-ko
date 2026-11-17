"""순차 정적 오케스트레이터 (§8-5, §4-2: 멀티에이전트 아님, 순차 스크립트 먼저).

입력 → 도구 호출 → normalizer → findings 적재(dedup/merge) → 통계.

APK:  MobSF + apkid (+ 선택: jadx 디컴파일 → semgrep)
IPA:  MobSF(appsec) + LIEF  (맥 없이, §10)

모든 도구 실패는 ToolResult.error 로 구조화(§4-3) — 한 도구가 죽어도 나머지 진행.
"""
from __future__ import annotations

import hashlib
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from adapters import apkid_adapter, jadx_adapter, lief_adapter, semgrep_adapter
from adapters.mobsf_adapter import MobsfAdapter, MobsfError
from normalizers import (
    apkid_normalizer,
    lief_normalizer,
    mobsf_normalizer,
    semgrep_normalizer,
)
from schema.findings import Finding, Target
from store.jsonl_store import FindingsStore


@dataclass
class ToolResult:
    tool: str
    ok: bool
    added: dict[str, int] = field(default_factory=dict)
    error: str = ""


@dataclass
class PipelineResult:
    target: str
    platform: str
    sha256: str
    tool_results: list[ToolResult] = field(default_factory=list)
    total_findings: int = 0
    mapped: int = 0
    unmapped: int = 0

    def summary(self) -> str:
        lines = [f"target={Path(self.target).name} platform={self.platform} sha256={self.sha256[:16]}"]
        for t in self.tool_results:
            if t.ok:
                lines.append(f"  [+] {t.tool}: new={t.added.get('new',0)} merged={t.added.get('merged',0)}")
            else:
                lines.append(f"  [x] {t.tool}: {t.error}")
        lines.append(f"  findings store: total={self.total_findings} mapped={self.mapped} unmapped={self.unmapped}")
        return "\n".join(lines)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _detect_platform(path: Path) -> str:
    if path.suffix.lower() == ".ipa":
        return "ios"
    if path.suffix.lower() == ".apk":
        return "android"
    # 내용 검사: IPA 는 Payload/ 를 가진 zip
    try:
        with zipfile.ZipFile(path) as zf:
            if any(n.startswith("Payload/") for n in zf.namelist()):
                return "ios"
    except zipfile.BadZipFile:
        pass
    return "android"


def _collect(store: FindingsStore, result: PipelineResult, tool: str, findings: list[Finding]):
    for f in findings:
        if not f.target.sha256:
            f.target.sha256 = result.sha256
    added = store.add(findings)
    result.tool_results.append(ToolResult(tool, True, added))


def run_static(file_path: str | Path, store: FindingsStore | None = None,
               fresh: bool = False, src_dir: str | Path | None = None,
               decompile: bool = False) -> PipelineResult:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(path)
    store = store or FindingsStore()
    if fresh:
        store.clear()

    platform = _detect_platform(path)
    result = PipelineResult(target=str(path), platform=platform, sha256=_sha256(path))

    # --- MobSF (양 플랫폼) ---
    report = None
    try:
        adapter = MobsfAdapter()
        report = adapter.analyze(path)
        if platform == "ios":
            findings = mobsf_normalizer.normalize_ios_appsec(report, sha256=result.sha256)
        else:
            findings = mobsf_normalizer.normalize(report)
        _collect(store, result, "mobsf", findings)
    except MobsfError as e:
        result.tool_results.append(ToolResult("mobsf", False, error=str(e)))

    if platform == "ios":
        # --- LIEF (iOS 정적, 맥 없이) ---
        try:
            data = lief_adapter.analyze_ipa(path)
            if "error" in data:
                result.tool_results.append(ToolResult("lief", False, error=data["error"]))
            else:
                _collect(store, result, "lief", lief_normalizer.normalize(data, sha256=result.sha256))
        except Exception as e:  # noqa: BLE001
            result.tool_results.append(ToolResult("lief", False, error=str(e)))
    else:
        # --- apkid (Android) ---
        tgt = Target(platform="android",
                     package=(report or {}).get("package_name", ""), sha256=result.sha256)
        aj = apkid_adapter.run_apkid(path)
        if "error" in aj:
            result.tool_results.append(ToolResult("apkid", False, error=aj["error"]))
        else:
            _collect(store, result, "apkid", apkid_normalizer.normalize(aj, tgt))

        # --- 선택: jadx 디컴파일 → semgrep ---
        src = Path(src_dir) if src_dir else None
        if decompile and not src:
            tmp = Path(tempfile.mkdtemp(prefix="jadx_"))
            dj = jadx_adapter.decompile(path, tmp)
            src = Path(dj["src_dir"]) if dj.get("src_dir") else None
            if dj.get("error"):
                result.tool_results.append(ToolResult("jadx", False, error=dj["error"]))
        if src and src.exists():
            sj = semgrep_adapter.run_semgrep(src)
            if "error" in sj:
                result.tool_results.append(ToolResult("semgrep", False, error=sj["error"]))
            else:
                _collect(store, result, "semgrep", semgrep_normalizer.normalize(sj, tgt))

    # --- 통계 ---
    allf = store.all()
    result.total_findings = len(allf)
    result.mapped = sum(1 for f in allf if f.is_mapped())
    result.unmapped = len(allf) - result.mapped
    return result
