"""순차 동적 오케스트레이터 (§9). 호스트 프로세스 — 컨테이너 아님.

세션 상태(§7) 점검 → 준비되면 Frida 런타임 점검 → dynamic findings → 공유 store.
기기 미연결/버전 불일치면 복구 시도 후 구조화 보고하고 **중단**(§9 수용기준).

정적과 같은 store 에 적재 → 같은 취약점의 정적·동적이 confidence 를 confirmed 로 상승.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from adapters import device_session, frida_adapter
from normalizers import dynamic_normalizer
from schema.findings import SourceTool, Target
from store.jsonl_store import FindingsStore


@dataclass
class DynamicResult:
    ok: bool
    state: str
    package: str = ""
    device: str = ""
    added: dict = field(default_factory=dict)
    session: dict = field(default_factory=dict)
    error: str = ""
    checks: int = 0
    promoted_static: int = 0

    def summary(self) -> str:
        if not self.ok:
            return (f"[동적 중단] state={self.state} device={self.device or '-'}\n"
                    f"  → {self.error or self.session.get('detail','')}")
        return (f"[동적 완료] device={self.device} package={self.package}\n"
                f"  런타임 점검 {self.checks}건 → store new={self.added.get('new',0)} "
                f"merged={self.added.get('merged',0)}, 정적 confidence 상승 {self.promoted_static}건")


def run_dynamic(package: str, platform: str = "android",
                script: str = "scripts/frida/android_checks.js",
                store: FindingsStore | None = None,
                sha256: str = "", spawn: bool = True) -> DynamicResult:
    store = store or FindingsStore()

    # 1) 세션 상태머신 (§7)
    status = device_session.check(platform=platform, package=package)
    if not status.ready:
        # 기기 미연결/불일치 → 구조화 보고 후 중단 (§9 수용기준)
        return DynamicResult(ok=False, state=status.state.value, package=package,
                             device=status.target, session=status.as_error(),
                             error=status.detail)

    # 2) Frida 런타임 점검
    run = frida_adapter.run_script(status.target, package, script, spawn=spawn)
    if not run["ok"]:
        return DynamicResult(ok=False, state="frida_run_failed", package=package,
                             device=status.target, session=status.as_error(),
                             error=run["error"])

    # 3) normalize → 공유 store 적재 (confidence=confirmed)
    target = Target(platform=platform, package=package, sha256=sha256)
    findings = dynamic_normalizer.normalize(run["messages"], target, source_tool=SourceTool.frida)
    added = store.add(findings)
    # 동적으로 재현된 mastg → 같은 취약점의 정적 finding confidence 상승 (§5, §9 수용기준)
    confirmed_ids = {mid for f in findings for mid in f.mastg_ids}
    promoted = store.promote_confidence(confirmed_ids)
    return DynamicResult(ok=True, state=status.state.value, package=package,
                         device=status.target, added=added, session=status.as_error(),
                         checks=len(findings), promoted_static=promoted)
