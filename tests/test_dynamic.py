"""Phase 2 회귀: 동적 세션 상태머신 + 런타임 normalizer + 정적·동적 confidence 상승.

디바이스 없이 검증: (1) 미연결→구조화 중단, (2) frida 메시지→confirmed findings,
(3) 동적 재현 mastg → 정적 finding confidence confirmed 상승(§9 수용기준 #4).
라이브 후킹(SSL→Burp)은 실단말에서 run_dynamic.py 로 확인.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from adapters import device_session  # noqa: E402
from normalizers import dynamic_normalizer  # noqa: E402
from pipeline import dynamic_pipeline  # noqa: E402
from schema.findings import (  # noqa: E402
    AnalysisType, Confidence, Finding, Location, Severity, SourceTool, Target,
)
from store.jsonl_store import FindingsStore  # noqa: E402


def test_no_device_structured_stop():
    st = device_session.check(platform="android", package="com.x")
    assert not st.ready
    assert st.state == device_session.SessionState.no_device
    assert "target" in st.as_error()
    print(f"[ok] 미연결 → 구조화 중단 (state={st.state.value})")


def test_runtime_messages_to_confirmed():
    msgs = [
        {"_artex": True, "check": "weak_hash_runtime", "mastg": "MASTG-TEST-0203",
         "masvs": "MASVS-CRYPTO-1", "severity": "medium", "title": "약한 해시 런타임",
         "evidence": 'MessageDigest.getInstance("MD5")'},
        {"_artex": True, "check": "hooks_installed", "severity": "info", "title": "설치"},
    ]
    tgt = Target(platform="android", package="com.x")
    fs = dynamic_normalizer.normalize(msgs, tgt)
    assert len(fs) == 1  # info(hooks_installed)는 제외
    assert fs[0].confidence == Confidence.confirmed
    assert fs[0].analysis_type == AnalysisType.dynamic
    print(f"[ok] frida 메시지 → {len(fs)} confirmed dynamic finding")


def test_static_promoted_by_dynamic():
    """§9 #4: 같은 mastg 의 정적(firm) finding 이 동적 재현으로 confirmed 상승."""
    d = Path(tempfile.mkdtemp())
    store = FindingsStore(d / "f.jsonl"); store.clear()
    # 정적 weak-hash (semgrep, firm, 특정 파일)
    static = Finding(
        title="weak hash", severity=Severity.medium, confidence=Confidence.firm,
        mastg_ids=["MASTG-TEST-0203"], masvs_ids=["MASVS-CRYPTO-1"], category="MASVS-CRYPTO",
        source_tool=SourceTool.semgrep, analysis_type=AnalysisType.static,
        target=Target(platform="android", package="com.x"),
        location=Location(file="zza.java"))
    store.add([static])
    assert store.all()[0].confidence == Confidence.firm

    # 동적 파이프라인 모사: 세션 ready + frida 메시지 반환을 패치
    ready = device_session.DeviceStatus(device_session.SessionState.ready,
                                        "android", "emulator-5554")
    msgs = {"ok": True, "messages": [
        {"_artex": True, "check": "weak_hash_runtime", "mastg": "MASTG-TEST-0203",
         "masvs": "MASVS-CRYPTO-1", "severity": "medium", "title": "약한 해시 런타임",
         "evidence": "MD5"}], "error": ""}
    with mock.patch.object(dynamic_pipeline.device_session, "check", return_value=ready), \
         mock.patch.object(dynamic_pipeline.frida_adapter, "run_script", return_value=msgs):
        res = dynamic_pipeline.run_dynamic("com.x", store=store)

    assert res.ok and res.checks == 1
    assert res.promoted_static == 1, "정적 finding 이 confirmed 로 상승하지 않음"
    # 정적 finding 이 confirmed 로 바뀌었는지 확인
    static_rows = [f for f in store.all() if f.analysis_type == AnalysisType.static]
    assert static_rows[0].confidence == Confidence.confirmed
    assert static_rows[0].raw.get("dynamically_confirmed") is True
    print(f"[ok] §9#4: 동적 재현 → 정적 confidence firm→confirmed (상승 {res.promoted_static}건)")


if __name__ == "__main__":
    test_no_device_structured_stop()
    test_runtime_messages_to_confirmed()
    test_static_promoted_by_dynamic()
    print("\nALL PASSED")
