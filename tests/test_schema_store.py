"""Step 2 수용 근거: findings 스키마(§5) + dedup/merge + store + 매핑 테이블.

레포 루트에서:  python -m pytest tests/test_schema_store.py -v
또는 직접:      python tests/test_schema_store.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mappings.loader import lookup  # noqa: E402
from schema.findings import (  # noqa: E402
    AnalysisType,
    Confidence,
    Finding,
    Severity,
    SourceTool,
    Target,
    Location,
    merge_findings,
)
from store.jsonl_store import FindingsStore  # noqa: E402


def _f(tool, atype, conf, mastg=("MASTG-TEST-0019",), cls="c.Net", method="connect", sev=Severity.high):
    return Finding(
        title="Insecure TrustManager",
        severity=sev,
        confidence=conf,
        source_tool=tool,
        analysis_type=atype,
        mastg_ids=list(mastg),
        target=Target(platform="android", package="com.x", sha256="ab"),
        location=Location(file="Net.java", **{"class": cls}, method=method, line=10),
        evidence=f"{tool.value} evidence",
    )


def test_schema_roundtrip():
    f = _f(SourceTool.mobsf, AnalysisType.static, Confidence.tentative)
    js = f.model_dump_json(by_alias=True)
    back = Finding.model_validate_json(js)
    assert back.location.class_ == "c.Net"  # alias "class" 왕복
    assert '"class"' in js and "class_" not in js
    print("[ok] schema roundtrip (class alias)")


def test_dedup_key_ignores_line():
    a = _f(SourceTool.mobsf, AnalysisType.static, Confidence.tentative)
    b = _f(SourceTool.semgrep, AnalysisType.static, Confidence.firm)
    b.location.line = 999  # line 은 dedup 키에서 제외(§5)
    assert a.dedup_key() == b.dedup_key()
    # 다른 method 면 다른 키
    c = _f(SourceTool.mobsf, AnalysisType.static, Confidence.tentative, method="other")
    assert c.dedup_key() != a.dedup_key()
    print("[ok] dedup key (line excluded, method distinguishes)")


def test_confidence_promotion():
    static = _f(SourceTool.mobsf, AnalysisType.static, Confidence.tentative)
    dynamic = _f(SourceTool.frida, AnalysisType.dynamic, Confidence.confirmed)
    merged = merge_findings(static, dynamic)
    assert merged.confidence == Confidence.confirmed  # §5 상승 규칙
    assert "mobsf:static:tentative" in merged.raw["merged_from"]
    assert "frida:dynamic:confirmed" in merged.raw["merged_from"]
    print("[ok] confidence promotion static+dynamic -> confirmed")


def test_store_dedup_and_merge(tmp_path=None):
    import tempfile
    d = tmp_path or Path(tempfile.mkdtemp())
    store = FindingsStore(d / "findings.jsonl")
    store.clear()
    s1 = store.add([_f(SourceTool.mobsf, AnalysisType.static, Confidence.tentative)])
    assert s1 == {"new": 1, "merged": 0}
    s2 = store.add([_f(SourceTool.frida, AnalysisType.dynamic, Confidence.confirmed)])
    assert s2 == {"new": 0, "merged": 1}  # 같은 취약점 → 병합
    allf = store.all()
    assert len(allf) == 1
    assert allf[0].confidence == Confidence.confirmed
    print("[ok] store dedup+merge: 2 findings -> 1 confirmed")


def test_mapping_table():
    m = lookup("android_default_trustmanager")
    assert m.mapped and "MASTG-TEST-0019" in m.mastg_ids
    assert lookup("manifest:app_is_debuggable".split(":")[-1] or "app_is_debuggable").mapped
    assert not lookup("nonexistent_rule_xyz").mapped  # unmapped 버킷
    print("[ok] mapping lookup (mapped + unmapped bucket)")


if __name__ == "__main__":
    test_schema_roundtrip()
    test_dedup_key_ignores_line()
    test_confidence_promotion()
    test_store_dedup_and_merge()
    test_mapping_table()
    print("\nALL PASSED")
