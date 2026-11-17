"""Step 3 회귀: MobSF report → findings 정규화 (라이브 컨테이너 불필요, 픽스처 사용)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from normalizers import mobsf_normalizer  # noqa: E402
from store.jsonl_store import FindingsStore  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "mobsf_insecurebank.json"


def _report():
    return json.loads(FIXTURE.read_text())


def test_normalize_produces_mapped_findings():
    findings = mobsf_normalizer.normalize(_report())
    assert len(findings) >= 10, f"기대보다 적음: {len(findings)}"
    assert all(f.target.platform.value == "android" for f in findings)
    assert all(f.target.package == "com.android.insecurebankv2" for f in findings)
    mapped = [f for f in findings if f.is_mapped()]
    assert len(mapped) == len(findings), "InsecureBankv2 는 전부 매핑돼야 함"
    ids = {m for f in findings for m in f.mastg_ids}
    assert "MASTG-TEST-0039" in ids  # debuggable
    assert "MASTG-TEST-0030" in ids  # exported/task hijacking
    print(f"[ok] normalize: {len(findings)} findings, all mapped, {len(ids)} distinct MASTG ids")


def test_store_roundtrip_and_dedup(tmp_path=None):
    import tempfile
    d = tmp_path or Path(tempfile.mkdtemp())
    store = FindingsStore(d / "f.jsonl")
    store.clear()
    findings = mobsf_normalizer.normalize(_report())
    s1 = store.add(findings)
    n = len(findings)
    assert s1["new"] == n and s1["merged"] == 0
    # 같은 리포트 재적재 → 전부 merge, 총계 불변 (dedup)
    s2 = store.add(mobsf_normalizer.normalize(_report()))
    assert s2["new"] == 0 and s2["merged"] == n
    assert len(store.all()) == n
    print(f"[ok] store dedup: {n} findings, re-add merges all (total stays {n})")


if __name__ == "__main__":
    test_normalize_produces_mapped_findings()
    test_store_roundtrip_and_dedup()
    print("\nALL PASSED")
