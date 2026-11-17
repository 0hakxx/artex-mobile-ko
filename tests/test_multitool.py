"""Step 4 회귀: 보강 도구(apkid/LIEF) 정규화 + 다도구 교차 dedup (오프라인 픽스처).

라이브 컨테이너 불필요 — adapters 출력 픽스처로 normalizer+store 를 검증.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from normalizers import apkid_normalizer, lief_normalizer, mobsf_normalizer  # noqa: E402
from schema.findings import Target  # noqa: E402
from store.jsonl_store import FindingsStore  # noqa: E402

FX = ROOT / "tests" / "fixtures"


def test_apkid_unmapped_bucket():
    data = json.loads((FX / "apkid_insecurebank.json").read_text())
    tgt = Target(platform="android", package="com.android.insecurebankv2")
    findings = apkid_normalizer.normalize(data, tgt)
    assert findings, "apkid findings 비어있음"
    # compiler/manipulator 범주 → 미매핑 버킷 존재해야 함(§8)
    unmapped = [f for f in findings if not f.is_mapped()]
    assert unmapped, "apkid 미매핑 버킷이 비어있음"
    print(f"[ok] apkid: {len(findings)} findings, {len(unmapped)} unmapped(bucket)")


def test_lief_ipa_findings():
    data = json.loads((FX / "lief_dvia.json").read_text())
    findings = lief_normalizer.normalize(data, sha256="deadbeef")
    assert findings, "LIEF findings 비어있음"
    assert all(f.target.platform.value == "ios" for f in findings)
    ids = {m for f in findings for m in f.mastg_ids}
    assert "MASTG-TEST-0070" in ids, "ATS(NSAllowsArbitraryLoads) 미검출"
    print(f"[ok] LIEF IPA: {len(findings)} findings, ATS detected, MASTG={sorted(ids)}")


def test_cross_tool_merge_on_ats():
    """MobSF(iOS appsec) + LIEF 가 같은 ATS 취약점 → store 에서 1건으로 병합."""
    mobsf_rep = {  # 최소 iOS appsec 리포트
        "bundle_id": "com.x", "sha256": "ab",
        "appsec": {"high": [
            {"title": "ATS AllowsArbitraryLoads", "description": "arbitrary loads",
             "section": "network"}]},
    }
    mobsf_findings = mobsf_normalizer.normalize_ios_appsec(mobsf_rep, sha256="ab")
    lief_data = json.loads((FX / "lief_dvia.json").read_text())
    lief_findings = lief_normalizer.normalize(lief_data, sha256="ab")

    d = Path(tempfile.mkdtemp())
    store = FindingsStore(d / "f.jsonl")
    store.clear()
    store.add(mobsf_findings)
    before = len(store.all())
    s2 = store.add(lief_findings)
    assert s2["merged"] >= 1, "ATS 교차 도구 병합이 일어나지 않음"
    merged = [f for f in store.all() if len(f.raw.get("merged_from", [])) > 1]
    tools = {t.split(":")[0] for f in merged for t in f.raw["merged_from"]}
    assert "mobsf" in tools and "lief" in tools
    print(f"[ok] cross-tool merge: mobsf+lief ATS → 1건 (store {before}→{len(store.all())}, merged={s2['merged']})")


if __name__ == "__main__":
    test_apkid_unmapped_bucket()
    test_lief_ipa_findings()
    test_cross_tool_merge_on_ats()
    print("\nALL PASSED")
