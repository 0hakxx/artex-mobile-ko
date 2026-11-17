#!/usr/bin/env python3
"""정적 파이프라인 CLI 진입점 (§8).

    python run_static.py <apk_or_ipa> [--fresh]

사람 개입 없이: upload → scan(폴링) → report → normalize → findings JSONL 적재.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pipeline.static_pipeline import run_static  # noqa: E402
from store.jsonl_store import FindingsStore  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Mobile ARTEX 정적 파이프라인")
    ap.add_argument("target", help="APK/IPA 경로")
    ap.add_argument("--fresh", action="store_true", help="실행 전 store 비우기")
    ap.add_argument("--store", default=None, help="findings store 경로 (기본: config)")
    ap.add_argument("--src", default=None, help="semgrep 대상 소스 디렉터리(디컴파일 결과)")
    ap.add_argument("--decompile", action="store_true", help="jadx 로 디컴파일 후 semgrep 실행")
    args = ap.parse_args()

    store = FindingsStore(args.store) if args.store else FindingsStore()
    res = run_static(args.target, store=store, fresh=args.fresh,
                     src_dir=args.src, decompile=args.decompile)
    print(res.summary())
    print(f"\nstore: {store.path}")
    # 도구가 하나라도 실패하면 비정상 종료코드
    return 0 if all(t.ok for t in res.tool_results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
