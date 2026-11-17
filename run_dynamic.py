#!/usr/bin/env python3
"""동적 파이프라인 CLI (§9). 호스트에서 실행 (컨테이너 아님).

    python run_dynamic.py <package> [--platform android|ios] [--no-spawn]

기기 식별·세션 규칙은 config/device_profiles.yaml (§7). 기기 미연결이면
구조화 상태를 출력하고 중단한다.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pipeline.dynamic_pipeline import run_dynamic  # noqa: E402
from store.jsonl_store import FindingsStore  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Mobile ARTEX 동적 파이프라인")
    ap.add_argument("package", help="타겟 앱 패키지/번들 id")
    ap.add_argument("--platform", default="android", choices=["android", "ios"])
    ap.add_argument("--script", default="scripts/frida/android_checks.js")
    ap.add_argument("--store", default=None)
    ap.add_argument("--sha256", default="")
    ap.add_argument("--no-spawn", action="store_true", help="spawn 대신 실행 중 앱에 attach")
    args = ap.parse_args()

    store = FindingsStore(args.store) if args.store else FindingsStore()
    res = run_dynamic(args.package, platform=args.platform, script=args.script,
                      store=store, sha256=args.sha256, spawn=not args.no_spawn)
    print(res.summary())
    print("\n[세션 상태]")
    print(json.dumps(res.session, ensure_ascii=False, indent=2))
    return 0 if res.ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
