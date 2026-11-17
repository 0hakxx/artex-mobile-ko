"""apkid 어댑터 (§6, §8-4). 컴파일러·패커·난독화 탐지. APK → JSON.

CLI `apkid --json`. 컨테이너(tools)에서 실행. 디바이스 안 건드림.
실패는 구조화 dict(error 키)로 반환(§4-3).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def run_apkid(file_path: str | Path, timeout: int = 300) -> dict[str, Any]:
    exe = shutil.which("apkid")
    if not exe:
        return {"error": "apkid 미설치 (tools 컨테이너에서 실행하라)"}
    p = Path(file_path)
    if not p.exists():
        return {"error": f"파일 없음: {p}"}
    try:
        proc = subprocess.run(
            [exe, "--json", str(p)],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"apkid 타임아웃 ({timeout}s)"}
    out = proc.stdout.strip()
    if not out:
        return {"error": f"apkid 출력 없음 (rc={proc.returncode}): {proc.stderr[:200]}"}
    try:
        # apkid 는 간혹 선행 로그 후 JSON 을 출력 → 첫 '{' 부터 파싱
        start = out.find("{")
        return json.loads(out[start:]) if start >= 0 else {"error": f"JSON 없음: {out[:200]}"}
    except json.JSONDecodeError as e:
        return {"error": f"apkid JSON 파싱 실패: {e}"}
