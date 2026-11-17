"""jadx 어댑터 (§6): APK 디컴파일 → Java 소스 트리.

플랜상 jadx MCP 가 연결돼 있으면 그쪽을 쓰고, 없으면 CLI 폴백.
semgrep 입력(소스 디렉터리)을 만드는 용도. 디바이스 안 건드림 → 정적 플레인.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def decompile(apk_path: str | Path, out_dir: str | Path, timeout: int = 900) -> dict:
    exe = shutil.which("jadx")
    if not exe:
        return {"error": "jadx 미설치/미연결 (MCP 또는 CLI 필요)", "src_dir": ""}
    apk = Path(apk_path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            [exe, "-d", str(out), "--no-res", str(apk)],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"jadx 타임아웃 ({timeout}s)", "src_dir": ""}
    src = out / "sources"
    return {
        "src_dir": str(src if src.exists() else out),
        "rc": proc.returncode,
        "stderr": proc.stderr[-300:] if proc.returncode else "",
    }
