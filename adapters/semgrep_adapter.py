"""semgrep 어댑터 (§6, §8-4). 소스 패턴 룰 검사. 소스디렉터리 → JSON.

semgrep 은 바이트코드가 아니라 소스를 본다 → APK 는 jadx 디컴파일(아래 jadx_adapter)
결과를 입력으로 받는다. 컨테이너(tools)에서 실행. 디바이스 안 건드림.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from schema.config import REPO_ROOT, load_config


def run_semgrep(src_dir: str | Path, config: str | None = None,
                timeout: int | None = None) -> dict[str, Any]:
    exe = shutil.which("semgrep")
    if not exe:
        return {"error": "semgrep 미설치 (tools 컨테이너에서 실행)"}
    src = Path(src_dir)
    if not src.exists():
        return {"error": f"소스 경로 없음: {src}"}
    cfg_yaml = load_config("tools").get("semgrep", {})
    config = config or cfg_yaml.get("config", "auto")
    # 레포-상대 경로면 절대경로로(로컬 룰셋). 아니면 registry id 로 그대로 전달.
    local = REPO_ROOT / config
    if local.exists():
        config = str(local)
    timeout = timeout or int(cfg_yaml.get("timeout_sec", 600))
    try:
        proc = subprocess.run(
            [exe, "--json", "--quiet", "--config", config, str(src)],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"semgrep 타임아웃 ({timeout}s)"}
    if not proc.stdout.strip():
        return {"error": f"semgrep 출력 없음 (rc={proc.returncode}): {proc.stderr[:200]}"}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return {"error": f"semgrep JSON 파싱 실패: {e}"}
