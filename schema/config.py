"""설정 로더 — config/*.yaml + .env 를 합쳐 읽는다 (§3, §12: 하드코딩 금지).

tools.yaml 안의 ${VAR} / ${VAR:-default} 를 .env·환경변수로 치환한다.
"""
from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _load_dotenv(path: Path) -> None:
    """.env 를 os.environ 에 주입 (이미 설정된 값은 덮지 않음)."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())


def _subst(value: Any) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            var, default = m.group(1), m.group(2)
            return os.environ.get(var, default if default is not None else "")
        return _VAR_RE.sub(repl, value)
    if isinstance(value, dict):
        return {k: _subst(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_subst(v) for v in value]
    return value


@lru_cache(maxsize=None)
def load_config(name: str = "tools") -> dict[str, Any]:
    """config/<name>.yaml 을 .env 치환 적용해 로드."""
    _load_dotenv(REPO_ROOT / ".env")
    path = REPO_ROOT / "config" / f"{name}.yaml"
    data = yaml.safe_load(path.read_text()) or {}
    return _subst(data)


def mobsf_config() -> dict[str, Any]:
    cfg = load_config("tools").get("mobsf", {})
    if not cfg.get("api_key"):
        raise RuntimeError(
            "MOBSF_API_KEY 미설정. scripts/setup-static.sh 로 추출하거나 .env 에 입력하라."
        )
    return cfg
