"""Frida 어댑터 (§6, §9-3). 호스트 프로세스. 기기 ID 로 명시 타겟팅(-U 금지, §7).

frida-python 으로 기기에 attach/spawn → JS 스크립트 로드 → send() 메시지 수집.
frida 미설치/기기 미연결은 구조화 dict(error)로 반환(§4-3).
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from schema.config import REPO_ROOT


def run_script(device_id: str, package: str, script_path: str | Path,
               spawn: bool = True, collect_sec: int = 6) -> dict[str, Any]:
    """device_id 기기에서 package 를 띄우고 script 를 로드, send() 메시지 수집.

    반환: {"ok": bool, "messages": [...], "error": str}
    messages 는 스크립트가 send() 한 _artex 레코드 리스트.
    """
    try:
        import frida  # noqa: F401
    except ImportError:
        return {"ok": False, "error": "frida 미설치 (호스트 setup-dynamic.sh)", "messages": []}

    import frida
    sp = Path(script_path)
    if not sp.is_absolute():
        sp = REPO_ROOT / sp
    if not sp.exists():
        return {"ok": False, "error": f"스크립트 없음: {sp}", "messages": []}

    messages: list[dict] = []

    def on_message(message, data):  # noqa: ANN001
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("_artex"):
                messages.append(payload)
        elif message.get("type") == "error":
            messages.append({"_artex": True, "check": "script_error", "severity": "info",
                             "title": "Frida 스크립트 오류", "evidence": message.get("description", "")})

    try:
        # device id 로 정확히 타겟팅 (-U 금지)
        device = frida.get_device(device_id, timeout=10)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"기기 '{device_id}' 접근 실패: {e}", "messages": []}

    session = None
    try:
        if spawn:
            pid = device.spawn([package])
            session = device.attach(pid)
        else:
            session = device.attach(package)
        script = session.create_script(sp.read_text())
        script.on("message", on_message)
        script.load()
        if spawn:
            device.resume(pid)
        time.sleep(collect_sec)  # 후킹 트리거 수집 윈도우
        return {"ok": True, "messages": messages, "error": ""}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"후킹 실패: {e}", "messages": messages}
    finally:
        try:
            if session:
                session.detach()
        except Exception:  # noqa: BLE001
            pass
