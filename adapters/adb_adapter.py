"""adb 어댑터 (§9-1). 호스트 프로세스(컨테이너 아님). 기기는 §7 serial 로 명시 타겟팅.

connect / devices / install / shell / pull — 각각 구조화 출력(AdbResult).
-U 같은 모호한 셀렉터 안 씀. serial 을 항상 지정.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class AdbResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    rc: int = 0
    error: str = ""


def _adb() -> str | None:
    return shutil.which("adb")


def _run(args: list[str], timeout: int = 60) -> AdbResult:
    exe = _adb()
    if not exe:
        return AdbResult(False, error="adb 미설치 (호스트에 android-tools 설치 필요)")
    try:
        p = subprocess.run([exe, *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return AdbResult(False, error=f"adb 타임아웃: {' '.join(args)}")
    return AdbResult(p.returncode == 0, p.stdout.strip(), p.stderr.strip(), p.returncode,
                     "" if p.returncode == 0 else p.stderr.strip()[:200])


def connect(host_port: str) -> AdbResult:
    """BlueStacks adb-over-TCP (<windows-host-ip>:<port>)."""
    return _run(["connect", host_port])


def devices() -> list[str]:
    """연결된 기기 serial 목록 (offline 제외)."""
    r = _run(["devices"])
    out = []
    for line in r.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            out.append(parts[0])
    return out


def shell(serial: str, cmd: str, timeout: int = 60) -> AdbResult:
    return _run(["-s", serial, "shell", cmd], timeout=timeout)


def install(serial: str, apk_path: str) -> AdbResult:
    return _run(["-s", serial, "install", "-r", apk_path], timeout=300)


def pull(serial: str, remote: str, local: str) -> AdbResult:
    return _run(["-s", serial, "pull", remote, local], timeout=300)


def getprop(serial: str, prop: str) -> str:
    return shell(serial, f"getprop {prop}").stdout.strip()


def cpu_abi(serial: str) -> str:
    return getprop(serial, "ro.product.cpu.abi")


def is_app_installed(serial: str, package: str) -> bool:
    r = shell(serial, f"pm list packages {package}")
    return f"package:{package}" in r.stdout
