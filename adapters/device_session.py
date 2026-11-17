"""기기 세션 상태머신 (§7). 동적 단계의 핵심 난이도 = 상태 관리.

관찰하고 구조화된 error 로 노출(§4-3, §7):
  1) 기기가 붙었는가 (frida-ls-devices/adb 목록에 target 이 있는가)
  2) frida-server 가 떠 있고 버전·arch 가 호스트와 맞는가
  3) 타겟 앱이 설치·실행 중인가

불일치·미연결이면 복구(frida-server 재기동) 시도, 안 되면 중단·보고.
-U 금지 — target 을 config/device_profiles.yaml 에서 읽어 명시 타겟팅.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml

from adapters import adb_adapter
from schema.config import REPO_ROOT


class SessionState(str, Enum):
    no_device = "no_device"                 # 기기 미연결
    frida_down = "frida_down"               # frida-server 미기동
    frida_mismatch = "frida_mismatch"       # 버전/arch 불일치
    app_not_installed = "app_not_installed"
    ready = "ready"                          # 후킹 준비 완료


@dataclass
class DeviceStatus:
    state: SessionState
    platform: str = "android"
    target: str = ""
    detail: str = ""
    host_frida_version: str = ""
    device_frida_version: str = ""
    abi: str = ""
    recovered: bool = False

    @property
    def ready(self) -> bool:
        return self.state == SessionState.ready

    def as_error(self) -> dict:
        """에이전트/파이프라인이 복구·중단 판단에 쓰는 구조화 상태."""
        return {
            "state": self.state.value, "platform": self.platform, "target": self.target,
            "detail": self.detail, "host_frida": self.host_frida_version,
            "device_frida": self.device_frida_version, "abi": self.abi,
            "recovered": self.recovered,
        }


def _profiles() -> dict:
    p = REPO_ROOT / "config" / "device_profiles.yaml"
    return yaml.safe_load(p.read_text()) or {}


def host_frida_version() -> str:
    exe = shutil.which("frida")
    if not exe:
        return ""
    try:
        return subprocess.run([exe, "--version"], capture_output=True, text=True,
                              timeout=15).stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def _ls_devices_ids() -> list[str]:
    """frida-ls-devices 로 기기 id 목록 (-U 미사용). frida 없으면 adb 로 폴백."""
    exe = shutil.which("frida-ls-devices")
    if exe:
        try:
            out = subprocess.run([exe], capture_output=True, text=True, timeout=20).stdout
            ids = []
            for line in out.splitlines()[2:]:  # 헤더 2줄 스킵
                tok = line.split()
                if tok:
                    ids.append(tok[0])
            if ids:
                return ids
        except Exception:  # noqa: BLE001
            pass
    return adb_adapter.devices()


def _device_frida_version(serial: str) -> str:
    """기기 frida-server 프로세스에서 버전 확인 (실행 중이면)."""
    # frida-server --version 을 기기에서. 경로 고정.
    r = adb_adapter.shell(serial, "/data/local/tmp/frida-server --version")
    v = r.stdout.strip()
    return v if r.ok and v and v[0].isdigit() else ""


def _frida_server_running(serial: str) -> bool:
    r = adb_adapter.shell(serial, "pidof frida-server")
    return bool(r.stdout.strip())


def _try_start_frida_server(serial: str) -> bool:
    """복구 시도: 기기의 frida-server 재기동 (su 우선)."""
    adb_adapter.shell(
        serial,
        "su -c '/data/local/tmp/frida-server &' >/dev/null 2>&1 "
        "|| /data/local/tmp/frida-server >/dev/null 2>&1 &",
        timeout=10,
    )
    import time
    time.sleep(2)
    return _frida_server_running(serial)


def _remote_device_ok(frida_host: str) -> tuple[bool, str]:
    """원격 frida-server(-H) 접속 가능 여부. (ok, detail)."""
    try:
        import frida
    except ImportError:
        return False, "frida 미설치 (setup-dynamic.sh)"
    try:
        dev = frida.get_device_manager().add_remote_device(frida_host)
        _ = dev.enumerate_processes()  # 실제 통신 확인
        return True, "원격 frida-server 접속 OK"
    except Exception as e:  # noqa: BLE001
        return False, f"원격 {frida_host} 접속 실패: {e}"


def check(platform: str = "android", package: str = "", auto_recover: bool = True) -> DeviceStatus:
    """세션 상태 점검 (§7). 디바이스 없으면 no_device 로 즉시 구조화 반환."""
    prof = _profiles()
    pconf = prof.get(platform, {})
    target = pconf.get("target", "") or ""
    # 기기 IP 는 공개 레포에 안 올리도록 .env(IOS_FRIDA_HOST/ANDROID_FRIDA_HOST)로 덮어쓰기 우선
    import os
    from schema.config import _load_dotenv
    _load_dotenv(REPO_ROOT / ".env")
    env_host = os.environ.get(f"{platform.upper()}_FRIDA_HOST", "")
    frida_host = env_host or pconf.get("host", "") or ""
    want_ver = str(prof.get("frida", {}).get("version", ""))
    host_ver = host_frida_version()

    # 원격 iOS 경로 (WSL2에서 USB 안 보일 때): host 로 네트워크 접속
    if frida_host:
        ok, detail = _remote_device_ok(frida_host)
        if not ok:
            return DeviceStatus(SessionState.no_device, platform, frida_host, detail=detail,
                                host_frida_version=host_ver, abi=pconf.get("arch", ""))
        return DeviceStatus(SessionState.ready, platform, frida_host,
                            detail=f"원격 frida 준비 완료 ({detail})",
                            host_frida_version=host_ver, device_frida_version=want_ver,
                            abi=pconf.get("arch", ""))

    # 1) 기기 연결 (USB/로컬 경로)
    ids = _ls_devices_ids()
    if not target:
        return DeviceStatus(SessionState.no_device, platform, target,
                            detail=f"config/device_profiles.yaml 의 {platform}.target 미설정 (§7). "
                                   f"현재 연결 목록: {ids or '없음'}",
                            host_frida_version=host_ver)
    if target not in ids:
        return DeviceStatus(SessionState.no_device, platform, target,
                            detail=f"target '{target}' 미연결. 연결 목록: {ids or '없음'}. "
                                   f"BlueStacks/실단말 연결·connect-android.sh 확인.",
                            host_frida_version=host_ver)

    abi = adb_adapter.cpu_abi(target) if platform == "android" else pconf.get("arch", "")

    # 2) frida-server 기동 + 버전/arch
    running = _frida_server_running(target) if platform == "android" else True
    recovered = False
    if platform == "android" and not running:
        if auto_recover and _try_start_frida_server(target):
            running = True
            recovered = True
        else:
            return DeviceStatus(SessionState.frida_down, platform, target,
                                detail="frida-server 미기동·복구 실패. bootstrap-frida.sh 실행 필요.",
                                host_frida_version=host_ver, abi=abi)

    dev_ver = _device_frida_version(target) if platform == "android" else want_ver
    if want_ver and dev_ver and dev_ver != want_ver:
        return DeviceStatus(SessionState.frida_mismatch, platform, target,
                            detail=f"frida 버전 불일치: 기기={dev_ver} config={want_ver} "
                                   f"(host={host_ver}). bootstrap-frida.sh 로 재매칭.",
                            host_frida_version=host_ver, device_frida_version=dev_ver,
                            abi=abi, recovered=recovered)
    if want_ver and host_ver and host_ver != want_ver:
        return DeviceStatus(SessionState.frida_mismatch, platform, target,
                            detail=f"호스트 frida({host_ver}) != config({want_ver}). "
                                   f"setup-dynamic.sh 로 버전 고정.",
                            host_frida_version=host_ver, device_frida_version=dev_ver,
                            abi=abi, recovered=recovered)

    # 3) 앱 설치
    if package and platform == "android" and not adb_adapter.is_app_installed(target, package):
        return DeviceStatus(SessionState.app_not_installed, platform, target,
                            detail=f"타겟 앱 '{package}' 미설치. adb install 필요.",
                            host_frida_version=host_ver, device_frida_version=dev_ver,
                            abi=abi, recovered=recovered)

    return DeviceStatus(SessionState.ready, platform, target,
                        detail="후킹 준비 완료.", host_frida_version=host_ver,
                        device_frida_version=dev_ver, abi=abi, recovered=recovered)
