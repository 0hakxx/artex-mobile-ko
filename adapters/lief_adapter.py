"""LIEF 어댑터 (§6, §8-4): 맥 없이 IPA 정적 분석.

IPA(zip) → Payload/*.app 추출 → Mach-O 바이너리 + Info.plist + entitlements 파싱.
class-dump 같은 맥 전용 도구 없이 LIEF 로 WSL2/컨테이너에서 처리.
출력은 구조화 dict (normalizer 가 findings 로 변환).
"""
from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path
from typing import Any


def _find_app_binary(names: list[str]) -> tuple[str | None, str | None]:
    """zip 엔트리에서 Payload/<App>.app/<App> 실행 바이너리와 Info.plist 경로 추정."""
    app_dirs = {n.split("/")[1] for n in names
                if n.startswith("Payload/") and n.split("/")[1].endswith(".app")} \
        if any(n.startswith("Payload/") for n in names) else set()
    if not app_dirs:
        return None, None
    app = sorted(app_dirs)[0]
    base = app[:-4]  # ".app" 제거 → 실행 파일명 추정
    binary = f"Payload/{app}/{base}"
    plist = f"Payload/{app}/Info.plist"
    if binary not in names:
        # CFBundleExecutable 로 다시 찾기 위해 None 바이너리 반환, plist 는 유지
        binary = None
    return binary, (plist if plist in names else None)


def analyze_ipa(file_path: str | Path) -> dict[str, Any]:
    p = Path(file_path)
    if not p.exists():
        return {"error": f"파일 없음: {p}"}
    try:
        import lief
    except ImportError:
        return {"error": "lief 미설치 (tools 컨테이너에서 실행)"}

    try:
        zf = zipfile.ZipFile(p)
    except zipfile.BadZipFile:
        return {"error": "IPA(zip) 열기 실패"}

    names = zf.namelist()
    binary_name, plist_name = _find_app_binary(names)

    info: dict[str, Any] = {}
    if plist_name:
        try:
            info = plistlib.loads(zf.read(plist_name))
        except Exception as e:  # noqa: BLE001
            info = {"_plist_error": str(e)}

    # CFBundleExecutable 로 바이너리 경로 보정
    app_dir = plist_name.rsplit("/", 1)[0] if plist_name else None
    if (not binary_name) and app_dir and info.get("CFBundleExecutable"):
        cand = f"{app_dir}/{info['CFBundleExecutable']}"
        if cand in names:
            binary_name = cand

    result: dict[str, Any] = {
        "bundle_id": info.get("CFBundleIdentifier", ""),
        "executable": binary_name or "",
        "min_os": info.get("MinimumOSVersion", ""),
        "ats": info.get("NSAppTransportSecurity", {}),
        "url_schemes": [s for d in info.get("CFBundleURLTypes", [])
                        for s in d.get("CFBundleURLSchemes", [])],
        "macho": {},
        "info_plist_keys": sorted(info.keys()),
    }

    if binary_name:
        try:
            import os
            import tempfile
            raw = zf.read(binary_name)
            tmp_fd, tmp_name = tempfile.mkstemp(suffix=".macho")
            try:
                with os.fdopen(tmp_fd, "wb") as fh:
                    fh.write(raw)
                fat = lief.MachO.parse(tmp_name)
            finally:
                os.unlink(tmp_name)
            bins = list(fat) if fat else []
            arches = []
            encryption = None
            pie = None
            nx = None
            for b in bins:
                hdr = b.header
                arches.append(str(hdr.cpu_type).split(".")[-1])
                # PIE / encryption 플래그
                flags = str(hdr.flags_list) if hasattr(hdr, "flags_list") else ""
                if pie is None:
                    pie = "PIE" in flags
                # encryption info
                try:
                    enc = b.encryption_info
                    if enc is not None:
                        encryption = int(getattr(enc, "crypt_id", 0))
                except Exception:  # noqa: BLE001
                    pass
            result["macho"] = {
                "arches": arches,
                "pie": pie,
                "crypt_id": encryption,  # 0 = 암호화 안 됨(App Store 아님), 1 = FairPlay
            }
        except Exception as e:  # noqa: BLE001
            result["macho"] = {"error": f"Mach-O 파싱 실패: {e}"}

    return result
