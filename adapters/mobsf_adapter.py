"""MobSF 어댑터 (§6, §8-2). REST API 를 3개 액션으로 래핑: upload / scan / report_json.

- scan 은 비동기 → 완료 폴링을 어댑터에 내장, 완료 전 report_json 호출 금지.
- 실패는 예외 대신 구조화 상태로 노출(§4-3): MobsfError.
- 기기를 안 건드림 → 컨테이너(정적 플레인) 대상.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import requests

from schema.config import mobsf_config


class MobsfError(RuntimeError):
    """어댑터 레벨 구조화 에러 (에이전트가 복구/중단 판단에 사용)."""

    def __init__(self, stage: str, detail: str, status: int | None = None):
        self.stage = stage
        self.detail = detail
        self.status = status
        super().__init__(f"[mobsf:{stage}] {detail}" + (f" (HTTP {status})" if status else ""))


class MobsfAdapter:
    def __init__(self, url: str | None = None, api_key: str | None = None,
                 poll_interval: int | None = None, poll_timeout: int | None = None):
        cfg = mobsf_config()
        self.url = (url or cfg["url"]).rstrip("/")
        self.api_key = api_key or cfg["api_key"]
        self.poll_interval = poll_interval or int(cfg.get("scan_poll_interval_sec", 5))
        self.poll_timeout = poll_timeout or int(cfg.get("scan_poll_timeout_sec", 900))
        self._h = {"Authorization": self.api_key}

    # --- 1) upload ---
    def upload(self, file_path: str | Path) -> dict[str, Any]:
        p = Path(file_path)
        if not p.exists():
            raise MobsfError("upload", f"파일 없음: {p}")
        with p.open("rb") as fh:
            files = {"file": (p.name, fh, "application/octet-stream")}
            r = self._post("/api/v1/upload", files=files)
        data = self._json(r, "upload")
        if "hash" not in data:
            raise MobsfError("upload", f"응답에 hash 없음: {data}", r.status_code)
        return data  # {hash, scan_type, file_name, ...}

    # --- 2) scan (비동기 → 완료까지 블로킹 폴링) ---
    def scan(self, file_hash: str) -> dict[str, Any]:
        """scan 트리거 후 완료까지 폴링. report_json 은 이 뒤에만 호출."""
        deadline = time.time() + self.poll_timeout
        attempt = 0
        while True:
            attempt += 1
            r = self._post("/api/v1/scan", data={"hash": file_hash})
            # MobSF scan 은 완료 시 전체 결과를 반환. 진행 중이면 비거나 오류 톤.
            if r.status_code == 200:
                try:
                    data = r.json()
                except ValueError:
                    data = {}
                # 완료 판정: scan 응답이 분석 섹션을 담고 있으면 완료
                if isinstance(data, dict) and self._looks_complete(data):
                    return data
            if time.time() > deadline:
                raise MobsfError("scan", f"완료 폴링 타임아웃({self.poll_timeout}s, {attempt}회)", r.status_code)
            time.sleep(self.poll_interval)

    @staticmethod
    def _looks_complete(data: dict[str, Any]) -> bool:
        # MobSF scan/report 완료 응답에 존재하는 대표 키들
        markers = ("code_analysis", "manifest_analysis", "appsec", "security_score",
                   "binary_analysis", "macho_analysis")
        return any(k in data for k in markers)

    # --- 3) report_json (scan 완료 후) ---
    def report_json(self, file_hash: str) -> dict[str, Any]:
        r = self._post("/api/v1/report_json", data={"hash": file_hash})
        return self._json(r, "report_json")

    # --- 편의: 한 방 (upload -> scan -> report) ---
    def analyze(self, file_path: str | Path) -> dict[str, Any]:
        up = self.upload(file_path)
        self.scan(up["hash"])
        report = self.report_json(up["hash"])
        report.setdefault("_upload", up)
        return report

    # --- 내부 ---
    def _post(self, path: str, **kw):
        try:
            return requests.post(self.url + path, headers=self._h, timeout=120, **kw)
        except requests.RequestException as e:
            raise MobsfError(path.strip("/").split("/")[-1], f"요청 실패: {e}") from e

    @staticmethod
    def _json(r, stage: str) -> dict[str, Any]:
        if r.status_code != 200:
            raise MobsfError(stage, r.text[:300], r.status_code)
        try:
            return r.json()
        except ValueError:
            raise MobsfError(stage, f"JSON 파싱 실패: {r.text[:200]}", r.status_code)
