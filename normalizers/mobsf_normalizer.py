"""MobSF report_json → Finding 리스트 (§8-3, §5).

해석 우선순위(§5): (1) mappings 테이블 → (2) MobSF metadata.masvs 폴백 → (3) unmapped 버킷.

정규화 대상 섹션(중복 롤업인 appsec 은 제외 — 아래 섹션들의 요약이라 과집계 방지):
  - code_analysis.findings      : 소스 코드 패턴 (rule id + files/lines + metadata)
  - manifest_analysis.manifest_findings : 매니페스트 (rule id)
  - certificate_analysis.certificate_findings : 서명/인증서
  - network_security.network_findings   : NSC(clear text 등)
"""
from __future__ import annotations

from typing import Any

from mappings.loader import lookup
from schema.findings import (
    AnalysisType,
    Confidence,
    Finding,
    Location,
    Severity,
    SourceTool,
    Target,
)

# MobSF severity 문자열 → 스키마 Severity
_SEV = {
    "high": Severity.high,
    "warning": Severity.medium,
    "medium": Severity.medium,
    "info": Severity.info,
    "secure": Severity.info,
    "hotspot": Severity.low,
    "good": Severity.info,
}


def _sev(s: str | None) -> Severity:
    return _SEV.get((s or "info").lower(), Severity.info)


def _masvs_from_metadata(meta: dict[str, Any]) -> tuple[list[str], list[str], str]:
    """MobSF metadata 폴백. masvs 는 'MSTG-...'(구) 또는 'MASVS-...' 형태."""
    masvs_raw = meta.get("masvs") or meta.get("owasp-masvs") or ""
    masvs = [masvs_raw] if masvs_raw else []
    # MASTG-TEST id 를 직접 주는 MobSF 버전 대응
    mastg_raw = meta.get("mastg") or ""
    mastg = [mastg_raw] if mastg_raw else []
    cat = masvs_raw.rsplit("-", 1)[0] if masvs_raw.startswith("MASVS") else ""
    return mastg, masvs, cat


def _resolve(rule_id: str, meta: dict[str, Any] | None = None) -> tuple[list[str], list[str], str]:
    """(mastg_ids, masvs_ids, category) — 테이블 우선, 없으면 metadata, 없으면 빈값(unmapped)."""
    m = lookup(rule_id)
    if m.mapped:
        return m.mastg_ids, m.masvs_ids, m.category
    if meta:
        return _masvs_from_metadata(meta)
    return [], [], ""


# appsec 섹션/키워드 → MASTG (iOS 경로용 best-effort; 없으면 unmapped 버킷)
_APPSEC_SECTION = {
    "network": (["MASTG-TEST-0070"], ["MASVS-NETWORK-1"], "MASVS-NETWORK"),
    "transport": (["MASTG-TEST-0070"], ["MASVS-NETWORK-1"], "MASVS-NETWORK"),
    "storage": (["MASTG-TEST-0052"], ["MASVS-STORAGE-1"], "MASVS-STORAGE"),
    "binary": (["MASTG-TEST-0085"], ["MASVS-RESILIENCE-1"], "MASVS-RESILIENCE"),
    "code": (["MASTG-TEST-0085"], ["MASVS-RESILIENCE-1"], "MASVS-RESILIENCE"),
}


def normalize_ios_appsec(report: dict[str, Any], sha256: str = "") -> list[Finding]:
    """iOS(IPA) 용 MobSF appsec 버킷 정규화 (code/manifest 는 android 전용이라 미사용).

    appsec 항목은 {title, description, section}. section 키워드로 best-effort 매핑,
    없으면 unmapped 버킷으로 분류(§8). LIEF 결과와 store 에서 합류한다.
    """
    appsec = report.get("appsec") or {}
    target = Target(
        platform="ios",
        package=report.get("bundle_id", "") or report.get("package_name", ""),
        sha256=report.get("sha256", "") or sha256,
    )
    sev_map = {"high": Severity.high, "warning": Severity.medium, "hotspot": Severity.low}
    out: list[Finding] = []
    for bucket, sev in sev_map.items():
        for item in appsec.get(bucket, []) or []:
            if not isinstance(item, dict):
                continue
            section = (item.get("section") or "").lower()
            mastg, masvs, cat = _APPSEC_SECTION.get(section, ([], [], ""))
            # 네트워크/전송 섹션은 Info.plist(ATS)로 정규화 → LIEF ATS 결과와 store 에서 합류.
            loc_file = "Info.plist" if section in ("network", "transport") else f"appsec/{section}"
            out.append(Finding(
                title=item.get("title", "")[:160],
                severity=sev,
                confidence=Confidence.firm if mastg else Confidence.tentative,
                category=cat, mastg_ids=mastg, masvs_ids=masvs,
                source_tool=SourceTool.mobsf, analysis_type=AnalysisType.static,
                target=target, location=Location(file=loc_file),
                evidence=item.get("description", "")[:300],
                description=item.get("description", ""),
                raw={"section": "appsec", "appsec_section": section, "orig": item},
            ))
    return out


def normalize(report: dict[str, Any]) -> list[Finding]:
    target = Target(
        platform="android" if report.get("app_type", "apk") != "ipa" else "ios",
        package=report.get("package_name", "") or report.get("bundle_id", ""),
        sha256=report.get("sha256", ""),
    )
    findings: list[Finding] = []

    # 정적 단독 → confidence 는 firm/tentative (§5). 매핑·metadata 있으면 firm, 아니면 tentative.
    def conf(mapped: bool) -> Confidence:
        return Confidence.firm if mapped else Confidence.tentative

    # --- 1) code_analysis.findings ---
    ca = (report.get("code_analysis") or {}).get("findings") or {}
    for rule_id, body in ca.items():
        if not isinstance(body, dict):
            continue
        meta = body.get("metadata", {}) or {}
        mastg, masvs, cat = _resolve(rule_id, meta)
        sev = _sev(meta.get("severity"))
        desc = meta.get("description", "")
        ref = meta.get("reference", "")
        files = body.get("files") or {}
        if files:
            for fpath, lines in files.items():
                first_line = 0
                if isinstance(lines, str) and lines:
                    try:
                        first_line = int(str(lines).split(",")[0])
                    except ValueError:
                        first_line = 0
                findings.append(Finding(
                    title=rule_id.replace("_", " ").strip().capitalize(),
                    severity=sev, confidence=conf(bool(mastg or masvs)),
                    category=cat, mastg_ids=mastg, masvs_ids=masvs,
                    source_tool=SourceTool.mobsf, analysis_type=AnalysisType.static,
                    target=target,
                    location=Location(file=fpath, line=first_line),
                    evidence=f"{fpath}:{lines}", description=desc,
                    recommendation=ref,
                    raw={"rule": rule_id, "section": "code_analysis", "metadata": meta},
                ))
        else:
            findings.append(Finding(
                title=rule_id.replace("_", " ").capitalize(),
                severity=sev, confidence=conf(bool(mastg or masvs)),
                category=cat, mastg_ids=mastg, masvs_ids=masvs,
                source_tool=SourceTool.mobsf, analysis_type=AnalysisType.static,
                target=target, description=desc, recommendation=ref,
                raw={"rule": rule_id, "section": "code_analysis", "metadata": meta},
            ))

    # --- 2) manifest_analysis.manifest_findings ---
    for m in (report.get("manifest_analysis") or {}).get("manifest_findings", []) or []:
        rule_id = m.get("rule", "")
        mastg, masvs, cat = _resolve(rule_id)
        comp = m.get("component", "") or ""
        if isinstance(comp, (list, tuple)):
            comp = ",".join(str(x) for x in comp)
        findings.append(Finding(
            title=m.get("title", rule_id)[:160],
            severity=_sev(m.get("severity")), confidence=conf(bool(mastg)),
            category=cat, mastg_ids=mastg, masvs_ids=masvs,
            source_tool=SourceTool.mobsf, analysis_type=AnalysisType.static,
            target=target,
            location=Location(file="AndroidManifest.xml", **{"class": comp}),
            evidence=m.get("name", "") or m.get("title", ""),
            description=m.get("description", ""),
            raw={"rule": rule_id, "section": "manifest_analysis", "orig": m},
        ))

    # --- 3) certificate_analysis.certificate_findings ([sev, desc, title]) ---
    for c in (report.get("certificate_analysis") or {}).get("certificate_findings", []) or []:
        if not isinstance(c, list) or len(c) < 3:
            continue
        sev_s, desc, title = c[0], c[1], c[2]
        # 제목 키워드 기반 rule 추정 (v1 signature → Janus)
        rule_id = "signed_with_v1" if "v1" in desc.lower() or "janus" in title.lower() else ""
        mastg, masvs, cat = _resolve(rule_id)
        if _sev(sev_s) == Severity.info and not mastg:
            continue  # 통과성 info(서명됨 등)는 스킵
        findings.append(Finding(
            title=title[:160], severity=_sev(sev_s), confidence=conf(bool(mastg)),
            category=cat, mastg_ids=mastg, masvs_ids=masvs,
            source_tool=SourceTool.mobsf, analysis_type=AnalysisType.static,
            target=target, location=Location(file="META-INF/"),
            evidence=desc, description=desc,
            raw={"rule": rule_id, "section": "certificate_analysis", "orig": c},
        ))

    # --- 4) network_security.network_findings ---
    for n in (report.get("network_security") or {}).get("network_findings", []) or []:
        sev_s = n.get("severity", "info")
        rule_id = "base_config_cleartext" if "clear" in str(n.get("description", "")).lower() else ""
        mastg, masvs, cat = _resolve(rule_id)
        findings.append(Finding(
            title=(n.get("title") or n.get("description", "network"))[:160],
            severity=_sev(sev_s), confidence=conf(bool(mastg)),
            category=cat, mastg_ids=mastg, masvs_ids=masvs,
            source_tool=SourceTool.mobsf, analysis_type=AnalysisType.static,
            target=target, location=Location(file="network_security_config.xml"),
            evidence=str(n.get("scope", "")), description=n.get("description", ""),
            raw={"rule": rule_id, "section": "network_security", "orig": n},
        ))

    return findings
