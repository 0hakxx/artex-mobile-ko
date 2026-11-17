"""리포트 렌더러 (§11). findings store → MASTG·전자금융 두 리포트(HTML/Markdown).

리포트는 오직 store 만 읽는다(§5 계약). 심각도·MASVS 카테고리로 그룹핑·정렬만 담당
— 심각도/증거/권고는 finding 에 이미 들어있다.
"""
from __future__ import annotations

import html
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from schema.config import REPO_ROOT
from schema.findings import Finding
from store.jsonl_store import FindingsStore

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {
    "critical": "#7c1d1d", "high": "#b91c1c", "medium": "#b45309",
    "low": "#2563eb", "info": "#6b7280",
}


def _efinance() -> dict[str, Any]:
    p = REPO_ROOT / "report" / "efinance_mapping.yaml"
    return yaml.safe_load(p.read_text()) or {}


def _sev_key(f: Finding) -> int:
    v = f.severity.value if hasattr(f.severity, "value") else f.severity
    return _SEV_ORDER.index(v) if v in _SEV_ORDER else len(_SEV_ORDER)


def _val(x):
    return x.value if hasattr(x, "value") else x


# ---------------- 데이터 집계 ----------------
def summarize(findings: list[Finding]) -> dict[str, Any]:
    by_sev: dict[str, int] = defaultdict(int)
    by_cat: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_sev[_val(f.severity)] += 1
        cat = f.category or "UNMAPPED"
        by_cat[cat].append(f)
    return {
        "total": len(findings),
        "by_severity": dict(by_sev),
        "by_category": by_cat,
        "mapped": sum(1 for f in findings if f.is_mapped()),
        "unmapped": sum(1 for f in findings if not f.is_mapped()),
    }


# ---------------- HTML ----------------
def _finding_html(f: Finding) -> str:
    sev = _val(f.severity)
    loc = f.location
    locs = " / ".join(x for x in [loc.file, loc.class_, loc.method] if x) or "-"
    mastg = ", ".join(f.mastg_ids) or "<em>미매핑</em>"
    masvs = ", ".join(f.masvs_ids) or "-"
    merged = f.raw.get("merged_from")
    merged_badge = (f"<span class='tool'>+{html.escape(','.join(merged))}</span>"
                    if merged and len(merged) > 1 else
                    f"<span class='tool'>{html.escape(_val(f.source_tool))}:{_val(f.analysis_type)}</span>")
    return f"""
    <div class="finding sev-{sev}">
      <div class="fhead">
        <span class="badge" style="background:{_SEV_COLOR.get(sev,'#666')}">{sev.upper()}</span>
        <span class="title">{html.escape(f.title)}</span>
        {merged_badge}
        <span class="conf">{_val(f.confidence)}</span>
      </div>
      <div class="meta">MASTG: <b>{mastg}</b> &nbsp;·&nbsp; MASVS: {html.escape(masvs)} &nbsp;·&nbsp; 위치: <code>{html.escape(locs)}</code></div>
      {f'<div class="desc">{html.escape(f.description)}</div>' if f.description else ''}
      {f'<pre class="evidence">{html.escape(f.evidence[:600])}</pre>' if f.evidence else ''}
      {f'<div class="rec">권고: {html.escape(f.recommendation)}</div>' if f.recommendation else ''}
    </div>"""


_CSS = """
body{font-family:-apple-system,Segoe UI,Roboto,'Malgun Gothic',sans-serif;margin:0;background:#0f172a;color:#e2e8f0}
.wrap{max-width:960px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 4px} h2{font-size:17px;border-bottom:1px solid #334155;padding-bottom:6px;margin-top:28px}
.sub{color:#94a3b8;font-size:13px;margin-bottom:16px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}
.card{background:#1e293b;border-radius:8px;padding:10px 14px;min-width:90px}
.card .n{font-size:22px;font-weight:700} .card .l{font-size:11px;color:#94a3b8;text-transform:uppercase}
.finding{background:#1e293b;border-left:4px solid #475569;border-radius:6px;padding:12px 14px;margin:10px 0}
.finding.sev-critical,.finding.sev-high{border-left-color:#b91c1c}
.finding.sev-medium{border-left-color:#b45309}
.fhead{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.badge{color:#fff;font-size:10px;font-weight:700;padding:2px 7px;border-radius:10px}
.title{font-weight:600;flex:1;min-width:200px}
.tool{font-size:10px;background:#334155;padding:2px 6px;border-radius:4px;color:#cbd5e1}
.conf{font-size:10px;color:#64748b}
.meta{font-size:12px;color:#cbd5e1;margin:6px 0}
code{background:#0f172a;padding:1px 5px;border-radius:3px;font-size:11px}
.desc{font-size:13px;color:#cbd5e1;margin:4px 0}
.evidence{background:#0f172a;padding:8px;border-radius:4px;font-size:11px;overflow:auto;max-height:160px;color:#94a3b8}
.rec{font-size:12px;color:#86efac;margin-top:4px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #334155;padding:6px 8px;text-align:left} th{background:#1e293b}
.note{color:#fbbf24;font-size:12px;margin:8px 0}
a.dl{color:#60a5fa}
"""


def render_mastg_html(findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
    s = summarize(findings)
    meta = meta or {}
    cards = "".join(
        f'<div class="card"><div class="n" style="color:{_SEV_COLOR.get(k,"#999")}">{s["by_severity"].get(k,0)}</div>'
        f'<div class="l">{k}</div></div>' for k in _SEV_ORDER
    )
    cards += f'<div class="card"><div class="n">{s["mapped"]}</div><div class="l">mapped</div></div>'
    cards += f'<div class="card"><div class="n">{s["unmapped"]}</div><div class="l">unmapped</div></div>'

    sections = []
    for cat in sorted(s["by_category"].keys()):
        fs = sorted(s["by_category"][cat], key=_sev_key)
        body = "".join(_finding_html(f) for f in fs)
        sections.append(f"<h2>{html.escape(cat)} <span class='sub'>({len(fs)})</span></h2>{body}")

    title = meta.get("package") or meta.get("target") or "Mobile ARTEX"
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>MASTG 리포트 — {html.escape(str(title))}</title>
<style>{_CSS}</style></head><body><div class="wrap">
<h1>MASTG / MASVS 리포트</h1>
<div class="sub">대상: {html.escape(str(title))} · platform={html.escape(str(meta.get('platform','-')))} · sha256={html.escape(str(meta.get('sha256',''))[:16])} · 총 {s['total']}건</div>
<div class="cards">{cards}</div>
{''.join(sections) if sections else '<p>findings 없음</p>'}
</div></body></html>"""


def render_efinance_html(findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
    emap = _efinance()
    meta = meta or {}
    by_cat: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_cat[f.category or "UNMAPPED"].append(f)

    rows = []
    for cat in sorted(by_cat.keys()):
        fs = sorted(by_cat[cat], key=_sev_key)
        em = emap.get(cat, emap.get("UNMAPPED", {}))
        arts = "<br>".join(html.escape(a) for a in em.get("articles", []))
        high = sum(1 for f in fs if _val(f.severity) in ("critical", "high"))
        rows.append(f"<tr><td><b>{html.escape(cat)}</b></td><td>{len(fs)} (고위험 {high})</td>"
                    f"<td>{arts}</td><td>{html.escape(em.get('note',''))}</td></tr>")

    title = meta.get("package") or meta.get("target") or "Mobile ARTEX"
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>전자금융 매핑 리포트 — {html.escape(str(title))}</title>
<style>{_CSS}</style></head><body><div class="wrap">
<h1>전자금융감독규정 매핑 리포트</h1>
<div class="sub">대상: {html.escape(str(title))} · 총 {len(findings)}건</div>
<div class="note">⚠ 조문 매핑은 참고용이다. 제출 전 최신 전자금융감독규정 원문으로 재확인할 것.</div>
<table><tr><th>MASVS 카테고리</th><th>발견 건수</th><th>전자금융 관련 조항(참고)</th><th>설명</th></tr>
{''.join(rows)}</table>
</div></body></html>"""


def render_markdown(findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
    s = summarize(findings)
    meta = meta or {}
    lines = [f"# Mobile ARTEX 리포트 — {meta.get('package') or meta.get('target','')}",
             f"- platform: {meta.get('platform','-')} / sha256: {str(meta.get('sha256',''))[:16]}",
             f"- 총 {s['total']}건 (mapped {s['mapped']}, unmapped {s['unmapped']})",
             "- 심각도: " + ", ".join(f"{k}={s['by_severity'].get(k,0)}" for k in _SEV_ORDER), ""]
    for cat in sorted(s["by_category"].keys()):
        lines.append(f"## {cat} ({len(s['by_category'][cat])})")
        for f in sorted(s["by_category"][cat], key=_sev_key):
            loc = f.location
            locs = "/".join(x for x in [loc.file, loc.class_, loc.method] if x) or "-"
            lines.append(f"- **[{_val(f.severity).upper()}]** {f.title} "
                         f"(`{', '.join(f.mastg_ids) or '미매핑'}`) — `{locs}`")
        lines.append("")
    return "\n".join(lines)


def render_all(store: FindingsStore | None = None, out_dir: str | Path | None = None,
               meta: dict[str, Any] | None = None) -> dict[str, str]:
    store = store or FindingsStore()
    findings = store.all()
    out = Path(out_dir) if out_dir else (REPO_ROOT / "report" / "out")
    out.mkdir(parents=True, exist_ok=True)
    paths = {
        "mastg_html": out / "report_mastg.html",
        "efinance_html": out / "report_efinance.html",
        "markdown": out / "report.md",
        "findings_json": out / "findings.json",
    }
    paths["mastg_html"].write_text(render_mastg_html(findings, meta), encoding="utf-8")
    paths["efinance_html"].write_text(render_efinance_html(findings, meta), encoding="utf-8")
    paths["markdown"].write_text(render_markdown(findings, meta), encoding="utf-8")
    paths["findings_json"].write_text(
        json.dumps([f.model_dump(by_alias=True, mode="json") for f in findings],
                   ensure_ascii=False, indent=2), encoding="utf-8")
    return {k: str(v) for k, v in paths.items()}


if __name__ == "__main__":
    import sys
    md = {"target": sys.argv[1]} if len(sys.argv) > 1 else {}
    print(json.dumps(render_all(meta=md), ensure_ascii=False, indent=2))
