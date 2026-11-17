"""Mobile ARTEX 웹 UI (§15 폴백: findings store/리포트 위 얇은 웹 뷰).

APK/IPA 업로드 → 잡 생성 → 정적 파이프라인 실행(백그라운드) → 진행 상태/리포트 열람.
UI 는 findings store 와 리포트만 읽는다(§5 계약). 백엔드 내부에 의존하지 않음.

기존 ARTEX 가 닫혀도 이 레포만으로 구동되도록 자체 완결(self-contained).
"""
from __future__ import annotations

import sys
import threading
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, UploadFile, File, HTTPException  # noqa: E402
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse  # noqa: E402

from pipeline.static_pipeline import run_static  # noqa: E402
from store.jsonl_store import FindingsStore  # noqa: E402
from report import render  # noqa: E402

app = FastAPI(title="Mobile ARTEX")

UPLOADS = ROOT / "store" / "uploads"
JOBS_DIR = ROOT / "store" / "jobs"
UPLOADS.mkdir(parents=True, exist_ok=True)
JOBS_DIR.mkdir(parents=True, exist_ok=True)

# 잡 상태 (메모리 + 디스크 store). 1인용 단순 구조.
JOBS: dict[str, dict] = {}


def _run_job(job_id: str, apk_path: Path):
    job = JOBS[job_id]
    try:
        job["status"] = "running"
        job["stage"] = "정적 분석(MobSF/apkid/LIEF) 실행 중..."
        store = FindingsStore(JOBS_DIR / job_id / "findings.jsonl")
        res = run_static(apk_path, store=store, fresh=True)
        meta = {"target": apk_path.name, "platform": res.platform, "sha256": res.sha256,
                "package": next((t for t in []), "")}
        # package 추출(첫 finding 에서)
        allf = store.all()
        if allf:
            meta["package"] = allf[0].target.package
        job["stage"] = "리포트 생성 중..."
        paths = render.render_all(store=store, out_dir=JOBS_DIR / job_id / "report", meta=meta)
        job["result"] = {
            "platform": res.platform, "sha256": res.sha256,
            "tools": [{"tool": t.tool, "ok": t.ok, "added": t.added, "error": t.error}
                      for t in res.tool_results],
            "total": res.total_findings, "mapped": res.mapped, "unmapped": res.unmapped,
            "by_severity": render.summarize(allf)["by_severity"],
        }
        job["report_paths"] = paths
        job["status"] = "done"
        job["stage"] = "완료"
    except Exception as e:  # noqa: BLE001
        job["status"] = "error"
        job["stage"] = f"실패: {e}"
        job["error"] = str(e)


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML


@app.post("/scan")
async def scan(file: UploadFile = File(...)):
    name = (file.filename or "upload.apk")
    if not name.lower().endswith((".apk", ".ipa")):
        raise HTTPException(400, "APK 또는 IPA 파일만 업로드 가능")
    job_id = uuid.uuid4().hex[:12]
    dest = UPLOADS / f"{job_id}_{name}"
    with dest.open("wb") as fh:
        while chunk := await file.read(1 << 20):
            fh.write(chunk)
    JOBS[job_id] = {"id": job_id, "file": name, "status": "queued", "stage": "대기 중"}
    threading.Thread(target=_run_job, args=(job_id, dest), daemon=True).start()
    return {"job_id": job_id}


@app.get("/jobs/{job_id}")
def job_status(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "잡 없음")
    return JSONResponse({k: v for k, v in job.items() if k != "report_paths"})


@app.get("/jobs/{job_id}/report/{kind}", response_class=HTMLResponse)
def job_report(job_id: str, kind: str):
    job = JOBS.get(job_id)
    if not job or job.get("status") != "done":
        raise HTTPException(404, "리포트 준비 안 됨")
    key = {"mastg": "mastg_html", "efinance": "efinance_html"}.get(kind)
    if not key:
        raise HTTPException(404, "알 수 없는 리포트 종류")
    return FileResponse(job["report_paths"][key], media_type="text/html")


@app.get("/jobs/{job_id}/download/{kind}")
def job_download(job_id: str, kind: str):
    job = JOBS.get(job_id)
    if not job or job.get("status") != "done":
        raise HTTPException(404, "준비 안 됨")
    key = {"md": "markdown", "json": "findings_json",
           "mastg": "mastg_html", "efinance": "efinance_html"}.get(kind)
    if not key:
        raise HTTPException(404, "알 수 없음")
    p = job["report_paths"][key]
    return FileResponse(p, filename=Path(p).name)


INDEX_HTML = """<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Mobile ARTEX</title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,'Malgun Gothic',sans-serif;background:#0f172a;color:#e2e8f0;margin:0}
.wrap{max-width:760px;margin:0 auto;padding:32px 20px}
h1{font-size:24px;margin:0 0 4px} .sub{color:#94a3b8;font-size:13px;margin-bottom:24px}
.drop{border:2px dashed #475569;border-radius:12px;padding:40px;text-align:center;background:#1e293b;cursor:pointer;transition:.2s}
.drop:hover,.drop.over{border-color:#60a5fa;background:#233247}
.drop input{display:none}
.btn{background:#2563eb;color:#fff;border:0;padding:10px 20px;border-radius:8px;font-size:14px;cursor:pointer}
.btn:disabled{opacity:.5}
#status{margin-top:24px}
.card{background:#1e293b;border-radius:10px;padding:16px 18px;margin-top:14px}
.stage{color:#fbbf24;font-size:14px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}
.mini{background:#0f172a;border-radius:8px;padding:8px 12px;min-width:70px}
.mini .n{font-size:20px;font-weight:700} .mini .l{font-size:10px;color:#94a3b8;text-transform:uppercase}
a.rep{display:inline-block;margin:6px 8px 0 0;color:#60a5fa;text-decoration:none;border:1px solid #334155;padding:6px 12px;border-radius:6px}
a.rep:hover{background:#233247}
.tool{font-size:12px;color:#cbd5e1} .err{color:#f87171}
.spin{display:inline-block;width:14px;height:14px;border:2px solid #475569;border-top-color:#60a5fa;border-radius:50%;animation:s .8s linear infinite;vertical-align:middle}
@keyframes s{to{transform:rotate(360deg)}}
</style></head><body><div class="wrap">
<h1>📱 Mobile ARTEX</h1>
<div class="sub">APK/IPA 업로드 → 자동 정적 분석(MobSF·apkid·LIEF) → MASTG/전자금융 리포트</div>
<label class="drop" id="drop">
  <input type="file" id="file" accept=".apk,.ipa">
  <div id="dropmsg">APK/IPA 를 끌어다 놓거나 클릭해 선택</div>
</label>
<div style="margin-top:14px"><button class="btn" id="go" disabled>분석 시작</button></div>
<div id="status"></div>
<script>
const drop=document.getElementById('drop'),file=document.getElementById('file'),
  go=document.getElementById('go'),msg=document.getElementById('dropmsg'),st=document.getElementById('status');
let chosen=null;
file.onchange=()=>{chosen=file.files[0];if(chosen){msg.textContent='선택됨: '+chosen.name;go.disabled=false;}};
['dragover','dragenter'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.add('over');}));
['dragleave','drop'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.remove('over');}));
drop.addEventListener('drop',ev=>{chosen=ev.dataTransfer.files[0];file.files=ev.dataTransfer.files;if(chosen){msg.textContent='선택됨: '+chosen.name;go.disabled=false;}});
go.onclick=async()=>{
  if(!chosen)return; go.disabled=true;
  const fd=new FormData();fd.append('file',chosen);
  st.innerHTML='<div class="card"><span class="spin"></span> 업로드 중...</div>';
  const r=await fetch('/scan',{method:'POST',body:fd});
  if(!r.ok){st.innerHTML='<div class="card err">업로드 실패: '+(await r.text())+'</div>';go.disabled=false;return;}
  const {job_id}=await r.json(); poll(job_id);
};
async function poll(id){
  const r=await fetch('/jobs/'+id); const j=await r.json();
  if(j.status==='done'){render(id,j);return;}
  if(j.status==='error'){st.innerHTML='<div class="card err">❌ '+j.stage+'</div>';go.disabled=false;return;}
  st.innerHTML='<div class="card"><span class="spin"></span> <span class="stage">'+j.stage+'</span><div class="sub">status: '+j.status+' (수 분 소요 — MobSF 스캔)</div></div>';
  setTimeout(()=>poll(id),2500);
}
function render(id,j){
  const res=j.result, sev=res.by_severity||{};
  const order=['critical','high','medium','low','info'];
  let cards=order.map(k=>`<div class="mini"><div class="n">${sev[k]||0}</div><div class="l">${k}</div></div>`).join('');
  cards+=`<div class="mini"><div class="n">${res.total}</div><div class="l">total</div></div>`;
  cards+=`<div class="mini"><div class="n">${res.unmapped}</div><div class="l">unmapped</div></div>`;
  let tools=res.tools.map(t=>t.ok?`<span class="tool">✓ ${t.tool} (+${(t.added&&t.added.new)||0})</span>`:`<span class="err">✗ ${t.tool}: ${t.error}</span>`).join(' · ');
  st.innerHTML=`<div class="card">
    <div style="font-size:15px;font-weight:600">✅ 분석 완료 — ${res.platform} · ${res.sha256.slice(0,16)}</div>
    <div class="cards">${cards}</div>
    <div class="tool">${tools}</div>
    <div style="margin-top:12px">
      <a class="rep" href="/jobs/${id}/report/mastg" target="_blank">📄 MASTG 리포트</a>
      <a class="rep" href="/jobs/${id}/report/efinance" target="_blank">🏦 전자금융 리포트</a>
      <a class="rep" href="/jobs/${id}/download/md">⬇ Markdown</a>
      <a class="rep" href="/jobs/${id}/download/json">⬇ findings JSON</a>
    </div></div>`;
  go.disabled=false;
}
</script></div></body></html>"""
