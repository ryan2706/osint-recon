from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional
import uuid
import os
import io
import pandas as pd
from scanner import Scanner

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan results
# In production, use a database (Redis/Postgres)
SCAN_RESULTS: Dict[str, Dict[str, Any]] = {}

class ScanRequest(BaseModel):
    domain: str

def run_scan_task(scan_id: str, domain: str):
    scanner = Scanner()
    SCAN_RESULTS[scan_id]["status"] = "running"
    try:
        results = scanner.scan_domain(domain)
        SCAN_RESULTS[scan_id]["status"] = "completed"
        SCAN_RESULTS[scan_id]["data"] = results
    except Exception as e:
        SCAN_RESULTS[scan_id]["status"] = "failed"
        SCAN_RESULTS[scan_id]["error"] = str(e)

@app.post("/scan")
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    SCAN_RESULTS[scan_id] = {
        "status": "pending",
        "domain": request.domain,
        "data": None
    }
    background_tasks.add_task(run_scan_task, scan_id, request.domain)
    return {"scan_id": scan_id}

@app.get("/scan/{scan_id}")
def get_scan_result(scan_id: str):
    if scan_id not in SCAN_RESULTS:
        raise HTTPException(status_code=404, detail="Scan not found")
    return SCAN_RESULTS[scan_id]

@app.get("/export/{scan_id}")
def export_scan_result(scan_id: str):
    if scan_id not in SCAN_RESULTS:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = SCAN_RESULTS[scan_id]
    if scan_data["status"] != "completed" or not scan_data["data"]:
         raise HTTPException(status_code=400, detail="Scan not completed yet")
    
    data = scan_data["data"]
    
    # 1. Summary Data
    summary_data = {
        "Metric": ["Domain", "Subdomains Found", "Live Hosts", "Vulnerabilities Found"],
        "Value": [
            scan_data["domain"],
            len(data.get("subdomains", [])),
            len(data.get("live_hosts", [])),
            len(data.get("vulnerabilities", []))
        ]
    }
    df_summary = pd.DataFrame(summary_data)
    
    # 2. Subdomains Data
    df_subdomains = pd.DataFrame(data.get("subdomains", []), columns=["Subdomain"])
    
    # 3. HTTPX Data
    # Flatten the dict structure for DataFrame
    httpx_rows = []
    for host in data.get("live_hosts", []):
         httpx_rows.append({
             "URL": host.get("url"),
             "Status Code": host.get("status_code"),
             "Title": host.get("title"),
             "Webserver": host.get("webserver"),
             "Tech": ", ".join(host.get("tech", [])) if host.get("tech") else "",
             "Host": host.get("host"),
             "Port": host.get("port")
         })
    df_httpx = pd.DataFrame(httpx_rows)
    
    # 4. Nuclei Data
    nuclei_rows = []
    for vuln in data.get("vulnerabilities", []):
        info = vuln.get("info", {})
        classification = info.get("classification", {})
        nuclei_rows.append({
            "Name": info.get("name", vuln.get("template_id")),
            "Severity": info.get("severity"),
            "Matched At": vuln.get("matched_at"),
            "Host": vuln.get("host"),
            "Type": vuln.get("type"),
            "Matcher Name": vuln.get("matcher_name"),
            "Extracted Results": ", ".join(vuln.get("extracted_results", [])) if isinstance(vuln.get("extracted_results"), list) else vuln.get("extracted_results"),
            "CVE ID": classification.get("cve_id"),
            "CVSS Score": classification.get("cvss_score"),
            "Description": info.get("description")
        })
    df_nuclei = pd.DataFrame(nuclei_rows)
    
    # Create Excel file in memory
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df_summary.to_excel(writer, sheet_name='Summary', index=False)
        df_subdomains.to_excel(writer, sheet_name='Subfinder', index=False)
        df_httpx.to_excel(writer, sheet_name='HTTPX', index=False)
        df_nuclei.to_excel(writer, sheet_name='Nuclei', index=False)
    
    output.seek(0)
    
    headers = {
        'Content-Disposition': f'attachment; filename="scan_results_{scan_data["domain"]}.xlsx"'
    }
    }
    return StreamingResponse(output, headers=headers, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

# Serve static files (production mode)
# In local dev, we use Vite proxy. In docker, we serve from dist.
if os.path.exists("../frontend/dist"):
    app.mount("/assets", StaticFiles(directory="../frontend/dist/assets"), name="assets")

    @app.get("/")
    async def read_root():
        return FileResponse("../frontend/dist/index.html")
else:
    @app.get("/")
    def read_root():
        return {"message": "OSINT API is running (Frontend not built)"}
