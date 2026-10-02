"""FastAPI service: upload, findings, risk ranking, report download. Optional API-key auth."""
import io
import os
import secrets
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse

from . import db
from .pipeline import run_analysis

XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def create_app(db_path=None, report_dir=None, api_key=None):
    db_path = str(db_path or os.getenv("COMPLIANCE_DB", "compliance.db"))
    report_dir = Path(report_dir or os.getenv("REPORT_DIR", "reports"))
    key = api_key if api_key is not None else os.getenv("API_KEY", "")
    db.init_db(db_path)
    report_dir.mkdir(parents=True, exist_ok=True)

    app = FastAPI(title="Compliance Log Analyzer", version="1.0.0")

    def require_key(x_api_key: Optional[str] = Header(default=None)):
        if key and not (x_api_key and secrets.compare_digest(x_api_key.encode(), key.encode())):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

    auth = [Depends(require_key)]

    def get_run_or_404(run_id):
        run = db.get_run(db_path, run_id)
        if not run:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
        return run

    @app.get("/health")
    def health():
        return {"status": "ok", "auth_required": bool(key)}

    @app.post("/upload", dependencies=auth)
    async def upload(file: UploadFile = File(...)):
        if not (file.filename or "").lower().endswith(".csv"):
            raise HTTPException(status_code=400, detail="Please upload a .csv file")
        content = await file.read()
        try:
            return run_analysis(io.BytesIO(content), file.filename, db_path, report_dir)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/runs", dependencies=auth)
    def runs():
        return db.list_runs(db_path)

    @app.get("/runs/{run_id}/findings", dependencies=auth)
    def findings(run_id: int, user: Optional[str] = None, rule: Optional[str] = None,
                 severity: Optional[str] = None):
        get_run_or_404(run_id)
        return db.get_findings(db_path, run_id, user, rule, severity)

    @app.get("/runs/{run_id}/risk", dependencies=auth)
    def risk(run_id: int):
        get_run_or_404(run_id)
        return db.get_risk(db_path, run_id)

    @app.get("/runs/{run_id}/report", dependencies=auth)
    def report(run_id: int):
        get_run_or_404(run_id)
        path = report_dir / f"run_{run_id}.xlsx"
        if not path.exists():
            raise HTTPException(status_code=404, detail="Report file not found")
        return FileResponse(path, media_type=XLSX, filename=f"risk_report_run_{run_id}.xlsx")

    return app
