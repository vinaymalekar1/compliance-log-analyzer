"""One call that does the whole job: load -> analyze -> save to SQLite -> write Excel report."""
from pathlib import Path

from . import db
from .engine import analyze, load_logs
from .report import write_report


def run_analysis(source, source_name, db_path, report_dir):
    df = load_logs(source)
    result = analyze(df)
    db.init_db(db_path)
    run_id = db.save_run(db_path, source_name, result)
    report_path = write_report(result, Path(report_dir) / f"run_{run_id}.xlsx")
    return {
        "run_id": run_id,
        "source": source_name,
        "total_events": result.total_events,
        "total_findings": len(result.findings),
        "top_risk": result.risk.head(5).to_dict("records"),
        "report_path": str(report_path),
    }
