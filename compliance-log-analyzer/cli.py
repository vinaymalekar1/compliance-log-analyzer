"""Batch CLI: analyze one CSV or a whole folder of CSVs.

Examples:
    python cli.py sample_data/audit_log.csv
    python cli.py logs/ --out reports --db compliance.db
"""
import argparse
import sys
from pathlib import Path

from analyzer.pipeline import run_analysis


def collect_files(path):
    p = Path(path)
    if p.is_dir():
        return sorted(p.glob("*.csv"))
    if p.is_file():
        return [p]
    raise FileNotFoundError(f"Path not found: {path}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compliance Log Analyzer (batch mode)")
    parser.add_argument("path", help="CSV file, or a folder containing CSV files")
    parser.add_argument("--out", default="reports", help="folder for Excel reports (default: reports)")
    parser.add_argument("--db", default="compliance.db", help="SQLite audit-trail file")
    args = parser.parse_args(argv)

    try:
        files = collect_files(args.path)
    except FileNotFoundError as exc:
        print(f"Error: {exc}")
        return 1
    if not files:
        print("No .csv files found.")
        return 1

    failures = 0
    for f in files:
        try:
            s = run_analysis(str(f), f.name, args.db, args.out)
        except ValueError as exc:
            print(f"[FAILED] {f.name}: {exc}")
            failures += 1
            continue
        print(f"\n{f.name}: {s['total_events']} events, {s['total_findings']} findings "
              f"(run #{s['run_id']})")
        for r in s["top_risk"][:3]:
            print(f"  {r['user']:<10} score {r['risk_score']:>3}  {r['risk_level']}")
        print(f"  Report: {s['report_path']}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
