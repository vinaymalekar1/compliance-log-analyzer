"""Load audit-log CSVs, run the rules and compute per-user risk scores."""
from dataclasses import dataclass

import pandas as pd

from .rules import RULES, Thresholds

REQUIRED_COLUMNS = ["timestamp", "user", "action", "ip_address", "status"]
FINDING_COLUMNS = ["rule", "user", "severity", "points", "timestamp", "description"]
RISK_COLUMNS = ["user", "risk_score", "risk_level", "findings", "events"]
MAX_SCORE = 100


@dataclass
class AnalysisResult:
    findings: pd.DataFrame
    risk: pd.DataFrame
    total_events: int


def normalize(df):
    """Validate columns and clean types. Optional columns: record_count, details."""
    df = df.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required column(s): {', '.join(missing)}")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp", "user"])
    for col in ("user", "ip_address"):
        df[col] = df[col].astype(str).str.strip()
    for col in ("action", "status"):
        df[col] = df[col].astype(str).str.strip().str.upper()

    if "record_count" in df.columns:
        df["record_count"] = pd.to_numeric(df["record_count"], errors="coerce").fillna(0)
    else:
        df["record_count"] = 0
    if "details" not in df.columns:
        df["details"] = ""
    df["details"] = df["details"].fillna("").astype(str)
    return df.sort_values("timestamp").reset_index(drop=True)


def load_logs(source):
    """Read a CSV (path or file-like object) and normalize it."""
    try:
        raw = pd.read_csv(source)
    except pd.errors.EmptyDataError:
        raise ValueError("The CSV file is empty")
    return normalize(raw)


def risk_level(score):
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def score_users(df, findings):
    points, counts = {}, {}
    for f in findings:
        points[f.user] = points.get(f.user, 0) + f.points
        counts[f.user] = counts.get(f.user, 0) + 1
    rows = []
    for user, events in df.groupby("user").size().items():
        score = min(MAX_SCORE, points.get(user, 0))
        rows.append({
            "user": user,
            "risk_score": score,
            "risk_level": risk_level(score),
            "findings": counts.get(user, 0),
            "events": int(events),
        })
    out = pd.DataFrame(rows, columns=RISK_COLUMNS)
    return out.sort_values(["risk_score", "user"], ascending=[False, True]).reset_index(drop=True)


def analyze(df, thresholds=None):
    t = thresholds or Thresholds()
    findings = []
    for rule in RULES:
        findings.extend(rule(df, t))

    findings_df = pd.DataFrame(
        [{
            "rule": f.rule, "user": f.user, "severity": f.severity, "points": f.points,
            "timestamp": f.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "description": f.description,
        } for f in findings],
        columns=FINDING_COLUMNS,
    )
    findings_df = findings_df.sort_values(
        ["points", "timestamp"], ascending=[False, True]
    ).reset_index(drop=True)
    return AnalysisResult(findings_df, score_users(df, findings), len(df))
