"""Five rule-based detections. Each rule takes a normalized DataFrame and returns Findings."""
from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class Thresholds:
    failed_login_count: int = 5        # failed logins ...
    failed_login_window_min: int = 10  # ... within this many minutes
    export_record_count: int = 1000    # exports at/above this many records are "bulk"
    multi_ip_count: int = 3            # distinct IPs ...
    multi_ip_window_min: int = 60      # ... within this many minutes
    off_hours_start: int = 22          # off hours = 22:00 to 06:00
    off_hours_end: int = 6


@dataclass
class Finding:
    rule: str
    user: str
    severity: str
    points: int
    timestamp: pd.Timestamp
    description: str


# rule name -> (severity, risk points added to the user's score)
RULE_META = {
    "failed_login_burst": ("HIGH", 30),
    "privilege_change": ("MEDIUM", 20),
    "bulk_export": ("HIGH", 25),
    "multi_ip_access": ("MEDIUM", 25),
    "off_hours_activity": ("LOW", 15),
}


def _finding(rule, user, ts, description):
    severity, points = RULE_META[rule]
    return Finding(rule, user, severity, points, ts, description)


def _sliding(times, window, accept):
    """Yield (start, end) index ranges where a window starting at `start` satisfies
    accept(start, end). After a hit, skip past the window so one burst = one finding."""
    i, n = 0, len(times)
    while i < n:
        j = i
        while j + 1 < n and times[j + 1] - times[i] <= window:
            j += 1
        if accept(i, j):
            yield i, j
            i = j + 1
        else:
            i += 1


def detect_failed_login_bursts(df, t):
    findings = []
    fails = df[(df["action"] == "LOGIN") & (df["status"] == "FAILURE")]
    window = pd.Timedelta(minutes=t.failed_login_window_min)
    for user, group in fails.groupby("user"):
        times = group["timestamp"].sort_values().tolist()
        for i, j in _sliding(times, window, lambda i, j: j - i + 1 >= t.failed_login_count):
            findings.append(_finding(
                "failed_login_burst", user, times[i],
                f"{j - i + 1} failed logins within {t.failed_login_window_min} minutes",
            ))
    return findings


def detect_privilege_changes(df, t):
    findings = []
    for row in df[df["action"] == "PRIVILEGE_CHANGE"].itertuples():
        detail = f": {row.details}" if row.details else ""
        findings.append(_finding(
            "privilege_change", row.user, row.timestamp,
            f"Privilege change by {row.user}{detail}",
        ))
    return findings


def detect_bulk_exports(df, t):
    findings = []
    bulk = df[(df["action"] == "EXPORT") & (df["record_count"] >= t.export_record_count)]
    for row in bulk.itertuples():
        findings.append(_finding(
            "bulk_export", row.user, row.timestamp,
            f"Exported {int(row.record_count):,} records (threshold {t.export_record_count:,})",
        ))
    return findings


def detect_multi_ip_access(df, t):
    findings = []
    ok = df[df["status"] == "SUCCESS"]
    window = pd.Timedelta(minutes=t.multi_ip_window_min)
    for user, group in ok.groupby("user"):
        group = group.sort_values("timestamp")
        times, ips = group["timestamp"].tolist(), group["ip_address"].tolist()
        accept = lambda i, j: len(set(ips[i:j + 1])) >= t.multi_ip_count
        for i, j in _sliding(times, window, accept):
            findings.append(_finding(
                "multi_ip_access", user, times[i],
                f"{len(set(ips[i:j + 1]))} distinct IPs within {t.multi_ip_window_min} minutes",
            ))
    return findings


def detect_off_hours_activity(df, t):
    findings = []
    ok = df[df["status"] == "SUCCESS"]
    hours = ok["timestamp"].dt.hour
    off = ok[(hours >= t.off_hours_start) | (hours < t.off_hours_end)]
    for user, group in off.groupby("user"):
        findings.append(_finding(
            "off_hours_activity", user, group["timestamp"].min(),
            f"{len(group)} successful action(s) between "
            f"{t.off_hours_start:02d}:00 and {t.off_hours_end:02d}:00",
        ))
    return findings


RULES = [
    detect_failed_login_bursts,
    detect_privilege_changes,
    detect_bulk_exports,
    detect_multi_ip_access,
    detect_off_hours_activity,
]
