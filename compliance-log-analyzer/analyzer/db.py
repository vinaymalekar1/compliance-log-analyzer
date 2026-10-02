"""SQLite persistence: every run is stored as an audit trail."""
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    total_events INTEGER NOT NULL,
    total_findings INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    rule TEXT, user TEXT, severity TEXT, points INTEGER,
    timestamp TEXT, description TEXT
);
CREATE TABLE IF NOT EXISTS user_risk (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    user TEXT, risk_score INTEGER, risk_level TEXT, findings INTEGER, events INTEGER
);
"""


def _connect(path):
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path):
    with closing(_connect(path)) as conn, conn:
        conn.executescript(SCHEMA)


def save_run(path, source, result):
    created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with closing(_connect(path)) as conn, conn:
        cur = conn.execute(
            "INSERT INTO runs (source, created_at, total_events, total_findings) VALUES (?,?,?,?)",
            (source, created, result.total_events, len(result.findings)),
        )
        run_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO findings (run_id, rule, user, severity, points, timestamp, description) "
            "VALUES (?,?,?,?,?,?,?)",
            [(run_id, r.rule, r.user, r.severity, int(r.points), r.timestamp, r.description)
             for r in result.findings.itertuples()],
        )
        conn.executemany(
            "INSERT INTO user_risk (run_id, user, risk_score, risk_level, findings, events) "
            "VALUES (?,?,?,?,?,?)",
            [(run_id, r.user, int(r.risk_score), r.risk_level, int(r.findings), int(r.events))
             for r in result.risk.itertuples()],
        )
    return run_id


def list_runs(path):
    with closing(_connect(path)) as conn:
        rows = conn.execute("SELECT * FROM runs ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def get_run(path, run_id):
    with closing(_connect(path)) as conn:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    return dict(row) if row else None


def get_findings(path, run_id, user=None, rule=None, severity=None):
    sql = "SELECT rule, user, severity, points, timestamp, description FROM findings WHERE run_id = ?"
    args = [run_id]
    for column, value in (("user", user), ("rule", rule), ("severity", severity)):
        if value:
            sql += f" AND {column} = ?"
            args.append(value.upper() if column == "severity" else value)
    sql += " ORDER BY points DESC, timestamp ASC"
    with closing(_connect(path)) as conn:
        return [dict(r) for r in conn.execute(sql, args).fetchall()]


def get_risk(path, run_id):
    with closing(_connect(path)) as conn:
        rows = conn.execute(
            "SELECT user, risk_score, risk_level, findings, events FROM user_risk "
            "WHERE run_id = ? ORDER BY risk_score DESC, user ASC", (run_id,)
        ).fetchall()
    return [dict(r) for r in rows]
