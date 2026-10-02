# 🛡️ Compliance Log Analyzer

Ingests audit/access-log CSVs, applies five rule-based detections and produces per-user
risk scores, Excel reports for compliance reviewers and a FastAPI service with an
SQLite audit trail of every run.

## Features
- **Five detections:** failed-login bursts, privilege changes, bulk exports, multi-IP access, off-hours activity
- **Per-user risk score** (0-100, capped) with HIGH / MEDIUM / LOW levels
- **Batch CLI:** analyze one CSV or a whole folder
- **Excel reports** with `User Risk` and `Findings` sheets (colour-coded)
- **FastAPI service:** upload, findings, risk ranking, report download
- **Optional API-key access control** via the `X-API-Key` header
- **SQLite audit trail:** every run, finding and score is stored
- **11 pytest tests** covering rules, edge cases and API behaviour

## Tech Stack
Python, pandas, FastAPI, SQLite, openpyxl, pytest

## Setup
```bash
git clone https://github.com/vinaymalekar1/compliance-log-analyzer.git
cd compliance-log-analyzer
python -m venv venv
venv\Scripts\activate          # Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### CLI (batch mode)
```bash
python cli.py sample_data/audit_log.csv      # one file
python cli.py logs/                          # every .csv in a folder
python cli.py logs/ --out reports --db compliance.db
```

### API
```bash
uvicorn main:app --reload
```
Interactive docs: http://127.0.0.1:8000/docs

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Health check (no key needed) |
| POST | `/upload` | Upload a CSV and run the analysis |
| GET | `/runs` | List past runs |
| GET | `/runs/{id}/findings` | Findings (filters: `user`, `rule`, `severity`) |
| GET | `/runs/{id}/risk` | Users ranked by risk score |
| GET | `/runs/{id}/report` | Download the Excel report |

To require an API key, set it before starting the server and send it as a header:
```bash
set API_KEY=mysecret            # Mac/Linux: export API_KEY=mysecret
uvicorn main:app --reload
curl -H "X-API-Key: mysecret" http://127.0.0.1:8000/runs
```

## Input Format
Required columns: `timestamp, user, action, ip_address, status`
Optional columns: `record_count` (used by the bulk-export rule), `details`

| Column | Example |
|---|---|
| timestamp | 2026-03-03 09:00:00 |
| action | LOGIN, VIEW, UPDATE, EXPORT, PRIVILEGE_CHANGE |
| status | SUCCESS or FAILURE |

## Detection Rules
| Rule | Trigger (default) | Severity | Points |
|---|---|---|---|
| failed_login_burst | 5+ failed logins within 10 min | HIGH | 30 |
| privilege_change | any PRIVILEGE_CHANGE action | MEDIUM | 20 each |
| bulk_export | EXPORT with 1,000+ records | HIGH | 25 each |
| multi_ip_access | 3+ distinct IPs within 60 min | MEDIUM | 25 |
| off_hours_activity | successful activity 22:00-06:00 | LOW | 15 |

Risk levels: 70+ HIGH, 40-69 MEDIUM, below 40 LOW. Thresholds can be changed in `analyzer/rules.py`.

## Tests
```bash
python -m pytest
```

## Project Structure
```
compliance-log-analyzer/
├── analyzer/
│   ├── rules.py      # five detection rules
│   ├── engine.py     # load/clean CSV, run rules, score users
│   ├── report.py     # Excel report
│   ├── db.py         # SQLite audit trail
│   ├── pipeline.py   # load -> analyze -> save -> report
│   └── api.py        # FastAPI app
├── cli.py            # batch CLI
├── main.py           # uvicorn entry point
├── sample_data/audit_log.csv
└── tests/test_analyzer.py
```

## Screenshots
_Add screenshots here (put images in a `screenshots/` folder), for example the Excel report and the `/docs` page._

## Future Improvements
- Configurable thresholds via a YAML/JSON file
- Per-user baselines instead of fixed thresholds
- Email/Slack alerts for HIGH-risk users
- Docker support and deployment
- Support for JSON and syslog formats
