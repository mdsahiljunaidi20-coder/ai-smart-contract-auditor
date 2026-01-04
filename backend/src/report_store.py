import json
import uuid
from datetime import datetime
from pathlib import Path

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

def save_report(report: dict) -> str:
    audit_id = str(uuid.uuid4())
    report["audit_id"] = audit_id
    report["timestamp"] = datetime.utcnow().isoformat()

    file_path = REPORTS_DIR / f"{audit_id}.json"
    with open(file_path, "w") as f:
        json.dump(report, f, indent=2)

    return audit_id


def load_report(audit_id: str) -> dict:
    file_path = REPORTS_DIR / f"{audit_id}.json"
    if not file_path.exists():
        raise FileNotFoundError("Report not found")

    with open(file_path) as f:
        return json.load(f)


def list_reports(limit: int = 10):
    files = sorted(
        REPORTS_DIR.glob("*.json"),
        key=lambda f: f.stat().st_mtime,
        reverse=True
    )
    reports = []
    for f in files[:limit]:
        with open(f) as file:
            reports.append(json.load(file))
    return reports
