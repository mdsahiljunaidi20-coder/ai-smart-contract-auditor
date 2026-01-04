from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
from datetime import datetime
import subprocess
import tempfile
import json
import uuid
from pathlib import Path

# =========================
# App Init
# =========================
app = FastAPI(title="AI Smart Contract Auditor")

# =========================
# Storage (Day 8)
# =========================
REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

# =========================
# Input Schema
# =========================
class ContractInput(BaseModel):
    contract_name: str
    code: str

# =========================
# Rule-Based Detector (Day 7)
# =========================
def rule_based_scan(code: str):
    issues = []

    if "tx.origin" in code:
        issues.append({
            "source": "rule",
            "check": "tx.origin usage",
            "impact": "High",
            "description": "Use of tx.origin for authentication is insecure"
        })

    if ".call(" in code or ".call{" in code:
        issues.append({
            "source": "rule",
            "check": "Low-level call",
            "impact": "Medium",
            "description": "Low-level call may lead to reentrancy"
        })

    return issues

# =========================
# Slither Runner (Day 7)
# =========================
def run_slither(code: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        sol_file = Path(tmpdir) / "contract.sol"
        sol_file.write_text(code)

        cmd = [
            "slither",
            str(sol_file),
            "--json",
            "-"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0 and not result.stdout:
                return []

            data = json.loads(result.stdout)
            findings = []

            for item in data.get("results", {}).get("detectors", []):
                findings.append({
                    "source": "slither",
                    "check": item.get("check"),
                    "impact": item.get("impact"),
                    "confidence": item.get("confidence"),
                    "description": item.get("description")
                })

            return findings

        except Exception as e:
            return [{
                "source": "slither",
                "check": "Execution error",
                "impact": "Error",
                "description": str(e)
            }]

# =========================
# Analyze API (Day 7)
# =========================
@app.post("/analyze")
def analyze_contract(input: ContractInput):
    rule_issues = rule_based_scan(input.code)
    slither_issues = run_slither(input.code)

    issues = rule_issues + slither_issues

    report = {
        "contract": input.contract_name,
        "total_issues": len(issues),
        "issues": issues
    }

    audit_id = save_report(report)
    report["audit_id"] = audit_id

    return report

# =========================
# Report Storage (Day 8)
# =========================
def save_report(report: dict) -> str:
    audit_id = str(uuid.uuid4())
    report["audit_id"] = audit_id
    report["timestamp"] = datetime.utcnow().isoformat()

    file_path = REPORTS_DIR / f"{audit_id}.json"
    with open(file_path, "w") as f:
        json.dump(report, f, indent=2)

    return audit_id

@app.get("/reports/{audit_id}")
def get_report(audit_id: str):
    file_path = REPORTS_DIR / f"{audit_id}.json"
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    with open(file_path) as f:
        return json.load(f)

@app.get("/reports")
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

# =========================
# Health Check
# =========================
@app.get("/")
def root():
    return {"message": "AI Smart Contract Auditor Backend Running"}
