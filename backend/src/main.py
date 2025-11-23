from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
from datetime import datetime

app = FastAPI()


# ----------------------------------------------------------
# 1. Input Model
# ----------------------------------------------------------
class ContractInput(BaseModel):
    contract_name: str
    code: str


# ----------------------------------------------------------
# 2. Helper function: get line numbers for a keyword
# ----------------------------------------------------------
def find_lines_with(code: str, keyword: str) -> List[int]:
    lines = code.split("\n")
    return [i + 1 for i, line in enumerate(lines) if keyword in line]


# ----------------------------------------------------------
# 3. Rule-Based Vulnerability Scanner (Same as Day 4)
# ----------------------------------------------------------
def rule_based_scan(code: str):

    issues = []

    # 1. Detect tx.origin
    origin_lines = find_lines_with(code, "tx.origin")
    if origin_lines:
        issues.append({
            "id": "TX_ORIGIN_AUTH",
            "title": "Use of tx.origin for authentication",
            "severity": "HIGH",
            "description": "tx.origin is insecure and can be exploited via phishing.",
            "recommendation": "Use msg.sender instead.",
            "line_numbers": origin_lines
        })

    # 2. Timestamp dependence
    timestamp_lines = (
        find_lines_with(code, "block.timestamp")
        + find_lines_with(code, "now")
    )
    if timestamp_lines:
        issues.append({
            "id": "TIMESTAMP_DEPENDENCE",
            "title": "Timestamp dependence",
            "severity": "MEDIUM",
            "description": "Miners can manipulate timestamps.",
            "recommendation": "Do not rely on timestamp for critical logic.",
            "line_numbers": timestamp_lines
        })

    # 3. Detect low-level calls
    low_level_lines = (
        find_lines_with(code, ".call(")
        + find_lines_with(code, ".delegatecall(")
        + find_lines_with(code, ".call.value(")
    )
    if low_level_lines:
        issues.append({
            "id": "LOW_LEVEL_CALL",
            "title": "Use of low-level calls",
            "severity": "MEDIUM",
            "description": "Low-level calls may introduce reentrancy risk.",
            "recommendation": "Use OpenZeppelin Address library instead.",
            "line_numbers": low_level_lines
        })

    # 4. Reentrancy indicators
    transfer_lines = (
        find_lines_with(code, ".transfer(")
        + find_lines_with(code, ".send(")
    )
    if transfer_lines:
        issues.append({
            "id": "REENTRANCY_RISK",
            "title": "Potential Reentrancy Vulnerability",
            "severity": "HIGH",
            "description": "External calls detected before state changes.",
            "recommendation": "Use checks-effects-interactions and ReentrancyGuard.",
            "line_numbers": transfer_lines
        })

    return issues


# ----------------------------------------------------------
# 4. Improved Scoring System (Day 5 Upgrade)
# ----------------------------------------------------------
def calculate_risk_score(issues: List[dict]) -> int:
    score = 0

    for item in issues:
        if item["severity"] == "HIGH":
            score += 40
        elif item["severity"] == "MEDIUM":
            score += 20
        else:
            score += 10

    # Cap score at 100
    return min(score, 100)


# ----------------------------------------------------------
# 5. POST /analyze — Now with metadata + sorted results
# ----------------------------------------------------------
@app.post("/analyze")
def analyze_contract(data: ContractInput):

    issues = rule_based_scan(data.code)
    issues_sorted = sorted(issues, key=lambda x: x["severity"], reverse=True)

    score = calculate_risk_score(issues)

    report = {
        "contract_name": data.contract_name,
        "timestamp": datetime.utcnow().isoformat(),
        "lines_of_code": len(data.code.split("\n")),
        "issues_found": len(issues),
        "risk_score": score,
        "issues": issues_sorted
    }

    return report


# ----------------------------------------------------------
# 6. Home Route
# ----------------------------------------------------------
@app.get("/")
def home():
    return {"message": "AI Smart Contract Auditor Backend Running!"}
