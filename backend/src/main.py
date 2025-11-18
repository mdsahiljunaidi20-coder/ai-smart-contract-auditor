from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

app = FastAPI()


# ----------------------------------------------------------
# 1. Input Model
# ----------------------------------------------------------
class ContractInput(BaseModel):
    contract_name: str
    code: str


# ----------------------------------------------------------
# 2. Helper function: get line numbers that contain a keyword
# ----------------------------------------------------------
def find_lines_with(code: str, keyword: str) -> List[int]:
    lines = code.split("\n")
    result = []
    for i, line in enumerate(lines, start=1):
        if keyword in line:
            result.append(i)
    return result


# ----------------------------------------------------------
# 3. Rule-Based Vulnerability Scanner (Day 4)
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
            "description": "tx.origin is insecure and can be exploited through phishing attacks.",
            "recommendation": "Use msg.sender for authorization checks.",
            "line_numbers": origin_lines
        })

    # 2. Detect timestamp dependence
    timestamp_lines = (
        find_lines_with(code, "block.timestamp")
        + find_lines_with(code, "now")
    )
    if timestamp_lines:
        issues.append({
            "id": "TIMESTAMP_DEPENDENCE",
            "title": "Timestamp dependence",
            "severity": "MEDIUM",
            "description": "block.timestamp / now can be manipulated by miners.",
            "recommendation": "Avoid using timestamps for critical logic.",
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
            "description": "Low-level calls bypass type safety and may introduce reentrancy risk.",
            "recommendation": "Use function calls or OpenZeppelin's Address library.",
            "line_numbers": low_level_lines
        })

    # 4. Detect reentrancy risk
    transfer_lines = find_lines_with(code, ".transfer(") + find_lines_with(code, ".send(")
    if transfer_lines:
        issues.append({
            "id": "REENTRANCY_RISK",
            "title": "Potential Reentrancy vulnerability",
            "severity": "HIGH",
            "description": "External calls detected. If state changes are after these calls, reentrancy attack may occur.",
            "recommendation": "Use checks-effects-interactions pattern or ReentrancyGuard.",
            "line_numbers": transfer_lines
        })

    return issues


# ----------------------------------------------------------
# 4. Risk Scoring System
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

    return min(score, 100)


# ----------------------------------------------------------
# 5. POST /analyze endpoint (updated for Day 4)
# ----------------------------------------------------------
@app.post("/analyze")
def analyze_contract(data: ContractInput):

    issues = rule_based_scan(data.code)
    score = calculate_risk_score(issues)

    return {
        "contract_name": data.contract_name,
        "risk_score": score,
        "issues": issues
    }


# ----------------------------------------------------------
# 6. Home Route
# ----------------------------------------------------------
@app.get("/")
def home():
    return {"message": "AI Smart Contract Auditor Backend Running!"}
