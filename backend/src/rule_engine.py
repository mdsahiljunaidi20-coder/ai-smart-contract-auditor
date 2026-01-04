def rule_scan(code: str):
    issues = []

    if "tx.origin" in code:
        issues.append({
            "source": "rule",
            "check": "tx.origin",
            "impact": "High",
            "description": "Use of tx.origin for authorization"
        })

    if ".call(" in code:
        issues.append({
            "source": "rule",
            "check": "low-level call",
            "impact": "Medium",
            "description": "Low-level call may lead to reentrancy"
        })

    return issues
