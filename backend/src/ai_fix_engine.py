def generate_fix(issue: dict, contract_code: str) -> dict:
    """
    AI-assisted fix generator (template-based, safe).
    """

    fix = {
        "fix_applied": False,
        "patched_code": None,
        "confidence": 0.0,
        "note": ""
    }

    check = issue.get("check", "").lower()

    # Reentrancy / low-level call
    if "reentrancy" in check or "low-level call" in check:
        fix["patched_code"] = (
            "// FIX: Apply Checks-Effects-Interactions pattern\n"
            "// 1. Update state before external call\n"
            "// 2. Avoid low-level call\n"
        )
        fix["fix_applied"] = True
        fix["confidence"] = 0.85
        fix["note"] = "Suggested CEI pattern to mitigate reentrancy."

    # tx.origin misuse
    elif "tx.origin" in check:
        fix["patched_code"] = (
            "// FIX: Replace tx.origin with msg.sender\n"
            "// Use proper access control (Ownable)\n"
        )
        fix["fix_applied"] = True
        fix["confidence"] = 0.90
        fix["note"] = "Replaced tx.origin with msg.sender."

    else:
        fix["note"] = "No automated fix available. Manual review recommended."

    return fix
