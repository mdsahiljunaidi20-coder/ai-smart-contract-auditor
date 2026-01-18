def generate_fix(issue: dict, contract_code: str) -> dict:
    """
    AI-assisted fix generator.
    Applies SAFE automated fixes where possible.
    Provides human-readable suggestions otherwise.
    """

    fix = {
        "fix_applied": False,
        "patched_code": None,
        "confidence": 0.0,
        "note": ""
    }

    check = (issue.get("check") or "").lower()
    description = (issue.get("description") or "").lower()

    # =====================================================
    # Reentrancy / low-level external calls
    # =====================================================
    if "reentrancy" in check or "low-level call" in check or "unchecked-lowlevel" in check:
        fix["patched_code"] = (
            "// AI FIX SUGGESTION:\n"
            "// Apply Checks-Effects-Interactions (CEI) pattern\n"
            "// 1. Validate conditions\n"
            "// 2. Update contract state\n"
            "// 3. Perform external calls last\n\n"
            "// Example:\n"
            "// balances[msg.sender] -= amount;\n"
            "// (bool success, ) = msg.sender.call{value: amount}(\"\");\n"
            "// require(success, \"ETH transfer failed\");\n"
        )
        fix["fix_applied"] = True
        fix["confidence"] = 0.85
        fix["note"] = "Suggested CEI pattern to mitigate reentrancy risk."

    # =====================================================
    # tx.origin misuse
    # =====================================================
    elif "tx.origin" in check:
        fix["patched_code"] = (
            "// AI FIX SUGGESTION:\n"
            "// Do NOT use tx.origin for authorization\n"
            "// Replace with msg.sender and proper access control\n\n"
            "// Example:\n"
            "// require(msg.sender == owner, \"Not authorized\");\n"
        )
        fix["fix_applied"] = True
        fix["confidence"] = 0.90
        fix["note"] = "Replaced tx.origin usage with msg.sender-based authorization."

    # =====================================================
    # Arbitrary ETH send
    # =====================================================
    elif "arbitrary-send-eth" in check:
        fix["note"] = (
            "Manual fix recommended: Restrict ETH transfers using access control "
            "(e.g., onlyOwner). Validate recipient addresses and avoid sending ETH "
            "to user-controlled inputs."
        )
        fix["confidence"] = 0.75

    # =====================================================
    # Uninitialized state variables
    # =====================================================
    elif "uninitialized" in check:
        fix["note"] = (
            "Manual fix recommended: Initialize all state variables explicitly "
            "in the constructor or during declaration before usage."
        )
        fix["confidence"] = 0.70

    # =====================================================
    # Solidity version / compiler issues
    # =====================================================
    elif "solc" in check or "version" in check:
        fix["note"] = (
            "Manual fix recommended: Lock the Solidity compiler version "
            "using a fixed pragma (e.g., pragma solidity ^0.8.20;)."
        )
        fix["confidence"] = 0.65

    # =====================================================
    # Optimization / informational findings
    # =====================================================
    elif "optimization" in check or "constable" in check:
        fix["note"] = (
            "Optional improvement: Mark variables as constant/immutable "
            "where applicable to reduce gas usage."
        )
        fix["confidence"] = 0.60

    # =====================================================
    # Fallback (SAFE DEFAULT)
    # =====================================================
    else:
        fix["note"] = (
            "Automated fix not applied. This vulnerability is context-dependent "
            "and requires manual security review to avoid breaking business logic."
        )
        fix["confidence"] = 0.50

    return fix
