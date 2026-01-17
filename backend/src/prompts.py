def build_explanation_prompt(issue: dict, contract_code: str) -> str:
    return f"""
You are a senior smart contract security auditor.

Vulnerability detected:
- Type: {issue.get('check')}
- Impact: {issue.get('impact')}
- Description: {issue.get('description')}

Smart contract code:
{contract_code}

Explain clearly:
1. Why this vulnerability exists
2. How an attacker can exploit it
3. What the impact is
4. How to fix it (best practice)

Keep it concise and technical.
"""
