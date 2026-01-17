from src.prompts import build_explanation_prompt

def explain_issue(issue: dict, contract_code: str) -> dict:
    """
    AI explanation engine (mocked for now).
    Replace with OpenAI / LLaMA later.
    """

    prompt = build_explanation_prompt(issue, contract_code)

    # Mocked AI response (academically acceptable)
    explanation = {
        "why": "The vulnerability occurs due to unsafe external calls or improper authorization logic.",
        "exploit": "An attacker can repeatedly call the function before state updates.",
        "impact": "Funds may be drained or contract state corrupted.",
        "fix": "Apply checks-effects-interactions pattern and proper access control."
    }

    issue["ai_explanation"] = explanation
    return issue
