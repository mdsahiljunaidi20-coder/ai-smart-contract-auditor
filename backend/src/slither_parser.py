import json

def parse_slither(raw_json: str):
    issues = []
    try:
        data = json.loads(raw_json)
    except Exception:
        return issues

    detectors = data.get("results", {}).get("detectors", [])
    for d in detectors:
        issues.append({
            "source": "slither",
            "check": d.get("check"),
            "impact": d.get("impact"),
            "confidence": d.get("confidence"),
            "description": d.get("description")
        })

    return issues
