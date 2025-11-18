from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

# ------------------------------
# 1. Request Model
# ------------------------------
class ContractInput(BaseModel):
    contract_name: str
    code: str


# ------------------------------
# 2. Dummy Analysis Function (Day 3)
# ------------------------------
def fake_analysis(code: str):
    # This is NOT real auditing — real scanning comes on Day 4
    # Today we return a static example structure
    
    return {
        "risk_score": 42,
        "issues": [
            {
                "id": "DUMMY_001",
                "title": "Dummy Vulnerability",
                "severity": "MEDIUM",
                "description": "This is a placeholder issue for testing.",
                "recommendation": "Real analysis will begin from Day 4.",
                "line_numbers": [1, 5]
            }
        ]
    }


# ------------------------------
# 3. POST /analyze Endpoint
# ------------------------------
@app.post("/analyze")
def analyze_contract(data: ContractInput):
    result = fake_analysis(data.code)

    return {
        "contract_name": data.contract_name,
        "analysis_result": result
    }


# ------------------------------
# 4. Home Route
# ------------------------------
@app.get("/")
def home():
    return {"message": "AI Smart Contract Auditor Backend Running!"}
