from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import tempfile
import json
import uuid

from jose import jwt, JWTError
from passlib.context import CryptContext

# ================= AI IMPORTS =================
from src.ai_engine import explain_issue          # Day 10
from src.ai_fix_engine import generate_fix       # Day 11

# =====================================================
# App Init
# =====================================================
app = FastAPI(title="AI Smart Contract Auditor")
# =====================================================
# CORS Middleware (Required for Frontend - Day 13)
# =====================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================================================
# Constants & Config
# =====================================================
SECRET_KEY = "super-secret-key-change-later"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# =====================================================
# In-memory user store (Day 9)
# =====================================================
users_db = {}

# =====================================================
# File-based report storage (Day 8)
# =====================================================
BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# =====================================================
# Schemas
# =====================================================
class ContractInput(BaseModel):
    contract_name: str
    code: str

class UserInput(BaseModel):
    username: str
    password: str

# =====================================================
# Auth utilities
# =====================================================
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_access_token(username: str):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username not in users_db:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# =====================================================
# Rule-based detection (Day 7)
# =====================================================
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

# =====================================================
# Slither runner (Day 7)
# =====================================================
def run_slither(code: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        sol_file = Path(tmpdir) / "contract.sol"
        sol_file.write_text(code)

        cmd = ["slither", str(sol_file), "--json", "-"]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if not result.stdout:
                return []

            data = json.loads(result.stdout)
            findings = []

            for d in data.get("results", {}).get("detectors", []):
                findings.append({
                    "source": "slither",
                    "check": d.get("check"),
                    "impact": d.get("impact"),
                    "confidence": d.get("confidence"),
                    "description": d.get("description")
                })

            return findings

        except Exception as e:
            return [{
                "source": "slither",
                "check": "Execution error",
                "impact": "Error",
                "description": str(e)
            }]

# =====================================================
# Report storage helpers (Day 8)
# =====================================================
def save_report(report: dict) -> str:
    audit_id = str(uuid.uuid4())
    report["audit_id"] = audit_id
    report["timestamp"] = datetime.utcnow().isoformat()

    file_path = REPORTS_DIR / f"{audit_id}.json"
    with open(file_path, "w") as f:
        json.dump(report, f, indent=2)

    return audit_id

def load_report(audit_id: str):
    file_path = REPORTS_DIR / f"{audit_id}.json"
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    with open(file_path) as f:
        return json.load(f)

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

# =====================================================
# Auth APIs (Day 9)
# =====================================================
@app.post("/auth/signup")
def signup(user: UserInput):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")

    users_db[user.username] = {
        "username": user.username,
        "password": hash_password(user.password)
    }

    return {"message": "User registered successfully"}

@app.post("/auth/login")
def login(user: UserInput):
    db_user = users_db.get(user.username)
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(user.username)
    return {"access_token": token, "token_type": "bearer"}

# =====================================================
# Core Audit API (Protected + AI Explanation + AI Fix)
# =====================================================
@app.post("/analyze")
def analyze_contract(
    input: ContractInput,
    user: str = Depends(get_current_user)
):
    rule_issues = rule_based_scan(input.code)
    slither_issues = run_slither(input.code)

    issues = rule_issues + slither_issues

    enhanced_issues = []
    for issue in issues:
        # ---- AI Explanation (Day 10) ----
        explained = explain_issue(issue, input.code)

        # ---- AI Fix Suggestion (Day 11) ----
        fix = generate_fix(issue, input.code)
        explained["ai_fix"] = fix

        enhanced_issues.append(explained)

    report = {
        "contract": input.contract_name,
        "total_issues": len(enhanced_issues),
        "issues": enhanced_issues
    }

    audit_id = save_report(report)
    report["audit_id"] = audit_id

    return report

# =====================================================
# Report APIs (Protected)
# =====================================================
@app.get("/reports")
def get_reports(
    limit: int = 10,
    user: str = Depends(get_current_user)
):
    return list_reports(limit)

@app.get("/reports/{audit_id}")
def get_report(
    audit_id: str,
    user: str = Depends(get_current_user)
):
    return load_report(audit_id)

# =====================================================
# Health check
# =====================================================
@app.get("/")
def root():
    return {"message": "Backend running (Day 11 complete)"}
