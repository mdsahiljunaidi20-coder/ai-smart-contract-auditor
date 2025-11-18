from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {"message": "AI Smart Contract Auditor Backend Running!"}
