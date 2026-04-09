# Save as demo_backend.py
from fastapi import FastAPI, Request
app = FastAPI()

@app.get("/users")
def get_user(id: str):
    return {"user_id": id}