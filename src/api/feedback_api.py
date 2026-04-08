from fastapi import FastAPI, HTTPException

feedback_app = FastAPI(title="NebulaShield Feedback API")

@feedback_app.get("/dashboard/false-positives")
async def get_false_positives(limit: int = 20):
    return {"count": 0, "items": []}

@feedback_app.get("/analytics/statistics")
async def get_statistics():
    return {
        "total_requests": 0,
        "blocked": 0,
        "allowed": 0,
        "accuracy": 0
    }
