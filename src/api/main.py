from fastapi import FastAPI, Request, Response, Query
from fastapi.responses import JSONResponse
import time

app = FastAPI()

@app.get("/health")
async def health_check():
    return JSONResponse(content={"status": "healthy"})

@app.get("/metrics")
async def metrics():
    # Here you would typically gather and return metrics data
    return JSONResponse(content={"message": "Metrics data is not implemented yet."})

@app.get("/users")
async def get_users(id: int = Query(..., description="The user ID to look up")):
    # Placeholder response — replace with real DB lookup later
    return JSONResponse(content={"id": id, "name": "example_user"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)