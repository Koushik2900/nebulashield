import logging
import sys
import os

import numpy as np
from fastapi import FastAPI, Request, Response, Query
from fastapi.responses import JSONResponse, Response as FastAPIResponse
from pydantic import BaseModel
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.analyzer.threat_analyzer import ThreatAnalyzer
from src.api.feedback_api import feedback_app

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Prometheus metrics
# --------------------------------------------------------------------------- #
REQUESTS_TOTAL = Counter("nebulashield_requests_total", "Total requests analyzed")
REQUESTS_BLOCKED = Counter("nebulashield_requests_blocked_total", "Requests blocked by WAF")
REQUESTS_ALLOWED = Counter("nebulashield_requests_allowed_total", "Requests allowed through WAF")
THREAT_SCORE_GAUGE = Gauge("nebulashield_last_threat_score", "Threat score of the last analyzed request")

# --------------------------------------------------------------------------- #
# Threat analyzer singleton
# --------------------------------------------------------------------------- #
analyzer = ThreatAnalyzer()

THREAT_THRESHOLD = 60


def _to_jsonable(obj):
    """Convert numpy scalars to Python-native types for JSON serialization."""
    if isinstance(obj, (np.bool_,)):
        return bool(obj)
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    return obj

# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #
app = FastAPI()

# Whitelist: paths that bypass WAF inspection
WAF_WHITELIST = {"/health", "/metrics", "/analyze", "/docs", "/openapi.json", "/redoc"}

# --------------------------------------------------------------------------- #
# WAF Middleware
# --------------------------------------------------------------------------- #
@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    # Allow whitelisted paths to pass through without inspection
    if request.url.path in WAF_WHITELIST or request.url.path.startswith("/feedback"):
        return await call_next(request)

    # Build a combined payload from URL, query params, and body
    query_string = str(request.url.query)
    try:
        body_bytes = await request.body()
        body_text = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        body_text = ""

    combined = f"{request.url.path} {query_string} {body_text}".strip()

    features = analyzer.extract_features(combined)
    score = analyzer.calculate_threat_score(features)

    REQUESTS_TOTAL.inc()
    THREAT_SCORE_GAUGE.set(score)

    if score > THREAT_THRESHOLD:
        REQUESTS_BLOCKED.inc()
        logger.warning(
            "WAF BLOCKED request: path=%s score=%.1f", request.url.path, score
        )
        return JSONResponse(
            status_code=403,
            content={"detail": "Forbidden", "threat_score": score},
        )

    REQUESTS_ALLOWED.inc()
    return await call_next(request)


# --------------------------------------------------------------------------- #
# Existing endpoints
# --------------------------------------------------------------------------- #
@app.get("/health")
async def health_check():
    return JSONResponse(content={"status": "healthy"})


@app.get("/metrics")
async def metrics():
    prometheus_output = generate_latest()
    return FastAPIResponse(content=prometheus_output, media_type=CONTENT_TYPE_LATEST)


@app.get("/users")
async def get_users(id: int = Query(..., description="The user ID to look up")):
    # Placeholder response — replace with real DB lookup later
    return JSONResponse(content={"id": id, "name": "example_user"})


# --------------------------------------------------------------------------- #
# Analyze endpoint
# --------------------------------------------------------------------------- #
class AnalyzeRequest(BaseModel):
    payload: str


@app.post("/analyze")
async def analyze(request: AnalyzeRequest):
    features = analyzer.extract_features(request.payload)
    score = analyzer.calculate_threat_score(features)
    decision = "BLOCK" if score > THREAT_THRESHOLD else "ALLOW"

    REQUESTS_TOTAL.inc()
    THREAT_SCORE_GAUGE.set(score)
    if decision == "BLOCK":
        REQUESTS_BLOCKED.inc()
    else:
        REQUESTS_ALLOWED.inc()

    features_jsonable = {k: _to_jsonable(v) for k, v in features.items()}
    return JSONResponse(
        content={"threat_score": score, "decision": decision, "features": features_jsonable}
    )


# --------------------------------------------------------------------------- #
# Mount Feedback API
# --------------------------------------------------------------------------- #
app.mount("/feedback", feedback_app)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)