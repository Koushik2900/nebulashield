import logging
import sys
import os

import numpy as np
from fastapi import FastAPI, Request, Response, Query, Depends
from fastapi.responses import JSONResponse, Response as FastAPIResponse
from pydantic import BaseModel
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
from sqlalchemy.orm import Session

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.analyzer.threat_analyzer import ThreatAnalyzer
from src.analyzer.llm_analyzer import AdaptiveLLMAnalyzer
from src.api.feedback_api import feedback_app
from src.db.database import get_db, init_db, SessionLocal
from src.db.models import ThreatLog

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Prometheus metrics
# --------------------------------------------------------------------------- #
REQUESTS_TOTAL = Counter("nebulashield_requests_total", "Total requests analyzed")
REQUESTS_BLOCKED = Counter("nebulashield_requests_blocked_total", "Requests blocked by WAF")
REQUESTS_ALLOWED = Counter("nebulashield_requests_allowed_total", "Requests allowed through WAF")
THREAT_SCORE_GAUGE = Gauge("nebulashield_last_threat_score", "Threat score of the last analyzed request")

# --------------------------------------------------------------------------- #
# Analyzer singletons
# --------------------------------------------------------------------------- #
analyzer = ThreatAnalyzer()
llm_analyzer = AdaptiveLLMAnalyzer()

THREAT_THRESHOLD = 60
# Grey zone: heuristic score where LLM is consulted for a second opinion
_LLM_GREY_ZONE_LOW = 30
_LLM_GREY_ZONE_HIGH = 70


def _to_jsonable(obj):
    """Convert numpy scalars to Python-native types for JSON serialization."""
    if isinstance(obj, (np.bool_,)):
        return bool(obj)
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    return obj


def _combine_scores(heuristic_score: float, llm_score: float) -> float:
    """Combine heuristic and LLM scores with weighted average."""
    return 0.4 * heuristic_score + 0.6 * llm_score


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #
app = FastAPI()

# Auto-create DB tables on startup
init_db()

# Whitelist: paths that bypass WAF inspection
WAF_WHITELIST = {"/health", "/metrics", "/analyze", "/analyze/deep", "/docs", "/openapi.json", "/redoc"}

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
    score = analyzer.calculate_threat_score(features, payload=combined)

    REQUESTS_TOTAL.inc()
    THREAT_SCORE_GAUGE.set(score)

    if score > THREAT_THRESHOLD:
        REQUESTS_BLOCKED.inc()
        logger.warning(
            "WAF BLOCKED request: path=%s score=%.1f", request.url.path, score
        )
        # Log the blocked request to the database
        source_ip = request.client.host if request.client else None
        db = SessionLocal()
        try:
            threat_log = ThreatLog(
                payload=combined,
                threat_score=score,
                decision="BLOCK",
                source_ip=source_ip,
                request_path=request.url.path,
            )
            threat_log.set_features({k: _to_jsonable(v) for k, v in features.items()})
            db.add(threat_log)
            db.commit()
        except Exception as db_err:
            logger.error("Failed to save WAF block to DB: %s", db_err)
            db.rollback()
        finally:
            db.close()
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
async def analyze(request: AnalyzeRequest, req: Request, db: Session = Depends(get_db)):
    features = analyzer.extract_features(request.payload)
    heuristic_score = analyzer.calculate_threat_score(features, payload=request.payload)

    # LLM second-opinion in the grey zone
    llm_analysis = None
    final_score = heuristic_score
    if _LLM_GREY_ZONE_LOW <= heuristic_score <= _LLM_GREY_ZONE_HIGH:
        try:
            llm_analysis = await llm_analyzer.analyze_payload(
                request.payload, features, heuristic_score
            )
            if llm_analysis and "llm_score" in llm_analysis:
                final_score = _combine_scores(heuristic_score, llm_analysis["llm_score"])
        except Exception as exc:
            logger.warning("LLM analysis skipped: %s", exc)

    decision = "BLOCK" if final_score > THREAT_THRESHOLD else "ALLOW"

    REQUESTS_TOTAL.inc()
    THREAT_SCORE_GAUGE.set(final_score)
    if decision == "BLOCK":
        REQUESTS_BLOCKED.inc()
    else:
        REQUESTS_ALLOWED.inc()

    features_jsonable = {k: _to_jsonable(v) for k, v in features.items()}

    source_ip = req.client.host if req.client else None
    threat_log = ThreatLog(
        payload=request.payload,
        threat_score=final_score,
        decision=decision,
        source_ip=source_ip,
        request_path=req.url.path,
    )
    threat_log.set_features(features_jsonable)
    db.add(threat_log)
    db.commit()
    db.refresh(threat_log)

    response_body = {
        "threat_log_id": threat_log.id,
        "threat_score": final_score,
        "heuristic_score": heuristic_score,
        "decision": decision,
        "features": features_jsonable,
    }
    if llm_analysis:
        response_body["llm_analysis"] = llm_analysis

    return JSONResponse(content=response_body)


@app.post("/analyze/deep")
async def analyze_deep(request: AnalyzeRequest, req: Request, db: Session = Depends(get_db)):
    """Deep analysis: always runs both heuristic + LLM analysis."""
    features = analyzer.extract_features(request.payload)
    heuristic_score = analyzer.calculate_threat_score(features, payload=request.payload)

    llm_analysis = None
    final_score = heuristic_score
    try:
        llm_analysis = await llm_analyzer.analyze_payload(
            request.payload, features, heuristic_score
        )
        if llm_analysis and "llm_score" in llm_analysis:
            final_score = _combine_scores(heuristic_score, llm_analysis["llm_score"])
    except Exception as exc:
        logger.warning("LLM analysis skipped in deep mode: %s", exc)

    decision = "BLOCK" if final_score > THREAT_THRESHOLD else "ALLOW"

    REQUESTS_TOTAL.inc()
    THREAT_SCORE_GAUGE.set(final_score)
    if decision == "BLOCK":
        REQUESTS_BLOCKED.inc()
    else:
        REQUESTS_ALLOWED.inc()

    features_jsonable = {k: _to_jsonable(v) for k, v in features.items()}

    source_ip = req.client.host if req.client else None
    threat_log = ThreatLog(
        payload=request.payload,
        threat_score=final_score,
        decision=decision,
        source_ip=source_ip,
        request_path=req.url.path,
    )
    threat_log.set_features(features_jsonable)
    db.add(threat_log)
    db.commit()
    db.refresh(threat_log)

    response_body = {
        "threat_log_id": threat_log.id,
        "threat_score": final_score,
        "heuristic_score": heuristic_score,
        "decision": decision,
        "features": features_jsonable,
        "llm_analysis": llm_analysis,
        "llm_available": llm_analysis is not None,
    }

    return JSONResponse(content=response_body)


# --------------------------------------------------------------------------- #
# Mount Feedback API
# --------------------------------------------------------------------------- #
app.mount("/feedback", feedback_app)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)