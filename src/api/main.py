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
from src.analyzer.ml_classifier import MLThreatClassifier
from src.api.feedback_api import feedback_app
from src.db.database import get_db, init_db, SessionLocal
from src.db.models import ThreatLog, AnalystFeedback

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
ml_classifier = MLThreatClassifier(model_path="models/threat_classifier.pkl")

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


def _combine_scores(
    heuristic_score: float,
    llm_score: float | None = None,
    ml_score: float | None = None,
) -> float:
    """Combine heuristic, ML, and LLM scores with weighted average."""
    ml_available = ml_score is not None
    llm_available = llm_score is not None

    if ml_available and llm_available:
        return 0.3 * heuristic_score + 0.3 * ml_score + 0.4 * llm_score
    elif ml_available:
        return 0.5 * heuristic_score + 0.5 * ml_score
    elif llm_available:
        return 0.4 * heuristic_score + 0.6 * llm_score
    else:
        return heuristic_score


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #
app = FastAPI()

# Auto-create DB tables on startup
init_db()

# Try to load pre-trained ML model; auto-train if training data is available
_ml_model_path = "models/threat_classifier.pkl"
_training_data_path = "data/training_data.csv"

if not ml_classifier.load():
    if os.path.exists(_training_data_path):
        logger.info(
            "ML model not found, training from %s...", _training_data_path
        )
        try:
            ml_classifier.train(csv_path=_training_data_path)
            logger.info("Auto-training complete.")
        except Exception as _train_exc:
            logger.warning("Auto-training failed: %s", _train_exc)

# Whitelist: paths that bypass WAF inspection
WAF_WHITELIST = {
    "/health", "/metrics", "/analyze", "/analyze/deep",
    "/llm/status", "/ml/status", "/ml/train", "/ml/retrain-from-feedback",
    "/docs", "/openapi.json", "/redoc",
}

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

    # ML prediction (always run if loaded)
    ml_prediction = None
    ml_score_val = None
    if ml_classifier.is_loaded():
        try:
            ml_prediction = ml_classifier.predict(request.payload, features)
            ml_score_val = float(ml_prediction["ml_score"])
        except Exception as exc:
            logger.warning("ML analysis skipped: %s", exc)

    # LLM second-opinion in the grey zone
    llm_analysis = None
    llm_score_val = None
    if _LLM_GREY_ZONE_LOW <= heuristic_score <= _LLM_GREY_ZONE_HIGH:
        try:
            llm_analysis = await llm_analyzer.analyze_payload(
                request.payload, features, heuristic_score
            )
            if llm_analysis and "llm_score" in llm_analysis:
                llm_score_val = float(llm_analysis["llm_score"])
        except Exception as exc:
            logger.warning("LLM analysis skipped: %s", exc)

    final_score = _combine_scores(heuristic_score, llm_score_val, ml_score_val)
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
    if ml_prediction:
        response_body["ml_prediction"] = ml_prediction
    if llm_analysis:
        response_body["llm_analysis"] = llm_analysis

    return JSONResponse(content=response_body)


@app.get("/llm/status")
async def llm_status():
    """Return the configured LLM backend, model, and availability."""
    return JSONResponse(content={
        "backend": llm_analyzer.backend,
        "model": llm_analyzer.model,
        "available": llm_analyzer.is_available(),
    })


@app.post("/analyze/deep")
async def analyze_deep(request: AnalyzeRequest, req: Request, db: Session = Depends(get_db)):
    """Deep analysis: always runs heuristic + ML + LLM analysis."""
    features = analyzer.extract_features(request.payload)
    heuristic_score = analyzer.calculate_threat_score(features, payload=request.payload)

    # ML prediction
    ml_prediction = None
    ml_score_val = None
    if ml_classifier.is_loaded():
        try:
            ml_prediction = ml_classifier.predict(request.payload, features)
            ml_score_val = float(ml_prediction["ml_score"])
        except Exception as exc:
            logger.warning("ML analysis skipped in deep mode: %s", exc)

    # LLM analysis (always attempted in deep mode)
    llm_analysis = None
    llm_score_val = None
    try:
        llm_analysis = await llm_analyzer.analyze_payload(
            request.payload, features, heuristic_score
        )
        if llm_analysis and "llm_score" in llm_analysis:
            llm_score_val = float(llm_analysis["llm_score"])
    except Exception as exc:
        logger.warning("LLM analysis skipped in deep mode: %s", exc)

    final_score = _combine_scores(heuristic_score, llm_score_val, ml_score_val)
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
    if ml_prediction:
        response_body["ml_prediction"] = ml_prediction

    return JSONResponse(content=response_body)


# --------------------------------------------------------------------------- #
# ML endpoints
# --------------------------------------------------------------------------- #

@app.get("/ml/status")
async def ml_status():
    """Return the ML classifier status and configuration."""
    return JSONResponse(content={
        "model_loaded": ml_classifier.is_loaded(),
        "model_path": ml_classifier.model_path,
        "features": ml_classifier.feature_count,
    })


@app.post("/ml/train")
async def ml_train(db: Session = Depends(get_db)):
    """
    Retrain the ML model by combining the base training CSV with labeled data
    from the threat_logs and analyst_feedback tables.
    """
    import tempfile
    import csv

    rows = []

    # Pull base CSV
    if os.path.exists(_training_data_path):
        import pandas as pd
        base_df = pd.read_csv(_training_data_path)
        rows.extend(
            {"payload": str(r["payload"]), "label": int(r["label"]), "attack_type": str(r.get("attack_type", "none"))}
            for r in base_df.to_dict("records")
        )

    # Pull from DB: analyst feedback with explicit corrections
    try:
        feedbacks = (
            db.query(AnalystFeedback)
            .join(ThreatLog, AnalystFeedback.threat_log_id == ThreatLog.id)
            .all()
        )
        for fb in feedbacks:
            log = fb.threat_log
            if log is None:
                continue
            if fb.is_false_positive:
                # WAF thought it was malicious, analyst says benign
                rows.append({"payload": log.payload, "label": 0, "attack_type": "none"})
            elif fb.is_false_negative:
                # WAF thought benign, analyst says malicious
                rows.append({"payload": log.payload, "label": 1, "attack_type": "unknown"})
    except Exception as exc:
        logger.warning("Could not pull feedback data for training: %s", exc)

    if not rows:
        return JSONResponse(
            status_code=400,
            content={"error": "No training data available. Provide data/training_data.csv or add analyst feedback."},
        )

    # Write to a temp CSV and train
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["payload", "label", "attack_type"])
        writer.writeheader()
        writer.writerows(rows)
        tmp_path = f.name

    try:
        metrics = ml_classifier.train(csv_path=tmp_path)
    finally:
        os.unlink(tmp_path)

    return JSONResponse(content={
        "status": "trained",
        "samples": metrics["samples_trained"],
        "feature_count": metrics["feature_count"],
        "binary_report": metrics["binary_classification_report"],
    })


@app.post("/ml/retrain-from-feedback")
async def ml_retrain_from_feedback(db: Session = Depends(get_db)):
    """
    Retrain using only analyst-corrected feedback entries, combined with the
    base training dataset for stability.
    """
    import tempfile
    import csv

    rows = []

    # Anchor on base CSV to avoid catastrophic forgetting
    if os.path.exists(_training_data_path):
        import pandas as pd
        base_df = pd.read_csv(_training_data_path)
        rows.extend(
            {"payload": str(r["payload"]), "label": int(r["label"]), "attack_type": str(r.get("attack_type", "none"))}
            for r in base_df.to_dict("records")
        )

    feedback_count = 0
    try:
        feedbacks = (
            db.query(AnalystFeedback)
            .join(ThreatLog, AnalystFeedback.threat_log_id == ThreatLog.id)
            .all()
        )
        for fb in feedbacks:
            log = fb.threat_log
            if log is None:
                continue
            if fb.is_false_positive:
                rows.append({"payload": log.payload, "label": 0, "attack_type": "none"})
                feedback_count += 1
            elif fb.is_false_negative:
                rows.append({"payload": log.payload, "label": 1, "attack_type": "unknown"})
                feedback_count += 1
    except Exception as exc:
        logger.warning("Could not pull feedback for retraining: %s", exc)

    if not rows:
        return JSONResponse(
            status_code=400,
            content={"error": "No training data available."},
        )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["payload", "label", "attack_type"])
        writer.writeheader()
        writer.writerows(rows)
        tmp_path = f.name

    try:
        metrics = ml_classifier.train(csv_path=tmp_path)
    finally:
        os.unlink(tmp_path)

    return JSONResponse(content={
        "status": "retrained",
        "feedback_samples_used": feedback_count,
        "total_samples": metrics["samples_trained"],
        "feature_count": metrics["feature_count"],
        "binary_report": metrics["binary_classification_report"],
    })


# --------------------------------------------------------------------------- #
# Mount Feedback API
# --------------------------------------------------------------------------- #
app.mount("/feedback", feedback_app)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)