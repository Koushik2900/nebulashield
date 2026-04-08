import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from fastapi import FastAPI, HTTPException, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.db.database import get_db
from src.db.models import AnalystFeedback, ThreatLog

feedback_app = FastAPI(title="NebulaShield Feedback API")


class FeedbackReportRequest(BaseModel):
    threat_log_id: int
    is_false_positive: bool = False
    is_false_negative: bool = False
    notes: str | None = None


@feedback_app.get("/dashboard/false-positives")
async def get_false_positives(limit: int = 20, db: Session = Depends(get_db)):
    rows = (
        db.query(AnalystFeedback)
        .filter(AnalystFeedback.is_false_positive == True)  # noqa: E712
        .join(ThreatLog)
        .limit(limit)
        .all()
    )
    items = [
        {
            "feedback_id": fb.id,
            "threat_log_id": fb.threat_log_id,
            "payload": fb.threat_log.payload,
            "threat_score": fb.threat_log.threat_score,
            "decision": fb.threat_log.decision,
            "notes": fb.notes,
            "created_at": fb.created_at.isoformat() if fb.created_at else None,
        }
        for fb in rows
    ]
    return {"count": len(items), "items": items}


@feedback_app.get("/analytics/statistics")
async def get_statistics(db: Session = Depends(get_db)):
    total = db.query(ThreatLog).count()
    blocked = db.query(ThreatLog).filter(ThreatLog.decision == "BLOCK").count()
    allowed = db.query(ThreatLog).filter(ThreatLog.decision == "ALLOW").count()

    # Accuracy: (total - false_positives - false_negatives) / total if any feedback exists
    fp_count = db.query(AnalystFeedback).filter(AnalystFeedback.is_false_positive == True).count()  # noqa: E712
    fn_count = db.query(AnalystFeedback).filter(AnalystFeedback.is_false_negative == True).count()  # noqa: E712
    feedback_total = db.query(AnalystFeedback).count()
    if total > 0 and feedback_total > 0:
        accuracy = round((feedback_total - fp_count - fn_count) / feedback_total, 4)
    elif total > 0:
        accuracy = None  # Not enough feedback to calculate
    else:
        accuracy = None

    return {
        "total_requests": total,
        "blocked": blocked,
        "allowed": allowed,
        "accuracy": accuracy,
    }


@feedback_app.post("/report")
async def report_feedback(payload: FeedbackReportRequest, db: Session = Depends(get_db)):
    threat_log = db.query(ThreatLog).filter(ThreatLog.id == payload.threat_log_id).first()
    if not threat_log:
        raise HTTPException(status_code=404, detail="ThreatLog not found")

    feedback = AnalystFeedback(
        threat_log_id=payload.threat_log_id,
        is_false_positive=payload.is_false_positive,
        is_false_negative=payload.is_false_negative,
        notes=payload.notes,
    )
    db.add(feedback)
    db.commit()
    db.refresh(feedback)

    return {
        "feedback_id": feedback.id,
        "threat_log_id": feedback.threat_log_id,
        "is_false_positive": feedback.is_false_positive,
        "is_false_negative": feedback.is_false_negative,
        "notes": feedback.notes,
        "created_at": feedback.created_at.isoformat() if feedback.created_at else None,
    }


@feedback_app.get("/history")
async def get_history(limit: int = Query(default=100, ge=1, le=1000), db: Session = Depends(get_db)):
    logs = (
        db.query(ThreatLog)
        .order_by(ThreatLog.created_at.desc())
        .limit(limit)
        .all()
    )
    items = [
        {
            "id": log.id,
            "payload": log.payload,
            "threat_score": log.threat_score,
            "decision": log.decision,
            "source_ip": log.source_ip,
            "request_path": log.request_path,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in logs
    ]
    return {"count": len(items), "items": items}
