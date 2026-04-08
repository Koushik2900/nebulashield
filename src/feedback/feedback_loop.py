import logging
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.db.database import SessionLocal
from src.db.models import AnalystFeedback, ThreatLog


class FeedbackLoop:
    def __init__(self):
        # Set up the logging configuration
        logging.basicConfig(filename='security_decisions.log', level=logging.INFO)

    def log_decision(self, decision: str, details: dict):
        """Logs a security decision with associated details and persists it to the DB."""
        logging.info(f'Decision: {decision}, Details: {details}')

        db = SessionLocal()
        try:
            threat_log = ThreatLog(
                payload=details.get("payload", ""),
                threat_score=details.get("threat_score", 0.0),
                decision=decision,
                source_ip=details.get("source_ip"),
                request_path=details.get("request_path"),
            )
            features = details.get("features")
            if features:
                threat_log.set_features(features)
            db.add(threat_log)
            db.commit()
            db.refresh(threat_log)
            return threat_log.id
        except Exception as e:
            logging.error(f"Failed to save decision to DB: {e}")
            db.rollback()
            return None
        finally:
            db.close()

    def collect_feedback(self, analyst_feedback: dict):
        """Collects feedback from analysts on security decisions and persists it to the DB."""
        logging.info(f'Analyst Feedback: {analyst_feedback}')

        threat_log_id = analyst_feedback.get("threat_log_id")
        if not threat_log_id:
            logging.warning("collect_feedback called without threat_log_id; skipping DB write.")
            return

        db = SessionLocal()
        try:
            feedback = AnalystFeedback(
                threat_log_id=threat_log_id,
                is_false_positive=analyst_feedback.get("is_false_positive", False),
                is_false_negative=analyst_feedback.get("is_false_negative", False),
                notes=analyst_feedback.get("notes"),
            )
            db.add(feedback)
            db.commit()
            db.refresh(feedback)
            return feedback.id
        except Exception as e:
            logging.error(f"Failed to save feedback to DB: {e}")
            db.rollback()
            return None
        finally:
            db.close()
