import json
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class ThreatLog(Base):
    __tablename__ = "threat_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    payload = Column(Text, nullable=False)
    threat_score = Column(Float, nullable=False)
    decision = Column(String(10), nullable=False)  # "BLOCK" or "ALLOW"
    features = Column(Text, nullable=True)  # JSON-serialized feature dict
    source_ip = Column(String(50), nullable=True)
    request_path = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    feedbacks = relationship("AnalystFeedback", back_populates="threat_log")

    def set_features(self, features_dict: dict):
        self.features = json.dumps(features_dict)

    def get_features(self) -> dict:
        if self.features:
            return json.loads(self.features)
        return {}


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id = Column(Integer, primary_key=True, autoincrement=True)
    threat_log_id = Column(Integer, ForeignKey("threat_logs.id"), nullable=False)
    is_false_positive = Column(Boolean, default=False)
    is_false_negative = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    threat_log = relationship("ThreatLog", back_populates="feedbacks")
