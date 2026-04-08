"""
Tests for the database-backed endpoints added in Phase 3.
Uses an in-memory SQLite database so no files are created on disk.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.db.models import Base
from src.db.database import get_db
from src.api.main import app
from src.api.feedback_api import feedback_app

# --------------------------------------------------------------------------- #
# In-memory DB fixture
# --------------------------------------------------------------------------- #
TEST_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture()
def db_session():
    """Create a fresh in-memory DB for each test."""
    engine = create_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db_session):
    """FastAPI test client that uses the in-memory DB."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    feedback_app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    feedback_app.dependency_overrides.clear()


# --------------------------------------------------------------------------- #
# POST /analyze — DB persistence
# --------------------------------------------------------------------------- #

def test_analyze_returns_threat_log_id(client):
    """POST /analyze must return a threat_log_id."""
    response = client.post("/analyze", json={"payload": "hello world"})
    assert response.status_code == 200
    data = response.json()
    assert "threat_log_id" in data
    assert isinstance(data["threat_log_id"], int)
    assert data["threat_log_id"] > 0


def test_analyze_log_is_persisted(client, db_session):
    """Each call to POST /analyze should create a ThreatLog row."""
    from src.db.models import ThreatLog

    before = db_session.query(ThreatLog).count()
    client.post("/analyze", json={"payload": "hello world"})
    after = db_session.query(ThreatLog).count()
    assert after == before + 1


def test_analyze_block_decision_stored(client, db_session):
    """A high-threat payload must store BLOCK in ThreatLog."""
    from src.db.models import ThreatLog

    payload = "UNION SELECT * FROM users EXEC xp_cmdshell WHOAMI OR 1=1 DROP TABLE 127.0.0.1 ../../etc/passwd"
    response = client.post("/analyze", json={"payload": payload})
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "BLOCK"

    log = db_session.query(ThreatLog).filter(ThreatLog.id == data["threat_log_id"]).first()
    assert log is not None
    assert log.decision == "BLOCK"
    assert log.threat_score > 60


def test_analyze_allow_decision_stored(client, db_session):
    """A benign payload must store ALLOW in ThreatLog."""
    from src.db.models import ThreatLog

    response = client.post("/analyze", json={"payload": "hello world"})
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "ALLOW"

    log = db_session.query(ThreatLog).filter(ThreatLog.id == data["threat_log_id"]).first()
    assert log is not None
    assert log.decision == "ALLOW"


# --------------------------------------------------------------------------- #
# POST /feedback/report
# --------------------------------------------------------------------------- #

def test_feedback_report_creates_entry(client, db_session):
    """POST /feedback/report must create an AnalystFeedback row."""
    from src.db.models import AnalystFeedback

    # First create a threat log
    analyze_resp = client.post("/analyze", json={"payload": "hello world"})
    threat_log_id = analyze_resp.json()["threat_log_id"]

    before = db_session.query(AnalystFeedback).count()
    response = client.post(
        "/feedback/report",
        json={
            "threat_log_id": threat_log_id,
            "is_false_positive": True,
            "is_false_negative": False,
            "notes": "This was a test payload, not a real threat.",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "feedback_id" in data
    assert data["is_false_positive"] is True
    assert data["threat_log_id"] == threat_log_id

    after = db_session.query(AnalystFeedback).count()
    assert after == before + 1


def test_feedback_report_404_for_missing_log(client):
    """POST /feedback/report with a non-existent threat_log_id must return 404."""
    response = client.post(
        "/feedback/report",
        json={"threat_log_id": 99999, "is_false_positive": False},
    )
    assert response.status_code == 404


# --------------------------------------------------------------------------- #
# GET /feedback/history
# --------------------------------------------------------------------------- #

def test_feedback_history_returns_logged_threats(client):
    """GET /feedback/history must return threat logs that were created."""
    client.post("/analyze", json={"payload": "hello world"})
    client.post("/analyze", json={"payload": "another test"})

    response = client.get("/feedback/history")
    assert response.status_code == 200
    data = response.json()
    assert "count" in data
    assert "items" in data
    assert data["count"] >= 2


def test_feedback_history_limit_param(client):
    """GET /feedback/history?limit=1 must return at most 1 item."""
    client.post("/analyze", json={"payload": "hello world"})
    client.post("/analyze", json={"payload": "another test"})

    response = client.get("/feedback/history?limit=1")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) <= 1


# --------------------------------------------------------------------------- #
# GET /feedback/analytics/statistics
# --------------------------------------------------------------------------- #

def test_statistics_returns_real_counts(client):
    """GET /feedback/analytics/statistics must reflect actual DB counts."""
    # Start with a clean slate — query current counts
    baseline = client.get("/feedback/analytics/statistics").json()
    baseline_total = baseline["total_requests"]

    client.post("/analyze", json={"payload": "hello world"})
    client.post(
        "/analyze",
        json={
            "payload": "UNION SELECT * FROM users EXEC xp_cmdshell WHOAMI OR 1=1 DROP TABLE 127.0.0.1 ../../etc/passwd"
        },
    )

    response = client.get("/feedback/analytics/statistics")
    assert response.status_code == 200
    data = response.json()
    assert data["total_requests"] == baseline_total + 2
    assert data["blocked"] + data["allowed"] == data["total_requests"]


# --------------------------------------------------------------------------- #
# GET /feedback/dashboard/false-positives
# --------------------------------------------------------------------------- #

def test_false_positives_returns_actual_entries(client):
    """GET /feedback/dashboard/false-positives must return entries after feedback is submitted."""
    # Create a log and mark it as a false positive
    analyze_resp = client.post("/analyze", json={"payload": "hello world"})
    threat_log_id = analyze_resp.json()["threat_log_id"]

    client.post(
        "/feedback/report",
        json={"threat_log_id": threat_log_id, "is_false_positive": True},
    )

    response = client.get("/feedback/dashboard/false-positives")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] >= 1
    ids = [item["threat_log_id"] for item in data["items"]]
    assert threat_log_id in ids


def test_false_negatives_not_in_false_positives(client):
    """False negatives should NOT appear in /dashboard/false-positives."""
    analyze_resp = client.post("/analyze", json={"payload": "hello world"})
    threat_log_id = analyze_resp.json()["threat_log_id"]

    client.post(
        "/feedback/report",
        json={"threat_log_id": threat_log_id, "is_false_negative": True, "is_false_positive": False},
    )

    response = client.get("/feedback/dashboard/false-positives")
    data = response.json()
    ids = [item["threat_log_id"] for item in data["items"]]
    assert threat_log_id not in ids
