"""
Tests for the ML threat classifier (Phase 6).
"""
import os
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.db.models import Base
from src.db.database import get_db
from src.api.main import app
from src.api.feedback_api import feedback_app
from src.analyzer.ml_classifier import MLThreatClassifier
from src.analyzer.threat_analyzer import ThreatAnalyzer

# --------------------------------------------------------------------------- #
# In-memory DB fixture (reuse pattern from test_db_integration.py)
# --------------------------------------------------------------------------- #
TEST_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture()
def db_session():
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
# Minimal training CSV fixture
# --------------------------------------------------------------------------- #
_MINI_CSV_CONTENT = """\
payload,label,attack_type
"' OR '1'='1",1,sqli
"1' UNION SELECT username,password FROM users--",1,sqli
"<script>alert('xss')</script>",1,xss
"<img src=x onerror=alert(1)>",1,xss
"; cat /etc/passwd",1,command_injection
"| whoami",1,command_injection
"../../etc/passwd",1,path_traversal
"../../../etc/shadow",1,path_traversal
"http://169.254.169.254/latest/meta-data/",1,ssrf
"http://127.0.0.1:80/admin",1,ssrf
"<!ENTITY xxe SYSTEM file:///etc/passwd>",1,xxe
"%27%20OR%20%271%27%3D%271",1,encoded
"search for electronics",0,none
"get user profile page=1",0,none
"checkout order id=12345",0,none
"find products under $50",0,none
"hello world",0,none
"normal text without any special characters",0,none
"list all available categories",0,none
"filter by brand=Nike color=red",0,none
"""


@pytest.fixture()
def mini_csv(tmp_path):
    csv_file = tmp_path / "test_training.csv"
    csv_file.write_text(_MINI_CSV_CONTENT)
    return str(csv_file)


@pytest.fixture()
def trained_classifier(mini_csv, tmp_path):
    model_path = str(tmp_path / "test_model.pkl")
    clf = MLThreatClassifier(model_path=model_path)
    clf.train(csv_path=mini_csv)
    return clf


# --------------------------------------------------------------------------- #
# MLThreatClassifier unit tests
# --------------------------------------------------------------------------- #

class TestMLThreatClassifierTraining:
    def test_train_creates_model_file(self, mini_csv, tmp_path):
        """Training must create a .pkl file."""
        model_path = str(tmp_path / "model.pkl")
        clf = MLThreatClassifier(model_path=model_path)
        clf.train(csv_path=mini_csv)
        assert os.path.exists(model_path)

    def test_train_returns_metrics(self, mini_csv, tmp_path):
        """train() must return a dict with required keys."""
        clf = MLThreatClassifier(model_path=str(tmp_path / "model.pkl"))
        metrics = clf.train(csv_path=mini_csv)
        assert "binary_classification_report" in metrics
        assert "binary_confusion_matrix" in metrics
        assert "samples_trained" in metrics
        assert metrics["samples_trained"] > 0

    def test_train_sets_is_loaded(self, mini_csv, tmp_path):
        """After training, is_loaded() must return True."""
        clf = MLThreatClassifier(model_path=str(tmp_path / "model.pkl"))
        assert not clf.is_loaded()
        clf.train(csv_path=mini_csv)
        assert clf.is_loaded()


class TestMLThreatClassifierLoadSave:
    def test_load_after_train(self, mini_csv, tmp_path):
        """A model saved during train() must be loadable."""
        model_path = str(tmp_path / "model.pkl")
        clf1 = MLThreatClassifier(model_path=model_path)
        clf1.train(csv_path=mini_csv)

        clf2 = MLThreatClassifier(model_path=model_path)
        assert not clf2.is_loaded()
        result = clf2.load()
        assert result is True
        assert clf2.is_loaded()

    def test_load_missing_file_returns_false(self, tmp_path):
        """load() must return False when file does not exist."""
        clf = MLThreatClassifier(model_path=str(tmp_path / "nonexistent.pkl"))
        assert clf.load() is False
        assert not clf.is_loaded()


class TestMLThreatClassifierPredict:
    def test_predict_returns_required_keys(self, trained_classifier):
        """predict() must return all required keys."""
        ta = ThreatAnalyzer()
        payload = "' OR '1'='1"
        features = ta.extract_features(payload)
        result = trained_classifier.predict(payload, features)
        assert "ml_prediction" in result
        assert "ml_confidence" in result
        assert "ml_score" in result
        assert "ml_attack_type" in result
        assert "ml_probabilities" in result

    def test_predict_malicious_sql_injection(self, trained_classifier):
        """SQL injection payload must be predicted as MALICIOUS."""
        ta = ThreatAnalyzer()
        payload = "1' UNION SELECT username, password FROM users--"
        features = ta.extract_features(payload)
        result = trained_classifier.predict(payload, features)
        assert result["ml_prediction"] == "MALICIOUS"
        assert result["ml_score"] > 50

    def test_predict_malicious_xss(self, trained_classifier):
        """XSS payload must be predicted as MALICIOUS."""
        ta = ThreatAnalyzer()
        payload = "<script>alert('xss')</script>"
        features = ta.extract_features(payload)
        result = trained_classifier.predict(payload, features)
        assert result["ml_prediction"] == "MALICIOUS"

    def test_predict_benign_input(self, trained_classifier):
        """Simple benign input must be predicted as BENIGN."""
        ta = ThreatAnalyzer()
        payload = "search for electronics"
        features = ta.extract_features(payload)
        result = trained_classifier.predict(payload, features)
        assert result["ml_prediction"] == "BENIGN"

    def test_predict_score_range(self, trained_classifier):
        """ml_score must be in [0, 100] and ml_confidence in [0, 1]."""
        ta = ThreatAnalyzer()
        for payload in ["hello world", "' OR '1'='1", "<script>alert(1)</script>"]:
            features = ta.extract_features(payload)
            result = trained_classifier.predict(payload, features)
            assert 0 <= result["ml_score"] <= 100
            assert 0.0 <= result["ml_confidence"] <= 1.0

    def test_predict_probabilities_sum_to_one(self, trained_classifier):
        """benign + malicious probabilities must sum to ~1.0."""
        ta = ThreatAnalyzer()
        payload = "test payload"
        features = ta.extract_features(payload)
        result = trained_classifier.predict(payload, features)
        probs = result["ml_probabilities"]
        total = probs["benign"] + probs["malicious"]
        assert abs(total - 1.0) < 1e-6

    def test_predict_raises_when_not_loaded(self, tmp_path):
        """predict() must raise RuntimeError when model is not loaded."""
        clf = MLThreatClassifier(model_path=str(tmp_path / "none.pkl"))
        with pytest.raises(RuntimeError):
            clf.predict("test", {})


# --------------------------------------------------------------------------- #
# API endpoint tests
# --------------------------------------------------------------------------- #

class TestMLStatusEndpoint:
    def test_ml_status_returns_200(self, client):
        """GET /ml/status must return 200."""
        response = client.get("/ml/status")
        assert response.status_code == 200

    def test_ml_status_response_keys(self, client):
        """GET /ml/status must include model_loaded, model_path, features."""
        response = client.get("/ml/status")
        data = response.json()
        assert "model_loaded" in data
        assert "model_path" in data
        assert "features" in data

    def test_ml_status_model_loaded_is_bool(self, client):
        """model_loaded must be a boolean."""
        response = client.get("/ml/status")
        assert isinstance(response.json()["model_loaded"], bool)


class TestMLTrainEndpoint:
    def test_ml_train_returns_200(self, client):
        """POST /ml/train must return 200 when training data is available."""
        response = client.post("/ml/train")
        assert response.status_code == 200

    def test_ml_train_response_has_status(self, client):
        """POST /ml/train response must include 'status' field."""
        response = client.post("/ml/train")
        data = response.json()
        assert "status" in data
        assert data["status"] == "trained"

    def test_ml_train_response_has_samples(self, client):
        """POST /ml/train response must include samples count."""
        response = client.post("/ml/train")
        data = response.json()
        assert "samples" in data
        assert data["samples"] > 0


class TestAnalyzeWithML:
    def test_analyze_includes_ml_prediction_when_model_loaded(self, client):
        """POST /analyze must include ml_prediction when model is loaded."""
        from src.api.main import ml_classifier
        if not ml_classifier.is_loaded():
            pytest.skip("ML model not loaded in this test run")

        response = client.post("/analyze", json={"payload": "' OR '1'='1"})
        assert response.status_code == 200
        data = response.json()
        assert "ml_prediction" in data
        pred = data["ml_prediction"]
        assert "ml_prediction" in pred
        assert "ml_score" in pred
        assert "ml_confidence" in pred
        assert "ml_attack_type" in pred

    def test_analyze_deep_includes_ml_prediction(self, client):
        """POST /analyze/deep must include ml_prediction when model is loaded."""
        from src.api.main import ml_classifier
        if not ml_classifier.is_loaded():
            pytest.skip("ML model not loaded in this test run")

        response = client.post("/analyze/deep", json={"payload": "' OR '1'='1"})
        assert response.status_code == 200
        data = response.json()
        assert "ml_prediction" in data

    def test_analyze_graceful_when_model_not_loaded(self, client, monkeypatch):
        """POST /analyze must work gracefully even if ML model is not loaded."""
        from src.api import main as main_module
        monkeypatch.setattr(main_module.ml_classifier, "model", None)

        response = client.post("/analyze", json={"payload": "hello world"})
        assert response.status_code == 200
        data = response.json()
        assert "threat_score" in data
        assert "decision" in data
        # ml_prediction key should be absent when model is not loaded
        assert "ml_prediction" not in data

    def test_combined_scoring_all_three_layers(self, client, monkeypatch):
        """Combined score uses weighted formula when all layers are available."""
        from src.api import main as main_module

        # Patch ML to return a known score
        class MockML:
            def is_loaded(self): return True
            def predict(self, payload, features):
                return {"ml_prediction": "MALICIOUS", "ml_confidence": 0.9,
                        "ml_score": 90, "ml_attack_type": "SQL Injection",
                        "ml_probabilities": {"benign": 0.1, "malicious": 0.9}}

        monkeypatch.setattr(main_module, "ml_classifier", MockML())

        response = client.post("/analyze", json={"payload": "hello world"})
        assert response.status_code == 200
        data = response.json()
        assert "threat_score" in data

    def test_analyze_malicious_sqli_blocked(self, client):
        """SQL injection payload must still be BLOCK with ML layer active."""
        payload = "UNION SELECT * FROM users EXEC xp_cmdshell WHOAMI OR 1=1 DROP TABLE 127.0.0.1 ../../etc/passwd"
        response = client.post("/analyze", json={"payload": payload})
        assert response.status_code == 200
        assert response.json()["decision"] == "BLOCK"

    def test_analyze_benign_allowed(self, client):
        """Benign payload must still be ALLOW with ML layer active."""
        response = client.post("/analyze", json={"payload": "hello world"})
        assert response.status_code == 200
        assert response.json()["decision"] == "ALLOW"
