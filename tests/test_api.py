import pytest
from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)

def test_get_user_returns_user_data():
    """Test that GET /users?id=123 returns expected user JSON"""
    response = client.get("/users?id=123")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 123
    assert data["name"] == "example_user"

def test_get_user_different_id():
    """Test that the returned id matches the requested id"""
    response = client.get("/users?id=456")
    assert response.status_code == 200
    assert response.json()["id"] == 456

def test_get_user_missing_id_returns_422():
    """Test that GET /users without id returns 422 Unprocessable Entity"""
    response = client.get("/users")
    assert response.status_code == 422

def test_get_user_invalid_id_returns_422():
    """Test that a non-integer id returns 422 Unprocessable Entity"""
    response = client.get("/users?id=abc")
    assert response.status_code == 422

# --------------------------------------------------------------------------- #
# /analyze endpoint tests
# --------------------------------------------------------------------------- #

def test_analyze_malicious_payload_returns_block():
    """Malicious SQL injection payload should be scored > 60 and return BLOCK"""
    # Multi-vector payload: SQLi + command injection + internal IP → scores well above 60
    payload = "UNION SELECT * FROM users EXEC xp_cmdshell WHOAMI OR 1=1 DROP TABLE 127.0.0.1 ../../etc/passwd"
    response = client.post("/analyze", json={"payload": payload})
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "BLOCK"
    assert data["threat_score"] > 60

def test_analyze_benign_payload_returns_allow():
    """Normal payload should score <= 60 and return ALLOW"""
    response = client.post("/analyze", json={"payload": "hello world"})
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "ALLOW"
    assert data["threat_score"] <= 60

def test_analyze_response_includes_features():
    """Response must include a features dict"""
    response = client.post("/analyze", json={"payload": "test"})
    assert response.status_code == 200
    data = response.json()
    assert "features" in data
    assert isinstance(data["features"], dict)

def test_analyze_xss_payload_returns_block():
    """XSS payload with multiple vectors should be blocked"""
    # Multiple XSS indicators plus an internal IP reference to push score above 60
    payload = "<script>alert('xss')</script> javascript:fetch('http://127.0.0.1') onerror=1 onload=eval()"
    response = client.post("/analyze", json={"payload": payload})
    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"

# --------------------------------------------------------------------------- #
# WAF middleware tests
# --------------------------------------------------------------------------- #

def test_waf_blocks_malicious_query_param():
    """WAF should return 403 when query string contains a high-score attack payload"""
    # Multi-vector payload in query params: SQLi + command injection + internal IP
    malicious_q = "UNION SELECT password FROM users EXEC xp_cmdshell WHOAMI OR 1=1 127.0.0.1 ../../"
    response = client.get("/search", params={"q": malicious_q})
    assert response.status_code == 403

def test_waf_allows_benign_users_request():
    """WAF should allow clean /users requests"""
    response = client.get("/users?id=42")
    assert response.status_code == 200

def test_waf_health_always_accessible():
    """Health endpoint must bypass WAF"""
    response = client.get("/health")
    assert response.status_code == 200

def test_waf_analyze_always_accessible():
    """Analyze endpoint must bypass WAF (it does its own check)"""
    response = client.post("/analyze", json={"payload": "safe input"})
    assert response.status_code == 200

# --------------------------------------------------------------------------- #
# Feedback API mount tests
# --------------------------------------------------------------------------- #

def test_feedback_false_positives_accessible():
    """GET /feedback/dashboard/false-positives should return 200"""
    response = client.get("/feedback/dashboard/false-positives")
    assert response.status_code == 200
    data = response.json()
    assert "count" in data
    assert "items" in data

def test_feedback_statistics_accessible():
    """GET /feedback/analytics/statistics should return 200"""
    response = client.get("/feedback/analytics/statistics")
    assert response.status_code == 200
    data = response.json()
    assert "total_requests" in data

# --------------------------------------------------------------------------- #
# Prometheus metrics endpoint test
# --------------------------------------------------------------------------- #

def test_metrics_endpoint_returns_prometheus_format():
    """GET /metrics should return Prometheus text format with nebulashield metrics"""
    response = client.get("/metrics")
    assert response.status_code == 200
    assert b"nebulashield_requests_total" in response.content
