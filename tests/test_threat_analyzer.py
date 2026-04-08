import pytest
from src.analyzer.threat_analyzer import ThreatAnalyzer

@pytest.fixture
def analyzer():
    return ThreatAnalyzer()

def test_sql_injection_detection(analyzer):
    """Test SQLi payload detection"""
    payload = "' OR '1'='1"
    features = analyzer.extract_features(payload)
    score = analyzer.calculate_threat_score(features)
    assert score > 10, "Should detect SQLi patterns"

def test_xss_detection(analyzer):
    """Test XSS payload detection"""
    payload = "<script>alert('xss')</script>"
    features = analyzer.extract_features(payload)
    score = analyzer.calculate_threat_score(features)
    assert score > 10, "Should detect XSS patterns"

def test_path_traversal_detection(analyzer):
    """Test path traversal detection"""
    payload = "../../etc/passwd"
    features = analyzer.extract_features(payload)
    score = analyzer.calculate_threat_score(features)
    assert score > 5, "Should detect path traversal"

def test_benign_request(analyzer):
    """Test normal request passes"""
    payload = "GET /api/users?id=123"
    features = analyzer.extract_features(payload)
    score = analyzer.calculate_threat_score(features)
    assert score < 30, "Should allow benign request"
