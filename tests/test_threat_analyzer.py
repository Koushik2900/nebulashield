import pytest
from src.analyzer.threat_analyzer import ThreatAnalyzer

@pytest.fixture
def analyzer():
    return ThreatAnalyzer()

def test_sql_injection_detection(analyzer):
    """Test SQLi payload detection"""
    payload = "' OR '1'='1"
    features = analyzer.extract_features(payload)
    score = analyzer.calculate_threat_score(features, payload=payload)
    assert score > 10, "Should detect SQLi patterns"

def test_xss_detection(analyzer):
    """Test XSS payload detection"""
    payload = "<script>alert('xss')</script>"
    features = analyzer.extract_features(payload)
    score = analyzer.calculate_threat_score(features, payload=payload)
    assert score > 10, "Should detect XSS patterns"

def test_path_traversal_detection(analyzer):
    """Test path traversal detection"""
    payload = "../../etc/passwd"
    features = analyzer.extract_features(payload)
    score = analyzer.calculate_threat_score(features, payload=payload)
    assert score > 5, "Should detect path traversal"

def test_benign_request(analyzer):
    """Test normal request passes"""
    payload = "GET /api/users?id=123"
    features = analyzer.extract_features(payload)
    score = analyzer.calculate_threat_score(features, payload=payload)
    assert score < 30, "Should allow benign request"

# --------------------------------------------------------------------------- #
# Improved scoring tests (Issue 1)
# --------------------------------------------------------------------------- #

def test_sql_injection_or_equals_scores_above_60(analyzer):
    """Classic SQLi ' OR '1'='1 must score > 60 (BLOCK)."""
    payload = "' OR '1'='1"
    features = analyzer.extract_features(payload)
    score = analyzer.calculate_threat_score(features, payload=payload)
    assert score > 60, f"Expected > 60, got {score}"

def test_union_select_drop_scores_above_60(analyzer):
    """UNION SELECT + DROP TABLE must score > 60 (BLOCK)."""
    payload = "1' UNION SELECT username, password FROM users-- DROP TABLE users"
    features = analyzer.extract_features(payload)
    score = analyzer.calculate_threat_score(features, payload=payload)
    assert score > 60, f"Expected > 60, got {score}"

def test_xss_script_tag_scores_above_60(analyzer):
    """<script>alert('xss')</script> must score > 60 (BLOCK)."""
    payload = "<script>alert('xss')</script>"
    features = analyzer.extract_features(payload)
    score = analyzer.calculate_threat_score(features, payload=payload)
    assert score > 60, f"Expected > 60, got {score}"

def test_command_injection_scores_above_60(analyzer):
    """; cat /etc/passwd | whoami must score > 60 (BLOCK)."""
    payload = "; cat /etc/passwd | whoami"
    features = analyzer.extract_features(payload)
    score = analyzer.calculate_threat_score(features, payload=payload)
    assert score > 60, f"Expected > 60, got {score}"

def test_path_traversal_deep_scores_above_60(analyzer):
    """../../etc/passwd must score > 60 (BLOCK)."""
    payload = "../../etc/passwd"
    features = analyzer.extract_features(payload)
    score = analyzer.calculate_threat_score(features, payload=payload)
    assert score > 60, f"Expected > 60, got {score}"

def test_benign_search_scores_below_60(analyzer):
    """Plain English search query must score < 60 (ALLOW)."""
    payload = "search for electronics"
    features = analyzer.extract_features(payload)
    score = analyzer.calculate_threat_score(features, payload=payload)
    assert score < 60, f"Expected < 60, got {score}"
