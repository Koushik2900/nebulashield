"""
Tests for the LLM analyzer (AdaptiveLLMAnalyzer) and the /analyze/deep endpoint.
LLM backend calls are mocked so tests run without any real LLM service.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
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
from src.analyzer.llm_analyzer import AdaptiveLLMAnalyzer, _parse_llm_response, _build_prompt

# --------------------------------------------------------------------------- #
# In-memory DB fixture (mirrors test_db_integration.py)
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
# Unit tests for _parse_llm_response
# --------------------------------------------------------------------------- #

def test_parse_valid_llm_json():
    raw = '{"classification": "MALICIOUS", "confidence": 95, "attack_type": "SQL Injection", "explanation": "Union select.", "llm_score": 90}'
    result = _parse_llm_response(raw)
    assert result is not None
    assert result["classification"] == "MALICIOUS"
    assert result["llm_score"] == 90


def test_parse_llm_json_embedded_in_text():
    raw = 'Sure! Here is the answer: {"classification": "BENIGN", "confidence": 10, "attack_type": "None", "explanation": "Normal.", "llm_score": 5} Done.'
    result = _parse_llm_response(raw)
    assert result is not None
    assert result["classification"] == "BENIGN"


def test_parse_llm_json_missing_required_fields():
    raw = '{"classification": "MALICIOUS"}'  # missing llm_score
    result = _parse_llm_response(raw)
    assert result is None


def test_parse_llm_json_invalid():
    result = _parse_llm_response("not json at all")
    assert result is None


# --------------------------------------------------------------------------- #
# Unit tests for _build_prompt
# --------------------------------------------------------------------------- #

def test_build_prompt_contains_payload():
    payload = "' OR '1'='1"
    features = {"sql_keywords_count": 1, "suspicious_quotes": 4}
    prompt = _build_prompt(payload, features, 54.1)
    assert payload in prompt
    assert "54.1" in prompt


# --------------------------------------------------------------------------- #
# Unit tests for AdaptiveLLMAnalyzer
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_llm_analyzer_returns_structured_response_ollama():
    """Mocked Ollama response is parsed into a structured dict."""
    mock_response = {
        "classification": "MALICIOUS",
        "confidence": 95,
        "attack_type": "SQL Injection",
        "explanation": "Classic union-based SQL injection.",
        "llm_score": 90,
    }
    llm = AdaptiveLLMAnalyzer()
    llm.backend = "ollama"

    with patch.object(llm, "_query_ollama", new=AsyncMock(return_value=mock_response)):
        result = await llm.analyze_payload("' OR '1'='1", {}, 54.1)

    assert result is not None
    assert result["classification"] == "MALICIOUS"
    assert result["llm_score"] == 90


@pytest.mark.asyncio
async def test_llm_analyzer_returns_none_on_timeout():
    """When the LLM backend times out, analyze_payload returns None."""
    import asyncio
    llm = AdaptiveLLMAnalyzer()
    llm.backend = "ollama"

    with patch.object(llm, "_query_ollama", new=AsyncMock(side_effect=asyncio.TimeoutError())):
        result = await llm.analyze_payload("' OR '1'='1", {}, 54.1)

    assert result is None


@pytest.mark.asyncio
async def test_llm_analyzer_returns_none_on_connection_error():
    """When the LLM backend is unreachable, analyze_payload returns None."""
    llm = AdaptiveLLMAnalyzer()
    llm.backend = "ollama"

    with patch.object(llm, "_query_ollama", new=AsyncMock(side_effect=Exception("Connection refused"))):
        result = await llm.analyze_payload("payload", {}, 40.0)

    assert result is None


# --------------------------------------------------------------------------- #
# is_available() tests for all backends
# --------------------------------------------------------------------------- #

def test_llm_is_available_groq_with_key(monkeypatch):
    """is_available() returns True for Groq when API key is set."""
    monkeypatch.setenv("LLM_BACKEND", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test_key")
    llm = AdaptiveLLMAnalyzer()
    assert llm.is_available() is True


def test_llm_is_available_groq_without_key(monkeypatch):
    """is_available() returns False for Groq when no API key."""
    monkeypatch.setenv("LLM_BACKEND", "groq")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    llm = AdaptiveLLMAnalyzer()
    assert llm.is_available() is False


def test_llm_is_available_gemini_with_key(monkeypatch):
    """is_available() returns True for Gemini when API key is set."""
    monkeypatch.setenv("LLM_BACKEND", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "gemini_test_key")
    llm = AdaptiveLLMAnalyzer()
    assert llm.is_available() is True


def test_llm_is_available_gemini_without_key(monkeypatch):
    """is_available() returns False for Gemini when no API key."""
    monkeypatch.setenv("LLM_BACKEND", "gemini")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    llm = AdaptiveLLMAnalyzer()
    assert llm.is_available() is False


def test_llm_is_available_openrouter_with_key(monkeypatch):
    """is_available() returns True for OpenRouter when API key is set."""
    monkeypatch.setenv("LLM_BACKEND", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test_key")
    llm = AdaptiveLLMAnalyzer()
    assert llm.is_available() is True


def test_llm_is_available_openrouter_without_key(monkeypatch):
    """is_available() returns False for OpenRouter when no API key."""
    monkeypatch.setenv("LLM_BACKEND", "openrouter")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    llm = AdaptiveLLMAnalyzer()
    assert llm.is_available() is False


def test_llm_is_available_openai_with_key(monkeypatch):
    """is_available() returns True for OpenAI when API key is set."""
    monkeypatch.setenv("LLM_BACKEND", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
    llm = AdaptiveLLMAnalyzer()
    assert llm.is_available() is True


def test_llm_is_available_openai_without_key(monkeypatch):
    """is_available() returns False for OpenAI when no API key."""
    monkeypatch.setenv("LLM_BACKEND", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    llm = AdaptiveLLMAnalyzer()
    assert llm.is_available() is False


def test_llm_is_available_ollama_unreachable(monkeypatch):
    """is_available() returns False when Ollama server is not reachable."""
    monkeypatch.setenv("LLM_BACKEND", "ollama")
    monkeypatch.setenv("OLLAMA_URL", "http://127.0.0.1:19999")
    llm = AdaptiveLLMAnalyzer()
    assert llm.is_available() is False


# --------------------------------------------------------------------------- #
# Default model selection tests
# --------------------------------------------------------------------------- #

def test_default_model_groq(monkeypatch):
    """Groq backend defaults to llama-3.3-70b-versatile."""
    monkeypatch.setenv("LLM_BACKEND", "groq")
    monkeypatch.delenv("LLM_MODEL", raising=False)
    llm = AdaptiveLLMAnalyzer()
    assert llm.model == "llama-3.3-70b-versatile"


def test_default_model_gemini(monkeypatch):
    """Gemini backend defaults to gemini-2.0-flash."""
    monkeypatch.setenv("LLM_BACKEND", "gemini")
    monkeypatch.delenv("LLM_MODEL", raising=False)
    llm = AdaptiveLLMAnalyzer()
    assert llm.model == "gemini-2.0-flash"


def test_default_model_openrouter(monkeypatch):
    """OpenRouter backend defaults to meta-llama/llama-3.3-70b-instruct:free."""
    monkeypatch.setenv("LLM_BACKEND", "openrouter")
    monkeypatch.delenv("LLM_MODEL", raising=False)
    llm = AdaptiveLLMAnalyzer()
    assert llm.model == "meta-llama/llama-3.3-70b-instruct:free"


def test_default_model_openai(monkeypatch):
    """OpenAI backend defaults to gpt-4o-mini."""
    monkeypatch.setenv("LLM_BACKEND", "openai")
    monkeypatch.delenv("LLM_MODEL", raising=False)
    llm = AdaptiveLLMAnalyzer()
    assert llm.model == "gpt-4o-mini"


def test_default_model_ollama(monkeypatch):
    """Ollama backend defaults to llama3.2."""
    monkeypatch.setenv("LLM_BACKEND", "ollama")
    monkeypatch.delenv("LLM_MODEL", raising=False)
    llm = AdaptiveLLMAnalyzer()
    assert llm.model == "llama3.2"


def test_model_override(monkeypatch):
    """LLM_MODEL env var overrides the default model for any backend."""
    monkeypatch.setenv("LLM_BACKEND", "groq")
    monkeypatch.setenv("LLM_MODEL", "mixtral-8x7b-32768")
    llm = AdaptiveLLMAnalyzer()
    assert llm.model == "mixtral-8x7b-32768"


# --------------------------------------------------------------------------- #
# _query_openai_compatible tests (mocked) for Groq, OpenRouter, OpenAI
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_query_openai_compatible_groq():
    """_query_openai_compatible routes Groq calls correctly."""
    mock_response = {
        "classification": "MALICIOUS",
        "confidence": 90,
        "attack_type": "SQL Injection",
        "explanation": "SQL injection detected.",
        "llm_score": 88,
    }
    llm = AdaptiveLLMAnalyzer()
    llm.backend = "groq"
    llm.groq_api_key = "gsk_test"

    with patch.object(llm, "_query_openai_compatible", new=AsyncMock(return_value=mock_response)):
        result = await llm.analyze_payload("' OR '1'='1", {}, 54.0)

    assert result is not None
    assert result["classification"] == "MALICIOUS"


@pytest.mark.asyncio
async def test_query_openai_compatible_openrouter():
    """_query_openai_compatible routes OpenRouter calls correctly."""
    mock_response = {
        "classification": "BENIGN",
        "confidence": 10,
        "attack_type": "None",
        "explanation": "Normal input.",
        "llm_score": 5,
    }
    llm = AdaptiveLLMAnalyzer()
    llm.backend = "openrouter"
    llm.openrouter_api_key = "sk-or-test"

    with patch.object(llm, "_query_openai_compatible", new=AsyncMock(return_value=mock_response)):
        result = await llm.analyze_payload("hello world", {}, 5.0)

    assert result is not None
    assert result["classification"] == "BENIGN"


@pytest.mark.asyncio
async def test_query_openai_compatible_openai():
    """_query_openai_compatible routes OpenAI calls correctly."""
    mock_response = {
        "classification": "SUSPICIOUS",
        "confidence": 55,
        "attack_type": "Other",
        "explanation": "Possibly suspicious.",
        "llm_score": 50,
    }
    llm = AdaptiveLLMAnalyzer()
    llm.backend = "openai"
    llm.openai_api_key = "sk-test"

    with patch.object(llm, "_query_openai_compatible", new=AsyncMock(return_value=mock_response)):
        result = await llm.analyze_payload("suspicious input", {}, 45.0)

    assert result is not None
    assert result["classification"] == "SUSPICIOUS"


# --------------------------------------------------------------------------- #
# _query_gemini tests (mocked)
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_query_gemini_parses_response():
    """_query_gemini returns structured dict from mocked Gemini response."""
    mock_response = {
        "classification": "MALICIOUS",
        "confidence": 92,
        "attack_type": "XSS",
        "explanation": "XSS script tag detected.",
        "llm_score": 85,
    }
    llm = AdaptiveLLMAnalyzer()
    llm.backend = "gemini"
    llm.gemini_api_key = "test_key"

    with patch.object(llm, "_query_gemini", new=AsyncMock(return_value=mock_response)):
        result = await llm.analyze_payload("<script>alert(1)</script>", {}, 55.0)

    assert result is not None
    assert result["attack_type"] == "XSS"


@pytest.mark.asyncio
async def test_query_gemini_returns_none_on_error():
    """_query_gemini returns None when the API call fails."""
    llm = AdaptiveLLMAnalyzer()
    llm.backend = "gemini"
    llm.gemini_api_key = "test_key"

    with patch.object(llm, "_query_gemini", new=AsyncMock(side_effect=Exception("API error"))):
        result = await llm.analyze_payload("payload", {}, 40.0)

    assert result is None


# --------------------------------------------------------------------------- #
# Fallback when no API key is set
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_groq_fallback_no_api_key(monkeypatch):
    """When GROQ_API_KEY is not set, analyze_payload should still not raise."""
    monkeypatch.setenv("LLM_BACKEND", "groq")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    llm = AdaptiveLLMAnalyzer()
    # _query_openai_compatible will raise due to missing key — should return None
    result = await llm.analyze_payload("test payload", {}, 40.0)
    assert result is None


# --------------------------------------------------------------------------- #
# Integration tests for /analyze with LLM mocked
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_analyze_grey_zone_triggers_llm(client):
    """/analyze with a grey-zone heuristic score should call LLM and combine scores."""
    mock_llm_result = {
        "classification": "MALICIOUS",
        "confidence": 88,
        "attack_type": "SQL Injection",
        "explanation": "Union select detected.",
        "llm_score": 85,
    }

    with patch("src.api.main.llm_analyzer.analyze_payload", new=AsyncMock(return_value=mock_llm_result)):
        # Use a payload that naturally falls in the grey zone heuristically
        # (we mock calculate_threat_score indirectly via the endpoint)
        response = client.post("/analyze", json={"payload": "search terms OR filter"})

    assert response.status_code == 200
    data = response.json()
    assert "heuristic_score" in data
    assert "threat_score" in data


def test_analyze_heuristic_only_when_llm_unavailable(client):
    """When LLM returns None (unavailable), the heuristic score is used alone."""
    with patch("src.api.main.llm_analyzer.analyze_payload", new=AsyncMock(return_value=None)):
        response = client.post("/analyze", json={"payload": "hello world"})

    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "ALLOW"
    # No LLM analysis in response when unavailable
    assert "llm_analysis" not in data or data.get("llm_analysis") is None


# --------------------------------------------------------------------------- #
# Integration tests for POST /analyze/deep
# --------------------------------------------------------------------------- #

def test_analyze_deep_endpoint_exists(client):
    """POST /analyze/deep should return 200."""
    with patch("src.api.main.llm_analyzer.analyze_payload", new=AsyncMock(return_value=None)):
        response = client.post("/analyze/deep", json={"payload": "hello world"})
    assert response.status_code == 200


def test_analyze_deep_returns_full_analysis(client):
    """POST /analyze/deep must return heuristic_score, threat_score, llm_available."""
    mock_llm_result = {
        "classification": "MALICIOUS",
        "confidence": 97,
        "attack_type": "SQL Injection",
        "explanation": "Clear SQL injection.",
        "llm_score": 92,
    }
    with patch("src.api.main.llm_analyzer.analyze_payload", new=AsyncMock(return_value=mock_llm_result)):
        response = client.post(
            "/analyze/deep",
            json={"payload": "1' UNION SELECT username, password FROM users--"},
        )

    assert response.status_code == 200
    data = response.json()
    assert "threat_score" in data
    assert "heuristic_score" in data
    assert "decision" in data
    assert "features" in data
    assert "llm_available" in data
    assert data["llm_available"] is True
    assert data["llm_analysis"]["attack_type"] == "SQL Injection"


def test_analyze_deep_graceful_degradation(client):
    """POST /analyze/deep works even when LLM is unavailable (returns None)."""
    with patch("src.api.main.llm_analyzer.analyze_payload", new=AsyncMock(return_value=None)):
        response = client.post(
            "/analyze/deep",
            json={"payload": "' OR '1'='1"},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["llm_available"] is False
    assert data["decision"] == "BLOCK"  # heuristic alone should block this


def test_analyze_deep_combines_scores(client):
    """Combined score = 0.4*heuristic + 0.6*llm_score when LLM available."""
    mock_llm_result = {
        "classification": "MALICIOUS",
        "confidence": 90,
        "attack_type": "XSS",
        "explanation": "XSS detected.",
        "llm_score": 80,
    }
    with patch("src.api.main.llm_analyzer.analyze_payload", new=AsyncMock(return_value=mock_llm_result)):
        response = client.post(
            "/analyze/deep",
            json={"payload": "<script>alert(1)</script>"},
        )
    assert response.status_code == 200
    data = response.json()
    # Combined score formula: 0.4 * heuristic + 0.6 * 80
    # heuristic for <script> tag is > 60, so combined should also be > 60
    assert data["decision"] == "BLOCK"
    assert data["threat_score"] != data["heuristic_score"]


# --------------------------------------------------------------------------- #
# Tests for GET /llm/status endpoint
# --------------------------------------------------------------------------- #

def test_llm_status_endpoint_returns_200(client, monkeypatch):
    """GET /llm/status should return 200 with backend info."""
    monkeypatch.setenv("LLM_BACKEND", "groq")
    response = client.get("/llm/status")
    assert response.status_code == 200
    data = response.json()
    assert "backend" in data
    assert "model" in data
    assert "available" in data


def test_llm_status_available_true_when_key_set(client, monkeypatch):
    """GET /llm/status returns available=True when the API key is configured."""
    import src.api.main as main_module
    original_analyzer = main_module.llm_analyzer

    mock_analyzer = MagicMock()
    mock_analyzer.backend = "groq"
    mock_analyzer.model = "llama-3.3-70b-versatile"
    mock_analyzer.is_available.return_value = True

    main_module.llm_analyzer = mock_analyzer
    try:
        response = client.get("/llm/status")
        assert response.status_code == 200
        data = response.json()
        assert data["backend"] == "groq"
        assert data["model"] == "llama-3.3-70b-versatile"
        assert data["available"] is True
    finally:
        main_module.llm_analyzer = original_analyzer


def test_llm_status_available_false_when_no_key(client, monkeypatch):
    """GET /llm/status returns available=False when no API key is configured."""
    import src.api.main as main_module
    original_analyzer = main_module.llm_analyzer

    mock_analyzer = MagicMock()
    mock_analyzer.backend = "groq"
    mock_analyzer.model = "llama-3.3-70b-versatile"
    mock_analyzer.is_available.return_value = False

    main_module.llm_analyzer = mock_analyzer
    try:
        response = client.get("/llm/status")
        assert response.status_code == 200
        data = response.json()
        assert data["available"] is False
    finally:
        main_module.llm_analyzer = original_analyzer

