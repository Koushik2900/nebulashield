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
