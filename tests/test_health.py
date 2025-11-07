# tests/test_health.py

import os
import sys

# Ensure the user-management directory (parent of tests/) is on the import path
CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient  # note: lowercase "c" in testclient
from main import app

client = TestClient(app)


def test_root_message():
    """Verify that GET / returns the welcome message."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "Welcome" in data["message"]


def test_health_no_path():
    """Verify /health returns a 200 and proper JSON structure."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == 200
    assert data["status_message"] == "OK"
    assert "timestamp" in data
    assert "ip_address" in data


def test_health_with_path_and_echo():
    """Verify /health/{path_echo}?echo= works correctly."""
    response = client.get("/health/testpath?echo=hello")
    assert response.status_code == 200
    data = response.json()
    assert data["path_echo"] == "testpath"
    assert data["echo"] == "hello"
