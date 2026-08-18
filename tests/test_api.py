"""Tests for api.main"""

from pathlib import Path
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_iam_export.json"


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_analyze_valid_fixture():
    with open(FIXTURE_PATH, "rb") as f:
        response = client.post("/analyze", files={"file": ("sample.json", f, "application/json")})

    assert response.status_code == 200
    body = response.json()

    assert body["summary"]["principal_count"] == 3
    assert body["summary"]["finding_count"] == 1
    assert len(body["findings"]) == 1
    assert body["findings"][0]["principal_name"] == "test-user"
    assert len(body["graph"]["nodes"]) == 3
    assert len(body["graph"]["edges"]) == 1


def test_analyze_rejects_invalid_json():
    response = client.post(
        "/analyze",
        files={"file": ("bad.json", b"{ not valid json", "application/json")},
    )
    assert response.status_code == 400
    assert "Invalid JSON" in response.json()["detail"]


def test_analyze_rejects_oversized_file():
    """File larger than MAX_UPLOAD_BYTES (5MB) should be rejected with 413."""
    oversized_content = b'{"UserDetailList": []}' + b" " * (6 * 1024 * 1024)
    response = client.post(
        "/analyze",
        files={"file": ("huge.json", oversized_content, "application/json")},
    )
    assert response.status_code == 413


def test_analyze_rejects_malformed_iam_structure():
    """Valid JSON, but doesn't match expected IAM export shape (e.g. missing required Arn field)."""
    malformed = b'{"UserDetailList": [{"UserName": "no-arn-field"}]}'
    response = client.post(
        "/analyze",
        files={"file": ("malformed.json", malformed, "application/json")},
    )
    assert response.status_code == 400
    assert "Could not parse" in response.json()["detail"]
