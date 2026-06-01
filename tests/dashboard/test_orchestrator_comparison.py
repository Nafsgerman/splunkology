"""Tests for /api/orchestrator-comparison/{case_id} endpoint."""

from fastapi.testclient import TestClient

EXPECTED_ORCH_IDS = [
    "splunkology-v2",
    "splunkology-langgraph",
    "splunkology-openai-fc",
    "splunkology-gemini",
    "splunkology-claudecode",
]


def test_comparison_returns_200():
    from splunkology.dashboard.app import app

    client = TestClient(app)
    r = client.get("/api/orchestrator-comparison/CASE-001")
    assert r.status_code == 200


def test_comparison_has_rows_key():
    from splunkology.dashboard.app import app

    client = TestClient(app)
    data = client.get("/api/orchestrator-comparison/CASE-001").json()
    assert "rows" in data


def test_comparison_has_five_orchestrators():
    from splunkology.dashboard.app import app

    client = TestClient(app)
    data = client.get("/api/orchestrator-comparison/CASE-001").json()
    assert len(data["rows"]) == 5
    for orch_id in EXPECTED_ORCH_IDS:
        assert orch_id in data["rows"]


def test_comparison_has_coverage():
    from splunkology.dashboard.app import app

    client = TestClient(app)
    data = client.get("/api/orchestrator-comparison/CASE-001").json()
    assert "coverage" in data
    assert "hits" in data["coverage"]
    assert "total" in data["coverage"]
    assert data["coverage"]["total"] > 0


def test_comparison_case_filter_default_all():
    from splunkology.dashboard.app import app

    client = TestClient(app)
    data = client.get("/api/orchestrator-comparison/CASE-001").json()
    assert data["case_filter"] == "all"


def test_comparison_case_filter_param():
    from splunkology.dashboard.app import app

    client = TestClient(app)
    data = client.get("/api/orchestrator-comparison/CASE-001?case=TEST-001").json()
    assert data["case_filter"] == "TEST-001"


def test_comparison_available_cases_present():
    from splunkology.dashboard.app import app

    client = TestClient(app)
    data = client.get("/api/orchestrator-comparison/CASE-001").json()
    assert "available_cases" in data
    assert "bots_apt" in data["available_cases"]


def test_comparison_row_shape():
    from splunkology.dashboard.app import app

    client = TestClient(app)
    data = client.get("/api/orchestrator-comparison/CASE-001").json()
    for _orch_id, row in data["rows"].items():
        assert "n_cases" in row
        assert "case_scores" in row
        # mean_f1 may be None if no runs yet — that's valid
        assert "mean_f1" in row
