from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.db import Base, get_db
from app.main import app

TEST_DATABASE_URL = "sqlite:///:memory:"

@pytest.fixture
def client():
    engine = create_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

def test_explain_alert_not_found(client):
    res = client.post("/alerts/999/explain")
    assert res.status_code == 404
    assert res.json()["detail"] == "Alert not found"

def test_explain_alert_missing_api_key(client, monkeypatch):
    client.post("/demo/load")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with patch("app.main.load_dotenv"):
        res = client.post("/alerts/1/explain")
        assert res.status_code == 503
        assert "Set OPENAI_API_KEY in .env" in res.json()["detail"]

def test_explain_alert_success(client, monkeypatch):
    client.post("/demo/load")
    monkeypatch.setenv("OPENAI_API_KEY", "test-api-key")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-5.5")

    mock_response = MagicMock()
    mock_response.output_text = (
        "### Summary\n"
        "PowerShell was executed on workstation.\n\n"
        "### Evidence\n"
        "Observed command line: powershell.exe -NoProfile.\n\n"
        "### Possible Impact\n"
        "Hypothesis: Legitimate admin activity or script execution.\n\n"
        "### Investigation Steps\n"
        "1. Check parent process.\n"
        "2. Review script block logs.\n"
        "3. Interview user alice."
    )

    with patch("openai.OpenAI") as mock_openai_cls:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.responses.create.return_value = mock_response

        res = client.post("/alerts/1/explain")
        assert res.status_code == 200
        data = res.json()
        assert data["alert_id"] == 1
        assert "Summary" in data["explanation"]
        assert "Investigation Steps" in data["explanation"]

        mock_client.responses.create.assert_called_once()
        call_kwargs = mock_client.responses.create.call_args[1]
        assert call_kwargs["model"] == "gpt-5.5"
        assert "cautious SOC assistant" in call_kwargs["instructions"]
        assert "Never claim a host is compromised without evidence" in call_kwargs["instructions"]
        assert "Alert title:" in call_kwargs["input"]

def test_legacy_explain_redacts_secret_before_provider_call(client, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-api-key")
    client.post("/events", json={
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand",
        "message": "api_key=sk-demo-secret",
    })
    monkeypatch.setenv("OPENAI_MODEL", "gpt-5.5")
    response_mock = MagicMock()
    response_mock.output_text = "Advisory"

    with patch("openai.OpenAI") as mock_openai_cls:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.responses.create.return_value = response_mock

        response = client.post("/alerts/1/explain")

    assert response.status_code == 200
    sent_input = mock_client.responses.create.call_args.kwargs["input"]
    assert "sk-demo-secret" not in sent_input
    assert "[REDACTED]" in sent_input

def test_explain_alert_mock_mode(client, monkeypatch):
    client.post("/demo/load")
    monkeypatch.setenv("OPENAI_API_KEY", "mock")

    res = client.post("/alerts/1/explain")
    assert res.status_code == 200
    data = res.json()
    assert data["alert_id"] == 1
    assert "### 1. Alert Summary" in data["explanation"]
    assert "### 2. Evidence (Observed Facts)" in data["explanation"]
    assert "### 3. Possible Impact (Hypotheses vs Facts)" in data["explanation"]
    assert "### 4. Safe Investigation Steps" in data["explanation"]

def test_assistant_creates_structured_advisory_and_records_review(client, monkeypatch):
    client.post("/demo/load")
    monkeypatch.setenv("OPENAI_API_KEY", "mock")

    response = client.post("/alerts/1/assist")

    assert response.status_code == 200
    run = response.json()
    assert len(run["result"]["summary_lines"]) == 5
    assert len(run["result"]["investigation_queries"]) == 3
    assert run["result"]["technique_id"] == "T1059.001"
    assert run["review_status"] == "needs_review"
    assert run["model"] == "mock"

    history = client.get("/alerts/1/assistant-runs")
    assert history.status_code == 200
    assert history.json()[0]["prompt_version"] == "tier1-v1"

    reviewed = client.patch(
        f"/assistant-runs/{run['id']}/review",
        json={"reviewed_by": " SOC analyst "},
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["review_status"] == "reviewed"
    assert reviewed.json()["reviewed_by"] == "SOC analyst"
    assert reviewed.json()["reviewed_at"]

def test_assistant_redacts_common_secrets_from_logged_prompt(client, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "mock")
    ingest = client.post("/events", json={
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand api_key=sk-demo-secret",
    })
    assert ingest.status_code == 200
    alerts = client.get("/alerts").json()
    alert = next(item for item in alerts if item["rule_id"] == "AM-004")

    response = client.post(f"/alerts/{alert['id']}/assist")

    assert response.status_code == 200
    history = client.get(f"/alerts/{alert['id']}/assistant-runs").json()
    assert "sk-demo-secret" not in history[0]["prompt_text"]
    assert "[REDACTED]" in history[0]["prompt_text"]

def test_assistant_rejects_malformed_model_output(client, monkeypatch):
    client.post("/demo/load")
    monkeypatch.setenv("OPENAI_API_KEY", "test-api-key")

    with patch("openai.OpenAI") as mock_openai_cls:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.responses.create.return_value.output_text = "not valid JSON"

        response = client.post("/alerts/1/assist")

    assert response.status_code == 502
    assert "did not match the assistant schema" in response.json()["detail"]
