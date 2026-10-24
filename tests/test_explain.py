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

