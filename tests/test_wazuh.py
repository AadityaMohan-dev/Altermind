import pytest
from pathlib import Path
from xml.etree import ElementTree
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.wazuh import normalize_wazuh_alert


@pytest.fixture
def client():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    engine.dispose()


def test_normalize_wazuh_sysmon_process_alert():
    event = normalize_wazuh_alert({
        "id": "1761828000.123",
        "timestamp": "2026-10-30T10:00:00Z",
        "rule": {"id": "100001", "description": "PowerShell process"},
        "agent": {"id": "007", "name": "windows-lab"},
        "data": {
            "win": {
                "system": {"eventID": "1"},
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "commandLine": "powershell.exe -EncodedCommand demo",
                    "user": "LAB\\student",
                },
            },
        },
        "location": "EventChannel",
    })

    assert event.event_type == "process_creation"
    assert event.username == "LAB\\student"
    assert event.process_name.endswith("powershell.exe")
    assert event.command_line.endswith("-EncodedCommand demo")
    assert event.timestamp is not None
    assert "Wazuh rule 100001" in event.message


def test_normalize_wazuh_linux_authentication_and_cloud_events():
    ssh_event = normalize_wazuh_alert({
        "rule": {"id": "5710", "groups": ["sshd", "authentication_failed"]},
        "data": {"srcip": "192.0.2.10", "srcuser": "student"},
        "full_log": "Failed password for student",
    })
    cloud_event = normalize_wazuh_alert({
        "data": {
            "aws": {
                "eventName": "ConsoleLogin",
                "sourceIPAddress": "192.0.2.20",
                "userIdentity": {"userName": "lab-user"},
            },
        },
    })

    assert ssh_event.event_type == "ssh_failed_login"
    assert ssh_event.source_ip == "192.0.2.10"
    assert cloud_event.event_type == "cloud_console_login"
    assert cloud_event.source_ip == "192.0.2.20"
    assert cloud_event.username == "lab-user"


def test_normalize_wazuh_rejects_invalid_data_shape():
    with pytest.raises(ValueError, match="'data' field"):
        normalize_wazuh_alert({"data": ["not", "an", "object"]})

def test_normalize_wazuh_rejects_invalid_nested_fields():
    with pytest.raises(ValueError, match="rule.groups"):
        normalize_wazuh_alert({
            "rule": {"groups": 7},
            "data": {},
        })

    with pytest.raises(ValueError, match="win.eventdata"):
        normalize_wazuh_alert({
            "rule": {},
            "data": {"win": {"eventdata": "unexpected"}},
        })

def test_normalize_wazuh_falls_back_when_event_id_is_missing():
    event = normalize_wazuh_alert({
        "rule": {"id": "900001", "description": "Unmapped lab alert"},
        "agent": {"id": "001"},
        "data": {},
    })

    assert event.event_type == "wazuh_alert_900001"

def test_wazuh_xml_examples_are_well_formed():
    root = Path(__file__).resolve().parents[1]
    integration_xml = (root / "integrations" / "ossec.conf.example.xml").read_text(
        encoding="utf-8"
    )
    source_xml = (root / "integrations" / "agent-log-source-examples.xml").read_text(
        encoding="utf-8"
    )
    cloudtrail_xml = (
        root / "integrations" / "cloudtrail-wodle.example.xml"
    ).read_text(encoding="utf-8")

    integration = ElementTree.fromstring(f"<ossec_config>{integration_xml}</ossec_config>")
    sources = ElementTree.fromstring(f"<ossec_config>{source_xml}</ossec_config>")
    cloudtrail = ElementTree.fromstring(f"<ossec_config>{cloudtrail_xml}</ossec_config>")

    assert integration.findtext("integration/name") == "custom-alertmind"
    assert integration.findtext("integration/alert_format") == "json"
    assert len(sources.findall("localfile")) == 3
    assert cloudtrail.find("wodle[@name='aws-s3']/bucket") is not None


def test_wazuh_api_requires_token_and_is_idempotent(client, monkeypatch):
    payload = {
        "id": "1761828000.123",
        "timestamp": "2026-10-30T10:00:00Z",
        "rule": {"id": "100001", "description": "PowerShell process"},
        "agent": {"id": "007", "name": "windows-lab"},
        "data": {
            "win": {
                "system": {"eventID": "1"},
                "eventdata": {
                    "image": "powershell.exe",
                    "commandLine": "powershell.exe -EncodedCommand demo",
                    "user": "student",
                },
            },
        },
    }

    disabled = client.post("/integrations/wazuh/alerts", json=payload)
    assert disabled.status_code == 503

    monkeypatch.setenv("WAZUH_INGEST_TOKEN", "test-token")
    unauthorized = client.post("/integrations/wazuh/alerts", json=payload)
    assert unauthorized.status_code == 401

    headers = {"X-Wazuh-Token": "test-token"}
    first = client.post("/integrations/wazuh/alerts", json=payload, headers=headers)
    second = client.post("/integrations/wazuh/alerts", json=payload, headers=headers)

    assert first.status_code == 200
    assert first.json()["duplicate"] is False
    assert first.json()["alerts_created"] >= 1
    assert second.status_code == 200
    assert second.json()["duplicate"] is True
    assert second.json()["event"]["id"] == first.json()["event"]["id"]
    assert len(client.get("/events").json()) == 1
    alerts = client.get("/alerts").json()
    assert len(alerts) == 2
    assert {alert["rule_id"] for alert in alerts} == {"AM-001", "AM-004"}
