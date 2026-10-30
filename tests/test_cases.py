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

def test_demo_load_and_list_alerts(client):
    res = client.post("/demo/load")
    assert res.status_code == 200
    data = res.json()
    assert data["events_loaded"] >= 4

    alerts_res = client.get("/alerts")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) >= 3

    rule_ids = {a["rule_id"] for a in alerts}
    assert "AM-001" in rule_ids
    assert "AM-002" in rule_ids
    assert "AM-003" in rule_ids
    assert "AM-004" in rule_ids

    # Verify Day 2 acceptance criteria: rule ID, severity, evidence
    for alert in alerts:
        assert alert["rule_id"]
        assert alert["severity"] in {"low", "medium", "high"}
        assert alert["evidence"]
        assert alert["status"] == "open"

def test_rules_endpoint_exposes_attack_mappings(client):
    response = client.get("/rules")

    assert response.status_code == 200
    rules = response.json()
    assert len(rules) == 12
    assert all(rule["attack_technique_id"] for rule in rules)
    assert {
        rule["attack_technique_id"] for rule in rules
    } >= {"T1059.001", "T1110", "T1105"}

def test_case_lifecycle(client):
    # 1. Load demo events
    client.post("/demo/load")
    alerts = client.get("/alerts").json()
    alert = alerts[0]
    alert_id = alert["id"]

    # 2. Create a case for the alert
    case_res = client.post(f"/alerts/{alert_id}/cases")
    assert case_res.status_code == 200
    case = case_res.json()
    assert case["alert_id"] == alert_id
    assert case["title"] == alert["title"]
    case_id = case["id"]

    # Alert status should transition to 'investigating'
    updated_alert = client.get("/alerts").json()
    target_alert = next(a for a in updated_alert if a["id"] == alert_id)
    assert target_alert["status"] == "investigating"

    # 3. Add analyst note and set status
    update_res = client.patch(f"/cases/{case_id}", json={
        "status": "investigating",
        "notes": "Analyst verified obfuscated command. Host isolated."
    })
    assert update_res.status_code == 200
    updated_case = update_res.json()
    assert updated_case["status"] == "investigating"
    assert "Host isolated" in updated_case["notes"]

    # 4. List cases
    cases_res = client.get("/cases")
    assert cases_res.status_code == 200
    cases = cases_res.json()
    assert len(cases) >= 1
    assert cases[0]["id"] == case_id

    # 5. Update alert directly
    patch_alert_res = client.patch(f"/alerts/{alert_id}", json={"status": "closed"})
    assert patch_alert_res.status_code == 200
    assert patch_alert_res.json()["status"] == "closed"

def test_case_persists_after_restart(tmp_path):
    db_file = tmp_path / "test_persist.db"
    file_db_url = f"sqlite:///{db_file}"

    # First session: Start API instance and make changes
    engine1 = create_engine(file_db_url, connect_args={"check_same_thread": False})
    Session1 = sessionmaker(bind=engine1, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine1)

    def get_db1():
        db = Session1()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = get_db1
    with TestClient(app) as client1:
        client1.post("/demo/load")
        alerts = client1.get("/alerts").json()
        target_alert = alerts[0]
        case_res = client1.post(f"/alerts/{target_alert['id']}/cases")
        case_id = case_res.json()["id"]
        client1.patch(f"/cases/{case_id}", json={
            "status": "investigating",
            "notes": "Persisted investigation note"
        })
    app.dependency_overrides.clear()
    engine1.dispose()

    # Second session: Simulate fresh restart of the API with new engine connecting to the same DB file
    engine2 = create_engine(file_db_url, connect_args={"check_same_thread": False})
    Session2 = sessionmaker(bind=engine2, autoflush=False, autocommit=False)

    def get_db2():
        db = Session2()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = get_db2
    with TestClient(app) as client2:
        cases = client2.get("/cases").json()
        assert len(cases) >= 1
        restarted_case = next(c for c in cases if c["id"] == case_id)
        assert restarted_case["status"] == "investigating"
        assert restarted_case["notes"] == "Persisted investigation note"
        assert restarted_case["alert_id"] == target_alert["id"]
    app.dependency_overrides.clear()
    engine2.dispose()
