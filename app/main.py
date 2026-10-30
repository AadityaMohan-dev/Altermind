from pathlib import Path
import json, os, secrets
from datetime import datetime, timezone
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Header, HTTPException
from openai import OpenAIError
from sqlalchemy.orm import Session
from .db import Base, engine, get_db
from .models import Event, Alert, Case, AssistantRun, IntegrationReceipt
from .schemas import EventIn, EventOut, CaseUpdate, AssistantReview
from .detection import load_rules, matching_rules
from .assistant import PROMPT_VERSION, build_prompt, generate_result, redact_secrets
from .wazuh import normalize_wazuh_alert

load_dotenv()
Base.metadata.create_all(bind=engine)
app = FastAPI(title="AlertMind SOC API", version="0.1.0")

@app.get("/health")
def health():
    return {"status": "ok", "service": "AlertMind"}

def event_dict(event: Event):
    return {"event_type": event.event_type, "username": event.username, "source_ip": event.source_ip,
            "process_name": event.process_name, "command_line": event.command_line, "message": event.message}

def alert_dict(a: Alert):
    return {"id": a.id, "event_id": a.event_id, "rule_id": a.rule_id, "title": a.title,
            "severity": a.severity, "evidence": a.evidence, "status": a.status,
            "created_at": a.created_at.isoformat() if a.created_at else None}

def case_dict(c: Case):
    return {"id": c.id, "alert_id": c.alert_id, "title": c.title, "status": c.status,
            "notes": c.notes, "created_at": c.created_at.isoformat() if c.created_at else None}

def assistant_run_dict(run: AssistantRun):
    return {
        "id": run.id,
        "alert_id": run.alert_id,
        "model": run.model,
        "prompt_version": run.prompt_version,
        "prompt_text": run.prompt_text,
        "result": json.loads(run.output_json),
        "review_status": run.review_status,
        "reviewed_by": run.reviewed_by,
        "reviewed_at": run.reviewed_at.isoformat() if run.reviewed_at else None,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }

def store_event(payload: EventIn, db: Session):
    event = Event(**payload.model_dump())
    db.add(event)
    db.commit()
    db.refresh(event)
    raw = event_dict(event)
    alerts_created = 0
    for rule in matching_rules(raw):
        exists = db.query(Alert).filter_by(event_id=event.id, rule_id=rule["id"]).first()
        if not exists:
            db.add(Alert(event_id=event.id, rule_id=rule["id"], title=rule["title"],
                         severity=rule.get("level", "medium"), evidence=json.dumps(raw)))
            alerts_created += 1
    db.commit()
    return event, alerts_created

@app.post("/events", response_model=EventOut)
def ingest_event(payload: EventIn, db: Session = Depends(get_db)):
    event, _ = store_event(payload, db)
    return event

@app.post("/integrations/wazuh/alerts")
def ingest_wazuh_alert(
    payload: dict,
    x_wazuh_token: str | None = Header(default=None, alias="X-Wazuh-Token"),
    db: Session = Depends(get_db),
):
    expected_token = os.getenv("WAZUH_INGEST_TOKEN")
    if not expected_token:
        raise HTTPException(503, "Wazuh integration is disabled; configure WAZUH_INGEST_TOKEN")
    if not x_wazuh_token or not secrets.compare_digest(x_wazuh_token, expected_token):
        raise HTTPException(401, "Invalid Wazuh integration token")
    try:
        event_payload = normalize_wazuh_alert(payload)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    wazuh_alert_id = payload.get("id")
    agent_id = (payload.get("agent") or {}).get("id")
    external_id = (
        f"wazuh:{agent_id or 'manager'}:{wazuh_alert_id}"
        if wazuh_alert_id is not None
        else None
    )
    if external_id:
        receipt = db.query(IntegrationReceipt).filter_by(
            source_event_id=external_id
        ).first()
        if receipt:
            return {
                "event": {
                    "id": receipt.event.id,
                    **event_dict(receipt.event),
                    "timestamp": receipt.event.timestamp.isoformat()
                    if receipt.event.timestamp else None,
                },
                "duplicate": True,
                "alerts_created": 0,
            }

    event, alerts_created = store_event(event_payload, db)
    if external_id:
        db.add(IntegrationReceipt(
            source="wazuh",
            source_event_id=external_id,
            event_id=event.id,
        ))
        db.commit()
    return {
        "event": {
            "id": event.id,
            **event_dict(event),
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        },
        "duplicate": False,
        "alerts_created": alerts_created,
    }

@app.post("/demo/load")
def load_demo(db: Session = Depends(get_db)):
    path = Path(__file__).resolve().parent.parent / "data" / "sample_events.json"
    events = json.loads(path.read_text(encoding="utf-8"))
    created = 0
    for item in events:
        event = Event(**item)
        db.add(event); db.flush()
        for rule in matching_rules(event_dict(event)):
            db.add(Alert(event_id=event.id, rule_id=rule["id"], title=rule["title"],
                         severity=rule.get("level", "medium"), evidence=json.dumps(event_dict(event))))
        created += 1
    db.commit()
    return {"events_loaded": created, "message": "Demo events processed; alerts generated where rules matched."}

@app.get("/events")
def list_events(db: Session = Depends(get_db)):
    return [{"id": e.id, **event_dict(e), "timestamp": e.timestamp.isoformat() if e.timestamp else None}
            for e in db.query(Event).order_by(Event.id.desc()).all()]

@app.get("/alerts")
def list_alerts(db: Session = Depends(get_db)):
    return [alert_dict(a) for a in db.query(Alert).order_by(Alert.id.desc()).all()]

@app.get("/rules")
def list_rules():
    return [
        {
            "id": rule["id"],
            "title": rule["title"],
            "severity": rule.get("level", "medium"),
            "attack_tactic": rule.get("attack_tactic"),
            "attack_technique_id": rule.get("attack_technique_id"),
            "attack_technique": rule.get("attack_technique"),
        }
        for rule in load_rules()
    ]

@app.post("/alerts/{alert_id}/assist")
def assist_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    if not os.getenv("OPENAI_API_KEY"):
        load_dotenv(override=True)
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(503, "Set OPENAI_API_KEY in .env to enable the assistant")

    rule = next((item for item in load_rules() if item["id"] == alert.rule_id), {})
    prompt = build_prompt(alert, rule)
    model = os.getenv("OPENAI_MODEL", "gpt-5.5")
    try:
        result = generate_result(prompt, rule, api_key, model)
    except ValueError as exc:
        raise HTTPException(502, str(exc)) from exc
    except OpenAIError as exc:
        raise HTTPException(
            502,
            f"LLM request failed: {type(exc).__name__}. Check API key, model name, and provider access.",
        ) from exc

    run = AssistantRun(
        alert_id=alert.id,
        model="mock" if api_key.lower() in {"mock", "demo"} else model,
        prompt_version=PROMPT_VERSION,
        prompt_text=prompt,
        output_json=result.model_dump_json(),
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return assistant_run_dict(run)

@app.get("/alerts/{alert_id}/assistant-runs")
def list_assistant_runs(alert_id: int, db: Session = Depends(get_db)):
    if not db.get(Alert, alert_id):
        raise HTTPException(404, "Alert not found")
    runs = (
        db.query(AssistantRun)
        .filter_by(alert_id=alert_id)
        .order_by(AssistantRun.id.desc())
        .all()
    )
    return [assistant_run_dict(run) for run in runs]

@app.patch("/assistant-runs/{run_id}/review")
def review_assistant_run(
    run_id: int,
    payload: AssistantReview,
    db: Session = Depends(get_db),
):
    run = db.get(AssistantRun, run_id)
    if not run:
        raise HTTPException(404, "Assistant run not found")
    run.review_status = "reviewed"
    run.reviewed_by = payload.reviewed_by.strip()
    if not run.reviewed_by:
        raise HTTPException(422, "Reviewer name must not be blank")
    run.reviewed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    db.refresh(run)
    return assistant_run_dict(run)

@app.patch("/alerts/{alert_id}")
def update_alert(alert_id: int, payload: dict, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert: raise HTTPException(404, "Alert not found")
    if payload.get("status") not in {"open", "investigating", "closed", None}:
        raise HTTPException(400, "Invalid status")
    if payload.get("status"): alert.status = payload["status"]
    db.commit(); db.refresh(alert)
    return alert_dict(alert)

@app.post("/alerts/{alert_id}/cases")
def create_case(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert: raise HTTPException(404, "Alert not found")
    existing = db.query(Case).filter_by(alert_id=alert_id).first()
    if existing: return case_dict(existing)
    case = Case(alert_id=alert.id, title=alert.title)
    db.add(case); alert.status = "investigating"; db.commit(); db.refresh(case)
    return case_dict(case)

@app.get("/cases")
def list_cases(db: Session = Depends(get_db)):
    return [case_dict(c) for c in db.query(Case).order_by(Case.id.desc()).all()]

@app.patch("/cases/{case_id}")
def update_case(case_id: int, payload: CaseUpdate, db: Session = Depends(get_db)):
    case = db.get(Case, case_id)
    if not case: raise HTTPException(404, "Case not found")
    if payload.status is not None:
        if payload.status not in {"open", "investigating", "closed"}: raise HTTPException(400, "Invalid status")
        case.status = payload.status
    if payload.notes is not None: case.notes = payload.notes
    db.commit(); db.refresh(case)
    return case_dict(case)

@app.post("/alerts/{alert_id}/explain")
def explain_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert: raise HTTPException(404, "Alert not found")
    if not os.getenv("OPENAI_API_KEY"):
        load_dotenv(override=True)
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key: raise HTTPException(503, "Set OPENAI_API_KEY in .env to enable AI explanations")
    if api_key.lower() in {"mock", "demo"}:
        try:
            ev = json.loads(alert.evidence)
        except Exception:
            ev = {}
        explanation = (
            f"### 1. Alert Summary\n"
            f"Alert '{alert.title}' (Rule: {alert.rule_id}) triggered with {alert.severity.upper()} severity.\n\n"
            f"### 2. Evidence (Observed Facts)\n"
            f"- Event Type: {ev.get('event_type', 'N/A')}\n"
            f"- User Account: {ev.get('username', 'N/A')}\n"
            f"- Source IP Address: {ev.get('source_ip', 'N/A')}\n"
            f"- Process Name: {ev.get('process_name', 'N/A')}\n"
            f"- Command Line: {ev.get('command_line', 'N/A')}\n\n"
            f"### 3. Possible Impact (Hypotheses vs Facts)\n"
            f"- Observed Fact: Process command line matched detection rule criteria.\n"
            f"- Hypothesis: Potential execution of unauthorized or obfuscated command attempting defense evasion.\n"
            f"- Precaution: There is no confirmed system compromise based strictly on this single log event.\n\n"
            f"### 4. Safe Investigation Steps\n"
            f"1. Triage the parent process tree and execution timestamp for process '{ev.get('process_name', 'N/A')}'.\n"
            f"2. Inspect network connections and authentication logs for user '{ev.get('username', 'N/A')}' around the event time.\n"
            f"3. Verify if the command matches approved administrative maintenance or developer activity before taking actions."
        )
        return {"alert_id": alert.id, "explanation": explanation}
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        safe_evidence = redact_secrets(alert.evidence or "{}")
        response = client.responses.create(
            model=os.getenv("OPENAI_MODEL", "gpt-5.5"),
            instructions=("You are a cautious SOC assistant. Use only the provided alert evidence. "
                          "Separate observed facts from hypotheses. Never claim a host is compromised without evidence. "
                          "Give: summary, evidence, possible impact, and 3 safe investigation steps. Do not execute actions."),
            input=f"Alert title: {alert.title}\nRule: {alert.rule_id}\nSeverity: {alert.severity}\nEvidence JSON: {safe_evidence}"
        )
        return {"alert_id": alert.id, "explanation": response.output_text}
    except Exception as exc:
        raise HTTPException(502, f"LLM request failed: {type(exc).__name__}. Check API key, model name, and provider access.")
