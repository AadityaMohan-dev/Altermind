# AlertMind — AI-Assisted Mini SOC (MVP)

Educational SOC prototype: synthetic or forwarded Wazuh alerts → local detection and case workflow → human-reviewed LLM advisory → Streamlit dashboard.

## Requirements
- Python 3.12+
- Optional hosted LLM API key for AI explanation

## Setup (macOS/Linux)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env and set OPENAI_API_KEY and OPENAI_MODEL if using OpenAI
```

## Run
Terminal 1:
```bash
uvicorn app.main:app --reload
```
Open API docs at http://127.0.0.1:8000/docs.

Terminal 2:
```bash
streamlit run dashboard.py
```
Click **Load sample events** in the dashboard to try the synthetic demo. Review alerts, create a case, add notes, and request a tier-1 advisory.
Use **SOC workspace** in the sidebar to switch between the daily briefing,
ATT&CK technique coverage, and alert/case investigation views.
The rule pack currently includes 12 ATT&CK-tagged starter rules; they remain
unvalidated until converted and tested against lab SIEM telemetry.

The **Generate tier-1 advisory** workflow returns a five-line summary, mapped
technique, suggested read-only searches, and a draft user message. It records
the prompt, model, output, and a human review declaration. The API is local and
unauthenticated; reviewer identity is not verified.

Wazuh alerts can be submitted to `POST /integrations/wazuh/alerts`. Set
`WAZUH_INGEST_TOKEN` in the API environment and send it as `X-Wazuh-Token`.
See [architecture and integration details](docs/architecture.md). Validate the
normalization against your actual Wazuh alert schema before using it.
Generate a local token with
`python -c 'import secrets; print(secrets.token_urlsafe(32))'`; do not commit it.
The [one-alert forwarder](tools/forward_wazuh_alert.py) is a smoke-test helper,
not a continuous Wazuh manager integration.
For manager-side forwarding and endpoint collection snippets, follow
[integrations/README.md](integrations/README.md). These files are templates to
merge into your existing Wazuh configuration; they do not enroll agents or
configure your cloud account automatically.

## Incident response playbooks

Starter playbooks are in [`docs/playbooks/`](docs/playbooks/) for phishing,
malware, and account-compromise investigations. They are templates: adapt
approval paths, contacts, evidence retention, and containment steps to the
organization and lab before use.

## Capstone documentation

- [Target architecture, retention, and RBAC status](docs/architecture.md)
- [Prompt library and assistant guardrails](docs/prompt-library-and-guardrails.md)
- [Final report template and evidence tables](docs/final-report-template.md)
- [MTTD/MTTR measurement CSV](data/impact_measurements_template.csv) and
  [calculator](tools/measure_impact.py)
- [Tabletop exercise worksheet](docs/tabletop-exercise-template.md)
- [Rule validation evidence CSV](data/detection_validation_template.csv)
- [Same-day completion checklist](docs/today-completion-plan.md)
- [Detection validation status](docs/detection-validation.md)

## Tests
```bash
pytest -q
```

## Important scope note
This MVP uses a deliberately small Sigma-style subset (`equals`, `contains`, `endswith`) and does not implement the full Sigma specification or correlation rules. For real SIEM conversion, install and use the official Sigma CLI / pySigma backends. It uses synthetic demo data, not live endpoint telemetry. Do not send confidential logs to an external LLM without authorization and redaction. AI recommendations are advisory only.
# Altermind
