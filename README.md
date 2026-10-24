# AlertMind — AI-Assisted Mini SOC (MVP)

Educational, local-only prototype: synthetic logs → Sigma-style YAML detection → alerts → cases → hosted LLM explanation → Streamlit dashboard.

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
Click **Load sample events** in the dashboard. Review alerts, create a case, add notes, and request an AI explanation.

## Tests
```bash
pytest -q
```

## Important scope note
This MVP uses a deliberately small Sigma-style subset (`equals`, `contains`, `endswith`) and does not implement the full Sigma specification or correlation rules. For real SIEM conversion, install and use the official Sigma CLI / pySigma backends. It uses synthetic demo data, not live endpoint telemetry. Do not send confidential logs to an external LLM without authorization and redaction. AI recommendations are advisory only.
# Altermind
