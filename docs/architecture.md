# AlertMind SOC architecture

## Status and scope

This is the capstone's proposed lab architecture, not evidence that a SIEM is
deployed. The repository currently runs a local FastAPI + SQLite + Streamlit
prototype against synthetic events. No endpoint agent, Wazuh manager, cloud
trail connector, authentication, or production retention control is configured.

## Target lab data flow

```text
Windows lab VM (Sysmon) ─┐
Linux lab VM (auditd) ───┼──> Wazuh agents/manager/indexer
CloudTrail sample ───────┘              │
                                        ├──> SIEM alerts and dashboards
                                        └──> approved alert export/normalizer
                                                   │
                                                   v
                                      AlertMind FastAPI + SQLite
                                                   │
                                      analyst-reviewed Streamlit UI
                                                   │
                                      optional hosted LLM advisory
```

Wazuh is the proposed SIEM for the lab. Only connect systems and accounts that
the learner owns or has explicit permission to monitor. Use Atomic Red Team
only in an isolated, instructor-approved lab.

## Data sources and normalization

| Source | Intended telemetry | Current repository status |
|---|---|---|
| Windows Sysmon | Process creation, network, image load, account/service/task events | Not connected; synthetic event types only |
| Linux auditd / sshd | Authentication failures, privileged commands, account changes | Not connected; synthetic event types only |
| CloudTrail sample | Console sign-in, role changes, identity audit events | Not connected; synthetic event types only |

The `EventIn` schema accepts event type, user, source address, process, command
line, message, and timestamp. A Wazuh alert adapter is implemented at
`POST /integrations/wazuh/alerts`; it maps common Windows event IDs, SSH
authentication signals, and selected CloudTrail event names into the local
schema. It is not a complete Wazuh decoder or universal event schema. Review
and test the mapping against the actual alert JSON and Wazuh version before
relying on it. Alerts with a Wazuh `id` are deduplicated by agent ID and event
ID.

The Wazuh endpoint requires `WAZUH_INGEST_TOKEN` and the matching
`X-Wazuh-Token` header. Keep the API bound to localhost or a protected lab
network; use TLS and a managed secret if traffic leaves the host. This token
does not provide analyst authentication for the rest of the API.
For a one-alert smoke test, use
[`../tools/forward_wazuh_alert.py`](../tools/forward_wazuh_alert.py) with a
file containing one sanitized Wazuh JSON alert:

```bash
WAZUH_INGEST_TOKEN="$WAZUH_INGEST_TOKEN" \
  python tools/forward_wazuh_alert.py /path/to/one-sanitized-alert.json
```

For manager-side forwarding, use the packaged [Wazuh integration setup](../integrations/README.md).
The one-alert helper is a smoke test, not a continuous integration service.

Example with a sanitized test alert:

```bash
export WAZUH_INGEST_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
curl --fail-with-body \
  -H "Content-Type: application/json" \
  -H "X-Wazuh-Token: $WAZUH_INGEST_TOKEN" \
  -d '{"id":"demo-1","timestamp":"2026-10-30T10:00:00Z","rule":{"id":"100001","description":"Process creation"},"agent":{"id":"007","name":"windows-lab"},"data":{"win":{"system":{"eventID":"1"},"eventdata":{"image":"powershell.exe","commandLine":"powershell.exe -NoProfile","user":"student"}}}}' \
  http://127.0.0.1:8000/integrations/wazuh/alerts
```

The test alert above is synthetic. Do not copy real credentials, customer
records, or unapproved production logs into examples or hosted model prompts.

## Detection and analyst workflow

The repository contains 12 Sigma-style starter rules in [`../rules/`](../rules/).
Their selection logic is a limited local evaluator, not full Sigma semantics.
The `status: test` labels and presence of ATT&CK metadata do not establish that
a rule is valid or effective in Wazuh. Convert, tune, and test each rule against
the selected Wazuh version and lab telemetry before making that claim.

Alert records are stored in SQLite and presented in Streamlit. The assistant
returns a structured advisory only; no endpoint, identity, network, or SIEM
actions are invoked by the application.

## Retention and evidence handling

- Keep lab data synthetic or approved and minimize fields to those needed for
  detection and investigation.
- Configure SIEM retention according to the instructor's lab policy before
  ingestion. Record the actual hot and archive retention values here:
  **[to be completed after SIEM setup]**.
- Restrict database files, exported evidence, screenshots, and reports to the
  cohort's approved storage. Do not put credentials, secrets, or real customer
  data in events or prompts.
- The SQLite prototype has no automated retention, encryption-at-rest, backup,
  or deletion policy. Do not use it as a production case store.

## Roles and access control

| Role | Intended access | Current implementation |
|---|---|---|
| SIEM administrator | Configure agents, sources, retention, and detection deployment | External SIEM configuration; not implemented here |
| SOC analyst | Review alerts, open cases, and prepare advisories | Streamlit workflow; API is not authenticated |
| Reviewer | Review assistant output and record review | Review declaration is stored; identity is not authenticated |
| Read-only assessor | View approved dashboard and report evidence | No separate role or access control implemented |

The local API currently has no authentication or authorization. Keep it bound to
localhost in the lab. Before any shared deployment, add authentication,
role-based authorization, transport protection, and audit controls.

## LLM boundary

Only send authorized, minimized, redacted lab evidence to the configured model.
The assistant stores a sanitized prompt, prompt version, model identifier,
output, and review declaration in SQLite. Pattern-based redaction is best-effort
and cannot guarantee removal of every secret; human data review is still
required before using a hosted model. See
[`prompt-library-and-guardrails.md`](./prompt-library-and-guardrails.md).
