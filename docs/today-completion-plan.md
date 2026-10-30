# Same-day capstone completion plan

The repository work below is prepared in parallel with SIEM setup. Complete the
lab-dependent steps only with authorized, instructor-approved systems. Do not
replace missing evidence with estimates or generated sample data.

## Completed in the repository

- [x] Add 12 ATT&CK-tagged Sigma-style starter rules and synthetic examples.
- [x] Add daily SOC briefing and ATT&CK coverage dashboard views.
- [x] Add phishing, malware, and account-compromise playbook drafts.
- [x] Add structured assistant output, prompt/model/output logging, best-effort
      secret redaction, and a human review declaration.
- [x] Add architecture, data-handling, prompt/guardrails, report, and measurement
      documentation/templates.
- [x] Add a paired MTTD/MTTR calculator; no real results are populated.
- [x] Add a token-protected Wazuh alert ingestion endpoint with common-field
      normalization and duplicate-event handling.
- [x] Package a Wazuh custom integration, install helper, and Windows/Linux
      source-collection XML examples.
- [x] Add an optional CloudTrail module template, source validation worksheet,
      and controlled tabletop worksheet.

## Remaining work for today

| Order | Owner | Task | Exit evidence |
|---|---|---|---|
| 1 | Learner | Add Wazuh manager integration and applicable endpoint source snippets; finish authorized Windows/Linux/cloud setup | SIEM version, source health, and timestamped screenshots/log references |
| 2 | Together | Confirm the sources are producing events; test Wazuh mapping against actual alert JSON; validate rule conversions | Ingestion evidence plus positive and benign-negative rule tests |
| 3 | Together | Adapt playbook contacts/approval paths and run one approved tabletop scenario without the assistant | Scenario ID, timeline, analyst actions, and baseline timestamps |
| 4 | Together | Repeat the same scenario with the advisory visible to the analyst; review output and record timings | Assistant-run/review evidence and paired timestamps |
| 5 | Together | Fill the report with actual architecture, screenshots, rule results, risks, and measured outcomes | Final report at the learner's required page count |
| 6 | Learner | Rehearse walkthrough and oral-defense questions | Working screencast/demo and evidence-backed answers |

Use [`../data/impact_measurements_template.csv`](../data/impact_measurements_template.csv)
for the same scenario in both conditions, then run:

```bash
python tools/measure_impact.py data/impact_measurements_template.csv
```

The command intentionally rejects an empty or unpaired worksheet. If SIEM
ingestion or the controlled exercise cannot be completed today, report that
limitation honestly; do not claim live ingestion or MTTD/MTTR improvement.
