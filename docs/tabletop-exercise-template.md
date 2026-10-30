# AlertMind controlled tabletop worksheet

> Complete this worksheet with the instructor-approved scenario and authorized
> lab. Do not execute a test outside the approved environment. Do not substitute
> synthetic sample-data timestamps for measured exercise results.

## Exercise setup

- Date / timezone: [fill in]
- Scenario title and Atomic Red Team test ID, if approved: [fill in]
- Instructor/lab approval reference: [fill in]
- Wazuh version and manager: [fill in]
- Authorized hosts and sources: [fill in]
- Operator and observer: [fill in]
- Reset/cleanup owner and method: [fill in]
- Evidence folder/reference: [fill in]

## Keep the comparison fair

- Use the same approved scenario, source coverage, alert, operator role, and
  measurement definitions in both runs.
- Record scenario start independently of the analyst's detection.
- For the baseline run, do not show the assistant output to the analyst.
- For the assisted run, show the advisory only after the alert is available;
  require the analyst to verify it and record review.
- Record delays, missing telemetry, and any differences between runs. A
  repeated scenario may benefit from operator learning; disclose this threat
  to validity.
- Do not let the assistant execute searches or actions. It only drafts text.

## Timestamp definitions

- **Scenario start:** instructor/observer-confirmed start of the approved event.
- **Detection:** first alert visible to the analyst in the SIEM or AlertMind.
- **Resolution:** instructor/observer-confirmed point at which the scenario is
  contained or resolved according to the exercise objective.
- **MTTD:** detection minus scenario start.
- **MTTR:** resolution minus detection. State this project definition in the
  report; do not compare it to a different MTTR definition without explaining.

## Run record

| Field | Baseline (assistant hidden) | Assisted (assistant visible) |
|---|---|---|
| Run ID | [fill in] | [fill in] |
| Scenario ID | [same approved ID] | [same approved ID] |
| Scenario start (UTC) | [fill in] | [fill in] |
| Alert/detection time (UTC) | [fill in] | [fill in] |
| Analyst acknowledgement (UTC) | [fill in] | [fill in] |
| Resolution time (UTC) | [fill in] | [fill in] |
| MTTD | [calculate] | [calculate] |
| MTTR | [calculate] | [calculate] |
| Detection source / Wazuh rule | [fill in] | [fill in] |
| Assistant prompt/model/review ID | Not used | [fill in] |
| Evidence references | [fill in] | [fill in] |

## Analyst observations

### Baseline run

- What evidence was available when the alert appeared? [fill in]
- Investigation steps and decision points: [fill in]
- Telemetry gaps or false positives: [fill in]

### Assisted run

- Which assistant claims/queries were independently verified? [fill in]
- What was corrected or rejected, and why? [fill in]
- Did the draft message require edits? [fill in]
- Did the assistant save time, add work, or create risk? [fill in]

## Debrief

- Did both runs have comparable telemetry and starting conditions? [yes/no + evidence]
- What operator-learning, timing, or instrumentation confounders remain? [fill in]
- What changes should be made to rules, playbooks, or guardrails? [fill in]
- Is the sample size sufficient to claim improvement? [usually explain limits]
- Cleanup completed by / time / evidence: [fill in]
