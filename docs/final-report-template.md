# AlertMind — AI-Assisted Mini SOC

> Working report template. Replace every bracketed instruction with verified
> evidence. Do not invent deployment details, test results, or performance
> improvements. Target the page count required for the learner's individual or
> team scope.

## Cover and declaration

- Learner/team: [name(s)]
- Cohort / program: IIT Roorkee × Futurense, PG Certificate in AI/GenAI Powered
  Cybersecurity, Cohort 1
- Project: CAP-SCE-3W — AlertMind
- Submission date: [date]
- GenAI disclosure: [provider, exact model, tasks used for, verification method]
- Responsible AI / lab conduct acknowledgement: [completion evidence]

## 1. Executive summary

[Problem, lab scope, what was deployed, principal measured findings, and
limitations. Do not state measured impact until the exercise data is collected.]

## 2. Objectives and scope

[Individual/team scope, authorized assets, exclusions, assumptions, and success
criteria.]

## 3. Architecture and data handling

[Insert the final diagram and actual SIEM version, sources, data flow, retention,
RBAC, and evidence handling. Start from [`architecture.md`](./architecture.md)
but distinguish implemented controls from proposed controls.]

## 4. SIEM deployment and log-source validation

| Source | Host/account | Events expected | Events observed | Health evidence | Status |
|---|---|---|---|---|---|
| Windows Sysmon | [fill in] | [fill in] | [fill in] | [screenshot/log reference] | [pass/fail] |
| Linux auditd/sshd | [fill in] | [fill in] | [fill in] | [screenshot/log reference] | [pass/fail] |
| Cloud trail (if in scope) | [fill in] | [fill in] | [fill in] | [screenshot/log reference] | [pass/fail] |

## 5. Detection engineering

[List the final rules, converted SIEM query, source fields, ATT&CK mapping,
severity rationale, positive test, benign negative test, and tuning notes. The
repository's 12 starter rules are not validated until tested against lab data.]

## 6. Dashboards and response playbooks

[Explain the daily briefing and ATT&CK coverage views, data used, known
limitations, and how the phishing, malware, and account-compromise playbooks
were adapted and tabletop-tested.]

## 7. Tabletop / controlled exercise

Use the [tabletop worksheet](./tabletop-exercise-template.md) to record
comparable baseline and assisted runs, observer timestamps, and evidence.

- Scenario and approved Atomic Red Team test identifier: [fill in]
- Lab topology and reset method: [fill in]
- Start/end timestamps and evidence references: [fill in]
- Safety approvals and containment: [fill in]

## 8. Assistant design, prompts, and guardrails

[Describe output schema, exact provider/model, prompt version, data minimization,
redaction, human review, logging, and the fact that the assistant cannot execute
actions. Discuss prompt injection, hallucinations, privacy, and unauthenticated
review attribution.]

## 9. Impact measurement

Define MTTD and MTTR before running the exercise. Use the same event, start/end
definitions, operator, and measurement method in both runs where feasible.

| Run | Detection time (UTC) | Acknowledgement time (UTC) | Containment/resolution time (UTC) | MTTD | MTTR | Evidence |
|---|---|---|---|---|---|---|
| Baseline, no assistant | [fill in] | [fill in] | [fill in] | [calculate] | [calculate] | [reference] |
| Assistant in loop | [fill in] | [fill in] | [fill in] | [calculate] | [calculate] | [reference] |

Report raw timings and formulas, not only percentages. If the scenario was not
run or measurements are incomplete, say so and do not claim improvement.
Use [`../data/impact_measurements_template.csv`](../data/impact_measurements_template.csv)
and [`../tools/measure_impact.py`](../tools/measure_impact.py) to calculate the
paired results once actual timestamps are available. The project defines MTTR
as detection-to-resolution for this exercise; state this definition in the
report.

## 10. Results and limitations

[Detection coverage, false positives/negatives observed, ingestion gaps,
measurement uncertainty, operator learning effects, sample size, model
variability, and other threats to validity.]

## 11. Conclusion and future work

[Evidence-backed conclusion and prioritized next steps.]

## Appendices

- Rule pack and SIEM conversion output
- Sanitized event samples and test results
- Dashboard screenshots and walkthrough link
- Playbooks and tabletop timeline
- Prompt/guardrail documentation
- Measurement worksheet and evidence index
