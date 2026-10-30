# Detection pack validation status

The local unit tests confirm the starter evaluator's behavior on synthetic
normalized events. They do **not** prove that the YAML is accepted by the Sigma
CLI, that the selected Wazuh version generates corresponding alerts, or that
the detections have acceptable false-positive rates.

| Rule | ATT&CK | Synthetic event tested | Local test | Wazuh validation |
|---|---|---|---|---|
| AM-001 | T1059.001 | `process_creation` with PowerShell image | Pass | Pending lab event |
| AM-002 | T1110 | `failed_login` | Pass | Pending lab event |
| AM-003 | T1105 | `process_creation` with DownloadString | Pass | Pending lab event |
| AM-004 | T1059.001 | `process_creation` with `-EncodedCommand` | Pass | Pending lab event |
| AM-005 | T1110.001 | `ssh_failed_login` | Pass | Pending lab event |
| AM-006 | T1548.003 | `sudo_command` | Pass | Pending lab event |
| AM-007 | T1136.001 | `account_created` | Pass | Pending lab event |
| AM-008 | T1053.005 | `scheduled_task_created` | Pass | Pending lab event |
| AM-009 | T1543.003 | `service_installed` | Pass | Pending lab event |
| AM-010 | T1078.004 | `cloud_console_login` | Pass | Pending lab event |
| AM-011 | T1003.001 | `lsass_access_signal` | Pass | Pending lab event |
| AM-012 | T1098.003 | `cloud_role_assigned` | Pass | Pending lab event |

These are illustrative event labels, not instructions to generate suspicious
activity. Validate with instructor-approved sample logs or an approved tabletop
scenario. For each Wazuh test, record the source event, Wazuh rule ID, resulting
AlertMind rule ID, a benign negative test, and evidence reference. Do not call a
rule "working in Wazuh" until both positive and benign cases have been checked.
Record actual lab results in
[`../data/detection_validation_template.csv`](../data/detection_validation_template.csv).

ATT&CK mappings describe the behavior the rule is intended to detect. They do
not establish that an observed event is malicious or that a technique occurred.
