# Phishing incident response playbook

Use this playbook when a user reports a suspicious message or telemetry indicates
that a message, link, or attachment may be malicious. Follow the organization's
approved escalation and evidence-handling procedures.

## 1. Preparation

- Confirm the incident contact list, mail administrator, identity administrator,
  and evidence storage location.
- Record the case ID, analyst, UTC timestamps, and actions taken.
- Preserve the original message and headers in an approved evidence location.
  Do not forward suspected messages to personal accounts.

## 2. Detection and reporting

- Record who reported the message, when it was received, and the affected
  mailbox.
- Collect the sender, reply-to address, subject, message ID, URLs, attachment
  names, and delivery scope from approved security tooling.
- Search for matching messages and indicators using authorized mail or SIEM
  consoles. Treat matches as leads, not proof of execution.

## 3. Analysis

- Determine whether the message was delivered, opened, replied to, or
  quarantined.
- Check approved endpoint and identity telemetry for related browser,
  attachment, process, and sign-in activity around the reported time.
- Establish scope, affected accounts/devices, likely impact, confidence, and
  unresolved questions. Record observed facts separately from hypotheses.

## 4. Containment

- Ask the mail administrator to quarantine or remove confirmed campaign
  messages using the approved process.
- If account or endpoint activity is suspicious, coordinate with the incident
  lead and relevant owners before restricting access or isolating a device.
- Obtain human approval for disruptive actions; document the approver, time,
  scope, and rollback plan.

## 5. Eradication and recovery

- Remove confirmed malicious messages or artifacts through approved tools.
- Reset credentials or revoke sessions only when evidence and policy warrant it,
  with identity-team approval.
- Restore affected systems from trusted sources when required. Validate
  mail-flow, endpoint, and identity telemetry for recurrence.

## 6. Closure and lessons learned

- Notify affected users with an approved, factual message; do not include
  unverified claims.
- Record timeline, evidence references, decisions, impact, and follow-up
  actions in the case.
- Review detection gaps, user-reporting friction, and campaign scope.
