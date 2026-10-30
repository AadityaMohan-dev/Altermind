# Account compromise incident response playbook

Use this playbook when identity telemetry or a user report suggests that an
account may have been accessed or used without authorization.

## 1. Preparation

- Confirm the identity administrator, incident lead, affected-user contact, and
  approved evidence repository.
- Record the case ID, account identifier, analyst, and UTC timestamps.
- Preserve sign-in and audit evidence through approved identity tooling.

## 2. Detection and reporting

- Record the alert source, account, sign-in time, source address, device or
  client details, and reported user activity.
- Review successful and failed sign-ins, MFA events, session events, and
  relevant account changes using authorized identity logs.
- Treat unfamiliar geography, addresses, or devices as investigation leads;
  validate against known VPNs, travel, and business activity.

## 3. Analysis

- Establish whether access was successful, which resources were accessed, and
  whether account settings, credentials, or permissions changed.
- Correlate identity findings with endpoint, mail, and cloud audit telemetry
  when available.
- Identify potentially affected sessions, users, assets, and data. Separate
  verified facts from hypotheses and record confidence.

## 4. Containment

- Escalate according to account privilege, evidence, and business impact.
- With identity-owner approval, revoke sessions, require credential reset, or
  temporarily restrict the account when warranted.
- Coordinate with application owners before disabling service or privileged
  accounts. Record approval, impact, timing, and rollback steps.

## 5. Eradication and recovery

- Remove unauthorized account changes and review delegated access or newly
  granted permissions.
- Re-establish trusted authentication factors through the organization's
  identity-verification process.
- Monitor sign-ins and account changes after restoration; confirm normal access
  with the user and identity owner.

## 6. Closure and lessons learned

- Document the timeline, evidence references, affected resources, containment
  decisions, impact, and remaining risk.
- Notify the user and relevant owners using an approved, factual message.
- Identify control or detection improvements and assign follow-up owners.
