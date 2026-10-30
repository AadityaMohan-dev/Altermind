# Wazuh manager integration

This adds a Wazuh **custom integration** that forwards Wazuh JSON alerts to
AlertMind. It is an alert forwarder, not an endpoint agent, Wazuh decoder, or
continuous raw-log collector. Wazuh remains responsible for source collection
and rule matching.

## Requirements

- A reachable AlertMind API running at the endpoint in the XML example.
- Wazuh manager custom integrations enabled by the installed Wazuh version.
- HTTPS when the API is on another host. The token must be protected and
  rotated; the example XML stores it in the manager configuration.
- A `WAZUH_INGEST_TOKEN` set in the AlertMind API environment, identical to the
  Wazuh integration `api_key`.

## Install

From the project directory on the Wazuh manager, install the script:

```bash
sudo ./integrations/install_wazuh_integration.sh
```

Add the contents of [`ossec.conf.example.xml`](./ossec.conf.example.xml) inside
the existing `<ossec_config>` element in `/var/ossec/etc/ossec.conf`. Replace
the URL with an address reachable **from the Wazuh manager** and replace the
token. The example sends alerts at level 3 and above; adjust or remove `<level>`
to match the lab's intended volume.

For endpoint collection, merge the relevant examples from
[`agent-log-source-examples.xml`](./agent-log-source-examples.xml) into each
matching agent configuration: Sysmon event channel on the Windows lab endpoint,
and audit/authentication files on the Linux lab endpoint. Install and configure
Sysmon/auditd separately, and confirm the paths exist before restarting agents.
Do not install endpoint collection blocks on unrelated hosts.

CloudTrail collection is intentionally not auto-configured here because it
requires an instructor-approved AWS account/bucket and a credentials method.
An optional starting example is
[`cloudtrail-wodle.example.xml`](./cloudtrail-wodle.example.xml). Confirm its
syntax and supported credential configuration for your installed Wazuh
version. Configure an AWS profile or an approved role outside this repository;
never place cloud access keys here or in an LLM prompt.

Validate the XML and integration settings using the procedure supported by
your installed Wazuh version, then restart the manager in an approved lab
window. Monitor Wazuh `ossec.log` and the AlertMind API for delivery errors.
Do not expose an unauthenticated AlertMind API publicly. The token protects
only the Wazuh-ingest endpoint; the other prototype API routes remain
unauthenticated.

## Safe connection test

First test the endpoint with a synthetic alert using
[`../tools/forward_wazuh_alert.py`](../tools/forward_wazuh_alert.py). This
isolates network, token, and API behavior before enabling manager forwarding.
Then use a benign, authorized lab event and verify the Wazuh alert, normalized
AlertMind event, and expected detection results.

## End-to-end setup checklist

1. Start AlertMind on a host reachable from the Wazuh manager. Set the same
   random `WAZUH_INGEST_TOKEN` in the API environment and Wazuh `<api_key>`.
2. From the Wazuh manager host, confirm the API URL is reachable. If the API
   host is different, configure TLS and use its reachable DNS/IP address; do
   not use `localhost` for a remote API.
3. Use the authorized Windows/Linux agent snippets above, install the source
   collectors, and verify those sources are reporting healthy in Wazuh. If
   CloudTrail is in scope, configure the optional AWS module and verify access
   to the approved bucket.
4. Install `custom-alertmind`, merge the integration XML block, and apply the
   configuration using your Wazuh version's supported validation procedure.
5. Start with the level filter, generate or select a benign authorized lab
   event, and verify it appears once in AlertMind. Check AlertMind's
   `/events`, `/alerts`, and dashboard.
6. Submit a duplicate synthetic alert and confirm the integration returns
   `duplicate: true`. Then test the expected local rule and a benign negative
   case using instructor-provided data.
7. Record Wazuh version, agent/source health, timestamps, rule IDs, screenshots,
   and any field mapping changes in the report evidence section.

If forwarding fails, verify the manager's integration log, API reachability,
token equality, API response status, and whether the alert meets the configured
Wazuh level filter. Never paste the token into chat or a report.

The adapter mapping is intentionally conservative and incomplete. In
particular, local starter rules currently match normalized event types; they
are not a replacement for Wazuh rules. Review the actual JSON from your manager
before interpreting missing alerts or claiming source coverage.
