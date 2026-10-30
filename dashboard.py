import os
from datetime import datetime, timedelta, timezone
import requests
import streamlit as st
import pandas as pd
from dotenv import load_dotenv

load_dotenv()
API = os.getenv("ALERTMIND_API", "http://127.0.0.1:8000")
st.set_page_config(page_title="AlertMind SOC", page_icon="🛡️", layout="wide")
st.title("🛡️ AlertMind — AI-Assisted Mini SOC")
st.caption("Educational MVP using synthetic events. Validate findings before taking action.")

def api_get(path):
    r = requests.get(f"{API}{path}", timeout=15); r.raise_for_status(); return r.json()
def api_post(path, body=None):
    r = requests.post(f"{API}{path}", json=body, timeout=60); r.raise_for_status(); return r.json()
def api_patch(path, body):
    r = requests.patch(f"{API}{path}", json=body, timeout=15); r.raise_for_status(); return r.json()

def parse_timestamp(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed

with st.sidebar:
    st.subheader("Demo controls")
    if st.button("Load sample events", width="stretch"):
        try:
            result = api_post("/demo/load")
            st.success(f"Loaded {result['events_loaded']} events")
            st.rerun()
        except Exception as e: st.error(f"API error: {e}")
    page = st.radio(
        "SOC workspace",
        ["Daily SOC briefing", "ATT&CK heatmap", "Alerts & cases"],
    )
    st.caption(f"API: {API}")
    st.info("Start the API before opening this dashboard.")

if page == "Daily SOC briefing":
    st.header("Daily SOC briefing")
    try:
        alerts = api_get("/alerts")
        cases = api_get("/cases")
        events = api_get("/events")
    except Exception as e:
        st.error(f"Cannot reach API: {e}. Run `uvicorn app.main:app --reload` from the project folder.")
        st.stop()

    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=24)
    recent_alerts = [
        alert for alert in alerts
        if (created := parse_timestamp(alert.get("created_at"))) and created >= since
    ]
    recent_events = [
        event for event in events
        if (created := parse_timestamp(event.get("timestamp"))) and created >= since
    ]
    open_alerts = [alert for alert in alerts if alert.get("status") == "open"]
    high_alerts = [
        alert for alert in open_alerts
        if alert.get("severity", "").lower() == "high"
    ]
    active_cases = [case for case in cases if case.get("status") != "closed"]

    st.caption(f"Operational snapshot for the last 24 hours · Updated {now:%Y-%m-%d %H:%M UTC}")
    metrics = st.columns(5)
    metrics[0].metric("Events (24h)", len(recent_events))
    metrics[1].metric("Alerts (24h)", len(recent_alerts))
    metrics[2].metric("Open alerts", len(open_alerts))
    metrics[3].metric("High severity open", len(high_alerts))
    metrics[4].metric("Active cases", len(active_cases))

    left, right = st.columns(2)
    with left:
        st.subheader("Open alert queue")
        if open_alerts:
            st.dataframe(
                [{
                    "Severity": alert.get("severity", "").upper(),
                    "Alert": alert.get("title", ""),
                    "Rule": alert.get("rule_id", ""),
                    "Status": alert.get("status", ""),
                    "Created": (alert.get("created_at") or "")[:19],
                } for alert in open_alerts[:10]],
                width="stretch",
                hide_index=True,
            )
        else:
            st.success("No open alerts.")
    with right:
        st.subheader("Alert volume by severity (24h)")
        severity_counts = {
            severity: sum(
                alert.get("severity", "").lower() == severity
                for alert in recent_alerts
            )
            for severity in ("high", "medium", "low")
        }
        st.bar_chart(severity_counts, horizontal=True)
        if not recent_alerts:
            st.caption("No alerts in the selected window.")

    st.subheader("Recent investigation cases")
    if active_cases:
        st.dataframe(
            [{
                "Case": case.get("id"),
                "Alert": case.get("alert_id"),
                "Title": case.get("title", ""),
                "Status": case.get("status", ""),
                "Created": (case.get("created_at") or "")[:19],
            } for case in active_cases[:10]],
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("No active investigation cases.")
    st.caption("This view summarizes ingested data; it does not calculate MTTD or MTTR.")
    st.stop()

if page == "ATT&CK heatmap":
    st.header("ATT&CK technique coverage")
    try:
        rules = api_get("/rules")
        alerts = api_get("/alerts")
    except Exception as e:
        st.error(f"Cannot reach API: {e}. Run `uvicorn app.main:app --reload` from the project folder.")
        st.stop()

    alert_counts = {}
    for alert in alerts:
        rule_id = alert.get("rule_id")
        alert_counts[rule_id] = alert_counts.get(rule_id, 0) + 1

    mapped_rules = [rule for rule in rules if rule.get("attack_technique_id")]
    st.caption(
        f"{len(mapped_rules)} of {len(rules)} detection rules have ATT&CK mappings. "
        "Alert counts are all-time totals from the current database."
    )
    if mapped_rules:
        coverage = {}
        for rule in mapped_rules:
            tactic = rule.get("attack_tactic", "Unmapped")
            coverage[tactic] = coverage.get(tactic, 0) + alert_counts.get(rule["id"], 0)
        st.subheader("Observed alerts by tactic")
        st.bar_chart(coverage, horizontal=True)

        st.subheader("Technique coverage")
        heatmap = {}
        for rule in mapped_rules:
            technique = f"{rule['attack_technique_id']} · {rule['attack_technique']}"
            tactic = rule.get("attack_tactic", "Unmapped")
            heatmap.setdefault(technique, {})
            heatmap[technique][tactic] = (
                heatmap[technique].get(tactic, 0) + alert_counts.get(rule["id"], 0)
            )
        heatmap_frame = pd.DataFrame.from_dict(heatmap, orient="index").fillna(0).astype(int)
        max_alert_count = max(heatmap_frame.to_numpy().flatten(), default=0)
        st.dataframe(
            heatmap_frame.style.map(
                lambda count: (
                    "background-color: rgba(255, 87, 34, "
                    f"{0.15 + 0.75 * count / max_alert_count})"
                    if count and max_alert_count
                    else "background-color: #f3f4f6"
                )
            ),
            width="stretch",
        )
        st.caption("Cells show all-time alert counts for mapped detection techniques.")
        st.dataframe(
            [{
                "Technique ID": rule.get("attack_technique_id", ""),
                "Technique": rule.get("attack_technique", ""),
                "Tactic": rule.get("attack_tactic", "Unmapped"),
                "Detection rule": rule.get("title", ""),
                "Rule ID": rule.get("id", ""),
                "Alerts": alert_counts.get(rule["id"], 0),
            } for rule in mapped_rules],
            width="stretch",
            hide_index=True,
        )
        st.caption("Coverage shows rule mappings and matching alerts, not confirmed adversary activity.")
    else:
        st.warning("No ATT&CK technique mappings are available yet.")
    st.stop()

try:
    alerts = api_get("/alerts")
    cases = api_get("/cases")
    events = api_get("/events")
except Exception as e:
    st.error(f"Cannot reach API: {e}. Run `uvicorn app.main:app --reload` from the project folder.")
    st.stop()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Events", len(events))
c2.metric("Total Alerts", len(alerts))
c3.metric("Open Alerts", sum(a["status"] == "open" for a in alerts))
c4.metric("Active Cases", sum(c["status"] != "closed" for c in cases))

# Severity metrics
high_count = sum(a.get("severity", "").lower() == "high" for a in alerts)
med_count = sum(a.get("severity", "").lower() == "medium" for a in alerts)
low_count = sum(a.get("severity", "").lower() == "low" for a in alerts)

st.markdown("##### Alert Counts by Severity")
s1, s2, s3 = st.columns(3)
s1.metric("🔴 High Severity", high_count)
s2.metric("🟡 Medium Severity", med_count)
s3.metric("🔵 Low Severity", low_count)

st.divider()

st.subheader("Security alerts")
if alerts:
    # Display table of alerts
    st.dataframe(
        [{
            "ID": a["id"],
            "Severity": a["severity"].upper(),
            "Title": a["title"],
            "Rule ID": a["rule_id"],
            "Status": a["status"],
            "Event ID": a["event_id"],
            "Created At": a.get("created_at", "")[:19] if a.get("created_at") else ""
        } for a in alerts],
        width="stretch",
        hide_index=True
    )

    ids = [a["id"] for a in alerts]
    selected = st.selectbox(
        "Select alert to inspect",
        ids,
        format_func=lambda i: f"#{i} [{next(a['severity'].upper() for a in alerts if a['id']==i)}] — {next(a['title'] for a in alerts if a['id']==i)} ({next(a['status'] for a in alerts if a['id']==i)})"
    )
    alert = next(a for a in alerts if a["id"] == selected)
    
    # Check if a case already exists for this alert
    existing_case = next((c for c in cases if c.get("alert_id") == selected), None)
    if existing_case:
        st.info(f"📋 **Investigation Case #{existing_case['id']}** is linked to this alert (Status: `{existing_case['status']}`).")

    st.write("**Supporting Event Evidence**")
    st.code(alert["evidence"], language="json")

    left, right = st.columns(2)
    with left:
        st.markdown("**Alert Actions**")
        status_options = ["open", "investigating", "closed"]
        current_idx = status_options.index(alert["status"]) if alert["status"] in status_options else 0
        new_alert_status = st.selectbox("Alert status", status_options, index=current_idx, key=f"status_sel_{selected}")
        if st.button("Update alert status", width="stretch"):
            try:
                api_patch(f"/alerts/{selected}", {"status": new_alert_status})
                st.success(f"Alert #{selected} status updated to '{new_alert_status}'")
                st.rerun()
            except Exception as e:
                st.error(str(e))

        case_button_label = "Open Investigation Case" if not existing_case else "Go to Investigation Case"
        if st.button(case_button_label, width="stretch"):
            try:
                res = api_post(f"/alerts/{selected}/cases")
                st.success(f"Case #{res['id']} active for Alert #{selected}")
                st.rerun()
            except Exception as e:
                st.error(str(e))

    with right:
        st.markdown("**AI Investigation Assistant**")
        if st.button("Generate tier-1 advisory", type="primary", width="stretch"):
            try:
                with st.spinner("Generating advisory for analyst review..."):
                    result = api_post(f"/alerts/{selected}/assist")
                st.session_state[f"assistant_run_{selected}"] = result
                st.rerun()
            except Exception as e:
                st.error(f"Assistant request failed: {e}")

        try:
            runs = api_get(f"/alerts/{selected}/assistant-runs")
            run = runs[0] if runs else st.session_state.get(f"assistant_run_{selected}")
        except Exception as e:
            run = st.session_state.get(f"assistant_run_{selected}")
            st.error(f"Could not load assistant review history: {e}")

        if run:
            result = run["result"]
            st.caption(
                f"Model: {run['model']} · Prompt: {run['prompt_version']} · "
                f"Review status: {run['review_status']}"
            )
            st.markdown("**Five-line summary**")
            for line in result["summary_lines"]:
                st.markdown(f"- {line}")
            st.markdown(
                f"**ATT&CK technique:** {result['technique_id']} — "
                f"{result['technique_name']}"
            )
            st.markdown("**Suggested read-only investigation queries**")
            for query in result["investigation_queries"]:
                st.code(query)
            st.text_area(
                "Draft message to affected user",
                value=result["draft_user_message"],
                disabled=True,
                key=f"draft_user_message_{selected}_{run['id']}",
            )
            st.warning(
                "Advisory only. Validate every claim against telemetry. "
                "This tool cannot execute actions; review the output before use."
            )
            with st.expander("Prompt audit record"):
                st.code(run["prompt_text"], language="json")
            if run["review_status"] != "reviewed":
                reviewer = st.text_input(
                    "Reviewer name",
                    key=f"reviewer_{selected}_{run['id']}",
                )
                confirmed = st.checkbox(
                    "I reviewed this advisory against the available evidence.",
                    key=f"review_confirmed_{selected}_{run['id']}",
                )
                if st.button(
                    "Record human review",
                    disabled=not (confirmed and reviewer.strip()),
                    key=f"record_review_{selected}_{run['id']}",
                ):
                    try:
                        api_patch(
                            f"/assistant-runs/{run['id']}/review",
                            {"reviewed_by": reviewer.strip()},
                        )
                        st.success("Human review recorded.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Could not record review: {e}")
            else:
                st.success(f"Reviewed by {run['reviewed_by']}.")
else:
    st.info("No alerts yet. Click 'Load sample events' in the sidebar.")

st.divider()

st.subheader("Investigation cases")
if cases:
    st.dataframe(
        [{
            "Case ID": c["id"],
            "Alert ID": c["alert_id"],
            "Title": c["title"],
            "Status": c["status"],
            "Analyst Notes": c.get("notes", ""),
            "Created At": c.get("created_at", "")[:19] if c.get("created_at") else ""
        } for c in cases],
        width="stretch",
        hide_index=True
    )

    case_ids = [c["id"] for c in cases]
    cid = st.selectbox(
        "Select case to review or update",
        case_ids,
        format_func=lambda i: f"Case #{i} — {next(c['title'] for c in cases if c['id']==i)} ({next(c['status'] for c in cases if c['id']==i)})"
    )
    case = next(c for c in cases if c["id"] == cid)
    
    status_options = ["open", "investigating", "closed"]
    c_idx = status_options.index(case["status"]) if case["status"] in status_options else 0
    new_case_status = st.selectbox("Case status", status_options, index=c_idx, key=f"case_status_{cid}")
    notes = st.text_area("Analyst notes & timeline findings", value=case.get("notes", ""), height=120)
    if st.button("Save Case Updates", type="primary"):
        try:
            api_patch(f"/cases/{cid}", {"status": new_case_status, "notes": notes})
            st.success("Case updates successfully saved.")
            st.rerun()
        except Exception as e:
            st.error(str(e))
else:
    st.write("No cases created yet.")

with st.expander("Recent events"):
    st.dataframe(events, width="stretch", hide_index=True)
