import os
import requests
import streamlit as st
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

with st.sidebar:
    st.subheader("Demo controls")
    if st.button("Load sample events", use_container_width=True):
        try:
            result = api_post("/demo/load")
            st.success(f"Loaded {result['events_loaded']} events")
            st.rerun()
        except Exception as e: st.error(f"API error: {e}")
    st.caption(f"API: {API}")
    st.info("Start the API before opening this dashboard.")

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
        use_container_width=True,
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
        if st.button("Update alert status", use_container_width=True):
            try:
                api_patch(f"/alerts/{selected}", {"status": new_alert_status})
                st.success(f"Alert #{selected} status updated to '{new_alert_status}'")
                st.rerun()
            except Exception as e:
                st.error(str(e))

        case_button_label = "Open Investigation Case" if not existing_case else "Go to Investigation Case"
        if st.button(case_button_label, use_container_width=True):
            try:
                res = api_post(f"/alerts/{selected}/cases")
                st.success(f"Case #{res['id']} active for Alert #{selected}")
                st.rerun()
            except Exception as e:
                st.error(str(e))

    with right:
        st.markdown("**AI Investigation Assistant**")
        if st.button("Ask AI to explain alert", type="primary", use_container_width=True):
            try:
                with st.spinner("Generating SOC advisory explanation..."):
                    result = api_post(f"/alerts/{selected}/explain")
                st.session_state[f"explanation_{selected}"] = result["explanation"]
            except Exception as e:
                st.error(f"AI request failed: {e}")

        explanation = st.session_state.get(f"explanation_{selected}")
        if explanation:
            st.markdown(explanation)
            st.caption("⚠️ AI output is advisory. Verify all claims against telemetry before executing actions.")
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
        use_container_width=True,
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
    st.dataframe(events, use_container_width=True, hide_index=True)
