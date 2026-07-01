"""
SOC Alert Triage — Streamlit UI
================================
Two main features:
1. Real-time graph progress: shows each node lighting up as it runs
2. Human-in-the-loop panel: surfaces paused alerts for analyst decision

Run:
    streamlit run ui/app.py
"""

import time
import uuid
import requests
import streamlit as st

API_URL = "http://localhost:8000"


# Page config


st.set_page_config(
    page_title="SOC Triage Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# Minimal CSS — severity colors + node step styling


st.markdown("""
<style>
/* severity badges */
.badge {
    display: inline-block;
    padding: 3px 12px;
    border-radius: 12px;
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.03em;
}
.badge-critical { background:#fee2e2; color:#991b1b; }
.badge-medium   { background:#fef9c3; color:#854d0e; }
.badge-low      { background:#dcfce7; color:#166534; }
.badge-fp       { background:#f3f4f6; color:#374151; }

/* graph step rows */
.step-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 6px 0;
    font-size: 14px;
}
.step-dot {
    width: 12px; height: 12px;
    border-radius: 50%;
    flex-shrink: 0;
}
.dot-done    { background: #22c55e; }
.dot-running { background: #f59e0b; animation: pulse 1s infinite; }
.dot-wait    { background: #d1d5db; }
.dot-skip    { background: #e5e7eb; }

@keyframes pulse {
    0%,100% { opacity:1; } 50% { opacity:0.3; }
}

.step-label-done    { color: #15803d; font-weight: 500; }
.step-label-running { color: #b45309; font-weight: 500; }
.step-label-wait    { color: #9ca3af; }

/* human review box */
.review-box {
    border: 2px solid #f59e0b;
    border-radius: 10px;
    padding: 16px 20px;
    background: #fffbeb;
}
</style>
""", unsafe_allow_html=True)


# Graph node sequence — used to animate progress

GRAPH_NODES = [
    ("ingest_node",       "Ingest & parse alert"),
    ("enrich_node",       "Start enrichment (parallel)"),
    ("ip_lookup_node",    "IP reputation lookup  [AbuseIPDB]"),
    ("cve_lookup_node",   "CVE details lookup  [DuckDuckGo]"),
    ("classify_node",     "LLM classification  [Claude Haiku]"),
    ("router",            "Severity router  →  branch decision"),
    ("branch",            ""),   # placeholder — filled dynamically
    ("report_node",       "Generate incident report  [Claude Haiku]"),
]

BRANCH_LABELS = {
    "critical": ("escalate_node",      "🔴  Escalate — create incident ticket"),
    "medium":   ("human_review_node",  "🟡  Pause — awaiting analyst decision"),
    "low":      ("auto_close_node",    "🟢  Auto-close — low severity"),
    "false_positive": ("auto_close_node", "⚪  Auto-close — false positive"),
}

MOCK_ALERTS = [
    {
        "label": "🔴  Log4Shell exploit attempt  (expect: CRITICAL)",
        "alert": {
            "type": "exploit_attempt",
            "description": "Inbound exploit attempt targeting Apache Log4j RCE vulnerability on port 8080",
            "source_ip": "193.106.191.5",
            "destination_ip": "10.0.1.45",
            "cve_id": "CVE-2021-44228",
            "timestamp": "2024-01-15T03:22:11Z",
        },
    },
    {
        "label": "🟡  SSH brute force  (expect: MEDIUM → human review)",
        "alert": {
            "type": "brute_force",
            "description": "SSH brute force attack — 847 failed login attempts in 60 seconds",
            "source_ip": "45.33.32.156",
            "destination_ip": "10.0.1.10",
            "cve_id": "unknown",
            "timestamp": "2024-01-15T07:45:00Z",
        },
    },
    {
        "label": "🟢  Port scan from Google DNS  (expect: LOW / false positive)",
        "alert": {
            "type": "port_scan",
            "description": "Port scan detected — 22 ports probed over 30 minutes",
            "source_ip": "8.8.8.8",
            "destination_ip": "10.0.1.0/24",
            "cve_id": "unknown",
            "timestamp": "2024-01-15T11:00:00Z",
        },
    },
]


# Session state defaults

defaults = {
    "triage_result": None,        # last API response dict
    "thread_id": None,
    "alert_id": None,
    "node_states": {},            # node_name → "done"|"running"|"wait"|"skip"
    "running": False,
    "paused": False,              # awaiting human review
    "history": [],               # list of completed alert summaries
    "custom_alert": {             # custom alert form values
        "type": "port_scan",
        "description": "",
        "source_ip": "",
        "destination_ip": "10.0.1.1",
        "cve_id": "unknown",
        "timestamp": "2024-01-15T12:00:00Z",
    },
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


# Helpers

def severity_badge(severity: str) -> str:
    cls = {
        "critical": "badge-critical",
        "medium": "badge-medium",
        "low": "badge-low",
        "false_positive": "badge-fp",
    }.get(severity or "", "badge-fp")
    label = (severity or "unknown").upper()
    return f'<span class="badge {cls}">{label}</span>'


def reset_node_states():
    st.session_state.node_states = {n: "wait" for n, _ in GRAPH_NODES}


def set_node(name: str, state: str):
    st.session_state.node_states[name] = state


def post_alert(raw_alert: dict, alert_id: str) -> dict | None:
    try:
        r = requests.post(
            f"{API_URL}/alert",
            json={"alert_id": alert_id, "raw_alert": raw_alert},
            timeout=120,
        )
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to FastAPI. Run: `uvicorn api.main:app --reload --port 8000`")
        return None
    except Exception as e:
        st.error(f"API error: {e}")
        return None


def post_resume(thread_id: str, decision: str) -> dict | None:
    try:
        r = requests.post(
            f"{API_URL}/alert/{thread_id}/resume",
            json={"decision": decision},
            timeout=120,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"Resume error: {e}")
        return None


# Real-time graph progress renderer

def render_graph_progress(severity: str | None = None):
    """Render the node pipeline with live dot states."""
    branch_node, branch_label = BRANCH_LABELS.get(
        severity or "", ("branch_node", "Branch node")
    )

    rows_html = ""
    for node_key, label in GRAPH_NODES:
        if node_key == "branch":
            # Replace placeholder with actual branch node
            state = st.session_state.node_states.get(branch_node, "wait")
            actual_label = branch_label
            actual_key = branch_node
        else:
            state = st.session_state.node_states.get(node_key, "wait")
            actual_label = label
            actual_key = node_key

        dot_cls = f"dot-{state}"
        label_cls = f"step-label-{state}"
        icon = {"done": "✓", "running": "◎", "wait": "○", "skip": "–"}.get(state, "○")

        rows_html += f"""
        <div class="step-row">
            <div class="step-dot {dot_cls}"></div>
            <span class="{label_cls}">{icon}  {actual_label}</span>
        </div>"""

    st.markdown(rows_html, unsafe_allow_html=True)


# Simulate node-by-node progress while API call is in flight
# The API is synchronous — we animate steps with sleeps matching real timings.

def run_triage_with_animation(raw_alert: dict, alert_id: str):
    reset_node_states()
    st.session_state.running = True
    st.session_state.paused = False
    st.session_state.triage_result = None

    prog_placeholder = st.empty()

    # Step timings (seconds) — approximate real node durations
    steps_before_api = [
        ("ingest_node",    0.4),
        ("enrich_node",    0.3),
        ("ip_lookup_node", 1.8),   # AbuseIPDB network call
        ("cve_lookup_node",1.8),   # DuckDuckGo call (parallel with above)
        ("classify_node",  2.5),   # LLM call
        ("router",         0.2),
    ]

    # Animate nodes up to classify while the real API runs in background
    # We use st.spinner to block and drive animation via sleep
    for node_key, delay in steps_before_api:
        set_node(node_key, "running")
        with prog_placeholder.container():
            render_graph_progress()
        time.sleep(delay)
        set_node(node_key, "done")

    # ip and cve run in parallel — mark both done together
    set_node("ip_lookup_node", "done")
    set_node("cve_lookup_node", "done")

    with prog_placeholder.container():
        render_graph_progress()

    # Now fire the actual API call — animation above was cosmetic
    # (In a real async setup you'd fire both concurrently)
    result = post_alert(raw_alert, alert_id)

    if result is None:
        st.session_state.running = False
        return

    severity = result.get("severity", "low")
    branch_node, _ = BRANCH_LABELS.get(severity, ("auto_close_node", ""))

    # Animate branch + report nodes
    set_node(branch_node, "running")
    with prog_placeholder.container():
        render_graph_progress(severity)
    time.sleep(0.6)

    if result.get("status") == "awaiting_human_review":
        # Graph is paused — branch node stays "running" (waiting)
        st.session_state.paused = True
        st.session_state.triage_result = result
        st.session_state.thread_id = result.get("thread_id")
        st.session_state.alert_id = alert_id
        st.session_state.running = False
        with prog_placeholder.container():
            render_graph_progress(severity)
        return

    set_node(branch_node, "done")
    set_node("report_node", "running")
    with prog_placeholder.container():
        render_graph_progress(severity)
    time.sleep(0.8)
    set_node("report_node", "done")

    st.session_state.triage_result = result
    st.session_state.thread_id = result.get("thread_id")
    st.session_state.alert_id = alert_id
    st.session_state.running = False

    # Add to history
    st.session_state.history.append({
        "alert_id": alert_id,
        "severity": severity,
        "ticket_id": result.get("ticket_id"),
        "status": result.get("status"),
    })

    with prog_placeholder.container():
        render_graph_progress(severity)


# Layout: sidebar + two columns

# ── Sidebar ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("🛡️ SOC Triage Agent")
    st.caption("LangGraph · AWS Bedrock · Human-in-the-loop")
    st.divider()

    st.subheader("Submit alert")
    alert_source = st.radio(
        "Alert source",
        ["Mock alerts", "Custom alert"],
        horizontal=True,
    )

    if alert_source == "Mock alerts":
        mock_choice = st.selectbox(
            "Pick a scenario",
            options=range(len(MOCK_ALERTS)),
            format_func=lambda i: MOCK_ALERTS[i]["label"],
        )
        selected_alert = MOCK_ALERTS[mock_choice]["alert"]
        st.json(selected_alert, expanded=False)

    else:
        st.markdown("**Fill alert fields**")
        alert_type = st.selectbox(
            "Type", ["port_scan", "brute_force", "exploit_attempt", "malware", "data_exfil"]
        )
        description = st.text_area("Description", placeholder="What happened?", height=80)
        source_ip = st.text_input("Source IP", placeholder="e.g. 192.168.1.1")
        dest_ip = st.text_input("Destination IP", placeholder="e.g. 10.0.1.45")
        cve_id = st.text_input("CVE ID (optional)", placeholder="e.g. CVE-2021-44228")
        selected_alert = {
            "type": alert_type,
            "description": description or "No description",
            "source_ip": source_ip or "unknown",
            "destination_ip": dest_ip or "unknown",
            "cve_id": cve_id or "unknown",
            "timestamp": "2024-01-15T12:00:00Z",
        }

    st.divider()
    submit_btn = st.button(
        "▶  Run triage",
        type="primary",
        use_container_width=True,
        disabled=st.session_state.running,
    )

    # History
    if st.session_state.history:
        st.divider()
        st.subheader("Recent alerts")
        for h in reversed(st.session_state.history[-5:]):
            sev = h.get("severity", "?")
            icon = {"critical": "🔴", "medium": "🟡", "low": "🟢", "false_positive": "⚪"}.get(sev, "⚫")
            st.caption(f"{icon} `{h['alert_id']}` — {sev.upper()}")


# ── Main area ────────────────────────────────────────────────────────────────
col_graph, col_result = st.columns([1, 1.6], gap="large")

# Left column — graph progress
with col_graph:
    st.subheader("Graph execution")
    st.caption("Nodes light up as the agent processes your alert")

    graph_area = st.container()
    with graph_area:
        if not st.session_state.node_states:
            # Initial idle state — show all nodes as waiting
            reset_node_states()
        render_graph_progress(
            st.session_state.triage_result.get("severity")
            if st.session_state.triage_result else None
        )

# Right column — results + human-in-the-loop
with col_result:
    st.subheader("Triage result")

    # ── Human-in-the-loop panel ─────────────────────────────────────────────
    if st.session_state.paused and st.session_state.triage_result:
        result = st.session_state.triage_result
        severity = result.get("severity", "medium")

        st.markdown(
            f"""<div class="review-box">
            <b>⏸ Waiting for analyst review</b><br><br>
            Severity: {severity_badge(severity)}<br><br>
            <b>Classification:</b> {result.get('classification_reason', '—')}<br><br>
            <b>Recommended action:</b> {result.get('recommended_action', '—')}
            </div>""",
            unsafe_allow_html=True,
        )

        st.markdown("")
        st.markdown("**Your decision:**")
        dec_col1, dec_col2 = st.columns(2)

        with dec_col1:
            if st.button("🔴  Escalate — create ticket", use_container_width=True, type="primary"):
                with st.spinner("Resuming graph..."):
                    resume_result = post_resume(st.session_state.thread_id, "escalate")
                if resume_result:
                    # Animate resume: branch → report
                    set_node("human_review_node", "done")
                    set_node("escalate_node", "done")
                    set_node("report_node", "done")
                    st.session_state.triage_result = resume_result
                    st.session_state.paused = False
                    st.session_state.history.append({
                        "alert_id": st.session_state.alert_id,
                        "severity": resume_result.get("severity"),
                        "ticket_id": resume_result.get("ticket_id"),
                        "status": "escalated",
                    })
                    st.rerun()

        with dec_col2:
            if st.button("🟢  Close — false positive", use_container_width=True):
                with st.spinner("Resuming graph..."):
                    resume_result = post_resume(st.session_state.thread_id, "close")
                if resume_result:
                    set_node("human_review_node", "done")
                    set_node("auto_close_node", "done")
                    set_node("report_node", "done")
                    st.session_state.triage_result = resume_result
                    st.session_state.paused = False
                    st.session_state.history.append({
                        "alert_id": st.session_state.alert_id,
                        "severity": resume_result.get("severity"),
                        "ticket_id": resume_result.get("ticket_id"),
                        "status": "closed",
                    })
                    st.rerun()

        st.stop()   # don't render result section while paused

    # ── Completed result ────────────────────────────────────────────────────
    if not st.session_state.triage_result:
        st.info("Submit an alert using the sidebar to see triage results here.")
    else:
        result = st.session_state.triage_result
        severity = result.get("severity", "unknown")

        # Header row
        h_col1, h_col2, h_col3 = st.columns(3)
        h_col1.metric("Alert ID", result.get("alert_id", "—"))
        h_col2.metric("Status", result.get("status", "—").replace("_", " ").title())
        with h_col3:
            st.markdown("**Severity**")
            st.markdown(severity_badge(severity), unsafe_allow_html=True)

        st.divider()

        # Classification details
        st.markdown("**Classification reasoning**")
        st.info(result.get("classification_reason") or "—")

        st.markdown("**Recommended action**")
        st.warning(result.get("recommended_action") or "—")

        # Ticket / disposition
        if result.get("ticket_id"):
            st.success(f"✅ Ticket created: `{result['ticket_id']}`")

        # Full incident report
        if result.get("report"):
            st.divider()
            with st.expander("📄  Full incident report", expanded=True):
                st.markdown(result["report"])


# Trigger: submit button clicked

if submit_btn:
    alert_id = f"ALT-{str(uuid.uuid4())[:8].upper()}"
    st.session_state.alert_id = alert_id

    with col_graph:
        run_triage_with_animation(selected_alert, alert_id)

    st.rerun()
