from dotenv import load_dotenv
import uuid
import json
# from langchain_aws import ChatBedrock
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from .state import AlertState
from .tools import lookup_ip_reputation, lookup_cve, parse_cvss_from_text

load_dotenv()


# Shared LLM instance
# Claude Haiku — fast and cheap for classification and report generation


# def _get_llm() -> ChatBedrock:
#     return ChatBedrock(
#         model_id="anthropic.claude-haiku-20240307-v1:0",
#         model_kwargs={"temperature": 0, "max_tokens": 2048},
#     )


def _get_llm():
    return ChatAnthropic(
        model="claude-haiku-4-5-20251001",   # current Haiku 4.5
        temperature=0,
        max_tokens=2048,
    )


# NODE 1: ingest_node
#
# Pure Python — no LLM, no API call.
# Parses the raw alert JSON and extracts fields into state.
# This is the "front door" of the graph.
#
# CONCEPT: nodes return ONLY the keys they change.
# LangGraph merges this partial dict into the full state automatically.


def ingest_node(state: AlertState) -> dict:
    print(f"\n[ingest_node] Processing alert: {state.get('alert_id', 'unknown')}")

    raw = state.get("raw_alert", {})

    # Extract fields — use .get() with sensible defaults so bad alerts
    # don't crash the graph; classify_node will handle ambiguous cases
    source_ip = (
        raw.get("source_ip")
        or raw.get("src_ip")
        or raw.get("attacker_ip")
        or "unknown"
    )
    cve_id = (
        raw.get("cve_id")
        or raw.get("cve")
        or raw.get("vulnerability_id")
        or "unknown"
    )

    return {
        "alert_type": raw.get("type", raw.get("alert_type", "unknown")),
        "source_ip": source_ip,
        "destination_ip": raw.get("destination_ip", raw.get("dst_ip", "unknown")),
        "cve_id": cve_id,
        "timestamp": raw.get("timestamp", raw.get("time", "unknown")),
        "description": raw.get("description", raw.get("message", "No description provided")),
        # Initialise the outcome flags — later nodes flip these to True
        "escalated": False,
        "auto_closed": False,
        "ticket_id": None,
        "human_decision": None,
        "report": None,
    }


# NODE 2: enrich_node
#
# A "fan-out coordinator" — its only job is to confirm both parallel
# child nodes (ip_lookup, cve_lookup) should run.
# In LangGraph, the parallel execution is defined in graph.py via edges,
# not here. This node can do lightweight pre-processing if needed.


def enrich_node(state: AlertState) -> dict:
    print(f"[enrich_node] Fanning out to IP + CVE lookups in parallel")
    # Nothing to do here — the graph edges handle the fan-out.
    # Return empty dict: no state change at this step.
    return {}


# NODE 3: ip_lookup_node  (runs in parallel with cve_lookup_node)
#
# Calls AbuseIPDB to get reputation data for the source IP.
# This is an IO-bound operation — perfect for parallel execution.

def ip_lookup_node(state: AlertState) -> dict:
    ip = state.get("source_ip", "unknown")
    print(f"[ip_lookup_node] Checking reputation for IP: {ip}")

    result = lookup_ip_reputation(ip)

    if "error" in result:
        print(f"[ip_lookup_node] Warning: {result['error']}")
        return {
            "ip_reputation_score": 0,
            "ip_country": "unknown",
            "ip_isp": "unknown",
            "ip_is_tor": False,
            "ip_total_reports": 0,
        }

    return {
        "ip_reputation_score": result.get("abuseConfidenceScore", 0),
        "ip_country": result.get("countryCode", "unknown"),
        "ip_isp": result.get("isp", "unknown"),
        "ip_is_tor": result.get("isTor", False),
        "ip_total_reports": result.get("totalReports", 0),
    }


# NODE 4: cve_lookup_node  (runs in parallel with ip_lookup_node)
#
# Searches for CVE details using DuckDuckGo + parses CVSS score.


def cve_lookup_node(state: AlertState) -> dict:
    cve_id = state.get("cve_id", "unknown")
    print(f"[cve_lookup_node] Looking up: {cve_id}")

    if cve_id == "unknown":
        return {
            "cve_description": "No CVE associated with this alert.",
            "cve_cvss_score": None,
            "cve_severity_label": None,
        }

    raw_text = lookup_cve(cve_id)
    cvss_score, cvss_label = parse_cvss_from_text(raw_text)

    return {
        "cve_description": raw_text[:800],   # cap to avoid huge state objects
        "cve_cvss_score": cvss_score,
        "cve_severity_label": cvss_label,
    }


# NODE 5: classify_node  (LLM)
#
# The ONLY node that calls the LLM for a decision.
# It reads all enriched data and outputs:
#   - severity: one of "critical" / "medium" / "low" / "false_positive"
#   - classification_reason: explanation
#   - recommended_action: what the analyst should do
#
# CONCEPT: We force JSON output with a strict system prompt.
# We never let the LLM decide routing — we just ask it for the severity label,
# then our Python router (in graph.py) makes the routing decision.


CLASSIFY_SYSTEM_PROMPT = """
    You are a senior SOC analyst AI. Your job is to classify security alerts.
    
    Given alert data, you MUST respond with ONLY valid JSON in this exact format:
    {
      "severity": "critical|medium|low|false_positive",
      "classification_reason": "2-3 sentence explanation of why you chose this severity",
      "recommended_action": "specific action the analyst should take"
    }
    
    Severity guidelines:
    - critical: active exploitation, confirmed breach, ransomware, data exfiltration, CVSS >= 9.0, IP abuse score >= 80
    - medium: suspicious activity, probable attack, CVSS 7.0-8.9, IP abuse score 40-79, needs human review
    - low: low confidence indicators, CVSS < 7.0, IP abuse score < 40, likely automated scan
    - false_positive: known safe IP, internal traffic, test/monitoring traffic
    
    Respond ONLY with the JSON object. No markdown, no explanation outside the JSON.
"""


def classify_node(state: AlertState) -> dict:
    print(f"[classify_node] Classifying alert with LLM...")

    llm = _get_llm()

    # Build a rich context string from all enriched state fields
    context = f"""
        Alert Type: {state.get('alert_type', 'unknown')}
        Description: {state.get('description', 'N/A')}
        Timestamp: {state.get('timestamp', 'N/A')}

        Source IP: {state.get('source_ip', 'N/A')}
          - Abuse Score: {state.get('ip_reputation_score', 'N/A')}/100
          - Country: {state.get('ip_country', 'N/A')}
          - ISP: {state.get('ip_isp', 'N/A')}
          - Is Tor Exit Node: {state.get('ip_is_tor', False)}
          - Total Historical Reports: {state.get('ip_total_reports', 0)}

        CVE ID: {state.get('cve_id', 'N/A')}
          - CVSS Score: {state.get('cve_cvss_score', 'N/A')}
          - CVSS Severity: {state.get('cve_severity_label', 'N/A')}
          - Description: {state.get('cve_description', 'N/A')}
    """.strip()

    messages = [
        SystemMessage(content=CLASSIFY_SYSTEM_PROMPT),
        HumanMessage(content=f"Classify this alert:\n\n{context}"),
    ]

    try:
        response = llm.invoke(messages)
        raw = response.content.strip()
    except Exception as ex:
        print(f"Failed to invoke LLM: {ex}")
        raise

    # Parse the JSON response
    try:
        # Strip markdown fences if present (defensive)
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        parsed = json.loads(raw)
        print(f"Classification result from LLM: {parsed}")
        severity = parsed.get("severity", "low")
        reason = parsed.get("classification_reason", "No reason provided")
        action = parsed.get("recommended_action", "Monitor and review")

        # Validate severity is one of the allowed values
        if severity not in ("critical", "medium", "low", "false_positive"):
            severity = "low"

        print(f"[classify_node] → severity: {severity}")
        return {
            "severity": severity,
            "classification_reason": reason,
            "recommended_action": action,
        }

    except json.JSONDecodeError as e:
        print(f"[classify_node] JSON parse error: {e} — defaulting to medium")
        return {
            "severity": "medium",
            "classification_reason": f"Classification parse error — raw response: {raw[:200]}",
            "recommended_action": "Manual review required due to classification error",
        }


# NODE 6a: escalate_node  (critical severity branch)
#
# Creates a ticket and logs escalation.
# In production: POST to Jira/PagerDuty/ServiceNow API.


def escalate_node(state: AlertState) -> dict:
    ticket_id = f"INC-{str(uuid.uuid4())[:8].upper()}"
    print(f"[escalate_node] CRITICAL alert — creating ticket {ticket_id}")

    # In production, replace this with a real API call:
    # jira_client.create_issue(...)
    # pagerduty_client.trigger_incident(...)
    print(f"[escalate_node] Would notify on-call analyst via PagerDuty")

    return {
        "escalated": True,
        "ticket_id": ticket_id,
    }


# NODE 6b: human_review_node  (medium severity branch)
#
# CONCEPT: This node is declared in graph.py under interrupt_before=[].
# The graph PAUSES before this node runs — it never actually executes
# during the first .invoke() call.
#
# After the graph is paused, your API returns the current state to the caller.
# The caller (analyst) reviews and submits a decision.
# Your API then calls .invoke() again with the same thread_id.
# LangGraph resumes from this node, now with human_decision set in state.
#
# This function only runs during the RESUME call.


def human_review_node(state: AlertState) -> dict:
    decision = state.get("human_decision", "escalate")
    print(f"[human_review_node] Analyst decision: {decision}")

    if decision == "escalate":
        ticket_id = f"INC-{str(uuid.uuid4())[:8].upper()}"
        return {"escalated": True, "ticket_id": ticket_id}
    else:
        return {"auto_closed": True}


# NODE 6c: auto_close_node  (low / false_positive branch)
#
# Marks the alert as auto-closed. No human needed.


def auto_close_node(state: AlertState) -> dict:
    print(f"[auto_close_node] Low severity — auto-closing alert")
    return {"auto_closed": True}


# NODE 7: report_node  (LLM — final output)
#
# All three branches converge here.
# Generates a structured markdown incident report from the full state.
# This is the artifact that gets stored, sent to SIEM, or shown in the UI.


REPORT_SYSTEM_PROMPT = """
    You are a SOC analyst writing an incident report.
    Generate a clear, structured markdown report based on the alert data provided.
    
    Use this exact structure:
    # Incident Report — {alert_id}
    
    ## Summary
    One paragraph overview.
    
    ## Alert Details
    Key fields in a markdown table.
    
    ## Threat Intelligence
    IP reputation findings and CVE details.
    
    ## Classification
    Severity, reasoning, and recommended action.
    
    ## Disposition
    What happened: escalated / sent to human review / auto-closed.
    
    ## Recommended Next Steps
    3-5 bullet points.
    
    Keep the report factual, concise, and under 400 words.
    """


def report_node(state: AlertState) -> dict:
    print(f"[report_node] Generating incident report...")

    llm = _get_llm()

    # Build disposition string
    if state.get("escalated") and state.get("ticket_id"):
        disposition = f"Escalated — ticket {state['ticket_id']} created"
    elif state.get("human_decision"):
        disposition = f"Human reviewed — analyst decision: {state['human_decision']}"
    elif state.get("auto_closed"):
        disposition = "Auto-closed — low severity / false positive"
    else:
        disposition = "Unknown disposition"

    context = f"""
        Alert ID: {state.get('alert_id')}
        Alert Type: {state.get('alert_type')}
        Description: {state.get('description')}
        Timestamp: {state.get('timestamp')}

        Source IP: {state.get('source_ip')} (abuse score: {state.get('ip_reputation_score')}/100,
          country: {state.get('ip_country')}, ISP: {state.get('ip_isp')},
          Tor: {state.get('ip_is_tor')}, reports: {state.get('ip_total_reports')})

        CVE: {state.get('cve_id')} — CVSS {state.get('cve_cvss_score')} ({state.get('cve_severity_label')})
        CVE Description: {state.get('cve_description', 'N/A')}

        Classification: {state.get('severity')}
        Reason: {state.get('classification_reason')}
        Recommended Action: {state.get('recommended_action')}

        Disposition: {disposition}
    """.strip()

    messages = [
        SystemMessage(content=REPORT_SYSTEM_PROMPT),
        HumanMessage(content=f"Write a report for this alert:\n\n{context}"),
    ]

    response = llm.invoke(messages)

    return {"report": response.content}
