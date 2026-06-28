# 🛡️ SOC Alert Triage Agent

> Automated L1 SOC analyst workflow built with LangGraph, AWS Bedrock, and FastAPI.
> Classifies security alerts, enriches with threat intelligence, and routes by severity —
> with human-in-the-loop review for ambiguous cases.

---

## Overview

This agent mirrors how a real L1 SOC analyst processes an incoming alert:

1. **Parse** the raw alert from SIEM
2. **Enrich** with IP reputation (AbuseIPDB) and CVE details (NVD) — in parallel
3. **Classify** severity using an LLM (Claude Haiku via AWS Bedrock)
4. **Route** by severity — critical alerts escalate automatically, medium alerts pause for analyst review, low alerts auto-close
5. **Report** — generate a structured markdown incident report

---

## Architecture

```
START
  │
  ▼
ingest_node          ← parse + validate raw alert JSON
  │
  ▼
enrich_node          ← fan-out coordinator
  ├──────────────────────────────────┐
  ▼                                  ▼
ip_lookup_node                  cve_lookup_node
(AbuseIPDB · geo)               (DuckDuckGo · CVSS)
  └──────────────┬───────────────────┘
                 ▼
           classify_node           ← LLM: Claude Haiku
                 │
                 ▼
              router               ← conditional edge (pure Python)
         ┌──────┼──────┐
         ▼      ▼      ▼
    escalate  human  auto_close
    _node    _review   _node
              _node
    (ticket) (pause)  (close)
         └──────┼──────┘
                ▼
          report_node              ← LLM: incident report
                │
                ▼
              END
```

### LangGraph concepts used

| Concept | Where |
|---|---|
| `StateGraph` + `TypedDict` state | `agent/state.py` — typed fields, partial updates |
| Sequential nodes | `ingest → enrich → classify` |
| Parallel fan-out / fan-in | `enrich → [ip_lookup ‖ cve_lookup] → classify` |
| Conditional edges | `route_by_severity()` in `agent/graph.py` |
| `interrupt_before` | pauses graph at `human_review_node` |
| `update_state` + resume | analyst injects decision, graph continues |
| `MemorySaver` checkpointer | persists state across the human review pause |

---

## Stack

| Layer | Technology |
|---|---|
| Agent framework | LangGraph 1.2+ |
| LLM | AWS Bedrock — Claude Haiku (`claude-haiku-4-5`) |
| Threat intel | AbuseIPDB API · DuckDuckGo search |
| API | FastAPI + Uvicorn |
| UI | Streamlit |
| Language | Python 3.11+ |

---

## Project Structure

```
soc-agent/
├── agent/
│   ├── __init__.py
│   ├── state.py        # AlertState TypedDict — shared state schema
│   ├── nodes.py        # all node functions (ingest, enrich, classify, ...)
│   ├── graph.py        # StateGraph assembly, edges, conditional routing
│   └── tools.py        # AbuseIPDB client, CVE search, CVSS parser
├── api/
│   ├── __init__.py
│   └── main.py         # FastAPI: /alert  /alert/{id}/resume  /alert/{id}
├── ui/
│   └── app.py          # Streamlit: real-time graph progress + analyst panel
├── mock/
│   └── alerts.json     # sample alerts for all 3 severity branches
├── .env.example
├── requirements.txt
└── README.md
```

---

## Setup

### 1. Clone and install

```bash
git clone https://github.com/your-username/soc-alert-triage-agent
cd soc-alert-triage-agent

python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env`:

```env
# AWS — required
AWS_DEFAULT_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_key_here
AWS_SECRET_ACCESS_KEY=your_secret_here

# AbuseIPDB — optional (mock data used if blank)
# Free tier: 1,000 checks/day — https://www.abuseipdb.com/register
ABUSEIPDB_API_KEY=
```

### 3. Enable AWS Bedrock model access

1. Go to AWS Console → Bedrock → **Model access**
2. Request access to **Claude Haiku** (`anthropic.claude-haiku-20240307-v1:0`)
3. Ensure your IAM user has `bedrock:InvokeModel` permission

---

## Instructions

### Terminal 1 — FastAPI backend

```bash
uvicorn api.main:app --reload --port 8000
```

API docs available at **http://localhost:8000/docs**

### Terminal 2 — Streamlit UI

```bash
streamlit run ui/app.py
```

Open **http://localhost:8501**

---

## Streamlit UI

The UI has two columns running side by side:

**Left — real-time graph execution**

Every node in the LangGraph pipeline is shown as a step with a live status dot:
- 🟡 pulsing = currently running
- 🟢 solid = completed
- ⚪ grey = waiting

Nodes animate in sequence as the agent processes the alert — ingest, parallel IP + CVE enrichment, LLM classification, routing, and report generation.

**Right — triage result / analyst panel**

For `critical` and `low` severity alerts the result renders immediately: severity badge, classification reasoning, recommended action, ticket ID (if escalated), and the full markdown incident report in an expander.

For `medium` severity alerts the right column switches into the **human-in-the-loop review panel** — the graph pauses and waits. The analyst sees the LLM's reasoning and two action buttons:

- 🔴 **Escalate** — creates an incident ticket, graph resumes and generates report
- 🟢 **Close** — marks as false positive, graph resumes and generates report

**Sidebar**

- Three pre-built mock alerts — one per severity branch (critical / medium / low)
- Custom alert form — enter any IP, alert type, CVE, and description
- Recent alerts history showing the last 5 processed alerts

---

## API Reference

### `POST /alert` — Submit alert for triage

```bash
curl -X POST http://localhost:8000/alert \
  -H "Content-Type: application/json" \
  -d '{
    "raw_alert": {
      "type": "exploit_attempt",
      "description": "Log4Shell exploit attempt on port 8080",
      "source_ip": "193.106.191.5",
      "destination_ip": "10.0.1.45",
      "cve_id": "CVE-2021-44228",
      "timestamp": "2024-01-15T03:22:11Z"
    }
  }'
```

**Response — critical (completed):**
```json
{
  "alert_id": "ALT-A1B2C3D4",
  "thread_id": "thread-ALT-A1B2C3D4",
  "status": "completed",
  "severity": "critical",
  "classification_reason": "Log4Shell (CVE-2021-44228) is a critical RCE vulnerability with CVSS 10.0. Source IP has abuse score 85/100.",
  "recommended_action": "Immediately isolate destination host. Block source IP at perimeter firewall.",
  "ticket_id": "INC-9F3E2A1B",
  "report": "# Incident Report — ALT-A1B2C3D4\n..."
}
```

**Response — medium (paused for human review):**
```json
{
  "alert_id": "ALT-B2C3D4E5",
  "thread_id": "thread-ALT-B2C3D4E5",
  "status": "awaiting_human_review",
  "severity": "medium",
  "classification_reason": "SSH brute force with 847 attempts. IP has moderate abuse score but no CVE.",
  "recommended_action": "Review authentication logs. Consider temporary IP block.",
  "message": "Alert classified as MEDIUM. POST /alert/thread-ALT-B2C3D4E5/resume with your decision."
}
```

---

### `POST /alert/{thread_id}/resume` — Analyst decision

Only called for alerts with `status: awaiting_human_review`.

```bash
curl -X POST http://localhost:8000/alert/thread-ALT-B2C3D4E5/resume \
  -H "Content-Type: application/json" \
  -d '{"decision": "escalate"}'
  # or: {"decision": "close"}
```

---

### `GET /alert/{thread_id}` — Get alert state

```bash
curl http://localhost:8000/alert/thread-ALT-A1B2C3D4
```

---

## Testing All Three Severity Branches

The `mock/alerts.json` file contains one alert per branch:

| Alert | Expected severity | Graph path |
|---|---|---|
| Log4Shell (CVE-2021-44228) from high-abuse IP | `critical` | → escalate → ticket → report |
| SSH brute force, no CVE | `medium` | → pause → analyst decision → report |
| Port scan from Google DNS (8.8.8.8) | `low` / `false_positive` | → auto-close → report |

---

## How Human-in-the-Loop Works

```
1. POST /alert  →  graph runs through classify_node
                    severity = "medium"
                    graph PAUSES before human_review_node
                    state saved to MemorySaver checkpointer
                    API returns status: "awaiting_human_review"

2. Analyst reviews classification + recommended action in Streamlit UI
   (or directly via API)

3. POST /alert/{thread_id}/resume  {"decision": "escalate"}
   →  compiled_graph.update_state() injects human_decision into saved state
   →  compiled_graph.invoke(None, config)  resumes from checkpoint
   →  human_review_node runs with decision
   →  report_node generates final report
   →  API returns completed result
```

The key: `MemorySaver` persists the full graph state between the two API calls.
Swap it for `SqliteSaver` or `RedisSaver` to survive server restarts.

---

## Cost Estimate

Each alert run makes 2 LLM calls (classify + report) — roughly 1,000 input + 400 output tokens total.

| Volume | Estimated cost |
|---|---|
| 1 alert | ~$0.003 |
| 100 alerts / day | ~$0.30 / day |
| 1,000 alerts / day | ~$3.00 / day |

*Based on Claude Haiku pricing: $1.00 / 1M input tokens, $5.00 / 1M output tokens.*

---

## Extending This Project

**Swap mock data for a real SIEM:**
Point `ingest_node` at an ElasticSearch / Splunk webhook instead of JSON.

**Persistent memory across restarts:**
```python
from langgraph.checkpoint.sqlite import SqliteSaver
checkpointer = SqliteSaver.from_conn_string("alerts.db")
```

**Add Slack / PagerDuty notifications:**
In `escalate_node`, replace the print statement with a real API call.

**Add a second LLM pass for false positive detection:**
Insert a `false_positive_check_node` between `ingest_node` and `enrich_node`.

---

## License

MIT
