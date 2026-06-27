from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uuid

from agent.graph import compiled_graph
from agent.state import AlertState

app = FastAPI(
    title="SOC Alert Triage Agent",
    description="LangGraph-powered security alert triage with human-in-the-loop",
    version="1.0.0",
    debug=True,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AlertRequest(BaseModel):
    alert_id: Optional[str] = None    # auto-generated if not provided
    raw_alert: dict                   # the raw SIEM alert JSON


class ResumeRequest(BaseModel):
    """
    Sent by the analyst after reviewing a paused (medium severity) alert.
    decision: "escalate" | "close"
    """
    decision: str = "escalate"


class AlertResponse(BaseModel):
    alert_id: str
    thread_id: str
    status: str                       # "completed" | "awaiting_human_review"
    severity: Optional[str] = None
    classification_reason: Optional[str] = None
    recommended_action: Optional[str] = None
    ticket_id: Optional[str] = None
    report: Optional[str] = None
    message: str = ""


# ---------------------------------------------------------------------------
# POST /alert  — submit a new alert for triage
# ---------------------------------------------------------------------------

@app.post("/alert", response_model=AlertResponse)
async def triage_alert(req: AlertRequest):
    """
    Submit a new security alert for automated triage.

    The graph runs through: ingest → enrich (parallel) → classify → route.

    If severity is CRITICAL or LOW → runs to completion, returns full report.
    If severity is MEDIUM → pauses before human_review_node, returns "awaiting_human_review".
    """
    alert_id = req.alert_id or f"ALT-{str(uuid.uuid4())[:8].upper()}"
    thread_id = f"thread-{alert_id}"

    initial_state: AlertState = {
        "alert_id": alert_id,
        "raw_alert": req.raw_alert,
        # All other fields start as None / False — ingest_node will set them
        "alert_type": "",
        "source_ip": None,
        "destination_ip": None,
        "cve_id": None,
        "timestamp": None,
        "description": "",
        "ip_reputation_score": None,
        "ip_country": None,
        "ip_isp": None,
        "ip_is_tor": None,
        "ip_total_reports": None,
        "cve_description": None,
        "cve_cvss_score": None,
        "cve_severity_label": None,
        "severity": None,
        "classification_reason": None,
        "recommended_action": None,
        "escalated": False,
        "ticket_id": None,
        "human_decision": None,
        "auto_closed": False,
        "report": None,
    }

    config = {"configurable": {"thread_id": thread_id}}

    try:
        result = compiled_graph.invoke(initial_state, config=config)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Check if graph is paused (awaiting human review)
    # LangGraph signals a pause by returning state where the next node
    # is human_review_node but it hasn't run yet
    graph_state = compiled_graph.get_state(config)
    next_nodes = list(graph_state.next)

    if "human_review_node" in next_nodes:
        return AlertResponse(
            alert_id=alert_id,
            thread_id=thread_id,
            status="awaiting_human_review",
            severity=result.get("severity"),
            classification_reason=result.get("classification_reason"),
            recommended_action=result.get("recommended_action"),
            message=(
                f"Alert classified as MEDIUM severity. "
                f"Awaiting analyst review. "
                f"POST /alert/{thread_id}/resume with your decision."
            ),
        )

    return AlertResponse(
        alert_id=alert_id,
        thread_id=thread_id,
        status="completed",
        severity=result.get("severity"),
        classification_reason=result.get("classification_reason"),
        recommended_action=result.get("recommended_action"),
        ticket_id=result.get("ticket_id"),
        report=result.get("report"),
        message="Triage completed.",
    )


# ---------------------------------------------------------------------------
# POST /alert/{thread_id}/resume  — analyst submits decision for paused alert
# ---------------------------------------------------------------------------

@app.post("/alert/{thread_id}/resume", response_model=AlertResponse)
async def resume_alert(thread_id: str, req: ResumeRequest):
    """
    Resume a paused alert after human review.

    The analyst sends their decision ("escalate" or "close").
    LangGraph resumes the graph from human_review_node and runs to completion.
    """
    config = {"configurable": {"thread_id": thread_id}}

    # Check the graph is actually paused
    graph_state = compiled_graph.get_state(config)
    next_nodes = list(graph_state.next)

    if "human_review_node" not in next_nodes:
        raise HTTPException(
            status_code=400,
            detail=f"Alert {thread_id} is not awaiting human review. Status: {next_nodes}",
        )

    if req.decision not in ("escalate", "close"):
        raise HTTPException(
            status_code=400,
            detail="decision must be 'escalate' or 'close'",
        )

    # Inject the analyst's decision into the state before resuming.
    # compiled_graph.update_state() patches the saved state without re-running nodes.
    compiled_graph.update_state(
        config,
        {"human_decision": req.decision},
    )

    # Resume — pass None as input since we already have state from the checkpoint
    try:
        result = compiled_graph.invoke(None, config=config)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    alert_id = result.get("alert_id", thread_id)

    return AlertResponse(
        alert_id=alert_id,
        thread_id=thread_id,
        status="completed",
        severity=result.get("severity"),
        classification_reason=result.get("classification_reason"),
        recommended_action=result.get("recommended_action"),
        ticket_id=result.get("ticket_id"),
        report=result.get("report"),
        message=f"Analyst decision '{req.decision}' applied. Triage completed.",
    )


# ---------------------------------------------------------------------------
# GET /alert/{thread_id}  — get current state of any alert
# ---------------------------------------------------------------------------

@app.get("/alert/{thread_id}")
async def get_alert_state(thread_id: str):
    """Return the current state of an alert by thread_id."""
    config = {"configurable": {"thread_id": thread_id}}
    graph_state = compiled_graph.get_state(config)

    if not graph_state.values:
        raise HTTPException(status_code=404, detail=f"Alert {thread_id} not found")

    state = graph_state.values
    next_nodes = list(graph_state.next)

    return {
        "thread_id": thread_id,
        "next_nodes": next_nodes,
        "status": "awaiting_human_review" if "human_review_node" in next_nodes else "completed",
        "alert_id": state.get("alert_id"),
        "severity": state.get("severity"),
        "classification_reason": state.get("classification_reason"),
        "ticket_id": state.get("ticket_id"),
        "report": state.get("report"),
    }


@app.get("/")
async def root():
    return {"status": "ok", "service": "SOC Alert Triage Agent"}
