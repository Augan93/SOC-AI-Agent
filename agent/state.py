from typing import TypedDict, Literal, Optional


class AlertState(TypedDict):
    """
    The single shared state object that flows through every node in the graph.

    LangGraph passes this dict from node to node. Each node reads what it needs
    and returns only the keys it wants to update — it does NOT return the full
    state. LangGraph merges the returned dict into the existing state automatically.

    Example: classify_node only returns {"severity": "critical", "classification_reason": "..."}
    It does not touch ip_reputation or any other key it didn't set.
    """

    # Set by ingest_node
    alert_id: str
    raw_alert: dict          # original JSON from SIEM / mock file

    alert_type: str          # e.g. "port_scan", "brute_force", "malware"
    source_ip: Optional[str]
    destination_ip: Optional[str]
    cve_id: Optional[str]    # Common Vulnerabilities and Exposures. e.g. "CVE-2024-1234" if present in alert
    timestamp: Optional[str]
    description: str         # human-readable alert description

    # Set by ip_lookup_node
    ip_reputation_score: Optional[int]    # AbuseIPDB: 0-100 (100 = most abusive)
    ip_country: Optional[str]
    ip_isp: Optional[str]
    ip_is_tor: Optional[bool]
    ip_total_reports: Optional[int]

    # Set by cve_lookup_node
    cve_description: Optional[str]
    cve_cvss_score: Optional[float]      # 0.0–10.0
    cve_severity_label: Optional[str]    # "CRITICAL" / "HIGH" / "MEDIUM" / "LOW"

    # Set by classify_node (LLM)
    severity: Optional[Literal["critical", "medium", "low", "false_positive"]]
    classification_reason: Optional[str]
    recommended_action: Optional[str]

    # Set by routing / action nodes
    escalated: bool                      # True if escalate_node ran
    ticket_id: Optional[str]            # created by escalate_node
    human_decision: Optional[str]        # analyst input after human_review pause
    auto_closed: bool                    # True if auto_close_node ran

    # Set by report_node (final output)
    report: Optional[str]               # full markdown incident report
