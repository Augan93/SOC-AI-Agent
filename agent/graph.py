from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from .state import AlertState
from .nodes import (
    ingest_node,
    enrich_node,
    ip_lookup_node,
    cve_lookup_node,
    classify_node,
    escalate_node,
    human_review_node,
    auto_close_node,
    report_node,
)


# Conditional edge function — the "router"
#
# This is a plain Python function, NOT an LLM call.
# It reads state["severity"] and returns the name of the next node as a string.
# LangGraph uses that string to look up which edge to follow.
#
# This is one of the most important LangGraph concepts:
#   - The LLM decides WHAT the severity is (in classify_node)
#   - Python decides WHERE to go next (here)
# Never let an LLM make routing decisions — it's slow, expensive, and unreliable.


def route_by_severity(state: AlertState) -> str:
    severity = state.get("severity", "low")

    if severity == "critical":
        return "escalate_node"
    elif severity == "medium":
        return "human_review_node"
    else:
        # "low" and "false_positive" both auto-close
        return "auto_close_node"


def build_graph() -> StateGraph:
    """Build the graph"""
    # 1. Create the graph, telling it what the state shape looks like
    graph = StateGraph(AlertState)

    # 2. Add every node — each is a function defined in nodes.py
    graph.add_node("ingest_node", ingest_node)
    graph.add_node("enrich_node", enrich_node)
    graph.add_node("ip_lookup_node", ip_lookup_node)
    graph.add_node("cve_lookup_node", cve_lookup_node)
    graph.add_node("classify_node", classify_node)
    graph.add_node("escalate_node", escalate_node)
    graph.add_node("human_review_node", human_review_node)
    graph.add_node("auto_close_node", auto_close_node)
    graph.add_node("report_node", report_node)

    # 3. Define edges — the fixed sequential flow
    graph.add_edge(START, "ingest_node")
    graph.add_edge("ingest_node", "enrich_node")

    # enrich_node fans out to TWO nodes in parallel.
    # LangGraph runs them concurrently and waits for both to finish
    # before moving on. No threading code needed — it's automatic.
    graph.add_edge("enrich_node", "ip_lookup_node")
    graph.add_edge("enrich_node", "cve_lookup_node")

    # Both parallel nodes fan back in to classify_node.
    # LangGraph knows to wait for BOTH ip_lookup and cve_lookup
    # before running classify — because both edges point here.
    graph.add_edge("ip_lookup_node", "classify_node")
    graph.add_edge("cve_lookup_node", "classify_node")

    # 4. Conditional edge — this is the "router"
    # After classify_node, call route_by_severity(state) to decide next node.
    # The dict maps return values → node names.
    graph.add_conditional_edges(
        "classify_node",
        route_by_severity,
        {
            "escalate_node": "escalate_node",
            "human_review_node": "human_review_node",
            "auto_close_node": "auto_close_node",
        },
    )

    # 5. All three branches converge at report_node
    graph.add_edge("escalate_node", "report_node")
    graph.add_edge("human_review_node", "report_node")
    graph.add_edge("auto_close_node", "report_node")

    graph.add_edge("report_node", END)

    return graph


# Compile the graph with a checkpointer
#
# compile() validates the graph structure — missing nodes, dangling edges,
# unreachable nodes — and returns a runnable object.
#
# The checkpointer (MemorySaver) is what makes human-in-the-loop possible.
# It saves the full state after every node. If the graph is interrupted
# at human_review_node, the state is preserved and can be resumed later
# with a new .invoke() call on the same thread_id.
#
# Swap MemorySaver for SqliteSaver or RedisSaver for production.


checkpointer = MemorySaver()

compiled_graph = build_graph().compile(
    checkpointer=checkpointer,
    # interrupt_before tells LangGraph to PAUSE before running this node.
    # The graph saves state and returns control to your code.
    # You resume it by calling .invoke() again on the same thread_id.
    interrupt_before=["human_review_node"],
)
