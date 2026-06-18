import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Literal

from fastmcp import FastMCP

mcp = FastMCP("Rapid7 InsightIDR")

API_KEY = os.environ["RAPID7_API_KEY"]
REGION = os.environ.get("RAPID7_REGION", "us")
USER_EMAIL = os.environ["RAPID7_USER_EMAIL"]

BASE_V1 = f"https://{REGION}.api.insight.rapid7.com/idr/v1"
BASE_V2 = f"https://{REGION}.api.insight.rapid7.com/idr/v2"
BASE_LOG_SEARCH = f"https://{REGION}.api.insight.rapid7.com/log_search"


def _req(method: str, url: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body else None
    r = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"X-Api-Key": API_KEY, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode()
        raise RuntimeError(f"HTTP {e.code}: {body_text}") from None


def _encode_rrn(rrn: str) -> str:
    return urllib.parse.quote(rrn, safe="")


@mcp.tool()
def list_investigations(
    assignee: Literal["unassigned", "me", "any"] = "unassigned",
    status: Literal["OPEN", "INVESTIGATING", "WAITING", "CLOSED"] = "OPEN",
    size: int = 25,
) -> list[dict]:
    """List InsightIDR investigations. Defaults to unassigned open investigations."""
    params = f"statuses={status}&size={size}"
    if assignee == "unassigned":
        params += "&assignee=unassigned"
    elif assignee == "me":
        params += f"&assignee.email={urllib.parse.quote(USER_EMAIL)}"

    result = _req("GET", f"{BASE_V2}/investigations?{params}")
    investigations = result.get("data", [])

    return [
        {
            "rrn": inv["rrn"],
            "title": inv["title"],
            "status": inv["status"],
            "priority": inv["priority"],
            "disposition": inv["disposition"],
            "assignee": (inv.get("assignee") or {}).get("name", "Unassigned"),
            "created_time": inv["created_time"],
            "responsibility": inv.get("responsibility"),
        }
        for inv in investigations
    ]


@mcp.tool()
def get_investigation(rrn: str) -> dict:
    """Get full details and linked alerts for an investigation by RRN."""
    encoded = _encode_rrn(rrn)
    detail = _req("GET", f"{BASE_V2}/investigations/{encoded}")
    alerts_resp = _req("GET", f"{BASE_V2}/investigations/{encoded}/alerts?size=20")

    alerts = [
        {
            "id": a["id"],
            "title": a["title"],
            "alert_type": a.get("alert_type"),
            "alert_source": a.get("alert_source"),
            "created_time": a.get("created_time"),
            "first_event_time": a.get("first_event_time"),
            "latest_event_time": a.get("latest_event_time"),
            "detection_rule_name": (a.get("detection_rule_rrn") or {}).get("rule_name"),
            "detection_rule_rrn": (a.get("detection_rule_rrn") or {}).get("rule_rrn"),
        }
        for a in alerts_resp.get("data", [])
    ]

    return {
        "rrn": detail["rrn"],
        "title": detail["title"],
        "status": detail["status"],
        "priority": detail["priority"],
        "disposition": detail["disposition"],
        "assignee": (detail.get("assignee") or {}).get("name", "Unassigned"),
        "responsibility": detail.get("responsibility"),
        "created_time": detail["created_time"],
        "first_alert_time": detail.get("first_alert_time"),
        "latest_alert_time": detail.get("latest_alert_time"),
        "actors": detail.get("actors", {}),
        "alerts": alerts,
    }


@mcp.tool()
def set_status(
    rrn: str,
    status: Literal["OPEN", "INVESTIGATING", "WAITING"],
) -> dict:
    """Update the status of an open investigation without closing it."""
    encoded = _encode_rrn(rrn)
    result = _req("PATCH", f"{BASE_V2}/investigations/{encoded}", {"status": status})
    return {
        "rrn": result["rrn"],
        "status": result["status"],
        "disposition": result["disposition"],
    }


@mcp.tool()
def assign_to_me(rrn: str) -> dict:
    """Assign an investigation to yourself."""
    encoded = _encode_rrn(rrn)
    result = _req("PATCH", f"{BASE_V2}/investigations/{encoded}", {"assignee": {"email": USER_EMAIL}})
    return {
        "rrn": result["rrn"],
        "assignee": result.get("assignee", {}).get("name"),
        "status": result["status"],
    }


@mcp.tool()
def add_comment(rrn: str, body: str) -> dict:
    """Add a comment to an investigation."""
    result = _req("POST", f"{BASE_V1}/comments", {"target": rrn, "body": body})
    return {
        "comment_rrn": result.get("rrn"),
        "created_time": result.get("created_time"),
    }


@mcp.tool()
def close_investigation(
    rrn: str,
    disposition: Literal["BENIGN", "MALICIOUS", "NOT_APPLICABLE"],
) -> dict:
    """Close an investigation with a disposition."""
    encoded = _encode_rrn(rrn)
    result = _req(
        "PATCH",
        f"{BASE_V2}/investigations/{encoded}",
        {"status": "CLOSED", "disposition": disposition},
    )
    return {
        "rrn": result["rrn"],
        "status": result["status"],
        "disposition": result["disposition"],
    }


@mcp.tool()
def list_log_sets() -> list[dict]:
    """List available InsightIDR log sets with their contained log IDs. Call this first to discover log set names and IDs before calling query_logs."""
    result = _req("GET", f"{BASE_LOG_SEARCH}/management/logsets")
    return [
        {
            "id": ls["id"],
            "name": ls["name"],
            "log_ids": [log["id"] for log in ls.get("logs_info", [])],
        }
        for ls in result.get("logsets", [])
    ]


@mcp.tool()
def query_logs(
    log_ids: list[str],
    leql_statement: str,
    from_ms: int,
    to_ms: int,
    limit: int = 50,
) -> dict:
    """
    Execute a LEQL query against InsightIDR logs and return matching events.

    log_ids: individual log UUIDs from list_log_sets → log_ids (pass all IDs from the relevant log set)
    leql_statement: LEQL where/calculate clause, e.g. 'where(source_json.EventCode = 4741)'
    from_ms / to_ms: time window in milliseconds since epoch
    limit: max events to return (default 50)
    """
    body = {
        "leql": {
            "during": {"from": from_ms, "to": to_ms},
            "statement": leql_statement,
        },
        "logs": log_ids,
    }
    result = _req("POST", f"{BASE_LOG_SEARCH}/query/logs/", body)
    query_id = result.get("id")
    if not query_id:
        raise RuntimeError(f"No query ID in response: {result}")

    for _ in range(30):
        if result.get("status") not in ("RUNNING", "PROCESSING"):
            break
        time.sleep(1)
        result = _req("GET", f"{BASE_LOG_SEARCH}/query/logs/{query_id}")

    events = (result.get("results") or {}).get("events", [])[:limit]
    return {
        "status": result.get("status"),
        "total_count": (result.get("results") or {}).get("total_count", 0),
        "events": [
            {
                "timestamp": e.get("timestamp"),
                "message": e.get("message"),
                "log_name": (e.get("log") or {}).get("name"),
            }
            for e in events
        ],
    }


if __name__ == "__main__":
    mcp.run()
