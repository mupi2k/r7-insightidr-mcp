import json
import os
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
            "detection_rule": a.get("detection_rule_rrn", {}).get("rule_name"),
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


if __name__ == "__main__":
    mcp.run()
