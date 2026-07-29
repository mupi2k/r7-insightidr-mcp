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
BASE_AT = f"https://{REGION}.api.insight.rapid7.com/idr/at"
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
def get_alert_evidences(alert_rrn: str) -> dict:
    """
    Fetch the evidence record for an R7 alert (use the alert id from get_investigation alerts[].id).

    For Cortex XDR-sourced investigations this is the primary enrichment path — it returns the
    Cortex alert ID and full actor/host context directly from the ingested log, bypassing the
    unreliable name-based Cortex search.
    """
    encoded = _encode_rrn(alert_rrn)
    resp = _req("GET", f"{BASE_AT}/alerts/{encoded}/evidences")
    evidences = resp.get("evidences", [])

    cortex_alert_ids: list[str] = []
    actors: list[dict] = []

    for ev in evidences:
        data_str = ev.get("data") or ""
        if not data_str:
            continue
        try:
            data = json.loads(data_str)
        except (ValueError, KeyError):
            continue

        alert_id = data.get("alert_id")
        if alert_id:
            cortex_alert_ids.append(str(alert_id))

        actors.append({
            "host_name": data.get("host_name") or data.get("asset"),
            "username": data.get("user_name"),
            "actor_process_image_name": data.get("actor_process_image_name"),
            "actor_process_command_line": data.get("actor_process_command_line"),
            "causality_actor_process_image_name": data.get("causality_actor_process_image_name"),
            "causality_actor_process_command_line": data.get("causality_actor_process_command_line"),
            "mitre_tactic": data.get("mitre_tactic_id_and_name"),
            "mitre_technique": data.get("mitre_technique_id_and_name"),
            "description": data.get("description"),
            "category": data.get("category"),
            "detection_timestamp": data.get("detection_timestamp"),
            "alert_name": data.get("name"),
        })

    return {
        "cortex_alert_ids": cortex_alert_ids,
        "evidence_count": len(evidences),
        "actors": actors,
    }


@mcp.tool()
def get_rule_definition(rule_rrn: str) -> dict:
    """Get the full definition of a detection rule by its RRN."""
    encoded = _encode_rrn(rule_rrn)
    return _req("GET", f"{BASE_V1}/rules/{encoded}")


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

    Polls for up to 60 seconds, which comfortably covers a narrow/quick query (e.g. a
    single alert's ~30-minute window). Broad-scope queries (many log_ids, wide time
    windows) or groupby/calculate aggregations can take several minutes and may not
    finish inside that budget -- check the returned "complete" field: if False,
    total_count/events reflect a partial, not final, result, and this tool is the
    wrong one for that query (aggregations aren't parsed here at all). Re-running
    won't help; a query that doesn't finish in 60s needs a purpose-built long-poll
    tool instead.

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

    # progress absent → already complete; only poll if query is still running
    complete = result.get("progress") is None
    if not complete:
        poll_url = next(
            (l["href"] for l in result.get("links", []) if l.get("rel") == "Self"), None
        )
        if not poll_url:
            raise RuntimeError(f"No poll URL in response: {result}")

        for _ in range(60):
            time.sleep(1)
            result = _req("GET", poll_url)
            if result.get("progress") is None:
                complete = True
                break

    events = result.get("events", [])[:limit]
    return {
        "complete": complete,
        "total_count": (result.get("search_stats") or {}).get("events_matched", 0),
        "events": [
            {
                "timestamp": e.get("timestamp"),
                "log_id": e.get("log_id"),
                "message": e.get("message"),
            }
            for e in events
        ],
    }


_PROCESS_LOG_SET_NAMES = {"Endpoint Agent", "Endpoint Activity", "Raw Log"}


def _default_process_log_ids() -> list[str]:
    result = _req("GET", f"{BASE_LOG_SEARCH}/management/logsets")
    return [
        log["id"]
        for ls in result.get("logsets", [])
        if ls["name"] in _PROCESS_LOG_SET_NAMES
        for log in ls.get("logs_info", [])
    ]


def _wait_for_completion(result: dict) -> dict:
    if result.get("progress") is None:
        return result
    poll_url = next((l["href"] for l in result.get("links", []) if l.get("rel") == "Self"), None)
    if not poll_url:
        raise RuntimeError(f"No poll URL in response: {result}")
    for _ in range(60):
        time.sleep(1)
        result = _req("GET", poll_url)
        if result.get("progress") is None:
            return result
    raise RuntimeError(
        "Query did not complete within 60s -- narrow the time window/log_ids "
        "and try again rather than retrying as-is"
    )


@mcp.tool()
def check_prevalence(
    exe_path_contains: str,
    days_back: int = 30,
    log_ids: list[str] | None = None,
    max_events: int = 250,
) -> dict:
    """
    Check how widespread a process/tool is across the org, grouped by exe_path and
    username. Use this before reaching out to an individual about "unusual"
    software -- it may turn out to be long-standing, widespread use rather than a
    one-off.

    Deliberately avoids LEQL groupby/calculate aggregation: that path scans raw
    event volume rather than using the indexed search R7 uses for plain where()
    queries, so it can take many minutes even at modest scope -- and an invalid
    nested field reference in the groupby clause has been observed to silently
    zero out the *entire* result (not just the aggregation) rather than erroring.
    Instead, this runs a fast where() search, walks paginated results, and groups
    client-side.

    Stops after max_events matching events to bound runtime -- each page of results
    costs a few seconds regardless of page size (observed ~6s/page at 50 events per
    page, seemingly real per-page server-side work rather than free pagination), so
    max_events trades runtime for sample size: the default (250, ~5 pages) finishes
    in well under a minute. If "truncated" is true, the tool is in even wider use
    than the counts reflect -- true counts for a genuinely widespread tool can run
    into the hundreds of thousands of process starts, since polling/health-check
    subprocesses can dominate raw invocation counts. Treat group counts as a
    relative signal ("N distinct people are using this"), not an exact total.

    exe_path_contains: substring to match against process.exe_path
    days_back: how many days back to search (default 30)
    log_ids: specific log IDs to search; omit to search the default endpoint-telemetry
        log sets (Endpoint Agent, Endpoint Activity, Raw Log)
    max_events: cap on total matching events fetched before stopping (default 250)
    """
    to_ms = int(time.time() * 1000)
    from_ms = to_ms - days_back * 24 * 60 * 60 * 1000
    body = {
        "leql": {
            "during": {"from": from_ms, "to": to_ms},
            "statement": f'where("process.exe_path" contains "{exe_path_contains}")',
        },
        "logs": log_ids or _default_process_log_ids(),
    }
    result = _wait_for_completion(_req("POST", f"{BASE_LOG_SEARCH}/query/logs/", body))

    counts: dict[tuple[str, str], int] = {}
    fetched = 0
    truncated = False
    while True:
        for e in result.get("events", []):
            try:
                proc = (json.loads(e.get("message") or "{}").get("process")) or {}
            except json.JSONDecodeError:
                proc = {}
            key = (proc.get("exe_path") or "?", proc.get("username") or "?")
            counts[key] = counts.get(key, 0) + 1
        fetched += len(result.get("events", []))

        next_url = next((l["href"] for l in result.get("links", []) if l.get("rel") == "Next"), None)
        if not next_url or fetched >= max_events:
            truncated = bool(next_url) and fetched >= max_events
            break
        result = _wait_for_completion(_req("GET", next_url))

    groups = [
        {"exe_path": exe_path, "username": username, "count": count}
        for (exe_path, username), count in sorted(counts.items(), key=lambda kv: -kv[1])
    ]
    return {"groups": groups, "events_fetched": fetched, "truncated": truncated}


if __name__ == "__main__":
    mcp.run()
