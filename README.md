# Rapid7 InsightIDR MCP Server

A [FastMCP](https://github.com/jlowin/fastmcp) server that exposes Rapid7 InsightIDR investigation management as MCP tools, enabling AI-assisted security triage workflows.

## Requirements

- [mise](https://mise.jdx.dev/) for tool management
- Python 3.10+

## Setup

```bash
mise install       # installs Python and uv
uv sync            # installs dependencies into .venv
```

## Configuration

The following environment variables are required:

| Variable | Description |
|---|---|
| `RAPID7_API_KEY` | Rapid7 Insight Platform API key |
| `RAPID7_USER_EMAIL` | Email address of the user (used by `assign_to_me`) |
| `RAPID7_REGION` | Rapid7 region prefix (default: `us`) — see [Rapid7 region docs](https://docs.rapid7.com/insight/api-overview/#base-urls) |

## Claude Code Setup

After running `mise install` and `uv sync`, register the server using the venv's Python so it works regardless of what's on your shell PATH:

```bash
claude mcp add --scope user r7-insightidr -- /path/to/r7-mcp/.venv/bin/python /path/to/r7-mcp/server.py
```

Ensure the required environment variables are available in the shell session where Claude Code runs.

## Tools

| Tool | Description |
|---|---|
| `list_investigations` | List investigations filtered by assignee (`unassigned`, `me`, `any`) and status |
| `get_investigation` | Get full details and linked alerts for an investigation by RRN |
| `assign_to_me` | Assign an investigation to the configured user |
| `set_status` | Update investigation status (`OPEN`, `INVESTIGATING`, `WAITING`) |
| `add_comment` | Add a comment to an investigation |
| `close_investigation` | Close an investigation with a disposition (`BENIGN`, `MALICIOUS`, `NOT_APPLICABLE`) |

## Notes

- Investigations are identified by RRN (Rapid7 Resource Name), e.g. `rrn:investigation:us:...:investigation:XXXXXXXX`
- The `assignee=me` filter uses `RAPID7_USER_EMAIL` to filter by the configured user
- Comments use the v1 API (`/idr/v1/comments`) with a `target` field pointing to the investigation RRN — the v2 comments endpoint is not functional
