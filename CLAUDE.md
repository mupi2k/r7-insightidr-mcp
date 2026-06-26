# r7-insightidr-mcp

MCP server for Rapid7 InsightIDR investigation management, providing IR triage tools for AI-assisted security workflows.

## Git workflow

- Always create a **new feature branch** from `main` before making changes. Never commit directly to `main` or reuse stale branches.
- Branch naming: `feat/<short-description>`, `fix/<short-description>`, `chore/<short-description>`
- Open a PR and wait for explicit approval before merging — do not create and merge in the same step.

## Development

```bash
mise install       # installs Python and uv
mise run install   # installs dependencies into .venv
```

## Versioning

Version is in `pyproject.toml`. Bump on every PR: patch for fixes, minor for new tools, major for breaking changes.
