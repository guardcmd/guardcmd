# guardcmd-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for
[GuardCMD](https://guardcmd.ai). It lets Claude Code, Cursor, and your own AI
apps check actions for abuse, screen prompts, authorize agent tool calls, and
manage GuardCMD projects and policies.

It runs locally over stdio with **your own** GuardCMD API key and calls the
GuardCMD API. Requires Node.js 20 or newer.

## Setup

Create an API key at [guardcmd.ai](https://guardcmd.ai), then:

**Claude Code**

```bash
claude mcp add guardcmd -e GUARDCMD_API_KEY=ag_live_... -- npx -y guardcmd-mcp
```

**Cursor, Claude Desktop, and other clients** (`mcp.json`)

```json
{
  "mcpServers": {
    "guardcmd": {
      "command": "npx",
      "args": ["-y", "guardcmd-mcp"],
      "env": { "GUARDCMD_API_KEY": "ag_live_..." }
    }
  }
}
```

| Environment variable | Required | Purpose |
| --- | --- | --- |
| `GUARDCMD_API_KEY` | yes | Your GuardCMD API key |
| `API_BASE_URL` | no | API origin (default `https://api.guardcmd.com`) |

The key grants the same access as your dashboard key. Keep it out of shared
config files and version control.

## Tools

**Runtime checks**

- `check_abuse`: score an action (signup, login, checkout, ...) and get
  `allow | challenge | throttle | review | block` with reasons.
- `screen_prompt`: screen a prompt for injection, data exfiltration, cost
  abuse, and harmful requests.
- `authorize_tool_call`: before an agent runs a tool, get
  `allow | require_approval | deny` based on the call, the user's intent, and
  untrusted context.

**Projects and findings**

- `list_projects`, `get_usage`
- `scan_repository`, `create_scan`, `get_scan`: map abuse surfaces in a repo
- `list_abuse_surfaces`, `list_recommendations`
- `create_protection_pr`: preview a protection patch, or open a pull request
  when called with `openPr: true`

**Agent hand-off (Fix Packs)**

- `get_fix_pack`: a scan's Fix Pack — `AGENT-TASK.md` with ordered tasks
  (file + line, patch, env keys, how to verify); `format` `md` (default),
  `json`, or `sarif`
- `get_recommendation_fix_pack`: the same for one recommendation
- Shareable handoff links are created in the GuardCMD dashboard (they need a
  signed-in session, not an API key)

**Security audits** (with Cloudflare's
[security-audit skill](https://github.com/cloudflare/security-audit-skill))

- `upload_security_audit`: upload the skill's `findings.json`; returns
  confirmed / needs-validation / rejected counts or the validation errors
- `list_security_audits`

**Prompts and resources**

| Name | What it does |
| --- | --- |
| `fix_abuse_surfaces` (scanId) | Fetch the Fix Pack and apply it task by task in shadow mode, testing after each |
| `protect_repo` (repoUrl, projectId?) | Scan, wait for the scan, fetch the Fix Pack, apply it |
| `deep_security_audit` (projectId) | Run Cloudflare's security-audit skill on the flagged routes and upload `findings.json` |
| `guardcmd://scans/{scanId}/fix-pack` | Resource: the scan's `AGENT-TASK.md` (markdown) |

**Policies and decisions**

- `list_policies`, `get_policy`, `set_rate_limit`
- `promote_policy` (requires `acknowledgeUserImpact: true`), `rollback_policy`
- `list_decisions`, `explain_decision`, `submit_feedback`, `get_metrics`

Tools that change state are labeled in their descriptions. Your MCP client
asks before calling them unless you have allowed them.

## Renamed from AbuseGuard

The `abuseguard-mcp` binary and the `ABUSEGUARD_API_KEY` variable still work
as deprecated aliases.

## License

MIT
