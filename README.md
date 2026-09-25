# GuardCMD

Abuse protection for apps and AI agents. GuardCMD scores sensitive events —
signups, logins, AI generations, messages, agent tool calls — from 0 to 100 and
returns one graduated action: `allow`, `challenge`, `throttle`, `review`, or
`block`.

[![M8ven Score](https://m8ven.ai/badge/mcp/guardcmd-guardcmd-x18fqc?v=b204003f31dc3835a3fe63dd6d72b248)](https://m8ven.ai/mcp/guardcmd-guardcmd-x18fqc)

- **Site and dashboard:** [guardcmd.ai](https://guardcmd.ai)
- **API:** `https://api.guardcmd.com`
- **SDK:** [`guardcmd`](https://www.npmjs.com/package/guardcmd)
- **MCP server:** [`guardcmd-mcp`](https://www.npmjs.com/package/guardcmd-mcp)

This repository holds GuardCMD's **agent skill**, so your coding agent can add
protection for you, and the auditable source for the **MCP server** in
[`mcp/`](mcp/).

## Start with a prompt

Install the skill, then ask your agent to protect the app.

**Claude Code**

```bash
claude plugin marketplace add guardcmd/guardcmd
claude plugin install guardcmd@guardcmd
```

**Other agents** (Cursor, Codex, and anything the `skills` CLI supports)

```bash
npx skills add guardcmd/guardcmd --skill guardcmd
```

Then:

> Add GuardCMD protection to my app.

The skill finds the abuse surfaces in your codebase, ranks them by what abuse
actually costs you, wires the SDK at the top few, and ships in **shadow mode**
so nothing is blocked until you have seen real decisions.

## Start with code

```bash
npm install guardcmd
```

```ts
import { createGuardCMD } from "guardcmd/cloud";

const guard = createGuardCMD(); // reads GUARDCMD_API_KEY

const decision = await guard.evaluate({
  action: "signup",
  actorId: user.id,
  ip: clientIp,          // derive server-side; never trust a client-sent IP
  email: body.email,
});

if (decision.enforced && decision.action === "block") return res.status(403).end();
```

Get a key from [guardcmd.ai/start](https://guardcmd.ai/start): paste a public
repository URL and GuardCMD maps its abuse surfaces, generates the protection
patch, and mints the key.

The client never throws and fails open on an outage. New projects start in
shadow mode: decisions are computed and logged, `decision.enforced` stays
`false`, and nothing is blocked until you promote a policy.

## Start with an agent

```bash
claude mcp add guardcmd -e GUARDCMD_API_KEY=ag_live_... -- npx -y guardcmd-mcp
```

Twenty tools, including `check_abuse`, `screen_prompt` (prompt injection, data
exfiltration, cost abuse) and `authorize_tool_call`, which returns
`allow | require_approval | deny` before your agent runs a tool. Model judgment
is evidence there, never authority: it can only tighten a decision.

## What it defends against

Bot signups and multi-accounting · credential stuffing and password spraying ·
free-credit and trial farming · LLM token farming and denial of wallet ·
scraping and bulk export · SMS/OTP toll fraud · spam and abusive content ·
prompt injection and unauthorized agent tool calls.

## MCP server source

[`mcp/`](mcp/) is the source for the [`guardcmd-mcp`](https://www.npmjs.com/package/guardcmd-mcp)
npm package: all 20 tools, the stdio and HTTP transports, and the test suite. It builds
byte-for-byte to the published `guardcmd-mcp@0.1.0`, and
[`mcp/PROVENANCE.md`](mcp/PROVENANCE.md) shows how to check that yourself. The server only
talks to the public API at `https://api.guardcmd.com`.

## Docs

Full documentation, including the REST API and the AI guard endpoints, is at
[guardcmd.ai/docs](https://guardcmd.ai/docs).

## License

MIT
