---
name: guardcmd
license: MIT
description: >
  Add GuardCMD abuse protection to an application. Use when the user asks to
  protect signups, logins, password resets, OTP/SMS sends, checkout, AI/LLM
  endpoints, or agent tool calls from bots, multi-accounting, credential
  stuffing, free-credit farming, prompt injection, or runaway cost. Finds the
  abuse surfaces in the codebase, wires the SDK at each one in shadow mode,
  and verifies the first decision arrives. Also covers screening prompts and
  authorizing agent tool calls, and connecting the GuardCMD MCP server.
---

# Add GuardCMD to an app

> Installed via `claude plugin install guardcmd@guardcmd` or
> `npx skills add guardcmd/guardcmd --skill guardcmd`.


GuardCMD (SDK package: `guardcmd`) scores each sensitive event 0–100 and returns one graduated action:
`allow`, `challenge`, `throttle`, `review`, or `block`. Your job is to find the
places in this codebase where abuse costs the user money or trust, put one
`evaluate` call at each, and ship it in **shadow mode** so nothing is blocked
until the user has seen real decisions.

Work in this order. Do not skip the discovery step: the value is in protecting
the right routes, not in installing a package.

## 1. Get credentials

The user needs an API key. The fastest path is the onboarding wizard at
`https://guardcmd.ai/start`: paste a public repository URL and it maps the
abuse surfaces, generates the protection patch, and mints a key. (One-click
GitHub App install, for private repos and PRs opened for you, is coming.)
If they already have a key, ask for it to be put in the environment. Never
paste a key into source files, commits, or chat logs.

```bash
GUARDCMD_API_KEY=ag_live_...
```

Add it to `.env.example` as a placeholder and to the deployment platform's
secret store. The SDK defaults to `https://api.guardcmd.com`, so no base URL
is needed; set `GUARDCMD_BASE_URL` only to point at a different environment.

## 2. Find the abuse surfaces

Detect the framework from `package.json` (Next.js App Router, Express,
Fastify, Hono, Koa) and list route handlers. Rank what you find:

| Surface | What to look for | Typical abuse |
| --- | --- | --- |
| `signup` | user creation, `createUser`, auth provider sign-up | bot signups, multi-accounting, free-credit farming |
| `login` | password verification, session creation | credential stuffing, password spraying |
| `password_reset` / `otp.send` | email/SMS sends, Twilio, Resend, SES | SMS toll fraud, email bombing |
| `ai.generate` | OpenAI/Anthropic/any model call, image/video generation | token farming, denial of wallet, prompt injection |
| `checkout` / `trial` / `referral` | Stripe, coupons, trial creation | card testing, promo abuse |
| `message.send` / `comment.create` | user-generated content | spam, harassment |
| agent tools / MCP tools | functions an LLM can call that write, send, or pay | unauthorized or injected tool calls |

Show the user the ranked list before editing. Protect the top 1–3 first.

## 3. Wire the SDK (shadow mode)

```bash
npm install guardcmd
```

Create one shared client (module singleton):

```ts
// lib/guardcmd.ts
import { createGuardCMD } from "guardcmd/cloud";

// Reads GUARDCMD_API_KEY, and defaults to https://api.guardcmd.com
export const guard = createGuardCMD();
```

**Next.js App Router** — wrap the handler; a blocking decision short-circuits:

```ts
// app/api/signup/route.ts
import { protect } from "guardcmd/next";
import { guard } from "@/lib/guardcmd";

export const POST = protect(
  guard,
  { action: "signup", email: async ({ request }) => (await request.clone().json()).email },
  async (request, decision) => {
    // existing handler body; decision.action is available for logging/flagging
    return Response.json({ ok: true });
  },
);
```

**Express / Fastify / Hono / Koa / anything else** — call `evaluate` and branch:

```ts
const decision = await guard.evaluate({
  action: "login",
  actorId: user?.id,          // stable id if known
  ip: clientIp(req),          // server-derived; never trust a client-sent IP
  email: req.body.email,
  userAgent: req.get("user-agent"),
});
if (decision.enforced && decision.action === "block") return res.status(403).end();
if (decision.enforced && decision.action === "throttle") return res.status(429).end();
if (decision.enforced && decision.action === "challenge") return res.status(428).end();
// "review": allow, but flag the user for a human to look at
```

For AI endpoints pass `units` (estimated cost units, e.g. tokens / 1000) so
budgets are cost-weighted: `{ action: "ai.generate", actorId, units }`.

Rules:
- Reuse existing auth context for `actorId`; don't invent ids.
- Derive IP server-side (`X-Forwarded-For` first hop only behind a trusted proxy).
- The client never throws and fails open on outage; don't wrap it in extra try/catch that changes that.
- Shadow mode is the account default: `decision.enforced` stays `false` until the user promotes a policy in the dashboard. Keep the `enforced` checks so promotion needs no code change.

## 4. Screen prompts and agent tool calls (AI apps)

Before sending user input or retrieved content to a model:

```ts
const res = await fetch("https://api.guardcmd.com/v1/guard/prompt", {
  method: "POST",
  headers: { authorization: `Bearer ${process.env.GUARDCMD_API_KEY}`, "content-type": "application/json" },
  body: JSON.stringify({ prompt: userMessage, actorId: user.id }),
});
const verdict = await res.json(); // { decision: "allow" | "review" | "block", score, reasons, degraded }
```

Before executing a tool the model asked for (especially one that writes, sends, or pays):

```ts
const res = await fetch("https://api.guardcmd.com/v1/guard/tool-call", {
  method: "POST",
  headers: { authorization: `Bearer ${process.env.GUARDCMD_API_KEY}`, "content-type": "application/json" },
  body: JSON.stringify({
    tool: { name: "send_email", mutating: true },
    args,
    userIntent: originalUserRequest,
    untrustedContext: retrievedDocsOrToolOutput,
  }),
});
const { decision } = await res.json(); // "allow" | "require_approval" | "deny"
```

Treat `require_approval` as "pause and ask a human". Model judgments here are
evidence, never authority: they can only add restriction, not grant access.

## 5. Connect the MCP server (optional)

Lets the user's coding agent list surfaces, explain decisions, and manage
policies. Run the MCP server locally with the user's own key:

```bash
claude mcp add guardcmd \
  -e GUARDCMD_API_KEY=$GUARDCMD_API_KEY \
  -- npx -y guardcmd-mcp
```

## 6. Verify

After the change is deployed (or running locally with the env set), trigger
the protected route once, then confirm a decision arrived: the dashboard's
Decisions page, or the MCP `list_decisions` tool. If nothing arrives, check
in order: the key is set in the running process, the evaluate call is
actually on the request path, and outbound HTTPS
is allowed.

Tell the user what was protected, that it is in shadow mode, and that they
should promote to enforce from the dashboard after reviewing a few days of
decisions.

## Don'ts

- Don't block on shared-IP signals alone; route those to `review`.
- Don't send raw request bodies, passwords, or payment data in `meta`.
- Don't put the API key in client-side code; every call is server-side.
- Don't enable enforcement on the user's behalf.
