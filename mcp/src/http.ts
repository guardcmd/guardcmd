#!/usr/bin/env node
/**
 * Hosted HTTP entrypoint (Streamable HTTP MCP transport).
 *
 * Serves the GuardCMD MCP server over HTTP so remote MCP clients can connect:
 *   - POST /mcp   — client→server JSON-RPC (initialize, tools/list, tools/call, ...)
 *   - GET  /mcp   — server→client SSE stream (notifications) for an existing session
 *   - DELETE /mcp — terminate a session
 *   - GET  /health — healthcheck ({ ok, service, version })
 *
 * Binds 0.0.0.0:PORT (default 8080). Sessions are tracked by the
 * `mcp-session-id` header, each backed by its own McpServer instance.
 *
 * SECURITY MODEL — read this before changing anything below
 * ---------------------------------------------------------
 * This process holds a FULL-ACCESS GuardCMD API key (`GUARDCMD_API_KEY`) and exposes
 * the whole tool surface on the key owner's account, including high-impact operations
 * (`promote_policy` to `live` enforces on real user traffic; `create_protection_pr` with
 * `openPr: true` opens real GitHub PRs). A request to `/mcp` is therefore a request to act
 * AS the account owner, so the endpoint is authenticated:
 *
 *   1. Bearer auth on every `/mcp` method. `MCP_AUTH_TOKEN` is a shared secret; callers send
 *      `Authorization: Bearer <token>`. Compared with `crypto.timingSafeEqual` so a wrong
 *      token cannot be recovered byte-by-byte from response timing. The check runs BEFORE a
 *      transport or McpServer is allocated, so an anonymous caller can never make us spend
 *      memory or reach the API key. `/health` stays open — platform healthchecks need it and
 *      it reveals nothing but the service name and version.
 *
 *   2. FAIL CLOSED when `MCP_AUTH_TOKEN` is unset and the process looks like production
 *      (`NODE_ENV === "production"`). Failing closed
 *      takes the deployment offline until the var is set, which is the deliberate trade:
 *      an unauthenticated `/mcp` hands the internet a full-access key, and "briefly down"
 *      is recoverable in a way that "account driven by strangers" is not. The startup logs
 *      say exactly which variable to set, and every rejected request says so too.
 *      Outside production the missing token is tolerated as a local-development escape
 *      hatch — and even then each start logs a warning, so an unauthenticated server is
 *      never a quiet state.
 *
 *   3. Bounded session registry. Each `initialize` allocates a transport + McpServer, so an
 *      unbounded map of them is a memory-exhaustion DoS: a loop of `initialize` calls grows
 *      the process until the container is OOM-killed. We cap concurrent sessions
 *      (`MAX_SESSIONS`) and reject past the cap with a JSON-RPC error, and an idle sweep
 *      closes sessions nobody has touched for `SESSION_IDLE_TIMEOUT_MS` — clients that
 *      vanish without a DELETE never leave a transport behind forever.
 *
 *   4. DNS-rebinding / Host-header protection, so a malicious page cannot rebind a hostname
 *      to this service and drive it from a victim's browser. Configured from
 *      `MCP_ALLOWED_HOSTS` / `MCP_ALLOWED_ORIGINS`; see `createMcpHttpApp` for why the flag
 *      is only enabled when at least one list is non-empty.
 *
 *   5. `helmet()` for baseline response security headers.
 *
 * Env: PORT, API_BASE_URL, GUARDCMD_API_KEY, MCP_AUTH_TOKEN (required in production),
 *      MCP_ALLOWED_HOSTS, MCP_ALLOWED_ORIGINS, NODE_ENV.
 */

import { randomUUID, timingSafeEqual } from "node:crypto";
import { pathToFileURL } from "node:url";
import express, { type Express, type NextFunction, type Request, type Response } from "express";
import helmet from "helmet";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { createServer, resolveConfig } from "./server.js";

const SERVICE = "mcp";
const VERSION = "0.1.0";

/**
 * Max concurrent MCP sessions. Each one costs a transport + an McpServer + its registered
 * tool closures, so this is the knob that turns "unbounded allocation on an unauthenticated
 * loop" into a bounded, survivable failure. 256 is far above any legitimate fan-out for a
 * single-account MCP server while staying small enough to fit a modest container.
 */
export const MAX_SESSIONS = 256;

/** Close sessions with no request traffic for this long (clients that left without DELETE). */
export const SESSION_IDLE_TIMEOUT_MS = 30 * 60_000;

/** How often the idle sweep runs. Coarse on purpose — this is hygiene, not a hot path. */
export const SESSION_SWEEP_INTERVAL_MS = 60_000;

/**
 * Generic server-defined JSON-RPC error code (the -32000..-32099 reserved band). Used for
 * both auth refusals and capacity refusals; the message distinguishes them, and neither
 * needs a code a client would branch on.
 */
const JSON_RPC_SERVER_ERROR = -32000;

/**
 * How the `/mcp` endpoint is guarded, decided once at startup:
 *   - `enforced`         — `MCP_AUTH_TOKEN` is set; a matching bearer token is required.
 *   - `misconfigured`    — production-like process with no token: reject everything (fail closed).
 *   - `development-open` — non-production with no token: allowed, loudly, for local work.
 */
export type AuthPosture = "enforced" | "misconfigured" | "development-open";

function jsonRpcError(id: string | number | null, code: number, message: string) {
  return { jsonrpc: "2.0" as const, error: { code, message }, id };
}

/** Parse a comma-separated env list. */
function envList(value: string | undefined): string[] {
  return (value || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Resolve the HTTP transport's security configuration from the environment.
 *
 * Kept separate from `createMcpHttpApp` so the posture decision (the part with real
 * consequences — whether a tokenless deploy serves traffic) is one small, testable function
 * rather than a condition buried in middleware.
 */
export function resolveHttpSecurityConfig(env: NodeJS.ProcessEnv = process.env): {
  authToken: string;
  posture: AuthPosture;
  allowedHosts: string[];
  allowedOrigins: string[];
} {
  const authToken = (env.MCP_AUTH_TOKEN ?? "").trim();
  // Container images for the hosted service set NODE_ENV=production — so "looks like
  // production" is an accurate read of the deployed service, and a plain `node dist/http.js`
  // on a laptop is not.
  const isProduction = env.NODE_ENV === "production";
  const posture: AuthPosture = authToken
    ? "enforced"
    : isProduction
      ? "misconfigured"
      : "development-open";
  return {
    authToken,
    posture,
    allowedHosts: envList(env.MCP_ALLOWED_HOSTS),
    allowedOrigins: envList(env.MCP_ALLOWED_ORIGINS),
  };
}

/**
 * Constant-time comparison of an `Authorization: Bearer <token>` header against the shared
 * secret.
 *
 * `timingSafeEqual` THROWS when the two buffers differ in length, so the length is checked
 * first and a mismatch is a plain `false`. That does leak the secret's length, which is not
 * a useful lever for an attacker against a random token — whereas letting the throw escape
 * would turn a wrong token into a 500 and, worse, a byte-by-byte timing oracle is exactly
 * what we are avoiding by not using `===` here.
 */
export function isValidBearerToken(
  headerValue: string | undefined,
  expectedToken: string,
): boolean {
  if (!headerValue || !expectedToken) return false;
  const match = /^Bearer[ \t]+(\S.*)$/i.exec(headerValue.trim());
  if (!match) return false;
  const presented = Buffer.from(match[1].trim(), "utf8");
  const expected = Buffer.from(expectedToken, "utf8");
  if (presented.length !== expected.length) return false;
  return timingSafeEqual(presented, expected);
}

/** One live MCP session: the transport, its server, and when we last saw traffic for it. */
interface SessionEntry {
  transport: StreamableHTTPServerTransport;
  /** Kept so the idle sweep can tear down the server, not just orphan the map entry. */
  server: ReturnType<typeof createServer>;
  lastActivityAt: number;
}

export interface McpHttpAppOptions {
  /** Public API origin the tools call (env: API_BASE_URL). */
  baseUrl: string;
  /** Full-access GuardCMD API key this server acts with (env: GUARDCMD_API_KEY). */
  apiKey: string;
  /** Shared secret callers must present as `Authorization: Bearer <token>`. */
  authToken: string;
  /** Guard mode for `/mcp` — see {@link AuthPosture}. */
  posture: AuthPosture;
  /** Allowed `Host` header values for DNS-rebinding protection (env: MCP_ALLOWED_HOSTS). */
  allowedHosts?: string[];
  /** Allowed `Origin` header values for DNS-rebinding protection (env: MCP_ALLOWED_ORIGINS). */
  allowedOrigins?: string[];
  /** Override the session cap (tests use a small value to exercise the refusal path). */
  maxSessions?: number;
  /** Override the idle timeout (tests use a short one). */
  idleTimeoutMs?: number;
  /** Override the sweep interval (tests use a short one). */
  sweepIntervalMs?: number;
}

/**
 * Build the Express app for the hosted transport.
 *
 * Exported (rather than being inlined in `main`) so the security behavior can be tested over
 * real HTTP without booting the process or depending on env vars.
 *
 * @returns the app, the live session registry (for assertions), and `shutdown()` which stops
 *          the sweep timer and closes every open session.
 */
export function createMcpHttpApp(options: McpHttpAppOptions): {
  app: Express;
  sessions: Map<string, SessionEntry>;
  shutdown: () => Promise<void>;
} {
  const {
    baseUrl,
    apiKey,
    authToken,
    posture,
    allowedHosts = [],
    allowedOrigins = [],
    maxSessions = MAX_SESSIONS,
    idleTimeoutMs = SESSION_IDLE_TIMEOUT_MS,
    sweepIntervalMs = SESSION_SWEEP_INTERVAL_MS,
  } = options;

  const app = express();

  // Baseline security headers (nosniff, no-referrer, HSTS, frame-deny, ...).
  // Cheap, and keeps a browser that somehow reaches /mcp from treating our
  // JSON as something it can render or sniff.
  app.use(helmet());

  // Active sessions keyed by MCP session id.
  const sessions = new Map<string, SessionEntry>();

  // In SDK 1.30.0 the transport only validates Host/Origin when the corresponding list is
  // non-empty (verified in the installed `webStandardStreamableHttp` source), so turning the
  // flag on with both lists empty would be silently inert. We therefore enable it exactly
  // when something was configured — an operator who sets neither var gets the documented
  // "protection off" behavior instead of a false sense of it being on.
  const enableDnsRebindingProtection = allowedHosts.length > 0 || allowedOrigins.length > 0;

  app.get("/health", (_req: Request, res: Response) => {
    res.status(200).json({ ok: true, service: SERVICE, version: VERSION });
  });

  /**
   * Gate every `/mcp` method (POST/GET/DELETE) on the shared secret.
   *
   * Registered before the body parser and before any route handler, so an unauthorized
   * request is rejected having cost us nothing but a header comparison — no JSON parsing,
   * no transport, no McpServer, no access to the API key.
   */
  app.use("/mcp", (req: Request, res: Response, next: NextFunction) => {
    if (posture === "development-open") {
      next();
      return;
    }
    if (posture === "misconfigured") {
      res
        .status(503)
        .json(
          jsonRpcError(
            null,
            JSON_RPC_SERVER_ERROR,
            "Server misconfigured: MCP_AUTH_TOKEN is not set, so this server refuses all MCP " +
              "requests rather than expose an unauthenticated, full-access API key. Set " +
              "MCP_AUTH_TOKEN in the deployment environment and restart.",
          ),
        );
      return;
    }
    if (!isValidBearerToken(req.headers.authorization, authToken)) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="guardcmd-mcp"');
      res
        .status(401)
        .json(
          jsonRpcError(
            null,
            JSON_RPC_SERVER_ERROR,
            "Unauthorized: send 'Authorization: Bearer <MCP_AUTH_TOKEN>'.",
          ),
        );
      return;
    }
    next();
  });

  app.use(express.json({ limit: "1mb" }));

  /** Close a session's server (which closes its transport) and drop it from the registry. */
  async function closeSession(sessionId: string, entry: SessionEntry): Promise<void> {
    try {
      // Closing the McpServer closes the transport underneath it, which fires
      // `transport.onclose` and removes the map entry. Dropping the entry without this would
      // leak the transport's open streams and the server's registered tools.
      await entry.server.close();
    } catch (err) {
      console.error(`[guardcmd-mcp:http] error closing session ${sessionId}:`, err);
    } finally {
      sessions.delete(sessionId);
    }
  }

  /**
   * Periodically reap sessions with no traffic for `idleTimeoutMs`.
   *
   * MCP clients are not required to send DELETE, and a crashed or disconnected client never
   * will — without this sweep those sessions are indistinguishable from a slow memory leak.
   * The timer is `unref()`d so it can never be the reason the process refuses to exit.
   */
  const sweepTimer = setInterval(() => {
    const cutoff = Date.now() - idleTimeoutMs;
    for (const [sessionId, entry] of sessions) {
      if (entry.lastActivityAt <= cutoff) {
        void closeSession(sessionId, entry);
      }
    }
  }, sweepIntervalMs);
  sweepTimer.unref();

  // POST /mcp — main JSON-RPC endpoint.
  app.post("/mcp", async (req: Request, res: Response) => {
    try {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;
      const existing = sessionId ? sessions.get(sessionId) : undefined;
      if (existing) existing.lastActivityAt = Date.now();
      let transport: StreamableHTTPServerTransport | undefined = existing?.transport;

      if (!transport) {
        if (sessionId) {
          res
            .status(404)
            .json(jsonRpcError(null, -32001, "Unknown or expired session"));
          return;
        }
        if (!isInitializeRequest(req.body)) {
          res
            .status(400)
            .json(
              jsonRpcError(
                null,
                JSON_RPC_SERVER_ERROR,
                "Bad Request: no valid session id and not an initialize request",
              ),
            );
          return;
        }
        // Refuse past the cap BEFORE allocating anything. 503 + Retry-After tells an honest
        // client to come back; an abusive `initialize` loop just bounces off a constant-cost
        // check instead of growing the heap.
        if (sessions.size >= maxSessions) {
          res.setHeader("Retry-After", "60");
          res
            .status(503)
            .json(
              jsonRpcError(
                null,
                JSON_RPC_SERVER_ERROR,
                `Too many active MCP sessions (limit ${maxSessions}). Close an existing session (DELETE /mcp) or retry later.`,
              ),
            );
          return;
        }

        // New session: create a transport + its own server instance.
        const server = createServer({ baseUrl, apiKey });
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          enableDnsRebindingProtection,
          allowedHosts,
          allowedOrigins,
          onsessioninitialized: (sid: string) => {
            sessions.set(sid, {
              transport: transport!,
              server,
              lastActivityAt: Date.now(),
            });
          },
        });

        transport.onclose = () => {
          if (transport!.sessionId) sessions.delete(transport!.sessionId);
        };

        await server.connect(transport);
      }

      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error("[guardcmd-mcp:http] POST /mcp error:", err);
      if (!res.headersSent) {
        res.status(500).json(jsonRpcError(null, -32603, "Internal server error"));
      }
    }
  });

  // GET /mcp — SSE stream for server-initiated messages on an existing session.
  app.get("/mcp", async (req: Request, res: Response) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    const entry = sessionId ? sessions.get(sessionId) : undefined;
    if (!entry) {
      res.status(400).send("Invalid or missing session id");
      return;
    }
    entry.lastActivityAt = Date.now();
    await entry.transport.handleRequest(req, res);
  });

  // DELETE /mcp — terminate a session.
  app.delete("/mcp", async (req: Request, res: Response) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    const entry = sessionId ? sessions.get(sessionId) : undefined;
    if (!entry) {
      res.status(400).send("Invalid or missing session id");
      return;
    }
    entry.lastActivityAt = Date.now();
    await entry.transport.handleRequest(req, res);
  });

  async function shutdown(): Promise<void> {
    clearInterval(sweepTimer);
    await Promise.all(
      [...sessions].map(([sessionId, entry]) => closeSession(sessionId, entry)),
    );
  }

  return { app, sessions, shutdown };
}

async function main(): Promise<void> {
  const { baseUrl, apiKey } = resolveConfig();
  if (!baseUrl || !apiKey) {
    console.error(
      "[guardcmd-mcp:http] Missing required env. Set API_BASE_URL and GUARDCMD_API_KEY (or the legacy ABUSEGUARD_API_KEY).",
    );
    process.exit(1);
  }

  const { authToken, posture, allowedHosts, allowedOrigins } = resolveHttpSecurityConfig();

  // Say the posture out loud at startup. A server that is open to the internet must never be
  // a state an operator has to go reading code to discover.
  if (posture === "misconfigured") {
    console.error(
      "[guardcmd-mcp:http] SECURITY: MCP_AUTH_TOKEN is not set and NODE_ENV=production. " +
        "Every /mcp request will be rejected with 503 until it is set, because this server " +
        "holds a full-access GUARDCMD_API_KEY and an unauthenticated /mcp would let anyone " +
        "drive the account. FIX: set MCP_AUTH_TOKEN (a long random secret) in the deployment " +
        "environment (Railway → service → Variables) and redeploy, then send it as " +
        "'Authorization: Bearer <token>'.",
    );
  } else if (posture === "development-open") {
    console.error(
      "[guardcmd-mcp:http] WARNING: MCP_AUTH_TOKEN is not set and NODE_ENV is not " +
        "'production', so /mcp is UNAUTHENTICATED (local-development escape hatch). Anyone " +
        "who can reach this port can use your GUARDCMD_API_KEY. Never expose this process.",
    );
  }
  if (!allowedHosts.length && !allowedOrigins.length) {
    console.error(
      "[guardcmd-mcp:http] NOTE: DNS-rebinding protection is off — set MCP_ALLOWED_HOSTS " +
        "(and/or MCP_ALLOWED_ORIGINS) to a comma-separated list, e.g. your Railway hostname.",
    );
  }

  const { app, shutdown } = createMcpHttpApp({
    baseUrl,
    apiKey,
    authToken,
    posture,
    allowedHosts,
    allowedOrigins,
  });

  const port = Number(process.env.PORT ?? 8080);
  const httpServer = app.listen(port, "0.0.0.0", () => {
    console.error(
      `[guardcmd-mcp:http] listening on 0.0.0.0:${port} (API_BASE_URL=${baseUrl}, auth=${posture}) — MCP at /mcp, health at /health`,
    );
  });

  // Close sessions on a platform-initiated stop so in-flight transports get a chance to
  // shut down cleanly instead of being killed mid-stream.
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    process.once(signal, () => {
      void shutdown().finally(() => httpServer.close(() => process.exit(0)));
    });
  }
}

/**
 * Only run the server when this file is the process entrypoint (`node dist/http.js`), so the
 * tests can import `createMcpHttpApp` without booting a listener or tripping the env checks.
 */
const isEntrypoint = (() => {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(entry).href;
  } catch {
    return false;
  }
})();

if (isEntrypoint) {
  main().catch((err) => {
    console.error("[guardcmd-mcp:http] fatal:", err);
    process.exit(1);
  });
}
