/**
 * Shared MCP server factory for GuardCMD Cloud.
 *
 * Builds an `McpServer` and registers the two tools defined by the MCP contract
 * (platform/CONTRACT.md):
 *   - `check_abuse` — mirrors POST /v1/evaluate, returns the decision.
 *   - `get_usage`   — mirrors GET /v1/usage, returns plan/used/remaining.
 *
 * Both the stdio and HTTP entrypoints call `createServer()` so behavior is identical
 * across transports.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  GuardCMDClient,
  ApiError,
  type GuardCMDClientOptions,
  type EvaluateDecision,
  type UsageResult,
  type Project,
  type Scan,
  type Surface,
  type Recommendation,
  type AutofixResult,
  type OpenPullRequestResponse,
  type Policy,
  type DecisionList,
  type Decision,
  type MetricsSummary,
  type ScreenPromptResult,
  type AuthorizeToolCallResult,
} from "./client.js";

export interface CreateServerOptions {
  /** Public API origin, e.g. https://api.guardcmd.com (env: API_BASE_URL). */
  baseUrl?: string;
  /** Caller's API key (env: GUARDCMD_API_KEY). */
  apiKey?: string;
  /** Pre-built client (used by tests). Overrides baseUrl/apiKey if provided. */
  client?: GuardCMDClient;
  /** Passthrough for the underlying client (custom fetch, timeout). */
  clientOptions?: Partial<Pick<GuardCMDClientOptions, "fetchImpl" | "timeoutMs">>;
}

/** Public GuardCMD API origin used when no base URL is configured. */
export const DEFAULT_API_BASE_URL = "https://api.guardcmd.com";

/** Resolve config from options, falling back to env vars with the exact contract names. */
export function resolveConfig(opts: CreateServerOptions = {}): {
  baseUrl: string;
  apiKey: string;
} {
  // API_BASE_URL is the service contract name; GUARDCMD_BASE_URL matches the SDK. Default to the
  // public API so a customer running `npx guardcmd-mcp` only has to supply their key.
  const baseUrl =
    opts.baseUrl ?? (process.env.API_BASE_URL || process.env.GUARDCMD_BASE_URL || DEFAULT_API_BASE_URL);
  // GUARDCMD_API_KEY first; ABUSEGUARD_API_KEY is the deprecated pre-rename name, kept as a
  // fallback so existing configurations keep working.
  const apiKey =
    opts.apiKey ?? (process.env.GUARDCMD_API_KEY || process.env.ABUSEGUARD_API_KEY || "");
  return { baseUrl, apiKey };
}

// ---- Tool input schemas (raw zod shapes so the SDK emits JSON Schema) ----

const checkAbuseShape = {
  action: z
    .string()
    .min(1)
    .describe(
      "The action being evaluated, e.g. 'signup', 'login', 'post_comment', 'checkout'. Required.",
    ),
  actorId: z
    .string()
    .optional()
    .describe("Stable identifier for the acting user/account, if known."),
  ip: z
    .string()
    .optional()
    .describe("Client IP address. If omitted the API fills it from the request."),
  email: z.string().optional().describe("Email address associated with the action."),
  fingerprint: z
    .string()
    .optional()
    .describe("Device/browser fingerprint hash, if available."),
  userAgent: z
    .string()
    .optional()
    .describe("Client User-Agent string. If omitted the API may fill it in."),
  content: z
    .string()
    .optional()
    .describe("Free-text content to run through AI content moderation (e.g. a comment)."),
  meta: z
    .record(z.string(), z.unknown())
    .optional()
    .describe("Arbitrary additional key/value context for the evaluation."),
  timestamp: z
    .string()
    .optional()
    .describe("ISO-8601 timestamp of the event (defaults to now)."),
};

const getUsageShape = {} as const;

// ---- Repository-scan control-plane tool schemas ----

const listProjectsShape = {} as const;

/**
 * Input for `scan_repository` (formerly `create_scan`).
 *
 * The old shape took `path`: an absolute path on the API HOST, passed straight through to
 * `POST /v1/projects/:id/scans`. That endpoint is now 501 `local_path_scans_disabled` by
 * default, because a caller-named scan root was an arbitrary-file-read primitive — scan a
 * host directory, then pull whole file contents back out through the autofix endpoint. The
 * tool was renamed along with the shape so an agent reading the tool list sees a new
 * contract rather than silently sending the old arguments into a 501.
 *
 * `repoUrl` is the supported replacement: the SERVER clones the repo into a disposable
 * sandbox it owns, so the caller never names a filesystem location. Public GitHub repos
 * only; a private repo needs the GitHub App (`POST /v1/projects/:id/scan-github`), which
 * is not exposed as a tool yet.
 */
const scanRepositoryShape = {
  projectId: z
    .string()
    .min(1)
    .describe("ID of the project to scan (create/list projects out of band)."),
  repoUrl: z
    .string()
    .min(1)
    .describe(
      "HTTPS URL of a PUBLIC GitHub repository to scan, e.g. " +
        "'https://github.com/owner/repo'. The server clones it itself into a disposable " +
        "sandbox — local/server filesystem paths are not accepted.",
    ),
};

/**
 * Input for `create_scan` — the DEPRECATED compatibility alias for `scan_repository`.
 *
 * `repoUrl` is optional (not required) here on purpose, unlike on `scan_repository`: making it
 * required would let zod reject a legacy `{ projectId, path }` call at the schema boundary
 * before the handler ever runs, which would surface as a terse, generic "invalid arguments"
 * protocol error. Validating in the handler instead lets us return a precise, actionable tool
 * error naming the security reason, the replacement argument, and the canonical tool — see
 * `runScanRepository` / the `create_scan` registration below for why that's the goal.
 *
 * `path` is declared (as optional, and always optional) ONLY so a legacy call can be detected
 * and rejected with that actionable message. It is never read for any other purpose, never
 * forwarded to the API client, and must never become load-bearing — see the WHY comment on the
 * `create_scan` registration below before "restoring" anything that reads it.
 */
const createScanShape = {
  projectId: z
    .string()
    .min(1)
    .describe("ID of the project to scan (create/list projects out of band)."),
  repoUrl: z
    .string()
    .min(1)
    .optional()
    .describe(
      "HTTPS URL of a PUBLIC GitHub repository to scan, e.g. 'https://github.com/owner/repo' " +
        "— identical to `scan_repository`'s `repoUrl`. The server clones it itself into a " +
        "disposable sandbox; local/server filesystem paths are not accepted.",
    ),
  path: z
    .string()
    .optional()
    .describe(
      "REMOVED. The legacy server-filesystem scan root. No longer supported for any value — " +
        "sending it returns an error explaining why and telling you to send `repoUrl` instead. " +
        "Never accepted, never acted on.",
    ),
};

const getScanShape = {
  scanId: z.string().min(1).describe("ID of the scan to fetch."),
};

const listAbuseSurfacesShape = {
  projectId: z
    .string()
    .optional()
    .describe("Project ID — returns surfaces from its latest completed scan."),
  scanId: z
    .string()
    .optional()
    .describe("Scan ID — returns surfaces from this specific scan. Takes precedence over projectId."),
  unprotectedOnly: z
    .boolean()
    .optional()
    .describe(
      "If true, only return surfaces with no existing protection (no `existing_protection` evidence).",
    ),
  priority: z
    .array(z.string())
    .optional()
    .describe("Filter to these priority buckets, e.g. ['critical','high']."),
};

const listRecommendationsShape = {
  surfaceId: z.string().min(1).describe("ID of the surface to get recommendations for."),
};

const createProtectionPrShape = {
  recommendationId: z
    .string()
    .min(1)
    .describe("ID of the recommendation to generate a protection patch for."),
  openPr: z
    .boolean()
    .optional()
    .describe(
      "If true, OPEN A REAL GitHub pull request (requires the project to have a linked GitHub " +
        "repo + a configured GitHub App). If false/omitted, only generate the diff for review.",
    ),
  ref: z
    .string()
    .optional()
    .describe("Base branch/ref for the PR (defaults to the repo's default branch). Only used when openPr=true."),
};

// ---- Policy + decision control-plane tool schemas ----

const listPoliciesShape = {
  projectId: z
    .string()
    .optional()
    .describe("Scope to a single project's policies. Omit to list all policies on the account."),
};

const getPolicyShape = {
  policyId: z.string().min(1).describe("ID of the policy to fetch (returns config + version history)."),
};

const setRateLimitShape = {
  policyId: z.string().min(1).describe("ID of the policy to update."),
  baseVersion: z
    .number()
    .int()
    .describe(
      "The policy version you read/based this change on (optimistic concurrency). " +
        "If the policy has advanced past this, the API returns 409 and you must re-read.",
    ),
  limits: z
    .array(
      z.object({
        dimension: z
          .string()
          .min(1)
          .describe("What the limit is keyed on, e.g. 'ip', 'actorId', 'email'."),
        limit: z.number().int().positive().describe("Max allowed events in the window."),
        windowSeconds: z.number().int().positive().describe("Window length in seconds."),
      }),
    )
    .min(1)
    .describe("The velocity/rate limits to set on the policy."),
  note: z.string().optional().describe("Optional human note recorded on the new version."),
};

const promotePolicyShape = {
  policyId: z.string().min(1).describe("ID of the policy to promote."),
  targetMode: z
    .string()
    .min(1)
    .describe(
      "Mode to promote to, e.g. 'shadow', 'live'. Promoting to 'live' ENFORCES on real users.",
    ),
  acknowledgeUserImpact: z
    .boolean()
    .optional()
    .describe(
      "REQUIRED to be true when targetMode is 'live' — confirms you understand this enforces " +
        "on real users. The API returns 422 if omitted for a live promotion. Not defaulted.",
    ),
  environment: z
    .string()
    .optional()
    .describe("Optional environment label to promote in (e.g. 'production')."),
};

const rollbackPolicyShape = {
  policyId: z.string().min(1).describe("ID of the policy to roll back."),
  toVersion: z
    .number()
    .int()
    .optional()
    .describe("Version to roll back to. Omit to roll back to the immediately previous version."),
};

const listDecisionsShape = {
  projectId: z.string().optional().describe("Filter to a single project."),
  action: z.string().optional().describe("Filter to a single action, e.g. 'signup'."),
  mode: z.string().optional().describe("Filter by policy mode, e.g. 'shadow' or 'live'."),
  enforced: z
    .boolean()
    .optional()
    .describe("If set, only decisions where enforcement was (true) / was not (false) applied."),
  limit: z.number().int().positive().optional().describe("Max rows to return (page size)."),
  cursor: z.string().optional().describe("Opaque pagination cursor from a previous nextCursor."),
};

const explainDecisionShape = {
  decisionId: z.string().min(1).describe("ID of the decision to explain in full."),
};

const submitFeedbackShape = {
  decisionId: z.string().min(1).describe("ID of the decision to label."),
  label: z
    .enum(["legitimate", "abusive"])
    .describe("Ground-truth label used to tune detection: 'legitimate' or 'abusive'."),
};

const getMetricsShape = {
  projectId: z.string().optional().describe("Scope metrics to a single project."),
  window: z
    .string()
    .optional()
    .describe("Time window for the aggregate, e.g. '24h', '7d', '30d'."),
};

const guardScopeShape = {
  actorId: z.string().max(256).optional().describe("Stable identifier for the acting user, if known."),
  projectId: z.string().optional().describe("Project to attribute the decision to."),
  environment: z.string().optional().describe("Environment name (default 'production')."),
};

const screenPromptShape = {
  prompt: z
    .string()
    .min(1)
    .max(16000)
    .describe("The end-user prompt about to be sent to an LLM (max 16k chars). Treated as untrusted data."),
  purpose: z
    .string()
    .max(1000)
    .optional()
    .describe("What the AI feature is for (helps judge compute/token-farming abuse)."),
  context: z.record(z.string(), z.unknown()).optional().describe("Optional extra context object."),
  ...guardScopeShape,
};

const authorizeToolCallShape = {
  tool: z
    .object({
      name: z.string().min(1).max(200).describe("Tool name, e.g. 'send_email'."),
      mutating: z
        .boolean()
        .describe("True if the tool writes/sends/deletes/pays. Mutating tools FAIL CLOSED when evidence is unavailable."),
      description: z.string().max(2000).optional().describe("What the tool does."),
    })
    .describe("The tool the agent wants to call."),
  args: z.unknown().optional().describe("The arguments the agent wants to pass (any JSON)."),
  userIntent: z.string().max(4000).optional().describe("What the human user actually asked for."),
  untrustedContext: z
    .string()
    .max(32000)
    .optional()
    .describe("Untrusted content the agent read (web page, email, tool output) that may carry injected instructions."),
  ...guardScopeShape,
};

function summarizePromptScreen(r: ScreenPromptResult): string {
  return [
    `Prompt screen: ${r.decision.toUpperCase()} (score ${r.score})`,
    `Reasons: ${r.reasons.length ? r.reasons.join(", ") : "none"}`,
    r.degraded ? "DEGRADED: AI judgment unavailable; heuristic result." : "",
  ]
    .filter(Boolean)
    .join("\n");
}

function summarizeToolCall(r: AuthorizeToolCallResult): string {
  return [
    `Tool call: ${r.decision.toUpperCase()}`,
    `Reasons: ${r.reasons.length ? r.reasons.join(", ") : "none"}`,
    r.degraded ? "DEGRADED: AI evidence unavailable (mutating tools fail closed)." : "",
  ]
    .filter(Boolean)
    .join("\n");
}

/** Max diff characters to inline in the text summary before truncating (structured content is full). */
const DIFF_TEXT_LIMIT = 6000;

/** Human-readable one-liner summary of a decision. */
function summarizeDecision(d: EvaluateDecision): string {
  const lines = [
    `Decision: ${d.action.toUpperCase()} (score ${d.score}, flagged=${d.flagged}, enforced=${d.enforced})`,
    `Request ID: ${d.requestId}`,
  ];
  if (d.reasons?.length) {
    lines.push(`Reasons: ${d.reasons.join("; ")}`);
  }
  if (d.signals?.length) {
    const sig = d.signals
      .map((s) => `${s.signal}=${s.score}${s.reasons?.length ? ` (${s.reasons.join(", ")})` : ""}`)
      .join(" | ");
    lines.push(`Signals: ${sig}`);
  }
  return lines.join("\n");
}

/** Human-readable summary of usage. */
function summarizeUsage(u: UsageResult): string {
  const limit = u.limit == null ? "unlimited (metered)" : String(u.limit);
  const remaining = u.remaining == null ? "n/a (metered)" : String(u.remaining);
  const period =
    u.periodStart && u.periodEnd ? ` | period ${u.periodStart} → ${u.periodEnd}` : "";
  return `Plan: ${u.plan} | used ${u.used} of ${limit} | remaining ${remaining}${period}`;
}

/** Human-readable summary of the account's projects. */
function summarizeProjects(projects: Project[]): string {
  if (!projects.length) return "No projects yet.";
  const lines = projects.map(
    (p) =>
      `- ${p.name} (id ${p.id})${p.defaultEnvironment ? ` [${p.defaultEnvironment}]` : ""}`,
  );
  return `${projects.length} project(s):\n${lines.join("\n")}`;
}

/** Human-readable summary of a scan. */
function summarizeScan(scan: Scan): string {
  const lines = [
    `Scan ${scan.id} — status: ${scan.status}`,
    `Project: ${scan.projectId}`,
  ];
  if (scan.scannerVersion) lines.push(`Scanner: ${scan.scannerVersion}`);
  if (scan.surfaceCount != null || scan.recommendationCount != null) {
    lines.push(
      `Surfaces: ${scan.surfaceCount ?? "?"} | Recommendations: ${scan.recommendationCount ?? "?"}`,
    );
  }
  if (scan.warnings?.length) lines.push(`Warnings: ${scan.warnings.join("; ")}`);
  if (scan.error) lines.push(`Error: ${scan.error}`);
  return lines.join("\n");
}

/** True if a surface already has some form of protection recorded in its evidence. */
function surfaceIsProtected(s: Surface): boolean {
  return (s.evidence ?? []).some((e) => e?.kind === "existing_protection");
}

/** Filter surfaces by priority bucket and (optionally) unprotected-only, per the PRD example. */
function filterSurfaces(
  surfaces: Surface[],
  opts: { unprotectedOnly?: boolean; priority?: string[] },
): Surface[] {
  let out = surfaces;
  if (opts.priority?.length) {
    const wanted = new Set(opts.priority.map((p) => p.toLowerCase()));
    out = out.filter((s) => s.priority && wanted.has(s.priority.toLowerCase()));
  }
  if (opts.unprotectedOnly) {
    out = out.filter((s) => !surfaceIsProtected(s));
  }
  return out;
}

/** Compact per-surface record for structuredContent. */
function compactSurface(s: Surface): Record<string, unknown> {
  return {
    id: s.id,
    surfaceKey: s.surfaceKey,
    route: s.route,
    method: s.method,
    action: s.action,
    surfaceType: s.surfaceType,
    exposure: s.exposure,
    abuseClasses: s.abuseClasses,
    priority: s.priority,
    priorityScore: s.priorityScore,
    confidence: s.confidence,
    impact: s.impact,
    protected: surfaceIsProtected(s),
  };
}

/** Human-readable summary of a surface list. */
function summarizeSurfaces(surfaces: Surface[]): string {
  if (!surfaces.length) return "No matching abuse surfaces.";
  const lines = surfaces.map((s) => {
    const loc = [s.method, s.route].filter(Boolean).join(" ") || s.action || s.surfaceKey;
    const classes = s.abuseClasses?.length ? ` [${s.abuseClasses.join(", ")}]` : "";
    const prot = surfaceIsProtected(s) ? "protected" : "UNPROTECTED";
    return `- ${loc} — priority ${s.priority ?? "?"}${classes} (${prot})`;
  });
  return `${surfaces.length} abuse surface(s):\n${lines.join("\n")}`;
}

/** Human-readable summary of a surface's recommendations. */
function summarizeRecommendations(recs: Recommendation[]): string {
  if (!recs.length) return "No recommendations for this surface.";
  const lines = recs.map(
    (r) => `- ${r.title} — priority ${r.priority ?? "?"}, status ${r.status ?? "?"}`,
  );
  return `${recs.length} recommendation(s):\n${lines.join("\n")}`;
}

/**
 * Human-readable summary of a generated autofix: whether the patch is valid, how many lines it
 * changes, any warnings, and the unified diff (truncated if very long — full diff is in
 * structuredContent).
 */
function summarizeAutofix(a: AutofixResult): string {
  const lines = [
    `Autofix for recommendation ${a.recommendationId} (surface ${a.surfaceId})`,
    `Patch: ${a.valid ? "VALID" : "INVALID / not applied"} | changed lines: ${a.estimatedChangedLines}`,
  ];
  if (a.envAdditions?.length) lines.push(`Env additions: ${a.envAdditions.join(", ")}`);
  if (a.warnings?.length) lines.push(`Warnings: ${a.warnings.join("; ")}`);
  if (a.diff) {
    const diff =
      a.diff.length > DIFF_TEXT_LIMIT
        ? `${a.diff.slice(0, DIFF_TEXT_LIMIT)}\n… (diff truncated; see structuredContent for the full patch)`
        : a.diff;
    lines.push("", "Unified diff:", diff);
  } else {
    lines.push("", "(no diff generated)");
  }
  return lines.join("\n");
}

/** Human-readable summary of a REAL opened pull request. */
function summarizeOpenedPr(r: OpenPullRequestResponse): string {
  const lines = [
    `Opened a real GitHub pull request: #${r.pullRequest.number}`,
    `URL: ${r.pullRequest.url}`,
    `Head branch: ${r.pullRequest.headBranch}`,
    `Patch: ${r.autofix.valid ? "VALID" : "INVALID"} | changed lines: ${r.autofix.estimatedChangedLines}`,
  ];
  if (r.autofix.diff) {
    const diff =
      r.autofix.diff.length > DIFF_TEXT_LIMIT
        ? `${r.autofix.diff.slice(0, DIFF_TEXT_LIMIT)}\n… (diff truncated; see structuredContent for the full patch)`
        : r.autofix.diff;
    lines.push("", "Unified diff:", diff);
  }
  return lines.join("\n");
}

/** Human-readable summary of a list of policies. */
function summarizePolicies(policies: Policy[]): string {
  if (!policies.length) return "No policies yet.";
  const lines = policies.map((p) => {
    const bits = [p.action, p.mode ? `mode ${p.mode}` : undefined, p.version != null ? `v${p.version}` : undefined]
      .filter(Boolean)
      .join(", ");
    return `- ${p.id}${bits ? ` (${bits})` : ""}${p.projectId ? ` [${p.projectId}]` : ""}`;
  });
  return `${policies.length} policy/policies:\n${lines.join("\n")}`;
}

/** Human-readable summary of a single policy + its version history. */
function summarizePolicy(p: Policy): string {
  const lines = [
    `Policy ${p.id}${p.action ? ` — action ${p.action}` : ""}`,
    `Mode: ${p.mode ?? "?"} | version: ${p.version ?? "?"}${p.projectId ? ` | project ${p.projectId}` : ""}`,
  ];
  const versions = p.versions ?? [];
  if (versions.length) {
    lines.push(`Version history (${versions.length}):`);
    for (const v of versions) {
      const parts = [`  v${v.version}`, v.mode ? `mode ${v.mode}` : undefined, v.note ? `"${v.note}"` : undefined]
        .filter(Boolean)
        .join(" — ");
      lines.push(parts);
    }
  }
  return lines.join("\n");
}

/** Human-readable summary of a policy mutation (update/promote/rollback/create). */
function summarizePolicyChange(p: Policy, verb: string): string {
  return `${verb} policy ${p.id} → now mode ${p.mode ?? "?"}, version ${p.version ?? "?"}.`;
}

/** Human-readable summary of a decision list. */
function summarizeDecisionList(list: DecisionList): string {
  const rows = list.decisions ?? [];
  if (!rows.length) return "No decisions match.";
  const lines = rows.map((d) => {
    const bits = [
      d.action,
      d.outcome,
      d.score != null ? `score ${d.score}` : undefined,
      d.mode ? `mode ${d.mode}` : undefined,
      `enforced=${d.enforced ?? false}`,
    ]
      .filter(Boolean)
      .join(", ");
    return `- ${d.id} (${bits})`;
  });
  const more = list.nextCursor ? `\n(more available; nextCursor=${list.nextCursor})` : "";
  return `${rows.length} decision(s):\n${lines.join("\n")}${more}`;
}

/** Human-readable, formatted explanation of a full decision (signals + reasons + policy). */
function summarizeDecisionExplanation(d: Decision): string {
  const lines = [
    `Decision ${d.id}${d.action ? ` — action ${d.action}` : ""}`,
    `Outcome: ${d.outcome ?? "?"} | score ${d.score ?? "?"} | mode ${d.mode ?? "?"} | enforced=${d.enforced ?? false}`,
  ];
  if (d.reasons?.length) lines.push(`Reasons: ${d.reasons.join("; ")}`);
  if (d.signals?.length) {
    lines.push("Signals:");
    for (const s of d.signals) {
      const rs = s.reasons?.length ? ` (${s.reasons.join(", ")})` : "";
      lines.push(`  - ${s.signal}: ${s.score}${rs}`);
    }
  }
  if (d.policy) {
    const pid = (d.policy as { id?: string }).id;
    lines.push(`Policy: ${pid ?? JSON.stringify(d.policy)}`);
  }
  if (d.feedback?.label) lines.push(`Feedback: ${d.feedback.label}`);
  return lines.join("\n");
}

/** Human-readable summary of aggregate metrics. */
function summarizeMetrics(m: MetricsSummary): string {
  const head = `Metrics${m.projectId ? ` for ${m.projectId}` : ""}${m.window ? ` (window ${m.window})` : ""}:`;
  return `${head}\n${JSON.stringify(m, null, 2)}`;
}

/** Turn an error into an MCP tool error result (isError:true) without throwing. */
function toToolError(err: unknown) {
  let body: { error: string; code: string };
  if (err instanceof ApiError) {
    body = { error: err.message, code: err.code };
  } else if (err instanceof Error) {
    body = { error: err.message, code: "mcp_error" };
  } else {
    body = { error: String(err), code: "unknown_error" };
  }
  return {
    isError: true as const,
    content: [
      { type: "text" as const, text: `GuardCMD error [${body.code}]: ${body.error}` },
      { type: "text" as const, text: JSON.stringify(body) },
    ],
    structuredContent: body,
  };
}

/**
 * Shared implementation for `scan_repository` and its deprecated alias `create_scan`.
 *
 * Both tools dispatch here for a valid `repoUrl` call so their behavior is byte-for-byte
 * identical and can never drift — there is exactly one code path that calls
 * `client.scanUrl()` (POST /v1/projects/:id/scan-url), and it is the only scan call either
 * tool can make. Neither tool has any other route to the API's scan endpoints, so the retired,
 * path-rooted `POST /v1/projects/:id/scans` is simply unreachable from here — not merely
 * unused by convention.
 */
async function runScanRepository(client: GuardCMDClient, projectId: string, repoUrl: string) {
  try {
    const scan = await client.scanUrl(projectId, repoUrl);
    return {
      content: [
        { type: "text" as const, text: summarizeScan(scan) },
        { type: "text" as const, text: JSON.stringify(scan, null, 2) },
      ],
      structuredContent: scan as unknown as Record<string, unknown>,
    };
  } catch (err) {
    return toToolError(err);
  }
}

/**
 * The actionable error returned to a legacy `create_scan` caller — one that omits `repoUrl`
 * (most commonly because it's still sending the pre-rename `{ projectId, path }` shape).
 *
 * This is surfaced as a tool error result (`isError: true`), not a zod validation error, even
 * though `create_scan`'s schema could in principle make `repoUrl` required and let the SDK
 * reject the call for us. A schema rejection would only ever say something generic like
 * "invalid arguments" — it can't explain WHY the field changed, WHAT to send instead, or THAT
 * the tool itself is now deprecated. A tool error result carries free-form text, so it's the
 * only place we can put a message that is actually useful to whoever (human or agent) is
 * staring at the failure. Using the tool-error path is also why `repoUrl` is optional in
 * `createScanShape` above: an optional field lets the call reach this handler instead of dying
 * at the protocol layer first.
 */
const CREATE_SCAN_PATH_REMOVED_MESSAGE =
  "`create_scan` no longer scans a filesystem path. Passing `path` (or omitting `repoUrl`) " +
  "cannot be honored: server-filesystem scan roots were removed for a security reason — any " +
  "signed-up caller could root a scan at an arbitrary directory on the API host and read whole " +
  "file contents back out through the autofix endpoint, so the API now rejects that endpoint " +
  "outright (501 local_path_scans_disabled). There is no way to safely turn a filesystem path " +
  "into a repository URL, so guessing one would be wrong — this call must fail instead. Pass " +
  "`repoUrl` with a PUBLIC GitHub repository URL instead, e.g. " +
  "'https://github.com/owner/repo'. Better yet, call the canonical tool `scan_repository` " +
  "directly with the same `repoUrl` argument — `create_scan` is now only a deprecated " +
  "compatibility alias for it.";

/**
 * Create a fully-configured GuardCMD MCP server (tools registered).
 * Throws if neither options nor env provide baseUrl + apiKey (and no client given).
 */
export function createServer(opts: CreateServerOptions = {}): McpServer {
  let client: GuardCMDClient;
  if (opts.client) {
    client = opts.client;
  } else {
    const { baseUrl, apiKey } = resolveConfig(opts);
    client = new GuardCMDClient({
      baseUrl,
      apiKey,
      fetchImpl: opts.clientOptions?.fetchImpl,
      timeoutMs: opts.clientOptions?.timeoutMs,
    });
  }

  const server = new McpServer(
    {
      name: "guardcmd-mcp",
      version: "0.1.0",
    },
    {
      instructions:
        "GuardCMD Cloud MCP server. Use `check_abuse` to evaluate whether an action " +
        "(signup, login, comment, checkout, ...) is abusive/fraudulent — it returns a " +
        "decision (allow/challenge/throttle/review/block) with a score, reasons, and signals. " +
        "Use `get_usage` to see the current plan and remaining quota. " +
        "Repository-scan control plane: `list_projects` lists your projects, `scan_repository` scans a " +
        "PUBLIC GitHub repo by URL (the server clones it itself — filesystem paths are not " +
        "accepted). `create_scan` is a DEPRECATED compatibility alias for `scan_repository` — " +
        "same `repoUrl` contract, identical behavior — kept only for MCP clients still on the " +
        "old tool name; use `scan_repository` instead, and never pass `path` (removed for " +
        "security, it now returns an actionable error). " +
        "`get_scan` reports scan status/counts, `list_abuse_surfaces` " +
        "returns the abuse surfaces a scan found (filterable by priority / unprotected-only), " +
        "`list_recommendations` returns hardening recommendations for a surface, and " +
        "`create_protection_pr` generates a PR-ready patch/diff for a recommendation (review-only), " +
        "or OPENS A REAL GitHub PR when called with openPr=true (needs a linked GitHub repo). " +
        "Reads are safe; `scan_repository` and the default `create_protection_pr` are low-risk (they " +
        "only analyze code / generate a patch); `create_protection_pr` with openPr=true opens a " +
        "real pull request against your repo (enforcement starts in Shadow mode). " +
        "Policy + decision control plane: `list_policies` / `get_policy` inspect anti-abuse " +
        "policies and their version history; `set_rate_limit` sets velocity limits (creates a " +
        "new draft/shadow version — it does NOT enforce by itself); `promote_policy` is " +
        "HIGH-IMPACT — promoting to `live` ENFORCES on real users and REQUIRES " +
        "`acknowledgeUserImpact: true` (omitting it on a live promotion is a 422); " +
        "`rollback_policy` reverts to a prior version (protective). `list_decisions` browses " +
        "recent decisions, `explain_decision` shows the full signals/reasons/policy for one, " +
        "`submit_feedback` labels a decision legitimate/abusive, and `get_metrics` returns " +
        "aggregate metrics for a window. " +
        "AI guard: `screen_prompt` screens a prompt bound for an LLM (injection, exfiltration, " +
        "token farming, harmful requests) and returns allow/review/block; `authorize_tool_call` " +
        "returns allow/require_approval/deny for an agent tool call. Decisions come from explicit " +
        "rules; the AI model only supplies evidence. Both are read-only checks.",
    },
  );

  server.registerTool(
    "check_abuse",
    {
      title: "Check for abuse",
      description:
        "Evaluate an action for abuse/fraud via GuardCMD. Returns a decision " +
        "(allow | challenge | throttle | review | block) with score, reasons, and signals. " +
        "Only `action` is required; provide as much context (ip, email, content, etc.) as you have.",
      inputSchema: checkAbuseShape,
    },
    async (args) => {
      try {
        const decision = await client.evaluate(args);
        return {
          content: [
            { type: "text", text: summarizeDecision(decision) },
            { type: "text", text: JSON.stringify(decision, null, 2) },
          ],
          structuredContent: decision as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  server.registerTool(
    "screen_prompt",
    {
      title: "Screen an AI prompt",
      description:
        "Screen a prompt headed for an LLM for abuse via GuardCMD + TypeSafe: prompt injection / " +
        "jailbreak, system-prompt or data exfiltration, compute/token farming, and harmful requests. " +
        "Returns allow | review | block with a 0-100 score, reason codes, per-judgment probabilities, " +
        "and `degraded` (true when AI judgment was unavailable and heuristics were used).",
      inputSchema: screenPromptShape,
    },
    async (args) => {
      try {
        const r = await client.screenPrompt(args);
        return {
          content: [
            { type: "text", text: summarizePromptScreen(r) },
            { type: "text", text: JSON.stringify(r, null, 2) },
          ],
          structuredContent: r as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  server.registerTool(
    "authorize_tool_call",
    {
      title: "Authorize an agent tool call",
      description:
        "Get an authorization decision (allow | require_approval | deny) for an agent tool call. " +
        "The AI model supplies EVIDENCE only (injected instructions in untrusted context, intent " +
        "match, data exfiltration); explicit rules make the decision and can only add restriction. " +
        "Mutating tools require approval when evidence is unavailable; read-only tools are allowed.",
      inputSchema: authorizeToolCallShape,
    },
    async (args) => {
      try {
        const r = await client.authorizeToolCall(args);
        return {
          content: [
            { type: "text", text: summarizeToolCall(r) },
            { type: "text", text: JSON.stringify(r, null, 2) },
          ],
          structuredContent: r as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  server.registerTool(
    "get_usage",
    {
      title: "Get usage",
      description:
        "Get the current GuardCMD plan and usage for this API key: plan, checks used, " +
        "limit, and remaining for the current billing period.",
      inputSchema: getUsageShape,
    },
    async () => {
      try {
        const usage = await client.usage();
        return {
          content: [
            { type: "text", text: summarizeUsage(usage) },
            { type: "text", text: JSON.stringify(usage, null, 2) },
          ],
          structuredContent: usage as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  server.registerTool(
    "list_projects",
    {
      title: "List projects",
      description:
        "List the GuardCMD projects for this account (GET /v1/projects). A project is a " +
        "container for repository scans. Read-only and safe.",
      inputSchema: listProjectsShape,
    },
    async () => {
      try {
        const projects = await client.listProjects();
        return {
          content: [
            { type: "text", text: summarizeProjects(projects) },
            { type: "text", text: JSON.stringify({ projects }, null, 2) },
          ],
          structuredContent: { projects } as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  server.registerTool(
    "scan_repository",
    {
      title: "Scan a repository",
      description:
        "Scan a PUBLIC GitHub repository for abuse surfaces (POST /v1/projects/:id/scan-url). " +
        "Pass `repoUrl`, e.g. 'https://github.com/owner/repo' — the server makes its own " +
        "disposable clone, so server/local filesystem paths are NOT accepted (the former " +
        "`create_scan` tool took one; that mode is disabled and now answers 501). Private " +
        "repositories need the GitHub App flow, which is not exposed here. Low-risk write: it " +
        "only analyzes code, it never modifies your repo. Returns the scan summary (scanId, " +
        "status, surfaceCount, recommendationCount); a repo that cannot be cloned comes back " +
        "as an error (invalid_github_url / repo_unavailable).",
      inputSchema: scanRepositoryShape,
    },
    async (args) => runScanRepository(client, args.projectId, args.repoUrl),
  );

  /**
   * `create_scan` — DEPRECATED compatibility alias for `scan_repository`.
   *
   * WHY THIS EXISTS: `create_scan` was this tool's original name, taking a server-filesystem
   * `path`. Renaming it to `scan_repository` (with `repoUrl`) as part of the fix for the
   * local-path-scan vulnerability means an MCP client still configured with the old name now
   * gets an "unknown tool" error instead of a working call — an abrupt break for anyone who
   * hadn't already migrated. This registration keeps the OLD NAME reachable without
   * resurrecting the OLD BEHAVIOR: a valid `repoUrl` call is forwarded verbatim to
   * `runScanRepository`, the exact same function `scan_repository` calls, so the two tools can
   * never drift apart for the case that matters.
   *
   * WHY IT CAN NEVER ACCEPT A PATH: a future maintainer "restoring" `path` support here — e.g.
   * to be extra lenient with old clients — would reopen the arbitrary-file-read primitive (root
   * a scan at a host directory, then read whole file contents back out through the autofix
   * endpoint) that the rename to `scan_repository` was built to close. There is no code path in
   * this handler that reads `args.path` for anything other than deciding to reject the call, no
   * code path that reaches `client.createScan`/`/v1/projects/:id/scans` (that endpoint has no
   * client method at all — see client.ts), and no fallback that guesses a URL from a path.
   * `path` exists in the schema purely so a legacy call can be told exactly what to do instead.
   */
  server.registerTool(
    "create_scan",
    {
      title: "Scan a repository (deprecated alias)",
      description:
        "DEPRECATED — this is a compatibility alias for `scan_repository`, kept only so MCP " +
        "clients still configured with the old tool name don't hit an 'unknown tool' error. " +
        "New integrations should call `scan_repository` directly. For a `repoUrl` call it " +
        "behaves IDENTICALLY to `scan_repository`: scans a PUBLIC GitHub repository " +
        "(POST /v1/projects/:id/scan-url), the server making its own disposable clone. The old " +
        "`path` argument (a server-filesystem scan root) is NOT supported and never will be — " +
        "it was a critical vulnerability (arbitrary file read via the autofix endpoint) — " +
        "sending it (or omitting `repoUrl`) returns a tool error explaining what changed and " +
        "telling you to send `repoUrl` instead.",
      inputSchema: createScanShape,
    },
    async (args) => {
      if (args.repoUrl) {
        return runScanRepository(client, args.projectId, args.repoUrl);
      }
      // No repoUrl: either a legacy `{ projectId, path }` call, or repoUrl was simply omitted.
      // Either way there is nothing safe to do but explain the change — see the constant's own
      // doc comment for why this is a tool error result rather than a schema rejection.
      return toToolError(
        new ApiError(CREATE_SCAN_PATH_REMOVED_MESSAGE, "local_path_scans_disabled", 400),
      );
    },
  );

  server.registerTool(
    "get_scan",
    {
      title: "Get scan",
      description:
        "Get a scan's status and counts (GET /v1/scans/:id): status, scannerVersion, stats, " +
        "warnings, surfaceCount, recommendationCount. Read-only and safe.",
      inputSchema: getScanShape,
    },
    async (args) => {
      try {
        const scan = await client.getScan(args.scanId);
        return {
          content: [
            { type: "text", text: summarizeScan(scan) },
            { type: "text", text: JSON.stringify(scan, null, 2) },
          ],
          structuredContent: scan as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  server.registerTool(
    "list_abuse_surfaces",
    {
      title: "List abuse surfaces",
      description:
        "List the abuse surfaces a scan discovered (endpoints/actions that can be abused). " +
        "Provide `scanId` for a specific scan, or `projectId` to use its latest completed scan. " +
        "Filter with `priority` (e.g. ['critical','high']) and `unprotectedOnly` (surfaces with " +
        "no existing protection). Read-only and safe.",
      inputSchema: listAbuseSurfacesShape,
    },
    async (args) => {
      try {
        if (!args.scanId && !args.projectId) {
          return toToolError(
            new ApiError(
              "Provide either `scanId` or `projectId`.",
              "invalid_arguments",
              400,
            ),
          );
        }
        const all = args.scanId
          ? await client.listScanSurfaces(args.scanId)
          : await client.listProjectSurfaces(args.projectId!);
        const surfaces = filterSurfaces(all, {
          unprotectedOnly: args.unprotectedOnly,
          priority: args.priority,
        });
        const compact = surfaces.map(compactSurface);
        return {
          content: [
            { type: "text", text: summarizeSurfaces(surfaces) },
            { type: "text", text: JSON.stringify({ surfaces: compact }, null, 2) },
          ],
          structuredContent: {
            surfaces: compact,
            total: all.length,
            returned: surfaces.length,
          } as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  server.registerTool(
    "list_recommendations",
    {
      title: "List recommendations",
      description:
        "List hardening recommendations for an abuse surface (GET /v1/surfaces/:id/recommendations): " +
        "title, summary, suggestedPolicy, controls, priority, status. Read-only and safe.",
      inputSchema: listRecommendationsShape,
    },
    async (args) => {
      try {
        const recommendations = await client.listSurfaceRecommendations(args.surfaceId);
        return {
          content: [
            { type: "text", text: summarizeRecommendations(recommendations) },
            { type: "text", text: JSON.stringify({ recommendations }, null, 2) },
          ],
          structuredContent: { recommendations } as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  server.registerTool(
    "create_protection_pr",
    {
      title: "Create protection PR",
      description:
        "Wire GuardCMD protection into the handler for a recommendation. Two modes:\n" +
        "• Default (openPr omitted/false): GENERATE the patch/diff for review only " +
        "(POST /v1/recommendations/:id/autofix) — a unified diff plus the `.env` keys the " +
        "integration needs; nothing is written to your repo.\n" +
        "• openPr=true: OPEN A REAL GitHub pull request (POST /v1/recommendations/:id/pull-request). " +
        "The server re-scans a sandboxed clone of the project's linked GitHub repo, validates the " +
        "patch, and opens a PR (enforcement starts in Shadow mode). Requires a linked GitHub repo " +
        "and a configured GitHub App; returns the PR number, url, and head branch.",
      inputSchema: createProtectionPrShape,
    },
    async (args) => {
      try {
        if (args.openPr) {
          const opened = await client.openPullRequest(args.recommendationId, args.ref);
          return {
            content: [
              { type: "text", text: summarizeOpenedPr(opened) },
              { type: "text", text: JSON.stringify(opened, null, 2) },
            ],
            structuredContent: opened as unknown as Record<string, unknown>,
          };
        }
        const autofix = await client.generateAutofix(args.recommendationId);
        return {
          content: [
            { type: "text", text: summarizeAutofix(autofix) },
            { type: "text", text: JSON.stringify(autofix, null, 2) },
          ],
          structuredContent: autofix as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  // ---- Policy control plane ----

  server.registerTool(
    "list_policies",
    {
      title: "List policies",
      description:
        "List the anti-abuse policies for this account (GET /v1/policies), optionally scoped to " +
        "a project. Returns id, action, mode, and current version for each. Read-only and safe.",
      inputSchema: listPoliciesShape,
    },
    async (args) => {
      try {
        const policies = await client.listPolicies(args.projectId);
        return {
          content: [
            { type: "text", text: summarizePolicies(policies) },
            { type: "text", text: JSON.stringify({ policies }, null, 2) },
          ],
          structuredContent: { policies } as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  server.registerTool(
    "get_policy",
    {
      title: "Get policy",
      description:
        "Get a single policy plus its full version history (GET /v1/policies/:id): config, " +
        "current mode/version, and each prior version. Read-only and safe.",
      inputSchema: getPolicyShape,
    },
    async (args) => {
      try {
        const policy = await client.getPolicy(args.policyId);
        return {
          content: [
            { type: "text", text: summarizePolicy(policy) },
            { type: "text", text: JSON.stringify(policy, null, 2) },
          ],
          structuredContent: policy as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  server.registerTool(
    "set_rate_limit",
    {
      title: "Set rate limit",
      description:
        "Set the velocity/rate limits on a policy (PATCH /v1/policies/:id). Pass `baseVersion` " +
        "(the version you read) for optimistic concurrency — a stale value returns 409. " +
        "Write, but LOW-RISK: this creates a new draft/shadow policy version with the limits in " +
        "its config; it does NOT enforce on real users by itself. Use `promote_policy` to go live.",
      inputSchema: setRateLimitShape,
    },
    async (args) => {
      try {
        const config = { velocityLimits: args.limits };
        const policy = await client.updatePolicy(args.policyId, {
          baseVersion: args.baseVersion,
          config,
          note: args.note,
        });
        return {
          content: [
            { type: "text", text: summarizePolicyChange(policy, "Updated rate limits on") },
            { type: "text", text: JSON.stringify(policy, null, 2) },
          ],
          structuredContent: policy as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  server.registerTool(
    "promote_policy",
    {
      title: "Promote policy",
      description:
        "HIGH-IMPACT / DESTRUCTIVE. Promote a policy to a target mode (POST /v1/policies/:id/promote). " +
        "Promoting to `live` ENFORCES the policy on REAL USER traffic and REQUIRES " +
        "`acknowledgeUserImpact: true` — this tool passes that flag through verbatim and NEVER " +
        "defaults or infers it. If you omit it for a live promotion the API returns 422, which is " +
        "surfaced as a tool error. Promoting to `shadow` observes without enforcing.",
      inputSchema: promotePolicyShape,
    },
    async (args) => {
      try {
        const body: { targetMode: string; acknowledgeUserImpact?: boolean; environment?: string } = {
          targetMode: args.targetMode,
        };
        // Pass acknowledgeUserImpact through ONLY if the caller provided it — never default it.
        if (args.acknowledgeUserImpact !== undefined) {
          body.acknowledgeUserImpact = args.acknowledgeUserImpact;
        }
        if (args.environment !== undefined) body.environment = args.environment;
        const policy = await client.promotePolicy(args.policyId, body);
        return {
          content: [
            { type: "text", text: summarizePolicyChange(policy, `Promoted (→ ${args.targetMode})`) },
            { type: "text", text: JSON.stringify(policy, null, 2) },
          ],
          structuredContent: policy as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  server.registerTool(
    "rollback_policy",
    {
      title: "Rollback policy",
      description:
        "Roll a policy back to a prior version (POST /v1/policies/:id/rollback). HIGH-IMPACT but " +
        "PROTECTIVE — use it to quickly revert a bad config. Omit `toVersion` to revert to the " +
        "immediately previous version.",
      inputSchema: rollbackPolicyShape,
    },
    async (args) => {
      try {
        const policy = await client.rollbackPolicy(args.policyId, { toVersion: args.toVersion });
        return {
          content: [
            { type: "text", text: summarizePolicyChange(policy, "Rolled back") },
            { type: "text", text: JSON.stringify(policy, null, 2) },
          ],
          structuredContent: policy as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  // ---- Decision control plane ----

  server.registerTool(
    "list_decisions",
    {
      title: "List decisions",
      description:
        "List recent abuse decisions (GET /v1/decisions), filterable by projectId, action, mode, " +
        "and enforced. Returns a compact list plus `nextCursor` for pagination. Read-only and safe.",
      inputSchema: listDecisionsShape,
    },
    async (args) => {
      try {
        const list = await client.listDecisions(args);
        return {
          content: [
            { type: "text", text: summarizeDecisionList(list) },
            { type: "text", text: JSON.stringify(list, null, 2) },
          ],
          structuredContent: list as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  server.registerTool(
    "explain_decision",
    {
      title: "Explain decision",
      description:
        "Explain a single decision in full (GET /v1/decisions/:id): the outcome, score, all " +
        "contributing signals with their scores/reasons, the policy that applied, and any " +
        "feedback. Read-only and safe.",
      inputSchema: explainDecisionShape,
    },
    async (args) => {
      try {
        const decision = await client.getDecision(args.decisionId);
        return {
          content: [
            { type: "text", text: summarizeDecisionExplanation(decision) },
            { type: "text", text: JSON.stringify(decision, null, 2) },
          ],
          structuredContent: decision as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  server.registerTool(
    "submit_feedback",
    {
      title: "Submit feedback",
      description:
        "Label a decision `legitimate` or `abusive` (POST /v1/decisions/:id/feedback) to tune " +
        "detection. Write, but low-risk — it records ground truth and does not change enforcement.",
      inputSchema: submitFeedbackShape,
    },
    async (args) => {
      try {
        const decision = await client.submitFeedback(args.decisionId, args.label);
        return {
          content: [
            { type: "text", text: `Recorded feedback '${args.label}' on decision ${args.decisionId}.` },
            { type: "text", text: JSON.stringify(decision, null, 2) },
          ],
          structuredContent: decision as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  server.registerTool(
    "get_metrics",
    {
      title: "Get metrics",
      description:
        "Get aggregate anti-abuse metrics for a project/window (GET /v1/metrics/summary): e.g. " +
        "decision counts, block/challenge rates, feedback. Read-only and safe.",
      inputSchema: getMetricsShape,
    },
    async (args) => {
      try {
        const metrics = await client.getMetrics(args);
        return {
          content: [
            { type: "text", text: summarizeMetrics(metrics) },
            { type: "text", text: JSON.stringify(metrics, null, 2) },
          ],
          structuredContent: metrics as unknown as Record<string, unknown>,
        };
      } catch (err) {
        return toToolError(err);
      }
    },
  );

  return server;
}
