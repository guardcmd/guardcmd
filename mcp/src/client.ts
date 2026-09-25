/**
 * Thin HTTP client for the GuardCMD Cloud API (data plane).
 *
 * Talks to `API_BASE_URL` using the caller's `GUARDCMD_API_KEY`.
 * Endpoints (see platform/CONTRACT.md):
 *   - POST /v1/evaluate  -> decision
 *   - GET  /v1/usage     -> plan/used/remaining
 *
 * Repository-scan control plane (account-scoped, same API key):
 *   - GET  /v1/projects                       -> list projects
 *   - POST /v1/projects                        -> create project
 *   - POST /v1/projects/:id/scan-url          -> scan a PUBLIC GitHub repo by URL
 *   - GET  /v1/scans/:id                        -> scan + counts
 *   - GET  /v1/scans/:id/surfaces             -> surfaces for a scan
 *   - GET  /v1/projects/:id/surfaces          -> surfaces for latest completed scan
 *   - GET  /v1/surfaces/:id                     -> a single surface
 *   - GET  /v1/surfaces/:id/recommendations   -> recommendations for a surface
 *   - POST /v1/recommendations/:id/autofix    -> generate a PR-ready patch for a recommendation
 *   - POST /v1/recommendations/:id/pull-request -> open a REAL GitHub PR for a recommendation
 *
 * Policy + decision control plane (account-scoped, same API key):
 *   - GET   /v1/policies?projectId=            -> list policies
 *   - GET   /v1/policies/:id                    -> policy + version history
 *   - PATCH /v1/policies/:id                    -> update config (optimistic concurrency)
 *   - POST  /v1/policies/:id/promote           -> promote to a target mode (shadow/live/...)
 *   - POST  /v1/policies/:id/rollback          -> roll back to a prior version
 *   - POST  /v1/policies                        -> create a policy
 *   - GET   /v1/decisions?...                    -> list recent decisions (paginated)
 *   - GET   /v1/decisions/:id                    -> a single decision (signals/reasons/policy/feedback)
 *   - POST  /v1/decisions/:id/feedback         -> label a decision legitimate/abusive
 *   - GET   /v1/metrics/summary?...             -> aggregate metrics for a window
 *
 * All API errors are normalized to `ApiError` carrying `{ error, code, status }`
 * so callers can surface them as MCP tool errors without crashing.
 */

/** Shape of the structured API error body per CONTRACT.md ("All errors: { error, code }"). */
export interface ApiErrorBody {
  error: string;
  code: string;
}

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(message: string, code: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }
}

/** Input to POST /v1/evaluate (mirrors the API body; `action` required, rest optional). */
export interface EvaluateInput {
  action: string;
  actorId?: string;
  ip?: string;
  email?: string;
  fingerprint?: string;
  userAgent?: string;
  content?: string;
  meta?: Record<string, unknown>;
  timestamp?: string;
}

/** A single contributing signal in a decision. */
export interface DecisionSignal {
  signal: string;
  score: number;
  reasons: string[];
  data?: unknown;
}

/** Decision returned by POST /v1/evaluate. */
export interface EvaluateDecision {
  action: "allow" | "challenge" | "throttle" | "review" | "block";
  score: number;
  flagged: boolean;
  enforced: boolean;
  reasons: string[];
  signals: DecisionSignal[];
  requestId: string;
}

/** Input to POST /v1/guard/prompt (TypeSafe-backed prompt screening). */
export interface ScreenPromptInput {
  prompt: string;
  purpose?: string;
  context?: Record<string, unknown>;
  actorId?: string;
  projectId?: string;
  environment?: string;
}

/** Result of POST /v1/guard/prompt. */
export interface ScreenPromptResult {
  id: string | null;
  decision: "allow" | "review" | "block";
  score: number;
  reasons: string[];
  signals: Record<string, number>;
  degraded: boolean;
  latencyMs: number;
}

/** Input to POST /v1/guard/tool-call (agent tool-call authorization evidence). */
export interface AuthorizeToolCallInput {
  tool: { name: string; mutating: boolean; description?: string };
  args?: unknown;
  userIntent?: string;
  untrustedContext?: string;
  actorId?: string;
  projectId?: string;
  environment?: string;
}

/** Result of POST /v1/guard/tool-call. */
export interface AuthorizeToolCallResult {
  id: string | null;
  decision: "allow" | "require_approval" | "deny";
  reasons: string[];
  evidence: Record<string, unknown>;
  degraded: boolean;
  latencyMs: number;
}

/** Usage returned by GET /v1/usage. */
export interface UsageResult {
  plan: string;
  periodStart?: string;
  periodEnd?: string;
  used: number;
  limit: number | null;
  remaining: number | null;
}

// ---- Repository-scan control-plane types (kept lightweight on purpose) ----

/** A project — a container for scans of a single repository/app. */
export interface Project {
  id: string;
  name: string;
  defaultEnvironment?: string;
  createdAt?: string;
}

/** A single evidence item attached to a surface (e.g. a matched call site). */
export interface SurfaceEvidence {
  kind: string;
  [key: string]: unknown;
}

/** A scan of a repository checkout the server created (see {@link GuardCMDClient.scanUrl}). */
export interface Scan {
  id: string;
  projectId: string;
  status: string;
  scannerVersion?: string;
  stats?: Record<string, unknown>;
  warnings?: string[];
  error?: string | null;
  /** Present on GET /v1/scans/:id. */
  surfaceCount?: number;
  recommendationCount?: number;
  [key: string]: unknown;
}

/** An abuse surface discovered by a scan (an endpoint/action that can be abused). */
export interface Surface {
  id: string;
  surfaceKey: string;
  route?: string;
  method?: string;
  action?: string;
  surfaceType?: string;
  exposure?: string;
  abuseClasses?: string[];
  confidence?: number;
  impact?: string;
  priority?: string;
  priorityScore?: number;
  evidence?: SurfaceEvidence[];
  [key: string]: unknown;
}

/** A hardening recommendation for a surface. */
export interface Recommendation {
  id: string;
  title: string;
  summary?: string;
  suggestedPolicy?: unknown;
  controls?: unknown;
  priority?: string;
  priorityScore?: number;
  status?: string;
  [key: string]: unknown;
}

/** A whole-file change in an autofix: the file's full text before and after the edit. */
export interface FileEdit {
  path: string;
  before: string;
  after: string;
}

/**
 * The generated patch for a recommendation (POST /v1/recommendations/:id/autofix). It's a
 * review-only artifact — a unified diff, per-file before/after edits, and the `.env` keys the
 * integration needs. It never writes files or opens a PR.
 */
export interface AutofixResult {
  surfaceId: string;
  recommendationId: string;
  edits: FileEdit[];
  /** A unified diff across all edits, PR-ready. */
  diff: string;
  /** Env keys the integration needs, e.g. `["GUARDCMD_API_KEY=", "GUARDCMD_PROJECT_ID="]`. */
  envAdditions: string[];
  /** True iff every edited code file re-parses cleanly AND contains the inserted guard call. */
  valid: boolean;
  /** Non-fatal problems (e.g. "could not locate handler body"); empty on a clean result. */
  warnings: string[];
  /** Count of added lines across all edits. */
  estimatedChangedLines: number;
  [key: string]: unknown;
}

/** A real GitHub pull request opened for a recommendation (POST /v1/recommendations/:id/pull-request). */
export interface PullRequestResult {
  number: number;
  /** The PR's html_url. */
  url: string;
  /** The head branch the PR was opened from. */
  headBranch: string;
}

/** Response of the open-PR endpoint: the opened PR plus a compact autofix summary. */
export interface OpenPullRequestResponse {
  pullRequest: PullRequestResult;
  autofix: { valid: boolean; estimatedChangedLines: number; diff: string };
}

// ---- Policy + decision control-plane types (kept lightweight on purpose) ----

/** A single entry in a policy's version history. */
export interface PolicyVersion {
  version: number;
  mode?: string;
  note?: string;
  createdAt?: string;
  config?: Record<string, unknown>;
  [key: string]: unknown;
}

/** An anti-abuse policy for a project/action. */
export interface Policy {
  id: string;
  projectId?: string;
  action?: string;
  mode?: string;
  version?: number;
  config?: Record<string, unknown>;
  versions?: PolicyVersion[];
  createdAt?: string;
  updatedAt?: string;
  [key: string]: unknown;
}

/** A single velocity/rate limit for a policy. */
export interface RateLimit {
  dimension: string;
  limit: number;
  windowSeconds: number;
}

/** Body for PATCH /v1/policies/:id (optimistic concurrency via baseVersion). */
export interface UpdatePolicyBody {
  baseVersion: number;
  config?: Record<string, unknown>;
  note?: string;
}

/** Body for POST /v1/policies/:id/promote. */
export interface PromotePolicyBody {
  targetMode: string;
  acknowledgeUserImpact?: boolean;
}

/** Body for POST /v1/policies/:id/rollback. */
export interface RollbackPolicyBody {
  toVersion?: number;
}

/** Body for POST /v1/policies — either adopt a recommendation, or create from scratch. */
export type CreatePolicyBody =
  | { recommendationId: string }
  | {
      projectId: string;
      action: string;
      config: Record<string, unknown>;
      mode?: string;
    };

/** Filters for GET /v1/decisions. */
export interface DecisionFilters {
  projectId?: string;
  action?: string;
  mode?: string;
  enforced?: boolean;
  limit?: number;
  cursor?: string;
}

/** A compact decision row in a decision list. */
export interface DecisionSummary {
  id: string;
  action?: string;
  outcome?: string;
  score?: number;
  mode?: string;
  enforced?: boolean;
  createdAt?: string;
  [key: string]: unknown;
}

/** Response of GET /v1/decisions. */
export interface DecisionList {
  decisions: DecisionSummary[];
  nextCursor?: string | null;
}

/** A full decision (GET /v1/decisions/:id): signals, reasons, policy, feedback. */
export interface Decision {
  id: string;
  action?: string;
  outcome?: string;
  score?: number;
  mode?: string;
  enforced?: boolean;
  reasons?: string[];
  signals?: DecisionSignal[];
  policy?: Record<string, unknown> | null;
  feedback?: { label?: string; [key: string]: unknown } | null;
  createdAt?: string;
  [key: string]: unknown;
}

/** Aggregate metrics (GET /v1/metrics/summary). */
export interface MetricsSummary {
  projectId?: string;
  window?: string;
  [key: string]: unknown;
}

export interface GuardCMDClientOptions {
  baseUrl: string;
  apiKey: string;
  /** Optional custom fetch (used by tests). Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Request timeout in ms (default 15000). */
  timeoutMs?: number;
}

export class GuardCMDClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(opts: GuardCMDClientOptions) {
    if (!opts.baseUrl) throw new Error("API_BASE_URL is required");
    if (!opts.apiKey) throw new Error("GUARDCMD_API_KEY is required");
    // Normalize: strip trailing slash so we can safely append paths.
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 15000;
  }

  async evaluate(input: EvaluateInput): Promise<EvaluateDecision> {
    return this.request<EvaluateDecision>("POST", "/v1/evaluate", input);
  }

  /** POST /v1/guard/prompt: screen a prompt headed for an LLM. */
  async screenPrompt(input: ScreenPromptInput): Promise<ScreenPromptResult> {
    return this.request<ScreenPromptResult>("POST", "/v1/guard/prompt", input);
  }

  /** POST /v1/guard/tool-call: evidence-based authorization for an agent tool call. */
  async authorizeToolCall(input: AuthorizeToolCallInput): Promise<AuthorizeToolCallResult> {
    return this.request<AuthorizeToolCallResult>("POST", "/v1/guard/tool-call", {
      ...input,
      args: input.args ?? null,
    });
  }

  async usage(): Promise<UsageResult> {
    return this.request<UsageResult>("GET", "/v1/usage");
  }

  // ---- Repository-scan control plane ----

  /** GET /v1/projects — the account's projects. */
  async listProjects(): Promise<Project[]> {
    const res = await this.request<{ projects: Project[] }>("GET", "/v1/projects");
    return res.projects ?? [];
  }

  /** POST /v1/projects — create a project. */
  async createProject(name: string): Promise<Project> {
    return this.request<Project>("POST", "/v1/projects", { name });
  }

  /**
   * POST /v1/projects/:id/scan-url — scan a PUBLIC GitHub repository by URL.
   *
   * This REPLACES the old `createScan(projectId, path)`, which posted a
   * server-filesystem `path` to `POST /v1/projects/:id/scans`. That endpoint took its scan
   * root straight from the request body, which made it an arbitrary-file-read primitive for
   * anyone holding a key (scan a host directory, then read whole file contents back out
   * through the autofix endpoint). The API now answers it with
   * 501 `local_path_scans_disabled` unless a development-only switch is set, so a client
   * method for it would only ever produce an error.
   *
   * The server clones the repo itself into a disposable sandbox — the caller never names a
   * path. Synchronous MVP: the response is already a terminal Scan (`completed` or
   * `failed`). A malformed URL is 400 `invalid_github_url`; a private/missing repo is
   * 422 `repo_unavailable`. Both arrive as {@link ApiError} with `code` intact.
   */
  async scanUrl(projectId: string, url: string): Promise<Scan> {
    return this.request<Scan>(
      "POST",
      `/v1/projects/${encodeURIComponent(projectId)}/scan-url`,
      { url },
    );
  }

  /** GET /v1/scans/:id — a scan plus surface/recommendation counts. */
  async getScan(scanId: string): Promise<Scan> {
    return this.request<Scan>("GET", `/v1/scans/${encodeURIComponent(scanId)}`);
  }

  /** GET /v1/projects/:id/surfaces — surfaces from the latest completed scan. */
  async listProjectSurfaces(projectId: string): Promise<Surface[]> {
    const res = await this.request<{ surfaces: Surface[] }>(
      "GET",
      `/v1/projects/${encodeURIComponent(projectId)}/surfaces`,
    );
    return res.surfaces ?? [];
  }

  /** GET /v1/scans/:id/surfaces — surfaces discovered by a specific scan. */
  async listScanSurfaces(scanId: string): Promise<Surface[]> {
    const res = await this.request<{ surfaces: Surface[] }>(
      "GET",
      `/v1/scans/${encodeURIComponent(scanId)}/surfaces`,
    );
    return res.surfaces ?? [];
  }

  /** GET /v1/surfaces/:id — a single surface. */
  async getSurface(surfaceId: string): Promise<Surface> {
    return this.request<Surface>(
      "GET",
      `/v1/surfaces/${encodeURIComponent(surfaceId)}`,
    );
  }

  /** GET /v1/surfaces/:id/recommendations — hardening recommendations. */
  async listSurfaceRecommendations(surfaceId: string): Promise<Recommendation[]> {
    const res = await this.request<{ recommendations: Recommendation[] }>(
      "GET",
      `/v1/surfaces/${encodeURIComponent(surfaceId)}/recommendations`,
    );
    return res.recommendations ?? [];
  }

  /**
   * POST /v1/recommendations/:id/autofix — generate a PR-ready patch/diff for a recommendation.
   * The server re-scans the recommendation's source checkout and returns a review-only patch;
   * it does not write files or open a real PR.
   */
  async generateAutofix(recommendationId: string): Promise<AutofixResult> {
    const res = await this.request<{ autofix: AutofixResult }>(
      "POST",
      `/v1/recommendations/${encodeURIComponent(recommendationId)}/autofix`,
    );
    return res.autofix;
  }

  /**
   * POST /v1/recommendations/:id/pull-request — open a REAL GitHub pull request for a
   * recommendation. The server re-scans a sandboxed checkout of the project's linked repo,
   * generates + VALIDATES the patch, and only then opens the PR. Returns the opened PR
   * (number, url, headBranch) plus a compact autofix summary. Requires a linked GitHub repo
   * (else 409) and a configured GitHub App (else 501).
   */
  async openPullRequest(
    recommendationId: string,
    ref?: string,
  ): Promise<OpenPullRequestResponse> {
    return this.request<OpenPullRequestResponse>(
      "POST",
      `/v1/recommendations/${encodeURIComponent(recommendationId)}/pull-request`,
      ref ? { ref } : {},
    );
  }

  // ---- Policy control plane ----

  /** GET /v1/policies?projectId= — the account's policies (optionally scoped to a project). */
  async listPolicies(projectId?: string): Promise<Policy[]> {
    const qs = projectId ? `?projectId=${encodeURIComponent(projectId)}` : "";
    const res = await this.request<{ policies: Policy[] }>(
      "GET",
      `/v1/policies${qs}`,
    );
    return res.policies ?? [];
  }

  /** GET /v1/policies/:id — a policy plus its version history. */
  async getPolicy(policyId: string): Promise<Policy> {
    return this.request<Policy>("GET", `/v1/policies/${encodeURIComponent(policyId)}`);
  }

  /**
   * PATCH /v1/policies/:id — update a policy's config with optimistic concurrency.
   * `baseVersion` must match the current version or the API returns 409 (stale).
   * Produces a new draft/shadow version; it does not enforce by itself.
   */
  async updatePolicy(policyId: string, body: UpdatePolicyBody): Promise<Policy> {
    return this.request<Policy>(
      "PATCH",
      `/v1/policies/${encodeURIComponent(policyId)}`,
      body,
    );
  }

  /**
   * POST /v1/policies/:id/promote — promote a policy to `targetMode`. Promoting to `live`
   * REQUIRES `acknowledgeUserImpact: true` (the API returns 422 without it).
   */
  async promotePolicy(policyId: string, body: PromotePolicyBody): Promise<Policy> {
    return this.request<Policy>(
      "POST",
      `/v1/policies/${encodeURIComponent(policyId)}/promote`,
      body,
    );
  }

  /** POST /v1/policies/:id/rollback — roll a policy back to a prior version (default: previous). */
  async rollbackPolicy(policyId: string, body: RollbackPolicyBody = {}): Promise<Policy> {
    return this.request<Policy>(
      "POST",
      `/v1/policies/${encodeURIComponent(policyId)}/rollback`,
      body,
    );
  }

  /** POST /v1/policies — create a policy (from a recommendation, or from scratch). */
  async createPolicy(body: CreatePolicyBody): Promise<Policy> {
    return this.request<Policy>("POST", "/v1/policies", body);
  }

  // ---- Decision control plane ----

  /** GET /v1/decisions — recent decisions (paginated via nextCursor). */
  async listDecisions(filters: DecisionFilters = {}): Promise<DecisionList> {
    const params = new URLSearchParams();
    if (filters.projectId) params.set("projectId", filters.projectId);
    if (filters.action) params.set("action", filters.action);
    if (filters.mode) params.set("mode", filters.mode);
    if (filters.enforced !== undefined) params.set("enforced", String(filters.enforced));
    if (filters.limit !== undefined) params.set("limit", String(filters.limit));
    if (filters.cursor) params.set("cursor", filters.cursor);
    const qs = params.toString();
    return this.request<DecisionList>("GET", `/v1/decisions${qs ? `?${qs}` : ""}`);
  }

  /** GET /v1/decisions/:id — a full decision (signals, reasons, policy, feedback). */
  async getDecision(decisionId: string): Promise<Decision> {
    return this.request<Decision>(
      "GET",
      `/v1/decisions/${encodeURIComponent(decisionId)}`,
    );
  }

  /** POST /v1/decisions/:id/feedback — label a decision `legitimate` or `abusive`. */
  async submitFeedback(
    decisionId: string,
    label: "legitimate" | "abusive",
  ): Promise<Decision> {
    return this.request<Decision>(
      "POST",
      `/v1/decisions/${encodeURIComponent(decisionId)}/feedback`,
      { label },
    );
  }

  /** GET /v1/metrics/summary — aggregate metrics for a project/window. */
  async getMetrics(opts: { projectId?: string; window?: string } = {}): Promise<MetricsSummary> {
    const params = new URLSearchParams();
    if (opts.projectId) params.set("projectId", opts.projectId);
    if (opts.window) params.set("window", opts.window);
    const qs = params.toString();
    return this.request<MetricsSummary>(
      "GET",
      `/v1/metrics/summary${qs ? `?${qs}` : ""}`,
    );
  }

  private async request<T>(
    method: "GET" | "POST" | "PATCH",
    path: string,
    body?: unknown,
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method,
        headers: {
          // Contract accepts either scheme; send both to be robust.
          Authorization: `Bearer ${this.apiKey}`,
          "x-api-key": this.apiKey,
          "content-type": "application/json",
          accept: "application/json",
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err) {
      clearTimeout(timer);
      const msg =
        err instanceof Error && err.name === "AbortError"
          ? `Request to ${url} timed out after ${this.timeoutMs}ms`
          : `Network error calling ${url}: ${(err as Error).message}`;
      throw new ApiError(msg, "network_error", 0);
    } finally {
      clearTimeout(timer);
    }

    const text = await res.text();
    let parsed: unknown = undefined;
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = undefined;
      }
    }

    if (!res.ok) {
      const errBody = parsed as Partial<ApiErrorBody> | undefined;
      const code = errBody?.code ?? `http_${res.status}`;
      const message =
        errBody?.error ??
        (text ? text.slice(0, 500) : `HTTP ${res.status} ${res.statusText}`);
      throw new ApiError(message, code, res.status);
    }

    if (parsed === undefined) {
      throw new ApiError(
        `Invalid JSON response from ${url}`,
        "invalid_response",
        res.status,
      );
    }
    return parsed as T;
  }
}

/** @deprecated use {@link GuardCMDClient} (the product was formerly AbuseGuard). */
export const AbuseGuardClient = GuardCMDClient;
/** @deprecated use {@link GuardCMDClient}. */
export type AbuseGuardClient = GuardCMDClient;
