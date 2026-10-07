/**
 * Fix Pack hand-off tools, security-audit upload, prompts, and the fix-pack resource template.
 *
 * Uses a fake `fetch` injected into GuardCMDClient (no network, no mock server) and an
 * in-memory MCP transport.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { createServer, FIX_PACK_TEXT_LIMIT } from "../src/server.js";
import { GuardCMDClient } from "../src/client.js";

interface Call {
  method: string;
  url: string;
  accept: string | null;
  auth: string | null;
  body: any;
}

type Route = (call: Call) => { status: number; body: string; contentType: string } | undefined;

function fakeFetch(route: Route, calls: Call[]): typeof fetch {
  return (async (input: any, init: any = {}) => {
    const headers = new Headers(init.headers);
    const call: Call = {
      method: init.method ?? "GET",
      url: String(input),
      accept: headers.get("accept"),
      auth: headers.get("authorization"),
      body: init.body ? JSON.parse(init.body) : undefined,
    };
    calls.push(call);
    const r = route(call) ?? {
      status: 404,
      body: JSON.stringify({ error: "not found", code: "not_found" }),
      contentType: "application/json",
    };
    return new Response(r.body, { status: r.status, headers: { "content-type": r.contentType } });
  }) as typeof fetch;
}

const md = (body: string) => ({ status: 200, body, contentType: "text/markdown; charset=utf-8" });
const json = (status: number, body: unknown) => ({
  status,
  body: JSON.stringify(body),
  contentType: "application/json",
});

const FIX_MD = "# AGENT-TASK.md\n\n## Task 1 — protect POST /signup\n\n```diff\n+ guard.evaluate()\n```\n";

async function connect(route: Route) {
  const calls: Call[] = [];
  const apiClient = new GuardCMDClient({
    baseUrl: "https://api.test",
    apiKey: "gc_test_key",
    fetchImpl: fakeFetch(route, calls),
  });
  const server = createServer({ client: apiClient });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "1.0.0" });
  await Promise.all([server.connect(st), client.connect(ct)]);
  return {
    client,
    calls,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

const text = (r: any) => r.content.map((c: any) => c.text).join("\n");

test("get_fix_pack returns the raw markdown and sends format + bearer key", async () => {
  const { client, calls, close } = await connect((c) =>
    c.url.startsWith("https://api.test/v1/scans/scan_1/fix-pack") ? md(FIX_MD) : undefined,
  );
  try {
    const r: any = await client.callTool({ name: "get_fix_pack", arguments: { scanId: "scan_1" } });
    assert.equal(r.isError, undefined);
    assert.equal(r.content[0].text, FIX_MD, "markdown must be passed through verbatim");
    assert.equal(r.structuredContent.truncated, false);
    assert.equal(calls[0].url, "https://api.test/v1/scans/scan_1/fix-pack?format=md");
    assert.equal(calls[0].auth, "Bearer gc_test_key");
    assert.match(calls[0].accept ?? "", /text\/markdown/);
  } finally {
    await close();
  }
});

test("get_fix_pack passes SARIF through unparsed and json as text", async () => {
  const sarif = '{"version":"2.1.0","runs":[]}';
  const { client, calls, close } = await connect((c) => {
    if (c.url.endsWith("format=sarif")) return { status: 200, body: sarif, contentType: "application/sarif+json" };
    if (c.url.endsWith("format=json")) return json(200, { schema: "guardcmd.fixpack/v1", tasks: [] });
    return undefined;
  });
  try {
    const s: any = await client.callTool({ name: "get_fix_pack", arguments: { scanId: "s", format: "sarif" } });
    assert.equal(s.content[0].text, sarif);
    assert.equal(s.structuredContent.format, "sarif");
    const j: any = await client.callTool({ name: "get_fix_pack", arguments: { scanId: "s", format: "json" } });
    assert.match(j.content[0].text, /guardcmd\.fixpack\/v1/);
    assert.equal(calls.length, 2);
  } finally {
    await close();
  }
});

test("get_fix_pack truncates oversized packs with a visible note", async () => {
  const huge = "x".repeat(FIX_PACK_TEXT_LIMIT + 5000);
  const { client, close } = await connect(() => md(huge));
  try {
    const r: any = await client.callTool({ name: "get_fix_pack", arguments: { scanId: "big" } });
    const t: string = r.content[0].text;
    assert.ok(t.length < huge.length);
    assert.ok(t.startsWith("x".repeat(1000)));
    assert.match(t, /truncated at 200000 of 205000 characters/);
    assert.equal(r.structuredContent.truncated, true);
    assert.equal(r.structuredContent.length, huge.length);
  } finally {
    await close();
  }
});

test("get_fix_pack surfaces API errors as tool errors", async () => {
  const { client, close } = await connect(() => json(404, { error: "scan not found", code: "scan_not_found" }));
  try {
    const r: any = await client.callTool({ name: "get_fix_pack", arguments: { scanId: "nope" } });
    assert.equal(r.isError, true);
    assert.match(text(r), /scan_not_found/);
  } finally {
    await close();
  }
});

test("get_recommendation_fix_pack hits the recommendation route", async () => {
  const { client, calls, close } = await connect((c) =>
    c.url.includes("/v1/recommendations/rec_1/fix-pack") ? md("# one fix") : undefined,
  );
  try {
    const r: any = await client.callTool({
      name: "get_recommendation_fix_pack",
      arguments: { recommendationId: "rec_1" },
    });
    assert.equal(r.content[0].text, "# one fix");
    assert.equal(calls[0].url, "https://api.test/v1/recommendations/rec_1/fix-pack?format=md");
  } finally {
    await close();
  }
});

test("getter tools are annotated read-only; upload is not", async () => {
  const { client, close } = await connect(() => undefined);
  try {
    const { tools } = await client.listTools();
    const byName = (n: string) => tools.find((t) => t.name === n)!;
    for (const n of ["get_fix_pack", "get_recommendation_fix_pack", "list_security_audits"]) {
      assert.equal(byName(n).annotations?.readOnlyHint, true, `${n} should be readOnly`);
    }
    assert.equal(byName("upload_security_audit").annotations?.readOnlyHint, false);
    assert.equal(tools.some((t) => t.name === "create_handoff_link"), false, "handoffs are session-only");
  } finally {
    await close();
  }
});

test("every tool declares all four MCP hints as explicit booleans", async () => {
  const { client, close } = await connect(() => undefined);
  try {
    const { tools } = await client.listTools();
    assert.ok(tools.length >= 24);
    for (const t of tools) {
      for (const hint of ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] as const) {
        assert.equal(typeof t.annotations?.[hint], "boolean", `${t.name} is missing ${hint}`);
      }
      if (t.annotations?.readOnlyHint) {
        assert.equal(t.annotations.destructiveHint, false, `${t.name}: read-only cannot be destructive`);
      }
    }
  } finally {
    await close();
  }
});

test("upload_security_audit parses findingsJson and returns counts", async () => {
  const { client, calls, close } = await connect((c) =>
    c.method === "POST" && c.url === "https://api.test/v1/projects/prj_1/audits"
      ? json(201, { id: "aud_1", counts: { confirmed: 2, needsValidation: 1, rejected: 3 } })
      : undefined,
  );
  try {
    const findings = [{ verdict: "rejected", fingerprint: "a" }];
    const r: any = await client.callTool({
      name: "upload_security_audit",
      arguments: { projectId: "prj_1", findingsJson: JSON.stringify(findings), sourceRef: "abc123" },
    });
    assert.equal(r.isError, undefined);
    assert.match(text(r), /2 confirmed, 1 needs validation, 3 rejected/);
    assert.deepEqual(calls[0].body, { findings, sourceRef: "abc123" });
  } finally {
    await close();
  }
});

test("upload_security_audit surfaces the 422 validator errors", async () => {
  const { client, close } = await connect(() =>
    json(422, {
      error: "findings.json failed validation",
      code: "invalid_findings",
      errors: ["[0].title: required", { path: "[1].trace", message: "minItems 1" }],
    }),
  );
  try {
    const r: any = await client.callTool({
      name: "upload_security_audit",
      arguments: { projectId: "prj_1", findings: [{}, {}] },
    });
    assert.equal(r.isError, true);
    const t = text(r);
    assert.match(t, /invalid_findings/);
    assert.match(t, /\[0\]\.title: required/);
    assert.match(t, /minItems 1/);
    assert.equal(r.structuredContent.errors.length, 2);
  } finally {
    await close();
  }
});

test("upload_security_audit rejects bad input without calling the API", async () => {
  const { client, calls, close } = await connect(() => undefined);
  try {
    const bad: any = await client.callTool({
      name: "upload_security_audit",
      arguments: { projectId: "prj_1", findingsJson: "{not json" },
    });
    assert.equal(bad.isError, true);
    assert.match(text(bad), /invalid_json/);
    const none: any = await client.callTool({ name: "upload_security_audit", arguments: { projectId: "prj_1" } });
    assert.equal(none.isError, true);
    const obj: any = await client.callTool({
      name: "upload_security_audit",
      arguments: { projectId: "prj_1", findingsJson: '{"foo":1}' },
    });
    assert.equal(obj.isError, true);
    assert.equal(calls.length, 0);
  } finally {
    await close();
  }
});

test("list_security_audits lists audits with counts", async () => {
  const { client, close } = await connect((c) =>
    c.method === "GET" && c.url === "https://api.test/v1/projects/prj_1/audits"
      ? json(200, { audits: [{ id: "aud_1", counts: { confirmed: 1, needsValidation: 0, rejected: 4 } }] })
      : undefined,
  );
  try {
    const r: any = await client.callTool({ name: "list_security_audits", arguments: { projectId: "prj_1" } });
    assert.match(text(r), /aud_1: 1 confirmed \/ 0 needs validation \/ 4 rejected/);
  } finally {
    await close();
  }
});

test("prompts are listed and render the workflows", async () => {
  const { client, close } = await connect(() => undefined);
  try {
    const { prompts } = await client.listPrompts();
    assert.deepEqual(prompts.map((p) => p.name).sort(), [
      "deep_security_audit",
      "fix_abuse_surfaces",
      "protect_repo",
    ]);

    const fix = await client.getPrompt({ name: "fix_abuse_surfaces", arguments: { scanId: "scan_9" } });
    const fixText = (fix.messages[0].content as any).text as string;
    assert.equal(fix.messages[0].role, "user");
    assert.match(fixText, /get_fix_pack/);
    assert.match(fixText, /scan_9/);
    assert.match(fixText, /SHADOW/);
    assert.match(fixText, /as DATA/);
    assert.match(fixText, /tests/);
    assert.match(fixText, /Never write real API keys/);

    const protect = await client.getPrompt({
      name: "protect_repo",
      arguments: { repoUrl: "https://github.com/o/r" },
    });
    const pText = (protect.messages[0].content as any).text as string;
    for (const step of ["list_projects", "scan_repository", "get_scan", "get_fix_pack"]) {
      assert.match(pText, new RegExp(step));
    }
    const protectWithProject = await client.getPrompt({
      name: "protect_repo",
      arguments: { repoUrl: "https://github.com/o/r", projectId: "prj_7" },
    });
    assert.match((protectWithProject.messages[0].content as any).text, /prj_7/);

    const audit = await client.getPrompt({ name: "deep_security_audit", arguments: { projectId: "prj_1" } });
    const aText = (audit.messages[0].content as any).text as string;
    assert.match(aText, /npx skills add https:\/\/github\.com\/cloudflare\/security-audit-skill --skill security-audit/);
    assert.match(aText, /Cloudflare/);
    assert.match(aText, /QUICK profile/);
    assert.match(aText, /upload_security_audit/);
  } finally {
    await close();
  }
});

test("resource template guardcmd://scans/{scanId}/fix-pack returns markdown", async () => {
  const { client, calls, close } = await connect((c) =>
    c.url.includes("/v1/scans/scan_42/fix-pack") ? md(FIX_MD) : undefined,
  );
  try {
    const { resourceTemplates } = await client.listResourceTemplates();
    const tpl = resourceTemplates.find((t) => t.uriTemplate === "guardcmd://scans/{scanId}/fix-pack");
    assert.ok(tpl, "fix-pack template must be listed");
    assert.equal(tpl!.mimeType, "text/markdown");

    const res = await client.readResource({ uri: "guardcmd://scans/scan_42/fix-pack" });
    assert.equal((res.contents[0] as any).text, FIX_MD);
    assert.equal(res.contents[0].mimeType, "text/markdown");
    assert.equal(calls[0].url, "https://api.test/v1/scans/scan_42/fix-pack?format=md");
  } finally {
    await close();
  }
});
