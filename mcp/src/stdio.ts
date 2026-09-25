#!/usr/bin/env node
/**
 * stdio entrypoint for the GuardCMD MCP server.
 *
 * This is what `npx guardcmd-mcp` runs. Claude Desktop / Cursor / Claude Code
 * spawn it and speak MCP over stdin/stdout. Requires env:
 *   - API_BASE_URL         (public API origin)
 *   - GUARDCMD_API_KEY   (caller's API key)
 *
 * IMPORTANT: never write non-protocol output to stdout — it corrupts the JSON-RPC
 * stream. All diagnostics go to stderr.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer, resolveConfig } from "./server.js";

async function main(): Promise<void> {
  const { baseUrl, apiKey } = resolveConfig();
  if (!baseUrl || !apiKey) {
    console.error(
      "[guardcmd-mcp] Missing GUARDCMD_API_KEY (create one at https://guardcmd.ai). Optionally set API_BASE_URL.",
    );
    process.exit(1);
  }

  const server = createServer({ baseUrl, apiKey });
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(
    `[guardcmd-mcp] stdio server ready (API_BASE_URL=${baseUrl}). Waiting for MCP client...`,
  );
}

main().catch((err) => {
  console.error("[guardcmd-mcp] fatal:", err);
  process.exit(1);
});
