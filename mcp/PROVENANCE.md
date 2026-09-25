# Provenance: guardcmd-mcp@0.1.0

This directory is the auditable source for the [`guardcmd-mcp`](https://www.npmjs.com/package/guardcmd-mcp)
npm package, version **0.1.0** (tarball integrity
`sha512-ox4pn+WMpKWNpnVorS9z4YMPvHqTX7521iTDd42D3m8+JrkMSIj3Gp2Syby8cq/HtPqU6ZJh1PWiv3EJYDFOZQ==`).

## What corresponds to what

| Here | In the npm package | Relationship |
| --- | --- | --- |
| `src/client.ts` | `dist/client.js`, `dist/client.d.ts` | Exact source; builds byte-for-byte |
| `src/server.ts` | `dist/server.js`, `dist/server.d.ts` | Exact source; builds byte-for-byte |
| `src/stdio.ts` | `dist/stdio.js`, `dist/stdio.d.ts` | Exact source; builds byte-for-byte (the `guardcmd-mcp` bin) |
| `README.md`, `LICENSE` | `README.md`, `LICENSE` | Identical text; the published copies have CRLF line endings (packed on Windows) |
| `package.json` | `package.json` | Same manifest; `bin` paths written as `dist/stdio.js` instead of `./dist/stdio.js` (npm treats these as equivalent) |
| `src/http.ts` | — (not published) | Streamable HTTP transport for the hosted server. Included because the tests exercise its auth and DNS-rebinding protections. |
| `test/mcp.test.ts` | — (not published) | Protocol and security tests covering all 20 tools |

`src/http.ts` and `test/mcp.test.ts` differ from the internal copies only in comments that
referenced internal paths or hosting details. Runtime and test behavior are unchanged.

The server talks only to the public GuardCMD API (`https://api.guardcmd.com` by default,
overridable with `API_BASE_URL`) using the caller's API key. It has no other network
dependencies.

## Verify it yourself

Requires Node 20+, npm, `tar` and `diff`.

```sh
git clone https://github.com/guardcmd/guardcmd.git
cd guardcmd/mcp

# 1. Install pinned dependencies and build from source
npm ci
npx tsc -p tsconfig.json

# 2. Fetch the published package
npm pack guardcmd-mcp@0.1.0 --pack-destination /tmp
mkdir -p /tmp/guardcmd-mcp && tar -xzf /tmp/guardcmd-mcp-0.1.0.tgz -C /tmp/guardcmd-mcp

# 3. Compare every published file with the local build
for f in client.js client.d.ts server.js server.d.ts stdio.js stdio.d.ts; do
  diff dist/$f /tmp/guardcmd-mcp/package/dist/$f && echo "dist/$f identical"
done
diff --strip-trailing-cr README.md /tmp/guardcmd-mcp/package/README.md && echo "README.md identical"
diff --strip-trailing-cr LICENSE   /tmp/guardcmd-mcp/package/LICENSE   && echo "LICENSE identical"

# 4. Run the test suite (40 tests; uses a local mock API, no network or key needed)
npm test
```

The compiled `dist/` files match byte-for-byte. The published package does not ship `.js.map`
files, but its compiled files still end with the `//# sourceMappingURL=...` comment that `tsc`
emits. `README.md` and `LICENSE` were packed with CRLF line endings, which is why step 3
compares them with `--strip-trailing-cr`.
