# Upstream: Cloudflare security-audit skill

| | |
| --- | --- |
| Source | https://github.com/cloudflare/security-audit-skill |
| Commit | `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` |
| Vendored on | 2026-10-07 |
| License | MIT (see [`LICENSE`](./LICENSE)) — Copyright Cloudflare, Inc. |

## What is vendored

Byte-for-byte copies of upstream files, flattened so Claude Code plugins discover the skill one
level under `skills/`:

| Here | Upstream |
| --- | --- |
| `SKILL.md`, companion `*.md`, `report-schema.json`, `validate-*.cjs` | `skills/security-audit/*` |
| `LICENSE` | `LICENSE` |
| `UPSTREAM-README.md` | `README.md` |

Nothing is modified; `.gitattributes` disables EOL normalization so the bytes stay identical.
`UPSTREAM.md` (this file) and `.gitattributes` are the only GuardCMD-authored additions.

## What GuardCMD uses it for

- **Companion skill.** GuardCMD finds abuse surfaces (signup/login/AI/upload routes without
  rate limits or risk checks) and hands them to a coding agent as a Fix Pack. The Fix Pack ends
  with an optional "Deep audit" step that tells the agent it may run this skill
  (`npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit`,
  `quick` profile scoped to the flagged routes) and upload the resulting `findings.json`.
- **Audit ingest.** The GuardCMD API (`POST /v1/projects/:id/audits`) accepts that
  `findings.json`, validates it against this `report-schema.json`, and turns confirmed findings
  with remediation into Fix Pack tasks.
- GuardCMD never relabels its own scanner output as `confirmed`; that verdict is reserved for
  findings that met this skill's evidence bar.

Nothing in this directory is executed by GuardCMD's services.

## Re-syncing

Copy the files listed above from the upstream commit you want, verify they are byte-identical,
and update the commit and date in this file.
