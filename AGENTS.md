# AGENTS.md — k6-load-suite

> Canon: `~/github/vault/personal/agent-config/AGENTS.md`
> Org policy: [`muntianus/.github/AGENT_POLICY.md`](https://github.com/muntianus/.github/blob/main/AGENT_POLICY.md) ·
> [Repository Standard](https://github.com/muntianus/.github/blob/main/docs/standards/REPOSITORY_STANDARD.md)

## Repo-local rules

- **Zero dependencies.** Node ≥ 20 standard library only (`node:http`, `node:test`);
  adding an npm dependency needs an ADR.
- **Contract first.** A route change updates `ROUTES` in `src/server.js` and
  `docs/api/openapi.json` in the same commit; `tests/openapi-contract.test.js` fails on drift.
- **Config is env-only.** Every variable the code reads is listed in `.env.example`;
  never commit `.env`.
- **`GET /health` stays dependency-free** (liveness only).
- **Every outbound fetch goes through `src/url-guard.js`** (`assertSafeUrl` + DNS pinning + per-hop redirect checks). Never call `fetch` on a user-supplied URL directly; `tests/ssrf-guard.test.js` must keep passing.
- k6 scenarios in `scenarios/` and `smoke.js` run under the k6 runtime, not Node — they are syntax-checked in CI but not imported by tests.
- Before pushing: `npm test`.
- Conventional commits; branch `feat/*` / `fix/*` / `chore/*`; never push to `main`.
