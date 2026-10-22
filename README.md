# k6 Load Suite (`k6-load-suite`)

Deterministic k6 load-testing scenarios, reusable SLO threshold profiles (`smoke`, `baseline`, `stress`, `spike`), and an HTTP HAR-to-k6 Converter Service with automatic PII redaction for **Globex** (`globlex.*`) and **PerfOps** (`perfops.*`) platforms.

## Architecture & Structure

- `scenarios/globlex-enterprise-slo.js` — Multi-group k6 load scenario testing `globlex.shop`, `globlex.pro`, `globlex.online`, `api.globlex.pro/health`, `api.globlex.pro/enterprise/overview`, and `api.globlex.pro/quote-parse/`.
- `scenarios/perfops-gateway-slo.js` — Edge and control-plane SLO scenario testing `perfops.tech`, `perfops.shop`, and `aco.perfops.shop/health`.
- `lib/thresholds.js` — Reusable SLO threshold profiles (`smoke`, `baseline`, `stress`, `spike`) and response verification helpers.
- `src/har-converter.js` — Pure JS HAR-to-k6 ES-module generator with automatic PII sanitization (`Authorization`, `Cookie`, `X-API-Key`, sensitive URL query tokens, and JSON body secrets).
- `src/url-guard.js` — Outbound fetch policy (scheme/host/IP validation, DNS re-checks, pinned connections, manual redirects, timeout and size caps) used by the OpenAPI smoke probe.
- `src/server.js` — HTTP microservice (`PORT` default `4040`) exposing scenario catalogs and live HAR-to-k6 conversion.
- `tests/k6-load-suite.test.js`, `tests/ssrf-guard.test.js` — Automated test suites using `node --test`.

## Quick Start

```bash
# Run automated test suite
npm test

# Start the HAR-to-k6 & Scenario Catalog HTTP service (default port 4040)
npm start

# Run k6 scenarios (requires k6 CLI)
k6 run --vus 1 --duration 10s scenarios/globlex-enterprise-slo.js
k6 run --env K6_PROFILE=baseline scenarios/perfops-gateway-slo.js
```

## HTTP API (`PORT=4040`)

- `GET /health` — Service health & loaded profile count.
- `GET /api/v1/scenarios` — Lists available k6 scenarios and threshold profiles.
- `POST /api/v1/har-to-k6` — Converts a HAR JSON payload into a clean ES-module k6 script with PII stripped.
- `POST /api/v1/swagger-to-k6` — Parses an OpenAPI/Swagger spec or endpoint list, generates a deterministic k6 script, and smoke-probes the endpoints.

### Outbound fetch policy (SSRF hardening)

`swagger-to-k6` only probes `http:`/`https:` URLs. Loopback, RFC1918 private ranges, CGNAT, link-local (including `169.254.169.254`), IPv6 local ranges, and `localhost`/`.local`/`.internal` hosts are rejected. Hostnames are resolved before each request and every answer is re-checked, with the socket pinned to the vetted IP (DNS-rebinding protection). Redirects are followed manually and every `Location` is re-validated. Requests time out after 5 seconds and responses are capped at 2 MiB. Policy violations return HTTP 400 instead of a probe verdict.

`SWAGGER_FETCH_ALLOWLIST` (comma-separated hostnames, `*.example.com` wildcards allowed) restricts fetching to the listed hosts. When set, all other hosts are rejected; listing a host also explicitly opts it in, e.g. `SWAGGER_FETCH_ALLOWLIST=127.0.0.1` for local tests.

## API contract, CI & deploy

- **Contract:** [`docs/api/openapi.json`](docs/api/openapi.json) (OpenAPI 3.1).
  `tests/openapi-contract.test.js` fails when `ROUTES` in `src/server.js` and the spec disagree.
- **Tests:** `npm test` — Node's built-in runner, no dependencies. CI runs it plus the
  org security gate (gitleaks) on every pull request.
- **Config:** every environment variable is listed in [`.env.example`](.env.example).
- **Deploy:** `docker build -t k6-load-suite . && docker run -p 4040:4040 k6-load-suite` — `node:22-alpine`,
  non-root, `HEALTHCHECK` on `GET /health`. The portfolio port map lives in
  [`muntianus/architecture`](https://github.com/muntianus/architecture).

## Contact / Support

PerfOps official Telegram contact: [@perfops_ai_manager](https://t.me/perfops_ai_manager).

For security vulnerabilities, use private vulnerability reporting rather than public Telegram messages.
