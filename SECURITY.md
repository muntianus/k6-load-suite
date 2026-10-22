# Security Policy

k6-load-suite is an internal PerfOps microservice (default port 4040).

- **Report a vulnerability:** open a private security advisory on this repo
  (GitHub → Security → Advisories) or contact the owner listed in
  [`muntianus/.github`](https://github.com/muntianus/.github/blob/main/SECURITY.md).
- **Secrets:** none are required. Never commit `.env`; only `.env.example`
  (placeholder values) is tracked. CI runs gitleaks via the org security gate.
- `POST /api/v1/swagger-to-k6` probes URLs taken from the posted spec. `src/url-guard.js` refuses private, loopback, link-local and metadata ranges, pins DNS and re-validates redirects; only `SWAGGER_FETCH_ALLOWLIST` widens that. HAR conversion redacts credentials and PII before generating scripts.
