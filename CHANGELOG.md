# Changelog

Notable changes to this service. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Changed

- Adopted the muntianus Repository Standard v1: committed OpenAPI contract
  (`docs/api/openapi.json`) with a route/spec drift test, `AGENTS.md` / `CLAUDE.md` /
  `SECURITY.md`, `.env.example`, Dependabot, a non-root Docker image with a health check,
  and CI with SHA-pinned actions, least-privilege permissions
  (secret scanning stays with GitGuardian).
