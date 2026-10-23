# Validation — 1.0.0-rc.3

Recorded on 2026-10-23 using Node 24.19.0 in the local execution environment. This record separates the current product checks from earlier reference evidence. No commercial-provider compatibility is inferred.

## Current release checks

| Check | Observed result |
|---|---|
| TypeScript, lint, API/SQL tests and builds (`npm run check`) | Passed; **53 tests**, 19.27 seconds for the test suite |
| Browser suite | **5 passed**, 35.2 seconds, Chromium 153 via an explicitly configured executable |
| Separate TV/phone approval and revocation | Passed; no WebAuthn or tempLogin account requests |
| Decline and automatic expiry | Passed; expiry exercised through the UI's 15-second demo option |
| English markup and narrow layout | Passed at 320px for overview, guide, TV, code entry and sessions |
| Developer-guide navigation | Passed, including integration anchor navigation |
| Visual inspection | Desktop overview, TV QR screen, developer guide and 390px phone consent reviewed |
| Local Markdown links | All referenced local targets exist |
| Fresh lockfile installation | `npm ci --ignore-scripts` passed; build regenerated successfully |
| Current dependency audit | `npm audit --audit-level=high`: zero reported advisories |
| SDK packaging | rc.3 tarball generated with compiled JS, types, README and licence |

The nine provider API/SQL cases cover identity without user/passkey creation, missing identity/subject injection, code and duration validation, concurrent decisions/exchanges, expiry, per-account revocation, preserving a second TV, deny/backoff/live entitlement, Origin enforcement, production demo blocking and provider namespace isolation. The other 44 tests check session-policy primitives and opt-in legacy API regressions.

## Test environment and limits

API tests use the real PGlite PostgreSQL engine. The legacy suite also supports TEST_DATABASE_URL in a disposable database; the provider suite currently uses isolated PGlite only. Networked PostgreSQL concurrency and a real multi-replica provider topology remain unvalidated.

Physical phone camera scanning, a real provider login, native TV hardware, media/DRM cutoff, Docker deployment, remote GitHub CI and independent security/accessibility audits have not been executed. Browser layout checks are not a complete accessibility audit. The real Cloudflare phone tunnel depends on the evaluator's machine/network and was not exercised here.

## Earlier backend/package evidence

The rc.2 provider SDK tarball was installed in a separate consumer directory and imported successfully. The rc.3 SDK keeps the same implementation and updates package version/documentation. The prior full dependency audit reported zero advisories; that result is not proof of security.

An earlier synthetic 80-request Fastify.inject/PGlite provider-session benchmark measured p50 1.86 ms and p95 2.94 ms. It excludes TCP, TLS, real authentication and media. It is not a production throughput or user-perceived latency claim.
