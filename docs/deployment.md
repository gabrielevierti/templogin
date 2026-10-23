# Deployment and operations

## Development

Node 24, `npm ci`, `npm run dev`. The default `.data` directory contains local session data and is excluded from Git. Use synthetic information. `npm run dev:phone` starts an optional public Cloudflare Quick Tunnel with an isolated in-memory database; use its HTTPS URL on both devices. Neither path requires passkeys or tempLogin registration.

## Real provider hosting

The bundled production entry point deliberately has **no real provider adapter**. Demo login is disabled when NODE_ENV=production. Do not enable development mode to obtain a working production login. Embed `registerTemporaryLogin` in the provider's application as documented in INTEGRATION.md, or pass a real `ProviderOptions` object as the third argument to `createApp(config, db, provider)` in a custom server entry point.

`PUBLIC_ORIGIN` must be the exact externally reachable HTTPS origin. Use PostgreSQL (`DATABASE_URL`), bounded request bodies/timeouts, safe logs, backups and private secrets. The provider's login cookie must be secure/HttpOnly, appropriately SameSite, and protected against fixation and CSRF. The reference host supplies strict Origin checks and persistent per-IP rate limiting. The standalone package expects host rate limiting.

The Dockerfile includes all workspace manifests. `compose.production.yaml` provides a candidate PostgreSQL/Caddy/TLS topology, but requires a custom real-adapter entry point to serve authenticated content. It has not been deployed here. Verify Docker, DNS, TLS, PostgreSQL migrations, proxy trust and image digests before a pilot. Trust only configured proxy IPs, never arbitrary forwarded headers.

## Data and retention

Core legacy schema migrations are checksummed; do not edit applied migrations. The provider SDK exports its initial `schemaSQL` and creates tables idempotently. For production, move that SQL into the provider's migration pipeline, verify schema version and use a least-privilege runtime adapter as described in INTEGRATION.md. Future changes require versioned migrations.

`npm run maintenance` deletes expired provider pairings, temporary sessions and demo login records. Its cleanup of old wallet data is retained for existing development databases. Expiry enforcement is independent of maintenance. Agree retention, deletion and auditing requirements before storing real subjects; the reference has no full provider-account deletion workflow because accounts remain with the provider.

Back up the database with encryption and restricted access. Test restore into an isolated environment. **Before admitting traffic after restore**, invalidate recovered credentials in one transaction:

```sql
BEGIN;
UPDATE tl_provider_sessions SET revoked_at = COALESCE(revoked_at, (extract(epoch FROM now())*1000)::bigint);
DELETE FROM tl_pairings;
COMMIT;
```

Invalidate provider login sessions according to the provider's own procedures. Never restore over a live database without a maintenance plan.

## Health and telemetry

`/healthz` reports process availability; `/readyz` checks database connectivity. Optional `/metrics` requires `METRICS_TOKEN` of at least 32 random characters, otherwise returns 404. Scrape privately. Metrics omit subjects, codes and tokens. Monitor errors, failed authorization, rate limits, SQL capacity and clock synchronization. The server's clock is authoritative for expiry; media/client clocks need explicit synchronization rules in the partner implementation.

Run tests and rehearse revoke/expiry/restore on the actual deployment before serving real users. Neither a passing unit suite nor the supplied Compose file establishes production readiness.
