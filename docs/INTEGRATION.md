# Provider integration guide

Before wiring an adapter, run the [quickstart](QUICKSTART.md) and [evaluation checklist](EVALUATION.md). The app also includes a Developer guide at `/guide`. For responsibilities across teams, use the [pilot checklist](PILOT-CHECKLIST.md).

## Deployment model

Embed tempLogin in the provider's backend. Keep existing accounts and login. Each deployed configuration has one fixed provider ID/origin. The integration receives a verified provider subject from the host application and creates an isolated temporary session, without inserting a tempLogin user or passkey.

The supported reference stack is Node 24, Fastify 5 and PostgreSQL (PGlite for local tests). This is a custom JSON protocol inspired by device authorization, not a complete OAuth authorization server. Cross-organization federation and turnkey commercial adapters are outside this candidate.

## Build the package

From the repository root:

```sh
npm ci
npm run build
npm pack ./packages/provider-sdk
```

Install the resulting tarball in the provider's backend. It exports `registerTemporaryLogin`, `schemaSQL`, and TypeScript types `ProviderOptions`, `ProviderIdentity`, `ProviderSession`, `SqlStore`. It depends on Zod and uses Fastify as a peer dependency. It is not yet published to a registry.

## Wire existing authentication

```ts
import {registerTemporaryLogin} from '@templogin/provider-sdk';

const temporary = await registerTemporaryLogin(app, database, {
  id: 'your-service',
  name: 'Your Service',
  origin: 'https://tv-login.your-service.example',
  maxDurationSeconds: 7200,
  identity: async request => {
    const account = await yourExistingLogin.verifySession(request);
    if (!account) return null;
    return {
      subject: account.immutableId,
      displayName: account.displayName,
      authenticatedAt: account.lastAuthenticationUnixMilliseconds,
    };
  },
  entitled: subject => yourAccountService.canUseStreaming(subject),
});

app.get('/playback', async request => {
  const session = await temporary.requireSession(request);
  return yourPlaybackService.issue({
    subject: session.subject,
    sessionId: session.id,
    expiresAt: Number(session.expires_at),
  });
});
```

`yourExistingLogin`, `yourAccountService`, `yourPlaybackService` and `database` represent the provider's existing implementations; this snippet is a wiring example, not fictitious working credentials. A reusable typed installer is supplied in `examples/provider-integration.ts`. The working reference host is `services/api/temporary.ts`.

**Never** derive `subject` from an unverified email, an arbitrary header, a TV request or an unsigned JWT. The identity callback must verify the actual provider session (or complete the provider's supported OIDC flow), including its validity and account status. An authenticated session older than 15 minutes requires provider reauthentication. Future/invalid timestamps fail closed. Passwords and upstream OAuth tokens are not passed to tempLogin or the TV.

If identity is absent, `/context`, `/decision` and `/sessions` return `401 provider_login_required`. The host must navigate the phone through its existing login, with a validated same-origin return path, then return to the pending code. Do not permit arbitrary return URLs. The included UI only implements fictional demo login; the partner supplies its real login navigation and branding.

## SQL adapter

Implement the structural `SqlStore` interface: parameterized `query`, `exec`, and `transaction`. Transactions must use one database connection, commit on success, roll back on throw, and support `SELECT ... FOR UPDATE`. The repository's `services/api/database.ts` is a working PostgreSQL/PGlite implementation.

The current installer executes idempotent `schemaSQL` to create `tl_pairings` and `tl_provider_sessions` plus indexes. For a least-privilege deployment, apply this exact initial SQL in your migration pipeline before runtime; call the installer with an adapter whose `exec(schemaSQL)` verifies the already-installed schema instead of granting ongoing DDL privileges. Future schema changes need new migrations, never silent changes to live tables.

Persist only the provider's opaque subject, device label, time bounds, revocation state and credential hashes. No foreign key into a tempLogin user database is required. Expired pairing/session data can be removed; enforcement checks timestamps independently. Pairings retain a session reference but no cascading foreign key; session removal fails closed for token exchange.

## TV integration

1. POST `/api/temporary/pairings` with `device_name`. Treat that label as unverified input.
2. Show `verification_uri_complete` as QR and `user_code` as readable text. Hold `device_code` privately in memory.
3. Poll `/token` at the advertised interval. On `slow_down`, increase the interval by at least five seconds; stop on expiry, denial or consumption. Apply bounded network backoff and cancellation in a native client.
4. Keep `access_token` only for the temporary session; send it as Bearer to the provider's guarded resources. It is a provider-scoped bearer credential, not a universal account token or hardware identity proof.
5. Honor absolute `expires_at` (Unix milliseconds) and reset local UI, playback and account cache at expiry. On wake/network recovery validate before revealing any profile or continuing playback. No perpetual refresh is provided: extension requires a new QR and explicit consent.
6. POST `/logout` to revoke only this session. If unreachable, clear local credentials and disclose that remote revocation was not confirmed. The phone can revoke via the provider's session-management UI.

The reference UI polls protected content every three seconds and updates the deadline locally; backend requests fail at expiry independently. It uses no browser localStorage/IndexedDB for device credentials. Closing a tab discards the token but does not claim remote revocation; the session remains bounded by its original deadline or phone revocation.

## Media integration is required

A successful `requireSession` is an authorization check, not a streaming player. Bind playback grants, manifest URLs, signed segment URLs, refresh tokens and DRM licences to this session and never beyond its deadline. Recheck/stop long-lived streams, align player clocks with server time, and document permitted buffer/offline behavior. A long-lived download cannot be recalled by a server timer. Confirm local cleanup separately from server revocation.

## Host responsibilities

- TLS; secure provider cookies; session fixation/CSRF protection on the provider's login; appropriate session lifetime.
- Rate limiting for pairing, code inspection, authentication and polling. The reference host supplies persistent per-IP limits. The standalone package requires host-level rate limiting.
- Same-origin deployment. The SDK rejects foreign Origin and cross-site Fetch Metadata. Native clients must send the configured Origin; Origin is not authentication.
- No-store on credential responses (SDK supplies it), safe CSP, private logs omitting tokens/cookies/query codes, body size/timeouts, secrets management and dependency updates.
- Real entitlement checks, revocation consistency, retention, backups and operational alerts. Errors from identity/entitlement checks must deny access.
- One-time exchange replay fails closed. Lost exchange responses cannot retrieve the same credential: start a new pairing and revoke any orphaned session through the phone UI.

No hardware attestation, proof-of-possession token binding, centrally signed federation assertions, standardized discovery, or existing Netflix/Disney+/Google session adapter is claimed. The host chooses trusted device enrollment if required.

## Pilot acceptance

Run tests against the provider's actual session system and PostgreSQL deployment. Verify account switching, stale auth, code phishing/mismatch, duplicate approval, exchange replay, concurrent revoke/playback, expiry while watching, TV suspend/resume, network outage, logout, no impact on home devices, retention and accessibility. Conduct independent security review and physical phone/TV tests. The reference checks are a starting suite, not a partner certification.

## HTTP error mapping

The host must map Zod validation failures to HTTP 400 `{ "error": "invalid_request" }`, and SDK errors carrying a 4xx `statusCode` to `{ "error": error.message }` with that status. Other failures return HTTP 500 `{ "error": "internal_error" }` without exposing stack traces or provider payloads. Fastify's default error JSON has a different shape; do not rely on it for this contract. The reference host's `services/api/app.ts` contains the working mapper. Install an equivalent handler in the provider's isolated route scope before exposing the SDK routes.
