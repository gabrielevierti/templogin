# tempLogin provider-owned protocol — rc.3

This is a custom same-origin JSON API for a provider-controlled deployment, inspired by the device handoff pattern in RFC 8628. It is not a general OAuth authorization server. No tempLogin user registration is involved. The old wallet protocol is archived separately.

Base path: `/api/temporary`. Send JSON bodies, HTTPS and exact configured `Origin` on every POST (including native device clients). Provider browser-session cookies authenticate phone actions. Bearer tokens authenticate protected TV requests. Origin is a CSRF control, not identity. All responses are no-store.

## Pair and authorize

POST `/pairings` with `{"device_name":"TV in room 12"}` returns:

```json
{
  "device_code": "<private 43-character random secret>",
  "user_code": "ABCDE-FG234",
  "verification_uri": "https://provider.example/approve",
  "verification_uri_complete": "https://provider.example/approve?code=ABCDE-FG234",
  "expires_in": 300,
  "interval": 3
}
```

The public code is ten random characters from an unambiguous alphabet, separated after five characters. The QR never contains the device secret. Provider and origin are server configuration, not request parameters. Device name is unverified and must be escaped when displayed.

GET `/context?code=ABCDE-FG234` requires the provider's verified recent identity. Returns account display name, provider, device label, code, current status, expiry, maximum duration and `device_verified:false`. Without identity, `401 provider_login_required`. The host sends the phone through its own login and safely returns to the same pending code.

POST `/decision` with:

```json
{"code":"ABCDE-FG234","matching_code":"ABCDE-FG234","approve":true,"duration_seconds":3600}
```

Requires provider authentication and current entitlement. Unexpected fields, invalid code, duration beyond policy or mismatched code are rejected. The UI requires deliberate confirmation that the displayed codes match. A session subject is never accepted in this body. The server transaction locks the pairing and permits one decision only. Approval returns `status`, `session_id` and `expires_at`. Denial returns `{"status":"denied"}` and creates no session.

## Exchange

POST `/token` with `{"device_code":"<secret>"}` returns a single-use exchange result:

```json
{"access_token":"<private opaque credential>","token_type":"Bearer","expires_at":1700003600000,"session_id":"<opaque id>"}
```

`expires_at` is **Unix milliseconds**. Pairing `expires_in` and polling `interval` are **seconds**. The access credential is valid only for this provider session and absolute deadline; requests also require live server validation. There is no refresh token or automatic extension in rc.3. Start a new explicitly approved pairing for additional time.

Polling errors use HTTP 400 with `{ "error": "..." }`: `authorization_pending`, `slow_down`, `access_denied`, `expired_token`, `invalid_grant`. Increase polling interval by at least five seconds after `slow_down`. The server records backoff and caps its required interval at 30 seconds; clients may wait longer. Stop on final errors. A consumed code cannot mint another credential; a lost successful response requires a new pairing.

## Protected use and termination

Provider routes call `requireSession(request)` for a Bearer credential before issuing resources. The guard verifies provider namespace, hash, expiry, revocation and account entitlement; it rechecks live state after the asynchronous entitlement lookup. Returned session fields include provider subject and absolute deadline for server-side use only. Do not expose the subject in a public token or QR.

POST `/logout` with `{}` and the device Bearer token revokes that session. Phone GET `/sessions` returns only that authenticated provider subject's unexpired sessions. Phone POST `/sessions/{id}/revoke` with `{}` revokes a matching session; another subject receives 404. Repeated valid phone revocation is idempotent. Device logout after expiry/revocation returns 401.

Revocation means subsequent successful authorization checks are denied. Already delivered content or an operation already authorized cannot be recalled. The host must enforce expiry/revocation in its streaming pipeline and clear local device data separately.

## Reference-host endpoints

GET `/mode` declares whether a real adapter is configured or fictional demo identity is active. POST `/demo-login` is only available with the development fictional provider and establishes a short-lived HttpOnly cookie for a distinct demo browser identity. It is not a credential verifier and must never be used as real authentication. GET `/content` is a real protected reference resource, not commercial media.

GET `/config` advertises configured provider name/ID, maximum duration and `account_required:false` (meaning **no tempLogin account**; provider authentication is still required).

## Storage and cleanup

Store only SHA-256 hashes of random device/access secrets. Transactions enforce one decision and one exchange. Delete expired pairing/session rows according to your retention policy. No scheduler is required to enforce expiration. Restore procedures must invalidate recovered session credentials to avoid resurrecting revoked sessions.

Error handling must omit stack traces and upstream credentials. Application-level rate limits are required; the reference host provides them. Every API mutation requires exact Origin; cross-site browser POSTs are rejected. Never use wildcard CORS to make a partner integration work.
