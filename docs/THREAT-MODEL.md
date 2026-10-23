# Threat model — provider-owned temporary sessions

## Trust boundaries

The provider owns authentication, account status, playback and deployment. The phone authorizes one pairing. A shared TV is potentially untrusted. tempLogin's SDK accepts only a host-verified identity and creates a dedicated session with a fixed deadline. A public QR code is not proof of who controls the TV.

| Threat | Implemented control | Remaining boundary |
|---|---|---|
| Login/subject spoofing | Subject comes only from provider identity callback, never request JSON | Partner must correctly validate its own cookie/OIDC session |
| QR phishing or device-name spoofing | Explicit code confirmation, escaped unverified label, short pairing TTL | Users can still approve an attacker's QR; no hardware attestation |
| Code guessing / polling abuse | Random public code, secret polling token, persistent host rate limits and backoff | Production rate limits need capacity and distributed abuse review |
| CSRF | Exact Origin and Fetch Metadata checks on mutations; provider cookie policy | Partner login/logout CSRF and return URLs remain host responsibilities |
| Replay / concurrent approvals | SQL row locks and single consumption | Lost successful response requires a new pairing |
| Cross-provider / cross-account access | Server-configured provider namespace; subject-scoped phone revocation | Separate providers need isolated secrets/configuration and trusted storage |
| Stolen TV bearer | Random opaque token stored hashed, limited lifetime, live revocation | No proof-of-possession: theft allows replay until expiry/revocation |
| Expiry evasion | Server deadline checked for every guarded resource, no refresh extension | Host must guard every endpoint, including media URLs/licences/streams |
| Offline cached content | Reference UI drops credentials on loss of validation; no persistent token storage | Already delivered data cannot be remotely erased |
| Provider outage | Identity/entitlement errors fail closed | Service availability and recovery are deployment responsibilities |
| Demo login in production | Production or real adapter disables demo endpoint | Never modify this gate or deploy development mode with real resources |
| Restored old database | Documented invalidation procedure | Operations must apply it after restore |

Private request logs must omit cookie, Authorization and query strings. Do not log credential-bearing response bodies. The reference host redacts incoming secrets and uses parameterized SQL. A compromised provider/backend or fully compromised phone/TV is outside the protocol's protection.

The reference is not independently penetration-tested or certified. No guarantee of exact physical playback interruption follows from an HTTP authorization check alone.
