# Provider pilot: ownership and acceptance

The first pilot should cover one provider, one TV client and a non-production environment. The provider retains authentication, subscription policy and content controls. tempLogin is an embedded session module; no centralized tempLogin identity is required.

## Integration ownership

| Owner | Required work | Evidence of completion |
|---|---|---|
| Identity team | Verify existing login; return immutable subject and recent authentication time; implement safe return navigation | Real sign-in/account switching works; missing/stale/invalid identity cannot approve |
| Backend team | Install provider SDK; supply transactional SQL store; apply schema; enforce resource guard and entitlement checks | All protected entry points reject expired/revoked/foreign sessions |
| TV team | Add QR/polling; apply backoff; hold dedicated credential; show duration; handle wake, errors, decline and logout | No password entry on TV; no expired session or profile restored after restart |
| Media/DRM team | Bind manifests, signed URLs, media licences, buffers and long-running playback to the same deadline | Documented and tested cutoff behavior, including content already buffered |
| Security team | Review identity boundary, tokens, Origin, rate limits, code phishing, device trust and logs | Findings resolved or explicitly accepted before real-user rollout |
| Operations team | Deploy HTTPS/PostgreSQL; configure secrets, proxy trust, retention, monitoring and recovery | Backup/restore invalidates old sessions; outage behavior fails closed |
| Product/accessibility team | Review consent wording, timing, device labels and assistive/remote navigation | Physical-device evaluation and accessibility acceptance documented |

## Mandatory acceptance cases

- The phone uses the provider's real login; it never creates a tempLogin user.
- One explicit consent issues at most one session credential, even during races and retries.
- Account eligibility and service policies are applied, not bypassed.
- The original deadline cannot slide through refresh, licence renewal or TV sleep/resume.
- Revoking one temporary TV session preserves the user's other sessions.
- Expiry works without a scheduled cleanup job; player behavior matches the agreed media cutoff.
- Unreachable identity, entitlement or session state cannot grant new access.
- Stolen bearer-token risk is reviewed; add device enrollment/proof-of-possession if your threat model requires it.
- Local cleanup is tested separately from server revocation. Do not report erased data without evidence.
- Device, phone and desktop tests cover supported browsers, TV operating systems, network changes and clock skew.

## Deliverables before rollout

Record the actual adapter, deployment configuration, migration ownership, test report, failure/recovery behavior, media/offline guarantees, operational support and security review. The reference is not a substitute for those provider-specific decisions.

## Out of scope for this candidate

Existing Netflix/YouTube/Disney+ adapters, private APIs, hardware attestation, cross-provider federation, native TV certification, a universal login token or an externally operated account vault. Additional adapters can be developed with authorized provider participation.
