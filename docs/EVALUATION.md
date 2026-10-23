# Partner evaluation walkthrough

**Goal:** decide whether a provider-owned, time-limited session is worth piloting in your TV application. Begin with [QUICKSTART.md](QUICKSTART.md); no commercial-provider credentials are required.

## Demo boundary

Screen Demo is fictional. Its sign-in button simulates a provider authentication result. Pairing, consent, token exchange, persistence, protected-resource authorization, expiry and revocation run against the real reference implementation. The demo does not demonstrate a real subscription, video stream, native TV platform or DRM integration.

## Manual checks

| Check | What to do | Expected outcome |
|---|---|---|
| Successful handoff | Create a QR, open the phone flow, match the code and approve one hour | TV displays “You’re connected” with an absolute-deadline countdown |
| Fast expiry | Select “15 seconds · quick expiry test” during consent | TV closes the session without a manual sign-out; server rejects further access |
| Early revocation | Authorize a normal session, then open Manage sessions and revoke it | Subsequent authorization fails; the reference TV closes after its next check |
| Declined consent | Start again and select Decline request | No usable TV session is issued; the TV shows “Access declined” |
| Explicit confirmation | Try to approve with the match checkbox unchecked | The form asks you to confirm the code before submitting |
| Two screens | Approve two TV tabs using the same phone provider session; revoke only one | The other session remains active |
| Expired pairing | Leave a new code unapproved for more than five minutes | The code can no longer authorize or exchange |
| Page reload | Reload an authorized TV tab | Its in-memory token is lost; a fresh pairing is required |
| Lost connectivity | Take the TV offline while connected | The reference stops showing protected access when it cannot validate it |
| Small screen | Repeat on a phone or narrow browser | Consent, code and primary actions remain readable without horizontal scrolling |

The sample phone identity is an ephemeral demo-browser session, not a recoverable real account. For lasting account management, integrate the provider's stable identity and reauthentication flow.

## Engineering verification

```sh
npm run check
npx playwright install chromium
npm run test:e2e
```

`check` runs TypeScript validation, lint, API/SQL tests and builds. Browser tests exercise TV and phone contexts without a WebAuthn authenticator. See [VALIDATION.md](VALIDATION.md) for the recorded execution results and limits.

The SDK test suite covers additional cases that are awkward to reproduce manually: concurrent approvals/exchanges, reuse, provider/account isolation, duration/code validation, missing identity, entitlement rejection and production demo blocking. Passing these checks does not establish compatibility with a commercial service.

## What to record

Record environment, release version, browser/device, observed steps and any failure. Report product questions separately from security findings. Do not attach QR device secrets, tokens, cookies, personal accounts or database dumps. Use the repository's private security reporting route once configured.

## Decision after evaluation

If the flow meets your needs, select one TV client and a non-production provider environment. Assign identity, backend, TV/media and security owners. Use [PILOT-CHECKLIST.md](PILOT-CHECKLIST.md) to agree the integration and acceptance criteria before enabling real accounts.
