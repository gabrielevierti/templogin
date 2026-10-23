# tempLogin

### Sign in for a while. Not for good.

**Temporary access for shared TVs, using the provider account you already have.**

Scan a QR. Authorize a duration on your phone. The provider issues one dedicated TV session and enforces its expiry. Your other devices stay signed in. No tempLogin account, extra phone app or password entry on the TV.

**Apache-2.0 · TypeScript · Node 24 · 1.0.0-rc.3**

[Start here](docs/QUICKSTART.md) · [Test the demo](docs/EVALUATION.md) · [Integrate your app](docs/INTEGRATION.md) · [Partner brief](docs/PARTNER-BRIEF.md) · [API contract](specs/openapi.json)

## Try the reference

From this repository, with Node.js 24 or later:

```sh
npm ci
npm run dev
```

Open **http://localhost:3000**. Choose **Live demo → Connect with tempLogin**, then scan the QR or open its phone-flow link in another tab. Continue with the fictional Screen Demo account, match the code and authorize access.

**Choose “15 seconds · quick expiry test” to verify automatic sign-out in a short test.** For early revocation, approve a longer session and select **Manage sessions → Revoke access** on the phone.

The built-in **Developer guide** explains setup, expected results, integration points and pilot requirements. There is no need to create an account or supply API keys to evaluate the demo.

### Testing on an iPhone or Android phone

On macOS, install the optional tunnel once, then start the isolated phone demo:

```sh
brew install cloudflared
npm run dev:phone
```

Open the **public HTTPS TV link printed in the terminal on your computer**, then scan that QR. An old localhost QR cannot connect a phone to your computer. The tunnel is temporary, publicly reachable while running and uses a separate in-memory database. Ctrl+C closes it. [Detailed setup and troubleshooting →](docs/QUICKSTART.md)

## What is real in the demo?

| Component | Reference behavior |
|---|---|
| Provider sign-in | Clearly labelled fictional account; no streaming service is contacted |
| QR and consent | Real handoff, code confirmation and duration selection |
| Authorization | SQL-backed single-use decision and credential exchange |
| Session use | Live server guard checks deadline, revocation and entitlement |
| Session termination | Server enforcement plus reference TV reset |
| Commercial playback | Not included; provider app, media and DRM integration is required |

The fictional login is disabled in production and when a real adapter is supplied. No Netflix, Google, YouTube or Disney+ integration or partnership is claimed.

## Integrate with your service

The intended first deployment runs **inside the provider's infrastructure**. Keep your existing identity system; embed the session module.

| Integration point | Your application supplies |
|---|---|
| Identity | `identity(request)` verifies the provider's existing browser session |
| Account eligibility | `entitled(subject)` applies subscription and service policies |
| Resource access | `requireSession(request)` guards protected backend operations |
| TV and media | QR/polling, local cleanup and the same deadline on playback URLs/licences |

Build the standalone server package:

```sh
npm run build
npm pack ./packages/provider-sdk
```

Install the generated tarball in your backend. It targets Fastify 5 and PostgreSQL-compatible transactions. Packages are not yet published to npm. [Integration guide with the exact host contract and wiring example →](docs/INTEGRATION.md)

## Verification and boundaries

```sh
npm run check
npx playwright install chromium
npm run test:e2e
```

The reference includes high-entropy hashed secrets, transactional single-use exchange, exact-Origin checks, host rate limits and live session revocation. The TV holds its token in memory and cannot extend the original deadline. Device labels are unverified; access tokens are bearer credentials, not hardware-bound proofs.

A backend check alone cannot stop a previously issued DRM licence or erase delivered data. The provider must apply the same deadline to its player, media pipeline and local cleanup. This is an **engineering evaluation release**, not an independently audited or certified production integration. [Validation record](docs/VALIDATION.md) · [Threat model](docs/THREAT-MODEL.md) · [Pilot checklist](docs/PILOT-CHECKLIST.md)

## Find your next step

| Goal | Document |
|---|---|
| Run it without prior knowledge | [Quick start](docs/QUICKSTART.md) |
| Know exactly what to test | [Evaluation walkthrough](docs/EVALUATION.md) |
| Connect the service backend and TV | [Integration guide](docs/INTEGRATION.md) |
| Understand HTTP semantics | [Protocol](specs/protocol.md) and [OpenAPI](specs/openapi.json) |
| Deploy and operate a real adapter | [Deployment](docs/deployment.md) |

## Source map

- `apps/web/temporary.ts` — English landing, developer guide, TV and phone UI.
- `packages/provider-sdk` — active provider-owned session API and guard.
- `services/api/temporary.ts` — reference adapter and development-only fictional identity.
- `tests/temporary.test.ts` — adversarial provider/API checks.
- `tests/e2e/temporary.spec.ts` — browser handoff, expiry, revocation and layout checks.

The older account-based APIs remain disabled by default for regression compatibility; only explicit programmatic `Config.legacyWallet=true` enables them. The old `sdk-js` and legacy specifications target that earlier API. **Use `provider-sdk` for new integrations.** Superseded wallet UI and onboarding documents are not included in this release.

## Open source

Licensed under [Apache-2.0](LICENSE). Read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) before reporting issues. No remote repository, package release or outreach message is created automatically by the project.
