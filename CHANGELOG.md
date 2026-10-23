# Changelog

## 1.0.0-rc.3 — English partner experience

- Redesign the overview, TV, phone consent, sessions and failure states.
- Add an in-app developer guide, evaluation walkthrough and pilot acceptance matrix.
- Use English throughout current UI, provider demo, terminal output and documentation.
- Add a clearly labelled 15-second demo duration for quick expiry verification.
- Remove the superseded wallet UI and multilingual historical onboarding from the release.
- Refresh open-source publication and targeted outreach instructions.


## 1.0.0-rc.2 — provider-owned temporary login

- Replace the default passkey wallet UI with TV/phone authorization using provider identity.
- Add a standalone provider SDK, SQL-backed single-use exchange, live entitlement/session guard and scoped revocation.
- Add a clearly labelled fictional provider for evaluation; disable it in production and when a real adapter is supplied.
- Disable legacy account APIs by default, retain historical sources and tests behind explicit programmatic opt-in.
- Add integration guide, current HTTP specification, partner brief and outreach drafts.
- Add no-account browser tests and adversarial provider/API tests.

Breaking change: the default `/tv` and `/approve` flows use `/api/temporary`, not the legacy wallet API. The old `sdk-js` targets the archived API; use `provider-sdk` for new integrations. Old session tables are not migrated into provider subjects; authentication must be supplied by the provider.

## 1.0.0-rc.1

Earlier passkey wallet reference, OAuth account-linking primitives, hospitality demo and development phone tunnel. Legacy protocol specifications and API regression tests are retained separately.
