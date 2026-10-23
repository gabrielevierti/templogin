# @templogin/provider-sdk

Provider-owned temporary TV sessions with no tempLogin user registration. Exports a Fastify installer, SQL schema, provider identity/entitlement callbacks and a live session guard. Node 24+, Fastify 5, PostgreSQL-compatible transactions.

Build from the repository root with `npm run build`; install the tarball from `npm pack ./packages/provider-sdk`. Not yet published to npm. See the repository's `docs/INTEGRATION.md` and `specs/protocol.md` for the full host contract. The package is an evaluation candidate, not an independently audited identity service.
