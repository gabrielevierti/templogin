// packages/connector-sdk/index.ts
import * as oauth from "oauth4webapi";

// packages/connector-sdk/session-policy.ts
var timestamp = (n) => Number.isSafeInteger(n) && n >= 0;
function sessionDeadline(input) {
  const { now, durationSeconds, maxDurationSeconds, stayEndsAt } = input;
  if (!timestamp(now) || !Number.isSafeInteger(durationSeconds) || durationSeconds < 1 || !Number.isSafeInteger(maxDurationSeconds) || maxDurationSeconds < 1 || durationSeconds > maxDurationSeconds || stayEndsAt !== void 0 && !timestamp(stayEndsAt)) throw new Error("invalid_session_policy");
  const end = Math.min(now + durationSeconds * 1e3, stayEndsAt ?? Number.MAX_SAFE_INTEGER);
  if (!timestamp(end) || end <= now) throw new Error("invalid_session_policy");
  return end;
}
function assertTemporarySession(session, expected, now) {
  if (!timestamp(now) || !session || !session.id || !session.subject || !expected.providerId || !expected.deviceId || !expected.scope || session.providerId !== expected.providerId || session.deviceId !== expected.deviceId || !timestamp(session.expiresAt) || session.expiresAt <= now || session.revokedAt !== null || !Array.isArray(session.scopes) || !session.scopes.includes(expected.scope)) throw new Error("invalid_session");
}
function credentialDeadline(now, sessionExpiresAt, lifetimeSeconds) {
  if (!timestamp(now) || !timestamp(sessionExpiresAt) || sessionExpiresAt <= now || !Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < 1) throw new Error("invalid_session_policy");
  const end = Math.min(now + lifetimeSeconds * 1e3, sessionExpiresAt);
  if (!timestamp(end)) throw new Error("invalid_session_policy");
  return end;
}

// packages/connector-sdk/index.ts
import { createCipheriv, createDecipheriv, randomBytes, createHash, timingSafeEqual } from "node:crypto";
var unsupportedCapabilities = Object.freeze({ accountLinking: false, providerAuthorization: false, deviceAuthorization: false, sessionProvisioning: false, sessionRevocation: false, tokenRevocation: false });
var UnavailableSessionConnector = class {
  constructor(id) {
    this.id = id;
  }
  id;
  capabilities() {
    return unsupportedCapabilities;
  }
  async provisionSession(_input) {
    throw new Error("session_provisioning_unavailable");
  }
  async revokeSession(_sessionId) {
    return { status: "revocation_unavailable" };
  }
};
var sha = (s) => createHash("sha256").update(s).digest("hex");
var equal = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
function safeHttps(value) {
  const u = new URL(value);
  if (u.protocol !== "https:" || u.username || u.password || u.hash) throw new Error("https_required");
  return u;
}
var OAuthAccountConnector = class _OAuthAccountConnector {
  constructor(config, server, store, transport) {
    this.config = config;
    this.server = server;
    this.store = store;
    this.transport = transport;
  }
  config;
  server;
  store;
  transport;
  client() {
    return { client_id: this.config.clientId };
  }
  authentication() {
    return this.config.clientSecret ? oauth.ClientSecretPost(this.config.clientSecret) : oauth.None();
  }
  options() {
    return { [oauth.customFetch]: this.transport, signal: () => AbortSignal.timeout(15e3) };
  }
  static async discover(config, store, transport = fetch) {
    const issuer = safeHttps(config.issuer), redirect = safeHttps(config.redirectUri);
    if (issuer.search || redirect.hash || !config.clientId || !config.id || !config.scopes.length) throw new Error("invalid_provider_config");
    if (config.oidc && !config.scopes.includes("openid")) throw new Error("openid_scope_required");
    const origins = /* @__PURE__ */ new Set([issuer.origin, ...config.allowedEndpointOrigins || []]);
    for (const origin of origins) if (safeHttps(origin).origin !== origin) throw new Error("invalid_endpoint_origin");
    const boundedFetch = async (input, init) => {
      const value = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const url = safeHttps(value);
      if (!origins.has(url.origin)) throw new Error("endpoint_not_allowed");
      return transport(value, { ...init, redirect: "manual", signal: init?.signal || AbortSignal.timeout(15e3) });
    };
    const response = await oauth.discoveryRequest(issuer, { algorithm: config.oidc ? "oidc" : "oauth2", [oauth.customFetch]: boundedFetch, signal: AbortSignal.timeout(15e3) });
    const metadata = await oauth.processDiscoveryResponse(issuer, response);
    if (!metadata.authorization_endpoint || !metadata.token_endpoint) throw new Error("provider_endpoints_missing");
    for (const endpoint of [metadata.authorization_endpoint, metadata.token_endpoint, metadata.jwks_uri, metadata.revocation_endpoint]) {
      if (endpoint && !origins.has(safeHttps(endpoint).origin)) throw new Error("endpoint_not_allowed");
    }
    if (metadata.code_challenge_methods_supported && !metadata.code_challenge_methods_supported.includes("S256")) throw new Error("pkce_s256_required");
    if (config.oidc && !metadata.jwks_uri) throw new Error("jwks_uri_required");
    return new _OAuthAccountConnector({ ...config, scopes: [...config.scopes] }, metadata, store, boundedFetch);
  }
  capabilities() {
    return { ...unsupportedCapabilities, accountLinking: true, providerAuthorization: true, tokenRevocation: !!this.server.revocation_endpoint };
  }
  async begin(userId, browserBinding, scopes = this.config.scopes) {
    if (!userId || browserBinding.length < 32 || !scopes.length || new Set(scopes).size !== scopes.length || scopes.some((s) => !this.config.scopes.includes(s))) throw new Error("invalid_authorization");
    if (this.config.oidc && !scopes.includes("openid")) throw new Error("openid_scope_required");
    const state = oauth.generateRandomState(), verifier = oauth.generateRandomCodeVerifier(), nonce = this.config.oidc ? oauth.generateRandomNonce() : void 0;
    await this.store.put({ stateHash: sha(state), userId, browserBindingHash: sha(browserBinding), verifier, nonce, scopes: [...scopes], expiresAt: Date.now() + 3e5 });
    const url = new URL(this.server.authorization_endpoint);
    url.searchParams.set("client_id", this.config.clientId);
    url.searchParams.set("redirect_uri", this.config.redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", scopes.join(" "));
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", await oauth.calculatePKCECodeChallenge(verifier));
    url.searchParams.set("code_challenge_method", "S256");
    if (nonce) url.searchParams.set("nonce", nonce);
    return { authorizationUrl: url.href, expiresIn: 300 };
  }
  async complete(callbackUrl, userId, browserBinding) {
    const callback = new URL(callbackUrl), expected = new URL(this.config.redirectUri);
    if (callback.origin !== expected.origin || callback.pathname !== expected.pathname || callback.hash) throw new Error("invalid_callback");
    const state = callback.searchParams.get("state");
    if (!state || callback.searchParams.getAll("state").length !== 1) throw new Error("invalid_state");
    const pending = await this.store.consume(sha(state));
    if (!pending || pending.expiresAt <= Date.now() || pending.userId !== userId || !equal(pending.browserBindingHash, sha(browserBinding))) throw new Error("invalid_state");
    const params = oauth.validateAuthResponse(this.server, this.client(), callback, state);
    const response = await oauth.authorizationCodeGrantRequest(this.server, this.client(), this.authentication(), params, this.config.redirectUri, pending.verifier, this.options());
    const tokens = await oauth.processAuthorizationCodeResponse(this.server, this.client(), response, { expectedNonce: pending.nonce, requireIdToken: this.config.oidc });
    if (tokens.id_token) await oauth.validateApplicationLevelSignature(this.server, response, this.options());
    if (tokens.scope && tokens.scope.split(" ").some((s) => !pending.scopes.includes(s))) throw new Error("unexpected_provider_scope");
    const identity = oauth.getValidatedIdTokenClaims(tokens);
    return { tokens, identity: identity ? { issuer: identity.iss, subject: identity.sub } : void 0, scopes: tokens.scope?.split(" ") || pending.scopes };
  }
  async refresh(refreshToken) {
    const response = await oauth.refreshTokenGrantRequest(this.server, this.client(), this.authentication(), refreshToken, this.options());
    const result = await oauth.processRefreshTokenResponse(this.server, this.client(), response);
    if (result.id_token) await oauth.validateApplicationLevelSignature(this.server, response, this.options());
    if (result.scope && result.scope.split(" ").some((s) => !this.config.scopes.includes(s))) throw new Error("unexpected_provider_scope");
    return result;
  }
  async revokeToken(value) {
    if (!this.server.revocation_endpoint) return { status: "revocation_unavailable", guarantee: "provider_token_only" };
    const response = await oauth.revocationRequest(this.server, this.client(), this.authentication(), value, this.options());
    await oauth.processRevocationResponse(response);
    return { status: "revocation_requested", guarantee: "provider_token_only" };
  }
};
var TokenVault = class {
  constructor(activeKeyId, keys) {
    this.activeKeyId = activeKeyId;
    this.keys = new Map(Object.entries(keys).map(([name, key]) => {
      if (!/^[a-zA-Z0-9_-]{1,80}$/.test(name) || key.byteLength !== 32) throw new Error("invalid_encryption_key");
      return [name, Buffer.from(key)];
    }));
    if (!this.keys.has(activeKeyId)) throw new Error("missing_active_key");
  }
  activeKeyId;
  keys;
  encrypt(value, context) {
    if (!context || value.length > 65536) throw new Error("invalid_token_payload");
    const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", this.keys.get(this.activeKeyId), iv);
    cipher.setAAD(Buffer.from("tempLogin:token:v1:" + this.activeKeyId + ":" + context));
    const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
    return { version: 1, kid: this.activeKeyId, iv: iv.toString("base64url"), ciphertext: ciphertext.toString("base64url"), tag: cipher.getAuthTag().toString("base64url") };
  }
  decrypt(envelope, context) {
    const key = this.keys.get(envelope.kid);
    if (!context || envelope.version !== 1 || !key || envelope.ciphertext.length > 9e4) throw new Error("invalid_token_envelope");
    const iv = Buffer.from(envelope.iv, "base64url"), tag = Buffer.from(envelope.tag, "base64url");
    if (iv.length !== 12 || tag.length !== 16) throw new Error("invalid_token_envelope");
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(Buffer.from("tempLogin:token:v1:" + envelope.kid + ":" + context));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64url")), decipher.final()]).toString("utf8");
  }
  rotate(envelope, context) {
    return this.encrypt(this.decrypt(envelope, context), context);
  }
};
var UnavailableStayProviderAdapter = class {
  constructor(id = "airbnb") {
    this.id = id;
  }
  id;
  capabilities() {
    return { stayImport: false, checkoutEvents: false };
  }
  async listStays(_propertyExternalId, _since) {
    throw new Error("authorized_stay_integration_unavailable");
  }
};
export {
  OAuthAccountConnector,
  TokenVault,
  UnavailableSessionConnector,
  UnavailableStayProviderAdapter,
  assertTemporarySession,
  credentialDeadline,
  sessionDeadline,
  unsupportedCapabilities
};
