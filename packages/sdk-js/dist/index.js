// packages/sdk-js/index.ts
var TempLoginError = class extends Error {
  constructor(code, status, retryAfter) {
    super(code);
    this.code = code;
    this.status = status;
    this.retryAfter = retryAfter;
    this.name = "TempLoginError";
  }
  code;
  status;
  retryAfter;
};
function wait(milliseconds, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const abort = () => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, milliseconds);
    signal?.addEventListener("abort", abort, { once: true });
  });
}
var TempLoginDevice = class {
  constructor(origin, clientId, transport = fetch) {
    this.clientId = clientId;
    this.transport = transport;
    const u = new URL(origin);
    if (u.origin !== origin || u.username || u.password || u.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)) throw new Error("Use an HTTPS origin (HTTP localhost is allowed for development)");
    this.origin = origin;
  }
  clientId;
  transport;
  tokens;
  accessExpiresAt = 0;
  refreshPromise;
  pairingDeadline = 0;
  currentPairing;
  generation = 0;
  polling = false;
  origin;
  async request(path, body, access, signal) {
    const response = await this.transport(this.origin + "/api" + path, {
      method: body === void 0 ? "GET" : "POST",
      credentials: "omit",
      redirect: "error",
      cache: "no-store",
      headers: { ...body === void 0 ? {} : { "Content-Type": "application/json" }, ...access ? { Authorization: "Bearer " + access } : {} },
      body: body === void 0 ? void 0 : JSON.stringify(body),
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(15e3)]) : AbortSignal.timeout(15e3)
    });
    const payload = await response.json();
    if (!response.ok) throw new TempLoginError(typeof payload?.error === "string" ? payload.error : "request_failed", response.status, Number(response.headers.get("Retry-After")) || void 0);
    return payload;
  }
  async begin(deviceName, scopes, registered, signal) {
    if (this.tokens || this.refreshPromise) throw new TempLoginError("logout_required", 409);
    if (this.currentPairing || this.polling) throw new TempLoginError("pairing_already_started", 409);
    const pairing = await this.request("/pairings", { client_id: this.clientId, device_name: deviceName, scopes, ...registered ? { device_id: registered.id, device_secret: registered.secret } : {} }, void 0, signal);
    this.currentPairing = pairing;
    this.pairingDeadline = Date.now() + pairing.expires_in * 1e3;
    return pairing;
  }
  /** Display only verification_uri_complete as QR; never display device_code. */
  async waitForApproval(pairing, signal) {
    if (pairing !== this.currentPairing || this.polling) throw new TempLoginError("unknown_pairing", 400);
    this.polling = true;
    try {
      let interval = pairing.interval * 1e3;
      while (Date.now() < this.pairingDeadline) {
        if (this.currentPairing !== pairing) throw new TempLoginError("operation_cancelled", 400);
        await wait(Math.min(interval, this.pairingDeadline - Date.now()), signal);
        if (Date.now() >= this.pairingDeadline) break;
        try {
          const result = await this.request("/token", { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: pairing.device_code, client_id: this.clientId }, void 0, signal);
          if (this.currentPairing !== pairing) throw new TempLoginError("operation_cancelled", 400);
          this.currentPairing = void 0;
          return this.accept(result);
        } catch (error) {
          if (!(error instanceof TempLoginError)) throw error;
          if (error.code === "authorization_pending") continue;
          if (error.code === "slow_down") {
            interval += 5e3;
            continue;
          }
          if (error.status === 429) {
            interval = Math.max(interval, (error.retryAfter || 60) * 1e3);
            continue;
          }
          this.currentPairing = void 0;
          throw error;
        }
      }
      this.currentPairing = void 0;
      throw new TempLoginError("expired_token", 400);
    } finally {
      if (this.currentPairing === pairing) this.currentPairing = void 0;
      this.polling = false;
    }
  }
  accept(result) {
    this.tokens = result;
    this.accessExpiresAt = Date.now() + result.expires_in * 1e3;
    return result;
  }
  /** Concurrent callers share one refresh. An uncertain network outcome discards local tokens. */
  async refresh(signal) {
    if (this.refreshPromise) return this.refreshPromise;
    const previous = this.tokens, generation = this.generation;
    if (!previous) throw new TempLoginError("not_authorized", 401);
    if (previous.grant_expires_at <= Date.now()) {
      this.clear();
      throw new TempLoginError("expired_token", 401);
    }
    this.tokens = void 0;
    this.refreshPromise = this.request("/token", { grant_type: "refresh_token", refresh_token: previous.refresh_token, client_id: this.clientId }, void 0, signal).then((result) => {
      if (generation !== this.generation) throw new TempLoginError("operation_cancelled", 400);
      return this.accept(result);
    }).finally(() => {
      this.refreshPromise = void 0;
    });
    return this.refreshPromise;
  }
  async resource(signal) {
    if (this.refreshPromise) await this.refreshPromise;
    if (!this.tokens) throw new TempLoginError("not_authorized", 401);
    if (Date.now() >= this.accessExpiresAt - 5e3) await this.refresh(signal);
    try {
      return await this.request("/resource", void 0, this.tokens.access_token, signal);
    } catch (error) {
      if (error instanceof TempLoginError && error.status === 401) this.clear();
      throw error;
    }
  }
  async logout(signal) {
    try {
      if (this.refreshPromise) await this.refreshPromise;
      if (!this.tokens) return;
      if (Date.now() >= this.accessExpiresAt - 5e3) await this.refresh(signal);
      await this.request("/device/logout", {}, this.tokens.access_token, signal);
    } finally {
      this.clear();
    }
  }
  /** For local reset only. Does not assert server revocation; prefer logout(). */
  clear() {
    this.generation++;
    this.tokens = void 0;
    this.currentPairing = void 0;
    this.accessExpiresAt = 0;
  }
};
export {
  TempLoginDevice,
  TempLoginError
};
