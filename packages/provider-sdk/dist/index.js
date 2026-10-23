// packages/provider-sdk/index.ts
import { createHash, randomBytes, randomInt, randomUUID } from "node:crypto";
import { z } from "zod";
var schemaSQL = `
CREATE TABLE IF NOT EXISTS tl_pairings (
 id TEXT PRIMARY KEY, provider TEXT NOT NULL, secret_hash TEXT UNIQUE NOT NULL,
 code TEXT UNIQUE NOT NULL, device_name TEXT NOT NULL, expires_at BIGINT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','denied','consumed')),
 last_poll BIGINT NOT NULL DEFAULT 0, interval_ms INTEGER NOT NULL DEFAULT 3000,
 session_id TEXT
);
CREATE TABLE IF NOT EXISTS tl_provider_sessions (
 id TEXT PRIMARY KEY, provider TEXT NOT NULL, subject TEXT NOT NULL,
 device_name TEXT NOT NULL, token_hash TEXT UNIQUE, expires_at BIGINT NOT NULL,
 revoked_at BIGINT, created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS tl_sessions_subject ON tl_provider_sessions(provider,subject);
CREATE INDEX IF NOT EXISTS tl_pairings_expiry ON tl_pairings(expires_at);
CREATE INDEX IF NOT EXISTS tl_sessions_expiry ON tl_provider_sessions(expires_at);
`;
var digest = (s) => createHash("sha256").update(s).digest("hex");
var secret = () => randomBytes(32).toString("base64url");
function fail(statusCode, message) {
  throw Object.assign(new Error(message), { statusCode });
}
var codeSchema = z.string().regex(/^[A-Z2-9]{5}-[A-Z2-9]{5}$/);
var tokenSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
async function registerTemporaryLogin(app, db, provider) {
  const origin = new URL(provider.origin);
  if (origin.origin !== provider.origin || origin.username || !provider.id || !provider.name || origin.protocol !== "https:" && !(origin.protocol === "http:" && ["localhost", "127.0.0.1"].includes(origin.hostname)) || !Number.isSafeInteger(provider.maxDurationSeconds) || provider.maxDurationSeconds < 60 || provider.maxDurationSeconds > 86400) throw new Error("invalid_provider_configuration");
  await db.exec(schemaSQL);
  const prefix = "/api/temporary";
  app.addHook("onRequest", async (req, reply) => {
    if (!req.url.startsWith(prefix + "/")) return;
    reply.header("Cache-Control", "no-store").header("Pragma", "no-cache");
    if (req.headers.origin && req.headers.origin !== provider.origin) fail(403, "origin_not_allowed");
    if (req.method !== "GET") {
      if (req.headers.origin !== provider.origin || req.headers["sec-fetch-site"] === "cross-site") fail(403, "origin_required");
    }
  });
  async function identity(req) {
    const who = await provider.identity(req);
    if (!who?.subject || !who.displayName || !Number.isSafeInteger(who.authenticatedAt) || who.authenticatedAt > Date.now() || who.authenticatedAt < Date.now() - 9e5) fail(401, "provider_login_required");
    return who;
  }
  const pair = async (store, code, lock = false) => {
    const p = (await store.query(`SELECT * FROM tl_pairings WHERE code=$1 AND provider=$2${lock ? " FOR UPDATE" : ""}`, [code, provider.id])).rows[0];
    if (!p || Number(p.expires_at) <= Date.now()) fail(410, "pairing_expired");
    return p;
  };
  const requireSession = async (req) => {
    const bearer = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization || "");
    if (!bearer) fail(401, "invalid_token");
    const s = (await db.query("SELECT * FROM tl_provider_sessions WHERE token_hash=$1 AND provider=$2", [digest(bearer[1]), provider.id])).rows[0];
    if (!s || s.revoked_at !== null || Number(s.expires_at) <= Date.now()) fail(401, "session_ended");
    if (!await provider.entitled(s.subject)) fail(403, "account_unavailable");
    const live = (await db.query("SELECT id FROM tl_provider_sessions WHERE id=$1 AND revoked_at IS NULL AND expires_at>$2", [s.id, Date.now()])).rows[0];
    if (!live) fail(401, "session_ended");
    return s;
  };
  app.get(prefix + "/config", async () => ({ provider: { id: provider.id, name: provider.name }, max_duration_seconds: provider.maxDurationSeconds, account_required: false }));
  app.post(prefix + "/pairings", async (req) => {
    const body = z.object({ device_name: z.string().trim().min(1).max(80) }).strict().parse(req.body);
    const device = secret(), alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const chars = Array.from({ length: 10 }, () => alphabet[randomInt(alphabet.length)]).join(""), code = chars.slice(0, 5) + "-" + chars.slice(5);
    await db.query("INSERT INTO tl_pairings(id,provider,secret_hash,code,device_name,expires_at) VALUES($1,$2,$3,$4,$5,$6)", [randomUUID(), provider.id, digest(device), code, body.device_name, Date.now() + 3e5]);
    return { device_code: device, user_code: code, verification_uri: provider.origin + "/approve", verification_uri_complete: provider.origin + "/approve?code=" + code, expires_in: 300, interval: 3 };
  });
  app.get(prefix + "/context", async (req) => {
    const who = await identity(req), q = z.object({ code: codeSchema }).strict().parse(req.query), p = await pair(db, q.code);
    return { provider: provider.name, account: who.displayName, device_name: p.device_name, user_code: p.code, status: p.status, expires_at: Number(p.expires_at), max_duration_seconds: provider.maxDurationSeconds, device_verified: false };
  });
  app.post(prefix + "/decision", async (req) => {
    const who = await identity(req);
    const b = z.object({ code: codeSchema, matching_code: codeSchema, approve: z.boolean(), duration_seconds: z.number().int().min(1).max(provider.maxDurationSeconds) }).strict().parse(req.body);
    if (b.code !== b.matching_code) fail(400, "code_mismatch");
    if (b.approve && !await provider.entitled(who.subject)) fail(403, "account_unavailable");
    return db.transaction(async (tx) => {
      const p = await pair(tx, b.code, true);
      if (p.status !== "pending") fail(409, "pairing_already_decided");
      if (!b.approve) {
        await tx.query("UPDATE tl_pairings SET status='denied' WHERE id=$1", [p.id]);
        return { status: "denied" };
      }
      const id = randomUUID(), now = Date.now(), end = now + b.duration_seconds * 1e3;
      await tx.query("INSERT INTO tl_provider_sessions(id,provider,subject,device_name,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6)", [id, provider.id, who.subject, p.device_name, end, now]);
      await tx.query("UPDATE tl_pairings SET status='approved',session_id=$1 WHERE id=$2", [id, p.id]);
      return { status: "approved", session_id: id, expires_at: end };
    });
  });
  app.post(prefix + "/token", async (req, reply) => {
    const b = z.object({ device_code: tokenSchema }).strict().parse(req.body);
    const result = await db.transaction(async (tx) => {
      const p = (await tx.query("SELECT * FROM tl_pairings WHERE secret_hash=$1 AND provider=$2 FOR UPDATE", [digest(b.device_code), provider.id])).rows[0];
      if (!p || Number(p.expires_at) <= Date.now()) return { error: "expired_token" };
      if (p.status === "consumed") return { error: "invalid_grant" };
      const now = Date.now();
      if (Number(p.last_poll) + p.interval_ms > now) {
        await tx.query("UPDATE tl_pairings SET last_poll=$1,interval_ms=LEAST(interval_ms+5000,30000) WHERE id=$2", [now, p.id]);
        return { error: "slow_down" };
      }
      await tx.query("UPDATE tl_pairings SET last_poll=$1 WHERE id=$2", [now, p.id]);
      if (p.status === "denied") return { error: "access_denied" };
      if (p.status === "pending") return { error: "authorization_pending" };
      const access = secret();
      const s = (await tx.query("UPDATE tl_provider_sessions SET token_hash=$1 WHERE id=$2 AND provider=$3 AND revoked_at IS NULL AND expires_at>$4 RETURNING *", [digest(access), p.session_id, provider.id, now])).rows[0];
      if (!s) return { error: "invalid_grant" };
      await tx.query("UPDATE tl_pairings SET status='consumed' WHERE id=$1", [p.id]);
      return { access_token: access, token_type: "Bearer", expires_at: Number(s.expires_at), session_id: s.id };
    });
    return "error" in result ? reply.code(400).send(result) : result;
  });
  app.get(prefix + "/sessions", async (req) => {
    const who = await identity(req);
    return (await db.query("SELECT id,device_name,expires_at,revoked_at FROM tl_provider_sessions WHERE provider=$1 AND subject=$2 AND expires_at>$3 ORDER BY created_at DESC", [provider.id, who.subject, Date.now()])).rows.map((s) => ({ id: s.id, device_name: s.device_name, expires_at: Number(s.expires_at), revoked: s.revoked_at !== null }));
  });
  app.post(prefix + "/sessions/:id/revoke", async (req) => {
    const who = await identity(req);
    z.object({}).strict().parse(req.body);
    const result = await db.query("UPDATE tl_provider_sessions SET revoked_at=COALESCE(revoked_at,$1) WHERE id=$2 AND provider=$3 AND subject=$4 RETURNING id", [Date.now(), req.params.id, provider.id, who.subject]);
    if (!result.rowCount) fail(404, "session_not_found");
    return { status: "revoked" };
  });
  app.post(prefix + "/logout", async (req) => {
    z.object({}).strict().parse(req.body);
    const s = await requireSession(req);
    await db.query("UPDATE tl_provider_sessions SET revoked_at=COALESCE(revoked_at,$1) WHERE id=$2", [Date.now(), s.id]);
    return { status: "revoked" };
  });
  return { requireSession };
}
export {
  registerTemporaryLogin,
  schemaSQL
};
