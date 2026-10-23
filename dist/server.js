// services/api/app.ts
import Fastify from "fastify";
import { timingSafeEqual as timingSafeEqual2 } from "node:crypto";
import cookie from "@fastify/cookie";
import helmet from "@fastify/helmet";
import staticPlugin from "@fastify/static";
import { resolve } from "node:path";
import { existsSync } from "node:fs";
import { ZodError } from "zod";

// services/api/database.ts
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { Pool } from "pg";
import { PGlite } from "@electric-sql/pglite";
async function createDatabase(config2) {
  let db;
  if (config2.databaseUrl) {
    const pool = new Pool({ connectionString: config2.databaseUrl, max: 10, connectionTimeoutMillis: 1e4 });
    const connection = (client) => ({
      async query(sql, params = []) {
        const result = await client.query(sql, params);
        return { rows: result.rows, rowCount: result.rowCount ?? result.rows.length };
      },
      async exec(sql) {
        await client.query(sql);
      },
      async transaction(fn) {
        if (client !== pool) throw new Error("Nested transactions are not supported");
        const leased = await pool.connect();
        try {
          await leased.query("BEGIN");
          const result = await fn(connection(leased));
          await leased.query("COMMIT");
          return result;
        } catch (error) {
          await leased.query("ROLLBACK");
          throw error;
        } finally {
          leased.release();
        }
      },
      async close() {
        if (client === pool) await pool.end();
      }
    });
    db = connection(pool);
  } else {
    if (config2.production) throw new Error("Production requires DATABASE_URL for PostgreSQL");
    const engine = new PGlite(config2.dataDir);
    await engine.waitReady;
    let queue = Promise.resolve();
    const lock = (fn) => {
      const next = queue.then(fn, fn);
      queue = next.catch(() => void 0);
      return next;
    };
    const direct = {
      async query(sql, params = []) {
        const result = await engine.query(sql, params);
        return { rows: result.rows, rowCount: Math.max(result.affectedRows ?? 0, result.rows.length) };
      },
      async exec(sql) {
        await engine.exec(sql);
      },
      async transaction() {
        throw new Error("Nested transactions are not supported");
      },
      async close() {
        await engine.close();
      }
    };
    db = {
      query: (sql, params = []) => lock(() => direct.query(sql, params)),
      exec: (sql) => lock(() => direct.exec(sql)),
      close: () => lock(() => direct.close()),
      transaction: (fn) => lock(async () => {
        await direct.exec("BEGIN");
        try {
          const result = await fn(direct);
          await direct.exec("COMMIT");
          return result;
        } catch (error) {
          await direct.exec("ROLLBACK");
          throw error;
        }
      })
    };
  }
  try {
    await db.transaction(async (tx) => {
      if (config2.databaseUrl) await tx.query("SELECT pg_advisory_xact_lock(734866021)");
      await tx.exec("CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at BIGINT NOT NULL)");
      for (const name2 of ["auth-schema.sql", "core-schema.sql", "oauth-schema.sql"]) {
        const sql = await readFile(new URL(name2, import.meta.url), "utf8");
        const checksum = createHash("sha256").update(sql).digest("hex");
        const existing = await tx.query("SELECT checksum FROM schema_migrations WHERE name=$1", [name2]);
        if (existing.rows[0]) {
          if (existing.rows[0].checksum !== checksum) throw new Error(`Migration checksum mismatch: ${name2}; create a new versioned migration`);
          continue;
        }
        await tx.exec(sql);
        await tx.query("INSERT INTO schema_migrations(name,checksum,applied_at) VALUES ($1,$2,$3)", [name2, checksum, Date.now()]);
      }
    });
    return db;
  } catch (error) {
    await db.close();
    throw error;
  }
}

// services/api/auth.ts
import { createHash as createHash2, randomBytes, randomUUID } from "node:crypto";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from "@simplewebauthn/server";
import { z } from "zod";
var hash = (value) => createHash2("sha256").update(value).digest("hex");
var fail = (code, statusCode = 400) => {
  throw Object.assign(new Error(code), { statusCode });
};
var validID = z.string().min(1).max(2048);
var sessionLife = 7 * 24 * 60 * 60 * 1e3;
var recentLife = 5 * 60 * 1e3;
async function requireUser(db, req) {
  const token2 = req.cookies.tl_session;
  if (!token2 || token2.length > 128) return fail("unauthorized", 401);
  const result = await db.query(
    `SELECT u.id,u.name,s.id AS session_id,s.authenticated_at FROM user_sessions s
     JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>$2`,
    [hash(token2), Date.now()]
  );
  const user = result.rows[0];
  if (!user) return fail("unauthorized", 401);
  return { id: user.id, name: user.name, sessionId: user.session_id, authenticatedAt: Number(user.authenticated_at) };
}
async function requireRecentUser(db, req) {
  const user = await requireUser(db, req);
  if (Date.now() - user.authenticatedAt > recentLife) return fail("reauthentication_required", 403);
  return user;
}
async function registerAuth(app2, db, config2) {
  const cookie2 = { httpOnly: true, secure: config2.production || config2.origin.startsWith("https:"), sameSite: "strict", path: "/" };
  const clearChallenge = (reply) => reply.clearCookie("tl_challenge", cookie2);
  const clearSession = (reply) => reply.clearCookie("tl_session", cookie2);
  async function recordAudit(tx, userId, action, targetId = null) {
    await tx.query("INSERT INTO audit_events(id,user_id,action,target_id,created_at) VALUES ($1,$2,$3,$4,$5)", [randomUUID(), userId, action, targetId, Date.now()]);
  }
  async function challenge(req, reply, kind, value, userId, name2, sessionId) {
    const binding = randomBytes(32).toString("base64url");
    await db.transaction(async (tx) => {
      if (req.cookies.tl_challenge) await tx.query("DELETE FROM auth_challenges WHERE binding_hash=$1", [hash(req.cookies.tl_challenge)]);
      await tx.query("DELETE FROM auth_challenges WHERE expires_at<=$1", [Date.now()]);
      await tx.query(`INSERT INTO auth_challenges(id,binding_hash,challenge,kind,user_id,user_name,session_id,expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, [randomUUID(), hash(binding), value, kind, userId ?? null, name2 ?? null, sessionId ?? null, Date.now() + 3e5]);
    });
    reply.setCookie("tl_challenge", binding, { ...cookie2, maxAge: 300 });
  }
  async function consume(req, reply, kind) {
    const binding = req.cookies.tl_challenge;
    clearChallenge(reply);
    if (!binding || binding.length > 128) return fail("invalid_challenge");
    const result = await db.query("DELETE FROM auth_challenges WHERE binding_hash=$1 RETURNING *", [hash(binding)]);
    const row = result.rows[0];
    if (!row || row.kind !== kind || Number(row.expires_at) <= Date.now()) return fail("invalid_challenge");
    return row;
  }
  async function createSession(tx, req, userId) {
    if (req.cookies.tl_session) await tx.query("DELETE FROM user_sessions WHERE token_hash=$1", [hash(req.cookies.tl_session)]);
    const token2 = randomBytes(32).toString("base64url");
    const now = Date.now();
    await tx.query("INSERT INTO user_sessions(id,user_id,token_hash,created_at,expires_at,authenticated_at) VALUES ($1,$2,$3,$4,$5,$4)", [randomUUID(), userId, hash(token2), now, now + sessionLife]);
    return token2;
  }
  function sendSession(reply, token2) {
    reply.setCookie("tl_session", token2, { ...cookie2, maxAge: sessionLife / 1e3 });
  }
  async function registrationOptions(req, reply, adding) {
    const user = adding ? await requireRecentUser(db, req) : void 0;
    if (!adding && req.cookies.tl_session) {
      try {
        await requireUser(db, req);
        return fail("already_authenticated", 409);
      } catch (error) {
        if (error.statusCode !== 401) throw error;
      }
    }
    const name2 = user?.name ?? z.object({ name: z.string().trim().min(1).max(80) }).parse(req.body).name;
    const userId = user?.id ?? randomUUID();
    const existing = adding ? await db.query("SELECT * FROM passkeys WHERE user_id=$1", [userId]) : { rows: [] };
    if (existing.rows.length >= 20) return fail("passkey_limit", 409);
    const options = await generateRegistrationOptions({
      rpName: "tempLogin",
      rpID: config2.rpID,
      userName: name2,
      userDisplayName: name2,
      userID: new TextEncoder().encode(userId),
      attestationType: "none",
      timeout: 3e5,
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      supportedAlgorithmIDs: [-7, -257],
      excludeCredentials: existing.rows.map((key) => ({ id: key.id, transports: key.transports }))
    });
    await challenge(req, reply, adding ? "add" : "register", options.challenge, userId, name2, user?.sessionId);
    return options;
  }
  async function registrationVerify(req, reply, adding) {
    const current = adding ? await requireRecentUser(db, req) : void 0;
    const pending = await consume(req, reply, adding ? "add" : "register");
    if (adding && (pending.user_id !== current?.id || pending.session_id !== current.sessionId)) return fail("invalid_challenge");
    const body = z.object({ response: z.object({ id: validID }).passthrough() }).parse(req.body);
    let verified;
    try {
      verified = await verifyRegistrationResponse({
        response: body.response,
        expectedChallenge: pending.challenge,
        expectedOrigin: config2.origin,
        expectedRPID: config2.rpID,
        requireUserVerification: true,
        requireUserPresence: true,
        supportedAlgorithmIDs: [-7, -257]
      });
    } catch {
      return fail("invalid_passkey");
    }
    if (!verified.verified || !verified.registrationInfo) return fail("invalid_passkey");
    const info = verified.registrationInfo;
    const token2 = await db.transaction(async (tx) => {
      if (adding) {
        const locked = await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [pending.user_id]);
        if (!locked.rows.length) return fail("unauthorized", 401);
        const live = await requireRecentUser(tx, req);
        if (live.sessionId !== pending.session_id || live.id !== pending.user_id) return fail("unauthorized", 401);
        const count = await tx.query("SELECT count(*)::text AS count FROM passkeys WHERE user_id=$1", [pending.user_id]);
        if (Number(count.rows[0].count) >= 20) return fail("passkey_limit", 409);
      } else {
        await tx.query("INSERT INTO users(id,name,created_at) VALUES ($1,$2,$3)", [pending.user_id, pending.user_name, Date.now()]);
      }
      const exists = await tx.query("SELECT id FROM passkeys WHERE id=$1", [info.credential.id]);
      if (exists.rows.length) return fail("passkey_already_registered", 409);
      await tx.query(`INSERT INTO passkeys(id,user_id,public_key,counter,transports,device_type,backed_up,name,created_at)
        VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)`, [
        info.credential.id,
        pending.user_id,
        Buffer.from(info.credential.publicKey).toString("base64url"),
        info.credential.counter,
        JSON.stringify(info.credential.transports ?? []),
        info.credentialDeviceType,
        info.credentialBackedUp,
        "Passkey",
        Date.now()
      ]);
      await recordAudit(tx, pending.user_id, adding ? "passkey.added" : "account.created", info.credential.id);
      return adding ? null : createSession(tx, req, pending.user_id);
    });
    if (token2) sendSession(reply, token2);
    return { verified: true, id: pending.user_id };
  }
  app2.post("/api/auth/register/options", (req, reply) => registrationOptions(req, reply, false));
  app2.post("/api/auth/register/verify", (req, reply) => registrationVerify(req, reply, false));
  app2.post("/api/auth/passkeys/options", (req, reply) => registrationOptions(req, reply, true));
  app2.post("/api/auth/passkeys/verify", (req, reply) => registrationVerify(req, reply, true));
  app2.post("/api/auth/login/options", async (req, reply) => {
    const options = await generateAuthenticationOptions({ rpID: config2.rpID, userVerification: "required", timeout: 3e5 });
    await challenge(req, reply, "login", options.challenge);
    return options;
  });
  app2.post("/api/auth/login/verify", async (req, reply) => {
    const pending = await consume(req, reply, "login");
    const body = z.object({ response: z.object({ id: validID }).passthrough() }).parse(req.body);
    const response = body.response;
    const token2 = await db.transaction(async (tx) => {
      const candidate = (await tx.query("SELECT * FROM passkeys WHERE id=$1", [response.id])).rows[0];
      if (!candidate) return fail("invalid_passkey");
      await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [candidate.user_id]);
      const keys = await tx.query("SELECT * FROM passkeys WHERE id=$1 FOR UPDATE", [response.id]);
      const key = keys.rows[0];
      if (!key) return fail("invalid_passkey");
      if (response.response?.userHandle !== Buffer.from(key.user_id).toString("base64url")) return fail("invalid_passkey");
      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response,
          expectedChallenge: pending.challenge,
          expectedOrigin: config2.origin,
          expectedRPID: config2.rpID,
          requireUserVerification: true,
          credential: { id: key.id, publicKey: new Uint8Array(Buffer.from(key.public_key, "base64url")), counter: Number(key.counter), transports: key.transports }
        });
      } catch {
        return fail("invalid_passkey");
      }
      if (!verification.verified) return fail("invalid_passkey");
      const info = verification.authenticationInfo;
      await tx.query("UPDATE passkeys SET counter=$1,backed_up=$2,device_type=$3 WHERE id=$4", [info.newCounter, info.credentialBackedUp, info.credentialDeviceType, key.id]);
      await recordAudit(tx, key.user_id, "auth.login", key.id);
      return createSession(tx, req, key.user_id);
    });
    sendSession(reply, token2);
    return { verified: true };
  });
  app2.get("/api/me", async (req) => {
    const user = await requireUser(db, req);
    return { id: user.id, name: user.name };
  });
  app2.get("/api/passkeys", async (req) => {
    const user = await requireUser(db, req);
    const keys = await db.query("SELECT id,name,created_at,device_type,backed_up FROM passkeys WHERE user_id=$1 ORDER BY created_at", [user.id]);
    return keys.rows.map((key) => ({ ...key, created_at: Number(key.created_at) }));
  });
  app2.delete("/api/passkeys/:id", async (req) => {
    const user = await requireRecentUser(db, req);
    const id2 = validID.parse(req.params.id);
    return db.transaction(async (tx) => {
      await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [user.id]);
      await requireRecentUser(tx, req);
      const keys = await tx.query("SELECT id FROM passkeys WHERE user_id=$1", [user.id]);
      if (!keys.rows.some((key) => key.id === id2)) return fail("not_found", 404);
      if (keys.rows.length <= 1) return fail("last_passkey", 409);
      await tx.query("DELETE FROM passkeys WHERE id=$1 AND user_id=$2", [id2, user.id]);
      await tx.query("DELETE FROM user_sessions WHERE user_id=$1 AND id<>$2", [user.id, user.sessionId]);
      await recordAudit(tx, user.id, "passkey.removed", id2);
      return { ok: true };
    });
  });
  app2.get("/api/sessions", async (req) => {
    const user = await requireUser(db, req);
    const sessions = await db.query("SELECT id,created_at,expires_at FROM user_sessions WHERE user_id=$1 AND expires_at>$2 ORDER BY created_at DESC", [user.id, Date.now()]);
    return sessions.rows.map((session) => ({ ...session, created_at: Number(session.created_at), expires_at: Number(session.expires_at), current: session.id === user.sessionId }));
  });
  app2.delete("/api/sessions/:id", async (req, reply) => {
    const user = await requireUser(db, req);
    const id2 = z.string().uuid().parse(req.params.id);
    const result = await db.query("DELETE FROM user_sessions WHERE id=$1 AND user_id=$2 RETURNING id", [id2, user.id]);
    if (!result.rows.length) return fail("not_found", 404);
    await recordAudit(db, user.id, "session.revoked", id2);
    if (id2 === user.sessionId) clearSession(reply);
    return { ok: true };
  });
  app2.post("/api/auth/logout", async (req, reply) => {
    if (req.cookies.tl_session) await db.query("DELETE FROM user_sessions WHERE token_hash=$1", [hash(req.cookies.tl_session)]);
    if (req.cookies.tl_challenge) await db.query("DELETE FROM auth_challenges WHERE binding_hash=$1", [hash(req.cookies.tl_challenge)]);
    clearChallenge(reply);
    clearSession(reply);
    return { ok: true };
  });
  app2.post("/api/auth/logout-all", async (req, reply) => {
    const user = await requireUser(db, req);
    await db.transaction(async (tx) => {
      await tx.query("DELETE FROM user_sessions WHERE user_id=$1", [user.id]);
      await tx.query("DELETE FROM auth_challenges WHERE user_id=$1", [user.id]);
      await recordAudit(tx, user.id, "sessions.revoked_all");
    });
    clearSession(reply);
    clearChallenge(reply);
    return { ok: true };
  });
  app2.get("/api/account/export", async (req, reply) => {
    const user = await requireRecentUser(db, req);
    reply.header("Content-Disposition", 'attachment; filename="templogin-account.json"');
    return db.transaction(async (tx) => {
      const profile = (await tx.query("SELECT id,name,created_at FROM users WHERE id=$1", [user.id])).rows[0];
      const passkeys = (await tx.query("SELECT id,name,created_at,device_type,backed_up FROM passkeys WHERE user_id=$1", [user.id])).rows;
      const sessions = (await tx.query("SELECT id,created_at,expires_at FROM user_sessions WHERE user_id=$1", [user.id])).rows;
      const grants = (await tx.query("SELECT * FROM grants WHERE user_id=$1", [user.id])).rows;
      const audit2 = (await tx.query("SELECT * FROM audit_events WHERE user_id=$1", [user.id])).rows;
      const connections = (await tx.query("SELECT id,provider_id,subject,scopes,status,created_at,updated_at FROM oauth_connections WHERE user_id=$1", [user.id])).rows;
      return { exported_at: (/* @__PURE__ */ new Date()).toISOString(), profile, passkeys, sessions, grants, audit: audit2, connections };
    });
  });
  app2.delete("/api/account", async (req, reply) => {
    const user = await requireRecentUser(db, req);
    await db.transaction(async (tx) => {
      await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [user.id]);
      await requireRecentUser(tx, req);
      const owned = await tx.query(
        `SELECT o.id FROM organizations o JOIN organization_members m ON m.organization_id=o.id
         WHERE m.user_id=$1 AND m.role='owner' FOR UPDATE OF o`,
        [user.id]
      );
      for (const organization of owned.rows) {
        const others = await tx.query("SELECT user_id FROM organization_members WHERE organization_id=$1 AND user_id<>$2", [organization.id, user.id]);
        if (others.rows.length) return fail("organization_transfer_required", 409);
        await tx.query("DELETE FROM organizations WHERE id=$1", [organization.id]);
      }
      await tx.query("DELETE FROM auth_challenges WHERE user_id=$1", [user.id]);
      await tx.query("DELETE FROM users WHERE id=$1", [user.id]);
    });
    clearSession(reply);
    clearChallenge(reply);
    return { ok: true };
  });
}

// services/api/core.ts
import { randomInt } from "node:crypto";
import { z as z2 } from "zod";

// services/api/security.ts
import { createHash as createHash3, randomBytes as randomBytes2, randomUUID as randomUUID2 } from "node:crypto";
var token = () => randomBytes2(32).toString("base64url");
var hash2 = (value) => createHash3("sha256").update(value).digest("hex");
var id = () => randomUUID2();
function fail2(statusCode, message) {
  throw Object.assign(new Error(message), { statusCode });
}
async function audit(db, userId, action, target = null, org = null) {
  await db.query("INSERT INTO audit_events(id,user_id,organization_id,action,target_id,created_at) VALUES($1,$2,$3,$4,$5,$6)", [id(), userId, org, action, target, Date.now()]);
}

// packages/connector-sdk/session-policy.ts
var timestamp = (n) => Number.isSafeInteger(n) && n >= 0;
function sessionDeadline(input) {
  const { now, durationSeconds, maxDurationSeconds, stayEndsAt } = input;
  if (!timestamp(now) || !Number.isSafeInteger(durationSeconds) || durationSeconds < 1 || !Number.isSafeInteger(maxDurationSeconds) || maxDurationSeconds < 1 || durationSeconds > maxDurationSeconds || stayEndsAt !== void 0 && !timestamp(stayEndsAt)) throw new Error("invalid_session_policy");
  const end = Math.min(now + durationSeconds * 1e3, stayEndsAt ?? Number.MAX_SAFE_INTEGER);
  if (!timestamp(end) || end <= now) throw new Error("invalid_session_policy");
  return end;
}
function credentialDeadline(now, sessionExpiresAt, lifetimeSeconds) {
  if (!timestamp(now) || !timestamp(sessionExpiresAt) || sessionExpiresAt <= now || !Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < 1) throw new Error("invalid_session_policy");
  const end = Math.min(now + lifetimeSeconds * 1e3, sessionExpiresAt);
  if (!timestamp(end)) throw new Error("invalid_session_policy");
  return end;
}

// services/api/core.ts
var clients = { "demo-tv": ["content:read", "profile:read"], "demo-car": ["preferences:read", "profile:read"] };
var clientSchema = z2.enum(["demo-tv", "demo-car"]);
var scopesSchema = z2.array(z2.enum(["content:read", "preferences:read", "profile:read"])).min(1).max(3).refine((s) => new Set(s).size === s.length);
var codeSchema = z2.string().regex(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
var userCode = () => {
  const a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const s = Array.from({ length: 8 }, () => a[randomInt(a.length)]).join("");
  return s.slice(0, 4) + "-" + s.slice(4);
};
var maxDuration = 86400;
var grantStatus = (g) => g.revoked_at ? "revoked" : Number(g.expires_at) <= Date.now() ? "expired" : "active";
async function stayValid(db, stayId, lock = false) {
  if (!stayId) return null;
  const s = (await db.query(`SELECT ends_at,starts_at,checked_out_at FROM stays WHERE id=$1${lock ? " FOR UPDATE" : ""}`, [stayId])).rows[0];
  if (!s || s.checked_out_at || Number(s.ends_at) <= Date.now() || Number(s.starts_at) > Date.now()) fail2(400, "stay_inactive");
  return Number(s.ends_at);
}
async function issue(tx, g) {
  const now = Date.now();
  if (Number(g.expires_at) <= now) fail2(400, "invalid_grant");
  const expires = credentialDeadline(now, Number(g.expires_at), 60), access = token(), refresh = token();
  await tx.query("INSERT INTO access_tokens(token_hash,grant_id,expires_at) VALUES($1,$2,$3)", [hash2(access), g.id, expires]);
  await tx.query("INSERT INTO refresh_tokens(token_hash,grant_id,expires_at,created_at) VALUES($1,$2,$3,$4)", [hash2(refresh), g.id, g.expires_at, now]);
  return { access_token: access, refresh_token: refresh, token_type: "Bearer", expires_in: Math.max(0, Math.floor((expires - now) / 1e3)), grant_id: g.id, grant_expires_at: Number(g.expires_at), scope: g.scopes.join(" ") };
}
async function bearerGrant(db, req) {
  const m = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization || "");
  if (!m) fail2(401, "invalid_token");
  const row = (await db.query("SELECT g.*,t.expires_at AS token_expiry FROM access_tokens t JOIN grants g ON g.id=t.grant_id WHERE t.token_hash=$1", [hash2(m[1])])).rows[0];
  if (!row || grantStatus(row) !== "active" || Number(row.token_expiry) <= Date.now()) fail2(401, "invalid_token");
  try {
    await stayValid(db, row.stay_id);
  } catch {
    fail2(401, "invalid_token");
  }
  return row;
}
async function registerCore(app2, db, config2) {
  app2.post("/api/pairings", async (req) => {
    const b = z2.object({ client_id: clientSchema, device_name: z2.string().trim().min(1).max(80), scopes: scopesSchema, device_id: z2.string().uuid().optional(), device_secret: z2.string().min(32).max(100).optional() }).strict().parse(req.body);
    if (b.scopes.some((s) => !clients[b.client_id].includes(s))) fail2(400, "invalid_scope");
    if (Boolean(b.device_id) !== Boolean(b.device_secret)) fail2(400, "invalid_device");
    return db.transaction(async (tx) => {
      let name2 = b.device_name, stayId = null;
      if (b.device_id) {
        const device = (await tx.query("SELECT * FROM devices WHERE id=$1 FOR UPDATE", [b.device_id])).rows[0];
        if (!device || device.secret_hash !== hash2(b.device_secret) || device.client_id !== b.client_id) fail2(401, "invalid_device");
        name2 = device.name;
        await tx.query("SELECT id FROM properties WHERE id=$1 FOR UPDATE", [device.property_id]);
        const stay = (await tx.query("SELECT id FROM stays WHERE property_id=$1 AND checked_out_at IS NULL AND starts_at<=$2 AND ends_at>$2 ORDER BY starts_at DESC LIMIT 1", [device.property_id, Date.now()])).rows[0];
        if (!stay) fail2(400, "stay_inactive");
        stayId = stay.id;
      }
      const code = userCode(), secret2 = token(), now = Date.now();
      await tx.query("INSERT INTO pairings(id,device_code_hash,user_code,client_id,device_name,device_id,stay_id,scopes,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", [id(), hash2(secret2), code, b.client_id, name2, b.device_id || null, stayId, JSON.stringify(b.scopes), now, now + 3e5]);
      return { device_code: secret2, user_code: code, verification_uri: config2.origin + "/approve", verification_uri_complete: config2.origin + "/approve?code=" + code, expires_in: 300, interval: 3 };
    });
  });
  app2.get("/api/pairings/:code", async (req) => {
    await requireUser(db, req);
    const code = codeSchema.parse(req.params.code.toUpperCase());
    const p = (await db.query("SELECT * FROM pairings WHERE user_code=$1", [code])).rows[0];
    if (!p) fail2(404, "pairing_not_found");
    const end = await stayValid(db, p.stay_id);
    return { user_code: p.user_code, device_name: p.device_name, client_id: p.client_id, scopes: p.scopes, expires_at: Number(p.expires_at), status: Number(p.expires_at) <= Date.now() ? "expired" : p.status, identity: p.device_id ? "registered" : "unverified", max_duration_seconds: Math.max(0, Math.min(maxDuration, end ? Math.floor((end - Date.now()) / 1e3) : maxDuration)) };
  });
  app2.post("/api/pairings/:code/decision", async (req) => {
    const u = await requireUser(db, req), code = codeSchema.parse(req.params.code.toUpperCase());
    const b = z2.object({ approve: z2.boolean(), matching_code: z2.string(), scopes: z2.array(z2.string()).max(3), duration_seconds: z2.number().int().min(1).max(maxDuration) }).strict().parse(req.body);
    return db.transaction(async (tx) => {
      await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [u.id]);
      const before = (await tx.query("SELECT * FROM pairings WHERE user_code=$1", [code])).rows[0];
      if (before?.device_id) await tx.query("SELECT id FROM devices WHERE id=$1 FOR UPDATE", [before.device_id]);
      const p = (await tx.query("SELECT * FROM pairings WHERE user_code=$1 FOR UPDATE", [code])).rows[0];
      await requireUser(tx, req);
      if (!p) fail2(404, "pairing_not_found");
      if (Number(p.expires_at) <= Date.now()) fail2(400, "expired_token");
      if (p.status !== "pending") fail2(409, "pairing_already_decided");
      if (b.matching_code !== p.user_code) fail2(400, "code_mismatch");
      if (!b.approve) {
        await tx.query("UPDATE pairings SET status='denied' WHERE id=$1", [p.id]);
        await audit(tx, u.id, "pairing.denied", p.id);
        return { status: "denied" };
      }
      if (!b.scopes.length || new Set(b.scopes).size !== b.scopes.length || b.scopes.some((s) => !p.scopes.includes(s))) fail2(400, "invalid_scope");
      const end = await stayValid(tx, p.stay_id, true), now = Date.now();
      const expires = sessionDeadline({ now, durationSeconds: b.duration_seconds, maxDurationSeconds: maxDuration, stayEndsAt: end ?? void 0 });
      if (expires <= now) fail2(400, "stay_inactive");
      const grantId = id();
      await tx.query("INSERT INTO grants(id,user_id,device_id,stay_id,client_id,device_name,scopes,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", [grantId, u.id, p.device_id, p.stay_id, p.client_id, p.device_name, JSON.stringify(b.scopes), now, expires]);
      await tx.query("UPDATE pairings SET status='approved',grant_id=$1 WHERE id=$2", [grantId, p.id]);
      await audit(tx, u.id, "pairing.approved", grantId);
      return { status: "approved", grant_id: grantId, expires_at: expires };
    });
  });
  app2.post("/api/token", async (req, reply) => {
    const b = z2.discriminatedUnion("grant_type", [
      z2.object({ grant_type: z2.literal("urn:ietf:params:oauth:grant-type:device_code"), device_code: z2.string().length(43), client_id: clientSchema }).strict(),
      z2.object({ grant_type: z2.literal("refresh_token"), refresh_token: z2.string().length(43), client_id: clientSchema }).strict()
    ]).parse(req.body);
    const result = await db.transaction(async (tx) => {
      if (b.grant_type === "refresh_token") {
        const owner2 = (await tx.query("SELECT g.user_id FROM refresh_tokens t JOIN grants g ON g.id=t.grant_id WHERE t.token_hash=$1", [hash2(b.refresh_token)])).rows[0];
        if (!owner2) return { error: "invalid_grant" };
        await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [owner2.user_id]);
        const r = (await tx.query("SELECT * FROM refresh_tokens WHERE token_hash=$1 FOR UPDATE", [hash2(b.refresh_token)])).rows[0];
        if (!r) return { error: "invalid_grant" };
        const g2 = (await tx.query("SELECT * FROM grants WHERE id=$1 FOR UPDATE", [r.grant_id])).rows[0];
        if (!g2 || g2.client_id !== b.client_id) return { error: "invalid_grant" };
        if (r.used_at) {
          await tx.query("UPDATE grants SET revoked_at=COALESCE(revoked_at,$1),revoke_reason='refresh_reuse' WHERE id=$2", [Date.now(), g2.id]);
          await audit(tx, g2.user_id, "token.reuse_detected", g2.id);
          return { error: "invalid_grant" };
        }
        if (grantStatus(g2) !== "active" || Number(r.expires_at) <= Date.now()) return { error: "invalid_grant" };
        try {
          await stayValid(tx, g2.stay_id);
        } catch {
          return { error: "invalid_grant" };
        }
        await tx.query("UPDATE refresh_tokens SET used_at=$1 WHERE token_hash=$2", [Date.now(), hash2(b.refresh_token)]);
        return issue(tx, g2);
      }
      const owner = (await tx.query("SELECT g.user_id FROM pairings p JOIN grants g ON g.id=p.grant_id WHERE p.device_code_hash=$1", [hash2(b.device_code)])).rows[0];
      if (owner) await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [owner.user_id]);
      const p = (await tx.query("SELECT * FROM pairings WHERE device_code_hash=$1 FOR UPDATE", [hash2(b.device_code)])).rows[0];
      if (!p || p.client_id !== b.client_id) return { error: "invalid_grant" };
      if (Number(p.expires_at) <= Date.now()) return { error: "expired_token" };
      if (p.status === "consumed") return { error: "invalid_grant" };
      const now = Date.now();
      if (Number(p.last_poll_at) > 0 && now - Number(p.last_poll_at) < p.poll_interval) {
        await tx.query("UPDATE pairings SET poll_interval=LEAST(poll_interval+5000,60000),last_poll_at=$1 WHERE id=$2", [now, p.id]);
        return { error: "slow_down" };
      }
      await tx.query("UPDATE pairings SET last_poll_at=$1 WHERE id=$2", [now, p.id]);
      if (p.status === "denied") return { error: "access_denied" };
      if (p.status !== "approved" || !p.grant_id || !owner) return { error: "authorization_pending" };
      const g = (await tx.query("SELECT * FROM grants WHERE id=$1 FOR UPDATE", [p.grant_id])).rows[0];
      if (!g || grantStatus(g) !== "active") return { error: "invalid_grant" };
      try {
        await stayValid(tx, g.stay_id);
      } catch {
        return { error: "invalid_grant" };
      }
      await tx.query("UPDATE pairings SET status='consumed' WHERE id=$1", [p.id]);
      await audit(tx, g.user_id, "token.issued", g.id);
      return issue(tx, g);
    });
    if ("error" in result) return reply.code(400).send(result);
    return result;
  });
  app2.get("/api/resource", async (req) => {
    const g = await bearerGrant(db, req), needed = g.client_id === "demo-tv" ? "content:read" : "preferences:read";
    if (!g.scopes.includes(needed)) fail2(403, "insufficient_scope");
    const u = (await db.query("SELECT name FROM users WHERE id=$1", [g.user_id])).rows[0];
    return { kind: g.client_id === "demo-tv" ? "tv" : "car", profile: g.scopes.includes("profile:read") ? { name: u.name } : {}, message: g.client_id === "demo-tv" ? "tempLogin original demo content" : "Temporary driving profile", preferences: g.client_id === "demo-car" ? { theme: "night", temperature: 21 } : void 0, expires_at: Number(g.expires_at), scopes: g.scopes };
  });
  app2.post("/api/device/logout", async (req) => {
    const g = await bearerGrant(db, req);
    await db.transaction(async (tx) => {
      await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [g.user_id]);
      await tx.query("UPDATE grants SET revoked_at=COALESCE(revoked_at,$1),revoke_reason='device_logout' WHERE id=$2", [Date.now(), g.id]);
      await audit(tx, g.user_id, "grant.device_logout", g.id);
    });
    return { status: "revoked" };
  });
  app2.get("/api/grants", async (req) => {
    const u = await requireUser(db, req);
    const rows = (await db.query("SELECT * FROM grants WHERE user_id=$1 ORDER BY created_at DESC LIMIT 500", [u.id])).rows;
    return rows.map((g) => ({ id: g.id, device_name: g.device_name, device_id: g.device_id, client_id: g.client_id, scopes: g.scopes, created_at: Number(g.created_at), expires_at: Number(g.expires_at), status: grantStatus(g) }));
  });
  app2.delete("/api/grants/:id", async (req) => {
    const u = await requireUser(db, req);
    await db.transaction(async (tx) => {
      await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [u.id]);
      await requireUser(tx, req);
      const g = (await tx.query("SELECT * FROM grants WHERE id=$1 AND user_id=$2 FOR UPDATE", [req.params.id, u.id])).rows[0];
      if (!g) fail2(404, "not_found");
      await tx.query("UPDATE grants SET revoked_at=COALESCE(revoked_at,$1),revoke_reason='user' WHERE id=$2", [Date.now(), g.id]);
      await audit(tx, u.id, "grant.revoked", g.id);
    });
    return { status: "revoked" };
  });
  app2.post("/api/grants/revoke-all", async (req) => {
    const u = await requireUser(db, req);
    await db.transaction(async (tx) => {
      await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [u.id]);
      await requireUser(tx, req);
      await tx.query("UPDATE grants SET revoked_at=$1,revoke_reason='user_all' WHERE user_id=$2 AND revoked_at IS NULL", [Date.now(), u.id]);
      await audit(tx, u.id, "grants.revoked_all");
    });
    return { status: "revoked" };
  });
  app2.get("/api/audit", async (req) => {
    const u = await requireUser(db, req);
    return (await db.query("SELECT action,target_id,created_at FROM audit_events WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200", [u.id])).rows;
  });
}

// services/api/providers.ts
import { z as z3 } from "zod";
import * as oauth2 from "oauth4webapi";

// packages/connector-sdk/index.ts
import * as oauth from "oauth4webapi";
import { createCipheriv, createDecipheriv, randomBytes as randomBytes3, createHash as createHash4, timingSafeEqual } from "node:crypto";
var unsupportedCapabilities = Object.freeze({ accountLinking: false, providerAuthorization: false, deviceAuthorization: false, sessionProvisioning: false, sessionRevocation: false, tokenRevocation: false });
var sha = (s) => createHash4("sha256").update(s).digest("hex");
var equal = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
function safeHttps(value) {
  const u = new URL(value);
  if (u.protocol !== "https:" || u.username || u.password || u.hash) throw new Error("https_required");
  return u;
}
var OAuthAccountConnector = class _OAuthAccountConnector {
  constructor(config2, server, store, transport) {
    this.config = config2;
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
  static async discover(config2, store, transport = fetch) {
    const issuer = safeHttps(config2.issuer), redirect = safeHttps(config2.redirectUri);
    if (issuer.search || redirect.hash || !config2.clientId || !config2.id || !config2.scopes.length) throw new Error("invalid_provider_config");
    if (config2.oidc && !config2.scopes.includes("openid")) throw new Error("openid_scope_required");
    const origins = /* @__PURE__ */ new Set([issuer.origin, ...config2.allowedEndpointOrigins || []]);
    for (const origin of origins) if (safeHttps(origin).origin !== origin) throw new Error("invalid_endpoint_origin");
    const boundedFetch = async (input, init) => {
      const value = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const url = safeHttps(value);
      if (!origins.has(url.origin)) throw new Error("endpoint_not_allowed");
      return transport(value, { ...init, redirect: "manual", signal: init?.signal || AbortSignal.timeout(15e3) });
    };
    const response = await oauth.discoveryRequest(issuer, { algorithm: config2.oidc ? "oidc" : "oauth2", [oauth.customFetch]: boundedFetch, signal: AbortSignal.timeout(15e3) });
    const metadata = await oauth.processDiscoveryResponse(issuer, response);
    if (!metadata.authorization_endpoint || !metadata.token_endpoint) throw new Error("provider_endpoints_missing");
    for (const endpoint of [metadata.authorization_endpoint, metadata.token_endpoint, metadata.jwks_uri, metadata.revocation_endpoint]) {
      if (endpoint && !origins.has(safeHttps(endpoint).origin)) throw new Error("endpoint_not_allowed");
    }
    if (metadata.code_challenge_methods_supported && !metadata.code_challenge_methods_supported.includes("S256")) throw new Error("pkce_s256_required");
    if (config2.oidc && !metadata.jwks_uri) throw new Error("jwks_uri_required");
    return new _OAuthAccountConnector({ ...config2, scopes: [...config2.scopes] }, metadata, store, boundedFetch);
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
    this.keys = new Map(Object.entries(keys).map(([name2, key]) => {
      if (!/^[a-zA-Z0-9_-]{1,80}$/.test(name2) || key.byteLength !== 32) throw new Error("invalid_encryption_key");
      return [name2, Buffer.from(key)];
    }));
    if (!this.keys.has(activeKeyId)) throw new Error("missing_active_key");
  }
  activeKeyId;
  keys;
  encrypt(value, context2) {
    if (!context2 || value.length > 65536) throw new Error("invalid_token_payload");
    const iv = randomBytes3(12), cipher = createCipheriv("aes-256-gcm", this.keys.get(this.activeKeyId), iv);
    cipher.setAAD(Buffer.from("tempLogin:token:v1:" + this.activeKeyId + ":" + context2));
    const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
    return { version: 1, kid: this.activeKeyId, iv: iv.toString("base64url"), ciphertext: ciphertext.toString("base64url"), tag: cipher.getAuthTag().toString("base64url") };
  }
  decrypt(envelope, context2) {
    const key = this.keys.get(envelope.kid);
    if (!context2 || envelope.version !== 1 || !key || envelope.ciphertext.length > 9e4) throw new Error("invalid_token_envelope");
    const iv = Buffer.from(envelope.iv, "base64url"), tag = Buffer.from(envelope.tag, "base64url");
    if (iv.length !== 12 || tag.length !== 16) throw new Error("invalid_token_envelope");
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(Buffer.from("tempLogin:token:v1:" + envelope.kid + ":" + context2));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64url")), decipher.final()]).toString("utf8");
  }
  rotate(envelope, context2) {
    return this.encrypt(this.decrypt(envelope, context2), context2);
  }
};

// services/api/providers.ts
function readProviderSettings(config2) {
  const input = process.env.OAUTH_PROVIDERS_JSON;
  if (!input) return { providers: [] };
  const providers = z3.array(z3.object({ id: z3.string().regex(/^[a-z0-9-]{1,40}$/), issuer: z3.url(), clientId: z3.string().min(1), clientSecret: z3.string().min(1).optional(), redirectUri: z3.url(), scopes: z3.array(z3.string().min(1)).min(1), oidc: z3.boolean(), allowedEndpointOrigins: z3.array(z3.url()).optional() }).strict()).max(20).parse(JSON.parse(input));
  if (new Set(providers.map((p) => p.id)).size !== providers.length || providers.some((p) => ["templogin", "external"].includes(p.id))) throw new Error("Invalid provider identifiers");
  for (const p of providers) if (p.redirectUri !== config2.origin + "/api/providers/" + p.id + "/callback") throw new Error("Provider redirectUri must match PUBLIC_ORIGIN callback");
  if (!providers.length) return { providers };
  const keys = z3.record(z3.string(), z3.string()).parse(JSON.parse(process.env.TOKEN_KEYRING || "{}"));
  const bytes = Object.fromEntries(Object.entries(keys).map(([kid, key]) => {
    if (!/^[A-Za-z0-9+/]{43}=$/.test(key)) throw new Error("TOKEN_KEYRING values must be canonical base64 encoded 32-byte keys");
    return [kid, Buffer.from(key, "base64")];
  }));
  return { providers, vault: new TokenVault(process.env.TOKEN_ACTIVE_KEY_ID || "", bytes) };
}
var context = (userId, provider) => JSON.stringify([userId, provider]);
function databaseStore(db, providerId, sessionId) {
  return {
    async put(p) {
      if (!sessionId) throw new Error("session_required");
      await db.transaction(async (tx) => {
        await tx.query("DELETE FROM oauth_pending WHERE expires_at<=$1 OR (user_id=$2 AND provider_id=$3)", [Date.now(), p.userId, providerId]);
        await tx.query("INSERT INTO oauth_pending(state_hash,provider_id,user_id,session_id,browser_binding_hash,verifier,nonce,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", [p.stateHash, providerId, p.userId, sessionId, p.browserBindingHash, p.verifier, p.nonce || null, JSON.stringify(p.scopes), p.expiresAt]);
      });
    },
    async consume(stateHash) {
      const row = (await db.query("DELETE FROM oauth_pending WHERE state_hash=$1 AND provider_id=$2 RETURNING *", [stateHash, providerId])).rows[0];
      return row ? { stateHash: row.state_hash, userId: row.user_id, browserBindingHash: row.browser_binding_hash, verifier: row.verifier, nonce: row.nonce || void 0, scopes: row.scopes, expiresAt: Number(row.expires_at) } : void 0;
    }
  };
}
async function registerProviders(app2, db, config2, settings = readProviderSettings(config2)) {
  if (settings.providers.length && !settings.vault) throw new Error("Provider token encryption keys required");
  const configs = new Map(settings.providers.map((p) => [p.id, p]));
  const vault = settings.vault;
  const cookie2 = { httpOnly: true, secure: config2.origin.startsWith("https:"), sameSite: "lax", path: "/api/providers", maxAge: 300 };
  const getConfig = (provider) => {
    const p = configs.get(provider);
    if (!p) fail2(404, "provider_unavailable");
    return p;
  };
  const connector = (provider, sessionId) => OAuthAccountConnector.discover(getConfig(provider), databaseStore(db, provider, sessionId), settings.transport);
  app2.get("/api/providers", async () => ({ providers: [
    { id: "templogin", name: "tempLogin native demos", capabilities: { accountLinking: false, providerAuthorization: false, deviceAuthorization: true, sessionProvisioning: true, sessionRevocation: true, tokenRevocation: false }, status: "available" },
    ...settings.providers.map((p) => ({ id: p.id, name: p.id, capabilities: { accountLinking: true, providerAuthorization: true, deviceAuthorization: false, sessionProvisioning: false, sessionRevocation: false, tokenRevocation: false }, status: "configured" })),
    ...settings.providers.length ? [] : [{ id: "external", name: "External providers", capabilities: { accountLinking: false, providerAuthorization: false, deviceAuthorization: false, sessionProvisioning: false, sessionRevocation: false, tokenRevocation: false }, status: "not_configured" }]
  ] }));
  app2.get("/api/connections", async (req) => {
    const user = await requireUser(db, req);
    return (await db.query("SELECT id,provider_id,subject,scopes,status,created_at,updated_at FROM oauth_connections WHERE user_id=$1 ORDER BY created_at", [user.id])).rows.map((c) => ({ ...c, provider_name: c.provider_id, created_at: Number(c.created_at), updated_at: Number(c.updated_at) }));
  });
  app2.post("/api/providers/:id/link", async (req, reply) => {
    const user = await requireRecentUser(db, req);
    z3.object({}).strict().parse(req.body);
    const binding = token(), client = await connector(req.params.id, user.sessionId), flow = await client.begin(user.id, binding);
    reply.setCookie("tl_oauth_binding", binding, cookie2);
    await audit(db, user.id, "provider.link_started", req.params.id);
    return { authorization_url: flow.authorizationUrl, expires_in: flow.expiresIn };
  });
  app2.get("/api/providers/:id/callback", async (req, reply) => {
    reply.clearCookie("tl_oauth_binding", cookie2);
    try {
      const cfg = getConfig(req.params.id), callback = new URL(req.url, config2.origin), state = callback.searchParams.get("state"), binding = req.cookies.tl_oauth_binding;
      if (!state || state.length > 512 || !binding || binding.length !== 43) fail2(400, "invalid_state");
      const row = (await db.query("SELECT p.* FROM oauth_pending p JOIN user_sessions s ON s.id=p.session_id WHERE p.state_hash=$1 AND p.provider_id=$2 AND p.browser_binding_hash=$3 AND p.expires_at>$4 AND s.expires_at>$4", [hash2(state), cfg.id, hash2(binding), Date.now()])).rows[0];
      if (!row) fail2(400, "invalid_state");
      const client = await connector(cfg.id), result = await client.complete(callback.href, row.user_id, binding);
      await db.transaction(async (tx) => {
        await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [row.user_id]);
        const session = (await tx.query("SELECT id FROM user_sessions WHERE id=$1 AND user_id=$2 AND expires_at>$3 FOR UPDATE", [row.session_id, row.user_id, Date.now()])).rows[0];
        if (!session) fail2(401, "unauthorized");
        const envelope = vault.encrypt(JSON.stringify(result.tokens), context(row.user_id, cfg.id));
        await tx.query("INSERT INTO oauth_connections(id,user_id,provider_id,subject,scopes,token_envelope,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$7) ON CONFLICT(user_id,provider_id) DO UPDATE SET subject=EXCLUDED.subject,scopes=EXCLUDED.scopes,token_envelope=EXCLUDED.token_envelope,status='linked',updated_at=EXCLUDED.updated_at", [id(), row.user_id, cfg.id, result.identity?.subject || null, JSON.stringify(result.scopes), JSON.stringify(envelope), Date.now()]);
        await audit(tx, row.user_id, "provider.linked", cfg.id);
      });
      return reply.redirect("/connections?linked=1");
    } catch {
      req.log.warn("Provider authorization failed");
      return reply.redirect("/connections?error=oauth_failed");
    }
  });
  app2.delete("/api/connections/:id", async (req) => {
    const user = await requireRecentUser(db, req);
    return db.transaction(async (tx) => {
      await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [user.id]);
      await requireRecentUser(tx, req);
      const connection = (await tx.query("SELECT * FROM oauth_connections WHERE id=$1 AND user_id=$2 FOR UPDATE", [req.params.id, user.id])).rows[0];
      if (!connection) fail2(404, "not_found");
      let providerRevocation = "revocation_unavailable";
      if (configs.has(connection.provider_id)) {
        try {
          const tokens = JSON.parse(vault.decrypt(connection.token_envelope, context(user.id, connection.provider_id)));
          const client = await connector(connection.provider_id);
          const result = await client.revokeToken(tokens.refresh_token || tokens.access_token);
          providerRevocation = result.status;
          if (tokens.refresh_token && client.capabilities().tokenRevocation) await client.revokeToken(tokens.access_token);
        } catch {
          providerRevocation = "error";
        }
      }
      await tx.query("DELETE FROM oauth_connections WHERE id=$1", [connection.id]);
      await audit(tx, user.id, "provider.unlinked", connection.provider_id);
      return { status: "unlinked", provider_revocation: providerRevocation };
    });
  });
  app2.post("/api/connections/:id/refresh", async (req, reply) => {
    const user = await requireRecentUser(db, req);
    z3.object({}).strict().parse(req.body);
    const result = await db.transaction(async (tx) => {
      await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [user.id]);
      await requireRecentUser(tx, req);
      const connection = (await tx.query("SELECT * FROM oauth_connections WHERE id=$1 AND user_id=$2 FOR UPDATE", [req.params.id, user.id])).rows[0];
      if (!connection) fail2(404, "not_found");
      if (connection.status !== "linked") return { error: "reauthorization_required" };
      try {
        const previous = JSON.parse(vault.decrypt(connection.token_envelope, context(user.id, connection.provider_id)));
        if (!previous.refresh_token) return { error: "refresh_unavailable" };
        const client = await connector(connection.provider_id), tokens = await client.refresh(previous.refresh_token), claims = oauth2.getValidatedIdTokenClaims(tokens);
        if (claims && connection.subject && claims.sub !== connection.subject) throw new Error("subject_changed");
        const scopes = tokens.scope?.split(" ") || connection.scopes;
        if (scopes.some((s) => !connection.scopes.includes(s))) throw new Error("scope_expanded");
        const envelope = vault.encrypt(JSON.stringify({ ...tokens, refresh_token: tokens.refresh_token || previous.refresh_token }), context(user.id, connection.provider_id));
        await tx.query("UPDATE oauth_connections SET token_envelope=$1,scopes=$2,updated_at=$3 WHERE id=$4", [JSON.stringify(envelope), JSON.stringify(scopes), Date.now(), connection.id]);
        await audit(tx, user.id, "provider.refreshed", connection.provider_id);
        return { status: "linked" };
      } catch {
        await tx.query("UPDATE oauth_connections SET status='reauthorization_required',updated_at=$1 WHERE id=$2", [Date.now(), connection.id]);
        return { error: "reauthorization_required" };
      }
    });
    if ("error" in result) return reply.code(409).send(result);
    return result;
  });
}

// services/api/hospitality.ts
import { z as z4 } from "zod";
var name = z4.string().trim().min(1).max(80);
async function member(db, userId, orgId, owner = false) {
  const m = (await db.query("SELECT role FROM organization_members WHERE organization_id=$1 AND user_id=$2", [orgId, userId])).rows[0];
  if (!m || owner && m.role !== "owner") fail2(404, "not_found");
}
async function registerHospitality(app2, db) {
  app2.get("/api/organizations", async (req) => {
    const u = await requireUser(db, req);
    return (await db.query("SELECT o.id,o.name,m.role FROM organizations o JOIN organization_members m ON m.organization_id=o.id WHERE m.user_id=$1 ORDER BY o.created_at", [u.id])).rows;
  });
  app2.post("/api/organizations", async (req) => {
    const u = await requireUser(db, req), b = z4.object({ name }).strict().parse(req.body), orgId = id();
    await db.transaction(async (tx) => {
      await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [u.id]);
      await requireUser(tx, req);
      await tx.query("INSERT INTO organizations(id,name,created_at) VALUES($1,$2,$3)", [orgId, b.name, Date.now()]);
      await tx.query("INSERT INTO organization_members(organization_id,user_id,role) VALUES($1,$2,'owner')", [orgId, u.id]);
      await audit(tx, u.id, "organization.created", orgId, orgId);
    });
    return { id: orgId, name: b.name };
  });
  app2.get("/api/organizations/:id", async (req) => {
    const u = await requireUser(db, req), org = req.params.id;
    await member(db, u.id, org);
    const o = (await db.query("SELECT id,name FROM organizations WHERE id=$1", [org])).rows[0];
    const properties = (await db.query("SELECT id,name FROM properties WHERE organization_id=$1 ORDER BY name", [org])).rows;
    const devices = (await db.query("SELECT id,name,property_id,client_id FROM devices WHERE organization_id=$1 ORDER BY name", [org])).rows;
    const stays = (await db.query("SELECT * FROM stays WHERE organization_id=$1 ORDER BY starts_at DESC LIMIT 200", [org])).rows;
    const events = (await db.query("SELECT action,target_id,created_at FROM audit_events WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100", [org])).rows;
    return { ...o, properties, devices, stays, events };
  });
  app2.post("/api/organizations/:id/properties", async (req) => {
    const u = await requireUser(db, req), org = req.params.id;
    await member(db, u.id, org, true);
    const b = z4.object({ name }).strict().parse(req.body), key = id();
    await db.transaction(async (tx) => {
      await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [u.id]);
      await requireUser(tx, req);
      await tx.query("INSERT INTO properties(id,organization_id,name) VALUES($1,$2,$3)", [key, org, b.name]);
      await audit(tx, u.id, "property.created", key, org);
    });
    return { id: key, name: b.name };
  });
  app2.post("/api/organizations/:id/devices", async (req) => {
    const u = await requireUser(db, req), org = req.params.id;
    await member(db, u.id, org, true);
    const b = z4.object({ name, property_id: z4.string().uuid(), client_id: z4.enum(["demo-tv", "demo-car"]) }).strict().parse(req.body);
    const property = (await db.query("SELECT id FROM properties WHERE id=$1 AND organization_id=$2", [b.property_id, org])).rows[0];
    if (!property) fail2(404, "not_found");
    const key = id(), secret2 = token();
    await db.transaction(async (tx) => {
      await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [u.id]);
      await requireUser(tx, req);
      await tx.query("INSERT INTO devices(id,organization_id,property_id,name,client_id,secret_hash,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)", [key, org, b.property_id, b.name, b.client_id, hash2(secret2), Date.now()]);
      await audit(tx, u.id, "device.registered", key, org);
    });
    return { id: key, secret: secret2 };
  });
  app2.post("/api/organizations/:id/stays", async (req) => {
    const u = await requireUser(db, req), org = req.params.id;
    await member(db, u.id, org, true);
    const b = z4.object({ property_id: z4.string().uuid(), guest_label: name, starts_at: z4.number().int().nonnegative(), ends_at: z4.number().int().positive() }).strict().refine((b2) => b2.ends_at > b2.starts_at && b2.ends_at - b2.starts_at <= 366 * 864e5).parse(req.body);
    if (b.ends_at <= Date.now()) fail2(400, "stay_in_past");
    const key = id();
    await db.transaction(async (tx) => {
      await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [u.id]);
      await requireUser(tx, req);
      const prop = (await tx.query("SELECT id FROM properties WHERE id=$1 AND organization_id=$2 FOR UPDATE", [b.property_id, org])).rows[0];
      if (!prop) fail2(404, "not_found");
      const overlap = (await tx.query("SELECT id FROM stays WHERE property_id=$1 AND checked_out_at IS NULL AND starts_at<$2 AND ends_at>$3", [b.property_id, b.ends_at, b.starts_at])).rows[0];
      if (overlap) fail2(409, "stay_overlap");
      await tx.query("INSERT INTO stays(id,organization_id,property_id,guest_label,starts_at,ends_at) VALUES($1,$2,$3,$4,$5,$6)", [key, org, b.property_id, b.guest_label, b.starts_at, b.ends_at]);
      await audit(tx, u.id, "stay.created", key, org);
    });
    return { id: key, ...b };
  });
  app2.post("/api/organizations/:id/stays/:stayId/checkout", async (req) => {
    const u = await requireUser(db, req), org = req.params.id;
    await member(db, u.id, org, true);
    await db.transaction(async (tx) => {
      await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [u.id]);
      await requireUser(tx, req);
      const stay = (await tx.query("SELECT id,property_id FROM stays WHERE id=$1 AND organization_id=$2", [req.params.stayId, org])).rows[0];
      if (!stay) fail2(404, "not_found");
      await tx.query("SELECT id FROM properties WHERE id=$1 FOR UPDATE", [stay.property_id]);
      await tx.query("UPDATE stays SET checked_out_at=COALESCE(checked_out_at,$1) WHERE id=$2", [Date.now(), stay.id]);
      await tx.query("UPDATE grants SET revoked_at=COALESCE(revoked_at,$1),revoke_reason='checkout' WHERE stay_id=$2", [Date.now(), stay.id]);
      await audit(tx, u.id, "stay.checked_out", stay.id, org);
    });
    return { status: "revocation_verified", external_status: "manual_verification_required" };
  });
  app2.post("/api/organizations/:id/devices/:deviceId/revoke", async (req) => {
    const u = await requireUser(db, req), org = req.params.id;
    await member(db, u.id, org, true);
    const d = (await db.query("SELECT id FROM devices WHERE id=$1 AND organization_id=$2", [req.params.deviceId, org])).rows[0];
    if (!d) fail2(404, "not_found");
    await db.transaction(async (tx) => {
      await tx.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [u.id]);
      await requireUser(tx, req);
      await tx.query("SELECT id FROM devices WHERE id=$1 FOR UPDATE", [req.params.deviceId]);
      await tx.query("DELETE FROM pairings WHERE device_id=$1", [req.params.deviceId]);
      await tx.query("UPDATE grants SET revoked_at=COALESCE(revoked_at,$1),revoke_reason='host_reset' WHERE device_id=$2", [Date.now(), req.params.deviceId]);
      await audit(tx, u.id, "device.revoked", req.params.deviceId, org);
    });
    return { status: "revocation_verified", external_status: "manual_verification_required" };
  });
}

// services/api/temporary.ts
import { z as z6 } from "zod";

// packages/provider-sdk/index.ts
import { createHash as createHash5, randomBytes as randomBytes4, randomInt as randomInt2, randomUUID as randomUUID3 } from "node:crypto";
import { z as z5 } from "zod";
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
var digest = (s) => createHash5("sha256").update(s).digest("hex");
var secret = () => randomBytes4(32).toString("base64url");
function fail3(statusCode, message) {
  throw Object.assign(new Error(message), { statusCode });
}
var codeSchema2 = z5.string().regex(/^[A-Z2-9]{5}-[A-Z2-9]{5}$/);
var tokenSchema = z5.string().regex(/^[A-Za-z0-9_-]{43}$/);
async function registerTemporaryLogin(app2, db, provider) {
  const origin = new URL(provider.origin);
  if (origin.origin !== provider.origin || origin.username || !provider.id || !provider.name || origin.protocol !== "https:" && !(origin.protocol === "http:" && ["localhost", "127.0.0.1"].includes(origin.hostname)) || !Number.isSafeInteger(provider.maxDurationSeconds) || provider.maxDurationSeconds < 60 || provider.maxDurationSeconds > 86400) throw new Error("invalid_provider_configuration");
  await db.exec(schemaSQL);
  const prefix = "/api/temporary";
  app2.addHook("onRequest", async (req, reply) => {
    if (!req.url.startsWith(prefix + "/")) return;
    reply.header("Cache-Control", "no-store").header("Pragma", "no-cache");
    if (req.headers.origin && req.headers.origin !== provider.origin) fail3(403, "origin_not_allowed");
    if (req.method !== "GET") {
      if (req.headers.origin !== provider.origin || req.headers["sec-fetch-site"] === "cross-site") fail3(403, "origin_required");
    }
  });
  async function identity(req) {
    const who = await provider.identity(req);
    if (!who?.subject || !who.displayName || !Number.isSafeInteger(who.authenticatedAt) || who.authenticatedAt > Date.now() || who.authenticatedAt < Date.now() - 9e5) fail3(401, "provider_login_required");
    return who;
  }
  const pair = async (store, code, lock = false) => {
    const p = (await store.query(`SELECT * FROM tl_pairings WHERE code=$1 AND provider=$2${lock ? " FOR UPDATE" : ""}`, [code, provider.id])).rows[0];
    if (!p || Number(p.expires_at) <= Date.now()) fail3(410, "pairing_expired");
    return p;
  };
  const requireSession = async (req) => {
    const bearer = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization || "");
    if (!bearer) fail3(401, "invalid_token");
    const s = (await db.query("SELECT * FROM tl_provider_sessions WHERE token_hash=$1 AND provider=$2", [digest(bearer[1]), provider.id])).rows[0];
    if (!s || s.revoked_at !== null || Number(s.expires_at) <= Date.now()) fail3(401, "session_ended");
    if (!await provider.entitled(s.subject)) fail3(403, "account_unavailable");
    const live = (await db.query("SELECT id FROM tl_provider_sessions WHERE id=$1 AND revoked_at IS NULL AND expires_at>$2", [s.id, Date.now()])).rows[0];
    if (!live) fail3(401, "session_ended");
    return s;
  };
  app2.get(prefix + "/config", async () => ({ provider: { id: provider.id, name: provider.name }, max_duration_seconds: provider.maxDurationSeconds, account_required: false }));
  app2.post(prefix + "/pairings", async (req) => {
    const body = z5.object({ device_name: z5.string().trim().min(1).max(80) }).strict().parse(req.body);
    const device = secret(), alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const chars = Array.from({ length: 10 }, () => alphabet[randomInt2(alphabet.length)]).join(""), code = chars.slice(0, 5) + "-" + chars.slice(5);
    await db.query("INSERT INTO tl_pairings(id,provider,secret_hash,code,device_name,expires_at) VALUES($1,$2,$3,$4,$5,$6)", [randomUUID3(), provider.id, digest(device), code, body.device_name, Date.now() + 3e5]);
    return { device_code: device, user_code: code, verification_uri: provider.origin + "/approve", verification_uri_complete: provider.origin + "/approve?code=" + code, expires_in: 300, interval: 3 };
  });
  app2.get(prefix + "/context", async (req) => {
    const who = await identity(req), q = z5.object({ code: codeSchema2 }).strict().parse(req.query), p = await pair(db, q.code);
    return { provider: provider.name, account: who.displayName, device_name: p.device_name, user_code: p.code, status: p.status, expires_at: Number(p.expires_at), max_duration_seconds: provider.maxDurationSeconds, device_verified: false };
  });
  app2.post(prefix + "/decision", async (req) => {
    const who = await identity(req);
    const b = z5.object({ code: codeSchema2, matching_code: codeSchema2, approve: z5.boolean(), duration_seconds: z5.number().int().min(1).max(provider.maxDurationSeconds) }).strict().parse(req.body);
    if (b.code !== b.matching_code) fail3(400, "code_mismatch");
    if (b.approve && !await provider.entitled(who.subject)) fail3(403, "account_unavailable");
    return db.transaction(async (tx) => {
      const p = await pair(tx, b.code, true);
      if (p.status !== "pending") fail3(409, "pairing_already_decided");
      if (!b.approve) {
        await tx.query("UPDATE tl_pairings SET status='denied' WHERE id=$1", [p.id]);
        return { status: "denied" };
      }
      const id2 = randomUUID3(), now = Date.now(), end = now + b.duration_seconds * 1e3;
      await tx.query("INSERT INTO tl_provider_sessions(id,provider,subject,device_name,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6)", [id2, provider.id, who.subject, p.device_name, end, now]);
      await tx.query("UPDATE tl_pairings SET status='approved',session_id=$1 WHERE id=$2", [id2, p.id]);
      return { status: "approved", session_id: id2, expires_at: end };
    });
  });
  app2.post(prefix + "/token", async (req, reply) => {
    const b = z5.object({ device_code: tokenSchema }).strict().parse(req.body);
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
  app2.get(prefix + "/sessions", async (req) => {
    const who = await identity(req);
    return (await db.query("SELECT id,device_name,expires_at,revoked_at FROM tl_provider_sessions WHERE provider=$1 AND subject=$2 AND expires_at>$3 ORDER BY created_at DESC", [provider.id, who.subject, Date.now()])).rows.map((s) => ({ id: s.id, device_name: s.device_name, expires_at: Number(s.expires_at), revoked: s.revoked_at !== null }));
  });
  app2.post(prefix + "/sessions/:id/revoke", async (req) => {
    const who = await identity(req);
    z5.object({}).strict().parse(req.body);
    const result = await db.query("UPDATE tl_provider_sessions SET revoked_at=COALESCE(revoked_at,$1) WHERE id=$2 AND provider=$3 AND subject=$4 RETURNING id", [Date.now(), req.params.id, provider.id, who.subject]);
    if (!result.rowCount) fail3(404, "session_not_found");
    return { status: "revoked" };
  });
  app2.post(prefix + "/logout", async (req) => {
    z5.object({}).strict().parse(req.body);
    const s = await requireSession(req);
    await db.query("UPDATE tl_provider_sessions SET revoked_at=COALESCE(revoked_at,$1) WHERE id=$2", [Date.now(), s.id]);
    return { status: "revoked" };
  });
  return { requireSession };
}

// services/api/temporary.ts
async function registerReferenceProvider(app2, db, config2, realProvider) {
  if (realProvider && realProvider.origin !== config2.origin) throw new Error("Provider origin must match host PUBLIC_ORIGIN");
  const demo = !config2.production && !realProvider;
  await db.exec("CREATE TABLE IF NOT EXISTS tl_demo_logins (hash TEXT PRIMARY KEY,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL)");
  const provider = realProvider ?? {
    id: "screen-demo",
    name: "Screen Demo",
    origin: config2.origin,
    maxDurationSeconds: 7200,
    async identity(req) {
      if (!demo) return null;
      const value = req.cookies.tl_demo_provider;
      if (!value) return null;
      const row = (await db.query("SELECT created_at FROM tl_demo_logins WHERE hash=$1 AND expires_at>$2", [hash2(value), Date.now()])).rows[0];
      return row ? { subject: "demo:" + hash2(value), displayName: "Demo Guest", authenticatedAt: Number(row.created_at) } : null;
    },
    async entitled() {
      return demo;
    }
  };
  const guard = await registerTemporaryLogin(app2, db, provider);
  app2.get("/api/temporary/mode", async () => ({ demo, configured: demo || !!realProvider }));
  app2.post("/api/temporary/demo-login", async (req, reply) => {
    if (!demo) fail2(404, "demo_disabled");
    z6.object({}).strict().parse(req.body);
    const value = token(), now = Date.now();
    await db.query("DELETE FROM tl_demo_logins WHERE expires_at<=$1", [now]);
    await db.query("INSERT INTO tl_demo_logins(hash,created_at,expires_at) VALUES($1,$2,$3)", [hash2(value), now, now + 9e5]);
    reply.setCookie("tl_demo_provider", value, { httpOnly: true, secure: config2.origin.startsWith("https:"), sameSite: "strict", path: "/api/temporary", maxAge: 900 });
    return { status: "signed_in", demo: true };
  });
  app2.get("/api/temporary/content", async (req) => {
    const session = await guard.requireSession(req);
    return { title: "Your temporary session", provider: provider.name, expires_at: Number(session.expires_at), demo, session_id: session.id };
  });
  return guard;
}

// services/api/app.ts
async function createApp(config2, suppliedDb, provider) {
  if (config2.production && (!config2.origin.startsWith("https://") || !config2.databaseUrl)) throw new Error("Production requires HTTPS and PostgreSQL");
  const db = suppliedDb || await createDatabase(config2);
  const app2 = Fastify({ logger: config2.production ? { level: "info", redact: ["req.headers.authorization", "req.headers.cookie", 'res.headers["set-cookie"]'], serializers: { req: (r) => ({ method: r.method, url: r.url?.split("?")[0], id: r.id }) } } : false, bodyLimit: 32768, trustProxy: config2.trustedProxies?.length ? config2.trustedProxies : false, requestTimeout: 15e3, connectionTimeout: 1e4 });
  app2.decorate("db", db);
  await app2.register(cookie);
  await app2.register(helmet, { contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"], imgSrc: ["'self'", "data:"], connectSrc: ["'self'"], frameAncestors: ["'none'"], formAction: ["'self'"], baseUri: ["'none'"], objectSrc: ["'none'"], upgradeInsecureRequests: config2.production ? [] : null } }, referrerPolicy: { policy: "no-referrer" }, hsts: config2.production ? { maxAge: 31536e3, includeSubDomains: true } : false });
  app2.addHook("onRequest", async (req, reply) => {
    if (!req.url.startsWith("/api/")) return;
    reply.header("Cache-Control", "no-store").header("Pragma", "no-cache");
    if (req.headers.origin && req.headers.origin !== config2.origin) return reply.code(403).send({ error: "origin_not_allowed" });
    if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
      const deviceEndpoint = ["/api/token", "/api/pairings", "/api/device/logout"].includes(req.url);
      if (req.headers.origin !== config2.origin && (!deviceEndpoint || req.cookies.tl_session)) return reply.code(403).send({ error: "origin_required" });
      if (req.headers["sec-fetch-site"] === "cross-site") return reply.code(403).send({ error: "cross_site_request" });
    }
    const route = req.url.split("?")[0], auth = route.startsWith("/api/auth/") || route === "/api/temporary/demo-login", pair = req.method === "POST" && (route === "/api/pairings" || route === "/api/temporary/pairings");
    const bucket = auth ? "auth" : pair ? "pair" : "general", limit = auth ? 20 : pair ? 12 : 120, now = Date.now(), window = Math.floor(now / 6e4) * 6e4;
    const key = hash2(req.ip + ":" + bucket);
    const count = (await db.query("INSERT INTO rate_limits(key,window_start,hits) VALUES($1,$2,1) ON CONFLICT(key) DO UPDATE SET hits=CASE WHEN rate_limits.window_start=$2 THEN rate_limits.hits+1 ELSE 1 END,window_start=$2 RETURNING hits", [key, window])).rows[0].hits;
    if (count > limit) return reply.header("Retry-After", Math.ceil((window + 6e4 - now) / 1e3)).code(429).send({ error: "rate_limited" });
  });
  app2.setErrorHandler((error, req, reply) => {
    if (error instanceof ZodError) return reply.code(400).send({ error: "invalid_request" });
    const e = error;
    if (e.code === "23505") return reply.code(409).send({ error: "conflict" });
    if (e.code === "23503") return reply.code(409).send({ error: "conflict" });
    const status = e.statusCode && e.statusCode >= 400 && e.statusCode < 500 ? e.statusCode : 500;
    if (status === 500) req.log.error({ code: e.code || "internal_error", requestId: req.id }, "Request failed");
    return reply.code(status).send({ error: status === 500 ? "internal_error" : e.message });
  });
  let requests = 0, failures = 0, durationSum = 0;
  const bounds = [0.01, 0.05, 0.1, 0.5, 1, 5, 15], buckets = bounds.map(() => 0);
  app2.addHook("onResponse", async (req, reply) => {
    if (req.url === "/metrics") return;
    requests++;
    if (reply.statusCode >= 500) failures++;
    const seconds = reply.elapsedTime / 1e3;
    durationSum += seconds;
    bounds.forEach((bound, i) => {
      if (seconds <= bound) buckets[i]++;
    });
  });
  app2.get("/metrics", async (req, reply) => {
    if (!config2.metricsToken) return reply.code(404).send({ error: "not_found" });
    const provided = (req.headers.authorization || "").replace(/^Bearer /, "");
    if (!timingSafeEqual2(Buffer.from(hash2(provided)), Buffer.from(hash2(config2.metricsToken)))) return reply.code(401).send({ error: "unauthorized" });
    reply.header("Cache-Control", "no-store").type("text/plain; version=0.0.4");
    return ["# TYPE templogin_http_requests_total counter", `templogin_http_requests_total ${requests}`, "# TYPE templogin_http_errors_total counter", `templogin_http_errors_total ${failures}`, "# TYPE templogin_http_duration_seconds histogram", ...bounds.map((b, i) => `templogin_http_duration_seconds_bucket{le="${b}"} ${buckets[i]}`), `templogin_http_duration_seconds_bucket{le="+Inf"} ${requests}`, `templogin_http_duration_seconds_sum ${durationSum}`, `templogin_http_duration_seconds_count ${requests}`, ""].join("\n");
  });
  app2.get("/healthz", async () => ({ status: "ok" }));
  app2.get("/readyz", async () => {
    await db.query("SELECT 1");
    return { status: "ready" };
  });
  app2.get("/api/config", async () => ({ origin: config2.origin, rpID: config2.rpID, production: config2.production }));
  await registerReferenceProvider(app2, db, config2, provider);
  if (config2.legacyWallet) {
    await registerAuth(app2, db, config2);
    await registerCore(app2, db, config2);
    await registerHospitality(app2, db);
    await registerProviders(app2, db, config2);
  }
  const publicDir = resolve("dist/public");
  if (existsSync(publicDir)) {
    await app2.register(staticPlugin, { root: publicDir, index: false });
    app2.get("/", (_req, reply) => reply.type("text/html").sendFile("index.html"));
    app2.setNotFoundHandler((req, reply) => {
      if (req.method === "GET" && !req.url.startsWith("/api/") && !req.url.split("?")[0].includes(".")) return reply.type("text/html").sendFile("index.html");
      return reply.code(404).send({ error: "not_found" });
    });
  }
  if (!suppliedDb) app2.addHook("onClose", async () => db.close());
  return app2;
}

// services/api/config.ts
import { isIP } from "node:net";
function readConfig() {
  const production = process.env.NODE_ENV === "production";
  const origin = process.env.PUBLIC_ORIGIN || "http://localhost:3000";
  const url = new URL(origin);
  if (url.origin !== origin || production && url.protocol !== "https:") throw new Error("PUBLIC_ORIGIN must be an origin, HTTPS in production");
  if (!production && url.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(url.hostname)) throw new Error("Use HTTPS for non-localhost passkeys");
  if (production && !process.env.DATABASE_URL) throw new Error("DATABASE_URL required in production");
  const rpID = process.env.RP_ID || url.hostname;
  if (url.hostname !== rpID && !url.hostname.endsWith("." + rpID)) throw new Error("RP_ID must match PUBLIC_ORIGIN");
  const port = Number(process.env.PORT || 3e3);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid PORT");
  const trustedProxies = process.env.TRUSTED_PROXY?.split(",").map((s) => s.trim()).filter(Boolean);
  if (trustedProxies?.some((s) => !isIP(s))) throw new Error("TRUSTED_PROXY must list explicit proxy IP addresses");
  const metricsToken = process.env.METRICS_TOKEN;
  if (metricsToken && metricsToken.length < 32) throw new Error("METRICS_TOKEN must contain at least 32 random characters");
  return { origin, rpID, production, trustedProxies, metricsToken, databaseUrl: process.env.DATABASE_URL, dataDir: process.env.DATA_DIR || "./.data", port };
}

// services/api/main.ts
var config = readConfig();
var app = await createApp(config);
await app.listen({ port: config.port, host: process.env.HOST || "127.0.0.1" });
console.log(`tempLogin listening at ${config.origin}`);
for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => {
  void app.close().then(() => process.exit(0));
});
//# sourceMappingURL=server.js.map
