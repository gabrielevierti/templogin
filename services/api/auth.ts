import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type {} from '@fastify/cookie';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
  type RegistrationResponseJSON, type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
} from '@simplewebauthn/server';
import { z } from 'zod';
import type { Database } from './database.js';

interface AuthConfig { origin: string; rpID: string; production: boolean }
export interface AuthenticatedUser { id: string; name: string; sessionId: string; authenticatedAt: number }
interface Challenge { id: string; kind: string; challenge: string; user_id: string; user_name: string; session_id: string | null; expires_at: number }
interface StoredKey { id: string; user_id: string; public_key: string; counter: number; transports: AuthenticatorTransportFuture[]; device_type: string; backed_up: boolean }
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const fail = (code: string, statusCode = 400): never => { throw Object.assign(new Error(code), { statusCode }); };
const validID = z.string().min(1).max(2048);
const sessionLife = 7 * 24 * 60 * 60 * 1000;
const recentLife = 5 * 60 * 1000;

export async function requireUser(db: Database, req: FastifyRequest): Promise<AuthenticatedUser> {
  const token = req.cookies.tl_session;
  if (!token || token.length > 128) return fail('unauthorized', 401);
  const result = await db.query<{ id: string; name: string; session_id: string; authenticated_at: number }>(
    `SELECT u.id,u.name,s.id AS session_id,s.authenticated_at FROM user_sessions s
     JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>$2`, [hash(token), Date.now()],
  );
  const user = result.rows[0];
  if (!user) return fail('unauthorized', 401);
  return { id: user.id, name: user.name, sessionId: user.session_id, authenticatedAt: Number(user.authenticated_at) };
}
export async function requireRecentUser(db: Database, req: FastifyRequest): Promise<AuthenticatedUser> {
  const user = await requireUser(db, req);
  if (Date.now() - user.authenticatedAt > recentLife) return fail('reauthentication_required', 403);
  return user;
}

export async function registerAuth(app: FastifyInstance, db: Database, config: AuthConfig): Promise<void> {
  const cookie = { httpOnly: true, secure: config.production || config.origin.startsWith('https:'), sameSite: 'strict' as const, path: '/' };
  const clearChallenge = (reply: FastifyReply) => reply.clearCookie('tl_challenge', cookie);
  const clearSession = (reply: FastifyReply) => reply.clearCookie('tl_session', cookie);

  async function recordAudit(tx: Database, userId: string, action: string, targetId: string | null = null) {
    await tx.query('INSERT INTO audit_events(id,user_id,action,target_id,created_at) VALUES ($1,$2,$3,$4,$5)', [randomUUID(), userId, action, targetId, Date.now()]);
  }

  async function challenge(req: FastifyRequest, reply: FastifyReply, kind: string, value: string, userId?: string, name?: string, sessionId?: string) {
    const binding = randomBytes(32).toString('base64url');
    await db.transaction(async (tx) => {
      if (req.cookies.tl_challenge) await tx.query('DELETE FROM auth_challenges WHERE binding_hash=$1', [hash(req.cookies.tl_challenge)]);
      await tx.query('DELETE FROM auth_challenges WHERE expires_at<=$1', [Date.now()]);
      await tx.query(`INSERT INTO auth_challenges(id,binding_hash,challenge,kind,user_id,user_name,session_id,expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, [randomUUID(), hash(binding), value, kind, userId ?? null, name ?? null, sessionId ?? null, Date.now() + 300000]);
    });
    reply.setCookie('tl_challenge', binding, { ...cookie, maxAge: 300 });
  }
  async function consume(req: FastifyRequest, reply: FastifyReply, kind: string): Promise<Challenge> {
    const binding = req.cookies.tl_challenge;
    clearChallenge(reply);
    if (!binding || binding.length > 128) return fail('invalid_challenge');
    // Deletion is committed before cryptographic verification, including failed assertions.
    const result = await db.query<Challenge>('DELETE FROM auth_challenges WHERE binding_hash=$1 RETURNING *', [hash(binding)]);
    const row = result.rows[0];
    if (!row || row.kind !== kind || Number(row.expires_at) <= Date.now()) return fail('invalid_challenge');
    return row;
  }
  async function createSession(tx: Database, req: FastifyRequest, userId: string) {
    // Rotate an existing browser session, preventing fixation and replacing stale sessions.
    if (req.cookies.tl_session) await tx.query('DELETE FROM user_sessions WHERE token_hash=$1', [hash(req.cookies.tl_session)]);
    const token = randomBytes(32).toString('base64url');
    const now = Date.now();
    await tx.query('INSERT INTO user_sessions(id,user_id,token_hash,created_at,expires_at,authenticated_at) VALUES ($1,$2,$3,$4,$5,$4)', [randomUUID(), userId, hash(token), now, now + sessionLife]);
    return token;
  }
  function sendSession(reply: FastifyReply, token: string) {
    reply.setCookie('tl_session', token, { ...cookie, maxAge: sessionLife / 1000 });
  }
  async function registrationOptions(req: FastifyRequest, reply: FastifyReply, adding: boolean) {
    const user = adding ? await requireRecentUser(db, req) : undefined;
    if (!adding && req.cookies.tl_session) {
      try { await requireUser(db, req); return fail('already_authenticated', 409); }
      catch (error) { if ((error as {statusCode?: number}).statusCode !== 401) throw error; }
    }
    const name = user?.name ?? z.object({ name: z.string().trim().min(1).max(80) }).parse(req.body).name;
    const userId = user?.id ?? randomUUID();
    const existing = adding ? await db.query<StoredKey>('SELECT * FROM passkeys WHERE user_id=$1', [userId]) : { rows: [] };
    if (existing.rows.length >= 20) return fail('passkey_limit', 409);
    const options = await generateRegistrationOptions({
      rpName: 'tempLogin', rpID: config.rpID, userName: name, userDisplayName: name,
      userID: new TextEncoder().encode(userId),
      attestationType: 'none', timeout: 300000,
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      supportedAlgorithmIDs: [-7, -257],
      excludeCredentials: existing.rows.map((key) => ({ id: key.id, transports: key.transports })),
    });
    await challenge(req, reply, adding ? 'add' : 'register', options.challenge, userId, name, user?.sessionId);
    return options;
  }
  async function registrationVerify(req: FastifyRequest, reply: FastifyReply, adding: boolean) {
    const current = adding ? await requireRecentUser(db, req) : undefined;
    const pending = await consume(req, reply, adding ? 'add' : 'register');
    if (adding && (pending.user_id !== current?.id || pending.session_id !== current.sessionId)) return fail('invalid_challenge');
    const body = z.object({ response: z.object({ id: validID }).passthrough() }).parse(req.body);
    let verified;
    try {
      verified = await verifyRegistrationResponse({
        response: body.response as unknown as RegistrationResponseJSON,
        expectedChallenge: pending.challenge, expectedOrigin: config.origin, expectedRPID: config.rpID,
        requireUserVerification: true, requireUserPresence: true, supportedAlgorithmIDs: [-7, -257],
      });
    } catch { return fail('invalid_passkey'); }
    if (!verified.verified || !verified.registrationInfo) return fail('invalid_passkey');
    const info = verified.registrationInfo;
    const token = await db.transaction(async (tx) => {
      if (adding) {
        // Revalidate after crypto verification under transaction; account deletion/session revocation wins.
        const locked = await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [pending.user_id]);
        if (!locked.rows.length) return fail('unauthorized', 401);
        const live = await requireRecentUser(tx, req);
        if (live.sessionId !== pending.session_id || live.id !== pending.user_id) return fail('unauthorized', 401);
        const count = await tx.query<{ count: string }>('SELECT count(*)::text AS count FROM passkeys WHERE user_id=$1', [pending.user_id]);
        if (Number(count.rows[0].count) >= 20) return fail('passkey_limit', 409);
      } else {
        await tx.query('INSERT INTO users(id,name,created_at) VALUES ($1,$2,$3)', [pending.user_id, pending.user_name, Date.now()]);
      }
      const exists = await tx.query('SELECT id FROM passkeys WHERE id=$1', [info.credential.id]);
      if (exists.rows.length) return fail('passkey_already_registered', 409);
      await tx.query(`INSERT INTO passkeys(id,user_id,public_key,counter,transports,device_type,backed_up,name,created_at)
        VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)`, [info.credential.id, pending.user_id,
        Buffer.from(info.credential.publicKey).toString('base64url'), info.credential.counter,
        JSON.stringify(info.credential.transports ?? []), info.credentialDeviceType, info.credentialBackedUp, 'Passkey', Date.now()]);
      await recordAudit(tx, pending.user_id, adding ? 'passkey.added' : 'account.created', info.credential.id);
      return adding ? null : createSession(tx, req, pending.user_id);
    });
    if (token) sendSession(reply, token);
    return { verified: true, id: pending.user_id };
  }
  app.post('/api/auth/register/options', (req, reply) => registrationOptions(req, reply, false));
  app.post('/api/auth/register/verify', (req, reply) => registrationVerify(req, reply, false));
  app.post('/api/auth/passkeys/options', (req, reply) => registrationOptions(req, reply, true));
  app.post('/api/auth/passkeys/verify', (req, reply) => registrationVerify(req, reply, true));
  app.post('/api/auth/login/options', async (req, reply) => {
    const options = await generateAuthenticationOptions({ rpID: config.rpID, userVerification: 'required', timeout: 300000 });
    await challenge(req, reply, 'login', options.challenge);
    return options;
  });
  app.post('/api/auth/login/verify', async (req, reply) => {
    const pending = await consume(req, reply, 'login');
    const body = z.object({ response: z.object({ id: validID }).passthrough() }).parse(req.body);
    const response = body.response as unknown as AuthenticationResponseJSON;
    const token = await db.transaction(async (tx) => {
      const candidate = (await tx.query<StoredKey>('SELECT * FROM passkeys WHERE id=$1', [response.id])).rows[0];
      if (!candidate) return fail('invalid_passkey');
      await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [candidate.user_id]);
      const keys = await tx.query<StoredKey>('SELECT * FROM passkeys WHERE id=$1 FOR UPDATE', [response.id]);
      const key = keys.rows[0];
      if (!key) return fail('invalid_passkey');
      if (response.response?.userHandle !== Buffer.from(key.user_id).toString('base64url')) return fail('invalid_passkey');
      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response, expectedChallenge: pending.challenge, expectedOrigin: config.origin,
          expectedRPID: config.rpID, requireUserVerification: true,
          credential: { id: key.id, publicKey: new Uint8Array(Buffer.from(key.public_key, 'base64url')), counter: Number(key.counter), transports: key.transports },
        });
      } catch { return fail('invalid_passkey'); }
      if (!verification.verified) return fail('invalid_passkey');
      const info = verification.authenticationInfo;
      await tx.query('UPDATE passkeys SET counter=$1,backed_up=$2,device_type=$3 WHERE id=$4', [info.newCounter, info.credentialBackedUp, info.credentialDeviceType, key.id]);
      await recordAudit(tx, key.user_id, 'auth.login', key.id);
      return createSession(tx, req, key.user_id);
    });
    sendSession(reply, token);
    return { verified: true };
  });
  app.get('/api/me', async (req) => {
    const user = await requireUser(db, req);
    return { id: user.id, name: user.name };
  });
  app.get('/api/passkeys', async (req) => {
    const user = await requireUser(db, req);
    const keys = await db.query<{id: string; name: string; created_at: number; device_type: string; backed_up: boolean}>('SELECT id,name,created_at,device_type,backed_up FROM passkeys WHERE user_id=$1 ORDER BY created_at', [user.id]);
    return keys.rows.map((key) => ({ ...key, created_at: Number(key.created_at) }));
  });
  app.delete('/api/passkeys/:id', async (req) => {
    const user = await requireRecentUser(db, req);
    const id = validID.parse((req.params as {id: string}).id);
    return db.transaction(async (tx) => {
      // Serialize per account so concurrent removals cannot remove its last credential.
      await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [user.id]);
      await requireRecentUser(tx, req);
      const keys = await tx.query<{id: string}>('SELECT id FROM passkeys WHERE user_id=$1', [user.id]);
      if (!keys.rows.some((key) => key.id === id)) return fail('not_found', 404);
      if (keys.rows.length <= 1) return fail('last_passkey', 409);
      await tx.query('DELETE FROM passkeys WHERE id=$1 AND user_id=$2', [id, user.id]);
      // A removed authenticator may have created other sessions; retire all except the current one.
      await tx.query('DELETE FROM user_sessions WHERE user_id=$1 AND id<>$2', [user.id, user.sessionId]);
      await recordAudit(tx, user.id, 'passkey.removed', id);
      return { ok: true };
    });
  });
  app.get('/api/sessions', async (req) => {
    const user = await requireUser(db, req);
    const sessions = await db.query<{id:string;created_at:number;expires_at:number}>('SELECT id,created_at,expires_at FROM user_sessions WHERE user_id=$1 AND expires_at>$2 ORDER BY created_at DESC', [user.id, Date.now()]);
    return sessions.rows.map((session) => ({ ...session, created_at: Number(session.created_at), expires_at: Number(session.expires_at), current: session.id === user.sessionId }));
  });
  app.delete('/api/sessions/:id', async (req, reply) => {
    const user = await requireUser(db, req);
    const id = z.string().uuid().parse((req.params as {id: string}).id);
    const result = await db.query('DELETE FROM user_sessions WHERE id=$1 AND user_id=$2 RETURNING id', [id, user.id]);
    if (!result.rows.length) return fail('not_found', 404);
    await recordAudit(db, user.id, 'session.revoked', id);
    if (id === user.sessionId) clearSession(reply);
    return { ok: true };
  });
  app.post('/api/auth/logout', async (req, reply) => {
    if (req.cookies.tl_session) await db.query('DELETE FROM user_sessions WHERE token_hash=$1', [hash(req.cookies.tl_session)]);
    if (req.cookies.tl_challenge) await db.query('DELETE FROM auth_challenges WHERE binding_hash=$1', [hash(req.cookies.tl_challenge)]);
    clearChallenge(reply); clearSession(reply);
    return { ok: true };
  });
  app.post('/api/auth/logout-all', async (req, reply) => {
    const user = await requireUser(db, req);
    await db.transaction(async (tx) => {
      await tx.query('DELETE FROM user_sessions WHERE user_id=$1', [user.id]);
      await tx.query('DELETE FROM auth_challenges WHERE user_id=$1', [user.id]);
      await recordAudit(tx, user.id, 'sessions.revoked_all');
    });
    clearSession(reply); clearChallenge(reply);
    return { ok: true };
  });
  app.get('/api/account/export', async (req, reply) => {
    const user = await requireRecentUser(db, req);
    reply.header('Content-Disposition', 'attachment; filename="templogin-account.json"');
    return db.transaction(async (tx) => {
      const profile = (await tx.query('SELECT id,name,created_at FROM users WHERE id=$1', [user.id])).rows[0];
      const passkeys = (await tx.query('SELECT id,name,created_at,device_type,backed_up FROM passkeys WHERE user_id=$1', [user.id])).rows;
      const sessions = (await tx.query('SELECT id,created_at,expires_at FROM user_sessions WHERE user_id=$1', [user.id])).rows;
      const grants = (await tx.query('SELECT * FROM grants WHERE user_id=$1', [user.id])).rows;
      const audit = (await tx.query('SELECT * FROM audit_events WHERE user_id=$1', [user.id])).rows;
      const connections = (await tx.query('SELECT id,provider_id,subject,scopes,status,created_at,updated_at FROM oauth_connections WHERE user_id=$1', [user.id])).rows;
      return { exported_at: new Date().toISOString(), profile, passkeys, sessions, grants, audit, connections };
    });
  });
  app.delete('/api/account', async (req, reply) => {
    const user = await requireRecentUser(db, req);
    await db.transaction(async (tx) => {
      await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [user.id]);
      await requireRecentUser(tx, req);
      const owned = await tx.query<{id: string}>(
        `SELECT o.id FROM organizations o JOIN organization_members m ON m.organization_id=o.id
         WHERE m.user_id=$1 AND m.role='owner' FOR UPDATE OF o`, [user.id]);
      for (const organization of owned.rows) {
        const others = await tx.query('SELECT user_id FROM organization_members WHERE organization_id=$1 AND user_id<>$2', [organization.id, user.id]);
        if (others.rows.length) return fail('organization_transfer_required', 409);
        await tx.query('DELETE FROM organizations WHERE id=$1', [organization.id]);
      }
      await tx.query('DELETE FROM auth_challenges WHERE user_id=$1', [user.id]);
      await tx.query('DELETE FROM users WHERE id=$1', [user.id]);
    });
    clearSession(reply); clearChallenge(reply);
    return { ok: true };
  });
}
