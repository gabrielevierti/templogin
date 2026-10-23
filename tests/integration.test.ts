import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { TempLoginDevice } from '../packages/sdk-js/index.js';
import { createApp } from '../services/api/app.js';
import { createDatabase, type Database } from '../services/api/database.js';

const origin = 'http://localhost:3000';
const config = { origin, rpID: 'localhost', legacyWallet: true,production: false, port: 3000, databaseUrl: process.env.TEST_DATABASE_URL };
let app: FastifyInstance;
let db: Database;
let ipIndex = 0;
const userId = randomUUID();
const otherId = randomUUID();
const session = randomBytes(32).toString('base64url');
const otherSession = randomBytes(32).toString('base64url');
const cookie = `tl_session=${session}`;
const otherCookie = `tl_session=${otherSession}`;
let time = Date.now();
const hash = (s: string) => createHash('sha256').update(s).digest('hex');
function advance(ms = 4000) { time += ms; vi.spyOn(Date, 'now').mockReturnValue(time); }
function req(method: 'GET' | 'POST' | 'DELETE', url: string, payload?: object, userCookie?: string, headers: Record<string,string> = {}) {
  return app.inject({ method, url: `/api${url}`, payload, remoteAddress: `10.0.${Math.floor(ipIndex / 250)}.${++ipIndex % 250 + 1}`, headers: { origin, ...(userCookie ? { cookie: userCookie } : {}), ...headers } });
}
async function newPair(scopes = ['profile:read','content:read'], extra: object = {}) {
  const res = await req('POST','/pairings',{client_id:'demo-tv',device_name:'Guest TV',scopes,...extra});
  expect(res.statusCode, res.body).toBe(200);
  return res.json<{device_code:string;user_code:string;verification_uri_complete:string;expires_in:number}>();
}
async function approve(pair: {user_code:string}, scopes = ['profile:read','content:read'], duration_seconds = 3600) {
  return req('POST',`/pairings/${pair.user_code}/decision`,{approve:true,matching_code:pair.user_code,scopes,duration_seconds},cookie);
}
async function exchange(pair: {device_code:string}, client_id = 'demo-tv') {
  return req('POST','/token',{grant_type:'urn:ietf:params:oauth:grant-type:device_code',device_code:pair.device_code,client_id});
}
async function authorized(scopes = ['profile:read','content:read']) {
  const pair = await newPair();
  const decision = await approve(pair, scopes);
  expect(decision.statusCode, decision.body).toBe(200);
  const res = await exchange(pair);
  expect(res.statusCode, res.body).toBe(200);
  return res.json<{access_token:string;refresh_token:string;grant_id:string;scope:string;expires_in:number}>();
}
const bearer = (token: string) => ({authorization:`Bearer ${token}`});

beforeAll(async () => {
  if (config.databaseUrl && !new URL(config.databaseUrl).pathname.toLowerCase().includes('test')) throw new Error('TEST_DATABASE_URL must name a disposable database containing test');
  db = await createDatabase(config);
  if (config.databaseUrl) await db.exec('TRUNCATE users, organizations, auth_challenges, pairings, rate_limits CASCADE');
  app = await createApp(config,db);
  for (const [id,token,name] of [[userId,session,'Alice'],[otherId,otherSession,'Bob']]) {
    await db.query('INSERT INTO users(id,name,created_at) VALUES($1,$2,$3)',[id,name,time]);
    await db.query('INSERT INTO user_sessions(id,user_id,token_hash,created_at,expires_at,authenticated_at) VALUES($1,$2,$3,$4,$5,$4)',[randomUUID(),id,hash(token),time,time+86400000]);
  }
});
afterEach(() => { vi.restoreAllMocks(); time = Date.now(); });
afterAll(async () => { await app?.close(); await db?.close(); });

describe('Persistent device authorization: actual PostgreSQL engine', () => {
  it('keeps credentials out of the QR, requires authentication and consent', async () => {
    const pair = await newPair();
    expect(pair.verification_uri_complete).not.toContain(pair.device_code);
    expect(pair.verification_uri_complete).toContain(pair.user_code);
    expect((await req('GET',`/pairings/${pair.user_code}`)).statusCode).toBe(401);
    const pending = await exchange(pair);
    expect(pending.json().error).toBe('authorization_pending');
    const consent = await req('GET',`/pairings/${pair.user_code}`,undefined,cookie);
    expect(consent.json()).toMatchObject({identity:'unverified',device_name:'Guest TV'});
  });
  it('rejects a mismatched screen code, then issues only approved scopes once', async () => {
    const pair = await newPair();
    const wrong = await req('POST',`/pairings/${pair.user_code}/decision`,{approve:true,matching_code:'WRONG',scopes:['content:read'],duration_seconds:3600},cookie);
    expect(wrong.statusCode).toBeGreaterThanOrEqual(400);
    expect((await approve(pair,['content:read'])).statusCode).toBe(200);
    const res = await exchange(pair);
    expect(res.statusCode,res.body).toBe(200);
    const token = res.json();
    expect(token.scope).toBe('content:read');
    const resource = await req('GET','/resource',undefined,undefined,bearer(token.access_token));
    expect(resource.statusCode).toBe(200);
    expect(resource.json().profile?.name).toBeUndefined();
    advance();
    expect((await exchange(pair)).statusCode).toBeGreaterThanOrEqual(400);
    expect((await approve(pair)).statusCode).toBeGreaterThanOrEqual(400);
  });
  it('denies privilege expansion and unsupported client scopes', async () => {
    const pair = await newPair(['content:read']);
    expect((await approve(pair,['content:read','profile:read'])).statusCode).toBeGreaterThanOrEqual(400);
    expect((await req('POST','/pairings',{client_id:'demo-tv',device_name:'TV',scopes:['admin:all']})).statusCode).toBe(400);
  });
  it('records explicit refusal without authorizing the device', async () => {
    const pair = await newPair();
    const decision = await req('POST',`/pairings/${pair.user_code}/decision`,{approve:false,matching_code:pair.user_code,scopes:[],duration_seconds:60},cookie);
    expect(decision.statusCode,decision.body).toBe(200);
    expect((await exchange(pair)).json().error).toBe('access_denied');
  });
  it('enforces pairing expiry without a scheduled cleanup job', async () => {
    const pair = await newPair();
    advance(301000);
    expect((await exchange(pair)).json().error).toBe('expired_token');
    expect((await approve(pair)).statusCode).toBeGreaterThanOrEqual(400);
  });
  it('throttles early polling and rejects a substituted client', async () => {
    const pair = await newPair();
    expect((await exchange(pair,'demo-car')).statusCode).toBeGreaterThanOrEqual(400);
    expect((await exchange(pair)).json().error).toBe('authorization_pending');
    expect((await exchange(pair)).json().error).toBe('slow_down');
  });
  it('atomically consumes one approval under simultaneous exchanges', async () => {
    const pair = await newPair();
    expect((await approve(pair)).statusCode).toBe(200);
    const results = await Promise.all([exchange(pair),exchange(pair),exchange(pair)]);
    expect(results.filter(x=>x.statusCode===200)).toHaveLength(1);
  });
  it('atomically handles competing approval and refusal', async () => {
    const pair = await newPair();
    const results = await Promise.all([
      approve(pair),
      req('POST',`/pairings/${pair.user_code}/decision`,{approve:false,matching_code:pair.user_code,scopes:[],duration_seconds:60},otherCookie),
    ]);
    expect(results.filter(x=>x.statusCode===200)).toHaveLength(1);
  });
  it('denies protected content when the required scope was not granted', async () => {
    const token = await authorized(['profile:read']);
    expect((await req('GET','/resource',undefined,undefined,bearer(token.access_token))).statusCode).toBe(403);
    expect((await req('GET','/resource')).statusCode).toBe(401);
  });
  it('revokes immediately and enforces ownership', async () => {
    const token = await authorized();
    expect((await req('DELETE',`/grants/${token.grant_id}`,undefined,otherCookie)).statusCode).toBeGreaterThanOrEqual(400);
    expect((await req('GET','/resource',undefined,undefined,bearer(token.access_token))).statusCode).toBe(200);
    expect((await req('DELETE',`/grants/${token.grant_id}`,undefined,cookie)).statusCode).toBe(200);
    expect((await req('GET','/resource',undefined,undefined,bearer(token.access_token))).statusCode).toBe(401);
    const refresh = await req('POST','/token',{grant_type:'refresh_token',refresh_token:token.refresh_token,client_id:'demo-tv'});
    expect(refresh.statusCode).toBeGreaterThanOrEqual(400);
  });
  it('rotates refresh tokens and revokes the family on reuse', async () => {
    const token = await authorized();
    const refresh = () => req('POST','/token',{grant_type:'refresh_token',refresh_token:token.refresh_token,client_id:'demo-tv'});
    const next = await refresh();
    expect(next.statusCode,next.body).toBe(200);
    expect(next.json().refresh_token).not.toBe(token.refresh_token);
    expect((await refresh()).statusCode).toBeGreaterThanOrEqual(400);
    expect((await req('GET','/resource',undefined,undefined,bearer(next.json().access_token))).statusCode).toBe(401);
  });
  it('rejects expired access even while disconnected from the UI', async () => {
    const token = await authorized();
    advance((token.expires_in+1)*1000);
    expect((await req('GET','/resource',undefined,undefined,bearer(token.access_token))).statusCode).toBe(401);
  });
  it('runs the public SDK against the real API and database', async () => {
    const transport: typeof fetch = async (input,init) => {
      const url = new URL(String(input));
      const headers: Record<string,string> = {};
      new Headers(init?.headers).forEach((value,key)=>{headers[key]=value;});
      const response = await app.inject({method:(init?.method || 'GET') as 'GET'|'POST',url:url.pathname,headers,payload:init?.body ? String(init.body) : undefined,remoteAddress:'192.0.2.90'});
      return new Response(response.body,{status:response.statusCode,headers:{'Content-Type':'application/json'}});
    };
    const sdk = new TempLoginDevice(origin,'demo-tv',transport);
    const pair = await sdk.begin('SDK integration',['content:read','profile:read']);
    expect((await approve(pair)).statusCode).toBe(200);
    const tokens = await sdk.waitForApproval(pair);
    expect((await sdk.resource()).profile.name).toBe('Alice');
    const refreshed = await sdk.refresh();
    expect(refreshed.refresh_token).not.toBe(tokens.refresh_token);
    await sdk.logout();
    await expect(sdk.resource()).rejects.toThrow('not_authorized');
    expect((await req('GET','/resource',undefined,undefined,bearer(refreshed.access_token))).statusCode).toBe(401);
  });
  it('refuses refresh after the grant deadline without cleanup', async () => {
    const pair = await newPair();
    expect((await approve(pair,undefined,60)).statusCode).toBe(200);
    const result = (await exchange(pair)).json();
    advance(61000);
    expect((await req('POST','/token',{grant_type:'refresh_token',refresh_token:result.refresh_token,client_id:'demo-tv'})).json().error).toBe('invalid_grant');
    expect((await req('GET','/resource',undefined,undefined,bearer(result.access_token))).statusCode).toBe(401);
  });
  it('device logout invalidates its authorization', async () => {
    const token = await authorized();
    expect((await req('POST','/device/logout',{},undefined,bearer(token.access_token))).statusCode).toBe(200);
    expect((await req('GET','/resource',undefined,undefined,bearer(token.access_token))).statusCode).toBe(401);
  });
});

describe('Sessions, isolation and request security', () => {
  it('rejects cross-site and missing-origin cookie mutations', async () => {
    expect((await req('POST','/auth/logout',{},cookie,{origin:'https://attacker.invalid'})).statusCode).toBe(403);
    const res = await app.inject({method:'POST',url:'/api/auth/logout',payload:{},headers:{cookie}});
    expect(res.statusCode).toBe(403);
    expect((await req('GET','/me',undefined,cookie)).statusCode).toBe(200);
  });
  it('rejects unverified and replayed registration responses', async () => {
    const options = await req('POST','/auth/register/options',{name:'Never registered'});
    expect(options.statusCode,options.body).toBe(200);
    const challengeCookie = options.headers['set-cookie'];
    const first = Array.isArray(challengeCookie) ? challengeCookie[0] : challengeCookie;
    const bad = await req('POST','/auth/register/verify',{response:{}},first?.split(';')[0]);
    expect(bad.statusCode).toBeGreaterThanOrEqual(400);
    expect((await req('POST','/auth/register/verify',{response:{}},first?.split(';')[0])).statusCode).toBeGreaterThanOrEqual(400);
  });
  it('does not expose other users sessions or grant records', async () => {
    const mine = (await req('GET','/sessions',undefined,cookie)).json();
    const theirs = (await req('GET','/sessions',undefined,otherCookie)).json();
    expect(mine.length).toBe(1); expect(theirs.length).toBe(1);
    expect((await req('DELETE',`/sessions/${theirs[0].id}`,undefined,cookie)).statusCode).toBeGreaterThanOrEqual(400);
    const grants = (await req('GET','/grants',undefined,otherCookie)).json();
    expect(grants.every((g: {user_id?:string})=>!g.user_id || g.user_id===otherId)).toBe(true);
  });
  it('rate limits registration requests from one source', async () => {
    const responses = [];
    for(let i=0;i<25;i++) responses.push(await app.inject({method:'POST',url:'/api/auth/login/options',payload:{},remoteAddress:'192.0.2.4',headers:{origin}}));
    expect(responses.some(x=>x.statusCode===429)).toBe(true);
  });
  it('isolates tenants and confirms only native revocation at checkout', async () => {
    const org = (await req('POST','/organizations',{name:'House A'},cookie)).json();
    expect(org.id).toBeTruthy();
    expect((await req('GET',`/organizations/${org.id}`,undefined,otherCookie)).statusCode).toBeGreaterThanOrEqual(400);
    const property = (await req('POST',`/organizations/${org.id}/properties`,{name:'Apartment'},cookie)).json();
    const device = (await req('POST',`/organizations/${org.id}/devices`,{name:'Living TV',property_id:property.id,client_id:'demo-tv'},cookie)).json();
    const stay = (await req('POST',`/organizations/${org.id}/stays`,{property_id:property.id,guest_label:'Guest',starts_at:time-1000,ends_at:time+3600000},cookie)).json();
    const pair = await newPair(undefined,{device_id:device.id,device_secret:device.secret});
    expect((await approve(pair,undefined,600)).statusCode).toBe(200);
    const token = (await exchange(pair)).json();
    expect((await req('GET','/resource',undefined,undefined,bearer(token.access_token))).statusCode).toBe(200);
    const denied = await req('POST',`/organizations/${org.id}/stays/${stay.id}/checkout`,{},otherCookie);
    expect(denied.statusCode).toBeGreaterThanOrEqual(400);
    const checkout = await req('POST',`/organizations/${org.id}/stays/${stay.id}/checkout`,{},cookie);
    expect(checkout.json()).toMatchObject({status:'revocation_verified',external_status:'manual_verification_required'});
    expect((await req('GET','/resource',undefined,undefined,bearer(token.access_token))).statusCode).toBe(401);
    const details = (await req('GET',`/organizations/${org.id}`,undefined,cookie)).json();
    expect(JSON.stringify(details)).not.toContain(device.secret);
  });
  it('host reset invalidates an outstanding QR before it can be approved', async () => {
    const org = (await req('POST','/organizations',{name:'House reset'},cookie)).json();
    const property = (await req('POST',`/organizations/${org.id}/properties`,{name:'Room'},cookie)).json();
    const device = (await req('POST',`/organizations/${org.id}/devices`,{name:'Reset TV',property_id:property.id,client_id:'demo-tv'},cookie)).json();
    await req('POST',`/organizations/${org.id}/stays`,{property_id:property.id,guest_label:'Guest',starts_at:time-1000,ends_at:time+3600000},cookie);
    const pair = await newPair(undefined,{device_id:device.id,device_secret:device.secret});
    const reset = await req('POST',`/organizations/${org.id}/devices/${device.id}/revoke`,{},cookie);
    expect(reset.statusCode,reset.body).toBe(200);
    expect((await approve(pair)).statusCode).toBeGreaterThanOrEqual(400);
    expect((await exchange(pair)).statusCode).toBeGreaterThanOrEqual(400);
  });
  it('deletes personal account data and prevents continued device access', async () => {
    const token = await authorized();
    const exportResult = await req('GET','/account/export',undefined,cookie);
    expect(exportResult.statusCode).toBe(200);
    expect(exportResult.body).not.toContain(session);
    const deleted = await req('DELETE','/account',undefined,cookie);
    expect(deleted.statusCode,deleted.body).toBe(200);
    expect((await req('GET','/me',undefined,cookie)).statusCode).toBe(401);
    expect((await req('GET','/resource',undefined,undefined,bearer(token.access_token))).statusCode).toBe(401);
  });
});
