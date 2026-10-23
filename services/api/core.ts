import type { FastifyInstance, FastifyRequest } from 'fastify';
import { randomInt } from 'node:crypto';
import { z } from 'zod';
import type { Database } from './database.js';
import type { Config } from './config.js';
import { requireUser } from './auth.js';
import { hash, token, id, audit, fail } from './security.js';
import {sessionDeadline,credentialDeadline} from '../../packages/connector-sdk/session-policy.js';

type Grant = {id:string;user_id:string;device_id:string|null;stay_id:string|null;client_id:string;device_name:string;scopes:string[];created_at:number;expires_at:number;revoked_at:number|null;revoke_reason:string|null};
type Pairing = {id:string;user_code:string;client_id:string;device_name:string;device_id:string|null;stay_id:string|null;scopes:string[];status:string;expires_at:number;last_poll_at:number;poll_interval:number;grant_id:string|null};
const clients = { 'demo-tv':['content:read','profile:read'], 'demo-car':['preferences:read','profile:read'] } as const;
const clientSchema = z.enum(['demo-tv','demo-car']);
const scopesSchema = z.array(z.enum(['content:read','preferences:read','profile:read'])).min(1).max(3).refine(s=>new Set(s).size===s.length);
const codeSchema = z.string().regex(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
const userCode = () => { const a='ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; const s=Array.from({length:8},()=>a[randomInt(a.length)]).join(''); return s.slice(0,4)+'-'+s.slice(4); };
const maxDuration = 86400;
const grantStatus = (g:Grant) => g.revoked_at ? 'revoked' : Number(g.expires_at)<=Date.now() ? 'expired':'active';
async function stayValid(db:Database,stayId:string|null,lock=false):Promise<number|null> {
  if (!stayId) return null;
  const s=(await db.query<{ends_at:number;starts_at:number;checked_out_at:number|null}>(`SELECT ends_at,starts_at,checked_out_at FROM stays WHERE id=$1${lock?' FOR UPDATE':''}`,[stayId])).rows[0];
  if(!s || s.checked_out_at || Number(s.ends_at)<=Date.now() || Number(s.starts_at)>Date.now()) fail(400,'stay_inactive');
  return Number(s.ends_at);
}
async function issue(tx:Database,g:Grant) {
  const now=Date.now();
  if(Number(g.expires_at)<=now) fail(400,'invalid_grant');
  const expires=credentialDeadline(now,Number(g.expires_at),60), access=token(), refresh=token();
  await tx.query('INSERT INTO access_tokens(token_hash,grant_id,expires_at) VALUES($1,$2,$3)',[hash(access),g.id,expires]);
  await tx.query('INSERT INTO refresh_tokens(token_hash,grant_id,expires_at,created_at) VALUES($1,$2,$3,$4)',[hash(refresh),g.id,g.expires_at,now]);
  return {access_token:access,refresh_token:refresh,token_type:'Bearer',expires_in:Math.max(0,Math.floor((expires-now)/1000)),grant_id:g.id,grant_expires_at:Number(g.expires_at),scope:g.scopes.join(' ')};
}
export async function bearerGrant(db:Database,req:FastifyRequest):Promise<Grant> {
  const m=/^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization||'');
  if(!m) fail(401,'invalid_token');
  const row=(await db.query<Grant & {token_expiry:number}>('SELECT g.*,t.expires_at AS token_expiry FROM access_tokens t JOIN grants g ON g.id=t.grant_id WHERE t.token_hash=$1',[hash(m[1])])).rows[0];
  if(!row || grantStatus(row)!=='active' || Number(row.token_expiry)<=Date.now()) fail(401,'invalid_token');
  try { await stayValid(db,row.stay_id); } catch { fail(401,'invalid_token'); }
  return row;
}
export async function registerCore(app:FastifyInstance,db:Database,config:Config) {
  app.post('/api/pairings',async req=>{
    const b=z.object({client_id:clientSchema,device_name:z.string().trim().min(1).max(80),scopes:scopesSchema,device_id:z.string().uuid().optional(),device_secret:z.string().min(32).max(100).optional()}).strict().parse(req.body);
    if(b.scopes.some(s=>!(clients[b.client_id] as readonly string[]).includes(s))) fail(400,'invalid_scope');
    if(Boolean(b.device_id)!==Boolean(b.device_secret)) fail(400,'invalid_device');
    return db.transaction(async tx=>{
      let name=b.device_name,stayId:string|null=null;
      if(b.device_id){
        const device=(await tx.query<{name:string;secret_hash:string;client_id:string;property_id:string}>('SELECT * FROM devices WHERE id=$1 FOR UPDATE',[b.device_id])).rows[0];
        if(!device || device.secret_hash!==hash(b.device_secret!) || device.client_id!==b.client_id) fail(401,'invalid_device');
        name=device.name;
        // Serialize against stay creation/checkout for the registered property's admission.
        await tx.query('SELECT id FROM properties WHERE id=$1 FOR UPDATE',[device.property_id]);
        const stay=(await tx.query<{id:string}>('SELECT id FROM stays WHERE property_id=$1 AND checked_out_at IS NULL AND starts_at<=$2 AND ends_at>$2 ORDER BY starts_at DESC LIMIT 1',[device.property_id,Date.now()])).rows[0];
        if(!stay) fail(400,'stay_inactive');
        stayId=stay.id;
      }
      const code=userCode(),secret=token(),now=Date.now();
      await tx.query('INSERT INTO pairings(id,device_code_hash,user_code,client_id,device_name,device_id,stay_id,scopes,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',[id(),hash(secret),code,b.client_id,name,b.device_id||null,stayId,JSON.stringify(b.scopes),now,now+300000]);
      return {device_code:secret,user_code:code,verification_uri:config.origin+'/approve',verification_uri_complete:config.origin+'/approve?code='+code,expires_in:300,interval:3};
    });
  });
  app.get<{Params:{code:string}}>('/api/pairings/:code',async req=>{
    await requireUser(db,req);const code=codeSchema.parse(req.params.code.toUpperCase());
    const p=(await db.query<Pairing>('SELECT * FROM pairings WHERE user_code=$1',[code])).rows[0];
    if(!p) fail(404,'pairing_not_found');
    const end=await stayValid(db,p.stay_id);
    return {user_code:p.user_code,device_name:p.device_name,client_id:p.client_id,scopes:p.scopes,expires_at:Number(p.expires_at),status:Number(p.expires_at)<=Date.now()?'expired':p.status,identity:p.device_id?'registered':'unverified',max_duration_seconds:Math.max(0,Math.min(maxDuration,end?Math.floor((end-Date.now())/1000):maxDuration))};
  });
  app.post<{Params:{code:string}}>('/api/pairings/:code/decision',async req=>{
    const u=await requireUser(db,req),code=codeSchema.parse(req.params.code.toUpperCase());
    const b=z.object({approve:z.boolean(),matching_code:z.string(),scopes:z.array(z.string()).max(3),duration_seconds:z.number().int().min(1).max(maxDuration)}).strict().parse(req.body);
    return db.transaction(async tx=>{
      await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[u.id]);
      const before=(await tx.query<Pairing>('SELECT * FROM pairings WHERE user_code=$1',[code])).rows[0];
      if(before?.device_id) await tx.query('SELECT id FROM devices WHERE id=$1 FOR UPDATE',[before.device_id]);
      const p=(await tx.query<Pairing>('SELECT * FROM pairings WHERE user_code=$1 FOR UPDATE',[code])).rows[0];
      await requireUser(tx,req);
      if(!p) fail(404,'pairing_not_found');
      if(Number(p.expires_at)<=Date.now()) fail(400,'expired_token');
      if(p.status!=='pending') fail(409,'pairing_already_decided');
      if(b.matching_code!==p.user_code) fail(400,'code_mismatch');
      if(!b.approve){await tx.query("UPDATE pairings SET status='denied' WHERE id=$1",[p.id]);await audit(tx,u.id,'pairing.denied',p.id);return {status:'denied'};}
      if(!b.scopes.length || new Set(b.scopes).size!==b.scopes.length || b.scopes.some(s=>!p.scopes.includes(s))) fail(400,'invalid_scope');
      const end=await stayValid(tx,p.stay_id,true),now=Date.now();
      const expires=sessionDeadline({now,durationSeconds:b.duration_seconds,maxDurationSeconds:maxDuration,stayEndsAt:end??undefined});
      if(expires<=now) fail(400,'stay_inactive');
      const grantId=id();
      await tx.query('INSERT INTO grants(id,user_id,device_id,stay_id,client_id,device_name,scopes,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[grantId,u.id,p.device_id,p.stay_id,p.client_id,p.device_name,JSON.stringify(b.scopes),now,expires]);
      await tx.query("UPDATE pairings SET status='approved',grant_id=$1 WHERE id=$2",[grantId,p.id]);
      await audit(tx,u.id,'pairing.approved',grantId);
      return {status:'approved',grant_id:grantId,expires_at:expires};
    });
  });
  app.post('/api/token',async(req,reply)=>{
    const b=z.discriminatedUnion('grant_type',[
      z.object({grant_type:z.literal('urn:ietf:params:oauth:grant-type:device_code'),device_code:z.string().length(43),client_id:clientSchema}).strict(),
      z.object({grant_type:z.literal('refresh_token'),refresh_token:z.string().length(43),client_id:clientSchema}).strict()
    ]).parse(req.body);
    const result=await db.transaction(async tx=>{
      if(b.grant_type==='refresh_token'){
        const owner=(await tx.query<{user_id:string}>('SELECT g.user_id FROM refresh_tokens t JOIN grants g ON g.id=t.grant_id WHERE t.token_hash=$1',[hash(b.refresh_token)])).rows[0];
        if(!owner)return {error:'invalid_grant'};
        await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[owner.user_id]);
        const r=(await tx.query<{grant_id:string;used_at:number|null;expires_at:number}>('SELECT * FROM refresh_tokens WHERE token_hash=$1 FOR UPDATE',[hash(b.refresh_token)])).rows[0];
        if(!r) return {error:'invalid_grant'};
        const g=(await tx.query<Grant>('SELECT * FROM grants WHERE id=$1 FOR UPDATE',[r.grant_id])).rows[0];
        if(!g || g.client_id!==b.client_id) return {error:'invalid_grant'};
        if(r.used_at){
          await tx.query("UPDATE grants SET revoked_at=COALESCE(revoked_at,$1),revoke_reason='refresh_reuse' WHERE id=$2",[Date.now(),g.id]);
          await audit(tx,g.user_id,'token.reuse_detected',g.id);
          return {error:'invalid_grant'};
        }
        if(grantStatus(g)!=='active' || Number(r.expires_at)<=Date.now()) return {error:'invalid_grant'};
        try{await stayValid(tx,g.stay_id);}catch{return {error:'invalid_grant'};}
        await tx.query('UPDATE refresh_tokens SET used_at=$1 WHERE token_hash=$2',[Date.now(),hash(b.refresh_token)]);
        return issue(tx,g);
      }
      const owner=(await tx.query<{user_id:string}>('SELECT g.user_id FROM pairings p JOIN grants g ON g.id=p.grant_id WHERE p.device_code_hash=$1',[hash(b.device_code)])).rows[0];
      if(owner)await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[owner.user_id]);
      const p=(await tx.query<Pairing>('SELECT * FROM pairings WHERE device_code_hash=$1 FOR UPDATE',[hash(b.device_code)])).rows[0];
      if(!p || p.client_id!==b.client_id) return {error:'invalid_grant'};
      if(Number(p.expires_at)<=Date.now()) return {error:'expired_token'};
      if(p.status==='consumed') return {error:'invalid_grant'};
      const now=Date.now();
      if(Number(p.last_poll_at)>0 && now-Number(p.last_poll_at)<p.poll_interval){
        await tx.query('UPDATE pairings SET poll_interval=LEAST(poll_interval+5000,60000),last_poll_at=$1 WHERE id=$2',[now,p.id]);
        return {error:'slow_down'};
      }
      await tx.query('UPDATE pairings SET last_poll_at=$1 WHERE id=$2',[now,p.id]);
      if(p.status==='denied') return {error:'access_denied'};
      if(p.status!=='approved' || !p.grant_id || !owner) return {error:'authorization_pending'};
      const g=(await tx.query<Grant>('SELECT * FROM grants WHERE id=$1 FOR UPDATE',[p.grant_id])).rows[0];
      if(!g || grantStatus(g)!=='active') return {error:'invalid_grant'};
      try{await stayValid(tx,g.stay_id);}catch{return {error:'invalid_grant'};}
      await tx.query("UPDATE pairings SET status='consumed' WHERE id=$1",[p.id]);
      await audit(tx,g.user_id,'token.issued',g.id);
      return issue(tx,g);
    });
    if('error' in result) return reply.code(400).send(result);
    return result;
  });
  app.get('/api/resource',async req=>{
    const g=await bearerGrant(db,req),needed=g.client_id==='demo-tv'?'content:read':'preferences:read';
    if(!g.scopes.includes(needed)) fail(403,'insufficient_scope');
    const u=(await db.query<{name:string}>('SELECT name FROM users WHERE id=$1',[g.user_id])).rows[0];
    return {kind:g.client_id==='demo-tv'?'tv':'car',profile:g.scopes.includes('profile:read')?{name:u.name}:{},message:g.client_id==='demo-tv'?'tempLogin original demo content':'Temporary driving profile',preferences:g.client_id==='demo-car'?{theme:'night',temperature:21}:undefined,expires_at:Number(g.expires_at),scopes:g.scopes};
  });
  app.post('/api/device/logout',async req=>{
    const g=await bearerGrant(db,req);
    await db.transaction(async tx=>{await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[g.user_id]);await tx.query("UPDATE grants SET revoked_at=COALESCE(revoked_at,$1),revoke_reason='device_logout' WHERE id=$2",[Date.now(),g.id]);await audit(tx,g.user_id,'grant.device_logout',g.id);});
    return {status:'revoked'};
  });
  app.get('/api/grants',async req=>{
    const u=await requireUser(db,req);
    const rows=(await db.query<Grant>('SELECT * FROM grants WHERE user_id=$1 ORDER BY created_at DESC LIMIT 500',[u.id])).rows;
    return rows.map(g=>({id:g.id,device_name:g.device_name,device_id:g.device_id,client_id:g.client_id,scopes:g.scopes,created_at:Number(g.created_at),expires_at:Number(g.expires_at),status:grantStatus(g)}));
  });
  app.delete<{Params:{id:string}}>('/api/grants/:id',async req=>{
    const u=await requireUser(db,req);
    await db.transaction(async tx=>{
      await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[u.id]);
      await requireUser(tx,req);
      const g=(await tx.query<Grant>('SELECT * FROM grants WHERE id=$1 AND user_id=$2 FOR UPDATE',[req.params.id,u.id])).rows[0];
      if(!g) fail(404,'not_found');
      await tx.query("UPDATE grants SET revoked_at=COALESCE(revoked_at,$1),revoke_reason='user' WHERE id=$2",[Date.now(),g.id]);await audit(tx,u.id,'grant.revoked',g.id);
    });return {status:'revoked'};
  });
  app.post('/api/grants/revoke-all',async req=>{
    const u=await requireUser(db,req);
    await db.transaction(async tx=>{await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[u.id]);await requireUser(tx,req);await tx.query("UPDATE grants SET revoked_at=$1,revoke_reason='user_all' WHERE user_id=$2 AND revoked_at IS NULL",[Date.now(),u.id]);await audit(tx,u.id,'grants.revoked_all');});return {status:'revoked'};
  });
  app.get('/api/audit',async req=>{const u=await requireUser(db,req);return (await db.query('SELECT action,target_id,created_at FROM audit_events WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200',[u.id])).rows;});
}
