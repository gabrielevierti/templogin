import {beforeAll,afterAll,beforeEach,it,expect} from 'vitest';
import {createApp} from '../services/api/app.js';
import {createDatabase,type Database} from '../services/api/database.js';
import type {ProviderOptions} from '../packages/provider-sdk/index.js';
let db:Database,app:Awaited<ReturnType<typeof createApp>>;
const origin='http://localhost:3000';
let entitled=true;
// Test-only identity boundary. A real adapter validates the provider session, not this header.
const provider:ProviderOptions={id:'test-provider',name:'Test Provider',origin,maxDurationSeconds:7200,
 async identity(req){const subject=req.headers['x-test-subject'];return typeof subject==='string'?{subject,displayName:subject,authenticatedAt:Date.now()}:null;},
 async entitled(){return entitled;}};
const call=(url:string,payload?:object,subject?:string,bearer?:string)=>app.inject({url:'/api/temporary/'+url,method:payload?'POST':'GET',headers:{origin,...(subject?{'x-test-subject':subject}:{}),...(bearer?{authorization:'Bearer '+bearer}:{})},payload});
beforeAll(async()=>{
 db=await createDatabase({production:false});app=await createApp({origin,rpID:'localhost',production:false,port:3000},db,provider);
});
afterAll(async()=>{await app.close();await db.close();});
beforeEach(async()=>{entitled=true;await db.exec('TRUNCATE tl_pairings,tl_provider_sessions,rate_limits');});
async function pair(){const response=await call('pairings',{device_name:'TV B&B'});expect(response.statusCode).toBe(200);return response.json();}
async function grant(subject='alice',duration=3600){const p=await pair();const response=await call('decision',{code:p.user_code,matching_code:p.user_code,approve:true,duration_seconds:duration},subject);expect(response.statusCode).toBe(200);const result=await call('token',{device_code:p.device_code});expect(result.statusCode).toBe(200);return {p,g:response.json(),t:result.json()};}
it('completes with provider identity without creating any tempLogin account',async()=>{
 const {p,g,t}=await grant();expect(p.verification_uri_complete).toContain('/approve?code=');expect(p.verification_uri_complete).not.toContain(p.device_code);
 expect((await call('content',undefined,undefined,t.access_token)).statusCode).toBe(200);
 expect(g.expires_at).toBe(t.expires_at);
 expect((await db.query('SELECT * FROM users')).rows).toHaveLength(0);
 expect((await db.query('SELECT * FROM passkeys')).rows).toHaveLength(0);
 expect((await app.inject('/api/me')).statusCode).toBe(404);
 const stored=(await db.query<{token_hash:string}>('SELECT token_hash FROM tl_provider_sessions')).rows[0];expect(stored.token_hash).not.toBe(t.access_token);
});
it('rejects missing identity, injected subject, wrong code and excessive duration',async()=>{
 const p=await pair();
 expect((await call('context?code='+p.user_code)).statusCode).toBe(401);
 const input={code:p.user_code,matching_code:p.user_code,approve:true,duration_seconds:3600};
 expect((await call('decision',input)).statusCode).toBe(401);
 expect((await call('decision',{...input,subject:'bob'},'alice')).statusCode).toBe(400);
 expect((await call('decision',{...input,matching_code:'ABCDE-FG234'},'alice')).statusCode).toBe(400);
 expect((await call('decision',{...input,duration_seconds:7201},'alice')).statusCode).toBe(400);
});
it('consumes decisions and exchanges exactly once under competition',async()=>{
 const p=await pair(),body={code:p.user_code,matching_code:p.user_code,approve:true,duration_seconds:3600};
 const decisions=await Promise.all([call('decision',body,'alice'),call('decision',body,'bob')]);expect(decisions.map(r=>r.statusCode).sort()).toEqual([200,409]);
 const exchanges=await Promise.all([call('token',{device_code:p.device_code}),call('token',{device_code:p.device_code})]);expect(exchanges.map(r=>r.statusCode).sort()).toEqual([200,400]);
 expect((await db.query('SELECT * FROM tl_provider_sessions')).rows).toHaveLength(1);
});
it('blocks expired sessions and pairing codes without scheduled cleanup',async()=>{
 const {p,g,t}=await grant();await db.query('UPDATE tl_provider_sessions SET expires_at=$1 WHERE id=$2',[Date.now(),g.session_id]);
 expect((await call('content',undefined,undefined,t.access_token)).statusCode).toBe(401);
 await db.query('UPDATE tl_pairings SET expires_at=$1 WHERE code=$2',[Date.now(),p.user_code]);expect((await call('context?code='+p.user_code,undefined,'alice')).statusCode).toBe(410);
});
it('enforces per-account revocation and preserves another TV session',async()=>{
 const one=await grant(),two=await grant();
 expect((await call('sessions',undefined,'bob')).json()).toEqual([]);
 expect((await call('sessions/'+one.g.session_id+'/revoke',{},'bob')).statusCode).toBe(404);
 expect((await call('sessions/'+one.g.session_id+'/revoke',{},'alice')).statusCode).toBe(200);
 expect((await call('content',undefined,undefined,one.t.access_token)).statusCode).toBe(401);
 expect((await call('content',undefined,undefined,two.t.access_token)).statusCode).toBe(200);
 expect((await call('logout',{},undefined,two.t.access_token)).statusCode).toBe(200);
 expect((await call('content',undefined,undefined,two.t.access_token)).statusCode).toBe(401);
});
it('denies cancelled consent, backs off polling and checks live entitlement',async()=>{
 const p=await pair();expect((await call('token',{device_code:p.device_code})).json().error).toBe('authorization_pending');
 expect((await call('token',{device_code:p.device_code})).json().error).toBe('slow_down');
 expect((await call('decision',{code:p.user_code,matching_code:p.user_code,approve:false,duration_seconds:3600},'alice')).statusCode).toBe(200);
 await db.query('UPDATE tl_pairings SET last_poll=0 WHERE code=$1',[p.user_code]);expect((await call('token',{device_code:p.device_code})).json().error).toBe('access_denied');
 const {t}=await grant();entitled=false;expect((await call('content',undefined,undefined,t.access_token)).statusCode).toBe(403);
});
it('rejects cross-origin consent and disables demo login for real adapters',async()=>{
 expect((await app.inject({method:'POST',url:'/api/temporary/pairings',headers:{origin:'https://evil.example'},payload:{device_name:'TV'}})).statusCode).toBe(403);
 expect((await app.inject({method:'POST',url:'/api/temporary/pairings',payload:{device_name:'TV'}})).statusCode).toBe(403);
 expect((await call('demo-login',{})).statusCode).toBe(404);
});
it('production cannot enable the fictional provider login',async()=>{
 const prod=await createApp({origin:'https://provider.example',rpID:'provider.example',production:true,databaseUrl:'postgres://unused/test',port:3000},db);
 try{expect((await prod.inject({method:'POST',url:'/api/temporary/demo-login',headers:{origin:'https://provider.example'},payload:{}})).statusCode).toBe(404);expect((await prod.inject('/api/temporary/mode')).json()).toEqual({demo:false,configured:false});}finally{await prod.close();}
});
it('rejects credentials belonging to a different provider namespace',async()=>{
 const {t}=await grant();const other=await createApp({origin,rpID:'localhost',production:false,port:3000},db,{...provider,id:'other'});
 try{expect((await other.inject({url:'/api/temporary/content',headers:{authorization:'Bearer '+t.access_token}})).statusCode).toBe(401);}finally{await other.close();}
});
