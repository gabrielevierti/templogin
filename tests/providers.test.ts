import {beforeAll,afterAll,describe,it,expect} from 'vitest';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {createDatabase,type Database} from '../services/api/database.js';
import {registerProviders} from '../services/api/providers.js';
import {TokenVault,type OAuthProviderConfig} from '../packages/connector-sdk/index.js';
const origin='https://app.example';
const config={origin,rpID:'app.example',legacyWallet:true,production:false,port:3000};
const provider:OAuthProviderConfig={id:'test',issuer:'https://issuer.example',clientId:'test-client',clientSecret:'test-secret',redirectUri:origin+'/api/providers/test/callback',scopes:['profile'],oidc:false};
const response=(body:unknown)=>new Response(JSON.stringify(body),{status:200,headers:{'Content-Type':'application/json'}});
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
let db:Database;const app=Fastify();let first:{id:string;session:string;cookie:string},second:{id:string;session:string;cookie:string};let failRefresh=false;
async function seed(){
  const id=randomUUID(),session=randomUUID(),token=randomBytes(32).toString('base64url'),now=Date.now();
  await db.query('INSERT INTO users(id,name,created_at) VALUES($1,$2,$3)',[id,'Provider test',now]);
  await db.query('INSERT INTO user_sessions(id,user_id,token_hash,created_at,expires_at,authenticated_at) VALUES($1,$2,$3,$4,$5,$4)',[session,id,sha(token),now,now+3600000]);
  return {id,session,cookie:'tl_session='+token};
}
async function begin(who=first){
  const result=await app.inject({method:'POST',url:'/api/providers/test/link',headers:{origin,cookie:who.cookie},payload:{}});
  expect(result.statusCode).toBe(200);
  const auth=new URL(result.json().authorization_url),state=auth.searchParams.get('state');
  const binding=result.cookies.find(c=>c.name==='tl_oauth_binding');expect(binding?.sameSite).toBe('Lax');expect(binding?.httpOnly).toBe(true);expect(binding?.secure).toBe(true);
  return {callback:'/api/providers/test/callback?code=code&state='+state+'&iss='+encodeURIComponent(provider.issuer),cookie:'tl_oauth_binding='+binding!.value,state};
}
beforeAll(async()=>{
  db=await createDatabase(config);first=await seed();second=await seed();
  await app.register(cookie);
  await registerProviders(app,db,config,{providers:[provider],vault:new TokenVault('test',{test:randomBytes(32)}),transport:async(input,init)=>{
    const url=String(input);
    if(url.includes('/.well-known/'))return response({issuer:provider.issuer,authorization_endpoint:provider.issuer+'/authorize',token_endpoint:provider.issuer+'/token',revocation_endpoint:provider.issuer+'/revoke',code_challenge_methods_supported:['S256'],authorization_response_iss_parameter_supported:true});
    if(url.endsWith('/token')){
      const body=new URLSearchParams(String(init?.body));
      if(body.get('grant_type')==='refresh_token'&&failRefresh)throw new Error('Simulated lost provider response');
      return response({access_token:'private-access-'+randomUUID(),refresh_token:'private-refresh-'+randomUUID(),token_type:'Bearer',expires_in:3600,scope:'profile'});
    }
    if(url.endsWith('/revoke'))return new Response('',{status:200});
    throw new Error('unexpected_provider_endpoint');
  }});
  await app.ready();
},30000);
afterAll(async()=>{await app.close();await db?.close();});
describe('provider routes with actual PostgreSQL persistence and synthetic provider transport',()=>{
  it('links with a Lax bound callback without sending the Strict session cookie, encrypts tokens and consumes state',async()=>{
    const flow=await begin();
    const callback=await app.inject({method:'GET',url:flow.callback,headers:{cookie:flow.cookie}});
    expect(callback.statusCode).toBe(302);expect(callback.headers.location).toBe('/connections?linked=1');
    const row=(await db.query<{token_envelope:unknown}>('SELECT token_envelope FROM oauth_connections WHERE user_id=$1',[first.id])).rows[0];
    expect(JSON.stringify(row.token_envelope)).not.toContain('private-access');expect(JSON.stringify(row.token_envelope)).not.toContain('private-refresh');
    const list=await app.inject({method:'GET',url:'/api/connections',headers:{cookie:first.cookie}});expect(list.json()).toHaveLength(1);expect(list.body).not.toContain('token_envelope');
    const replay=await app.inject({method:'GET',url:flow.callback,headers:{cookie:flow.cookie}});expect(replay.headers.location).toBe('/connections?error=oauth_failed');
  });
  it('isolates connection metadata and unlink from another user',async()=>{
    const connection=(await db.query<{id:string}>('SELECT id FROM oauth_connections WHERE user_id=$1',[first.id])).rows[0];
    const list=await app.inject({method:'GET',url:'/api/connections',headers:{cookie:second.cookie}});expect(list.json()).toEqual([]);
    const deletion=await app.inject({method:'DELETE',url:'/api/connections/'+connection.id,headers:{cookie:second.cookie,origin}});expect(deletion.statusCode).toBe(404);
  });
  it('rotates provider tokens then fails closed after an uncertain refresh result',async()=>{
    const connection=(await db.query<{id:string;token_envelope:unknown}>('SELECT id,token_envelope FROM oauth_connections WHERE user_id=$1',[first.id])).rows[0];
    const ok=await app.inject({method:'POST',url:'/api/connections/'+connection.id+'/refresh',headers:{cookie:first.cookie,origin},payload:{}});expect(ok.json()).toEqual({status:'linked'});
    const after=(await db.query<{token_envelope:unknown}>('SELECT token_envelope FROM oauth_connections WHERE id=$1',[connection.id])).rows[0];expect(after.token_envelope).not.toEqual(connection.token_envelope);
    failRefresh=true;
    const failed=await app.inject({method:'POST',url:'/api/connections/'+connection.id+'/refresh',headers:{cookie:first.cookie,origin},payload:{}});expect(failed.statusCode).toBe(409);expect(failed.json()).toEqual({error:'reauthorization_required'});
    failRefresh=false;
    const blocked=await app.inject({method:'POST',url:'/api/connections/'+connection.id+'/refresh',headers:{cookie:first.cookie,origin},payload:{}});expect(blocked.statusCode).toBe(409);
  });
  it('unlinks locally with truthful provider-token-only revocation result',async()=>{
    const connection=(await db.query<{id:string}>('SELECT id FROM oauth_connections WHERE user_id=$1',[first.id])).rows[0];
    const result=await app.inject({method:'DELETE',url:'/api/connections/'+connection.id,headers:{cookie:first.cookie,origin}});
    expect(result.json()).toEqual({status:'unlinked',provider_revocation:'revocation_requested'});
    expect((await db.query('SELECT id FROM oauth_connections WHERE id=$1',[connection.id])).rows).toEqual([]);
  });
  it('rejects callback when its initiating browser session has been revoked',async()=>{
    const isolated=await seed(),flow=await begin(isolated);
    await db.query('DELETE FROM user_sessions WHERE id=$1',[isolated.session]);
    const result=await app.inject({method:'GET',url:flow.callback,headers:{cookie:flow.cookie}});expect(result.headers.location).toBe('/connections?error=oauth_failed');
    expect((await db.query('SELECT id FROM oauth_connections WHERE user_id=$1',[isolated.id])).rows).toEqual([]);
  });
  it('rejects mismatched browser binding and expired pending authorization',async()=>{
    const flow=await begin();
    const wrong=await app.inject({method:'GET',url:flow.callback,headers:{cookie:'tl_oauth_binding='+randomBytes(32).toString('base64url')}});expect(wrong.headers.location).toBe('/connections?error=oauth_failed');
    await db.query('UPDATE oauth_pending SET expires_at=$1 WHERE state_hash=$2',[Date.now()-1,sha(flow.state!)]);
    const expired=await app.inject({method:'GET',url:flow.callback,headers:{cookie:flow.cookie}});expect(expired.headers.location).toBe('/connections?error=oauth_failed');
  });
});
