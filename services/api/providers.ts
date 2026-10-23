import type {FastifyInstance} from 'fastify';
import {z} from 'zod';
import * as oauth from 'oauth4webapi';
import {OAuthAccountConnector,TokenVault,type OAuthProviderConfig,type AuthorizationStore,type PendingAuthorization,type EncryptedToken} from '../../packages/connector-sdk/index.js';
import type {Database} from './database.js';
import type {Config} from './config.js';
import {requireUser,requireRecentUser} from './auth.js';
import {token,hash,id,audit,fail} from './security.js';

export interface ProviderSettings {providers:OAuthProviderConfig[];vault?:TokenVault;transport?:typeof fetch}
export function readProviderSettings(config:Config):ProviderSettings{
  const input=process.env.OAUTH_PROVIDERS_JSON;
  if(!input)return {providers:[]};
  const providers=z.array(z.object({id:z.string().regex(/^[a-z0-9-]{1,40}$/),issuer:z.url(),clientId:z.string().min(1),clientSecret:z.string().min(1).optional(),redirectUri:z.url(),scopes:z.array(z.string().min(1)).min(1),oidc:z.boolean(),allowedEndpointOrigins:z.array(z.url()).optional()}).strict()).max(20).parse(JSON.parse(input));
  if(new Set(providers.map(p=>p.id)).size!==providers.length||providers.some(p=>['templogin','external'].includes(p.id)))throw new Error('Invalid provider identifiers');
  for(const p of providers)if(p.redirectUri!==config.origin+'/api/providers/'+p.id+'/callback')throw new Error('Provider redirectUri must match PUBLIC_ORIGIN callback');
  if(!providers.length)return {providers};
  const keys=z.record(z.string(),z.string()).parse(JSON.parse(process.env.TOKEN_KEYRING||'{}'));
  const bytes=Object.fromEntries(Object.entries(keys).map(([kid,key])=>{if(!/^[A-Za-z0-9+/]{43}=$/.test(key))throw new Error('TOKEN_KEYRING values must be canonical base64 encoded 32-byte keys');return [kid,Buffer.from(key,'base64')];}));
  return {providers,vault:new TokenVault(process.env.TOKEN_ACTIVE_KEY_ID||'',bytes)};
}
interface PendingRow {state_hash:string;provider_id:string;user_id:string;session_id:string;browser_binding_hash:string;verifier:string;nonce:string|null;scopes:string[];expires_at:number}
interface Connection {id:string;user_id:string;provider_id:string;subject:string|null;scopes:string[];token_envelope:EncryptedToken;status:string;created_at:number;updated_at:number}
const context=(userId:string,provider:string)=>JSON.stringify([userId,provider]);
function databaseStore(db:Database,providerId:string,sessionId?:string):AuthorizationStore{
  return {
    async put(p){
      if(!sessionId)throw new Error('session_required');
      await db.transaction(async tx=>{
        await tx.query('DELETE FROM oauth_pending WHERE expires_at<=$1 OR (user_id=$2 AND provider_id=$3)',[Date.now(),p.userId,providerId]);
        await tx.query('INSERT INTO oauth_pending(state_hash,provider_id,user_id,session_id,browser_binding_hash,verifier,nonce,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[p.stateHash,providerId,p.userId,sessionId,p.browserBindingHash,p.verifier,p.nonce||null,JSON.stringify(p.scopes),p.expiresAt]);
      });
    },
    async consume(stateHash){
      const row=(await db.query<PendingRow>('DELETE FROM oauth_pending WHERE state_hash=$1 AND provider_id=$2 RETURNING *',[stateHash,providerId])).rows[0];
      return row?{stateHash:row.state_hash,userId:row.user_id,browserBindingHash:row.browser_binding_hash,verifier:row.verifier,nonce:row.nonce||undefined,scopes:row.scopes,expiresAt:Number(row.expires_at)} satisfies PendingAuthorization:undefined;
    }
  };
}
export async function registerProviders(app:FastifyInstance,db:Database,config:Config,settings:ProviderSettings=readProviderSettings(config)){
  if(settings.providers.length&&!settings.vault)throw new Error('Provider token encryption keys required');
  const configs=new Map(settings.providers.map(p=>[p.id,p]));
  const vault=settings.vault;
  const cookie={httpOnly:true,secure:config.origin.startsWith('https:'),sameSite:'lax' as const,path:'/api/providers',maxAge:300};
  const getConfig=(provider:string)=>{const p=configs.get(provider);if(!p)fail(404,'provider_unavailable');return p;};
  const connector=(provider:string,sessionId?:string)=>OAuthAccountConnector.discover(getConfig(provider),databaseStore(db,provider,sessionId),settings.transport);
  app.get('/api/providers',async()=>({providers:[
    {id:'templogin',name:'tempLogin native demos',capabilities:{accountLinking:false,providerAuthorization:false,deviceAuthorization:true,sessionProvisioning:true,sessionRevocation:true,tokenRevocation:false},status:'available'},
    ...settings.providers.map(p=>({id:p.id,name:p.id,capabilities:{accountLinking:true,providerAuthorization:true,deviceAuthorization:false,sessionProvisioning:false,sessionRevocation:false,tokenRevocation:false},status:'configured'})),
    ...(settings.providers.length?[]:[{id:'external',name:'External providers',capabilities:{accountLinking:false,providerAuthorization:false,deviceAuthorization:false,sessionProvisioning:false,sessionRevocation:false,tokenRevocation:false},status:'not_configured'}])
  ]}));
  app.get('/api/connections',async req=>{
    const user=await requireUser(db,req);
    return (await db.query<Connection>('SELECT id,provider_id,subject,scopes,status,created_at,updated_at FROM oauth_connections WHERE user_id=$1 ORDER BY created_at',[user.id])).rows.map(c=>({...c,provider_name:c.provider_id,created_at:Number(c.created_at),updated_at:Number(c.updated_at)}));
  });
  app.post<{Params:{id:string}}>('/api/providers/:id/link',async(req,reply)=>{
    const user=await requireRecentUser(db,req);z.object({}).strict().parse(req.body);
    const binding=token(),client=await connector(req.params.id,user.sessionId),flow=await client.begin(user.id,binding);
    reply.setCookie('tl_oauth_binding',binding,cookie);
    await audit(db,user.id,'provider.link_started',req.params.id);
    return {authorization_url:flow.authorizationUrl,expires_in:flow.expiresIn};
  });
  app.get<{Params:{id:string}}>('/api/providers/:id/callback',async(req,reply)=>{
    reply.clearCookie('tl_oauth_binding',cookie);
    try{
      const cfg=getConfig(req.params.id),callback=new URL(req.url,config.origin),state=callback.searchParams.get('state'),binding=req.cookies.tl_oauth_binding;
      if(!state||state.length>512||!binding||binding.length!==43)fail(400,'invalid_state');
      const row=(await db.query<PendingRow>('SELECT p.* FROM oauth_pending p JOIN user_sessions s ON s.id=p.session_id WHERE p.state_hash=$1 AND p.provider_id=$2 AND p.browser_binding_hash=$3 AND p.expires_at>$4 AND s.expires_at>$4',[hash(state),cfg.id,hash(binding),Date.now()])).rows[0];
      if(!row)fail(400,'invalid_state');
      const client=await connector(cfg.id),result=await client.complete(callback.href,row.user_id,binding);
      await db.transaction(async tx=>{
        await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[row.user_id]);
        const session=(await tx.query('SELECT id FROM user_sessions WHERE id=$1 AND user_id=$2 AND expires_at>$3 FOR UPDATE',[row.session_id,row.user_id,Date.now()])).rows[0];
        if(!session)fail(401,'unauthorized');
        const envelope=vault!.encrypt(JSON.stringify(result.tokens),context(row.user_id,cfg.id));
        await tx.query("INSERT INTO oauth_connections(id,user_id,provider_id,subject,scopes,token_envelope,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$7) ON CONFLICT(user_id,provider_id) DO UPDATE SET subject=EXCLUDED.subject,scopes=EXCLUDED.scopes,token_envelope=EXCLUDED.token_envelope,status='linked',updated_at=EXCLUDED.updated_at",[id(),row.user_id,cfg.id,result.identity?.subject||null,JSON.stringify(result.scopes),JSON.stringify(envelope),Date.now()]);
        await audit(tx,row.user_id,'provider.linked',cfg.id);
      });
      return reply.redirect('/connections?linked=1');
    }catch{
      // No callback parameters, authorization code, or provider payload is logged.
      req.log.warn('Provider authorization failed');
      return reply.redirect('/connections?error=oauth_failed');
    }
  });
  app.delete<{Params:{id:string}}>('/api/connections/:id',async req=>{
    const user=await requireRecentUser(db,req);
    return db.transaction(async tx=>{
      await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[user.id]);
      await requireRecentUser(tx,req);
      const connection=(await tx.query<Connection>('SELECT * FROM oauth_connections WHERE id=$1 AND user_id=$2 FOR UPDATE',[req.params.id,user.id])).rows[0];
      if(!connection)fail(404,'not_found');
      let providerRevocation='revocation_unavailable';
      if(configs.has(connection.provider_id)){
        try{
          const tokens=JSON.parse(vault!.decrypt(connection.token_envelope,context(user.id,connection.provider_id))) as oauth.TokenEndpointResponse;
          const client=await connector(connection.provider_id);
          const result=await client.revokeToken(tokens.refresh_token||tokens.access_token);
          providerRevocation=result.status;
          if(tokens.refresh_token&&client.capabilities().tokenRevocation)await client.revokeToken(tokens.access_token);
        }catch{providerRevocation='error';}
      }
      await tx.query('DELETE FROM oauth_connections WHERE id=$1',[connection.id]);
      await audit(tx,user.id,'provider.unlinked',connection.provider_id);
      return {status:'unlinked',provider_revocation:providerRevocation};
    });
  });
  app.post<{Params:{id:string}}>('/api/connections/:id/refresh',async(req,reply)=>{
    const user=await requireRecentUser(db,req);z.object({}).strict().parse(req.body);
    const result=await db.transaction(async tx=>{
      await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[user.id]);
      await requireRecentUser(tx,req);
      const connection=(await tx.query<Connection>('SELECT * FROM oauth_connections WHERE id=$1 AND user_id=$2 FOR UPDATE',[req.params.id,user.id])).rows[0];
      if(!connection)fail(404,'not_found');
      if(connection.status!=='linked')return {error:'reauthorization_required'};
      try{
        const previous=JSON.parse(vault!.decrypt(connection.token_envelope,context(user.id,connection.provider_id))) as oauth.TokenEndpointResponse;
        if(!previous.refresh_token)return {error:'refresh_unavailable'};
        const client=await connector(connection.provider_id),tokens=await client.refresh(previous.refresh_token),claims=oauth.getValidatedIdTokenClaims(tokens);
        if(claims&&connection.subject&&claims.sub!==connection.subject)throw new Error('subject_changed');
        const scopes=tokens.scope?.split(' ')||connection.scopes;
        if(scopes.some(s=>!connection.scopes.includes(s)))throw new Error('scope_expanded');
        const envelope=vault!.encrypt(JSON.stringify({...tokens,refresh_token:tokens.refresh_token||previous.refresh_token}),context(user.id,connection.provider_id));
        await tx.query('UPDATE oauth_connections SET token_envelope=$1,scopes=$2,updated_at=$3 WHERE id=$4',[JSON.stringify(envelope),JSON.stringify(scopes),Date.now(),connection.id]);
        await audit(tx,user.id,'provider.refreshed',connection.provider_id);
        return {status:'linked'};
      }catch{
        // Commit failure state; do not retry a possibly consumed provider refresh token.
        await tx.query("UPDATE oauth_connections SET status='reauthorization_required',updated_at=$1 WHERE id=$2",[Date.now(),connection.id]);
        return {error:'reauthorization_required'};
      }
    });
    if('error' in result)return reply.code(409).send(result);
    return result;
  });
}
