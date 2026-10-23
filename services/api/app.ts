import Fastify from 'fastify';
import { timingSafeEqual } from 'node:crypto';
import cookie from '@fastify/cookie';
import helmet from '@fastify/helmet';
import staticPlugin from '@fastify/static';
import { resolve } from 'node:path';
import { existsSync } from 'node:fs';
import { ZodError } from 'zod';
import { createDatabase, type Database } from './database.js';
import type { Config } from './config.js';
import { registerAuth } from './auth.js';
import { registerCore } from './core.js';
import { registerProviders } from './providers.js';
import { registerHospitality } from './hospitality.js';
import {registerReferenceProvider} from './temporary.js';
import type {ProviderOptions} from '../../packages/provider-sdk/index.js';
import { hash } from './security.js';
declare module 'fastify' { interface FastifyInstance { db:Database } }
export async function createApp(config:Config,suppliedDb?:Database,provider?:ProviderOptions){
  if(config.production && (!config.origin.startsWith('https://') || !config.databaseUrl)) throw new Error('Production requires HTTPS and PostgreSQL');
  const db=suppliedDb||await createDatabase(config);
  const app=Fastify({logger:config.production?{level:'info',redact:['req.headers.authorization','req.headers.cookie','res.headers["set-cookie"]'],serializers:{req:r=>({method:r.method,url:r.url?.split('?')[0],id:r.id})}}:false,bodyLimit:32768,trustProxy:config.trustedProxies?.length?config.trustedProxies:false,requestTimeout:15000,connectionTimeout:10000});
  app.decorate('db',db);
  await app.register(cookie);
  await app.register(helmet,{contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'"],imgSrc:["'self'",'data:'],connectSrc:["'self'"],frameAncestors:["'none'"],formAction:["'self'"],baseUri:["'none'"],objectSrc:["'none'"],upgradeInsecureRequests:config.production?[]:null}},referrerPolicy:{policy:'no-referrer'},hsts:config.production?{maxAge:31536000,includeSubDomains:true}:false});
  app.addHook('onRequest',async(req,reply)=>{
    if(!req.url.startsWith('/api/'))return;
    reply.header('Cache-Control','no-store').header('Pragma','no-cache');
    if(req.headers.origin && req.headers.origin!==config.origin)return reply.code(403).send({error:'origin_not_allowed'});
    if(['POST','PUT','PATCH','DELETE'].includes(req.method)){
      const deviceEndpoint=['/api/token','/api/pairings','/api/device/logout'].includes(req.url);
      if(req.headers.origin!==config.origin && (!deviceEndpoint||req.cookies.tl_session))return reply.code(403).send({error:'origin_required'});
      if(req.headers['sec-fetch-site']==='cross-site')return reply.code(403).send({error:'cross_site_request'});
    }
    // PostgreSQL-backed fixed windows are shared by every API replica.
    // Trust only configured proxy IPs; forged forwarding headers from other peers are ignored.
    const route=req.url.split('?')[0],auth=(route.startsWith('/api/auth/')||route==='/api/temporary/demo-login'),pair=req.method==='POST'&&(route==='/api/pairings'||route==='/api/temporary/pairings');
    const bucket=auth?'auth':pair?'pair':'general',limit=auth?20:pair?12:120,now=Date.now(),window=Math.floor(now/60000)*60000;
    const key=hash(req.ip+':'+bucket);
    const count=(await db.query<{hits:number}>('INSERT INTO rate_limits(key,window_start,hits) VALUES($1,$2,1) ON CONFLICT(key) DO UPDATE SET hits=CASE WHEN rate_limits.window_start=$2 THEN rate_limits.hits+1 ELSE 1 END,window_start=$2 RETURNING hits',[key,window])).rows[0].hits;
    if(count>limit)return reply.header('Retry-After',Math.ceil((window+60000-now)/1000)).code(429).send({error:'rate_limited'});
  });
  app.setErrorHandler((error,req,reply)=>{
    if(error instanceof ZodError)return reply.code(400).send({error:'invalid_request'});
    const e=error as Error & {statusCode?:number;code?:string};
    if(e.code==='23505')return reply.code(409).send({error:'conflict'});
    if(e.code==='23503')return reply.code(409).send({error:'conflict'});
    const status=e.statusCode && e.statusCode>=400 && e.statusCode<500?e.statusCode:500;
    if(status===500)req.log.error({code:e.code||'internal_error',requestId:req.id},'Request failed');
    return reply.code(status).send({error:status===500?'internal_error':e.message});
  });
  let requests=0,failures=0,durationSum=0;
  const bounds=[0.01,0.05,0.1,0.5,1,5,15],buckets=bounds.map(()=>0);
  app.addHook('onResponse',async(req,reply)=>{
    if(req.url==='/metrics')return;
    requests++;if(reply.statusCode>=500)failures++;
    const seconds=reply.elapsedTime/1000;durationSum+=seconds;
    bounds.forEach((bound,i)=>{if(seconds<=bound)buckets[i]++;});
  });
  app.get('/metrics',async(req,reply)=>{
    if(!config.metricsToken)return reply.code(404).send({error:'not_found'});
    const provided=(req.headers.authorization||'').replace(/^Bearer /,'');
    if(!timingSafeEqual(Buffer.from(hash(provided)),Buffer.from(hash(config.metricsToken))))return reply.code(401).send({error:'unauthorized'});
    reply.header('Cache-Control','no-store').type('text/plain; version=0.0.4');
    return ['# TYPE templogin_http_requests_total counter',`templogin_http_requests_total ${requests}`,'# TYPE templogin_http_errors_total counter',`templogin_http_errors_total ${failures}`,'# TYPE templogin_http_duration_seconds histogram',...bounds.map((b,i)=>`templogin_http_duration_seconds_bucket{le="${b}"} ${buckets[i]}`),`templogin_http_duration_seconds_bucket{le="+Inf"} ${requests}`,`templogin_http_duration_seconds_sum ${durationSum}`,`templogin_http_duration_seconds_count ${requests}`,''].join('\n');
  });
  app.get('/healthz',async()=>({status:'ok'}));
  app.get('/readyz',async()=>{await db.query('SELECT 1');return {status:'ready'};});
  app.get('/api/config',async()=>({origin:config.origin,rpID:config.rpID,production:config.production}));
  await registerReferenceProvider(app,db,config,provider);
  if(config.legacyWallet){
  await registerAuth(app,db,config);
  await registerCore(app,db,config);
  await registerHospitality(app,db);
  await registerProviders(app,db,config);
  }
  const publicDir=resolve('dist/public');
  if(existsSync(publicDir)){
    await app.register(staticPlugin,{root:publicDir,index:false});
    app.get('/',(_req,reply)=>reply.type('text/html').sendFile('index.html'));
    app.setNotFoundHandler((req,reply)=>{
      if(req.method==='GET' && !req.url.startsWith('/api/') && !req.url.split('?')[0].includes('.'))return reply.type('text/html').sendFile('index.html');
      return reply.code(404).send({error:'not_found'});
    });
  }
  if(!suppliedDb)app.addHook('onClose',async()=>db.close());
  return app;
}
