import {it,expect} from 'vitest';
import {readFile} from 'node:fs/promises';
import {createDatabase} from '../services/api/database.js';
import {createApp} from '../services/api/app.js';
it('OpenAPI operations resolve to actual server routes and all local references exist',async()=>{
 const config={origin:'http://localhost:3000',rpID:'localhost',legacyWallet:true,production:false,port:3000};
 const db=await createDatabase(config),app=await createApp(config,db);
 try{
  await app.ready();
  const spec=JSON.parse(await readFile('specs/openapi.json','utf8'));
  for(const [url,methods] of Object.entries(spec.paths))for(const method of Object.keys(methods as object).filter(m=>['get','post','delete','put','patch'].includes(m))){
   expect(app.hasRoute({method:method.toUpperCase() as 'GET',url:url.replace(/\{([^}]+)\}/g,':$1')}),method+' '+url).toBe(true);
  }
  const walk=(v:unknown)=>{if(!v||typeof v!=='object')return;for(const [key,value] of Object.entries(v)){if(key==='$ref'){const path=String(value).slice(2).split('/');let current=spec;for(const part of path)current=current[part];expect(current).toBeDefined();}else walk(value);}};
  walk(spec);
 }finally{await app.close();await db.close();}
});
it('metrics are private, contain no identities and do not trust forged proxy headers',async()=>{
 const config={origin:'http://localhost:3000',rpID:'localhost',legacyWallet:true,production:false,port:3000,metricsToken:'synthetic-metrics-key-longer-than-thirty-two'};
 const db=await createDatabase(config),app=await createApp(config,db);
 try{
  expect((await app.inject('/metrics')).statusCode).toBe(401);
  await app.inject('/healthz');
  const metrics=await app.inject({url:'/metrics',headers:{authorization:'Bearer '+config.metricsToken}});
  expect(metrics.statusCode).toBe(200);expect(metrics.body).toContain('templogin_http_requests_total');expect(metrics.body).not.toContain(config.metricsToken);
  for(let i=0;i<12;i++)expect((await app.inject({method:'POST',url:'/api/pairings',headers:{'x-forwarded-for':`192.0.2.${i}`},payload:{client_id:'demo-tv',device_name:'Rate test',scopes:['content:read']}})).statusCode).toBe(200);
  expect((await app.inject({method:'POST',url:'/api/pairings',headers:{'x-forwarded-for':'198.51.100.1'},payload:{client_id:'demo-tv',device_name:'Rate test',scopes:['content:read']}})).statusCode).toBe(429);
 }finally{await app.close();await db.close();}
});
