import {performance} from 'node:perf_hooks';
import {createApp} from '../services/api/app.js';
import {createDatabase} from '../services/api/database.js';
import {id,token,hash} from '../services/api/security.js';
const config={origin:'http://localhost:3000',rpID:'localhost',production:false,port:3000};
const db=await createDatabase(config),app=await createApp(config,db);
try{
 const grant=id(),access=token(),now=Date.now();
 await db.query('INSERT INTO tl_provider_sessions(id,provider,subject,device_name,token_hash,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)',[grant,'screen-demo','benchmark-synthetic','Benchmark',hash(access),now+3600000,now]);
 const samples:number[]=[];
 for(let i=0;i<80;i++){
  const start=performance.now(),response=await app.inject({method:'GET',url:'/api/temporary/content',headers:{authorization:'Bearer '+access}});
  if(response.statusCode!==200)throw new Error('Benchmark request failed '+response.statusCode);
  samples.push(performance.now()-start);
 }
 samples.sort((a,b)=>a-b);
 console.log(JSON.stringify({method:'80 sequential Fastify.inject requests to actual resource authorization + PGlite; synthetic seeded provider session; excludes TCP/TLS and startup; not a production load test',node:process.version,requests:samples.length,p50_ms:samples[39],p95_ms:samples[75],max_ms:samples[79]},null,2));
}finally{await app.close();await db.close();}
