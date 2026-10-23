import {it,expect} from 'vitest';
import {randomUUID,randomBytes,createHash} from 'node:crypto';
import {createDatabase} from '../services/api/database.js';
import {createApp} from '../services/api/app.js';
import {TempLoginDevice} from '../packages/sdk-js/index.js';
it('runs the external SDK against actual API handlers and PostgreSQL storage',async()=>{
  const config={origin:'http://localhost:3000',rpID:'localhost',legacyWallet:true,production:false,port:3000},db=await createDatabase(config),app=await createApp(config,db);
  try{
    const user=randomUUID(),session=randomUUID(),secret=randomBytes(32).toString('base64url'),now=Date.now();
    await db.query('INSERT INTO users(id,name,created_at) VALUES($1,$2,$3)',[user,'SDK owner',now]);
    await db.query('INSERT INTO user_sessions(id,user_id,token_hash,created_at,expires_at,authenticated_at) VALUES($1,$2,$3,$4,$5,$4)',[session,user,createHash('sha256').update(secret).digest('hex'),now,now+3600000]);
    // In-process HTTP transport, not a route mock. Every request executes real handlers and SQL.
    const transport:typeof fetch=async(input,init)=>{
      const url=new URL(String(input)),headers:Record<string,string>={};new Headers(init?.headers).forEach((value,key)=>{headers[key]=value;});
      const result=await app.inject({method:(init?.method||'GET') as 'GET'|'POST',url:url.pathname+url.search,headers,payload:init?.body?String(init.body):undefined});
      return new Response(result.body,{status:result.statusCode,headers:{'Content-Type':'application/json'}});
    };
    const sdk=new TempLoginDevice(config.origin,'demo-tv',transport),pairing=await sdk.begin('SDK television',['content:read']);
    const approved=await app.inject({method:'POST',url:'/api/pairings/'+pairing.user_code+'/decision',headers:{origin:config.origin,cookie:'tl_session='+secret},payload:{approve:true,matching_code:pairing.user_code,scopes:['content:read'],duration_seconds:300}});
    expect(approved.statusCode).toBe(200);
    const tokens=await sdk.waitForApproval(pairing);
    expect((await sdk.resource()).kind).toBe('tv');await sdk.refresh();await sdk.logout();
    const denied=await app.inject({method:'GET',url:'/api/resource',headers:{authorization:'Bearer '+tokens.access_token}});expect(denied.statusCode).toBe(401);
  }finally{await app.close();await db.close();}
},30000);
