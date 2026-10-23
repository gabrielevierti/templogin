import type {FastifyInstance} from 'fastify';
import {z} from 'zod';
import {registerTemporaryLogin,type ProviderOptions} from '../../packages/provider-sdk/index.js';
import type {Config} from './config.js';
import type {Database} from './database.js';
import {token,hash,fail} from './security.js';
/** Public fictional account, exclusively for the sandbox. Never enabled in production. */
export async function registerReferenceProvider(app:FastifyInstance,db:Database,config:Config,realProvider?:ProviderOptions){
 if(realProvider&&realProvider.origin!==config.origin)throw new Error('Provider origin must match host PUBLIC_ORIGIN');
 const demo=!config.production&&!realProvider;
 await db.exec('CREATE TABLE IF NOT EXISTS tl_demo_logins (hash TEXT PRIMARY KEY,created_at BIGINT NOT NULL,expires_at BIGINT NOT NULL)');
 const provider:ProviderOptions=realProvider??{
  id:'screen-demo',name:'Screen Demo',origin:config.origin,maxDurationSeconds:7200,
  async identity(req){
   if(!demo)return null;
   const value=req.cookies.tl_demo_provider;if(!value)return null;
   const row=(await db.query<{created_at:number}>('SELECT created_at FROM tl_demo_logins WHERE hash=$1 AND expires_at>$2',[hash(value),Date.now()])).rows[0];
   return row?{subject:'demo:'+hash(value),displayName:'Demo Guest',authenticatedAt:Number(row.created_at)}:null;
  },
  async entitled(){return demo;}
 };
 const guard=await registerTemporaryLogin(app,db,provider);
 app.get('/api/temporary/mode',async()=>({demo,configured:demo||!!realProvider}));
 app.post('/api/temporary/demo-login',async(req,reply)=>{
  if(!demo)fail(404,'demo_disabled');
  z.object({}).strict().parse(req.body);
  const value=token(),now=Date.now();
  await db.query('DELETE FROM tl_demo_logins WHERE expires_at<=$1',[now]);
  await db.query('INSERT INTO tl_demo_logins(hash,created_at,expires_at) VALUES($1,$2,$3)',[hash(value),now,now+900000]);
  reply.setCookie('tl_demo_provider',value,{httpOnly:true,secure:config.origin.startsWith('https:'),sameSite:'strict',path:'/api/temporary',maxAge:900});
  return {status:'signed_in',demo:true};
 });
 app.get('/api/temporary/content',async req=>{
  const session=await guard.requireSession(req);
  return {title:'Your temporary session',provider:provider.name,expires_at:Number(session.expires_at),demo,session_id:session.id};
 });
 return guard;
}
