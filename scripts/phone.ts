import {spawn,spawnSync,type ChildProcess} from 'node:child_process';
import {createServer} from 'node:net';
import {createApp} from '../services/api/app.js';
import {phoneOrigin} from './phone-origin.js';

if(spawnSync('cloudflared',['--version'],{stdio:'ignore'}).status!==0){
  console.error('cloudflared is required. On macOS: brew install cloudflared\nThen run: npm run dev:phone');
  process.exit(1);
}
// A separate, ephemeral instance: never inherit the user's persistent DB or provider links.
delete process.env.OAUTH_PROVIDERS_JSON;
const reserve=createServer();
await new Promise<void>((resolve,reject)=>{reserve.once('error',reject);reserve.listen(0,'127.0.0.1',resolve);});
const address=reserve.address();
if(!address||typeof address==='string')throw new Error('Cannot reserve a local port');
const port=address.port;
await new Promise<void>((resolve,reject)=>reserve.close(e=>e?reject(e):resolve()));
console.log('Starting an isolated HTTPS demo. Existing local accounts and provider links are not loaded.');
console.log('The demo will be publicly reachable through Cloudflare while this command runs.');
let tunnel:ChildProcess|undefined;
let app:Awaited<ReturnType<typeof createApp>>|undefined;
let closing=false;
async function stop(code:number){
  if(closing)return;closing=true;
  tunnel?.kill('SIGTERM');
  const force=setTimeout(()=>{tunnel?.kill('SIGKILL');process.exit(code);},5000);force.unref();
  try{await app?.close();}finally{clearTimeout(force);process.exit(code);}
}
for(const signal of ['SIGINT','SIGTERM'] as const)process.once(signal,()=>{void stop(0);});
try{
  const origin=await new Promise<string>((resolve,reject)=>{
    let logs='';let settled=false;
    const timeout=setTimeout(()=>reject(new Error('Tunnel unavailable after 90 seconds. Check your network and cloudflared configuration.')),90000);
    tunnel=spawn('cloudflared',['tunnel','--no-autoupdate','--url',`http://127.0.0.1:${port}`],{stdio:['ignore','pipe','pipe']});
    const read=(chunk:Buffer)=>{
      logs=(logs+chunk.toString()).slice(-16000);
      // Wait for a delimiter to avoid accepting a partial hostname at a chunk boundary.
      const found=phoneOrigin(logs.slice(0,logs.lastIndexOf('\n')+1));
      if(found&&!settled){settled=true;clearTimeout(timeout);resolve(found);}
    };
    tunnel.stdout?.on('data',read);tunnel.stderr?.on('data',read);
    tunnel.once('error',e=>{clearTimeout(timeout);reject(e);});
    tunnel.once('exit',code=>{
      clearTimeout(timeout);
      if(!settled)reject(new Error(`cloudflared exited (${code}). ${logs.slice(-1800)}`));
      else if(!closing){console.error('Tunnel closed. Stopping the demo server.');void stop(1);}
    });
  });
  if(closing)throw new Error('Startup interrupted');
  app=await createApp({origin,rpID:new URL(origin).hostname,production:false,port});
  await app.listen({host:'127.0.0.1',port});
  console.log(`\nREADY — open on your computer: ${origin}/tv\nPhone: ${origin}\n`);
  console.log('Scan the NEW QR and select Continue with demo account. No passkey required. Do not use an old localhost tab.');
  console.log('The hostname changes and demo sessions are cleared on restart. Ctrl+C stops the tunnel and demo.');
}catch(error){console.error(error instanceof Error?error.message:String(error));await stop(1);}
