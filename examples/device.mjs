// Run after npm run build: node examples/device.mjs
// Open printed verification URI in a browser with a passkey; this CLI is the guest device.
import {TempLoginDevice} from '../packages/sdk-js/dist/index.js';
const device=new TempLoginDevice(process.env.TEMPLOGIN_ORIGIN||'http://localhost:3000','demo-tv');
const controller=new globalThis.AbortController();
process.once('SIGINT',()=>controller.abort());
try{
  const pairing=await device.begin('External SDK example',['content:read','profile:read']);
  console.log('Open:',pairing.verification_uri_complete);
  console.log('Confirm this code:',pairing.user_code);
  await device.waitForApproval(pairing,controller.signal);
  console.log(await device.resource(controller.signal));
  await device.logout();
  console.log('Session revoked.');
}catch(error){console.error(error instanceof Error?error.message:'Device flow failed');process.exitCode=1;}
