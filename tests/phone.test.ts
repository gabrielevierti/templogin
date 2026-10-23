import {it,expect} from 'vitest';
import {phoneOrigin} from '../scripts/phone-origin.js';
import {createApp} from '../services/api/app.js';
it('extracts only a valid HTTPS quick-tunnel origin',()=>{
 expect(phoneOrigin('INF | https://quiet-river-123.trycloudflare.com |')).toBe('https://quiet-river-123.trycloudflare.com');
 for(const invalid of ['http://quiet.trycloudflare.com','https://quiet.trycloudflare.com.attacker.example','https://localhost:3000','https://trycloudflare.com','https://quiet.trycloudflare.com@attacker.example'])expect(phoneOrigin(invalid)).toBeUndefined();
});
it('uses the public HTTPS origin consistently for QR and WebAuthn, rejecting localhost Origin',async()=>{
 const origin='https://quiet-river-123.trycloudflare.com',host=new URL(origin).hostname;
 const app=await createApp({origin,rpID:host,legacyWallet:true,production:false,port:3000});
 try{
  const pair=await app.inject({method:'POST',url:'/api/pairings',headers:{origin},payload:{client_id:'demo-tv',device_name:'Phone test',scopes:['content:read']}});
  expect(pair.statusCode).toBe(200);expect(pair.json().verification_uri_complete).toMatch(/^https:\/\/quiet-river-123\.trycloudflare\.com\/approve\?code=/);
  const options=await app.inject({method:'POST',url:'/api/auth/register/options',headers:{origin},payload:{name:'Phone'}});
  expect(options.statusCode).toBe(200);expect(options.json().rp.id).toBe(host);expect(options.headers['set-cookie']).toContain('Secure');
  const wrong=await app.inject({method:'POST',url:'/api/auth/register/options',headers:{origin:'http://localhost:3000'},payload:{name:'Phone'}});
  expect(wrong.statusCode).toBe(403);
  expect((await app.db.query('SELECT id FROM users')).rows).toEqual([]);
 }finally{await app.close();}
});
