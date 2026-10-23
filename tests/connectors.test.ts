import { describe,it,expect,vi } from 'vitest';
import { randomBytes,webcrypto } from 'node:crypto';
import { OAuthAccountConnector,TokenVault,UnavailableSessionConnector,type AuthorizationStore,type PendingAuthorization } from '../packages/connector-sdk/index.js';
import {TempLoginDevice} from '../packages/sdk-js/index.js';
const response=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});
class TestAuthorizationStore implements AuthorizationStore{
  rows=new Map<string,PendingAuthorization>();
  async put(p:PendingAuthorization){this.rows.set(p.stateHash,p);}
  async consume(key:string){const p=this.rows.get(key);this.rows.delete(key);return p;}
}
const provider={id:'test',issuer:'https://issuer.example',clientId:'test-client',clientSecret:'test-client-secret',redirectUri:'https://app.example/callback',scopes:['profile'],oidc:false};
const metadata={issuer:provider.issuer,authorization_endpoint:provider.issuer+'/authorize',token_endpoint:provider.issuer+'/token',revocation_endpoint:provider.issuer+'/revoke',code_challenge_methods_supported:['S256'],authorization_response_iss_parameter_supported:true};
describe('token vault',()=>{
  it('authenticates ciphertext and context and rotates without losing tokens',()=>{
    const first=randomBytes(32),second=randomBytes(32),oldVault=new TokenVault('old',{old:first}),item=oldVault.encrypt('sensitive provider token','user:42/provider:example');
    expect(oldVault.decrypt(item,'user:42/provider:example')).toBe('sensitive provider token');
    expect(()=>oldVault.decrypt(item,'user:43/provider:example')).toThrow();
    expect(()=>oldVault.decrypt({...item,tag:randomBytes(16).toString('base64url')},'user:42/provider:example')).toThrow();
    const rotating=new TokenVault('new',{old:first,new:second}),rotated=rotating.rotate(item,'user:42/provider:example');
    expect(rotated.kid).toBe('new');expect(new TokenVault('new',{new:second}).decrypt(rotated,'user:42/provider:example')).toBe('sensitive provider token');
    expect(()=>new TokenVault('new',{new:second}).decrypt(item,'user:42/provider:example')).toThrow();
    expect(()=>new TokenVault('bad',{bad:randomBytes(16)})).toThrow();
  });
});
describe('OAuth adapter (test-only provider transport)',()=>{
  it('enforces PKCE, single-use bound state, issuer, and truthful capabilities',async()=>{
    let tokenRequests=0;
    const transport=vi.fn(async(input:RequestInfo|URL,init?:RequestInit)=>{
      const url=String(input);
      if(url.includes('/.well-known/'))return response(metadata);
      if(url.endsWith('/token')){
        tokenRequests++;const body=new URLSearchParams(String(init?.body));
        expect(body.get('code_verifier')!.length).toBeGreaterThanOrEqual(43);expect(body.get('client_secret')).toBe('test-client-secret');
        return response({access_token:'provider-token',token_type:'Bearer',expires_in:3600,scope:'profile'});
      }
      if(url.endsWith('/revoke'))return new Response('',{status:200});
      throw new Error('unexpected_endpoint');
    }) as typeof fetch;
    const store=new TestAuthorizationStore(),connector=await OAuthAccountConnector.discover(provider,store,transport),binding=randomBytes(32).toString('hex');
    const flow=await connector.begin('user',binding),url=new URL(flow.authorizationUrl);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');expect(url.searchParams.get('code_challenge')?.length).toBe(43);
    const callback=provider.redirectUri+'?code=test-code&state='+url.searchParams.get('state')+'&iss='+encodeURIComponent(provider.issuer);
    expect((await connector.complete(callback,'user',binding)).tokens.access_token).toBe('provider-token');
    await expect(connector.complete(callback,'user',binding)).rejects.toThrow('invalid_state');expect(tokenRequests).toBe(1);
    expect(connector.capabilities()).toMatchObject({accountLinking:true,sessionProvisioning:false,sessionRevocation:false,tokenRevocation:true});
    expect(await connector.revokeToken('provider-token')).toEqual({status:'revocation_requested',guarantee:'provider_token_only'});
  });
  it('rejects wrong browser binding, expanded scopes, issuer mismatch and untrusted endpoints',async()=>{
    const store=new TestAuthorizationStore();
    const connector=await OAuthAccountConnector.discover(provider,store,async()=>response(metadata));
    await expect(connector.begin('user','x'.repeat(32),['admin'])).rejects.toThrow('invalid_authorization');
    const flow=await connector.begin('user','x'.repeat(32)),state=new URL(flow.authorizationUrl).searchParams.get('state');
    await expect(connector.complete(provider.redirectUri+'?code=c&state='+state,'user','y'.repeat(32))).rejects.toThrow('invalid_state');
    expect(store.rows.size).toBe(0);
    await expect(OAuthAccountConnector.discover(provider,store,async()=>response({...metadata,issuer:'https://attacker.example'}))).rejects.toThrow();
    await expect(OAuthAccountConnector.discover(provider,store,async()=>response({...metadata,token_endpoint:'https://attacker.example/token'}))).rejects.toThrow('endpoint_not_allowed');
    await expect(OAuthAccountConnector.discover({...provider,issuer:'http://issuer.example'},store)).rejects.toThrow('https_required');
    expect(await new UnavailableSessionConnector('streaming').revokeSession('s')).toEqual({status:'revocation_unavailable'});
  });
  it('checks signed OIDC identity and rejects nonce mismatch',async()=>{
    const keypair=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
    const publicJwk={...await webcrypto.subtle.exportKey('jwk',keypair.publicKey),kid:'one',alg:'ES256',use:'sig'};
    let expectedNonce='',wrongNonce=false,badSignature=false;
    const connector=await OAuthAccountConnector.discover({...provider,oidc:true,scopes:['openid','profile']},new TestAuthorizationStore(),async(input)=>{
      const url=String(input);
      if(url.includes('/.well-known/'))return response({...metadata,jwks_uri:provider.issuer+'/jwks',id_token_signing_alg_values_supported:['ES256']});
      if(url.endsWith('/jwks'))return response({keys:[publicJwk]});
      const encoded=(v:unknown)=>Buffer.from(JSON.stringify(v)).toString('base64url');
      const now=Math.floor(Date.now()/1000),content=encoded({alg:'ES256',kid:'one'})+'.'+encoded({iss:provider.issuer,sub:'subject',aud:provider.clientId,iat:now,exp:now+300,nonce:wrongNonce?'wrong':expectedNonce});
      const signature=await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},keypair.privateKey,Buffer.from(content));
      if(badSignature)new Uint8Array(signature)[0]^=1;
      return response({access_token:'oidc-token',token_type:'Bearer',id_token:content+'.'+Buffer.from(signature).toString('base64url')});
    });
    const binding='x'.repeat(32);
    const run=async()=>{
      const flow=await connector.begin('user',binding),auth=new URL(flow.authorizationUrl);expectedNonce=auth.searchParams.get('nonce')!;
      return connector.complete(provider.redirectUri+'?code=code&state='+auth.searchParams.get('state')+'&iss='+encodeURIComponent(provider.issuer),'user',binding);
    };
    expect((await run()).identity).toEqual({issuer:provider.issuer,subject:'subject'});
    wrongNonce=true;await expect(run()).rejects.toThrow();
    wrongNonce=false;badSignature=true;await expect(run()).rejects.toThrow();
  });
});
describe('device SDK',()=>{
  it('uses real API shapes, keeps device code out of QR and serializes refresh rotation',async()=>{
    vi.useFakeTimers();
    try{
      let refreshes=0;
      const transport=vi.fn(async(input:RequestInfo|URL,init?:RequestInit)=>{
        const path=new URL(String(input)).pathname,body=init?.body?JSON.parse(String(init.body)):undefined;
        expect(init?.credentials).toBe('omit');
        if(path==='/api/pairings')return response({device_code:'secret',user_code:'ABCD-EFGH',verification_uri:'http://localhost:3000/approve',verification_uri_complete:'http://localhost:3000/approve?code=ABCD-EFGH',expires_in:300,interval:3});
        if(path==='/api/token'){
          if(body.grant_type==='refresh_token')refreshes++;
          return response({access_token:'access'+refreshes,refresh_token:'refresh'+refreshes,expires_in:60,grant_id:'grant',grant_expires_at:Date.now()+3600000,token_type:'Bearer',scope:'content:read'});
        }
        if(path==='/api/resource')return response({kind:'tv',profile:{},message:'content',expires_at:Date.now()+3600000,scopes:['content:read']});
        if(path==='/api/device/logout')return response({status:'revoked'});
        throw new Error('unexpected');
      }) as typeof fetch;
      const sdk=new TempLoginDevice('http://localhost:3000','demo-tv',transport),pair=await sdk.begin('TV',['content:read']);
      expect(pair.verification_uri_complete).not.toContain(pair.device_code);
      const polling=sdk.waitForApproval(pair);await vi.advanceTimersByTimeAsync(3000);await polling;
      await Promise.all([sdk.refresh(),sdk.refresh()]);expect(refreshes).toBe(1);
      expect((await sdk.resource()).kind).toBe('tv');await sdk.logout();await expect(sdk.resource()).rejects.toThrow('not_authorized');
    }finally{vi.useRealTimers();}
  });
  it('rejects insecure remote origin',()=>{expect(()=>new TempLoginDevice('http://example.com','demo-tv')).toThrow();});
});
