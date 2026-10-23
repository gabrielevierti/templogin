import * as oauth from 'oauth4webapi';
export {sessionDeadline,assertTemporarySession,credentialDeadline,type TemporarySession} from './session-policy.js';
import { createCipheriv,createDecipheriv,randomBytes,createHash,timingSafeEqual } from 'node:crypto';

export interface ProviderCapabilities {
  accountLinking:boolean; providerAuthorization:boolean; deviceAuthorization:boolean;
  sessionProvisioning:boolean; sessionRevocation:boolean; tokenRevocation:boolean;
}
export const unsupportedCapabilities:Readonly<ProviderCapabilities>=Object.freeze({accountLinking:false,providerAuthorization:false,deviceAuthorization:false,sessionProvisioning:false,sessionRevocation:false,tokenRevocation:false});
export type CleanupState='revocation_verified'|'revocation_requested'|'revocation_unavailable'|'error'|'manual_verification_required';
export interface SessionConnector {
  readonly id:string;
  capabilities():Readonly<ProviderCapabilities>;
  provisionSession(input:{userId:string;deviceId:string;scopes:string[];expiresAt:number}):Promise<{sessionId:string;expiresAt:number}>;
  revokeSession(sessionId:string):Promise<{status:CleanupState}>;
}
export class UnavailableSessionConnector implements SessionConnector {
  constructor(readonly id:string){}
  capabilities(){return unsupportedCapabilities;}
  async provisionSession(_input:{userId:string;deviceId:string;scopes:string[];expiresAt:number}):Promise<never>{throw new Error('session_provisioning_unavailable');}
  async revokeSession(_sessionId:string):Promise<{status:CleanupState}>{return {status:'revocation_unavailable'};}
}
export interface PendingAuthorization {
  stateHash:string; userId:string; browserBindingHash:string; verifier:string; nonce?:string;
  scopes:string[]; expiresAt:number;
}
/** Implement in PostgreSQL. consume MUST atomically delete and return once, even on failed callback validation. */
export interface AuthorizationStore {
  put(value:PendingAuthorization):Promise<void>;
  consume(stateHash:string):Promise<PendingAuthorization|undefined>;
}
export interface OAuthProviderConfig {
  id:string; issuer:string; clientId:string; clientSecret?:string;
  redirectUri:string; scopes:readonly string[]; oidc:boolean;
  /** Exact origins configured by operator; never derive from request input. Default issuer origin only. */
  allowedEndpointOrigins?:readonly string[];
}
const sha=(s:string)=>createHash('sha256').update(s).digest('hex');
const equal=(a:string,b:string)=>a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
function safeHttps(value:string){const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password||u.hash)throw new Error('https_required');return u;}
/** Server-only OAuth account authorization. Does not transfer provider tokens to guest devices. */
export class OAuthAccountConnector {
  private constructor(private readonly config:OAuthProviderConfig,private readonly server:oauth.AuthorizationServer,private readonly store:AuthorizationStore,private readonly transport:typeof fetch){}
  private client():oauth.Client{return {client_id:this.config.clientId};}
  private authentication(){return this.config.clientSecret?oauth.ClientSecretPost(this.config.clientSecret):oauth.None();}
  private options(){return {[oauth.customFetch]:this.transport,signal:()=>AbortSignal.timeout(15000)};}
  static async discover(config:OAuthProviderConfig,store:AuthorizationStore,transport:typeof fetch=fetch){
    const issuer=safeHttps(config.issuer),redirect=safeHttps(config.redirectUri);
    if(issuer.search||redirect.hash||!config.clientId||!config.id||!config.scopes.length)throw new Error('invalid_provider_config');
    if(config.oidc&&!config.scopes.includes('openid'))throw new Error('openid_scope_required');
    const origins=new Set([issuer.origin,...(config.allowedEndpointOrigins||[])]);
    for(const origin of origins)if(safeHttps(origin).origin!==origin)throw new Error('invalid_endpoint_origin');
    const boundedFetch:typeof fetch=async(input,init)=>{
      const value=typeof input==='string'?input:input instanceof URL?input.href:input.url;
      const url=safeHttps(value);
      if(!origins.has(url.origin))throw new Error('endpoint_not_allowed');
      return transport(value,{...init,redirect:'manual',signal:init?.signal||AbortSignal.timeout(15000)});
    };
    const response=await oauth.discoveryRequest(issuer,{algorithm:config.oidc?'oidc':'oauth2',[oauth.customFetch]:boundedFetch,signal:AbortSignal.timeout(15000)});
    const metadata=await oauth.processDiscoveryResponse(issuer,response);
    if(!metadata.authorization_endpoint||!metadata.token_endpoint)throw new Error('provider_endpoints_missing');
    for(const endpoint of [metadata.authorization_endpoint,metadata.token_endpoint,metadata.jwks_uri,metadata.revocation_endpoint]){
      if(endpoint&&!origins.has(safeHttps(endpoint).origin))throw new Error('endpoint_not_allowed');
    }
    if(metadata.code_challenge_methods_supported&&!metadata.code_challenge_methods_supported.includes('S256'))throw new Error('pkce_s256_required');
    if(config.oidc&&!metadata.jwks_uri)throw new Error('jwks_uri_required');
    return new OAuthAccountConnector({...config,scopes:[...config.scopes]},metadata,store,boundedFetch);
  }
  capabilities():Readonly<ProviderCapabilities>{return {...unsupportedCapabilities,accountLinking:true,providerAuthorization:true,tokenRevocation:!!this.server.revocation_endpoint};}
  async begin(userId:string,browserBinding:string,scopes:readonly string[]=this.config.scopes){
    if(!userId||browserBinding.length<32||!scopes.length||new Set(scopes).size!==scopes.length||scopes.some(s=>!this.config.scopes.includes(s)))throw new Error('invalid_authorization');
    if(this.config.oidc&&!scopes.includes('openid'))throw new Error('openid_scope_required');
    const state=oauth.generateRandomState(),verifier=oauth.generateRandomCodeVerifier(),nonce=this.config.oidc?oauth.generateRandomNonce():undefined;
    await this.store.put({stateHash:sha(state),userId,browserBindingHash:sha(browserBinding),verifier,nonce,scopes:[...scopes],expiresAt:Date.now()+300000});
    const url=new URL(this.server.authorization_endpoint!);
    url.searchParams.set('client_id',this.config.clientId);url.searchParams.set('redirect_uri',this.config.redirectUri);
    url.searchParams.set('response_type','code');url.searchParams.set('scope',scopes.join(' '));url.searchParams.set('state',state);
    url.searchParams.set('code_challenge',await oauth.calculatePKCECodeChallenge(verifier));url.searchParams.set('code_challenge_method','S256');
    if(nonce)url.searchParams.set('nonce',nonce);
    return {authorizationUrl:url.href,expiresIn:300};
  }
  async complete(callbackUrl:string,userId:string,browserBinding:string){
    const callback=new URL(callbackUrl),expected=new URL(this.config.redirectUri);
    if(callback.origin!==expected.origin||callback.pathname!==expected.pathname||callback.hash)throw new Error('invalid_callback');
    const state=callback.searchParams.get('state');
    if(!state||callback.searchParams.getAll('state').length!==1)throw new Error('invalid_state');
    const pending=await this.store.consume(sha(state));
    if(!pending||pending.expiresAt<=Date.now()||pending.userId!==userId||!equal(pending.browserBindingHash,sha(browserBinding)))throw new Error('invalid_state');
    const params=oauth.validateAuthResponse(this.server,this.client(),callback,state);
    const response=await oauth.authorizationCodeGrantRequest(this.server,this.client(),this.authentication(),params,this.config.redirectUri,pending.verifier,this.options());
    const tokens=await oauth.processAuthorizationCodeResponse(this.server,this.client(),response,{expectedNonce:pending.nonce,requireIdToken:this.config.oidc});
    if(tokens.id_token)await oauth.validateApplicationLevelSignature(this.server,response,this.options());
    if(tokens.scope&&tokens.scope.split(' ').some(s=>!pending.scopes.includes(s)))throw new Error('unexpected_provider_scope');
    const identity=oauth.getValidatedIdTokenClaims(tokens);
    return {tokens,identity:identity?{issuer:identity.iss,subject:identity.sub}:undefined,scopes:tokens.scope?.split(' ')||pending.scopes};
  }
  async refresh(refreshToken:string){
    // Caller must lock its persisted connection row and replace rotated tokens atomically.
    const response=await oauth.refreshTokenGrantRequest(this.server,this.client(),this.authentication(),refreshToken,this.options());
    const result=await oauth.processRefreshTokenResponse(this.server,this.client(),response);
    if(result.id_token)await oauth.validateApplicationLevelSignature(this.server,response,this.options());
    if(result.scope&&result.scope.split(' ').some(s=>!this.config.scopes.includes(s)))throw new Error('unexpected_provider_scope');
    return result;
  }
  async revokeToken(value:string):Promise<{status:CleanupState;guarantee:'provider_token_only'}>{
    if(!this.server.revocation_endpoint)return {status:'revocation_unavailable',guarantee:'provider_token_only'};
    const response=await oauth.revocationRequest(this.server,this.client(),this.authentication(),value,this.options());
    await oauth.processRevocationResponse(response);
    // RFC 7009 success does not establish that a TV application's session was removed.
    return {status:'revocation_requested',guarantee:'provider_token_only'};
  }
}
export interface EncryptedToken {version:1;kid:string;iv:string;ciphertext:string;tag:string}
/** AES-256-GCM using Node's crypto. Keys are operator-supplied, not generated in source code. */
export class TokenVault {
  private readonly keys:Map<string,Buffer>;
  constructor(readonly activeKeyId:string,keys:Readonly<Record<string,Uint8Array>>){
    this.keys=new Map(Object.entries(keys).map(([name,key])=>{if(!/^[a-zA-Z0-9_-]{1,80}$/.test(name)||key.byteLength!==32)throw new Error('invalid_encryption_key');return [name,Buffer.from(key)];}));
    if(!this.keys.has(activeKeyId))throw new Error('missing_active_key');
  }
  encrypt(value:string,context:string):EncryptedToken{
    if(!context||value.length>65536)throw new Error('invalid_token_payload');
    const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',this.keys.get(this.activeKeyId)!,iv);
    cipher.setAAD(Buffer.from('tempLogin:token:v1:'+this.activeKeyId+':'+context));
    const ciphertext=Buffer.concat([cipher.update(value,'utf8'),cipher.final()]);
    return {version:1,kid:this.activeKeyId,iv:iv.toString('base64url'),ciphertext:ciphertext.toString('base64url'),tag:cipher.getAuthTag().toString('base64url')};
  }
  decrypt(envelope:EncryptedToken,context:string):string{
    const key=this.keys.get(envelope.kid);
    if(!context||envelope.version!==1||!key||envelope.ciphertext.length>90000)throw new Error('invalid_token_envelope');
    const iv=Buffer.from(envelope.iv,'base64url'),tag=Buffer.from(envelope.tag,'base64url');
    if(iv.length!==12||tag.length!==16)throw new Error('invalid_token_envelope');
    const decipher=createDecipheriv('aes-256-gcm',key,iv);
    decipher.setAAD(Buffer.from('tempLogin:token:v1:'+envelope.kid+':'+context));decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext,'base64url')),decipher.final()]).toString('utf8');
  }
  rotate(envelope:EncryptedToken,context:string){return this.encrypt(this.decrypt(envelope,context),context);}
}

/** Future authorized hospitality integration. This contract does not call private Airbnb APIs. */
export interface StayProviderAdapter {
  readonly id:string;
  capabilities():Readonly<{stayImport:boolean;checkoutEvents:boolean}>;
  listStays(propertyExternalId:string,since:string):Promise<Array<{externalId:string;guestLabel:string;startsAt:number;endsAt:number}>>;
}
export class UnavailableStayProviderAdapter implements StayProviderAdapter {
  constructor(readonly id:string='airbnb'){}
  capabilities(){return {stayImport:false,checkoutEvents:false} as const;}
  async listStays(_propertyExternalId:string,_since:string):Promise<never>{throw new Error('authorized_stay_integration_unavailable');}
}
