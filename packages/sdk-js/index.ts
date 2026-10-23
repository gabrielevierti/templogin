/** tempLogin device SDK. Tokens stay in memory; no cookie or localStorage persistence. */
export type ClientID = 'demo-tv' | 'demo-car';
export type Scope = 'content:read' | 'preferences:read' | 'profile:read';
export interface Pairing {
  device_code: string; user_code: string; verification_uri: string;
  verification_uri_complete: string; expires_in: number; interval: number;
}
export interface Tokens {
  access_token: string; refresh_token: string; token_type: 'Bearer'; expires_in: number;
  grant_id: string; grant_expires_at: number; scope: string;
}
export interface ProtectedResource {kind:'tv'|'car'; profile:{name?:string};message:string;expires_at:number;scopes:Scope[];preferences?:{theme:string;temperature:number}}
export class TempLoginError extends Error {
  constructor(public readonly code:string,public readonly status:number,public readonly retryAfter?:number){super(code);this.name='TempLoginError';}
}
function wait(milliseconds:number,signal?:AbortSignal):Promise<void>{
  return new Promise((resolve,reject)=>{
    if(signal?.aborted){reject(signal.reason);return;}
    const abort=()=>{clearTimeout(timer);reject(signal?.reason);};
    const timer=setTimeout(()=>{signal?.removeEventListener('abort',abort);resolve();},milliseconds);
    signal?.addEventListener('abort',abort,{once:true});
  });
}
export class TempLoginDevice {
  private tokens:Tokens|undefined;
  private accessExpiresAt=0;
  private refreshPromise:Promise<Tokens>|undefined;
  private pairingDeadline=0;
  private currentPairing:Pairing|undefined;
  private generation=0;
  private polling=false;
  readonly origin:string;
  constructor(origin:string,readonly clientId:ClientID,private readonly transport:typeof fetch=fetch){
    const u=new URL(origin);
    if(u.origin!==origin||u.username||u.password||(u.protocol!=='https:'&&!['localhost','127.0.0.1','[::1]'].includes(u.hostname)))throw new Error('Use an HTTPS origin (HTTP localhost is allowed for development)');
    this.origin=origin;
  }
  private async request<T>(path:string,body?:unknown,access?:string,signal?:AbortSignal):Promise<T>{
    const response=await this.transport(this.origin+'/api'+path,{
      method:body===undefined?'GET':'POST',credentials:'omit',redirect:'error',cache:'no-store',
      headers:{...(body===undefined?{}:{'Content-Type':'application/json'}),...(access?{Authorization:'Bearer '+access}:{})},
      body:body===undefined?undefined:JSON.stringify(body),signal:signal?AbortSignal.any([signal,AbortSignal.timeout(15000)]):AbortSignal.timeout(15000),
    });
    const payload=await response.json();
    if(!response.ok)throw new TempLoginError(typeof payload?.error==='string'?payload.error:'request_failed',response.status,Number(response.headers.get('Retry-After'))||undefined);
    return payload as T;
  }
  async begin(deviceName:string,scopes:Scope[],registered?:{id:string;secret:string},signal?:AbortSignal):Promise<Pairing>{
    if(this.tokens||this.refreshPromise)throw new TempLoginError('logout_required',409);
    if(this.currentPairing||this.polling)throw new TempLoginError('pairing_already_started',409);
    const pairing=await this.request<Pairing>('/pairings',{client_id:this.clientId,device_name:deviceName,scopes,...(registered?{device_id:registered.id,device_secret:registered.secret}:{})},undefined,signal);
    this.currentPairing=pairing;this.pairingDeadline=Date.now()+pairing.expires_in*1000;
    return pairing;
  }
  /** Display only verification_uri_complete as QR; never display device_code. */
  async waitForApproval(pairing:Pairing,signal?:AbortSignal):Promise<Tokens>{
    if(pairing!==this.currentPairing||this.polling)throw new TempLoginError('unknown_pairing',400);
    this.polling=true;
    try {
    let interval=pairing.interval*1000;
    while(Date.now()<this.pairingDeadline){
      if(this.currentPairing!==pairing)throw new TempLoginError('operation_cancelled',400);
      await wait(Math.min(interval,this.pairingDeadline-Date.now()),signal);
      if(Date.now()>=this.pairingDeadline)break;
      try{
        const result=await this.request<Tokens>('/token',{grant_type:'urn:ietf:params:oauth:grant-type:device_code',device_code:pairing.device_code,client_id:this.clientId},undefined,signal);
        if(this.currentPairing!==pairing)throw new TempLoginError('operation_cancelled',400);
        this.currentPairing=undefined;return this.accept(result);
      }catch(error){
        if(!(error instanceof TempLoginError))throw error; // A network failure can hide a consumed result. Restart pairing explicitly.
        if(error.code==='authorization_pending')continue;
        if(error.code==='slow_down'){interval+=5000;continue;}
        if(error.status===429){interval=Math.max(interval,(error.retryAfter||60)*1000);continue;}
        this.currentPairing=undefined;throw error;
      }
    }
    this.currentPairing=undefined;throw new TempLoginError('expired_token',400);
    } finally {if(this.currentPairing===pairing)this.currentPairing=undefined;this.polling=false;}
  }
  private accept(result:Tokens){this.tokens=result;this.accessExpiresAt=Date.now()+result.expires_in*1000;return result;}
  /** Concurrent callers share one refresh. An uncertain network outcome discards local tokens. */
  async refresh(signal?:AbortSignal):Promise<Tokens>{
    if(this.refreshPromise)return this.refreshPromise;
    const previous=this.tokens,generation=this.generation;
    if(!previous)throw new TempLoginError('not_authorized',401);
    if(previous.grant_expires_at<=Date.now()){this.clear();throw new TempLoginError('expired_token',401);}
    this.tokens=undefined;
    this.refreshPromise=this.request<Tokens>('/token',{grant_type:'refresh_token',refresh_token:previous.refresh_token,client_id:this.clientId},undefined,signal)
      .then(result=>{if(generation!==this.generation)throw new TempLoginError('operation_cancelled',400);return this.accept(result);}).finally(()=>{this.refreshPromise=undefined;});
    return this.refreshPromise;
  }
  async resource(signal?:AbortSignal):Promise<ProtectedResource>{
    if(this.refreshPromise)await this.refreshPromise;
    if(!this.tokens)throw new TempLoginError('not_authorized',401);
    if(Date.now()>=this.accessExpiresAt-5000)await this.refresh(signal);
    try{return await this.request<ProtectedResource>('/resource',undefined,this.tokens!.access_token,signal);}
    catch(error){if(error instanceof TempLoginError&&error.status===401)this.clear();throw error;}
  }
  async logout(signal?:AbortSignal):Promise<void>{
    try{
      if(this.refreshPromise)await this.refreshPromise;
      if(!this.tokens)return;
      if(Date.now()>=this.accessExpiresAt-5000)await this.refresh(signal);
      await this.request('/device/logout',{},this.tokens!.access_token,signal);
    }finally{this.clear();}
  }
  /** For local reset only. Does not assert server revocation; prefer logout(). */
  clear(){this.generation++;this.tokens=undefined;this.currentPairing=undefined;this.accessExpiresAt=0;}
}
