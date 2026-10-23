/** Provider-side primitives. All timestamps are Unix milliseconds from the server clock.
 * These functions enforce policy, NOT authentication. Load records from an authoritative
 * store only after verifying the opaque token and its provider/audience binding.
 */
export interface TemporarySession {
  id:string;
  providerId:string;
  subject:string;
  deviceId:string;
  scopes:readonly string[];
  expiresAt:number;
  revokedAt:number|null;
}
const timestamp=(n:number)=>Number.isSafeInteger(n)&&n>=0;
export function sessionDeadline(input:{now:number;durationSeconds:number;maxDurationSeconds:number;stayEndsAt?:number}):number {
  const {now,durationSeconds,maxDurationSeconds,stayEndsAt}=input;
  if(!timestamp(now)||!Number.isSafeInteger(durationSeconds)||durationSeconds<1||
    !Number.isSafeInteger(maxDurationSeconds)||maxDurationSeconds<1||durationSeconds>maxDurationSeconds||
    (stayEndsAt!==undefined&&!timestamp(stayEndsAt)))throw new Error('invalid_session_policy');
  const end=Math.min(now+durationSeconds*1000,stayEndsAt??Number.MAX_SAFE_INTEGER);
  if(!timestamp(end)||end<=now)throw new Error('invalid_session_policy');
  return end;
}
/** Call on every protected request AND renewal. Do not trust a browser countdown. */
export function assertTemporarySession(session:TemporarySession|undefined,expected:{providerId:string;deviceId:string;scope:string},now:number):asserts session is TemporarySession {
  if(!timestamp(now)||!session||!session.id||!session.subject||!expected.providerId||!expected.deviceId||!expected.scope||
    session.providerId!==expected.providerId||session.deviceId!==expected.deviceId||
    !timestamp(session.expiresAt)||session.expiresAt<=now||session.revokedAt!==null||
    !Array.isArray(session.scopes)||!session.scopes.includes(expected.scope))throw new Error('invalid_session');
}
/** A refresh, playback URL or media licence must never extend the original consent. */
export function credentialDeadline(now:number,sessionExpiresAt:number,lifetimeSeconds:number):number {
  if(!timestamp(now)||!timestamp(sessionExpiresAt)||sessionExpiresAt<=now||
    !Number.isSafeInteger(lifetimeSeconds)||lifetimeSeconds<1)throw new Error('invalid_session_policy');
  const end=Math.min(now+lifetimeSeconds*1000,sessionExpiresAt);
  if(!timestamp(end))throw new Error('invalid_session_policy');
  return end;
}
