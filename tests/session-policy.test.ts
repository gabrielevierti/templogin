import {expect,it} from 'vitest';
import {sessionDeadline,credentialDeadline,assertTemporarySession,type TemporarySession} from '../packages/connector-sdk/index.js';
const start=1700000000000;
const session:TemporarySession={id:'session-1',providerId:'cinema',subject:'provider-user-7',deviceId:'room-tv',scopes:['playback'],expiresAt:start+3600000,revokedAt:null};
const expected={providerId:'cinema',deviceId:'room-tv',scope:'playback'};
it('caps one hour by checkout and rejects invalid durations and dates',()=>{
 expect(sessionDeadline({now:start,durationSeconds:3600,maxDurationSeconds:86400})).toBe(session.expiresAt);
 expect(sessionDeadline({now:start,durationSeconds:3600,maxDurationSeconds:86400,stayEndsAt:start+1000})).toBe(start+1000);
 for(const durationSeconds of [0,-1,1.5,NaN,Infinity,86401])expect(()=>sessionDeadline({now:start,durationSeconds,maxDurationSeconds:86400})).toThrow();
 for(const stayEndsAt of [NaN,Infinity,start,start-1])expect(()=>sessionDeadline({now:start,durationSeconds:3600,maxDurationSeconds:86400,stayEndsAt})).toThrow();
});
it('rejects access at the exact deadline without a scheduler or browser logout',()=>{
 expect(()=>assertTemporarySession(session,expected,session.expiresAt-1)).not.toThrow();
 expect(()=>assertTemporarySession(session,expected,session.expiresAt)).toThrow('invalid_session');
 expect(()=>assertTemporarySession(session,expected,session.expiresAt+1)).toThrow();
});
it('rejects cross-provider, cross-device, scope escalation and revoked/missing records',()=>{
 for(const altered of [{providerId:'other'},{deviceId:'other'},{scope:'billing'}])expect(()=>assertTemporarySession(session,{...expected,...altered},start)).toThrow();
 for(const invalid of [undefined,{...session,revokedAt:0},{...session,expiresAt:NaN},{...session,subject:''}])expect(()=>assertTemporarySession(invalid,expected,start)).toThrow();
});
it('never slides the session deadline on renewal or media licence issuance',()=>{
 expect(credentialDeadline(start,session.expiresAt,60)).toBe(start+60000);
 expect(credentialDeadline(session.expiresAt-1,session.expiresAt,60)).toBe(session.expiresAt);
 expect(()=>credentialDeadline(session.expiresAt,session.expiresAt,60)).toThrow();
 expect(()=>credentialDeadline(start,session.expiresAt,Infinity)).toThrow();
});
it('revoking one device session does not revoke another session for the same account',()=>{
 const second={...session,id:'session-2',deviceId:'home-tv'};
 expect(()=>assertTemporarySession({...session,revokedAt:start},expected,start)).toThrow();
 expect(()=>assertTemporarySession(second,{...expected,deviceId:'home-tv'},start)).not.toThrow();
});
