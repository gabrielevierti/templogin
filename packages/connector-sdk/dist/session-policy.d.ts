/** Provider-side primitives. All timestamps are Unix milliseconds from the server clock.
 * These functions enforce policy, NOT authentication. Load records from an authoritative
 * store only after verifying the opaque token and its provider/audience binding.
 */
export interface TemporarySession {
    id: string;
    providerId: string;
    subject: string;
    deviceId: string;
    scopes: readonly string[];
    expiresAt: number;
    revokedAt: number | null;
}
export declare function sessionDeadline(input: {
    now: number;
    durationSeconds: number;
    maxDurationSeconds: number;
    stayEndsAt?: number;
}): number;
/** Call on every protected request AND renewal. Do not trust a browser countdown. */
export declare function assertTemporarySession(session: TemporarySession | undefined, expected: {
    providerId: string;
    deviceId: string;
    scope: string;
}, now: number): asserts session is TemporarySession;
/** A refresh, playback URL or media licence must never extend the original consent. */
export declare function credentialDeadline(now: number, sessionExpiresAt: number, lifetimeSeconds: number): number;
