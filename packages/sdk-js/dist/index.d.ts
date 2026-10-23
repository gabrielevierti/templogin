/** tempLogin device SDK. Tokens stay in memory; no cookie or localStorage persistence. */
export type ClientID = 'demo-tv' | 'demo-car';
export type Scope = 'content:read' | 'preferences:read' | 'profile:read';
export interface Pairing {
    device_code: string;
    user_code: string;
    verification_uri: string;
    verification_uri_complete: string;
    expires_in: number;
    interval: number;
}
export interface Tokens {
    access_token: string;
    refresh_token: string;
    token_type: 'Bearer';
    expires_in: number;
    grant_id: string;
    grant_expires_at: number;
    scope: string;
}
export interface ProtectedResource {
    kind: 'tv' | 'car';
    profile: {
        name?: string;
    };
    message: string;
    expires_at: number;
    scopes: Scope[];
    preferences?: {
        theme: string;
        temperature: number;
    };
}
export declare class TempLoginError extends Error {
    readonly code: string;
    readonly status: number;
    readonly retryAfter?: number | undefined;
    constructor(code: string, status: number, retryAfter?: number | undefined);
}
export declare class TempLoginDevice {
    readonly clientId: ClientID;
    private readonly transport;
    private tokens;
    private accessExpiresAt;
    private refreshPromise;
    private pairingDeadline;
    private currentPairing;
    private generation;
    private polling;
    readonly origin: string;
    constructor(origin: string, clientId: ClientID, transport?: typeof fetch);
    private request;
    begin(deviceName: string, scopes: Scope[], registered?: {
        id: string;
        secret: string;
    }, signal?: AbortSignal): Promise<Pairing>;
    /** Display only verification_uri_complete as QR; never display device_code. */
    waitForApproval(pairing: Pairing, signal?: AbortSignal): Promise<Tokens>;
    private accept;
    /** Concurrent callers share one refresh. An uncertain network outcome discards local tokens. */
    refresh(signal?: AbortSignal): Promise<Tokens>;
    resource(signal?: AbortSignal): Promise<ProtectedResource>;
    logout(signal?: AbortSignal): Promise<void>;
    /** For local reset only. Does not assert server revocation; prefer logout(). */
    clear(): void;
}
