import * as oauth from 'oauth4webapi';
export { sessionDeadline, assertTemporarySession, credentialDeadline, type TemporarySession } from './session-policy.js';
export interface ProviderCapabilities {
    accountLinking: boolean;
    providerAuthorization: boolean;
    deviceAuthorization: boolean;
    sessionProvisioning: boolean;
    sessionRevocation: boolean;
    tokenRevocation: boolean;
}
export declare const unsupportedCapabilities: Readonly<ProviderCapabilities>;
export type CleanupState = 'revocation_verified' | 'revocation_requested' | 'revocation_unavailable' | 'error' | 'manual_verification_required';
export interface SessionConnector {
    readonly id: string;
    capabilities(): Readonly<ProviderCapabilities>;
    provisionSession(input: {
        userId: string;
        deviceId: string;
        scopes: string[];
        expiresAt: number;
    }): Promise<{
        sessionId: string;
        expiresAt: number;
    }>;
    revokeSession(sessionId: string): Promise<{
        status: CleanupState;
    }>;
}
export declare class UnavailableSessionConnector implements SessionConnector {
    readonly id: string;
    constructor(id: string);
    capabilities(): Readonly<ProviderCapabilities>;
    provisionSession(_input: {
        userId: string;
        deviceId: string;
        scopes: string[];
        expiresAt: number;
    }): Promise<never>;
    revokeSession(_sessionId: string): Promise<{
        status: CleanupState;
    }>;
}
export interface PendingAuthorization {
    stateHash: string;
    userId: string;
    browserBindingHash: string;
    verifier: string;
    nonce?: string;
    scopes: string[];
    expiresAt: number;
}
/** Implement in PostgreSQL. consume MUST atomically delete and return once, even on failed callback validation. */
export interface AuthorizationStore {
    put(value: PendingAuthorization): Promise<void>;
    consume(stateHash: string): Promise<PendingAuthorization | undefined>;
}
export interface OAuthProviderConfig {
    id: string;
    issuer: string;
    clientId: string;
    clientSecret?: string;
    redirectUri: string;
    scopes: readonly string[];
    oidc: boolean;
    /** Exact origins configured by operator; never derive from request input. Default issuer origin only. */
    allowedEndpointOrigins?: readonly string[];
}
/** Server-only OAuth account authorization. Does not transfer provider tokens to guest devices. */
export declare class OAuthAccountConnector {
    private readonly config;
    private readonly server;
    private readonly store;
    private readonly transport;
    private constructor();
    private client;
    private authentication;
    private options;
    static discover(config: OAuthProviderConfig, store: AuthorizationStore, transport?: typeof fetch): Promise<OAuthAccountConnector>;
    capabilities(): Readonly<ProviderCapabilities>;
    begin(userId: string, browserBinding: string, scopes?: readonly string[]): Promise<{
        authorizationUrl: string;
        expiresIn: number;
    }>;
    complete(callbackUrl: string, userId: string, browserBinding: string): Promise<{
        tokens: oauth.TokenEndpointResponse;
        identity: {
            issuer: string;
            subject: string;
        } | undefined;
        scopes: string[];
    }>;
    refresh(refreshToken: string): Promise<oauth.TokenEndpointResponse>;
    revokeToken(value: string): Promise<{
        status: CleanupState;
        guarantee: 'provider_token_only';
    }>;
}
export interface EncryptedToken {
    version: 1;
    kid: string;
    iv: string;
    ciphertext: string;
    tag: string;
}
/** AES-256-GCM using Node's crypto. Keys are operator-supplied, not generated in source code. */
export declare class TokenVault {
    readonly activeKeyId: string;
    private readonly keys;
    constructor(activeKeyId: string, keys: Readonly<Record<string, Uint8Array>>);
    encrypt(value: string, context: string): EncryptedToken;
    decrypt(envelope: EncryptedToken, context: string): string;
    rotate(envelope: EncryptedToken, context: string): EncryptedToken;
}
/** Future authorized hospitality integration. This contract does not call private Airbnb APIs. */
export interface StayProviderAdapter {
    readonly id: string;
    capabilities(): Readonly<{
        stayImport: boolean;
        checkoutEvents: boolean;
    }>;
    listStays(propertyExternalId: string, since: string): Promise<Array<{
        externalId: string;
        guestLabel: string;
        startsAt: number;
        endsAt: number;
    }>>;
}
export declare class UnavailableStayProviderAdapter implements StayProviderAdapter {
    readonly id: string;
    constructor(id?: string);
    capabilities(): {
        readonly stayImport: false;
        readonly checkoutEvents: false;
    };
    listStays(_propertyExternalId: string, _since: string): Promise<never>;
}
