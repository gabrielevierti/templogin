import type { FastifyInstance, FastifyRequest } from 'fastify';
export interface SqlStore {
    query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{
        rows: T[];
        rowCount: number;
    }>;
    transaction<T>(fn: (tx: SqlStore) => Promise<T>): Promise<T>;
    exec(sql: string): Promise<void>;
}
export interface ProviderIdentity {
    subject: string;
    displayName: string;
    authenticatedAt: number;
}
export interface ProviderOptions {
    /** One trusted provider per deployment. Never take this from request JSON. */
    id: string;
    name: string;
    origin: string;
    maxDurationSeconds: number;
    /** Validate the provider's existing server-side session. No tempLogin account. */
    identity(req: FastifyRequest): Promise<ProviderIdentity | null>;
    /** Check account status/entitlement on approval AND every resource request. Fail closed. */
    entitled(subject: string): Promise<boolean>;
}
export declare const schemaSQL = "\nCREATE TABLE IF NOT EXISTS tl_pairings (\n id TEXT PRIMARY KEY, provider TEXT NOT NULL, secret_hash TEXT UNIQUE NOT NULL,\n code TEXT UNIQUE NOT NULL, device_name TEXT NOT NULL, expires_at BIGINT NOT NULL,\n status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','denied','consumed')),\n last_poll BIGINT NOT NULL DEFAULT 0, interval_ms INTEGER NOT NULL DEFAULT 3000,\n session_id TEXT\n);\nCREATE TABLE IF NOT EXISTS tl_provider_sessions (\n id TEXT PRIMARY KEY, provider TEXT NOT NULL, subject TEXT NOT NULL,\n device_name TEXT NOT NULL, token_hash TEXT UNIQUE, expires_at BIGINT NOT NULL,\n revoked_at BIGINT, created_at BIGINT NOT NULL\n);\nCREATE INDEX IF NOT EXISTS tl_sessions_subject ON tl_provider_sessions(provider,subject);\nCREATE INDEX IF NOT EXISTS tl_pairings_expiry ON tl_pairings(expires_at);\nCREATE INDEX IF NOT EXISTS tl_sessions_expiry ON tl_provider_sessions(expires_at);\n";
export interface ProviderSession {
    id: string;
    provider: string;
    subject: string;
    device_name: string;
    expires_at: number;
    revoked_at: number | null;
    created_at: number;
}
/** Register on a Fastify scope with cookies parsed, rate limits, safe logging and error handling.
 * The plugin additionally enforces its own Origin, no-store and Fetch Metadata checks.
 */
export declare function registerTemporaryLogin(app: FastifyInstance, db: SqlStore, provider: ProviderOptions): Promise<{
    requireSession: (req: FastifyRequest) => Promise<ProviderSession>;
}>;
