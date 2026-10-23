import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { Pool, type PoolClient } from 'pg';
import { PGlite } from '@electric-sql/pglite';

export interface Database {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: T[]; rowCount: number }>;
  transaction<T>(fn: (tx: Database) => Promise<T>): Promise<T>;
  exec(sql: string): Promise<void>;
  close(): Promise<void>;
}
export interface DatabaseConfig {
  production: boolean;
  databaseUrl?: string;
  dataDir?: string;
}

export async function createDatabase(config: DatabaseConfig): Promise<Database> {
  let db: Database;
  if (config.databaseUrl) {
    const pool = new Pool({ connectionString: config.databaseUrl, max: 10, connectionTimeoutMillis: 10000 });
    const connection = (client: Pool | PoolClient): Database => ({
      async query<T>(sql: string, params: unknown[] = []) {
        const result = await client.query(sql, params);
        return { rows: result.rows as T[], rowCount: result.rowCount ?? result.rows.length };
      },
      async exec(sql) { await client.query(sql); },
      async transaction<T>(fn: (tx: Database) => Promise<T>): Promise<T> {
        if (client !== pool) throw new Error('Nested transactions are not supported');
        const leased = await pool.connect();
        try {
          await leased.query('BEGIN');
          const result = await fn(connection(leased));
          await leased.query('COMMIT');
          return result;
        } catch (error) {
          await leased.query('ROLLBACK');
          throw error;
        } finally { leased.release(); }
      },
      async close() { if (client === pool) await pool.end(); },
    });
    db = connection(pool);
  } else {
    if (config.production) throw new Error('Production requires DATABASE_URL for PostgreSQL');
    const engine = new PGlite(config.dataDir);
    await engine.waitReady;
    let queue: Promise<unknown> = Promise.resolve();
    const lock = <T>(fn: () => Promise<T>): Promise<T> => {
      const next = queue.then(fn, fn);
      queue = next.catch(() => undefined);
      return next;
    };
    const direct: Database = {
      async query<T>(sql: string, params: unknown[] = []) {
        const result = await engine.query<T>(sql, params);
        return { rows: result.rows, rowCount: Math.max(result.affectedRows ?? 0, result.rows.length) };
      },
      async exec(sql) { await engine.exec(sql); },
      async transaction() { throw new Error('Nested transactions are not supported'); },
      async close() { await engine.close(); },
    };
    db = {
      query: <T>(sql: string, params: unknown[] = []) => lock(() => direct.query<T>(sql, params)),
      exec: (sql: string) => lock(() => direct.exec(sql)),
      close: () => lock(() => direct.close()),
      transaction: <T>(fn: (tx: Database) => Promise<T>) => lock(async () => {
        await direct.exec('BEGIN');
        try {
          const result = await fn(direct);
          await direct.exec('COMMIT');
          return result;
        } catch (error) {
          await direct.exec('ROLLBACK');
          throw error;
        }
      }),
    };
  }
  try {
    await db.transaction(async (tx) => {
      if (config.databaseUrl) await tx.query('SELECT pg_advisory_xact_lock(734866021)');
      await tx.exec('CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at BIGINT NOT NULL)');
      for (const name of ['auth-schema.sql', 'core-schema.sql', 'oauth-schema.sql']) {
        const sql = await readFile(new URL(name, import.meta.url), 'utf8');
        const checksum = createHash('sha256').update(sql).digest('hex');
        const existing = await tx.query<{checksum: string}>('SELECT checksum FROM schema_migrations WHERE name=$1', [name]);
        if (existing.rows[0]) {
          if (existing.rows[0].checksum !== checksum) throw new Error(`Migration checksum mismatch: ${name}; create a new versioned migration`);
          continue;
        }
        await tx.exec(sql);
        await tx.query('INSERT INTO schema_migrations(name,checksum,applied_at) VALUES ($1,$2,$3)', [name, checksum, Date.now()]);
      }
    });
    return db;
  } catch (error) { await db.close(); throw error; }
}
