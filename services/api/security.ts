import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { Database } from './database.js';
export const token = () => randomBytes(32).toString('base64url');
export const hash = (value: string) => createHash('sha256').update(value).digest('hex');
export const id = () => randomUUID();
export function fail(statusCode: number, message: string): never { throw Object.assign(new Error(message), {statusCode}); }
export async function audit(db: Database, userId: string|null, action: string, target: string|null = null, org: string|null = null) {
  await db.query('INSERT INTO audit_events(id,user_id,organization_id,action,target_id,created_at) VALUES($1,$2,$3,$4,$5,$6)', [id(),userId,org,action,target,Date.now()]);
}
