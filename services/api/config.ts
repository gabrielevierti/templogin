import { isIP } from 'node:net';
export interface Config {
  /** Archived account-based reference APIs. Off by default; not the product flow. */
  legacyWallet?: boolean;
  origin: string;
  rpID: string;
  production: boolean;
  databaseUrl?: string;
  dataDir?: string;
  port: number;
  trustedProxies?: string[];
  metricsToken?: string;
}
export function readConfig(): Config {
  const production = process.env.NODE_ENV === 'production';
  const origin = process.env.PUBLIC_ORIGIN || 'http://localhost:3000';
  const url = new URL(origin);
  if (url.origin !== origin || (production && url.protocol !== 'https:')) throw new Error('PUBLIC_ORIGIN must be an origin, HTTPS in production');
  if (!production && url.protocol !== 'https:' && !['localhost','127.0.0.1'].includes(url.hostname)) throw new Error('Use HTTPS for non-localhost passkeys');
  if (production && !process.env.DATABASE_URL) throw new Error('DATABASE_URL required in production');
  const rpID = process.env.RP_ID || url.hostname;
  if (url.hostname !== rpID && !url.hostname.endsWith('.' + rpID)) throw new Error('RP_ID must match PUBLIC_ORIGIN');
  const port = Number(process.env.PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
  const trustedProxies=process.env.TRUSTED_PROXY?.split(',').map(s=>s.trim()).filter(Boolean);
  if(trustedProxies?.some(s=>!isIP(s))) throw new Error('TRUSTED_PROXY must list explicit proxy IP addresses');
  const metricsToken=process.env.METRICS_TOKEN;
  if(metricsToken && metricsToken.length<32)throw new Error('METRICS_TOKEN must contain at least 32 random characters');
  return { origin, rpID, production, trustedProxies, metricsToken, databaseUrl: process.env.DATABASE_URL, dataDir: process.env.DATA_DIR || './.data', port };
}
