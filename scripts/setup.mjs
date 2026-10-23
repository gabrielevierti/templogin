import { writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
const password=randomBytes(32).toString('hex');
await writeFile('.env',`POSTGRES_PASSWORD=${password}\nPUBLIC_ORIGIN=http://localhost:3000\nRP_ID=localhost\nPORT=3000\n# Set DOMAIN=login.example.com for production\n# Uncomment for local network PostgreSQL:\n# DATABASE_URL=postgres://templogin:${password}@127.0.0.1:5432/templogin\n`,{flag:'wx',mode:0o600});
console.log('Created .env with a fresh secret. Existing files are never overwritten.');
