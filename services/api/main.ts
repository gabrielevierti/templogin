import { createApp } from './app.js';
import { readConfig } from './config.js';
const config=readConfig();
const app=await createApp(config);
await app.listen({port:config.port,host:process.env.HOST||'127.0.0.1'});
console.log(`tempLogin listening at ${config.origin}`);
for(const signal of ['SIGINT','SIGTERM'] as const)process.once(signal,()=>{void app.close().then(()=>process.exit(0));});
