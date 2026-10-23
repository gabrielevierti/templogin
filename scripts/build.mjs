import {execFileSync} from 'node:child_process';
import { build } from 'esbuild';
import { mkdir,copyFile,rm } from 'node:fs/promises';
await rm('dist',{recursive:true,force:true});
await mkdir('dist/public',{recursive:true});
await build({entryPoints:['services/api/main.ts'],outfile:'dist/server.js',bundle:true,platform:'node',target:'node22',format:'esm',packages:'external',sourcemap:true});
await build({entryPoints:['apps/web/temporary.ts'],outfile:'dist/public/app.js',bundle:true,platform:'browser',target:'es2022',format:'esm',minify:true,sourcemap:true});
for(const f of ['index.html','style.css','favicon.svg'])await copyFile('apps/web/'+f,'dist/public/'+f);
for(const f of ['auth-schema.sql','core-schema.sql','oauth-schema.sql'])await copyFile('services/api/'+f,'dist/'+f);
await build({entryPoints:['packages/sdk-js/index.ts'],outfile:'packages/sdk-js/dist/index.js',bundle:true,platform:'neutral',target:'es2022',format:'esm'});
await build({entryPoints:['packages/connector-sdk/index.ts'],outfile:'packages/connector-sdk/dist/index.js',bundle:true,platform:'node',target:'node22',format:'esm',packages:'external'});

await build({entryPoints:['packages/provider-sdk/index.ts'],outfile:'packages/provider-sdk/dist/index.js',bundle:true,platform:'node',target:'node24',format:'esm',packages:'external'});
for(const name of ["sdk-js","connector-sdk","provider-sdk"]){
  execFileSync(process.execPath,["node_modules/typescript/bin/tsc",`packages/${name}/index.ts`,"--declaration","--emitDeclarationOnly","--target","ES2022","--module","NodeNext","--moduleResolution","NodeNext","--skipLibCheck","--strict","--outDir",`packages/${name}/dist`],{stdio:"inherit"});
  await copyFile("LICENSE",`packages/${name}/LICENSE`);
}
