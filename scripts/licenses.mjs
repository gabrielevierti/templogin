import {readFile,writeFile} from 'node:fs/promises';
const lock=JSON.parse(await readFile('package-lock.json','utf8'));
const entries=[];
for(const [path,metadata] of Object.entries(lock.packages)){
  if(!path)continue;
  try{
    const pkg=JSON.parse(await readFile(path+'/package.json','utf8'));
    entries.push({name:pkg.name,version:pkg.version,license:pkg.license||pkg.licenses||'UNDECLARED',developmentOnly:Boolean(metadata.dev),repository:typeof pkg.repository==='object'?pkg.repository.url:pkg.repository||null});
  }catch{/* Optional platform-specific dependencies not installed here. */}
}
entries.sort((a,b)=>a.name.localeCompare(b.name)||a.version.localeCompare(b.version));
await writeFile('docs/DEPENDENCY-LICENSES.json',JSON.stringify({notice:'Inventory of installed packages; consult each package LICENSE and NOTICE before redistributing. Missing optional platform packages must be reviewed on target platform.',packages:entries},null,2)+'\n');
console.log(`Recorded ${entries.length} installed dependency licenses.`);
