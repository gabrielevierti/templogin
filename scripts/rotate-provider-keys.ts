import {createDatabase} from '../services/api/database.js';
import {readConfig} from '../services/api/config.js';
import {TokenVault,type EncryptedToken} from '../packages/connector-sdk/index.js';
const keyring=JSON.parse(process.env.TOKEN_KEYRING||'{}') as Record<string,string>;
const keys=Object.fromEntries(Object.entries(keyring).map(([kid,value])=>{
  if(typeof value!=='string'||!/^[A-Za-z0-9+/]{43}=$/.test(value))throw new Error('Invalid TOKEN_KEYRING encoding');
  return [kid,Buffer.from(value,'base64')];
}));
const vault=new TokenVault(process.env.TOKEN_ACTIVE_KEY_ID||'',keys);
const db=await createDatabase(readConfig());
try{
  const count=await db.transaction(async tx=>{
    const connections=(await tx.query<{id:string;user_id:string;provider_id:string;token_envelope:EncryptedToken}>('SELECT id,user_id,provider_id,token_envelope FROM oauth_connections FOR UPDATE')).rows;
    for(const connection of connections){
      const envelope=vault.rotate(connection.token_envelope,JSON.stringify([connection.user_id,connection.provider_id]));
      await tx.query('UPDATE oauth_connections SET token_envelope=$1 WHERE id=$2',[JSON.stringify(envelope),connection.id]);
    }
    return connections.length;
  });
  console.log(`Re-encrypted ${count} provider connection(s).`);
}finally{await db.close();}
