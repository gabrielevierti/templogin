import { createDatabase } from '../services/api/database.js';
import {schemaSQL} from '../packages/provider-sdk/index.js';
import { readConfig } from '../services/api/config.js';
const db=await createDatabase(readConfig());
try{
  await db.exec(schemaSQL);
  const now=Date.now();
  await db.transaction(async tx=>{
    await tx.query('DELETE FROM tl_pairings WHERE expires_at<=$1',[now]);
    await tx.query('DELETE FROM tl_provider_sessions WHERE expires_at<=$1',[now]);
    if((await tx.query<{name:string|null}>("SELECT to_regclass('tl_demo_logins')::text AS name")).rows[0].name)await tx.query('DELETE FROM tl_demo_logins WHERE expires_at<=$1',[now]);
    await tx.query('DELETE FROM rate_limits WHERE window_start<$1',[now-3600000]);
    await tx.query('DELETE FROM oauth_pending WHERE expires_at<=$1',[now]);
    await tx.query('DELETE FROM auth_challenges WHERE expires_at<=$1',[now]);
    await tx.query('DELETE FROM user_sessions WHERE expires_at<=$1',[now]);
    await tx.query('DELETE FROM access_tokens WHERE expires_at<=$1',[now]);
    // Keep spent refresh tokens until the grant expires for replay detection.
    await tx.query('DELETE FROM refresh_tokens WHERE expires_at<=$1',[now]);
    await tx.query('DELETE FROM pairings WHERE expires_at<$1',[now-86400000]);
    await tx.query('DELETE FROM grants WHERE expires_at<$1',[now-90*86400000]);
    await tx.query('DELETE FROM audit_events WHERE created_at<$1',[now-90*86400000]);
  });
  console.log('Expired transient data and history older than 90 days removed.');
}finally{await db.close();}
