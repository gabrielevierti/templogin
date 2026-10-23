import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Database } from './database.js';
import { requireUser } from './auth.js';
import { id, token, hash, fail, audit } from './security.js';
const name=z.string().trim().min(1).max(80);
async function member(db:Database,userId:string,orgId:string,owner=false){
  const m=(await db.query<{role:string}>('SELECT role FROM organization_members WHERE organization_id=$1 AND user_id=$2',[orgId,userId])).rows[0];
  if(!m || (owner && m.role!=='owner')) fail(404,'not_found');
}
export async function registerHospitality(app:FastifyInstance,db:Database){
  app.get('/api/organizations',async req=>{const u=await requireUser(db,req);return (await db.query('SELECT o.id,o.name,m.role FROM organizations o JOIN organization_members m ON m.organization_id=o.id WHERE m.user_id=$1 ORDER BY o.created_at',[u.id])).rows;});
  app.post('/api/organizations',async req=>{
    const u=await requireUser(db,req),b=z.object({name}).strict().parse(req.body),orgId=id();
    await db.transaction(async tx=>{
      await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[u.id]);
      await requireUser(tx,req);
      await tx.query('INSERT INTO organizations(id,name,created_at) VALUES($1,$2,$3)',[orgId,b.name,Date.now()]);
      await tx.query("INSERT INTO organization_members(organization_id,user_id,role) VALUES($1,$2,'owner')",[orgId,u.id]);
      await audit(tx,u.id,'organization.created',orgId,orgId);
    });return {id:orgId,name:b.name};
  });
  app.get<{Params:{id:string}}>('/api/organizations/:id',async req=>{
    const u=await requireUser(db,req),org=req.params.id;await member(db,u.id,org);
    const o=(await db.query('SELECT id,name FROM organizations WHERE id=$1',[org])).rows[0];
    const properties=(await db.query('SELECT id,name FROM properties WHERE organization_id=$1 ORDER BY name',[org])).rows;
    const devices=(await db.query('SELECT id,name,property_id,client_id FROM devices WHERE organization_id=$1 ORDER BY name',[org])).rows;
    const stays=(await db.query('SELECT * FROM stays WHERE organization_id=$1 ORDER BY starts_at DESC LIMIT 200',[org])).rows;
    const events=(await db.query('SELECT action,target_id,created_at FROM audit_events WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 100',[org])).rows;
    return {...o,properties,devices,stays,events};
  });
  app.post<{Params:{id:string}}>('/api/organizations/:id/properties',async req=>{
    const u=await requireUser(db,req),org=req.params.id;await member(db,u.id,org,true);
    const b=z.object({name}).strict().parse(req.body),key=id();
    await db.transaction(async tx=>{
      await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[u.id]);
      await requireUser(tx,req);await tx.query('INSERT INTO properties(id,organization_id,name) VALUES($1,$2,$3)',[key,org,b.name]);await audit(tx,u.id,'property.created',key,org);});return {id:key,name:b.name};
  });
  app.post<{Params:{id:string}}>('/api/organizations/:id/devices',async req=>{
    const u=await requireUser(db,req),org=req.params.id;await member(db,u.id,org,true);
    const b=z.object({name,property_id:z.string().uuid(),client_id:z.enum(['demo-tv','demo-car'])}).strict().parse(req.body);
    const property=(await db.query('SELECT id FROM properties WHERE id=$1 AND organization_id=$2',[b.property_id,org])).rows[0];if(!property)fail(404,'not_found');
    const key=id(),secret=token();
    await db.transaction(async tx=>{
      await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[u.id]);
      await requireUser(tx,req);await tx.query('INSERT INTO devices(id,organization_id,property_id,name,client_id,secret_hash,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)',[key,org,b.property_id,b.name,b.client_id,hash(secret),Date.now()]);await audit(tx,u.id,'device.registered',key,org);});
    return {id:key,secret};
  });
  app.post<{Params:{id:string}}>('/api/organizations/:id/stays',async req=>{
    const u=await requireUser(db,req),org=req.params.id;await member(db,u.id,org,true);
    const b=z.object({property_id:z.string().uuid(),guest_label:name,starts_at:z.number().int().nonnegative(),ends_at:z.number().int().positive()}).strict().refine(b=>b.ends_at>b.starts_at && b.ends_at-b.starts_at<=366*86400000).parse(req.body);
    if(b.ends_at<=Date.now()) fail(400,'stay_in_past');
    const key=id();
    await db.transaction(async tx=>{
      await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[u.id]);
      await requireUser(tx,req);
      const prop=(await tx.query('SELECT id FROM properties WHERE id=$1 AND organization_id=$2 FOR UPDATE',[b.property_id,org])).rows[0];if(!prop)fail(404,'not_found');
      const overlap=(await tx.query('SELECT id FROM stays WHERE property_id=$1 AND checked_out_at IS NULL AND starts_at<$2 AND ends_at>$3',[b.property_id,b.ends_at,b.starts_at])).rows[0];if(overlap)fail(409,'stay_overlap');
      await tx.query('INSERT INTO stays(id,organization_id,property_id,guest_label,starts_at,ends_at) VALUES($1,$2,$3,$4,$5,$6)',[key,org,b.property_id,b.guest_label,b.starts_at,b.ends_at]);
      await audit(tx,u.id,'stay.created',key,org);
    });return {id:key,...b};
  });
  app.post<{Params:{id:string;stayId:string}}>('/api/organizations/:id/stays/:stayId/checkout',async req=>{
    const u=await requireUser(db,req),org=req.params.id;await member(db,u.id,org,true);
    await db.transaction(async tx=>{
      await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[u.id]);
      await requireUser(tx,req);
      const stay=(await tx.query<{id:string;property_id:string}>('SELECT id,property_id FROM stays WHERE id=$1 AND organization_id=$2',[req.params.stayId,org])).rows[0];if(!stay)fail(404,'not_found');
      await tx.query('SELECT id FROM properties WHERE id=$1 FOR UPDATE',[stay.property_id]);
      await tx.query('UPDATE stays SET checked_out_at=COALESCE(checked_out_at,$1) WHERE id=$2',[Date.now(),stay.id]);
      await tx.query("UPDATE grants SET revoked_at=COALESCE(revoked_at,$1),revoke_reason='checkout' WHERE stay_id=$2",[Date.now(),stay.id]);
      await audit(tx,u.id,'stay.checked_out',stay.id,org);
    });return {status:'revocation_verified',external_status:'manual_verification_required'};
  });
  app.post<{Params:{id:string;deviceId:string}}>('/api/organizations/:id/devices/:deviceId/revoke',async req=>{
    const u=await requireUser(db,req),org=req.params.id;await member(db,u.id,org,true);
    const d=(await db.query('SELECT id FROM devices WHERE id=$1 AND organization_id=$2',[req.params.deviceId,org])).rows[0];if(!d)fail(404,'not_found');
    await db.transaction(async tx=>{
      await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[u.id]);
      await requireUser(tx,req);await tx.query('SELECT id FROM devices WHERE id=$1 FOR UPDATE',[req.params.deviceId]);await tx.query('DELETE FROM pairings WHERE device_id=$1',[req.params.deviceId]);await tx.query("UPDATE grants SET revoked_at=COALESCE(revoked_at,$1),revoke_reason='host_reset' WHERE device_id=$2",[Date.now(),req.params.deviceId]);await audit(tx,u.id,'device.revoked',req.params.deviceId,org);});return {status:'revocation_verified',external_status:'manual_verification_required'};
  });
}
