import type {FastifyInstance} from 'fastify';
import {registerTemporaryLogin,type SqlStore,type ProviderOptions} from '../packages/provider-sdk/index.js';
/** The provider injects real authentication and entitlement functions.
 * There is intentionally no permissive default or fictitious production identity.
 * Supply host-level TLS, rate limiting, safe error handling and log redaction first.
 */
export async function installProviderTemporaryLogin(app:FastifyInstance,db:SqlStore,options:ProviderOptions){
 return registerTemporaryLogin(app,db,options);
}
