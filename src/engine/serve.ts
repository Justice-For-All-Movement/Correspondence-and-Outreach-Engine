// Standalone server: migrations, HTTP API and the delivery/reconciliation/sync worker loop.
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { createHttpHandler, createTokenVerifier, objectStoreFromEnv, pgSql, serve } from '../service-kit.ts';
import type { ServiceContext } from '../service-kit.ts';
import { createEngine, manifest, migrate, routes } from './index.ts';

const env = process.env;
function required(name: string): string { const v = env[name]; if (v === undefined || v === '') { console.error(`${name} is required`); process.exit(2); } return v; }
function publicKeys(): Record<string, string> {
  if (env.IDENTITY_PUBLIC_KEYS !== undefined && env.IDENTITY_PUBLIC_KEYS !== '') return JSON.parse(env.IDENTITY_PUBLIC_KEYS) as Record<string, string>;
  if (env.IDENTITY_JWKS_FILE !== undefined && env.IDENTITY_JWKS_FILE !== '') return JSON.parse(readFileSync(env.IDENTITY_JWKS_FILE, 'utf8')) as Record<string, string>;
  console.error('IDENTITY_PUBLIC_KEYS (JSON map kid→PEM) or IDENTITY_JWKS_FILE is required'); return process.exit(2);
}

const pool = new pg.Pool({ connectionString: required('DATABASE_URL'), max: Number(env.DATABASE_POOL_MAX ?? 10) });
const sql = pgSql(pool);
const applied = await migrate(sql);
const testProviders = env.CORRESPONDENCE_ALLOW_PRIVATE_HOSTS === 'true';
const engine = createEngine({ sql, objects: objectStoreFromEnv(env, './data/objects'), config: {
  ...(env.CORRESPONDENCE_SECRET_KEY === undefined || env.CORRESPONDENCE_SECRET_KEY === '' ? {} : { secretKey: env.CORRESPONDENCE_SECRET_KEY }),
  provider: { allowPrivateHosts: testProviders, allowEndpointOverride: testProviders, allowInsecureTls: env.CORRESPONDENCE_ALLOW_INSECURE_TLS === 'true',
    ...(env.CORRESPONDENCE_PROVIDER_TIMEOUT_MS === undefined ? {} : { timeoutMs: Number(env.CORRESPONDENCE_PROVIDER_TIMEOUT_MS) }) },
  ...(env.CORRESPONDENCE_RULES_FILE === undefined ? {} : { rules: JSON.parse(readFileSync(env.CORRESPONDENCE_RULES_FILE, 'utf8')) }),
} });
const handler = createHttpHandler({ name: manifest.name, version: manifest.version, routes: routes(engine), verify: createTokenVerifier({ publicKeys: publicKeys(), ...(env.IDENTITY_ISSUER === undefined ? {} : { issuer: env.IDENTITY_ISSUER }) }),
  health: () => engine.health(), maxBodyBytes: 40 * 1024 * 1024, onError: (error, info) => console.error(JSON.stringify({ level: 'error', ...info, error: error instanceof Error ? error.message : 'error' })) });
const server = await serve(handler, Number(env.PORT ?? 8703), env.HOST ?? '127.0.0.1');
console.log(JSON.stringify({ level: 'info', msg: 'correspondence engine listening', port: (server.address() as { port: number }).port, migrations: applied }));

let stopping = false;
const pollMs = Number(env.CORRESPONDENCE_WORKER_POLL_MS ?? 2000);
const syncEveryMs = Number(env.CORRESPONDENCE_SYNC_INTERVAL_MS ?? 0);
let lastSync = 0;
async function scheduleSyncs(): Promise<void> {
  // Periodic synchronization acts as the engine's own service identity, limited to the sync capability.
  const rows = await sql.query<{ tenant_id: string; project_id: string; id: string }>(`select tenant_id, project_id, id from e03_correspondence.mailboxes where state='active' and provider <> 'ingest_only'`);
  for (const m of rows) {
    const ctx: ServiceContext = { tenantId: m.tenant_id, projectId: m.project_id, purpose: 'mailbox synchronization', requestId: `sync-${Math.floor(Date.now() / Math.max(syncEveryMs, 1))}`, now: new Date().toISOString(),
      actor: { id: 'service:correspondence-sync', kind: 'service', roles: [] }, capabilities: ['correspondence:sync'], compartments: [] };
    try { await engine.syncMailbox(ctx, m.id); } catch (error) { console.error(JSON.stringify({ level: 'error', msg: 'sync scheduling failed', error: error instanceof Error ? error.message : 'error' })); }
  }
}
async function loop(): Promise<void> {
  while (!stopping) {
    try {
      if (syncEveryMs > 0 && Date.now() - lastSync >= syncEveryMs) { lastSync = Date.now(); await scheduleSyncs(); }
      if ((await engine.runWorkerOnce({ limit: 5 })) === 0) await new Promise((r) => setTimeout(r, pollMs));
    } catch (error) { console.error(JSON.stringify({ level: 'error', msg: 'worker pass failed', error: error instanceof Error ? error.message : 'error' })); await new Promise((r) => setTimeout(r, pollMs)); }
  }
}
const worker = env.CORRESPONDENCE_WORKER === 'off' ? Promise.resolve() : loop();
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, () => { stopping = true; server.close(); void worker.then(() => pool.end()).then(() => process.exit(0)); });
