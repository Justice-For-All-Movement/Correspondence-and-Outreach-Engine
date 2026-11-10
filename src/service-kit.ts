// Accountability engine service kit, version 1.
// Source of truth: Identity-Authorization-and-Policy-Engine/src/service-kit.ts.
// Other engines vendor this file byte-identically (same convention as contracts.ts).
// Zero runtime dependencies: PostgreSQL access is through a structural pool type.
import { createHash, createHmac, createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, sign as edSign, verify as edVerify } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { lstat, mkdir, readdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { DomainError, canonical, invariant } from './contracts.ts';
import type { Actor, Context, Json, Scope } from './contracts.ts';

export const SERVICE_KIT_VERSION = '1.0.1';

// ───────────────────────────── SQL ─────────────────────────────
export type Row = Record<string, unknown>;
export interface Sql {
  query<T extends Row = Row>(text: string, params?: readonly unknown[]): Promise<T[]>;
  /** Runs fn in a transaction (or a savepoint when already inside one). */
  tx<T>(fn: (tx: Sql) => Promise<T>): Promise<T>;
}
export interface PgClientLike { query(text: string, params?: unknown[]): Promise<{ rows: unknown[] }>; release(err?: unknown): void }
export interface PgPoolLike { query(text: string, params?: unknown[]): Promise<{ rows: unknown[] }>; connect(): Promise<PgClientLike> }

function clientSql(client: { query(text: string, params?: unknown[]): Promise<{ rows: unknown[] }> }, depth: number): Sql {
  let counter = 0;
  return {
    async query<T extends Row = Row>(text: string, params: readonly unknown[] = []): Promise<T[]> {
      return (await client.query(text, [...params])).rows as T[];
    },
    async tx<T>(fn: (tx: Sql) => Promise<T>): Promise<T> {
      const name = `kit_sp_${depth}_${++counter}`;
      await client.query(`savepoint ${name}`);
      try { const out = await fn(clientSql(client, depth + 1)); await client.query(`release savepoint ${name}`); return out; }
      catch (error) { await client.query(`rollback to savepoint ${name}`); throw error; }
    },
  };
}

/** Adapts a node-postgres Pool (or compatible) to Sql. */
export function pgSql(pool: PgPoolLike): Sql {
  return {
    async query<T extends Row = Row>(text: string, params: readonly unknown[] = []): Promise<T[]> {
      return (await pool.query(text, [...params])).rows as T[];
    },
    async tx<T>(fn: (tx: Sql) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      try {
        await client.query('begin');
        const out = await fn(clientSql(client, 1));
        await client.query('commit');
        client.release();
        return out;
      } catch (error) {
        try { await client.query('rollback'); client.release(); } catch (rollbackError) { client.release(rollbackError); }
        throw error;
      }
    },
  };
}

const IDENT = /^[a-z][a-z0-9_]{0,48}$/;
export function ident(name: string): string { invariant(IDENT.test(name), 'invalid_identifier', 'Invalid SQL identifier'); return name; }

export type Migration = Readonly<{ id: string; sql: string }>;

/** Kit tables every engine schema receives: outbox, idempotency, audit and jobs. `{s}` is the schema name. */
const KIT_BASE = `
create table if not exists {s}._events (
  seq bigint generated always as identity primary key,
  xid xid8 not null default pg_current_xact_id(),
  tenant_id text not null, project_id text not null,
  type text not null, subject text not null, payload jsonb not null,
  actor_id text not null, request_id text not null, occurred_at timestamptz not null
);
create index if not exists _events_tenant on {s}._events (tenant_id, seq);
create table if not exists {s}._idempotency (
  tenant_id text not null, project_id text not null, key text not null,
  input_digest text not null, result jsonb, created_at timestamptz not null default now(),
  primary key (tenant_id, project_id, key)
);
create table if not exists {s}._audit (
  seq bigint generated always as identity primary key,
  tenant_id text not null, project_id text not null, tenant_seq bigint not null,
  action text not null, subject text not null, detail jsonb not null,
  actor_id text not null, actor_kind text not null, purpose text not null, request_id text not null,
  at timestamptz not null, previous_hash text not null, hash text not null,
  unique (tenant_id, tenant_seq)
);
create index if not exists _audit_subject on {s}._audit (tenant_id, subject);
create table if not exists {s}._jobs (
  id uuid primary key,
  tenant_id text not null, project_id text not null,
  kind text not null, dedupe_key text, payload jsonb not null, ctx jsonb not null,
  state text not null default 'queued' check (state in ('queued','leased','done','failed','dead','cancelled','paused')),
  attempts int not null default 0, max_attempts int not null default 5,
  run_at timestamptz not null, lease_owner text, lease_until timestamptz, generation int not null default 0,
  result jsonb, last_error text, created_at timestamptz not null, updated_at timestamptz not null
);
create unique index if not exists _jobs_dedupe on {s}._jobs (tenant_id, project_id, kind, dedupe_key) where dedupe_key is not null;
create index if not exists _jobs_ready on {s}._jobs (state, run_at);
`;

/** Applies kit tables then engine migrations in order, once each, under an advisory lock. Returns newly applied ids. */
export async function runMigrations(sql: Sql, schema: string, migrations: readonly Migration[]): Promise<string[]> {
  const s = ident(schema);
  return sql.tx(async (tx) => {
    await tx.query('select pg_advisory_xact_lock(hashtext($1))', [`kit-migrate:${s}`]);
    await tx.query(`create schema if not exists ${s}`);
    await tx.query(`create table if not exists ${s}._migrations (id text primary key, checksum text not null, applied_at timestamptz not null default now())`);
    await tx.query(KIT_BASE.replaceAll('{s}', s));
    const done = new Map((await tx.query<{ id: string; checksum: string }>(`select id, checksum from ${s}._migrations`)).map((r) => [r.id, r.checksum]));
    const applied: string[] = [];
    for (const m of migrations) {
      const checksum = createHash('sha256').update(m.sql).digest('hex');
      const prior = done.get(m.id);
      if (prior !== undefined) { invariant(prior === checksum, 'migration_changed', `Applied migration ${m.id} was modified`); continue; }
      await tx.query(m.sql.replaceAll('{s}', s));
      await tx.query(`insert into ${s}._migrations (id, checksum) values ($1, $2)`, [m.id, checksum]);
      applied.push(m.id);
    }
    return applied;
  });
}

// ───────────────────────────── Context & capabilities ─────────────────────────────
export type ServiceContext = Context & Readonly<{
  /** Purpose-specific capabilities such as `evidence:read`. `engine:*` grants an engine; there is no global wildcard. */
  capabilities: readonly string[];
  compartments: readonly string[];
  tokenId?: string;
  policyVersion?: string;
  locale?: string;
}>;

/**
 * Actions that move information or value out of the system, or change who may do so. They are never satisfied by an
 * `engine:*` wildcard: a role must name them exactly (research permission does not imply disclosure, contact, release or spend).
 */
export const SENSITIVE_ACTIONS: readonly string[] = ['disclose_identity', 'contact', 'send', 'publish', 'approve', 'spend', 'grant', 'admin', 'export', 'withdraw', 'events'];
export function hasCapability(ctx: ServiceContext, capability: string): boolean {
  if (ctx.capabilities.includes(capability)) return true;
  const colon = capability.indexOf(':');
  if (colon <= 0 || SENSITIVE_ACTIONS.includes(capability.slice(colon + 1))) return false;
  return ctx.capabilities.includes(`${capability.slice(0, colon)}:*`);
}
/** Fails closed: any missing or malformed context denies. */
export function requireCapability(ctx: ServiceContext, capability: string): void {
  invariant(ctx !== null && typeof ctx === 'object' && Array.isArray(ctx.capabilities), 'unauthenticated', 'Authenticated context required');
  invariant(typeof ctx.tenantId === 'string' && ctx.tenantId.length > 0 && typeof ctx.projectId === 'string' && ctx.projectId.length > 0, 'unauthenticated', 'Scoped context required');
  if (!hasCapability(ctx, capability)) throw new DomainError('forbidden', `Missing capability ${capability}`);
}
export function requireCompartment(ctx: ServiceContext, compartment: string | null | undefined): void {
  if (compartment === null || compartment === undefined || compartment === '') return;
  if (!ctx.compartments.includes(compartment)) throw new DomainError('not_found', 'Not found');
}
export function scopeOf(ctx: Scope): Scope { return { tenantId: ctx.tenantId, projectId: ctx.projectId }; }

// ───────────────────────────── Access tokens (EdDSA compact JWS) ─────────────────────────────
export type TokenClaims = Readonly<{
  iss: string; sub: string; kind: Actor['kind']; tid: string; pid: string;
  roles: readonly string[]; caps: readonly string[]; cmp: readonly string[];
  purpose: string; pv: string; iat: number; exp: number; jti: string; locale?: string;
}>;
export type SigningKey = Readonly<{ kid: string; privateKeyPem: string; publicKeyPem: string }>;

const b64u = (b: Uint8Array | string): string => Buffer.from(b).toString('base64url');

export function generateSigningKey(kid: string = randomUUID()): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { kid, privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString() };
}
export function signAccessToken(claims: TokenClaims, key: Pick<SigningKey, 'kid' | 'privateKeyPem'>): string {
  const head = b64u(JSON.stringify({ alg: 'EdDSA', typ: 'JWT', kid: key.kid }));
  const body = b64u(JSON.stringify(claims));
  const sig = edSign(null, Buffer.from(`${head}.${body}`), createPrivateKey(key.privateKeyPem));
  return `${head}.${body}.${b64u(sig)}`;
}
export type TokenVerifier = (token: string, request: { requestId: string; now?: Date }) => Promise<ServiceContext>;
export type TokenVerifierOptions = Readonly<{
  publicKeys: Readonly<Record<string, string>>;
  issuer?: string;
  /** Consulted on every verification; throw or return true to deny. Absent means signature+expiry only. */
  isRevoked?: (claims: TokenClaims) => Promise<boolean>;
  clockSkewSeconds?: number;
}>;
const isStrings = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === 'string');

export function createTokenVerifier(options: TokenVerifierOptions): TokenVerifier {
  const deny = (): never => { throw new DomainError('unauthenticated', 'Invalid or expired credentials'); };
  return async (token, request) => {
    try {
      if (typeof token !== 'string' || token.length > 16384) deny();
      const parts = token.split('.');
      if (parts.length !== 3) deny();
      const [head, body, sig] = parts as [string, string, string];
      const header = JSON.parse(Buffer.from(head, 'base64url').toString('utf8')) as { alg?: unknown; kid?: unknown };
      if (header.alg !== 'EdDSA' || typeof header.kid !== 'string' || !Object.hasOwn(options.publicKeys, header.kid)) deny();
      const pem = options.publicKeys[header.kid as string] as string;
      if (!edVerify(null, Buffer.from(`${head}.${body}`), createPublicKey(pem), Buffer.from(sig, 'base64url'))) deny();
      const c = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as TokenClaims;
      const now = Math.floor((request.now ?? new Date()).getTime() / 1000);
      const skew = options.clockSkewSeconds ?? 5;
      if (typeof c.exp !== 'number' || typeof c.iat !== 'number' || c.exp <= now || c.iat > now + skew) deny();
      if (options.issuer !== undefined && c.iss !== options.issuer) deny();
      if (typeof c.sub !== 'string' || !c.sub || typeof c.tid !== 'string' || !c.tid || typeof c.pid !== 'string' || !c.pid) deny();
      if (c.kind !== 'human' && c.kind !== 'agent' && c.kind !== 'service') deny();
      if (!isStrings(c.roles) || !isStrings(c.caps) || !isStrings(c.cmp) || typeof c.purpose !== 'string' || typeof c.jti !== 'string') deny();
      if (c.caps.includes('*')) deny();
      if (options.isRevoked !== undefined && await options.isRevoked(c)) deny();
      return {
        tenantId: c.tid, projectId: c.pid, purpose: c.purpose, requestId: request.requestId,
        now: (request.now ?? new Date()).toISOString(),
        actor: { id: c.sub, kind: c.kind, roles: [...c.roles] },
        capabilities: [...c.caps], compartments: [...c.cmp], tokenId: c.jti, policyVersion: String(c.pv ?? ''),
        ...(typeof c.locale === 'string' ? { locale: c.locale } : {}),
      };
    } catch (error) {
      if (error instanceof DomainError && error.code === 'unauthenticated') throw error;
      return deny();
    }
  };
}

// ───────────────────────────── Universal references ─────────────────────────────
/** `E05:evidence_version:<id>@<revision>`; revision optional. Ids must not contain ':' or '@'. */
export function uref(engine: string, kind: string, id: string, revision?: number): string {
  invariant(/^E\d\d$/.test(engine) && /^[a-z][a-z0-9_]*$/.test(kind) && /^[A-Za-z0-9._~-]+$/.test(id), 'invalid_reference', 'Invalid universal reference');
  return `${engine}:${kind}:${id}${revision === undefined ? '' : `@${revision}`}`;
}
export function parseUref(value: string): { engine: string; kind: string; id: string; revision?: number } {
  const m = /^(E\d\d):([a-z][a-z0-9_]*):([A-Za-z0-9._~-]+)(?:@(\d+))?$/.exec(value);
  invariant(m !== null, 'invalid_reference', 'Invalid universal reference');
  const [, engine, kind, id, rev] = m as unknown as [string, string, string, string, string | undefined];
  return rev === undefined ? { engine, kind, id } : { engine, kind, id, revision: Number(rev) };
}
/** True when `candidate` names the same object as `ref`, at the same revision if `ref` pins one. */
export function urefMatches(ref: string, candidate: string): boolean {
  const a = parseUref(ref), b = parseUref(candidate);
  return a.engine === b.engine && a.kind === b.kind && a.id === b.id && (a.revision === undefined || b.revision === undefined || a.revision === b.revision);
}

// ───────────────────────────── Outbox events ─────────────────────────────
export type EngineEvent = Readonly<{
  id: string; engine?: string; tenantId: string; projectId: string; type: string; subject: string;
  payload: Json; actorId: string; requestId: string; occurredAt: string;
}>;
export async function emitEvent(tx: Sql, schema: string, ctx: Context, type: string, subject: string, payload: Json): Promise<EngineEvent> {
  const rows = await tx.query<{ seq: string }>(
    `insert into ${ident(schema)}._events (tenant_id, project_id, type, subject, payload, actor_id, request_id, occurred_at) values ($1,$2,$3,$4,$5::jsonb,$6,$7,$8) returning seq::text as seq`,
    [ctx.tenantId, ctx.projectId, type, subject, JSON.stringify(payload), ctx.actor.id, ctx.requestId, ctx.now]);
  return { id: (rows[0] as { seq: string }).seq, tenantId: ctx.tenantId, projectId: ctx.projectId, type, subject, payload, actorId: ctx.actor.id, requestId: ctx.requestId, occurredAt: ctx.now };
}
/**
 * Reads committed events after a cursor in a gap-safe order: rows written by transactions that may still be
 * in flight are withheld, so a consumer that stores the last id never skips a late commit. Delivery is at-least-once.
 */
export async function readEvents(sql: Sql, schema: string, options: { after?: string; limit?: number; tenantId?: string } = {}): Promise<EngineEvent[]> {
  const limit = Math.min(Math.max(options.limit ?? 200, 1), 1000);
  const rows = await sql.query<{ seq: string; tenant_id: string; project_id: string; type: string; subject: string; payload: Json; actor_id: string; request_id: string; occurred_at: Date }>(
    `select e.seq::text as seq, e.tenant_id, e.project_id, e.type, e.subject, e.payload, e.actor_id, e.request_id, e.occurred_at from ${ident(schema)}._events e
     where e.seq > $1::bigint and e.xid < pg_snapshot_xmin(pg_current_snapshot()) and ($2::text is null or e.tenant_id = $2) order by e.seq limit ${limit}`,
    [options.after ?? '0', options.tenantId ?? null]);
  return rows.map((r) => ({ id: r.seq, tenantId: r.tenant_id, projectId: r.project_id, type: r.type, subject: r.subject, payload: r.payload, actorId: r.actor_id, requestId: r.request_id, occurredAt: new Date(r.occurred_at).toISOString() }));
}

// ───────────────────────────── Idempotency ─────────────────────────────
/** Runs fn once per (scope, key). A replay with identical input returns the stored result; different input conflicts. */
export async function idempotent<T extends Json>(tx: Sql, schema: string, ctx: Context, key: string | undefined, input: unknown, fn: () => Promise<T>): Promise<T> {
  if (key === undefined) return fn();
  invariant(typeof key === 'string' && key.length > 0 && key.length <= 200, 'invalid_input', 'Invalid idempotency key');
  const s = ident(schema);
  const inputDigest = createHash('sha256').update(canonical(JSON.parse(JSON.stringify(input ?? null)))).digest('hex');
  const inserted = await tx.query(`insert into ${s}._idempotency (tenant_id, project_id, key, input_digest) values ($1,$2,$3,$4) on conflict do nothing returning key`, [ctx.tenantId, ctx.projectId, key, inputDigest]);
  if (inserted.length === 0) {
    const prior = (await tx.query<{ input_digest: string; result: T | null }>(`select input_digest, result from ${s}._idempotency where tenant_id=$1 and project_id=$2 and key=$3 for update`, [ctx.tenantId, ctx.projectId, key]))[0];
    invariant(prior !== undefined && prior.input_digest === inputDigest, 'idempotency_conflict', 'Idempotency key was used with different input');
    invariant(prior.result !== null, 'idempotency_conflict', 'Original request did not complete');
    return prior.result;
  }
  const result = await fn();
  await tx.query(`update ${s}._idempotency set result=$4::jsonb where tenant_id=$1 and project_id=$2 and key=$3`, [ctx.tenantId, ctx.projectId, key, JSON.stringify(result)]);
  return result;
}

// ───────────────────────────── Audit (hash chained per tenant) ─────────────────────────────
export type AuditRecord = Readonly<{
  id: string; tenantId: string; projectId: string; tenantSeq: number; action: string; subject: string; detail: Json;
  actorId: string; actorKind: string; purpose: string; requestId: string; at: string; previousHash: string; hash: string;
}>;
function auditHash(r: Omit<AuditRecord, 'id' | 'hash'>): string {
  return createHash('sha256').update(canonical({ tenantId: r.tenantId, projectId: r.projectId, tenantSeq: r.tenantSeq, action: r.action, subject: r.subject, detail: r.detail, actorId: r.actorId, actorKind: r.actorKind, purpose: r.purpose, requestId: r.requestId, at: r.at, previousHash: r.previousHash })).digest('hex');
}
/** Records what was actually done. Never put secrets or protected content in `detail`; reference by id. */
export async function appendAudit(tx: Sql, schema: string, ctx: Context, action: string, subject: string, detail: Json = {}): Promise<void> {
  const s = ident(schema);
  await tx.query('select pg_advisory_xact_lock(hashtext($1))', [`kit-audit:${s}:${ctx.tenantId}`]);
  const last = (await tx.query<{ tenant_seq: string; hash: string }>(`select a.tenant_seq::text as tenant_seq, a.hash from ${s}._audit a where a.tenant_id=$1 order by a.tenant_seq desc limit 1`, [ctx.tenantId]))[0];
  const at = new Date(ctx.now).toISOString();
  const base = { tenantId: ctx.tenantId, projectId: ctx.projectId, tenantSeq: last === undefined ? 1 : Number(last.tenant_seq) + 1, action, subject, detail: JSON.parse(JSON.stringify(detail)) as Json, actorId: ctx.actor.id, actorKind: ctx.actor.kind, purpose: ctx.purpose, requestId: ctx.requestId, at, previousHash: last?.hash ?? '' };
  await tx.query(`insert into ${s}._audit (tenant_id, project_id, tenant_seq, action, subject, detail, actor_id, actor_kind, purpose, request_id, at, previous_hash, hash) values ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10,$11,$12,$13)`,
    [base.tenantId, base.projectId, base.tenantSeq, action, subject, JSON.stringify(base.detail), base.actorId, base.actorKind, base.purpose, base.requestId, at, base.previousHash, auditHash(base)]);
}
export async function listAudit(sql: Sql, schema: string, scope: Scope, options: { after?: string; limit?: number; subject?: string; allProjects?: boolean } = {}): Promise<AuditRecord[]> {
  const limit = Math.min(Math.max(options.limit ?? 200, 1), 1000);
  const rows = await sql.query<Record<string, unknown>>(
    `select a.seq::text as seq, a.tenant_id, a.project_id, a.tenant_seq::text as tenant_seq, a.action, a.subject, a.detail, a.actor_id, a.actor_kind, a.purpose, a.request_id, a.at, a.previous_hash, a.hash from ${ident(schema)}._audit a
     where a.tenant_id=$1 and ($2::text is null or a.project_id=$2) and a.seq > $3::bigint and ($4::text is null or a.subject=$4) order by a.seq limit ${limit}`,
    [scope.tenantId, options.allProjects === true ? null : scope.projectId, options.after ?? '0', options.subject ?? null]);
  return rows.map((r) => ({ id: r.seq as string, tenantId: r.tenant_id as string, projectId: r.project_id as string, tenantSeq: Number(r.tenant_seq), action: r.action as string, subject: r.subject as string, detail: r.detail as Json, actorId: r.actor_id as string, actorKind: r.actor_kind as string, purpose: r.purpose as string, requestId: r.request_id as string, at: new Date(r.at as Date).toISOString(), previousHash: r.previous_hash as string, hash: r.hash as string }));
}
/** Verifies a complete, ordered tenant chain (use listAudit with allProjects). */
export function verifyAuditChain(records: readonly AuditRecord[]): boolean {
  let previous = '';
  for (const [i, r] of records.entries()) {
    if (r.tenantSeq !== i + 1 || r.previousHash !== previous || auditHash(r) !== r.hash) return false;
    previous = r.hash;
  }
  return true;
}

// ───────────────────────────── Durable jobs (leases, retries, pause, cancel) ─────────────────────────────
export type JobState = 'queued' | 'leased' | 'done' | 'failed' | 'dead' | 'cancelled' | 'paused';
export type Job = Readonly<{
  id: string; tenantId: string; projectId: string; kind: string; payload: Json; ctx: ServiceContext;
  state: JobState; attempts: number; maxAttempts: number; generation: number; leaseOwner: string | null;
  leaseUntil: string | null; runAt: string; result: Json | null; lastError: string | null;
}>;
const JOB_COLS = `id, tenant_id, project_id, kind, payload, ctx, state, attempts, max_attempts, generation, lease_owner, lease_until, run_at, result, last_error`;
function toJob(r: Record<string, unknown>): Job {
  return { id: r.id as string, tenantId: r.tenant_id as string, projectId: r.project_id as string, kind: r.kind as string, payload: r.payload as Json, ctx: r.ctx as ServiceContext, state: r.state as JobState, attempts: r.attempts as number, maxAttempts: r.max_attempts as number, generation: r.generation as number, leaseOwner: (r.lease_owner as string | null) ?? null, leaseUntil: r.lease_until ? new Date(r.lease_until as Date).toISOString() : null, runAt: new Date(r.run_at as Date).toISOString(), result: (r.result as Json | null) ?? null, lastError: (r.last_error as string | null) ?? null };
}
/** Enqueues work in the caller's transaction. With `dedupeKey`, a second enqueue returns the existing job. */
export async function enqueueJob(tx: Sql, schema: string, ctx: ServiceContext, job: { kind: string; payload: Json; dedupeKey?: string; runAt?: Date; maxAttempts?: number }): Promise<Job> {
  const s = ident(schema);
  const id = randomUUID();
  const rows = await tx.query(`insert into ${s}._jobs (id, tenant_id, project_id, kind, dedupe_key, payload, ctx, max_attempts, run_at, created_at, updated_at)
    values ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8,$9,$10,$10) on conflict do nothing returning ${JOB_COLS}`,
    [id, ctx.tenantId, ctx.projectId, job.kind, job.dedupeKey ?? null, JSON.stringify(job.payload), JSON.stringify(ctx), job.maxAttempts ?? 5, (job.runAt ?? new Date(ctx.now)).toISOString(), ctx.now]);
  if (rows[0] !== undefined) return toJob(rows[0]);
  const prior = await tx.query(`select ${JOB_COLS} from ${s}._jobs where tenant_id=$1 and project_id=$2 and kind=$3 and dedupe_key=$4`, [ctx.tenantId, ctx.projectId, job.kind, job.dedupeKey ?? null]);
  invariant(prior[0] !== undefined, 'conflict', 'Job could not be enqueued');
  return toJob(prior[0]);
}
/**
 * Leases ready jobs (queued and due, or leased with an expired lease). Each lease bumps `generation`; completing or
 * failing requires the same owner and generation, so a worker that lost its lease cannot publish a result.
 * A job whose attempts are exhausted when its lease expires becomes `dead` instead of being leased again.
 */
export async function leaseJobs(sql: Sql, schema: string, options: { worker: string; kinds?: readonly string[]; limit?: number; leaseMs?: number; now?: Date }): Promise<Job[]> {
  const s = ident(schema);
  const now = (options.now ?? new Date()).toISOString();
  const until = new Date((options.now ?? new Date()).getTime() + (options.leaseMs ?? 60_000)).toISOString();
  return sql.tx(async (tx) => {
    await tx.query(`update ${s}._jobs set state='dead', lease_owner=null, lease_until=null, last_error=coalesce(last_error,'lease expired after final attempt'), updated_at=$1
      where state='leased' and lease_until < $1 and attempts >= max_attempts`, [now]);
    const rows = await tx.query(`update ${s}._jobs set state='leased', lease_owner=$2, lease_until=$3, attempts=attempts+1, generation=generation+1, updated_at=$1
      where id in (select id from ${s}._jobs where ((state='queued' and run_at <= $1) or (state='leased' and lease_until < $1))
        and ($4::text[] is null or kind = any($4)) order by run_at, created_at limit ${Math.min(Math.max(options.limit ?? 1, 1), 100)} for update skip locked)
      returning ${JOB_COLS}`, [now, options.worker, until, options.kinds === undefined ? null : [...options.kinds]]);
    return rows.map(toJob);
  });
}
async function settle(sql: Sql, schema: string, job: Pick<Job, 'id' | 'leaseOwner' | 'generation'>, set: string, params: unknown[]): Promise<Job> {
  const rows = await sql.query(`update ${ident(schema)}._jobs set ${set}, updated_at=now() where id=$1 and state='leased' and lease_owner=$2 and generation=$3 returning ${JOB_COLS}`, [job.id, job.leaseOwner, job.generation, ...params]);
  invariant(rows[0] !== undefined, 'lease_lost', 'Job lease is no longer held');
  return toJob(rows[0]);
}
export function heartbeatJob(sql: Sql, schema: string, job: Job, leaseMs = 60_000): Promise<Job> {
  return settle(sql, schema, job, `lease_until=$4`, [new Date(Date.now() + leaseMs).toISOString()]);
}
export function completeJob(sql: Sql, schema: string, job: Job, result: Json = null): Promise<Job> {
  return settle(sql, schema, job, `state='done', result=$4::jsonb, lease_owner=null, lease_until=null`, [JSON.stringify(result)]);
}
/** Retries with backoff until attempts are exhausted, then marks the job dead. `permanent` skips retries. */
export function failJob(sql: Sql, schema: string, job: Job, error: string, options: { retryInMs?: number; permanent?: boolean } = {}): Promise<Job> {
  const exhausted = options.permanent === true || job.attempts >= job.maxAttempts;
  const retryIn = options.retryInMs ?? Math.min(60_000 * 30, 1000 * 2 ** job.attempts);
  return exhausted
    ? settle(sql, schema, job, `state='dead', last_error=$4, lease_owner=null, lease_until=null`, [error.slice(0, 2000)])
    : settle(sql, schema, job, `state='queued', last_error=$4, run_at=$5, lease_owner=null, lease_until=null`, [error.slice(0, 2000), new Date(Date.now() + retryIn).toISOString()]);
}
/** Operator controls. Cancel/pause apply to queued and leased jobs; a leased worker then loses its lease (lease_lost). */
export async function controlJob(sql: Sql, schema: string, scope: Scope, id: string, action: 'cancel' | 'pause' | 'resume' | 'retry'): Promise<Job> {
  const s = ident(schema);
  const q = action === 'cancel' ? `state='cancelled', lease_owner=null, lease_until=null where state in ('queued','leased','paused','failed')`
    : action === 'pause' ? `state='paused', lease_owner=null, lease_until=null where state in ('queued','leased')`
    : action === 'resume' ? `state='queued' where state='paused'`
    : `state='queued', attempts=0, run_at=now() where state in ('dead','failed','cancelled')`;
  const rows = await sql.query(`update ${s}._jobs set ${q} and id=$1 and tenant_id=$2 and project_id=$3 returning ${JOB_COLS}`.replace(' where ', ', updated_at=now() where '), [id, scope.tenantId, scope.projectId]);
  if (rows[0] !== undefined) return toJob(rows[0]);
  const cur = await sql.query(`select ${JOB_COLS} from ${s}._jobs where id=$1 and tenant_id=$2 and project_id=$3`, [id, scope.tenantId, scope.projectId]);
  invariant(cur[0] !== undefined, 'not_found', 'Not found');
  throw new DomainError('invalid_state', `Job in state ${toJob(cur[0]).state} cannot ${action}`);
}
export async function getJob(sql: Sql, schema: string, scope: Scope, id: string): Promise<Job | null> {
  const rows = await sql.query(`select ${JOB_COLS} from ${ident(schema)}._jobs where id=$1 and tenant_id=$2 and project_id=$3`, [id, scope.tenantId, scope.projectId]);
  return rows[0] === undefined ? null : toJob(rows[0]);
}
export async function listJobs(sql: Sql, schema: string, scope: Scope, options: { states?: readonly JobState[]; kind?: string; limit?: number } = {}): Promise<Job[]> {
  const rows = await sql.query(`select ${JOB_COLS} from ${ident(schema)}._jobs where tenant_id=$1 and project_id=$2 and ($3::text[] is null or state = any($3)) and ($4::text is null or kind=$4) order by created_at desc limit ${Math.min(Math.max(options.limit ?? 100, 1), 500)}`,
    [scope.tenantId, scope.projectId, options.states === undefined ? null : [...options.states], options.kind ?? null]);
  return rows.map(toJob);
}
export type JobHandler = (job: Job) => Promise<Json | void>;
/** Runs one polling pass. Handlers must be idempotent: delivery is at-least-once. Returns the number of jobs processed. */
export async function runJobsOnce(sql: Sql, schema: string, handlers: Readonly<Record<string, JobHandler>>, options: { worker: string; limit?: number; leaseMs?: number }): Promise<number> {
  const jobs = await leaseJobs(sql, schema, { worker: options.worker, kinds: Object.keys(handlers), limit: options.limit ?? 5, ...(options.leaseMs === undefined ? {} : { leaseMs: options.leaseMs }) });
  for (const job of jobs) {
    try {
      const result = await (handlers[job.kind] as JobHandler)(job);
      await completeJob(sql, schema, job, (result ?? null) as Json);
    } catch (error) {
      if (error instanceof DomainError && error.code === 'lease_lost') continue;
      const permanent = error instanceof DomainError && ['forbidden', 'unauthenticated', 'invalid_input', 'not_found', 'consent_denied', 'budget_exhausted'].includes(error.code);
      const message = error instanceof DomainError ? `${error.code}: ${error.message}` : error instanceof Error ? error.message : String(error);
      try { await failJob(sql, schema, job, message, { permanent }); } catch (settleError) { if (!(settleError instanceof DomainError && settleError.code === 'lease_lost')) throw settleError; }
    }
  }
  return jobs.length;
}

// ───────────────────────────── Standard engine surface ─────────────────────────────
export type EngineManifestV1 = Readonly<{ id: string; name: string; version: string; kit: string; capabilities: readonly string[]; emits: readonly string[]; consumes: readonly string[] }>;
export type Inspection = Readonly<{
  ref: string; kind: string; title: string; state: string;
  stale: boolean; blocked: boolean; staleReasons: readonly string[];
  versions: readonly Readonly<{ revision: number; at: string; actorId: string; summary?: string }>[];
  /** Upstream universal references this object depends on (evidence, claims, permissions, assets …). */
  sources: readonly string[];
  dependents: readonly string[];
  permissions: readonly Json[];
  decisions: readonly Json[];
  history: readonly Readonly<{ at: string; actorId: string; action: string; detail?: Json }>[];
  data: Json;
}>;
export type SearchHit = Readonly<{ ref: string; kind: string; title: string; snippet: string; state?: string }>;
/** A change in another engine that may make this engine's dependent objects stale or blocked. Idempotent by eventId. */
export type UpstreamChange = Readonly<{
  eventId: string;
  kind: 'source_corrected' | 'source_superseded' | 'source_removed' | 'permission_withdrawn' | 'permission_changed' | 'claim_changed' | 'content_changed' | 'render_changed' | 'audience_changed' | 'rights_changed';
  refs: readonly string[]; reason: string;
}>;
export interface StandardEngine {
  readonly manifest: EngineManifestV1;
  /** Returns null (never an error naming the object) when the ref is unknown or outside the caller's scope/compartments. */
  inspect(ctx: ServiceContext, ref: string): Promise<Inspection | null>;
  search(ctx: ServiceContext, query: { q: string; limit?: number }): Promise<SearchHit[]>;
  audit(ctx: ServiceContext, options?: { after?: string; limit?: number; subject?: string }): Promise<AuditRecord[]>;
  /** Service-only outbox feed for the orchestrator's event router. */
  events(ctx: ServiceContext, options?: { after?: string; limit?: number }): Promise<EngineEvent[]>;
  applyUpstreamChange(ctx: ServiceContext, change: UpstreamChange): Promise<{ affected: string[] }>;
  health(): Promise<{ ok: boolean; detail: Json }>;
}

// Cross-engine ports. An engine declares the ports it needs; the host (PAM or a standalone deployment) supplies them.
export type UseAction = 'investigate' | 'preserve' | 'cite' | 'reproduce' | 'adapt' | 'publish' | 'license' | 'contact' | 'process';
export type UseDecision = Readonly<{ decision: 'allow' | 'deny' | 'review'; reasons: readonly string[]; permissionRefs: readonly string[]; restrictions: readonly string[]; decidedAt: string }>;
export interface UseDecisionPort {
  /** E11. Subjects are universal refs (identities, testimony, originals, derivatives, assets). Unknown ≠ deny for citation. */
  decide(ctx: ServiceContext, request: { subjects: readonly string[]; action: UseAction; purpose: string; audience?: string; territory?: string; destination?: string }): Promise<UseDecision>;
}
export interface AuthorizationPort {
  /** E01. Re-checked before sensitive side effects; must fail closed (throw or allowed:false) when it cannot decide. */
  authorize(ctx: ServiceContext, request: { capability: string; resource?: string }): Promise<{ allowed: boolean; reason: string; policyVersion: string }>;
}
export type EvidenceVersionInfo = Readonly<{ ref: string; evidenceId: string; revision: number; sha256: string; size: number; mediaType: string; filename: string; compartment: string | null; available: boolean }>;
export interface EvidencePort {
  /** E05. */
  describe(ctx: ServiceContext, ref: string): Promise<EvidenceVersionInfo | null>;
  getBytes(ctx: ServiceContext, ref: string): Promise<Uint8Array>;
  accept(ctx: ServiceContext, input: { bytes: Uint8Array; mediaType: string; filename: string; origin: Json; compartment?: string; idempotencyKey?: string }): Promise<EvidenceVersionInfo>;
  addDerivative(ctx: ServiceContext, input: { parent: string; bytes: Uint8Array; mediaType: string; filename: string; relation: string; tool: Json; idempotencyKey?: string }): Promise<EvidenceVersionInfo>;
}
export interface BudgetPort {
  /** E13. reserve throws DomainError('budget_exhausted') when a ceiling would be exceeded. */
  reserve(ctx: ServiceContext, request: { category: string; amount: number; unit: string; subject: string; idempotencyKey: string }): Promise<{ reservationId: string }>;
  commit(ctx: ServiceContext, reservationId: string, actual: { amount: number; detail?: Json }): Promise<void>;
  release(ctx: ServiceContext, reservationId: string, reason: string): Promise<void>;
}

// ───────────────────────────── HTTP ─────────────────────────────
export type HttpRequest = Readonly<{
  method: string; path: string; params: Readonly<Record<string, string>>; query: URLSearchParams;
  headers: IncomingMessage['headers']; body: unknown; raw: Uint8Array; ctx: ServiceContext;
}>;
export type HttpResponse = Readonly<{ status?: number; json?: unknown; bytes?: Uint8Array; text?: string; headers?: Readonly<Record<string, string>> }>;
export type Route = Readonly<{
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'; path: string;
  /** Public routes receive no ctx (ctx is undefined at runtime); use only for health and participant bootstrap. */
  public?: boolean;
  handler: (request: HttpRequest) => Promise<HttpResponse | Json | void>;
}>;
const STATUS: Readonly<Record<string, number>> = {
  unauthenticated: 401, forbidden: 403, scope_denied: 404, not_found: 404, conflict: 409, idempotency_conflict: 409, invalid_state: 409,
  revision_conflict: 409, lease_lost: 409, stale: 409, consent_denied: 403, approval_invalid: 409, budget_exhausted: 402, rate_limited: 429,
  payload_too_large: 413, unsupported_media_type: 415, unavailable: 503, provider_unavailable: 503, takeover_active: 409, grant_invalid: 403,
};
export function errorStatus(code: string): number { return STATUS[code] ?? (code.startsWith('invalid_') ? 400 : 500); }
function isResponse(value: unknown): value is HttpResponse {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && (Object.hasOwn(value, 'json') || Object.hasOwn(value, 'bytes') || Object.hasOwn(value, 'text') || Object.hasOwn(value, 'status')) && Object.keys(value).every((k) => ['status', 'json', 'bytes', 'text', 'headers'].includes(k));
}
export type HttpHandlerOptions = Readonly<{
  name: string; version: string; routes: readonly Route[]; verify: TokenVerifier;
  maxBodyBytes?: number; health?: () => Promise<{ ok: boolean; detail: Json }>;
  onError?: (error: unknown, info: { requestId: string; method: string; path: string }) => void;
}>;
/** Builds a node:http listener. Bearer tokens are verified per request; unknown routes and foreign objects answer 404. */
export function createHttpHandler(options: HttpHandlerOptions): (req: IncomingMessage, res: ServerResponse) => void {
  const compiled = options.routes.map((route) => {
    const names: string[] = [];
    const pattern = route.path.split('/').map((seg) => seg.startsWith(':') ? (names.push(seg.slice(1)), '([^/]+)') : seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('/');
    return { route, names, regex: new RegExp(`^${pattern}$`) };
  });
  const send = (res: ServerResponse, requestId: string, out: HttpResponse): void => {
    const headers: Record<string, string> = { 'x-request-id': requestId, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...out.headers };
    if (out.bytes !== undefined) { res.writeHead(out.status ?? 200, { 'content-type': 'application/octet-stream', ...headers, 'content-length': String(out.bytes.byteLength) }); res.end(out.bytes); return; }
    if (out.text !== undefined) { res.writeHead(out.status ?? 200, { 'content-type': 'text/plain; charset=utf-8', ...headers }); res.end(out.text); return; }
    const body = Buffer.from(JSON.stringify(out.json ?? null));
    res.writeHead(out.status ?? 200, { 'content-type': 'application/json; charset=utf-8', ...headers, 'content-length': String(body.byteLength) }); res.end(body);
  };
  return (req, res) => {
    const requestId = typeof req.headers['x-request-id'] === 'string' && /^[A-Za-z0-9._-]{1,100}$/.test(req.headers['x-request-id']) ? req.headers['x-request-id'] : randomUUID();
    const url = new URL(req.url ?? '/', 'http://engine.invalid');
    const method = (req.method ?? 'GET').toUpperCase();
    void (async () => {
      try {
        if (method === 'GET' && url.pathname === '/healthz') {
          const h = options.health === undefined ? { ok: true, detail: {} as Json } : await options.health();
          return send(res, requestId, { status: h.ok ? 200 : 503, json: { engine: options.name, version: options.version, ...h } });
        }
        let match: { route: Route; params: Record<string, string> } | undefined;
        for (const c of compiled) {
          if (c.route.method !== method) continue;
          const m = c.regex.exec(url.pathname);
          if (m === null) continue;
          const params: Record<string, string> = {};
          c.names.forEach((n, i) => { params[n] = decodeURIComponent(m[i + 1] as string); });
          match = { route: c.route, params }; break;
        }
        if (match === undefined) throw new DomainError('not_found', 'Not found');
        let ctx = undefined as unknown as ServiceContext;
        if (match.route.public !== true) {
          const auth = req.headers.authorization;
          if (typeof auth !== 'string' || !auth.startsWith('Bearer ')) throw new DomainError('unauthenticated', 'Bearer token required');
          ctx = await options.verify(auth.slice(7), { requestId });
        }
        const max = options.maxBodyBytes ?? 64 * 1024 * 1024;
        const chunks: Buffer[] = []; let size = 0;
        for await (const chunk of req) { size += (chunk as Buffer).byteLength; if (size > max) throw new DomainError('payload_too_large', 'Request body too large'); chunks.push(chunk as Buffer); }
        const raw = Buffer.concat(chunks);
        let body: unknown = undefined;
        const type = String(req.headers['content-type'] ?? '');
        if (raw.byteLength > 0 && type.includes('application/json')) {
          try { body = JSON.parse(raw.toString('utf8')); } catch { throw new DomainError('invalid_json', 'Malformed JSON body'); }
        }
        const out = await match.route.handler({ method, path: url.pathname, params: match.params, query: url.searchParams, headers: req.headers, body, raw: new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength), ctx });
        send(res, requestId, isResponse(out) ? out : { json: out ?? null });
      } catch (error) {
        if (error instanceof DomainError) {
          const status = errorStatus(error.code);
          if (status < 500) return send(res, requestId, { status, json: { error: { code: status === 404 ? 'not_found' : error.code, message: status === 404 ? 'Not found' : error.message, requestId } } });
        }
        options.onError?.(error, { requestId, method, path: url.pathname });
        if (!res.headersSent) send(res, requestId, { status: 500, json: { error: { code: 'internal', message: 'Internal error', requestId } } });
        else res.destroy();
      }
    })();
  };
}
/** Standard routes every engine serves in addition to its own `/v1/...` API. */
export function standardRoutes(engine: StandardEngine): Route[] {
  const num = (v: string | null): number | undefined => (v === null ? undefined : Number(v));
  return [
    { method: 'GET', path: '/v1/manifest', public: true, handler: async () => engine.manifest as unknown as Json },
    { method: 'GET', path: '/v1/inspect', handler: async (r) => { const out = await engine.inspect(r.ctx, r.query.get('ref') ?? ''); if (out === null) throw new DomainError('not_found', 'Not found'); return out as unknown as Json; } },
    { method: 'GET', path: '/v1/search', handler: async (r) => { const limit = num(r.query.get('limit')); return (await engine.search(r.ctx, { q: r.query.get('q') ?? '', ...(limit === undefined ? {} : { limit }) })) as unknown as Json; } },
    { method: 'GET', path: '/v1/audit', handler: async (r) => { const limit = num(r.query.get('limit')); const after = r.query.get('after'); const subject = r.query.get('subject'); return (await engine.audit(r.ctx, { ...(after === null ? {} : { after }), ...(limit === undefined ? {} : { limit }), ...(subject === null ? {} : { subject }) })) as unknown as Json; } },
    { method: 'GET', path: '/v1/events', handler: async (r) => { const limit = num(r.query.get('limit')); const after = r.query.get('after'); return (await engine.events(r.ctx, { ...(after === null ? {} : { after }), ...(limit === undefined ? {} : { limit }) })) as unknown as Json; } },
    { method: 'POST', path: '/v1/upstream-changes', handler: async (r) => (await engine.applyUpstreamChange(r.ctx, r.body as UpstreamChange)) as unknown as Json },
  ];
}
export function serve(handler: (req: IncomingMessage, res: ServerResponse) => void, port: number, host = '127.0.0.1'): Promise<Server> {
  return new Promise((resolveServer, reject) => {
    const server = createServer(handler);
    server.once('error', reject);
    server.listen(port, host, () => resolveServer(server));
  });
}
/** Minimal authenticated JSON client for another engine's HTTP API. */
export function engineClient(baseUrl: string, getToken: () => Promise<string> | string): { call<T = unknown>(method: string, path: string, body?: unknown): Promise<T>; bytes(path: string): Promise<Uint8Array> } {
  const request = async (method: string, path: string, body?: unknown): Promise<Response> => {
    const response = await fetch(new URL(path, baseUrl), { method, headers: { authorization: `Bearer ${await getToken()}`, ...(body === undefined ? {} : { 'content-type': body instanceof Uint8Array ? 'application/octet-stream' : 'application/json' }) }, ...(body === undefined ? {} : { body: (body instanceof Uint8Array ? body : JSON.stringify(body)) as BodyInit }) });
    if (!response.ok) {
      let code = 'unavailable', message = `HTTP ${response.status}`;
      try { const parsed = await response.json() as { error?: { code?: string; message?: string } }; code = parsed.error?.code ?? code; message = parsed.error?.message ?? message; } catch { /* non-JSON error body */ }
      throw new DomainError(code, message);
    }
    return response;
  };
  return {
    async call<T = unknown>(method: string, path: string, body?: unknown): Promise<T> { return await (await request(method, path, body)).json() as T; },
    async bytes(path: string): Promise<Uint8Array> { return new Uint8Array(await (await request('GET', path)).arrayBuffer()); },
  };
}

// ───────────────────────────── Object storage ─────────────────────────────
export type ObjectInfo = Readonly<{ key: string; size: number; sha256: string }>;
export interface ObjectStore {
  put(key: string, bytes: Uint8Array): Promise<ObjectInfo>;
  /** Throws DomainError('not_found') when absent. */
  get(key: string): Promise<Uint8Array>;
  head(key: string): Promise<{ size: number } | null>;
  delete(key: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
}
const KEY = /^[A-Za-z0-9][A-Za-z0-9._-]*(\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/;
export function validObjectKey(key: string): string {
  invariant(typeof key === 'string' && key.length <= 512 && KEY.test(key) && !key.split('/').some((p) => p === '..' || p === '.'), 'invalid_input', 'Invalid object key');
  return key;
}
const sha256Hex = (bytes: Uint8Array | string): string => createHash('sha256').update(bytes).digest('hex');

/** Local filesystem store: atomic writes, no symlink traversal. Suitable for single-node and development deployments. */
export class FsObjectStore implements ObjectStore {
  readonly #root: string;
  constructor(root: string) { this.#root = resolve(root); }
  async #path(key: string, create: boolean): Promise<string> {
    const full = join(this.#root, ...validObjectKey(key).split('/'));
    invariant(full.startsWith(this.#root + sep), 'invalid_input', 'Invalid object key');
    if (create) await mkdir(dirname(full), { recursive: true });
    let dir = dirname(full);
    while (dir.startsWith(this.#root) && dir !== this.#root) {
      try { invariant(!(await lstat(dir)).isSymbolicLink(), 'invalid_input', 'Symbolic links are not allowed in object storage'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      dir = dirname(dir);
    }
    return full;
  }
  async put(key: string, bytes: Uint8Array): Promise<ObjectInfo> {
    const copy = Uint8Array.from(bytes);
    const full = await this.#path(key, true);
    const tmp = `${full}.tmp-${randomUUID()}`;
    await writeFile(tmp, copy, { flag: 'wx', mode: 0o600 });
    await rename(tmp, full);
    return { key, size: copy.byteLength, sha256: sha256Hex(copy) };
  }
  async get(key: string): Promise<Uint8Array> {
    const full = await this.#path(key, false);
    try {
      invariant(!(await lstat(full)).isSymbolicLink(), 'not_found', 'Object not found');
      return new Uint8Array(await readFile(full));
    } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new DomainError('not_found', 'Object not found'); throw error; }
  }
  async head(key: string): Promise<{ size: number } | null> {
    try { const st = await lstat(await this.#path(key, false)); return st.isFile() ? { size: st.size } : null; }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw error; }
  }
  async delete(key: string): Promise<void> {
    try { await unlink(await this.#path(key, false)); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
  async list(prefix: string): Promise<string[]> {
    const out: string[] = [];
    const walk = async (dir: string, rel: string): Promise<void> => {
      let entries;
      try { entries = await readdir(dir, { withFileTypes: true }); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return; throw error; }
      for (const e of entries) {
        const key = rel === '' ? e.name : `${rel}/${e.name}`;
        if (e.isDirectory()) await walk(join(dir, e.name), key);
        else if (e.isFile() && !e.name.includes('.tmp-') && key.startsWith(prefix)) out.push(key);
      }
    };
    await walk(this.#root, '');
    return out.sort();
  }
}

export type S3Options = Readonly<{ endpoint: string; region: string; bucket: string; accessKeyId: string; secretAccessKey: string; prefix?: string; sessionToken?: string }>;
/** S3-compatible store (AWS S3, MinIO, R2, …) using SigV4 and path-style addressing over fetch. */
export class S3ObjectStore implements ObjectStore {
  readonly #o: S3Options;
  constructor(options: S3Options) { this.#o = options; }
  #key(key: string): string { return `${this.#o.prefix ?? ''}${validObjectKey(key)}`; }
  async #request(method: string, key: string, query: Record<string, string>, body?: Uint8Array): Promise<Response> {
    const o = this.#o;
    const url = new URL(o.endpoint);
    const path = `${url.pathname.replace(/\/$/, '')}/${o.bucket}${key === '' ? '' : `/${key.split('/').map(encodeURIComponent).join('/')}`}`;
    const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
    const date = amzDate.slice(0, 8);
    const payloadHash = sha256Hex(body ?? new Uint8Array());
    const headers: Record<string, string> = { host: url.host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate, ...(o.sessionToken === undefined ? {} : { 'x-amz-security-token': o.sessionToken }) };
    const signed = Object.keys(headers).sort();
    const qs = Object.keys(query).sort().map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(query[k] as string)}`).join('&');
    const canonicalRequest = [method, path, qs, ...signed.map((h) => `${h}:${headers[h]}`), '', signed.join(';'), payloadHash].join('\n');
    const scope = `${date}/${o.region}/s3/aws4_request`;
    const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256Hex(canonicalRequest)].join('\n');
    const hmac = (k: Uint8Array | string, d: string): Buffer => createHmac('sha256', k).update(d).digest();
    const signature = hmac(hmac(hmac(hmac(hmac(`AWS4${o.secretAccessKey}`, date), o.region), 's3'), 'aws4_request'), toSign).toString('hex');
    const { host: _host, ...sendHeaders } = headers;
    return fetch(`${url.protocol}//${url.host}${path}${qs === '' ? '' : `?${qs}`}`, { method, headers: { ...sendHeaders, authorization: `AWS4-HMAC-SHA256 Credential=${o.accessKeyId}/${scope}, SignedHeaders=${signed.join(';')}, Signature=${signature}` }, ...(body === undefined ? {} : { body: body as BodyInit }) });
  }
  async put(key: string, bytes: Uint8Array): Promise<ObjectInfo> {
    const copy = Uint8Array.from(bytes);
    const r = await this.#request('PUT', this.#key(key), {}, copy);
    if (!r.ok) throw new DomainError('unavailable', `Object storage write failed (${r.status})`);
    return { key, size: copy.byteLength, sha256: sha256Hex(copy) };
  }
  async get(key: string): Promise<Uint8Array> {
    const r = await this.#request('GET', this.#key(key), {});
    if (r.status === 404) throw new DomainError('not_found', 'Object not found');
    if (!r.ok) throw new DomainError('unavailable', `Object storage read failed (${r.status})`);
    return new Uint8Array(await r.arrayBuffer());
  }
  async head(key: string): Promise<{ size: number } | null> {
    const r = await this.#request('HEAD', this.#key(key), {});
    if (r.status === 404) return null;
    if (!r.ok) throw new DomainError('unavailable', `Object storage head failed (${r.status})`);
    return { size: Number(r.headers.get('content-length') ?? 0) };
  }
  async delete(key: string): Promise<void> {
    const r = await this.#request('DELETE', this.#key(key), {});
    if (!r.ok && r.status !== 404) throw new DomainError('unavailable', `Object storage delete failed (${r.status})`);
  }
  async list(prefix: string): Promise<string[]> {
    const out: string[] = []; let token: string | undefined;
    const base = this.#o.prefix ?? '';
    do {
      const r = await this.#request('GET', '', { 'list-type': '2', prefix: `${base}${prefix}`, ...(token === undefined ? {} : { 'continuation-token': token }) });
      if (!r.ok) throw new DomainError('unavailable', `Object storage list failed (${r.status})`);
      const xml = await r.text();
      for (const m of xml.matchAll(/<Key>([^<]+)<\/Key>/g)) out.push((m[1] as string).replaceAll('&amp;', '&').slice(base.length));
      token = /<NextContinuationToken>([^<]+)<\/NextContinuationToken>/.exec(xml)?.[1];
    } while (token !== undefined);
    return out.sort();
  }
}
/** Builds a store from environment-style configuration: OBJECT_STORE=fs|s3 plus OBJECT_STORE_PATH or S3_* values. */
export function objectStoreFromEnv(env: Readonly<Record<string, string | undefined>>, fallbackPath: string): ObjectStore {
  if ((env.OBJECT_STORE ?? 'fs') === 's3') {
    for (const k of ['S3_ENDPOINT', 'S3_BUCKET', 'S3_ACCESS_KEY_ID', 'S3_SECRET_ACCESS_KEY']) invariant(typeof env[k] === 'string' && env[k] !== '', 'invalid_config', `${k} is required for OBJECT_STORE=s3`);
    return new S3ObjectStore({ endpoint: env.S3_ENDPOINT as string, region: env.S3_REGION ?? 'us-east-1', bucket: env.S3_BUCKET as string, accessKeyId: env.S3_ACCESS_KEY_ID as string, secretAccessKey: env.S3_SECRET_ACCESS_KEY as string, ...(env.S3_PREFIX === undefined ? {} : { prefix: env.S3_PREFIX }) });
  }
  return new FsObjectStore(env.OBJECT_STORE_PATH ?? fallbackPath);
}

// ───────────────────────────── Test support ─────────────────────────────
export interface PgModuleLike { Pool: new (config: { connectionString: string; max?: number }) => PgPoolLike & { end(): Promise<void> } }
/** Creates a disposable database on a real PostgreSQL server, runs fn, then drops it. For tests and acceptance runs. */
export async function withDisposableDatabase<T>(pg: PgModuleLike, adminUrl: string, fn: (url: string, sql: Sql) => Promise<T>): Promise<T> {
  const name = `kit_test_${randomUUID().replaceAll('-', '')}`;
  const admin = new pg.Pool({ connectionString: adminUrl, max: 1 });
  await admin.query(`create database ${name}`);
  const target = new URL(adminUrl); target.pathname = `/${name}`;
  const pool = new pg.Pool({ connectionString: target.toString(), max: 8 });
  try { return await fn(target.toString(), pgSql(pool)); }
  finally {
    try { await pool.end(); } catch { /* the primary failure, if any, is what matters */ }
    try {
      // Backends finish exiting shortly after pool.end(); retry a plain drop before forcing.
      for (let attempt = 0; ; attempt++) {
        try { await admin.query(`drop database if exists ${name}`); break; }
        catch (error) { if (attempt >= 40) { await admin.query(`drop database if exists ${name} with (force)`); break; } await new Promise((r) => setTimeout(r, 50)); void error; }
      }
    } finally { await admin.end(); }
  }
}
