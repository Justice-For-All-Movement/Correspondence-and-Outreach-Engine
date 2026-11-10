// Shared internals of the correspondence service: configuration, scoping, row views and mailbox/provider access.
import { DomainError, invariant } from '../contracts.ts';
import type { Json } from '../contracts.ts';
import { appendAudit, emitEvent, idempotent, requireCapability, uref } from '../service-kit.ts';
import type { AuthorizationPort, BudgetPort, EvidencePort, ObjectStore, Row, ServiceContext, Sql, UseDecisionPort } from '../service-kit.ts';
import { normalizeAddress } from '../validation.ts';
import { DEFAULT_RULES } from './mail.ts';
import type { MailRules, SenderProfile } from './mail.ts';
import { DEFAULT_PROVIDER_POLICY, createAdapter, forgetTokens, missingCredentials, openSecrets, sealSecrets } from './providers.ts';
import type { MailAdapter, MailboxConfig, MailboxProvider, MailboxSecrets, ProviderPolicy } from './providers.ts';
import { SCHEMA } from './schema.ts';

export const S = SCHEMA;
export const ENGINE = 'E03';

export type EngineConfig = Readonly<{
  /** 32-byte key (base64/hex) sealing provider credentials. Absent: credentials cannot be stored or used (`unavailable`). */
  secretKey?: string;
  rules?: Partial<MailRules>;
  provider?: Partial<ProviderPolicy>;
  /** Automated first contact requires a human-verified contact route. Default true. */
  requireVerifiedContactForAutomation?: boolean;
  /** Hard ceiling for follow-ups per thread regardless of grant. Default 3. */
  maxFollowUps?: number;
  /** Delay before the first provider lookup of an uncertain send, and the number of lookups. */
  reconcileDelayMs?: number; reconcileAttempts?: number;
  maxAttachmentBytes?: number; maxRecipients?: number;
  /** Permit human contact with contacts flagged sensitive when no UseDecisionPort is supplied. Default false (deny). */
  standaloneAllowSensitiveContact?: boolean;
  workerId?: string;
}>;
export type Ports = Readonly<{ authorization?: AuthorizationPort; budget?: BudgetPort; evidence?: EvidencePort; useDecision?: UseDecisionPort }>;
export type Core = Readonly<{
  sql: Sql; objects: ObjectStore | null; ports: Ports; secretKey: Buffer | null; rules: MailRules; policy: ProviderPolicy;
  cfg: Required<Pick<EngineConfig, 'requireVerifiedContactForAutomation' | 'maxFollowUps' | 'reconcileDelayMs' | 'reconcileAttempts' | 'maxAttachmentBytes' | 'maxRecipients' | 'standaloneAllowSensitiveContact' | 'workerId'>>;
}>;
export function resolveConfig(config: EngineConfig): Pick<Core, 'rules' | 'policy' | 'cfg'> {
  return {
    rules: { ...DEFAULT_RULES, ...config.rules }, policy: { ...DEFAULT_PROVIDER_POLICY, ...config.provider },
    cfg: { requireVerifiedContactForAutomation: config.requireVerifiedContactForAutomation ?? true, maxFollowUps: config.maxFollowUps ?? 3,
      reconcileDelayMs: config.reconcileDelayMs ?? 60_000, reconcileAttempts: config.reconcileAttempts ?? 5, maxAttachmentBytes: config.maxAttachmentBytes ?? 20 * 1024 * 1024,
      maxRecipients: config.maxRecipients ?? 10, standaloneAllowSensitiveContact: config.standaloneAllowSensitiveContact ?? false, workerId: config.workerId ?? `e03-${process.pid}` },
  };
}

// ───────────────────────────── Scoping ─────────────────────────────
/** Every query takes ($1 tenant, $2 project, $3 compartments) first. */
export const sc = (ctx: ServiceContext, ...rest: unknown[]): unknown[] => [ctx.tenantId, ctx.projectId, [...(ctx.compartments ?? [])], ...rest];
/** Scope predicate for compartmented tables: hidden compartments are indistinguishable from absence. */
export const W = (a: string): string => `${a}.tenant_id=$1 and ${a}.project_id=$2 and (${a}.compartment is null or ${a}.compartment = any($3::text[]))`;
/** Scope predicate for tables without compartments (mailboxes, grants, labels, suppressions). */
export const P = (a: string): string => `${a}.tenant_id=$1 and ${a}.project_id=$2 and $3::text[] is not null`;
/** Scope predicate for system work (ingestion, dispatch) that must see a row whatever the caller's compartments. */
export const T = (a: string): string => `${a}.tenant_id=$1 and ${a}.project_id=$2 and $3::text[] is not null`;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
/** Malformed ids are simply "not found": nothing about validity leaks. */
export function id(value: unknown): string { if (typeof value !== 'string' || !UUID.test(value)) throw new DomainError('not_found', 'Not found'); return value.toLowerCase(); }
export const notFound = (): never => { throw new DomainError('not_found', 'Not found'); };
export function requireHuman(ctx: ServiceContext, what: string): void { invariant(ctx.actor.kind === 'human', 'forbidden', `${what} requires a human actor`); }
export const ref = (kind: string, rowId: string, revision?: number): string => uref(ENGINE, kind, rowId, revision);
export function address(value: unknown): string { invariant(typeof value === 'string', 'invalid_address', 'Address required'); return normalizeAddress(value); }
export function addressList(value: unknown, max: number, label: string): string[] {
  invariant(Array.isArray(value) && value.length <= max, 'invalid_input', `${label} must be a list of at most ${max} addresses`);
  return [...new Set(value.map(address))];
}
export function optionalUref(value: unknown, label: string): string | null {
  if (value === undefined || value === null) return null;
  invariant(typeof value === 'string' && /^E\d\d:[a-z][a-z0-9_]*:[A-Za-z0-9._~-]+(?:@\d+)?$/.test(value), 'invalid_reference', `${label} must be a universal reference`);
  return value;
}
export function compartment(ctx: ServiceContext, value: unknown): string | null {
  if (value === undefined || value === null || value === '') return null;
  invariant(typeof value === 'string' && /^[A-Za-z0-9._:-]{1,100}$/.test(value), 'invalid_input', 'Invalid compartment');
  // A caller can only file objects in a compartment it can itself read.
  invariant(ctx.compartments.includes(value), 'forbidden', 'Compartment is not available to this actor');
  return value;
}
export function time(value: unknown, label: string): Date {
  invariant(typeof value === 'string' && Number.isFinite(Date.parse(value)), 'invalid_time', `${label} must be an ISO timestamp`);
  return new Date(value);
}
export function int(value: unknown, label: string, min: number, max: number): number {
  invariant(Number.isInteger(value) && (value as number) >= min && (value as number) <= max, 'invalid_input', `${label} must be an integer between ${min} and ${max}`);
  return value as number;
}

// ───────────────────────────── Views ─────────────────────────────
const HIDDEN = new Set(['search', 'secret_enc', 'raw_key', 'object_key', 'dedupe_key', 'body_html']);
export type View = { [key: string]: Json };
/** Row → API object: camelCase keys, ISO timestamps, internal and secret columns removed. */
export function view(row: Row | undefined): View {
  if (row === undefined) return notFound();
  const out: View = {};
  for (const [k, v] of Object.entries(row)) {
    if (HIDDEN.has(k)) continue;
    const key = k.replace(/_([a-z0-9])/g, (_m, c: string) => c.toUpperCase());
    out[key] = v instanceof Date ? v.toISOString() : typeof v === 'bigint' ? String(v) : (v ?? null) as Json;
  }
  return out;
}
export const views = (rows: readonly Row[]): View[] => rows.map(view);
export function page(query: { limit?: number } | undefined, fallback = 50, max = 200): number {
  const n = query?.limit ?? fallback;
  return Number.isFinite(n) ? Math.min(Math.max(Math.trunc(n), 1), max) : fallback;
}
export function encodeCursor(parts: readonly string[]): string { return Buffer.from(JSON.stringify(parts)).toString('base64url'); }
export function decodeCursor(cursor: string | undefined, length: number): string[] | null {
  if (cursor === undefined || cursor === '') return null;
  try {
    const v = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as unknown;
    invariant(Array.isArray(v) && v.length === length && v.every((x) => typeof x === 'string'), 'invalid_input', 'Invalid cursor');
    return v as string[];
  } catch { throw new DomainError('invalid_input', 'Invalid cursor'); }
}

// ───────────────────────────── Commands ─────────────────────────────
/** One transaction per command: capability check, idempotency, state change, audit and events. */
export async function command<T extends Json>(core: Core, ctx: ServiceContext, capability: string, key: string | undefined, input: unknown, fn: (tx: Sql) => Promise<T>): Promise<T> {
  requireCapability(ctx, capability);
  return core.sql.tx((tx) => idempotent(tx, S, ctx, key, input, () => fn(tx)));
}
export async function record(tx: Sql, ctx: ServiceContext, action: string, subject: string, detail: Json, event?: { type: string; payload?: Json }): Promise<void> {
  await appendAudit(tx, S, ctx, action, subject, detail);
  if (event !== undefined) await emitEvent(tx, S, ctx, event.type, subject, event.payload ?? detail);
}
export async function contactEvent(tx: Sql, ctx: ServiceContext, contactId: string | null, kind: string, reference: string | null, detail: Json = {}): Promise<void> {
  if (contactId === null) return;
  await tx.query(`insert into ${S}.contact_events (tenant_id, project_id, contact_id, kind, ref, detail, actor_id, at) values ($1,$2,$3,$4,$5,$6::jsonb,$7,$8)`,
    [ctx.tenantId, ctx.projectId, contactId, kind, reference, JSON.stringify(detail), ctx.actor.id, ctx.now]);
}
export async function deliveryEvent(tx: Sql, ctx: ServiceContext, dispatchId: string, kind: string, detail: Json = {}): Promise<void> {
  await tx.query(`insert into ${S}.delivery_events (tenant_id, project_id, dispatch_id, kind, detail, at) values ($1,$2,$3,$4,$5::jsonb,$6)`,
    [ctx.tenantId, ctx.projectId, dispatchId, kind, JSON.stringify(detail), ctx.now]);
}
export function reasons(existing: unknown, reason: string, cause: string, kind: string, at: string): string {
  const list = Array.isArray(existing) ? existing as Json[] : [];
  return JSON.stringify([...list, { reason: reason.slice(0, 500), cause, kind, at }]);
}

// ───────────────────────────── Mailboxes and providers ─────────────────────────────
export type MailboxRow = Row & {
  id: string; address: string; display_name: string; provider: MailboxProvider; config: MailboxConfig; secret_enc: string | null; auth_epoch: number;
  sender_profile: SenderProfile; profile_verified_at: Date | null; control_mode: 'automation' | 'human'; control_epoch: number; state: 'active' | 'disabled'; sync_state: Json;
};
export const MAILBOX_COLS = `id, tenant_id, project_id, address, display_name, provider, config, secret_fields, secret_set_at, auth_epoch, sender_profile, profile_verified_at, profile_verified_by,
  control_mode, control_epoch, control_reason, control_by, control_at, state, last_sync_at, last_sync_status, last_sync_error, created_by, created_at, updated_at`;
/** Loads a mailbox including its sealed credentials. Internal use only: never pass the row to `view`. */
export async function loadMailbox(sql: Sql, ctx: ServiceContext, mailboxId: string, lock = ''): Promise<MailboxRow> {
  const rows = await sql.query<MailboxRow>(`select * from ${S}.mailboxes m where ${P('m')} and m.id=$4 ${lock}`, sc(ctx, id(mailboxId)));
  return rows[0] ?? notFound();
}
export const secretAad = (ctx: { tenantId: string; projectId: string }, mailboxId: string): string => `${ctx.tenantId}/${ctx.projectId}/${mailboxId}`;
export function sealFor(core: Core, ctx: ServiceContext, mailboxId: string, secrets: MailboxSecrets): string {
  if (core.secretKey === null) throw new DomainError('unavailable', 'Credential storage is unavailable: CORRESPONDENCE_SECRET_KEY is not configured');
  return sealSecrets(core.secretKey, secretAad(ctx, mailboxId), secrets);
}
export function secretsOf(core: Core, ctx: ServiceContext, mailbox: MailboxRow): MailboxSecrets | null {
  if (mailbox.secret_enc === null) return null;
  if (core.secretKey === null) throw new DomainError('unavailable', 'Provider credentials are unavailable: CORRESPONDENCE_SECRET_KEY is not configured');
  return openSecrets(core.secretKey, secretAad(ctx, mailbox.id), mailbox.secret_enc);
}
/** Builds a provider adapter, or throws `unavailable` naming exactly what is missing. Never fabricates a provider. */
export function adapterFor(core: Core, ctx: ServiceContext, mailbox: MailboxRow, use: 'send' | 'read' | 'any'): MailAdapter {
  const secrets = secretsOf(core, ctx, mailbox);
  if (use !== 'any') {
    const missing = missingCredentials(mailbox.provider, mailbox.config, secrets, use);
    if (missing.length > 0) throw new DomainError('unavailable', `Mailbox provider is unavailable for ${use}: missing ${missing.join(', ')}`);
  }
  return createAdapter({ provider: mailbox.provider, address: mailbox.address, config: mailbox.config, secrets, policy: core.policy,
    scope: { tenantId: ctx.tenantId, projectId: ctx.projectId, mailboxId: mailbox.id, authEpoch: mailbox.auth_epoch },
    onRefreshTokenRotated: async (token) => {
      const sealed = sealFor(core, ctx, mailbox.id, { ...secrets, oauthRefreshToken: token });
      await core.sql.query(`update ${S}.mailboxes m set secret_enc=$5, secret_set_at=now() where ${P('m')} and m.id=$4 and m.auth_epoch=$6`, sc(ctx, mailbox.id, sealed, mailbox.auth_epoch));
    } });
}
export { forgetTokens };
export function objects(core: Core): ObjectStore {
  if (core.objects === null) throw new DomainError('unavailable', 'Object storage is not configured; original messages and attachments cannot be stored');
  return core.objects;
}
export const objectKey = (ctx: { tenantId: string; projectId: string }, kind: 'raw' | 'attachments', name: string): string => `${ctx.tenantId}/${ctx.projectId}/e03/${kind}/${name}`;
/** Active suppression covering any of the addresses (exact address or its domain). */
export async function suppressed(tx: Sql, ctx: ServiceContext, addrs: readonly string[]): Promise<string | null> {
  if (addrs.length === 0) return null;
  const domains = addrs.map((a) => a.slice(a.indexOf('@') + 1));
  const rows = await tx.query<{ value: string }>(`select s.value from ${S}.suppressions s where ${P('s')} and s.lifted_at is null and ((s.scope='address' and s.value = any($4::text[])) or (s.scope='domain' and s.value = any($5::text[]))) limit 1`, sc(ctx, addrs, domains));
  return rows[0]?.value ?? null;
}
