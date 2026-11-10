// Correspondence and Outreach engine (E03) service layer. See docs/ENGINE_API.md.
import { DomainError } from '../contracts.ts';
import type { Json } from '../contracts.ts';
import { SERVICE_KIT_VERSION, errorStatus, listAudit, parseUref, readEvents, requireCapability, runMigrations, standardRoutes } from '../service-kit.ts';
import type { AuditRecord, EngineEvent, EngineManifestV1, HttpRequest, HttpResponse, Inspection, ObjectStore, Route, SearchHit, ServiceContext, Sql, StandardEngine } from '../service-kit.ts';
import { P, S, W, id, ref, resolveConfig, sc } from './core.ts';
import type { Core, EngineConfig, Ports, View } from './core.ts';
import { delivery } from './delivery.ts';
import { parseSecretKey } from './providers.ts';
import { SCHEMA, migrations } from './schema.ts';
import { FOLDERS, workspace } from './workspace.ts';
import type { Folder } from './workspace.ts';

export { SCHEMA, migrations };
export type { EngineConfig, Ports, View } from './core.ts';
export type { Folder, Page } from './workspace.ts';
export type { MailboxConfig, MailboxProvider, MailboxSecrets, ProviderPolicy } from './providers.ts';
export type { SenderProfile, StructuredInquiry, MailRules, DisclosureTemplate } from './mail.ts';
export { DEFAULT_RULES, renderDisclosure, renderStructured, findIdentityClaims, parseInbound, assertionCandidates } from './mail.ts';

export const CAPABILITIES = ['correspondence:read', 'correspondence:write', 'correspondence:send', 'correspondence:contact', 'correspondence:grant', 'correspondence:admin',
  'correspondence:ingest', 'correspondence:sync', 'correspondence:upstream', 'correspondence:events'] as const;
export const EVENTS = ['mailbox.created', 'message.drafted', 'message.queued', 'message.sent', 'message.send.uncertain', 'message.send.reconciled', 'message.send.failed', 'message.send.cancelled',
  'message.delivered', 'message.bounced', 'message.received', 'correspondence.reply_received', 'answer.proposed', 'message.preserved_as_evidence', 'contact.refused', 'suppression.added', 'suppression.lifted',
  'outreach.plan.created', 'outreach.candidate.verified', 'grant.created', 'grant.revoked', 'conversation.taken_over', 'conversation.resumed', 'conversation.assigned', 'conversation.blocked', 'conversation.stale',
  'conversation.stale_reviewed', 'contact.blocked', 'contact.stale', 'plan.blocked', 'plan.stale'] as const;
export const manifest: EngineManifestV1 = {
  id: 'E03', name: 'correspondence', version: '1.0.0', kit: SERVICE_KIT_VERSION, capabilities: CAPABILITIES, emits: EVENTS,
  consumes: ['investigation.outreach_required', 'permission_withdrawn', 'permission_changed', 'source_removed', 'source_corrected', 'source_superseded', 'claim_changed', 'content_changed'],
};
export function migrate(sql: Sql): Promise<string[]> { return runMigrations(sql, SCHEMA, migrations); }

export type EngineDeps = Readonly<{ sql: Sql; objects?: ObjectStore; ports?: Ports; config?: EngineConfig }>;
export type CorrespondenceEngine = StandardEngine & Omit<ReturnType<typeof workspace>, 'internal'> & ReturnType<typeof delivery>;

export function createEngine(deps: EngineDeps): CorrespondenceEngine {
  const config = deps.config ?? {};
  const core: Core = { sql: deps.sql, objects: deps.objects ?? null, ports: deps.ports ?? {}, secretKey: parseSecretKey(config.secretKey), ...resolveConfig(config) };
  const { sql } = core;
  const full = workspace(core);
  const { internal: _internal, ...ws } = full;
  const dl = delivery(core, full);

  async function inspect(ctx: ServiceContext, reference: string): Promise<Inspection | null> {
    requireCapability(ctx, 'correspondence:read');
    let parsed: ReturnType<typeof parseUref>;
    try { parsed = parseUref(reference); id(parsed.id); } catch { return null; }
    if (parsed.engine !== 'E03') return null;
    const tables: Record<string, { table: string; scope: (a: string) => string; title: string }> = {
      conversation: { table: 'threads', scope: W, title: 'subject' }, message: { table: 'messages', scope: W, title: 'subject' }, contact: { table: 'contacts', scope: W, title: 'address' },
      plan: { table: 'plans', scope: W, title: 'question' }, dispatch: { table: 'dispatches', scope: W, title: 'message_id_header' }, grant: { table: 'grants', scope: P, title: 'purpose' }, mailbox: { table: 'mailboxes', scope: P, title: 'address' },
    };
    const t = tables[parsed.kind];
    if (t === undefined) return null;
    const row = (await sql.query(`select x.* from ${S}.${t.table} x where ${t.scope('x')} and x.id=$4`, sc(ctx, parsed.id)))[0];
    if (row === undefined) return null;
    const subject = ref(parsed.kind, parsed.id);
    const audit = await listAudit(sql, S, ctx, { subject, limit: 200 });
    const reasons = [...(Array.isArray(row.stale_reasons) ? row.stale_reasons : []), ...(Array.isArray(row.block_reasons) ? row.block_reasons : [])].map((r) => String((r as { reason?: unknown }).reason ?? (r as { note?: unknown }).note ?? ''));
    const sources = [...new Set([...(Array.isArray(row.sources) ? row.sources as string[] : []), ...[row.question_ref, row.route_source].filter((s): s is string => typeof s === 'string'),
      ...(parsed.kind === 'message' ? [ref('conversation', row.thread_id as string)] : []), ...(parsed.kind === 'dispatch' ? [ref('message', row.message_id as string)] : [])])];
    let dependents: string[] = []; let permissions: Json[] = []; let versions: Inspection['versions'] = [];
    const data: View = {};
    for (const [k, v] of Object.entries(row)) if (!['search', 'secret_enc', 'raw_key', 'object_key', 'dedupe_key', 'body_html', 'body_text', 'config', 'sync_state'].includes(k)) data[k] = v instanceof Date ? v.toISOString() : (v ?? null) as Json;
    if (parsed.kind === 'conversation') {
      dependents = [...(await sql.query<{ id: string }>(`select m.id from ${S}.messages m where ${W('m')} and m.thread_id=$4 order by m.created_at limit 500`, sc(ctx, parsed.id))).map((m) => ref('message', m.id)),
        ...(await sql.query<{ id: string }>(`select d.id from ${S}.dispatches d where ${W('d')} and d.thread_id=$4 limit 500`, sc(ctx, parsed.id))).map((d) => ref('dispatch', d.id))];
      permissions = (await sql.query(`select distinct g.id, g.grantee_id, g.state, g.expires_at from ${S}.grants g join ${S}.dispatches d on d.grant_id=g.id where ${P('g')} and d.thread_id=$4`, sc(ctx, parsed.id))).map((g) => ({ grant: ref('grant', g.id as string), grantee: g.grantee_id as string, state: g.state as string, expiresAt: (g.expires_at as Date).toISOString() }));
    } else if (parsed.kind === 'message') {
      dependents = [...(await sql.query<{ id: string }>(`select a.id from ${S}.assertions a where ${W('a')} and a.message_id=$4`, sc(ctx, parsed.id))).map((a) => ref('assertion', a.id)),
        ...(await sql.query<{ id: string }>(`select d.id from ${S}.dispatches d where ${W('d')} and d.message_id=$4`, sc(ctx, parsed.id))).map((d) => ref('dispatch', d.id))];
      versions = (await sql.query(`select v.revision, v.at, v.actor_id from ${S}.message_versions v where ${P('v')} and v.message_id=$4 order by v.revision`, sc(ctx, parsed.id))).map((v) => ({ revision: v.revision as number, at: (v.at as Date).toISOString(), actorId: v.actor_id as string }));
    } else if (parsed.kind === 'contact' || parsed.kind === 'plan') {
      dependents = (await sql.query<{ id: string }>(`select t.id from ${S}.threads t where ${W('t')} and t.${parsed.kind === 'contact' ? 'contact_id' : 'plan_id'}=$4 limit 500`, sc(ctx, parsed.id))).map((t) => ref('conversation', t.id));
    }
    const state = String(row.state ?? (row.trashed === true ? 'trashed' : row.archived === true ? 'archived' : row.control_mode === 'human' ? 'human_control' : 'open'));
    return { ref: subject, kind: parsed.kind, title: String(row[t.title] ?? '').slice(0, 200), state, stale: row.stale === true, blocked: row.blocked === true || row.refused === true, staleReasons: reasons.filter((r) => r !== ''),
      versions, sources, dependents, permissions, decisions: row.reconciliation == null ? [] : [row.reconciliation as Json],
      history: audit.map((a) => ({ at: a.at, actorId: a.actorId, action: a.action, detail: a.detail })), data };
  }
  async function search(ctx: ServiceContext, query: { q: string; limit?: number }): Promise<SearchHit[]> {
    requireCapability(ctx, 'correspondence:read');
    if (typeof query.q !== 'string' || query.q.trim() === '') return [];
    const limit = Math.min(Math.max(Math.trunc(query.limit ?? 20) || 20, 1), 100);
    const messages = await ws.searchMessages(ctx, { q: query.q, limit });
    const contacts = await ws.listContacts(ctx, { q: query.q, limit: Math.min(limit, 20) });
    return [...messages.items.map((m) => ({ ref: ref('message', m.id as string), kind: 'message', title: String(m.subject), snippet: String(m.headline ?? '').slice(0, 300), state: String(m.state) })),
      ...contacts.items.map((c) => ({ ref: ref('contact', c.id as string), kind: 'contact', title: String(c.displayName || c.address), snippet: String(c.whyMayKnow).slice(0, 300), state: String(c.state) }))].slice(0, limit);
  }
  async function audit(ctx: ServiceContext, options: { after?: string; limit?: number; subject?: string } = {}): Promise<AuditRecord[]> {
    requireCapability(ctx, 'correspondence:admin');
    return listAudit(sql, S, ctx, options);
  }
  async function events(ctx: ServiceContext, options: { after?: string; limit?: number } = {}): Promise<EngineEvent[]> {
    requireCapability(ctx, 'correspondence:events');
    return (await readEvents(sql, S, { ...options, tenantId: ctx.tenantId })).map((e) => ({ ...e, engine: 'E03' }));
  }
  async function health(): Promise<{ ok: boolean; detail: Json }> {
    try {
      await sql.query('select 1');
      return { ok: true, detail: { database: 'ok', objectStore: core.objects === null ? 'not configured' : 'configured', credentialStorage: core.secretKey === null ? 'unavailable: CORRESPONDENCE_SECRET_KEY is not set' : 'configured',
        ports: { authorization: core.ports.authorization !== undefined, budget: core.ports.budget !== undefined, evidence: core.ports.evidence !== undefined, useDecision: core.ports.useDecision !== undefined } } };
    } catch { return { ok: false, detail: { database: 'unreachable' } }; }
  }
  return { manifest, inspect, search, audit, events, health, ...ws, ...dl } as CorrespondenceEngine;
}

// ───────────────────────────── HTTP ─────────────────────────────
const EXTRA_STATUS: Readonly<Record<string, number>> = { suppressed: 409, provider_auth_failed: 502, provider_unavailable: 503, unavailable: 503, policy_denied: 403 };
/** The kit masks 5xx and unmapped domain errors; this keeps their explicit code and status (for example 503 `unavailable`). */
function explicit(handler: Route['handler']): Route['handler'] {
  return async (request) => {
    try { return await handler(request); }
    catch (error) {
      if (!(error instanceof DomainError)) throw error;
      const status = EXTRA_STATUS[error.code] ?? errorStatus(error.code);
      if (EXTRA_STATUS[error.code] === undefined && status < 500) throw error;
      if (status === 500) throw error;
      return { status, json: { error: { code: error.code, message: error.message } } };
    }
  };
}
// Request bodies are untrusted JSON; every service method validates its own input.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const body = (r: HttpRequest): any => (r.body !== null && typeof r.body === 'object' && !Array.isArray(r.body) ? r.body : {});
const q = (r: HttpRequest, name: string): string | undefined => r.query.get(name) ?? undefined;
const num = (r: HttpRequest, name: string): number | undefined => { const v = r.query.get(name); return v === null || v === '' ? undefined : Number(v); };
const bool = (r: HttpRequest, name: string): boolean | undefined => { const v = r.query.get(name); return v === null ? undefined : v === 'true' || v === '1'; };
const defined = <T extends Record<string, unknown>>(o: T): { [K in keyof T]: Exclude<T[K], undefined> } => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as { [K in keyof T]: Exclude<T[K], undefined> };
const key = (r: HttpRequest): { idempotencyKey?: string } => { const h = r.headers['idempotency-key']; const b = (body(r) as { idempotencyKey?: unknown }).idempotencyKey; return typeof h === 'string' ? { idempotencyKey: h } : typeof b === 'string' ? { idempotencyKey: b } : {}; };
const download = (bytes: Uint8Array, filename: string, type: string): HttpResponse => ({ bytes, headers: { 'content-type': type, 'content-disposition': `attachment; filename="${filename.replace(/[^A-Za-z0-9._-]/g, '_')}"`, 'content-security-policy': "default-src 'none'; sandbox" } });

export function routes(engine: CorrespondenceEngine): Route[] {
  const e = engine;
  const r = (method: Route['method'], path: string, handler: (request: HttpRequest) => Promise<unknown>): Route => ({ method, path, handler: explicit(handler as Route['handler']) });
  const target = (req: HttpRequest, kind: 'threadId' | 'mailboxId'): { threadId?: string; mailboxId?: string; reason?: string } => ({ [kind]: req.params.id as string, ...defined({ reason: (body(req) as { reason?: string }).reason }) });
  return [
    ...standardRoutes(e).map((route) => ({ ...route, handler: explicit(route.handler) })),
    // Mailboxes
    r('GET', '/v1/mailboxes', (req) => e.listMailboxes(req.ctx)),
    r('POST', '/v1/mailboxes', (req) => e.createMailbox(req.ctx, { ...body(req), ...key(req) })),
    r('GET', '/v1/mailboxes/:id', (req) => e.getMailbox(req.ctx, req.params.id as string)),
    r('PATCH', '/v1/mailboxes/:id', (req) => e.updateMailbox(req.ctx, req.params.id as string, { ...body(req), ...key(req) })),
    r('PUT', '/v1/mailboxes/:id/credentials', (req) => e.setMailboxCredentials(req.ctx, req.params.id as string, body(req))),
    r('PUT', '/v1/mailboxes/:id/sender-profile', (req) => e.setSenderProfile(req.ctx, req.params.id as string, body(req))),
    r('POST', '/v1/mailboxes/:id/sender-profile/verify', (req) => e.verifySenderProfile(req.ctx, req.params.id as string)),
    r('POST', '/v1/mailboxes/:id/test', (req) => e.testMailboxConnection(req.ctx, req.params.id as string)),
    r('POST', '/v1/mailboxes/:id/sync', (req) => (bool(req, 'wait') === true ? e.syncMailboxNow(req.ctx, req.params.id as string, defined({ limit: num(req, 'limit') })) : e.syncMailbox(req.ctx, req.params.id as string))),
    r('POST', '/v1/mailboxes/:id/ingest', async (req) => { const out = await e.ingestRawMessage(req.ctx, req.params.id as string, req.raw, defined({ providerId: q(req, 'providerId') })); return { status: out.duplicate ? 200 : 201, json: out }; }),
    r('POST', '/v1/mailboxes/:id/takeover', (req) => e.takeover(req.ctx, target(req, 'mailboxId'))),
    r('POST', '/v1/mailboxes/:id/resume', (req) => e.resume(req.ctx, target(req, 'mailboxId'))),
    // Folder views, threads, search
    r('GET', '/v1/inbox', (req) => e.listThreads(req.ctx, defined({ folder: 'inbox' as Folder, mailboxId: q(req, 'mailboxId'), unread: bool(req, 'unread'), q: q(req, 'q'), limit: num(req, 'limit'), cursor: q(req, 'cursor') }))),
    r('GET', '/v1/folders', async () => ({ folders: FOLDERS as unknown as Json })),
    r('GET', '/v1/counts', (req) => e.counts(req.ctx, defined({ mailboxId: q(req, 'mailboxId') }))),
    r('GET', '/v1/conversations', (req) => e.listThreads(req.ctx, defined({ folder: q(req, 'folder') as Folder | undefined, mailboxId: q(req, 'mailboxId'), labelId: q(req, 'labelId'), assignee: q(req, 'assignee'), unread: bool(req, 'unread'),
      questionRef: q(req, 'questionRef'), contactId: q(req, 'contactId'), q: q(req, 'q'), limit: num(req, 'limit'), cursor: q(req, 'cursor') }))),
    r('POST', '/v1/conversations/modify', (req) => e.modifyThreads(req.ctx, { ...body(req), ...key(req) })),
    r('GET', '/v1/conversations/:id', (req) => e.getThread(req.ctx, req.params.id as string, defined({ markRead: bool(req, 'markRead') }))),
    r('POST', '/v1/conversations/:id/takeover', (req) => e.takeover(req.ctx, target(req, 'threadId'))),
    r('POST', '/v1/conversations/:id/resume', (req) => e.resume(req.ctx, target(req, 'threadId'))),
    r('POST', '/v1/conversations/:id/review-stale', (req) => e.reviewStale(req.ctx, req.params.id as string, body(req))),
    r('POST', '/v1/conversations/:id/follow-ups', (req) => e.scheduleFollowUp(req.ctx, req.params.id as string, { ...body(req), ...key(req) })),
    r('GET', '/v1/messages/search', (req) => e.searchMessages(req.ctx, defined({ q: q(req, 'q') ?? '', mailboxId: q(req, 'mailboxId'), limit: num(req, 'limit'), cursor: q(req, 'cursor') }))),
    // Messages, drafts, attachments
    r('POST', '/v1/messages', async (req) => ({ status: 201, json: await e.createDraft(req.ctx, { ...body(req), ...key(req) }) })),
    r('GET', '/v1/messages/:id', (req) => e.getMessage(req.ctx, req.params.id as string)),
    r('PATCH', '/v1/messages/:id', (req) => e.updateDraft(req.ctx, req.params.id as string, { ...body(req), ...key(req) })),
    r('DELETE', '/v1/messages/:id', (req) => e.discardDraft(req.ctx, req.params.id as string)),
    r('POST', '/v1/messages/:id/send', async (req) => ({ status: 202, json: await e.sendMessage(req.ctx, req.params.id as string, { ...body(req), ...key(req) }) })),
    r('GET', '/v1/messages/:id/raw', async (req) => { const raw = await e.getRawMessage(req.ctx, req.params.id as string); return download(raw.bytes, raw.filename, 'message/rfc822'); }),
    r('POST', '/v1/messages/:id/evidence', (req) => e.handToEvidence(req.ctx, req.params.id as string)),
    r('GET', '/v1/messages/:id/assertions', (req) => e.listAssertions(req.ctx, { messageId: req.params.id as string })),
    r('POST', '/v1/messages/:id/assertions', (req) => e.proposeAssertions(req.ctx, req.params.id as string, { ...body(req), ...key(req) })),
    r('POST', '/v1/messages/:id/attachments', async (req) => ({ status: 201, json: await e.addAttachment(req.ctx, req.params.id as string, { filename: q(req, 'filename') ?? '', mediaType: String(req.headers['content-type'] ?? 'application/octet-stream').split(';')[0] as string, bytes: req.raw }) })),
    r('GET', '/v1/attachments/:id', async (req) => { const a = await e.getAttachment(req.ctx, req.params.id as string); return download(a.bytes, String(a.meta.filename), 'application/octet-stream'); }),
    r('DELETE', '/v1/attachments/:id', (req) => e.removeAttachment(req.ctx, req.params.id as string)),
    r('PATCH', '/v1/assertions/:id', (req) => e.linkAssertion(req.ctx, req.params.id as string, body(req))),
    // Dispatch queue
    r('GET', '/v1/dispatches', (req) => e.listDispatches(req.ctx, defined({ states: q(req, 'state')?.split(','), mailboxId: q(req, 'mailboxId'), threadId: q(req, 'conversationId'), limit: num(req, 'limit') }))),
    r('GET', '/v1/dispatches/:id', (req) => e.getDispatch(req.ctx, req.params.id as string)),
    r('POST', '/v1/dispatches/:id/cancel', (req) => e.cancelDispatch(req.ctx, req.params.id as string, body(req))),
    r('POST', '/v1/dispatches/:id/reconcile', (req) => e.reconcileDispatch(req.ctx, req.params.id as string)),
    r('POST', '/v1/dispatches/:id/resolve', (req) => e.resolveDispatch(req.ctx, req.params.id as string, body(req))),
    // Labels
    r('GET', '/v1/labels', (req) => e.listLabels(req.ctx)),
    r('POST', '/v1/labels', async (req) => ({ status: 201, json: await e.createLabel(req.ctx, { ...body(req), ...key(req) }) })),
    r('PATCH', '/v1/labels/:id', (req) => e.updateLabel(req.ctx, req.params.id as string, body(req))),
    r('DELETE', '/v1/labels/:id', (req) => e.deleteLabel(req.ctx, req.params.id as string)),
    // Contacts and suppression
    r('GET', '/v1/contacts', (req) => e.listContacts(req.ctx, defined({ q: q(req, 'q'), state: q(req, 'state'), limit: num(req, 'limit'), cursor: q(req, 'cursor') }))),
    r('POST', '/v1/contacts', (req) => e.upsertContact(req.ctx, { ...body(req), ...key(req) })),
    r('GET', '/v1/contacts/:id', (req) => e.getContact(req.ctx, req.params.id as string)),
    r('POST', '/v1/contacts/:id/verify', (req) => e.verifyContact(req.ctx, req.params.id as string, body(req))),
    r('GET', '/v1/suppressions', (req) => e.listSuppressions(req.ctx, defined({ includeLifted: bool(req, 'includeLifted'), limit: num(req, 'limit') }))),
    r('POST', '/v1/suppressions', (req) => e.addSuppression(req.ctx, { ...body(req), ...key(req) })),
    r('POST', '/v1/suppressions/:id/lift', (req) => e.liftSuppression(req.ctx, req.params.id as string, body(req))),
    // Outreach plans and questions
    r('GET', '/v1/outreach/plans', (req) => e.listPlans(req.ctx, defined({ questionRef: q(req, 'questionRef'), limit: num(req, 'limit') }))),
    r('POST', '/v1/outreach/plans', async (req) => ({ status: 201, json: (body(req) as { inquiry?: unknown }).inquiry === undefined ? await e.createOutreachPlan(req.ctx, { ...body(req), ...key(req) }) : await e.planOutreach(req.ctx, { ...body(req), ...key(req) }) })),
    r('GET', '/v1/outreach/plans/:id', (req) => e.getPlan(req.ctx, req.params.id as string)),
    r('POST', '/v1/outreach/plans/:id/inquiries', async (req) => ({ status: 201, json: await e.draftInquiry(req.ctx, { ...body(req), planId: req.params.id as string, ...key(req) }) })),
    r('GET', '/v1/outreach/questions', (req) => e.questionStatus(req.ctx, q(req, 'ref') ?? '')),
    r('GET', '/v1/assertions', (req) => e.listAssertions(req.ctx, defined({ threadId: q(req, 'conversationId'), questionRef: q(req, 'questionRef') }))),
    // Grants
    r('GET', '/v1/grants', (req) => e.listGrants(req.ctx, defined({ granteeId: q(req, 'granteeId'), mailboxId: q(req, 'mailboxId'), state: q(req, 'state') }))),
    r('POST', '/v1/grants', async (req) => ({ status: 201, json: await e.createGrant(req.ctx, { ...body(req), ...key(req) }) })),
    r('GET', '/v1/grants/:id', (req) => e.getGrant(req.ctx, req.params.id as string)),
    r('POST', '/v1/grants/:id/revoke', (req) => e.revokeGrant(req.ctx, req.params.id as string, body(req))),
  ];
}

// ───────────────────────────── Port for the investigation engine (E08) ─────────────────────────────
/**
 * Adapter matching E08's `CorrespondencePort`. `mailboxId` is the mailbox inquiries are drafted in. Nothing is sent:
 * drafts wait for a human or for an agent holding a sending grant.
 */
export function correspondencePort(engine: CorrespondenceEngine, options: { mailboxId: string }) {
  const refId = (value: string, kind: string): string => { const p = parseUref(value); if (p.engine !== 'E03' || p.kind !== kind) throw new DomainError('invalid_reference', `Expected an E03 ${kind} reference`); return p.id; };
  return {
    /** `subject` is the question uref (E08:question:<id>); `contactLeadRef` selects known contacts found through that lead. */
    async createContactPlan(ctx: ServiceContext, input: { subject: string; question: string; contactLeadRef?: string; purpose: string; idempotencyKey: string }): Promise<{ planRef: string; state: string }> {
      const known = input.contactLeadRef === undefined ? [] : (await engine.listContacts(ctx, { limit: 200 })).items.filter((c) => c.routeSource === input.contactLeadRef || (Array.isArray(c.sources) && c.sources.includes(input.contactLeadRef as string)));
      const plan = await engine.createOutreachPlan(ctx, { questionRef: input.subject, question: input.question, context: input.purpose, candidates: known.map((c) => ({ contactId: c.id as string })), idempotencyKey: input.idempotencyKey });
      return { planRef: plan.ref as string, state: (plan.candidates as Json[]).length === 0 ? 'needs_contact_candidates' : 'planned' };
    },
    async draftInquiry(ctx: ServiceContext, input: { subject: string; questions: readonly string[]; contactPlanRef?: string; contactLeadRef?: string; idempotencyKey: string }): Promise<{ draftRef: string; threadRef?: string; state: string }> {
      const plans = input.contactPlanRef !== undefined ? [await engine.getPlan(ctx, refId(input.contactPlanRef, 'plan'))] : await engine.listPlans(ctx, { questionRef: input.subject, limit: 1 });
      const plan = plans[0];
      if (plan === undefined) throw new DomainError('invalid_state', 'No contact plan exists for this question');
      const candidate = (plan.candidates as View[]).find((c) => c.threadId === null && c.contactBlocked !== true && (input.contactLeadRef === undefined || c.routeSource === input.contactLeadRef));
      if (candidate === undefined) throw new DomainError('invalid_state', 'The contact plan has no candidate without an inquiry');
      const draft = await engine.draftInquiry(ctx, { planId: plan.id as string, contactId: candidate.contactId as string, mailboxId: options.mailboxId, idempotencyKey: input.idempotencyKey,
        structured: { subject: `Question about: ${String(plan.question).replace(/\s+/g, ' ').slice(0, 100)}`, purpose: String(plan.context || 'We are trying to establish a fact and believe you may know.').replace(/\s+/g, ' ').slice(0, 400), questions: [...input.questions] } });
      return { draftRef: draft.ref as string, threadRef: ref('conversation', draft.threadId as string), state: 'drafted_not_sent' };
    },
    async getThreadState(ctx: ServiceContext, threadRef: string): Promise<{ threadRef: string; state: string; replies: { ref: string; receivedAt: string; evidenceRef?: string }[] }> {
      const thread = await engine.getThread(ctx, refId(threadRef, 'conversation'));
      const messages = thread.messages as View[];
      const replies = messages.filter((m) => m.direction === 'inbound').map((m) => ({ ref: m.ref as string, receivedAt: m.receivedAt as string }));
      const state = thread.refused === true ? 'refused' : messages.some((m) => m.direction === 'inbound' && m.classification === 'reply') ? 'answered_unverified' : (thread.dispatches as View[]).some((d) => d.state === 'uncertain') ? 'send_uncertain'
        : (thread.dispatches as View[]).some((d) => d.state === 'bounced') ? 'bounced' : (thread.dispatches as View[]).some((d) => d.inTransit === true || d.state === 'delivered') ? 'awaiting_response' : messages.some((m) => m.state === 'queued') ? 'queued' : 'drafted_not_sent';
      return { threadRef, state, replies };
    },
  };
}
