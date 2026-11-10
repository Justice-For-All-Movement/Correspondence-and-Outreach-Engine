// Outbound dispatch queue (queued → dispatching → accepted/in transit → delivered | bounced | uncertain → reconciled),
// inbound ingestion (raw RFC822, provider sync), bounded grants, reconciliation and upstream blocking.
import { randomUUID } from 'node:crypto';
import { DomainError, invariant } from '../contracts.ts';
import type { Json } from '../contracts.ts';
import { enqueueJob, requireCapability, runJobsOnce, urefMatches } from '../service-kit.ts';
import type { Job, Row, ServiceContext, Sql, UpstreamChange } from '../service-kit.ts';
import { assertionCandidates, findIdentityClaims, freeText, parseInbound, renderDisclosure, withDisclosure } from './mail.ts';
import type { ParsedInbound } from './mail.ts';
import { composeMime, sanitizeResponse } from './providers.ts';
import type { LookupOutcome, SendOutcome } from './providers.ts';
import { P, S, T, W, adapterFor, contactEvent, command, deliveryEvent, id, loadMailbox, notFound, objectKey, objects, page, reasons, record, ref, requireHuman, sc, suppressed, time, view, views } from './core.ts';
import type { Core, MailboxRow, View } from './core.ts';
import { MESSAGE_COLS, dispatchView, messageView } from './workspace.ts';
import type { workspace } from './workspace.ts';

export const JOB_DISPATCH = 'correspondence.dispatch';
export const JOB_RECONCILE = 'correspondence.reconcile';
export const JOB_SYNC = 'correspondence.sync';
type Blocker = { code: string; message: string };
type SendCheck = { mode: 'automated' | 'human'; kind: string; grantId: string | null; requestedBy: string; recipients: string[]; threadId: string; mailboxId: string; at: Date;
  dispatchId: string | null; threadEpoch?: number; mailboxEpoch?: number };
const ACTIVE = `('queued','dispatching','accepted','delivered','bounced','uncertain')`;
const SENT = `('dispatching','accepted','delivered','bounced','uncertain')`;
const domainOf = (a: string): string => a.slice(a.indexOf('@') + 1);

export function delivery(core: Core, ws: ReturnType<typeof workspace>) {
  const { sql } = core;
  const system = (ctx: ServiceContext): ServiceContext => ({ ...ctx, now: new Date().toISOString() });

  // ───────────── Shared send validation (at request time and again inside the job) ─────────────
  async function sendBlocker(tx: Sql, ctx: ServiceContext, mailbox: MailboxRow, thread: Row, p: SendCheck): Promise<Blocker | null> {
    const atDispatch = p.dispatchId !== null;
    if (mailbox.state !== 'active') return { code: 'invalid_state', message: 'The mailbox is disabled' };
    if (mailbox.profile_verified_at === null) return { code: 'invalid_state', message: 'The mailbox sender profile has not been verified by a human; nothing can be sent under it' };
    const hit = await suppressed(tx, ctx, p.recipients);
    if (hit !== null) return { code: 'suppressed', message: 'A recipient has refused contact or is suppressed' };
    const contact = thread.contact_id === null ? undefined : (await tx.query(`select c.* from ${S}.contacts c where ${T('c')} and c.id=$4`, sc(ctx, thread.contact_id)))[0];
    if (p.mode === 'human') {
      if (contact?.sensitive === true && core.ports.useDecision === undefined && !core.cfg.standaloneAllowSensitiveContact) return { code: 'consent_denied', message: 'Contact with a sensitive contact needs a use decision; no decision service is connected' };
      return null;
    }
    // Automated sending: control, consent state, contact route and the grant, all re-read under lock.
    if (mailbox.control_mode !== 'automation' || thread.control_mode !== 'automation') return { code: 'takeover_active', message: 'A human has taken over; automated sending is stopped' };
    if (p.threadEpoch !== undefined && (p.threadEpoch !== thread.control_epoch || p.mailboxEpoch !== mailbox.control_epoch)) return { code: 'takeover_active', message: 'Control changed hands after this message was queued' };
    if (thread.blocked === true || contact?.blocked === true) return { code: 'consent_denied', message: 'Automated contact is blocked for this conversation or contact' };
    if (thread.stale === true) return { code: 'stale', message: 'The question or contact route changed; a human must review before automation continues' };
    if (thread.refused === true) return { code: 'suppressed', message: 'The contact refused; automated contact has stopped' };
    if (contact === undefined) return { code: 'grant_invalid', message: 'Automated messages go only to a recorded contact' };
    if (contact.sensitive === true) return { code: 'consent_denied', message: 'Sensitive contacts are never contacted automatically' };
    if (core.cfg.requireVerifiedContactForAutomation && contact.state !== 'verified') return { code: 'grant_invalid', message: 'The contact route has not been verified by a human' };
    if (p.recipients.length !== 1 || p.recipients[0] !== contact.address) return { code: 'grant_invalid', message: 'Automated messages go only to the contact on record' };
    if (thread.plan_id !== null) {
      const plan = (await tx.query(`select blocked, stale from ${S}.plans p where ${T('p')} and p.id=$4`, sc(ctx, thread.plan_id)))[0];
      if (plan?.blocked === true) return { code: 'consent_denied', message: 'Automated contact is blocked for this question' };
    }
    if (p.grantId === null) return { code: 'grant_invalid', message: 'Automated sending requires a sending grant' };
    const g = (await tx.query(`select g.* from ${S}.grants g where ${P('g')} and g.id=$4 for update`, sc(ctx, p.grantId)))[0];
    const deny = (message: string): Blocker => ({ code: 'grant_invalid', message });
    if (g === undefined) return deny('The sending grant does not exist');
    if (g.state !== 'active') return deny('The sending grant was revoked');
    const expires = (g.expires_at as Date).getTime();
    if (expires <= Date.now() || expires <= p.at.getTime()) return deny('The sending grant has expired or expires before the send time');
    if (g.grantee_id !== p.requestedBy) return deny('The sending grant belongs to another actor');
    if (g.mailbox_id !== p.mailboxId) return deny('The sending grant is for another mailbox');
    if (!p.recipients.every((r) => (g.recipient_allowlist as string[]).includes(r) || (g.domain_allowlist as string[]).includes(domainOf(r)))) return deny('A recipient is outside the grant');
    if ((g.question_refs as string[]).length > 0 && !(g.question_refs as string[]).some((q) => typeof thread.question_ref === 'string' && urefMatches(q, thread.question_ref))) return deny('The conversation is outside the questions covered by the grant');
    const self = p.dispatchId ?? '00000000-0000-0000-0000-000000000000';
    const pending = atDispatch ? 0 : Number((await tx.query(`select count(*)::int as n from ${S}.dispatches d where ${T('d')} and d.grant_id=$4 and d.state='queued'`, sc(ctx, g.id)))[0]?.n ?? 0);
    if ((g.used_messages as number) + pending >= (g.max_messages as number)) return deny('The sending grant is used up');
    const states = atDispatch ? SENT : ACTIVE;
    if (p.kind === 'follow_up') {
      const n = Number((await tx.query(`select count(*)::int as n from ${S}.dispatches d where ${T('d')} and d.thread_id=$4 and d.kind='follow_up' and d.state in ${states} and d.id<>$5`, sc(ctx, p.threadId, self)))[0]?.n ?? 0);
      if (n >= Math.min(g.follow_up_limit as number, core.cfg.maxFollowUps)) return deny('The follow-up limit is reached');
    } else {
      const n = Number((await tx.query(`select count(*)::int as n from ${S}.dispatches d where ${T('d')} and d.grant_id=$4 and d.kind<>'follow_up' and d.recipients && $5::text[] and d.state in ${states} and d.id<>$6`, sc(ctx, g.id, p.recipients, self)))[0]?.n ?? 0);
      if (n >= (g.per_recipient_cap as number)) return deny('The per-recipient limit of the grant is reached');
    }
    const last = (await tx.query<{ at: Date | null }>(`select max(coalesce(d.dispatching_at, d.run_at)) as at from ${S}.dispatches d where ${T('d')} and d.mailbox_id=$4 and d.mode='automated' and d.recipients && $5::text[] and d.state in ${states} and d.id<>$6`, sc(ctx, p.mailboxId, p.recipients, self)))[0]?.at ?? null;
    if (last !== null && last.getTime() + (g.cooldown_seconds as number) * 1000 > p.at.getTime()) return deny('The recipient was contacted too recently (cooldown)');
    return null;
  }

  // ───────────── Send request ─────────────
  /** Queues a draft for delivery, now or at `sendAt`. Agents need a grant; every check is repeated inside the dispatch job. */
  async function sendMessage(ctx: ServiceContext, messageId: string, input: { grantId?: string; sendAt?: string; idempotencyKey?: string } = {}): Promise<View> {
    return command(core, ctx, 'correspondence:send', input.idempotencyKey, { messageId, ...input }, async (tx) => {
      const head = (await tx.query(`select m.mailbox_id, m.thread_id from ${S}.messages m where ${W('m')} and m.id=$4`, sc(ctx, id(messageId))))[0] ?? notFound();
      const mailbox = await loadMailbox(tx, ctx, head.mailbox_id as string, 'for share');
      const thread = (await tx.query(`select t.* from ${S}.threads t where ${T('t')} and t.id=$4 for update`, sc(ctx, head.thread_id)))[0] ?? notFound();
      const msg = (await tx.query(`select m.* from ${S}.messages m where ${T('m')} and m.id=$4 for update`, sc(ctx, messageId)))[0] ?? notFound();
      invariant(msg.direction === 'outbound' && ['draft', 'cancelled', 'failed'].includes(msg.state as string), 'invalid_state', `A message in state ${msg.state} cannot be sent`);
      const mode = ctx.actor.kind === 'human' ? 'human' : 'automated';
      const recipients = [...new Set([...(msg.to_addrs as string[]), ...(msg.cc_addrs as string[])])];
      invariant(recipients.length >= 1 && recipients.length <= core.cfg.maxRecipients, 'invalid_input', 'The message needs at least one recipient');
      invariant((msg.subject as string).trim() !== '' && (msg.body_text as string).trim() !== '', 'invalid_input', 'The message needs a subject and a body');
      const now = new Date(ctx.now);
      const runAt = input.sendAt === undefined ? now : time(input.sendAt, 'sendAt');
      invariant(runAt.getTime() <= now.getTime() + 366 * 86_400_000, 'invalid_input', 'sendAt is too far in the future');
      if (mode === 'automated') {
        const flags = findIdentityClaims(`${msg.subject}\n${msg.body_text}`, mailbox.sender_profile, core.rules);
        invariant(flags.length === 0, 'invalid_identity_claim', `Automated messages may not claim an identity outside the sender profile (${flags.join(', ')})`);
        invariant((msg.body_text as string).length <= core.rules.maxAutomatedBodyChars, 'invalid_input', `Automated messages are limited to ${core.rules.maxAutomatedBodyChars} characters`);
        invariant(Number((await tx.query(`select count(*)::int as n from ${S}.attachments a where ${T('a')} and a.message_id=$4 and not a.removed`, sc(ctx, msg.id)))[0]?.n ?? 0) === 0, 'invalid_input', 'Automated messages carry no attachments');
      }
      const prior = (await tx.query<{ at: Date }>(`select max(d.created_at) as at from ${S}.dispatches d where ${T('d')} and d.thread_id=$4 and d.state in ${ACTIVE}`, sc(ctx, thread.id)))[0]?.at ?? null;
      const answered = prior !== null && (await tx.query(`select 1 from ${S}.messages m where ${T('m')} and m.thread_id=$4 and m.direction='inbound' and m.classification in ('reply','refusal') and m.created_at > $5 limit 1`, sc(ctx, thread.id, prior))).length > 0;
      const kind = msg.in_reply_to !== null || answered ? 'reply' : prior === null ? 'initial' : mode === 'automated' ? 'follow_up' : 'reply';
      const grantId = mode === 'automated' ? (input.grantId === undefined ? null : id(input.grantId)) : null;
      const blocker = await sendBlocker(tx, ctx, mailbox, thread, { mode, kind, grantId, requestedBy: ctx.actor.id, recipients, threadId: thread.id as string, mailboxId: mailbox.id, at: runAt > now ? runAt : now, dispatchId: null });
      if (blocker !== null) throw new DomainError(blocker.code, blocker.message);
      const dispatchId = randomUUID();
      const header = (msg.message_id_header as string | null) ?? `<${randomUUID()}@${domainOf(mailbox.address)}>`;
      const job = await enqueueJob(tx, S, ctx, { kind: JOB_DISPATCH, payload: { dispatchId }, dedupeKey: dispatchId, runAt, maxAttempts: 4 });
      const row = (await tx.query(`insert into ${S}.dispatches (tenant_id, project_id, id, message_id, thread_id, mailbox_id, compartment, mode, kind, grant_id, requested_by, recipients, message_id_header, thread_epoch, mailbox_epoch, state, run_at, job_id, created_at, updated_at)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'queued',$16,$17,$18,$18) returning *`,
        [ctx.tenantId, ctx.projectId, dispatchId, msg.id, thread.id, mailbox.id, msg.compartment, mode, kind, grantId, ctx.actor.id, recipients, header, thread.control_epoch, mailbox.control_epoch, runAt.toISOString(), job.id, ctx.now]))[0] as Row;
      await tx.query(`update ${S}.messages m set state='queued', message_id_header=$5, disclosure=$6, updated_at=$7 where ${T('m')} and m.id=$4`, sc(ctx, msg.id, header, renderDisclosure(mailbox.sender_profile, mode === 'automated', core.rules), ctx.now));
      await deliveryEvent(tx, ctx, dispatchId, 'queued', { mode, kind, runAt: runAt.toISOString(), by: ctx.actor.id });
      await record(tx, ctx, 'message.queued', ref('message', msg.id as string), { dispatch: dispatchId, mode, kind, grant: grantId, runAt: runAt.toISOString() }, { type: 'message.queued', payload: { dispatch: ref('dispatch', dispatchId), mode, kind } });
      return dispatchView(view(row));
    });
  }
  /** Follow-up to an unanswered automated inquiry: bounded by the grant's follow-up limit and cooldown, cancelled by any reply. */
  async function scheduleFollowUp(ctx: ServiceContext, threadId: string, input: { grantId: string; sendAt: string; structured: Json; idempotencyKey?: string }): Promise<View> {
    requireCapability(ctx, 'correspondence:send'); requireCapability(ctx, 'correspondence:write');
    const key = input.idempotencyKey;
    const draft = await ws.createDraft(ctx, { threadId, structured: input.structured, ...(key === undefined ? {} : { idempotencyKey: `${key}:draft` }) });
    try { return await sendMessage(ctx, draft.id as string, { grantId: input.grantId, sendAt: input.sendAt, ...(key === undefined ? {} : { idempotencyKey: `${key}:send` }) }); }
    catch (error) { await ws.discardDraft(ctx, draft.id as string).catch(() => undefined); throw error; }
  }
  async function cancelDispatch(ctx: ServiceContext, dispatchId: string, input: { reason?: string } = {}): Promise<View> {
    requireCapability(ctx, 'correspondence:send');
    return sql.tx(async (tx) => {
      const rows = await tx.query<Row & { id: string; message_id: string; job_id: string | null }>(`update ${S}.dispatches d set state='cancelled', state_reason='cancelled_by_user', settled_at=$5, updated_at=$5 where ${W('d')} and d.id=$4 and d.state='queued' returning d.*`, sc(ctx, id(dispatchId), ctx.now));
      if (rows[0] === undefined) {
        const cur = (await tx.query(`select d.state from ${S}.dispatches d where ${W('d')} and d.id=$4`, sc(ctx, dispatchId)))[0] ?? notFound();
        throw new DomainError('invalid_state', `A dispatch in state ${cur.state} cannot be cancelled; once handed to a provider it stays in transit`);
      }
      await ws.internal.releaseCancelled(tx, ctx, rows, 'cancelled_by_user');
      await record(tx, ctx, 'message.send.cancelled', ref('message', rows[0].message_id), { dispatch: dispatchId, reason: input.reason === undefined ? 'cancelled_by_user' : freeText(input.reason, 'reason', 300) }, { type: 'message.send.cancelled', payload: { dispatch: ref('dispatch', dispatchId), reason: 'cancelled_by_user' } });
      return dispatchView(view(rows[0]));
    });
  }
  async function listDispatches(ctx: ServiceContext, query: { states?: string[]; mailboxId?: string; threadId?: string; limit?: number } = {}): Promise<View[]> {
    requireCapability(ctx, 'correspondence:read');
    return views(await sql.query(`select d.*, m.subject from ${S}.dispatches d join ${S}.messages m on m.id=d.message_id where ${W('d')} and ($4::text[] is null or d.state = any($4)) and ($5::uuid is null or d.mailbox_id=$5) and ($6::uuid is null or d.thread_id=$6) order by d.created_at desc limit ${page(query, 100, 500)}`,
      sc(ctx, query.states === undefined ? null : query.states, query.mailboxId === undefined ? null : id(query.mailboxId), query.threadId === undefined ? null : id(query.threadId)))).map(dispatchView);
  }
  async function getDispatch(ctx: ServiceContext, dispatchId: string): Promise<View> {
    requireCapability(ctx, 'correspondence:read');
    const v = dispatchView(view((await sql.query(`select d.* from ${S}.dispatches d where ${W('d')} and d.id=$4`, sc(ctx, id(dispatchId))))[0]));
    v.evidence = views(await sql.query(`select e.seq::text as id, e.kind, e.detail, e.at from ${S}.delivery_events e where ${P('e')} and e.dispatch_id=$4 order by e.seq`, sc(ctx, v.id)));
    return v;
  }

  // ───────────── Dispatch job ─────────────
  async function cancelInJob(tx: Sql, ctx: ServiceContext, d: Row, reason: string, detail: string): Promise<Json> {
    await tx.query(`update ${S}.dispatches d set state='cancelled', state_reason=$5, settled_at=$6, updated_at=$6 where ${T('d')} and d.id=$4`, sc(ctx, d.id, reason, ctx.now));
    await tx.query(`update ${S}.messages m set state='cancelled', updated_at=$5 where ${T('m')} and m.id=$4 and m.state in ('queued','sending')`, sc(ctx, d.message_id, ctx.now));
    await deliveryEvent(tx, ctx, d.id as string, 'cancelled', { reason, detail });
    await record(tx, ctx, 'message.send.cancelled', ref('message', d.message_id as string), { dispatch: d.id as string, reason, detail }, { type: 'message.send.cancelled', payload: { dispatch: ref('dispatch', d.id as string), reason } });
    return { state: 'cancelled', reason };
  }
  async function acceptedEffects(tx: Sql, ctx: ServiceContext, d: Row): Promise<void> {
    await tx.query(`update ${S}.messages m set state='sent', sent_at=coalesce(sent_at, $5), updated_at=$5 where ${T('m')} and m.id=$4`, sc(ctx, d.message_id, ctx.now));
    const thread = (await tx.query(`update ${S}.threads t set last_message_at=$5, updated_at=$5 where ${T('t')} and t.id=$4 returning contact_id, plan_id`, sc(ctx, d.thread_id, ctx.now)))[0];
    if (thread?.plan_id != null && thread.contact_id != null) await tx.query(`update ${S}.plan_candidates set state='contacted', updated_at=$3 where plan_id=$1 and contact_id=$2 and state in ('proposed','drafted')`, [thread.plan_id, thread.contact_id, ctx.now]);
    await contactEvent(tx, ctx, (thread?.contact_id as string | null | undefined) ?? null, 'message_sent', ref('message', d.message_id as string), { mode: d.mode as string, kind: d.kind as string });
  }
  async function settle(ctx: ServiceContext, dispatchId: string, outcome: SendOutcome, job: Pick<Job, 'attempts' | 'maxAttempts'> | null): Promise<{ result: Json; retry: boolean; budget: 'commit' | 'release' | 'keep'; reservation: string | null }> {
    return sql.tx(async (tx) => {
      const d = (await tx.query(`select d.* from ${S}.dispatches d where ${T('d')} and d.id=$4 for update`, sc(ctx, dispatchId)))[0] ?? notFound();
      const reservation = d.budget_reservation as string | null;
      if (d.state !== 'dispatching' && !(d.state === 'uncertain' && outcome.kind === 'accepted')) return { result: { state: d.state as string }, retry: false, budget: 'keep' as const, reservation };
      const subject = ref('message', d.message_id as string);
      if (outcome.kind === 'accepted') {
        const late = d.state === 'uncertain';
        await tx.query(`update ${S}.dispatches d set state='accepted', accepted_at=$5, provider_id=$6, provider_response=$7, state_reason=null, updated_at=$5,
          reconciled_at=case when $8 then $5::timestamptz else reconciled_at end, reconciliation=case when $8 then $9::jsonb else reconciliation end where ${T('d')} and d.id=$4`,
          sc(ctx, d.id, ctx.now, outcome.providerId, outcome.response, late, JSON.stringify({ method: 'late_provider_response', result: 'accepted' })));
        await acceptedEffects(tx, ctx, d);
        await deliveryEvent(tx, ctx, d.id as string, 'provider_accepted', { response: outcome.response, providerId: outcome.providerId });
        await record(tx, ctx, 'message.sent', subject, { dispatch: d.id as string, state: 'accepted', mode: d.mode as string }, { type: 'message.sent', payload: { dispatch: ref('dispatch', d.id as string), state: 'accepted', inTransit: true, mode: d.mode as string, kind: d.kind as string } });
        return { result: { state: 'accepted' }, retry: false, budget: 'commit' as const, reservation };
      }
      if (outcome.kind === 'rejected') {
        if (d.grant_id !== null) await tx.query(`update ${S}.grants g set used_messages=greatest(used_messages-1, 0) where ${P('g')} and g.id=$4`, sc(ctx, d.grant_id));
        const retry = !outcome.permanent && job !== null && job.attempts < job.maxAttempts;
        await deliveryEvent(tx, ctx, d.id as string, retry ? 'attempt_not_accepted' : 'provider_refused', { code: outcome.code, response: outcome.response, permanent: outcome.permanent });
        if (retry) {
          await tx.query(`update ${S}.dispatches d set state='queued', state_reason=$5, updated_at=$6 where ${T('d')} and d.id=$4`, sc(ctx, d.id, `retrying: ${outcome.code}`, ctx.now));
          await tx.query(`update ${S}.messages m set state='queued', updated_at=$5 where ${T('m')} and m.id=$4`, sc(ctx, d.message_id, ctx.now));
          return { result: { state: 'queued' }, retry: true, budget: 'release' as const, reservation };
        }
        await tx.query(`update ${S}.dispatches d set state='failed', state_reason=$5, provider_response=$6, settled_at=$7, updated_at=$7 where ${T('d')} and d.id=$4`, sc(ctx, d.id, outcome.code, outcome.response, ctx.now));
        await tx.query(`update ${S}.messages m set state='failed', updated_at=$5 where ${T('m')} and m.id=$4`, sc(ctx, d.message_id, ctx.now));
        await record(tx, ctx, 'message.send.failed', subject, { dispatch: d.id as string, code: outcome.code, response: outcome.response }, { type: 'message.send.failed', payload: { dispatch: ref('dispatch', d.id as string), code: outcome.code } });
        return { result: { state: 'failed', code: outcome.code }, retry: false, budget: 'release' as const, reservation };
      }
      await tx.query(`update ${S}.dispatches d set state='uncertain', state_reason=$5, updated_at=$6 where ${T('d')} and d.id=$4`, sc(ctx, d.id, outcome.reason, ctx.now));
      await tx.query(`update ${S}.messages m set state='uncertain', updated_at=$5 where ${T('m')} and m.id=$4`, sc(ctx, d.message_id, ctx.now));
      await deliveryEvent(tx, ctx, d.id as string, 'outcome_unknown', { reason: outcome.reason });
      await enqueueJob(tx, S, ctx, { kind: JOB_RECONCILE, payload: { dispatchId: d.id as string }, dedupeKey: `${d.id}:1`, runAt: new Date(Date.now() + core.cfg.reconcileDelayMs), maxAttempts: 3 });
      await record(tx, ctx, 'message.send.uncertain', subject, { dispatch: d.id as string, reason: outcome.reason }, { type: 'message.send.uncertain', payload: { dispatch: ref('dispatch', d.id as string), messageIdHeader: d.message_id_header as string, reason: outcome.reason } });
      return { result: { state: 'uncertain' }, retry: false, budget: 'commit' as const, reservation };
    });
  }
  async function settleBudget(ctx: ServiceContext, action: 'commit' | 'release' | 'keep', reservation: string | null, why: string): Promise<void> {
    if (reservation === null || core.ports.budget === undefined || action === 'keep') return;
    try { if (action === 'commit') await core.ports.budget.commit(ctx, reservation, { amount: 1 }); else await core.ports.budget.release(ctx, reservation, why); } catch { /* the reservation expires on the budget side; delivery state is already recorded */ }
  }
  async function runDispatch(job: Job): Promise<Json> {
    const ctx = system(job.ctx);
    const dispatchId = (job.payload as { dispatchId: string }).dispatchId;
    const head = (await sql.query(`select d.* from ${S}.dispatches d where ${T('d')} and d.id=$4`, sc(ctx, dispatchId)))[0];
    if (head === undefined) return { skipped: 'missing' };
    // A previous attempt reached the provider call and never recorded an outcome: unknown, so reconcile; never resend.
    if (head.state === 'dispatching') { const s = await settle(ctx, dispatchId, { kind: 'uncertain', reason: 'the worker stopped after handing the message to the provider' }, null); await settleBudget(ctx, s.budget, s.reservation, 'uncertain'); return s.result; }
    if (head.state !== 'queued') return { state: head.state as string };
    let denial: string | null = null;
    try {
      requireCapability(ctx, 'correspondence:send');
      if (core.ports.authorization !== undefined) {
        const decision = await core.ports.authorization.authorize(ctx, { capability: 'correspondence:send', resource: ref('mailbox', head.mailbox_id as string) });
        if (!decision.allowed) denial = `authorization denied (${sanitizeResponse(decision.reason)})`;
      }
    } catch (error) {
      if (error instanceof DomainError && ['forbidden', 'unauthenticated', 'grant_invalid', 'consent_denied'].includes(error.code)) denial = 'authorization denied';
      else if (job.attempts >= job.maxAttempts) denial = 'authorization could not be confirmed';
      else throw new Error('authorization service unavailable');
    }
    let reservation: string | null = null;
    if (denial === null && core.ports.budget !== undefined) {
      try { reservation = (await core.ports.budget.reserve(ctx, { category: 'correspondence.send', amount: 1, unit: 'message', subject: ref('dispatch', dispatchId), idempotencyKey: `e03-dispatch-${dispatchId}` })).reservationId; }
      catch (error) {
        if (error instanceof DomainError && error.code === 'budget_exhausted') denial = 'budget exhausted';
        else if (job.attempts >= job.maxAttempts) denial = 'budget could not be reserved';
        else throw new Error('budget service unavailable');
      }
    }
    type Prepared = { stop: Json } | { raw: Buffer; mailbox: MailboxRow; d: Row };
    let prepared: Prepared;
    try {
      prepared = await sql.tx<Prepared>(async (tx) => {
        const mailbox = await loadMailbox(tx, ctx, head.mailbox_id as string, 'for share');
        const thread = (await tx.query(`select t.* from ${S}.threads t where ${T('t')} and t.id=$4 for update`, sc(ctx, head.thread_id)))[0] ?? notFound();
        const d = (await tx.query(`select d.* from ${S}.dispatches d where ${T('d')} and d.id=$4 for update`, sc(ctx, dispatchId)))[0] ?? notFound();
        if (d.state !== 'queued') return { stop: { state: d.state as string } };
        if ((d.run_at as Date).getTime() > Date.now() + 1000) return { stop: { state: 'queued', waiting: true } };
        if (denial !== null) return { stop: await cancelInJob(tx, ctx, d, 'authorization_or_budget', denial) };
        const blocker = await sendBlocker(tx, ctx, mailbox, thread, { mode: d.mode as 'human', kind: d.kind as string, grantId: d.grant_id as string | null, requestedBy: d.requested_by as string, recipients: d.recipients as string[],
          threadId: d.thread_id as string, mailboxId: mailbox.id, at: new Date(), dispatchId, threadEpoch: d.thread_epoch as number, mailboxEpoch: d.mailbox_epoch as number });
        if (blocker !== null) return { stop: await cancelInJob(tx, ctx, d, blocker.code, blocker.message) };
        const msg = (await tx.query(`select m.* from ${S}.messages m where ${T('m')} and m.id=$4 for update`, sc(ctx, d.message_id)))[0] ?? notFound();
        const store = objects(core);
        const attachments = [];
        for (const a of await tx.query(`select a.filename, a.media_type, a.object_key from ${S}.attachments a where ${T('a')} and a.message_id=$4 and not a.removed order by a.created_at`, sc(ctx, msg.id))) attachments.push({ filename: a.filename as string, mediaType: a.media_type as string, content: await store.get(a.object_key as string) });
        const automated = d.mode === 'automated';
        const disclosure = renderDisclosure(mailbox.sender_profile, automated, core.rules);
        const raw = await composeMime({ from: { name: mailbox.display_name || mailbox.sender_profile.organizationName, address: mailbox.address }, to: msg.to_addrs as string[], cc: msg.cc_addrs as string[], subject: msg.subject as string,
          text: withDisclosure(msg.body_text as string, disclosure), messageId: d.message_id_header as string, inReplyTo: msg.in_reply_to as string | null, references: msg.refs as string[], date: new Date(), automated, attachments });
        const info = await store.put(objectKey(ctx, 'raw', `${msg.id}.eml`), raw);
        await tx.query(`update ${S}.dispatches d set state='dispatching', dispatching_at=$5, attempts=attempts+1, budget_reservation=$6, updated_at=$5 where ${T('d')} and d.id=$4`, sc(ctx, dispatchId, ctx.now, reservation));
        await tx.query(`update ${S}.messages m set state='sending', raw_key=$5, raw_sha256=$6, raw_size=$7, disclosure=$8, updated_at=$9 where ${T('m')} and m.id=$4`, sc(ctx, msg.id, info.key, info.sha256, info.size, disclosure, ctx.now));
        if (d.grant_id !== null) await tx.query(`update ${S}.grants g set used_messages=used_messages+1 where ${P('g')} and g.id=$4`, sc(ctx, d.grant_id));
        await deliveryEvent(tx, ctx, dispatchId, 'dispatching', { attempt: (d.attempts as number) + 1, sha256: info.sha256 });
        return { raw, mailbox, d };
      });
    } catch (error) {
      await settleBudget(ctx, 'release', reservation, 'not sent');
      if (job.attempts >= job.maxAttempts) await sql.tx(async (tx) => {
        const d = (await tx.query(`select d.* from ${S}.dispatches d where ${T('d')} and d.id=$4 and d.state='queued' for update`, sc(ctx, dispatchId)))[0];
        if (d !== undefined) await cancelInJob(tx, ctx, d, 'unavailable', error instanceof DomainError ? error.message : 'the message could not be prepared');
      });
      throw error;
    }
    if ('stop' in prepared) { await settleBudget(ctx, 'release', reservation, 'not sent'); return prepared.stop; }
    let outcome: SendOutcome;
    try { outcome = await adapterFor(core, ctx, prepared.mailbox, 'send').send({ from: prepared.mailbox.address, to: prepared.d.recipients as string[] }, prepared.raw, prepared.d.message_id_header as string); }
    catch (error) {
      // Missing configuration is detected before any network use; anything else may have reached the provider.
      outcome = error instanceof DomainError && ['unavailable', 'provider_unavailable', 'provider_auth_failed'].includes(error.code) ? { kind: 'rejected', permanent: true, code: error.code, response: error.message } : { kind: 'uncertain', reason: 'the provider adapter failed during the send' };
    }
    const settled = await settle(ctx, dispatchId, outcome, job);
    await settleBudget(ctx, settled.budget, settled.reservation, 'not sent');
    if (settled.retry) throw new Error(`provider did not accept the message (${outcome.kind === 'rejected' ? outcome.code : 'retry'})`);
    return settled.result;
  }

  // ───────────── Reconciliation of uncertain sends ─────────────
  async function applyLookup(ctx: ServiceContext, dispatchId: string, lookup: LookupOutcome, manual: boolean): Promise<View> {
    return sql.tx(async (tx) => {
      const d = (await tx.query(`select d.* from ${S}.dispatches d where ${T('d')} and d.id=$4 for update`, sc(ctx, dispatchId)))[0] ?? notFound();
      if (d.state !== 'uncertain') return dispatchView(view(d));
      const attempts = (d.reconcile_attempts as number) + 1; const subject = ref('message', d.message_id as string);
      const exhausted = attempts >= core.cfg.reconcileAttempts;
      if (lookup.kind === 'found') {
        const reconciliation = { method: 'provider_lookup', result: 'found', where: lookup.where, attempts };
        const row = (await tx.query(`update ${S}.dispatches d set state='accepted', accepted_at=coalesce(accepted_at, $5), provider_id=coalesce($6, provider_id), reconciled_at=$5, reconciliation=$7::jsonb, reconcile_attempts=$8, state_reason=null, updated_at=$5 where ${T('d')} and d.id=$4 returning *`, sc(ctx, d.id, ctx.now, lookup.providerId, JSON.stringify(reconciliation), attempts)))[0] as Row;
        await acceptedEffects(tx, ctx, d);
        await deliveryEvent(tx, ctx, d.id as string, 'reconciled_found', reconciliation);
        await record(tx, ctx, 'message.send.reconciled', subject, { dispatch: d.id as string, outcome: 'accepted', ...reconciliation }, { type: 'message.send.reconciled', payload: { dispatch: ref('dispatch', d.id as string), outcome: 'accepted', resent: false } });
        return dispatchView(view(row));
      }
      if (lookup.kind === 'absent' && lookup.conclusive && exhausted) {
        // The provider keeps an authoritative record of sent mail and has none after repeated lookups. Still not resent automatically.
        const reconciliation = { method: 'provider_lookup', result: 'absent', searched: [...lookup.searched], attempts };
        const row = (await tx.query(`update ${S}.dispatches d set state='not_sent', reconciled_at=$5, settled_at=$5, reconciliation=$6::jsonb, reconcile_attempts=$7, updated_at=$5 where ${T('d')} and d.id=$4 returning *`, sc(ctx, d.id, ctx.now, JSON.stringify(reconciliation), attempts)))[0] as Row;
        await tx.query(`update ${S}.messages m set state='cancelled', updated_at=$5 where ${T('m')} and m.id=$4`, sc(ctx, d.message_id, ctx.now));
        if (d.grant_id !== null) await tx.query(`update ${S}.grants g set used_messages=greatest(used_messages-1, 0) where ${P('g')} and g.id=$4`, sc(ctx, d.grant_id));
        await deliveryEvent(tx, ctx, d.id as string, 'reconciled_absent', reconciliation);
        await record(tx, ctx, 'message.send.reconciled', subject, { dispatch: d.id as string, outcome: 'not_sent', ...reconciliation }, { type: 'message.send.reconciled', payload: { dispatch: ref('dispatch', d.id as string), outcome: 'not_sent', resent: false } });
        return dispatchView(view(row));
      }
      const reconciliation = { method: 'provider_lookup', result: lookup.kind === 'absent' ? 'not_found_yet' : 'lookup_unavailable', detail: lookup.kind === 'absent' ? `searched ${lookup.searched.join(', ')}` : lookup.reason, attempts, exhausted: exhausted && !manual,
        next: exhausted ? 'A person must decide: mark as sent, or confirm it was not sent.' : 'Another lookup is scheduled.' };
      const row = (await tx.query(`update ${S}.dispatches d set reconciliation=$5::jsonb, reconcile_attempts=$6, updated_at=$7 where ${T('d')} and d.id=$4 returning *`, sc(ctx, d.id, JSON.stringify(reconciliation), attempts, ctx.now)))[0] as Row;
      await deliveryEvent(tx, ctx, d.id as string, 'reconcile_attempt', reconciliation);
      if (!exhausted) await enqueueJob(tx, S, ctx, { kind: JOB_RECONCILE, payload: { dispatchId: d.id as string }, dedupeKey: `${d.id}:${attempts + 1}`, runAt: new Date(Date.now() + core.cfg.reconcileDelayMs * 2 ** Math.min(attempts, 8)), maxAttempts: 3 });
      else await record(tx, ctx, 'message.send.reconcile_exhausted', subject, { dispatch: d.id as string, attempts });
      return dispatchView(view(row));
    });
  }
  async function lookupNow(ctx: ServiceContext, d: Row): Promise<LookupOutcome> {
    try { return await adapterFor(core, ctx, await loadMailbox(sql, ctx, d.mailbox_id as string), 'any').lookup(d.message_id_header as string); }
    catch (error) { return { kind: 'unavailable', reason: error instanceof DomainError ? error.message : 'provider lookup failed' }; }
  }
  async function runReconcile(job: Job): Promise<Json> {
    const ctx = system(job.ctx);
    const d = (await sql.query(`select d.* from ${S}.dispatches d where ${T('d')} and d.id=$4`, sc(ctx, (job.payload as { dispatchId: string }).dispatchId)))[0];
    if (d === undefined || d.state !== 'uncertain') return { state: (d?.state as string | undefined) ?? 'missing' };
    return { state: (await applyLookup(ctx, d.id as string, await lookupNow(ctx, d), false)).state as string };
  }
  /** Asks the provider now whether it holds the message (by Message-ID). Never resends. */
  async function reconcileDispatch(ctx: ServiceContext, dispatchId: string): Promise<View> {
    requireCapability(ctx, 'correspondence:send');
    const d = (await sql.query(`select d.* from ${S}.dispatches d where ${W('d')} and d.id=$4`, sc(ctx, id(dispatchId))))[0] ?? notFound();
    invariant(d.state === 'uncertain', 'invalid_state', 'Only an uncertain dispatch can be reconciled');
    return applyLookup(ctx, d.id as string, await lookupNow(ctx, d), true);
  }
  /** A person settles an uncertain send from outside knowledge. `resend` is an explicit, audited human decision. */
  async function resolveDispatch(ctx: ServiceContext, dispatchId: string, input: { outcome: 'sent' | 'not_sent'; note: string; resend?: boolean }): Promise<View> {
    requireCapability(ctx, 'correspondence:send'); requireHuman(ctx, 'Resolving an uncertain send');
    invariant(input.outcome === 'sent' || input.outcome === 'not_sent', 'invalid_input', 'outcome must be sent or not_sent');
    invariant(input.resend !== true || input.outcome === 'not_sent', 'invalid_input', 'Only a message confirmed as not sent can be sent again');
    const note = freeText(input.note, 'note', 500);
    const resolved = await sql.tx(async (tx) => {
      const d = (await tx.query(`select d.* from ${S}.dispatches d where ${W('d')} and d.id=$4 for update`, sc(ctx, id(dispatchId))))[0] ?? notFound();
      invariant(d.state === 'uncertain', 'invalid_state', 'Only an uncertain dispatch can be resolved');
      const reconciliation = { method: 'human_decision', result: input.outcome, by: ctx.actor.id, note };
      const state = input.outcome === 'sent' ? 'accepted' : 'not_sent';
      const row = (await tx.query(`update ${S}.dispatches d set state=$5, accepted_at=case when $5='accepted' then coalesce(accepted_at, $6::timestamptz) else accepted_at end, settled_at=case when $5='not_sent' then $6::timestamptz else settled_at end, reconciled_at=$6, reconciliation=$7::jsonb, state_reason=null, updated_at=$6 where ${T('d')} and d.id=$4 returning *`, sc(ctx, d.id, state, ctx.now, JSON.stringify(reconciliation))))[0] as Row;
      if (state === 'accepted') await acceptedEffects(tx, ctx, d);
      else {
        await tx.query(`update ${S}.messages m set state='cancelled', updated_at=$5 where ${T('m')} and m.id=$4`, sc(ctx, d.message_id, ctx.now));
        if (d.grant_id !== null) await tx.query(`update ${S}.grants g set used_messages=greatest(used_messages-1, 0) where ${P('g')} and g.id=$4`, sc(ctx, d.grant_id));
      }
      await deliveryEvent(tx, ctx, d.id as string, 'resolved_by_human', reconciliation);
      await record(tx, ctx, 'message.send.reconciled', ref('message', d.message_id as string), { dispatch: d.id as string, outcome: state, ...reconciliation, resend: input.resend === true }, { type: 'message.send.reconciled', payload: { dispatch: ref('dispatch', d.id as string), outcome: state, resent: false } });
      return row;
    });
    // The re-send keeps the same Message-ID so a receiving system can recognise a duplicate if the first copy did arrive.
    if (input.resend === true) return sendMessage(ctx, resolved.message_id as string);
    return dispatchView(view(resolved));
  }

  // ───────────── Inbound ─────────────
  type IngestResult = { message: View; duplicate: boolean; observedOutbound: boolean };
  async function ingest(ctx: ServiceContext, mailbox: MailboxRow, raw: Uint8Array, providerId: string | null): Promise<IngestResult> {
    invariant(raw instanceof Uint8Array && raw.byteLength > 0, 'invalid_input', 'A raw RFC822 message is required');
    invariant(raw.byteLength <= core.policy.maxMessageBytes, 'payload_too_large', 'Message exceeds the size limit');
    invariant(providerId === null || (providerId.length <= 600 && !/[\u0000-\u001f]/.test(providerId)), 'invalid_input', 'Invalid provider id');
    const known = async (q: Sql): Promise<IngestResult | null> => {
      if (providerId === null) return null;
      const row = (await q.query(`select ${MESSAGE_COLS} from ${S}.messages m join ${S}.message_provider_ids p on p.message_id=m.id where ${T('m')} and p.mailbox_id=$4 and p.provider_id=$5`, sc(ctx, mailbox.id, providerId)))[0];
      return row === undefined ? null : { message: messageView(row), duplicate: true, observedOutbound: row.direction === 'outbound' };
    };
    const seen = await known(sql);
    if (seen !== null) return seen;
    let parsed: ParsedInbound;
    try { parsed = await parseInbound(raw, core.rules); }
    catch (error) { if (error instanceof DomainError) throw error; throw new DomainError('invalid_input', 'The message could not be parsed as RFC822'); }
    const store = objects(core);
    return sql.tx(async (tx) => {
      const mapProvider = async (messageId: string): Promise<void> => {
        if (providerId !== null) await tx.query(`insert into ${S}.message_provider_ids (tenant_id, project_id, mailbox_id, provider_id, message_id) values ($1,$2,$3,$4,$5) on conflict do nothing`, [ctx.tenantId, ctx.projectId, mailbox.id, providerId, messageId]);
      };
      // Our own outbound message seen in the mailbox is delivery evidence, not new mail.
      if (parsed.messageId !== null) {
        const own = (await tx.query(`select d.* from ${S}.dispatches d where ${T('d')} and d.mailbox_id=$4 and d.message_id_header=$5 order by d.created_at desc limit 1 for update`, sc(ctx, mailbox.id, parsed.messageId)))[0];
        if (own !== undefined) {
          await mapProvider(own.message_id as string);
          await deliveryEvent(tx, ctx, own.id as string, 'observed_in_mailbox', { providerId, sha256: parsed.sha256 });
          if (own.state === 'uncertain') {
            const reconciliation = { method: 'observed_in_mailbox', result: 'found' };
            await tx.query(`update ${S}.dispatches d set state='accepted', accepted_at=coalesce(accepted_at, $5), reconciled_at=$5, reconciliation=$6::jsonb, state_reason=null, updated_at=$5 where ${T('d')} and d.id=$4`, sc(ctx, own.id, ctx.now, JSON.stringify(reconciliation)));
            await acceptedEffects(tx, ctx, own);
            await record(tx, ctx, 'message.send.reconciled', ref('message', own.message_id as string), { dispatch: own.id as string, outcome: 'accepted', ...reconciliation }, { type: 'message.send.reconciled', payload: { dispatch: ref('dispatch', own.id as string), outcome: 'accepted', resent: false } });
          }
          const row = (await tx.query(`select ${MESSAGE_COLS} from ${S}.messages m where ${T('m')} and m.id=$4`, sc(ctx, own.message_id)))[0];
          return { message: messageView(row), duplicate: true, observedOutbound: true };
        }
      }
      const c = parsed.classification;
      const linkIds = [...new Set([parsed.inReplyTo, ...parsed.references, ...(c.reportedMessageIds ?? [])].filter((x): x is string => typeof x === 'string'))];
      const parent = linkIds.length === 0 ? undefined : (await tx.query(`select m.id, m.thread_id, m.direction, m.message_id_header from ${S}.messages m where ${T('m')} and m.mailbox_id=$4 and m.message_id_header = any($5::text[]) order by (m.direction='outbound') desc, m.created_at desc limit 1`, sc(ctx, mailbox.id, linkIds)))[0];
      const from = parsed.from ?? 'unknown-sender@invalid.invalid';
      let thread: Row;
      if (parent !== undefined) thread = (await tx.query(`select t.* from ${S}.threads t where ${T('t')} and t.id=$4 for update`, sc(ctx, parent.thread_id)))[0] as Row;
      else {
        const contacts = await tx.query(`select c.id, c.compartment from ${S}.contacts c where ${T('c')} and c.address=$4 limit 2`, sc(ctx, from));
        const contact = contacts.length === 1 ? contacts[0] : undefined;
        thread = (await tx.query(`insert into ${S}.threads (tenant_id, project_id, id, mailbox_id, subject, contact_id, compartment, last_message_at, created_by, created_at, updated_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$8,$8) returning *`,
          [ctx.tenantId, ctx.projectId, randomUUID(), mailbox.id, parsed.subject, contact?.id ?? null, contact?.compartment ?? null, ctx.now, ctx.actor.id]))[0] as Row;
      }
      const messageId = randomUUID();
      const inserted = (await tx.query(`insert into ${S}.messages (tenant_id, project_id, id, thread_id, mailbox_id, compartment, direction, state, origin, author_id, from_addr, from_name, to_addrs, cc_addrs, subject, body_text, body_html,
        message_id_header, in_reply_to, refs, dedupe_key, raw_sha256, raw_size, classification, classification_detail, is_read, received_at, created_at, updated_at, search)
        values ($1,$2,$3,$4,$5,$6,'inbound','received','external',$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22::jsonb,false,$23,$23,$23, setweight(to_tsvector('simple', $12), 'A') || to_tsvector('simple', left($13, 200000)) || to_tsvector('simple', $8 || ' ' || $9))
        on conflict (tenant_id, project_id, mailbox_id, dedupe_key) where direction = 'inbound' do nothing returning ${MESSAGE_COLS.replaceAll('m.', '')}`,
        [ctx.tenantId, ctx.projectId, messageId, thread.id, mailbox.id, thread.compartment, from, from, parsed.fromName, [...parsed.to], [...parsed.cc], parsed.subject, parsed.text, parsed.html, parsed.messageId, parsed.inReplyTo, [...parsed.references],
          parsed.dedupeKey, parsed.sha256, parsed.size, c.kind, JSON.stringify({ rule: c.rule, ...(c.action === undefined ? {} : { action: c.action }), ...(c.status === undefined ? {} : { status: c.status }), ...(c.failedRecipients === undefined ? {} : { failedRecipients: [...c.failedRecipients] }), declaredDate: parsed.date }), ctx.now]))[0];
      if (inserted === undefined) {
        // Same Message-ID already ingested (replayed webhook, second folder, repeated sync): one message, one extraction.
        if (parent === undefined) await tx.query(`delete from ${S}.threads t where ${T('t')} and t.id=$4`, sc(ctx, thread.id));
        const prior = (await tx.query(`select ${MESSAGE_COLS} from ${S}.messages m where ${T('m')} and m.mailbox_id=$4 and m.dedupe_key=$5 and m.direction='inbound'`, sc(ctx, mailbox.id, parsed.dedupeKey)))[0] as Row;
        await mapProvider(prior.id as string);
        if (prior.raw_sha256 !== parsed.sha256) await record(tx, ctx, 'message.duplicate_id_different_content', ref('message', prior.id as string), { sha256: parsed.sha256 });
        return { message: messageView(prior), duplicate: true, observedOutbound: false };
      }
      // Original bytes are preserved exactly; the parsed columns are a derived view.
      const rawInfo = await store.put(objectKey(ctx, 'raw', `${messageId}.eml`), raw);
      await tx.query(`update ${S}.messages m set raw_key=$5 where ${T('m')} and m.id=$4`, sc(ctx, messageId, rawInfo.key));
      await mapProvider(messageId);
      for (const a of parsed.attachments) {
        if (a.content.byteLength === 0 || a.content.byteLength > core.policy.maxMessageBytes) continue;
        const attachmentId = randomUUID(); const info = await store.put(objectKey(ctx, 'attachments', attachmentId), a.content);
        await tx.query(`insert into ${S}.attachments (tenant_id, project_id, id, message_id, thread_id, compartment, filename, media_type, size, sha256, object_key, content_id, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
          [ctx.tenantId, ctx.projectId, attachmentId, messageId, thread.id, thread.compartment, a.filename, a.mediaType, info.size, info.sha256, info.key, a.contentId, ctx.now]);
      }
      await tx.query(`update ${S}.threads t set last_message_at=$5, archived=false, updated_at=$5 where ${T('t')} and t.id=$4`, sc(ctx, thread.id, ctx.now));
      const subject = ref('message', messageId); const contactId = thread.contact_id as string | null;
      const candidateState = async (state: string): Promise<void> => { if (thread.plan_id !== null && contactId !== null) await tx.query(`update ${S}.plan_candidates set state=$3, updated_at=$4 where plan_id=$1 and contact_id=$2`, [thread.plan_id, contactId, state, ctx.now]); };
      const cancelQueued = async (reason: string): Promise<string[]> => {
        const rows = await tx.query<{ id: string; message_id: string; job_id: string | null }>(`update ${S}.dispatches d set state='cancelled', state_reason=$5, settled_at=$6, updated_at=$6 where ${T('d')} and d.thread_id=$4 and d.mode='automated' and d.state='queued' returning d.id, d.message_id, d.job_id`, sc(ctx, thread.id, reason, ctx.now));
        await ws.internal.releaseCancelled(tx, ctx, rows, reason);
        return rows.map((r) => r.id);
      };
      const outboundIds = linkIds.length === 0 ? [] : await tx.query(`select d.* from ${S}.dispatches d where ${T('d')} and d.mailbox_id=$4 and d.message_id_header = any($5::text[]) and d.state in ('accepted','uncertain') for update`, sc(ctx, mailbox.id, linkIds));
      const settleOutbound = async (state: 'delivered' | 'bounced', kind: string, detail: Json): Promise<void> => {
        for (const d of outboundIds) {
          const wasUncertain = d.state === 'uncertain';
          await tx.query(`update ${S}.dispatches d set state=$5, settled_at=$6, accepted_at=coalesce(accepted_at, $6), updated_at=$6, state_reason=null, reconciled_at=case when $7 then $6::timestamptz else reconciled_at end,
            reconciliation=case when $7 then $8::jsonb else reconciliation end where ${T('d')} and d.id=$4`, sc(ctx, d.id, state, ctx.now, wasUncertain, JSON.stringify({ method: kind, result: 'found' })));
          if (wasUncertain) await acceptedEffects(tx, ctx, d);
          await deliveryEvent(tx, ctx, d.id as string, kind, { ...(detail as Record<string, Json>), evidence: subject });
          await record(tx, ctx, `message.${state}`, ref('message', d.message_id as string), { dispatch: d.id as string, evidence: subject, reconciled: wasUncertain }, { type: `message.${state}`, payload: { dispatch: ref('dispatch', d.id as string), evidence: subject, reconciledFromUncertain: wasUncertain } });
        }
      };
      let cancelled: string[] = [];
      if (c.kind === 'bounce') {
        await settleOutbound('bounced', 'bounce_reported', { action: c.action ?? '', status: c.status ?? '' });
        cancelled = await cancelQueued('bounced');
        if (outboundIds.length > 0) {
          await candidateState('bounced'); await contactEvent(tx, ctx, contactId, 'bounced', subject, { status: c.status ?? '' });
          // A permanent failure for an address we wrote to: stop writing to it.
          if ((c.status ?? '').startsWith('5')) for (const r of new Set(outboundIds.flatMap((d) => d.recipients as string[]).filter((r) => (c.failedRecipients ?? []).includes(r)))) await ws.internal.addSuppressionTx(tx, ctx, { scope: 'address', value: r, reason: `permanent delivery failure ${c.status}`, source: 'bounce', sourceRef: subject });
        }
      } else {
        if (c.kind === 'delivery_report') { if (c.action === 'delivered') await settleOutbound('delivered', 'delivery_report', { action: c.action, status: c.status ?? '' }); }
        else await settleOutbound('delivered', 'reply_observed', { classification: c.kind });
        if (c.kind === 'refusal') {
          // Refusal stops follow-up: the sender is suppressed for the whole project and the conversation is closed to automation.
          await tx.query(`update ${S}.threads t set refused=true where ${T('t')} and t.id=$4`, sc(ctx, thread.id));
          if (parsed.from !== null) await ws.internal.addSuppressionTx(tx, ctx, { scope: 'address', value: parsed.from, reason: 'recipient asked not to be contacted', source: 'refusal', sourceRef: subject });
          cancelled = await cancelQueued('refused');
          await candidateState('refused'); await contactEvent(tx, ctx, contactId, 'refused', subject, {});
          await record(tx, ctx, 'contact.refused', subject, { thread: thread.id as string, contact: contactId }, { type: 'contact.refused', payload: { conversation: ref('conversation', thread.id as string), contact: contactId === null ? null : ref('contact', contactId) } });
        } else if (c.kind === 'reply') {
          cancelled = await cancelQueued('reply_received');
          await candidateState('responded'); await contactEvent(tx, ctx, contactId, 'replied', subject, {});
        }
      }
      await record(tx, ctx, 'message.received', subject, { thread: thread.id as string, classification: c.kind, rule: c.rule, sha256: parsed.sha256, cancelledDispatches: cancelled },
        { type: 'message.received', payload: { conversation: ref('conversation', thread.id as string), classification: c.kind, sha256: parsed.sha256, questionRef: thread.question_ref as string | null } });
      // A reply to something we sent: its statements are attributed candidates for evaluation elsewhere, never facts.
      const answersOutbound = parent !== undefined && (await tx.query(`select 1 from ${S}.messages m where ${T('m')} and m.thread_id=$4 and m.direction='outbound' and m.state in ('sent','uncertain','sending') limit 1`, sc(ctx, thread.id))).length > 0;
      if (c.kind === 'reply' && answersOutbound) {
        const candidates: Json[] = [];
        for (const cand of assertionCandidates(parsed.text, core.rules)) {
          const assertionId = randomUUID();
          await tx.query(`insert into ${S}.assertions (tenant_id, project_id, id, message_id, thread_id, compartment, question_ref, quote, attributed_to, contact_id, extraction, proposed_by, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'deterministic',$11,$12)`,
            [ctx.tenantId, ctx.projectId, assertionId, messageId, thread.id, thread.compartment, thread.question_ref, cand.text, from, contactId, ctx.actor.id, ctx.now]);
          candidates.push({ ref: ref('assertion', assertionId), text: cand.text.slice(0, 300), start: cand.start, end: cand.end });
        }
        await record(tx, ctx, 'correspondence.reply_received', subject, { thread: thread.id as string, candidates: candidates.length },
          { type: 'correspondence.reply_received', payload: { questionRef: thread.question_ref as string | null, conversation: ref('conversation', thread.id as string), source: subject, attributedTo: from, contact: contactId === null ? null : ref('contact', contactId), status: 'attributed_unverified', candidates } });
      }
      return { message: messageView(inserted), duplicate: false, observedOutbound: false };
    });
  }
  /** Provider-independent ingestion of original RFC822 bytes (webhook, forwarder, import). Idempotent by Message-ID and provider id. */
  async function ingestRawMessage(ctx: ServiceContext, mailboxId: string, raw: Uint8Array, options: { providerId?: string } = {}): Promise<IngestResult> {
    requireCapability(ctx, 'correspondence:ingest');
    return ingest(ctx, await loadMailbox(sql, ctx, mailboxId), raw, options.providerId === undefined ? null : `ingest:${options.providerId}`);
  }
  type SyncResult = { ingested: number; duplicates: number; skipped: number; resets: number; more: boolean };
  async function syncOnce(ctx: ServiceContext, mailboxId: string, limit: number): Promise<SyncResult> {
    const mailbox = await loadMailbox(sql, ctx, mailboxId);
    const result: SyncResult = { ingested: 0, duplicates: 0, skipped: 0, resets: 0, more: false };
    const priorState = JSON.stringify(mailbox.sync_state);
    const finish = async (status: string, error: string | null, state?: Json): Promise<void> => {
      // The checkpoint advances only after every fetched message was ingested, and never over a concurrent run's newer checkpoint.
      await sql.query(`update ${S}.mailboxes m set last_sync_at=now(), last_sync_status=$5, last_sync_error=$6, sync_state=case when $7::jsonb is not null and m.sync_state=$8::jsonb then $7::jsonb else m.sync_state end where ${P('m')} and m.id=$4`,
        sc(ctx, mailbox.id, status, error, state === undefined ? null : JSON.stringify(state), priorState));
    };
    try {
      if (mailbox.state !== 'active') throw new DomainError('invalid_state', 'The mailbox is disabled');
      const batch = await adapterFor(core, ctx, mailbox, 'read').sync(mailbox.sync_state, limit);
      for (const m of batch.messages) {
        try { const r = await ingest(ctx, mailbox, m.raw, m.providerId); if (r.duplicate) result.duplicates++; else result.ingested++; }
        catch (error) { if (error instanceof DomainError && ['invalid_input', 'payload_too_large'].includes(error.code)) { result.skipped++; await sql.tx((tx) => record(tx, ctx, 'message.sync_skipped', ref('mailbox', mailbox.id), { providerId: m.providerId, reason: error.message })); } else throw error; }
      }
      for (const s of batch.skipped) { result.skipped++; await sql.tx((tx) => record(tx, ctx, 'message.sync_skipped', ref('mailbox', mailbox.id), { providerId: s.providerId, reason: s.reason })); }
      result.resets = batch.resets; result.more = batch.more;
      await finish('ok', null, batch.state);
      return result;
    } catch (error) {
      await finish(error instanceof DomainError && error.code === 'unavailable' ? 'unavailable' : 'failed', error instanceof DomainError ? error.message : 'synchronization failed');
      throw error;
    }
  }
  /** Reads new mail from the configured provider now (IMAP UID checkpoints, Gmail history or Graph delta). */
  async function syncMailboxNow(ctx: ServiceContext, mailboxId: string, options: { limit?: number } = {}): Promise<SyncResult> {
    requireCapability(ctx, 'correspondence:sync');
    return syncOnce(ctx, id(mailboxId), page(options, 50, 200));
  }
  async function syncMailbox(ctx: ServiceContext, mailboxId: string): Promise<{ jobId: string }> {
    requireCapability(ctx, 'correspondence:sync');
    const mailbox = await loadMailbox(sql, ctx, mailboxId);
    return sql.tx(async (tx) => ({ jobId: (await enqueueJob(tx, S, ctx, { kind: JOB_SYNC, payload: { mailboxId: mailbox.id }, dedupeKey: `${mailbox.id}:${ctx.requestId}`, maxAttempts: 3 })).id }));
  }
  async function runSync(job: Job): Promise<Json> {
    const ctx = system(job.ctx);
    requireCapability(ctx, 'correspondence:sync');
    let total: SyncResult = { ingested: 0, duplicates: 0, skipped: 0, resets: 0, more: true };
    for (let i = 0; i < 20 && total.more; i++) {
      const r = await syncOnce(ctx, (job.payload as { mailboxId: string }).mailboxId, 50);
      total = { ingested: total.ingested + r.ingested, duplicates: total.duplicates + r.duplicates, skipped: total.skipped + r.skipped, resets: total.resets + r.resets, more: r.more };
    }
    return total;
  }
  /** One polling pass of the delivery, reconciliation and synchronization workers. */
  async function runWorkerOnce(options: { limit?: number } = {}): Promise<number> {
    return runJobsOnce(sql, S, { [JOB_DISPATCH]: runDispatch, [JOB_RECONCILE]: runReconcile, [JOB_SYNC]: runSync }, { worker: core.cfg.workerId, limit: options.limit ?? 5, leaseMs: Math.max(core.policy.timeoutMs * 5, 60_000) });
  }

  // ───────────── Evidence hand-off ─────────────
  /** Hands the preserved original message (and its attachments) to the evidence engine and records the returned references. */
  async function handToEvidence(ctx: ServiceContext, messageId: string): Promise<View> {
    requireCapability(ctx, 'correspondence:write');
    if (core.ports.evidence === undefined) throw new DomainError('unavailable', 'No evidence service is connected');
    const msg = (await sql.query(`select m.id, m.raw_key, m.compartment, m.from_addr, m.direction, m.classification_detail from ${S}.messages m where ${W('m')} and m.id=$4`, sc(ctx, id(messageId))))[0] ?? notFound();
    invariant(msg.raw_key !== null, 'invalid_state', 'The message has no preserved original');
    const origin = { engine: 'E03', source: ref('message', msg.id as string), direction: msg.direction as string, attributedTo: msg.from_addr as string, verification: 'attributed_unverified' };
    const comp = msg.compartment === null ? {} : { compartment: msg.compartment as string };
    const original = await core.ports.evidence.accept(ctx, { bytes: await objects(core).get(msg.raw_key as string), mediaType: 'message/rfc822', filename: `${msg.id}.eml`, origin, ...comp, idempotencyKey: `e03-message-${msg.id}` });
    const attachments: Json[] = [];
    for (const a of await sql.query(`select a.* from ${S}.attachments a where ${W('a')} and a.message_id=$4 and not a.removed`, sc(ctx, msg.id))) {
      const info = await core.ports.evidence.accept(ctx, { bytes: await objects(core).get(a.object_key as string), mediaType: a.media_type as string, filename: a.filename as string, origin: { ...origin, attachment: a.id as string, parent: original.ref }, ...comp, idempotencyKey: `e03-attachment-${a.id}` });
      await sql.query(`update ${S}.attachments a set evidence_ref=$5 where ${T('a')} and a.id=$4`, sc(ctx, a.id, info.ref));
      attachments.push({ attachment: a.id as string, evidenceRef: info.ref });
    }
    await sql.tx((tx) => record(tx, ctx, 'message.preserved_as_evidence', ref('message', msg.id as string), { evidenceRef: original.ref, attachments }, { type: 'message.preserved_as_evidence', payload: { evidenceRef: original.ref } }));
    return { message: ref('message', msg.id as string), evidenceRef: original.ref, attachments };
  }

  // ───────────── Upstream changes ─────────────
  async function applyUpstreamChange(ctx: ServiceContext, change: UpstreamChange): Promise<{ affected: string[] }> {
    if (!Array.isArray(ctx?.capabilities) || !ctx.capabilities.includes('correspondence:upstream')) requireCapability(ctx, 'correspondence:write');
    invariant(change !== null && typeof change === 'object' && typeof change.eventId === 'string' && change.eventId.length > 0 && change.eventId.length <= 200 && Array.isArray(change.refs) && change.refs.length <= 500 && typeof change.reason === 'string' && typeof change.kind === 'string', 'invalid_input', 'Invalid upstream change');
    const refs = change.refs.filter((r) => { try { return urefMatches(r, r); } catch { return false; } });
    return sql.tx(async (tx) => {
      const done = await tx.query(`insert into ${S}.upstream_changes (tenant_id, project_id, event_id, kind, result, at) values ($1,$2,$3,$4,'{}'::jsonb,$5) on conflict do nothing returning event_id`, [ctx.tenantId, ctx.projectId, change.eventId, change.kind, ctx.now]);
      if (done[0] === undefined) return ((await tx.query<{ result: { affected: string[] } }>(`select result from ${S}.upstream_changes where tenant_id=$1 and project_id=$2 and event_id=$3`, [ctx.tenantId, ctx.projectId, change.eventId]))[0] as { result: { affected: string[] } }).result;
      // Withdrawn or changed permission blocks automated contact; other upstream changes make the conversation stale for human review.
      const block = change.kind === 'permission_withdrawn' || change.kind === 'permission_changed' || change.kind === 'source_removed';
      const flag = block ? 'blocked' : 'stale'; const col = block ? 'block_reasons' : 'stale_reasons';
      const matches = (list: unknown): boolean => (Array.isArray(list) ? list : [list]).some((s) => typeof s === 'string' && refs.some((r) => { try { return urefMatches(r, s); } catch { return false; } }));
      const ids = refs.map((r) => r.replace(/@\d+$/, ''));
      const like = ids.map((r) => `${r}@%`);
      const affected: string[] = []; const threadIds = new Set<string>();
      const mark = async (table: string, kind: string, row: Row): Promise<void> => {
        await tx.query(`update ${S}.${table} x set ${flag}=true, ${col}=$5::jsonb, updated_at=$6 where ${T('x')} and x.id=$4`, sc(ctx, row.id, reasons(row[col], change.reason, change.eventId, change.kind, ctx.now), ctx.now));
        const subject = ref(kind, row.id as string); affected.push(subject);
        await record(tx, ctx, `${kind}.${flag}`, subject, { reason: change.reason.slice(0, 500), cause: change.eventId, kind: change.kind }, { type: `${kind}.${flag}`, payload: { reason: change.reason.slice(0, 500), cause: change.eventId, kind: change.kind } });
      };
      const candidates = (table: string, extra: string): Promise<Row[]> => tx.query(`select x.* from ${S}.${table} x where ${T('x')} and (x.sources && $4::text[] or exists (select 1 from unnest(x.sources) s where s like any($5::text[])) ${extra}) for update`, sc(ctx, ids, like));
      for (const c of await candidates('contacts', `or ('E03:contact:' || x.id::text) = any($4::text[])`)) {
        if (!matches(c.sources) && !ids.includes(`E03:contact:${c.id}`)) continue;
        await mark('contacts', 'contact', c);
        await contactEvent(tx, ctx, c.id as string, flag, null, { cause: change.eventId, kind: change.kind });
        for (const t of await tx.query<{ id: string }>(`select t.id from ${S}.threads t where ${T('t')} and t.contact_id=$4`, sc(ctx, c.id))) threadIds.add(t.id);
      }
      for (const p of await candidates('plans', '')) {
        if (!matches(p.sources)) continue;
        await mark('plans', 'plan', p);
        for (const t of await tx.query<{ id: string }>(`select t.id from ${S}.threads t where ${T('t')} and t.plan_id=$4`, sc(ctx, p.id))) threadIds.add(t.id);
      }
      for (const t of await candidates('threads', `or ('E03:conversation:' || x.id::text) = any($4::text[])`)) if (matches(t.sources) || ids.includes(`E03:conversation:${t.id}`)) threadIds.add(t.id as string);
      for (const threadId of threadIds) {
        const t = (await tx.query(`select t.* from ${S}.threads t where ${T('t')} and t.id=$4 for update`, sc(ctx, threadId)))[0];
        if (t === undefined) continue;
        await mark('threads', 'conversation', t);
        const cancelled = await tx.query<{ id: string; message_id: string; job_id: string | null }>(`update ${S}.dispatches d set state='cancelled', state_reason=$5, settled_at=$6, updated_at=$6 where ${T('d')} and d.thread_id=$4 and d.mode='automated' and d.state='queued' returning d.id, d.message_id, d.job_id`, sc(ctx, threadId, `upstream_${flag}`, ctx.now));
        await ws.internal.releaseCancelled(tx, ctx, cancelled, `upstream_${flag}`);
      }
      await tx.query(`update ${S}.upstream_changes set result=$4::jsonb where tenant_id=$1 and project_id=$2 and event_id=$3`, [ctx.tenantId, ctx.projectId, change.eventId, JSON.stringify({ affected })]);
      return { affected };
    });
  }
  /** A human reviewed a stale conversation (changed question or route) and lets automation continue. Blocks are not cleared here. */
  async function reviewStale(ctx: ServiceContext, threadId: string, input: { note: string }): Promise<View> {
    requireCapability(ctx, 'correspondence:write'); requireHuman(ctx, 'Reviewing a stale conversation');
    return sql.tx(async (tx) => {
      const t = (await tx.query(`select t.* from ${S}.threads t where ${W('t')} and t.id=$4 for update`, sc(ctx, id(threadId))))[0] ?? notFound();
      const row = (await tx.query(`update ${S}.threads t set stale=false, stale_reasons=$5::jsonb, updated_at=$6 where ${T('t')} and t.id=$4 returning id, stale, stale_reasons, blocked, block_reasons`,
        sc(ctx, t.id, JSON.stringify([...(t.stale_reasons as Json[]), { reviewedBy: ctx.actor.id, note: freeText(input.note, 'note', 500), at: ctx.now }]), ctx.now)))[0];
      await record(tx, ctx, 'conversation.stale_reviewed', ref('conversation', t.id as string), { note: input.note }, { type: 'conversation.stale_reviewed' });
      return view(row);
    });
  }

  return { sendMessage, scheduleFollowUp, cancelDispatch, listDispatches, getDispatch, reconcileDispatch, resolveDispatch, ingestRawMessage, syncMailboxNow, syncMailbox, runWorkerOnce, handToEvidence, applyUpstreamChange, reviewStale };
}
