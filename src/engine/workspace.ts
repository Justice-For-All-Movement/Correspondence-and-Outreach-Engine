// Mail workspace: mailboxes, contacts, suppression, labels, threads, drafts, attachments, outreach plans, grants, takeover.
import { randomUUID } from 'node:crypto';
import { DomainError, hashBytes, invariant } from '../contracts.ts';
import type { Json } from '../contracts.ts';
import { requireCapability } from '../service-kit.ts';
import type { Row, ServiceContext, Sql } from '../service-kit.ts';
import { findIdentityClaims, freeText, line, renderStructured, validateSenderProfile, validateStructured } from './mail.ts';
import type { SenderProfile, StructuredInquiry } from './mail.ts';
import { validateMailboxConfig, validateSecrets } from './providers.ts';
import type { MailboxProvider } from './providers.ts';
import { MAILBOX_COLS, P, S, T, W, adapterFor, address, addressList, command, compartment, contactEvent, decodeCursor, encodeCursor, forgetTokens, id, int, loadMailbox, notFound, objectKey, objects, optionalUref, page, record, ref, requireHuman, sc, sealFor, suppressed, time, view, views } from './core.ts';
import type { Core, View } from './core.ts';

export type Page<T> = { items: T[]; nextCursor: string | null; total: number };
export type Folder = 'inbox' | 'sent' | 'drafts' | 'outbox' | 'archive' | 'trash' | 'spam' | 'starred' | 'all' | 'attention';
export const FOLDERS: readonly Folder[] = ['inbox', 'sent', 'drafts', 'outbox', 'archive', 'trash', 'spam', 'starred', 'all', 'attention'];
const FOLDER_SQL: Readonly<Record<Folder, string>> = {
  inbox: `not t.archived and not t.trashed and not t.spam and exists (select 1 from ${S}.messages m where m.thread_id=t.id and m.direction='inbound')`,
  sent: `not t.trashed and exists (select 1 from ${S}.messages m where m.thread_id=t.id and m.direction='outbound' and m.state in ('sent','uncertain'))`,
  drafts: `not t.trashed and exists (select 1 from ${S}.messages m where m.thread_id=t.id and m.state='draft')`,
  outbox: `not t.trashed and exists (select 1 from ${S}.messages m where m.thread_id=t.id and m.state in ('queued','sending'))`,
  archive: 't.archived and not t.trashed', trash: 't.trashed', spam: 't.spam and not t.trashed', starred: 't.starred and not t.trashed', all: 'not t.trashed and not t.spam',
  attention: `not t.trashed and (t.stale or t.blocked or exists (select 1 from ${S}.dispatches d where d.thread_id=t.id and d.state='uncertain'))`,
};
const THREAD_SELECT = `select t.*, mb.control_mode as mailbox_control_mode, mb.address as mailbox_address,
  (select count(*)::int from ${S}.messages m where m.thread_id=t.id and m.state<>'discarded') as message_count,
  (select count(*)::int from ${S}.messages m where m.thread_id=t.id and m.direction='inbound' and not m.is_read) as unread_count,
  (select left(m.body_text, 200) from ${S}.messages m where m.thread_id=t.id and m.state<>'discarded' order by coalesce(m.received_at, m.sent_at, m.created_at) desc limit 1) as snippet,
  (select coalesce(array_agg(distinct a), '{}') from ${S}.messages m, unnest(array[m.from_addr] || m.to_addrs) a where m.thread_id=t.id and m.state<>'discarded') as participants,
  (select coalesce(array_agg(l.label_id::text), '{}') from ${S}.thread_labels l where l.thread_id=t.id) as label_ids,
  (select count(*)::int from ${S}.dispatches d where d.thread_id=t.id and d.state in ('dispatching','accepted','uncertain')) as in_transit_count,
  (select count(*)::int from ${S}.dispatches d where d.thread_id=t.id and d.state='queued') as queued_count,
  exists (select 1 from ${S}.attachments a where a.thread_id=t.id and not a.removed) as has_attachments
  from ${S}.threads t join ${S}.mailboxes mb on mb.id=t.mailbox_id`;
function threadView(row: Row | undefined): View {
  const v = view(row);
  // Automation acts only when both the mailbox and the thread are under automation control and nothing blocks it.
  v.automation = v.controlMode === 'human' || v.mailboxControlMode === 'human' ? 'human_control' : v.blocked === true ? 'blocked' : v.stale === true ? 'stale' : v.refused === true ? 'refused' : 'permitted_under_grant';
  v.ref = ref('conversation', String(v.id));
  return v;
}
export const MESSAGE_COLS = `m.id, m.thread_id, m.mailbox_id, m.compartment, m.direction, m.state, m.origin, m.author_id, m.from_addr, m.from_name, m.to_addrs, m.cc_addrs, m.subject, m.body_text,
  m.structured, m.disclosure, m.identity_flags, m.message_id_header, m.in_reply_to, m.refs, m.raw_sha256, m.raw_size, m.classification, m.classification_detail, m.is_read, m.revision,
  m.sent_at, m.received_at, m.created_at, m.updated_at`;
export function messageView(row: Row | undefined): View {
  const v = view(row);
  v.ref = ref('message', String(v.id), Number(v.revision));
  // Inbound text is attributed, unverified information from an outside party.
  if (v.direction === 'inbound') v.trust = 'untrusted_external_content';
  return v;
}
function mailboxView(row: Row | undefined): View {
  const v = view(row);
  v.credentials = { configured: v.secretFields as Json, setAt: v.secretSetAt as Json };
  delete v.secretFields; delete v.secretSetAt;
  v.profileVerified = v.profileVerifiedAt !== null;
  return v;
}
const TSV = (subject: string, body: string, people: string): string => `setweight(to_tsvector('simple', ${subject}), 'A') || to_tsvector('simple', ${body}) || to_tsvector('simple', ${people})`;

export function workspace(core: Core) {
  const { sql } = core;

  // ───────────── Mailboxes ─────────────
  async function createMailbox(ctx: ServiceContext, input: { address: string; displayName?: string; provider: MailboxProvider; config?: Json; senderProfile?: Json; credentials?: Json; idempotencyKey?: string }): Promise<View> {
    return command(core, ctx, 'correspondence:admin', input.idempotencyKey, { ...input, credentials: input.credentials === undefined ? null : 'provided' }, async (tx) => {
      invariant(['smtp_imap', 'gmail', 'graph', 'ingest_only'].includes(input.provider), 'invalid_input', 'Unknown provider');
      const mailboxId = randomUUID();
      const config = input.provider === 'ingest_only' ? {} : validateMailboxConfig(input.provider, input.config ?? {}, core.policy);
      const profile = input.senderProfile === undefined ? {} : validateSenderProfile(input.senderProfile);
      const secrets = input.credentials === undefined ? null : validateSecrets(input.credentials);
      const rows = await tx.query(`insert into ${S}.mailboxes (tenant_id, project_id, id, address, display_name, provider, config, secret_enc, secret_fields, secret_set_at, sender_profile, created_by, created_at, updated_at)
        values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11::jsonb,$12,$13,$13) on conflict (tenant_id, project_id, address) do nothing returning ${MAILBOX_COLS}`,
        [ctx.tenantId, ctx.projectId, mailboxId, address(input.address), input.displayName === undefined ? '' : line(input.displayName, 'displayName', 120), input.provider, JSON.stringify(config),
          secrets === null ? null : sealFor(core, ctx, mailboxId, secrets), secrets === null ? [] : Object.keys(secrets).sort(), secrets === null ? null : ctx.now, JSON.stringify(profile), ctx.actor.id, ctx.now]);
      invariant(rows[0] !== undefined, 'conflict', 'A mailbox with this address already exists');
      await record(tx, ctx, 'mailbox.created', ref('mailbox', mailboxId), { provider: input.provider, credentialFields: secrets === null ? [] : Object.keys(secrets).sort() }, { type: 'mailbox.created', payload: { provider: input.provider } });
      return mailboxView(rows[0]);
    });
  }
  async function updateMailbox(ctx: ServiceContext, mailboxId: string, input: { displayName?: string; config?: Json; state?: 'active' | 'disabled'; idempotencyKey?: string }): Promise<View> {
    return command(core, ctx, 'correspondence:admin', input.idempotencyKey, { mailboxId, ...input }, async (tx) => {
      const mb = await loadMailbox(tx, ctx, mailboxId, 'for update');
      const config = input.config === undefined ? mb.config : mb.provider === 'ingest_only' ? {} : validateMailboxConfig(mb.provider, input.config, core.policy);
      invariant(input.state === undefined || ['active', 'disabled'].includes(input.state), 'invalid_input', 'Invalid state');
      // New connection settings start a new synchronization history; stored credentials are kept.
      const rows = await tx.query(`update ${S}.mailboxes m set display_name=$5, config=$6::jsonb, state=$7, sync_state=case when $8 then '{}'::jsonb else sync_state end, updated_at=$9 where ${P('m')} and m.id=$4 returning ${MAILBOX_COLS}`,
        sc(ctx, mb.id, input.displayName === undefined ? mb.display_name : line(input.displayName, 'displayName', 120), JSON.stringify(config), input.state ?? mb.state, input.config !== undefined, ctx.now));
      await record(tx, ctx, 'mailbox.updated', ref('mailbox', mb.id), { fields: Object.keys(input).filter((k) => k !== 'idempotencyKey') });
      return mailboxView(rows[0]);
    });
  }
  async function setMailboxCredentials(ctx: ServiceContext, mailboxId: string, credentials: Json): Promise<View> {
    requireCapability(ctx, 'correspondence:admin');
    const secrets = validateSecrets(credentials);
    return sql.tx(async (tx) => {
      const mb = await loadMailbox(tx, ctx, mailboxId, 'for update');
      const rows = await tx.query(`update ${S}.mailboxes m set secret_enc=$5, secret_fields=$6, secret_set_at=$7, auth_epoch=auth_epoch+1, updated_at=$7 where ${P('m')} and m.id=$4 returning ${MAILBOX_COLS}`,
        sc(ctx, mb.id, sealFor(core, ctx, mb.id, secrets), Object.keys(secrets).sort(), ctx.now));
      forgetTokens({ tenantId: ctx.tenantId, projectId: ctx.projectId, mailboxId: mb.id });
      await record(tx, ctx, 'mailbox.credentials_set', ref('mailbox', mb.id), { credentialFields: Object.keys(secrets).sort() });
      return mailboxView(rows[0]);
    });
  }
  async function setSenderProfile(ctx: ServiceContext, mailboxId: string, profile: Json): Promise<View> {
    requireCapability(ctx, 'correspondence:admin');
    const valid = validateSenderProfile(profile);
    return sql.tx(async (tx) => {
      const mb = await loadMailbox(tx, ctx, mailboxId, 'for update');
      // A changed identity must be verified again by a human before anything is sent under it.
      const rows = await tx.query(`update ${S}.mailboxes m set sender_profile=$5::jsonb, profile_verified_at=null, profile_verified_by=null, updated_at=$6 where ${P('m')} and m.id=$4 returning ${MAILBOX_COLS}`, sc(ctx, mb.id, JSON.stringify(valid), ctx.now));
      await record(tx, ctx, 'mailbox.sender_profile_set', ref('mailbox', mb.id), { organizationName: valid.organizationName });
      return mailboxView(rows[0]);
    });
  }
  async function verifySenderProfile(ctx: ServiceContext, mailboxId: string): Promise<View> {
    requireCapability(ctx, 'correspondence:admin'); requireHuman(ctx, 'Verifying a sender identity');
    return sql.tx(async (tx) => {
      const mb = await loadMailbox(tx, ctx, mailboxId, 'for update');
      validateSenderProfile(mb.sender_profile);
      const rows = await tx.query(`update ${S}.mailboxes m set profile_verified_at=$5, profile_verified_by=$6, updated_at=$5 where ${P('m')} and m.id=$4 returning ${MAILBOX_COLS}`, sc(ctx, mb.id, ctx.now, ctx.actor.id));
      await record(tx, ctx, 'mailbox.sender_profile_verified', ref('mailbox', mb.id), { organizationName: mb.sender_profile.organizationName });
      return mailboxView(rows[0]);
    });
  }
  async function listMailboxes(ctx: ServiceContext): Promise<View[]> {
    requireCapability(ctx, 'correspondence:read');
    return (await sql.query(`select ${MAILBOX_COLS} from ${S}.mailboxes m where ${P('m')} order by m.address`, sc(ctx))).map(mailboxView);
  }
  async function getMailbox(ctx: ServiceContext, mailboxId: string): Promise<View> {
    requireCapability(ctx, 'correspondence:read');
    return mailboxView((await sql.query(`select ${MAILBOX_COLS} from ${S}.mailboxes m where ${P('m')} and m.id=$4`, sc(ctx, id(mailboxId))))[0]);
  }
  /** Connects to the configured provider and reports what works. Makes network calls; changes nothing. */
  async function testMailboxConnection(ctx: ServiceContext, mailboxId: string): Promise<{ send: string; read: string }> {
    requireCapability(ctx, 'correspondence:admin');
    const mb = await loadMailbox(sql, ctx, mailboxId);
    if (mb.provider === 'ingest_only') return { send: 'unavailable: mailbox is ingest-only', read: 'unavailable: mailbox is ingest-only (use the raw ingest route)' };
    return adapterFor(core, ctx, mb, 'any').verify();
  }

  // ───────────── Contacts and suppression ─────────────
  type ContactInput = { address: string; displayName?: string; organization?: string; roleTitle?: string; whyMayKnow?: string; routeSource?: string; routeNote?: string; sensitive?: boolean; compartment?: string };
  async function upsertContactTx(tx: Sql, ctx: ServiceContext, input: ContactInput): Promise<Row> {
    const addr = address(input.address); const comp = compartment(ctx, input.compartment);
    const route = optionalUref(input.routeSource, 'routeSource');
    const text = (v: string | undefined, label: string, max: number): string | null => (v === undefined ? null : v === '' ? '' : freeText(v, label, max));
    const rows = await tx.query(`insert into ${S}.contacts (tenant_id, project_id, id, address, display_name, organization, role_title, why_may_know, route_source, route_note, sources, sensitive, compartment, created_by, created_at, updated_at, search)
      values ($1,$2,$4,$5,coalesce($6,''),coalesce($7,''),coalesce($8,''),coalesce($9,''),$10,coalesce($11,''),case when $10::text is null then '{}'::text[] else array[$10::text] end,coalesce($12,false),$13,$14,$15,$15, null)
      on conflict (tenant_id, project_id, address, coalesce(compartment, '')) do update set display_name=coalesce($6, contacts.display_name), organization=coalesce($7, contacts.organization), role_title=coalesce($8, contacts.role_title),
        why_may_know=coalesce($9, contacts.why_may_know), route_note=coalesce($11, contacts.route_note), sensitive=contacts.sensitive or coalesce($12,false),
        -- A different route is a different claim about how this person was found: it needs verification again.
        state=case when $10::text is not null and contacts.route_source is distinct from $10 and contacts.state='verified' then 'candidate' else contacts.state end,
        route_source=coalesce($10, contacts.route_source), sources=case when $10::text is null or $10 = any(contacts.sources) then contacts.sources else contacts.sources || $10::text end,
        revision=contacts.revision+1, updated_at=$15
      where $3::text[] is not null returning *, (xmax = 0) as inserted`,
      sc(ctx, randomUUID(), addr, text(input.displayName, 'displayName', 200), text(input.organization, 'organization', 200), text(input.roleTitle, 'roleTitle', 200), text(input.whyMayKnow, 'whyMayKnow', 1000),
        route, text(input.routeNote, 'routeNote', 1000), input.sensitive ?? null, comp, ctx.actor.id, ctx.now));
    const row = rows[0] as Row;
    await tx.query(`update ${S}.contacts set search=to_tsvector('simple', address || ' ' || display_name || ' ' || organization || ' ' || role_title || ' ' || why_may_know) where id=$1`, [row.id]);
    if (row.inserted === true) await contactEvent(tx, ctx, row.id as string, 'created', route, {});
    await record(tx, ctx, row.inserted === true ? 'contact.created' : 'contact.updated', ref('contact', row.id as string), { routeSource: route });
    delete row.inserted;
    return row;
  }
  const contactView = (row: Row | undefined): View => { const v = view(row); v.ref = ref('contact', String(v.id), Number(v.revision)); return v; };
  async function upsertContact(ctx: ServiceContext, input: ContactInput & { idempotencyKey?: string }): Promise<View> {
    return command(core, ctx, 'correspondence:write', input.idempotencyKey, input, async (tx) => contactView(await upsertContactTx(tx, ctx, input)));
  }
  /** A human confirms the contact route (who this is and why they may know). Required before automated first contact. */
  async function verifyContact(ctx: ServiceContext, contactId: string, input: { note?: string; reject?: boolean } = {}): Promise<View> {
    requireCapability(ctx, 'correspondence:contact'); requireHuman(ctx, 'Verifying a contact route');
    return sql.tx(async (tx) => {
      const state = input.reject === true ? 'rejected' : 'verified';
      const rows = await tx.query(`update ${S}.contacts c set state=$5, verified_by=$6, verified_at=$7, revision=revision+1, updated_at=$7 where ${W('c')} and c.id=$4 returning *`, sc(ctx, id(contactId), state, ctx.actor.id, ctx.now));
      const row = rows[0] ?? notFound();
      const note = input.note === undefined ? '' : freeText(input.note, 'note', 500);
      await contactEvent(tx, ctx, row.id as string, state, row.route_source as string | null, { note });
      await record(tx, ctx, `contact.${state}`, ref('contact', row.id as string), { routeSource: row.route_source as Json }, state === 'verified' ? { type: 'outreach.candidate.verified', payload: { routeSource: row.route_source as Json } } : undefined);
      return contactView(row);
    });
  }
  async function listContacts(ctx: ServiceContext, query: { q?: string; state?: string; limit?: number; cursor?: string } = {}): Promise<Page<View>> {
    requireCapability(ctx, 'correspondence:read');
    const limit = page(query); const cur = decodeCursor(query.cursor, 2);
    const where = `${W('c')} and ($4::text is null or c.state=$4) and ($5::text is null or c.search @@ websearch_to_tsquery('simple', $5) or c.address ilike '%' || $5 || '%')`;
    const params = sc(ctx, query.state ?? null, query.q === undefined || query.q.trim() === '' ? null : query.q.slice(0, 200));
    const rows = await sql.query(`select c.* from ${S}.contacts c where ${where} and ($6::text is null or (c.address, c.id::text) > ($6, $7)) order by c.address, c.id limit ${limit + 1}`, [...params, cur?.[0] ?? null, cur?.[1] ?? null]);
    const total = (await sql.query<{ n: number }>(`select count(*)::int as n from ${S}.contacts c where ${where}`, params))[0]?.n ?? 0;
    const items = rows.slice(0, limit); const last = items[items.length - 1];
    return { items: items.map(contactView), nextCursor: rows.length > limit && last !== undefined ? encodeCursor([last.address as string, last.id as string]) : null, total };
  }
  async function getContact(ctx: ServiceContext, contactId: string): Promise<View> {
    requireCapability(ctx, 'correspondence:read');
    const row = (await sql.query(`select c.* from ${S}.contacts c where ${W('c')} and c.id=$4`, sc(ctx, id(contactId))))[0] ?? notFound();
    const v = contactView(row);
    v.history = views(await sql.query(`select e.seq::text as id, e.kind, e.ref, e.detail, e.actor_id, e.at from ${S}.contact_events e where ${P('e')} and e.contact_id=$4 order by e.seq desc limit 500`, sc(ctx, row.id)));
    v.threads = (await sql.query(`${THREAD_SELECT} where ${W('t')} and t.contact_id=$4 order by t.last_message_at desc limit 100`, sc(ctx, row.id))).map(threadView);
    v.suppressed = (await suppressed(sql, ctx, [row.address as string])) !== null;
    return v;
  }
  async function addSuppressionTx(tx: Sql, ctx: ServiceContext, input: { scope: 'address' | 'domain'; value: string; reason: string; source: 'refusal' | 'manual' | 'bounce' | 'upstream'; sourceRef?: string | null }): Promise<Row | null> {
    const rows = await tx.query(`insert into ${S}.suppressions (tenant_id, project_id, id, scope, value, reason, source, source_ref, created_by, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      on conflict (tenant_id, project_id, scope, value) where lifted_at is null do nothing returning *`,
      [ctx.tenantId, ctx.projectId, randomUUID(), input.scope, input.value, input.reason.slice(0, 500), input.source, input.sourceRef ?? null, ctx.actor.id, ctx.now]);
    if (rows[0] === undefined) return null;
    // A suppression stops everything still waiting to go to that recipient, automated or human.
    const cancelled = await tx.query<{ id: string; message_id: string; job_id: string | null }>(`update ${S}.dispatches d set state='cancelled', state_reason='suppressed', settled_at=$5, updated_at=$5 where ${T('d')} and d.state='queued'
      and exists (select 1 from unnest(d.recipients) r where ($6 = 'address' and r = $4) or ($6 = 'domain' and split_part(r, '@', 2) = $4)) returning d.id, d.message_id, d.job_id`, sc(ctx, input.value, ctx.now, input.scope));
    await releaseCancelled(tx, ctx, cancelled, 'suppressed');
    await record(tx, ctx, 'suppression.added', ref('suppression', rows[0].id as string), { scope: input.scope, source: input.source, cancelledDispatches: cancelled.length }, { type: 'suppression.added', payload: { scope: input.scope, source: input.source, sourceRef: input.sourceRef ?? null } });
    return rows[0];
  }
  /** Cancelled dispatches release their jobs and return their messages to editable drafts. */
  async function releaseCancelled(tx: Sql, ctx: ServiceContext, cancelled: readonly { id: string; message_id: string; job_id: string | null }[], reason: string): Promise<void> {
    if (cancelled.length === 0) return;
    await tx.query(`update ${S}._jobs set state='cancelled', lease_owner=null, lease_until=null, updated_at=now() where tenant_id=$1 and project_id=$2 and id = any($3::uuid[]) and state in ('queued','paused')`, [ctx.tenantId, ctx.projectId, cancelled.map((c) => c.job_id).filter((j) => j !== null)]);
    await tx.query(`update ${S}.messages m set state='cancelled', updated_at=$5 where ${T('m')} and m.id = any($4::uuid[]) and m.state='queued'`, sc(ctx, cancelled.map((c) => c.message_id), ctx.now));
    for (const c of cancelled) await tx.query(`insert into ${S}.delivery_events (tenant_id, project_id, dispatch_id, kind, detail, at) values ($1,$2,$3,'cancelled',$4::jsonb,$5)`, [ctx.tenantId, ctx.projectId, c.id, JSON.stringify({ reason, by: ctx.actor.id }), ctx.now]);
  }
  async function addSuppression(ctx: ServiceContext, input: { address?: string; domain?: string; reason: string; idempotencyKey?: string }): Promise<View> {
    return command(core, ctx, 'correspondence:write', input.idempotencyKey, input, async (tx) => {
      invariant((input.address === undefined) !== (input.domain === undefined), 'invalid_input', 'Give exactly one of address or domain');
      const value = input.address !== undefined ? address(input.address) : address(`x@${input.domain}`).slice(2);
      const scope = input.address !== undefined ? 'address' : 'domain';
      const row = await addSuppressionTx(tx, ctx, { scope, value, reason: line(input.reason, 'reason', 500), source: 'manual' });
      return view(row ?? (await tx.query(`select s.* from ${S}.suppressions s where ${P('s')} and s.scope=$4 and s.value=$5 and s.lifted_at is null`, sc(ctx, scope, value)))[0]);
    });
  }
  async function listSuppressions(ctx: ServiceContext, query: { includeLifted?: boolean; limit?: number } = {}): Promise<View[]> {
    requireCapability(ctx, 'correspondence:read');
    return views(await sql.query(`select s.* from ${S}.suppressions s where ${P('s')} and ($4 or s.lifted_at is null) order by s.created_at desc limit ${page(query, 200, 1000)}`, sc(ctx, query.includeLifted === true)));
  }
  async function liftSuppression(ctx: ServiceContext, suppressionId: string, input: { reason: string }): Promise<View> {
    requireCapability(ctx, 'correspondence:admin'); requireHuman(ctx, 'Lifting a suppression');
    return sql.tx(async (tx) => {
      const rows = await tx.query(`update ${S}.suppressions s set lifted_at=$5, lifted_by=$6, lift_reason=$7 where ${P('s')} and s.id=$4 and s.lifted_at is null returning *`, sc(ctx, id(suppressionId), ctx.now, ctx.actor.id, line(input.reason, 'reason', 500)));
      const row = rows[0] ?? notFound();
      await record(tx, ctx, 'suppression.lifted', ref('suppression', row.id as string), { reason: input.reason }, { type: 'suppression.lifted' });
      return view(row);
    });
  }

  // ───────────── Labels ─────────────
  async function createLabel(ctx: ServiceContext, input: { name: string; color?: string; idempotencyKey?: string }): Promise<View> {
    return command(core, ctx, 'correspondence:write', input.idempotencyKey, input, async (tx) => {
      const rows = await tx.query(`insert into ${S}.labels (tenant_id, project_id, id, name, color, created_by, created_at) values ($1,$2,$3,$4,$5,$6,$7) on conflict do nothing returning *`,
        [ctx.tenantId, ctx.projectId, randomUUID(), line(input.name, 'name', 80), input.color === undefined ? '' : line(input.color, 'color', 30), ctx.actor.id, ctx.now]);
      invariant(rows[0] !== undefined, 'conflict', 'A label with this name already exists');
      await record(tx, ctx, 'label.created', ref('label', rows[0].id as string), {});
      return view(rows[0]);
    });
  }
  async function listLabels(ctx: ServiceContext): Promise<View[]> {
    requireCapability(ctx, 'correspondence:read');
    return views(await sql.query(`select l.* from ${S}.labels l where ${P('l')} order by l.name`, sc(ctx)));
  }
  async function updateLabel(ctx: ServiceContext, labelId: string, input: { name?: string; color?: string }): Promise<View> {
    requireCapability(ctx, 'correspondence:write');
    return sql.tx(async (tx) => {
      const taken = input.name === undefined ? [] : await tx.query(`select 1 from ${S}.labels l where ${P('l')} and l.name=$4 and l.id<>$5`, sc(ctx, input.name, id(labelId)));
      invariant(taken.length === 0, 'conflict', 'A label with this name already exists');
      const rows = await tx.query(`update ${S}.labels l set name=coalesce($5, name), color=coalesce($6, color) where ${P('l')} and l.id=$4 returning *`,
        sc(ctx, id(labelId), input.name === undefined ? null : line(input.name, 'name', 80), input.color === undefined ? null : input.color === '' ? '' : line(input.color, 'color', 30)));
      await record(tx, ctx, 'label.updated', ref('label', (rows[0] ?? notFound()).id as string), {});
      return view(rows[0]);
    });
  }
  async function deleteLabel(ctx: ServiceContext, labelId: string): Promise<{ deleted: true }> {
    requireCapability(ctx, 'correspondence:write');
    return sql.tx(async (tx) => {
      const rows = await tx.query(`delete from ${S}.labels l where ${P('l')} and l.id=$4 returning id`, sc(ctx, id(labelId)));
      if (rows[0] === undefined) notFound();
      await tx.query(`delete from ${S}.thread_labels where tenant_id=$1 and project_id=$2 and label_id=$3`, [ctx.tenantId, ctx.projectId, labelId]);
      await record(tx, ctx, 'label.deleted', ref('label', labelId), {});
      return { deleted: true as const };
    });
  }

  // ───────────── Threads and messages ─────────────
  type ThreadQuery = { mailboxId?: string; folder?: Folder; labelId?: string; assignee?: string; unread?: boolean; questionRef?: string; contactId?: string; q?: string; limit?: number; cursor?: string };
  function threadFilter(ctx: ServiceContext, query: ThreadQuery): { where: string; params: unknown[] } {
    const folder = query.folder ?? 'inbox';
    invariant(FOLDERS.includes(folder), 'invalid_input', 'Unknown folder');
    const params = sc(ctx, query.mailboxId === undefined ? null : id(query.mailboxId), query.labelId === undefined ? null : id(query.labelId), query.assignee ?? null, query.unread ?? null,
      query.questionRef ?? null, query.contactId === undefined ? null : id(query.contactId), query.q === undefined || query.q.trim() === '' ? null : query.q.slice(0, 300));
    const where = `${W('t')} and ${FOLDER_SQL[folder]} and ($4::uuid is null or t.mailbox_id=$4)
      and ($5::uuid is null or exists (select 1 from ${S}.thread_labels l where l.thread_id=t.id and l.label_id=$5))
      and ($6::text is null or t.assignee=$6)
      and ($7::boolean is null or $7 = exists (select 1 from ${S}.messages m where m.thread_id=t.id and m.direction='inbound' and not m.is_read))
      and ($8::text is null or t.question_ref=$8) and ($9::uuid is null or t.contact_id=$9)
      and ($10::text is null or exists (select 1 from ${S}.messages m where m.thread_id=t.id and m.state<>'discarded' and m.search @@ websearch_to_tsquery('simple', $10)))`;
    return { where, params };
  }
  async function listThreads(ctx: ServiceContext, query: ThreadQuery = {}): Promise<Page<View>> {
    requireCapability(ctx, 'correspondence:read');
    const limit = page(query); const cur = decodeCursor(query.cursor, 2);
    const { where, params } = threadFilter(ctx, query);
    const rows = await sql.query(`${THREAD_SELECT} where ${where} and ($11::timestamptz is null or (t.last_message_at, t.id) < ($11::timestamptz, $12::uuid)) order by t.last_message_at desc, t.id desc limit ${limit + 1}`, [...params, cur?.[0] ?? null, cur?.[1] ?? null]);
    const total = (await sql.query<{ n: number }>(`select count(*)::int as n from ${S}.threads t where ${where}`, params))[0]?.n ?? 0;
    const items = rows.slice(0, limit); const last = items[items.length - 1];
    return { items: items.map(threadView), nextCursor: rows.length > limit && last !== undefined ? encodeCursor([(last.last_message_at as Date).toISOString(), last.id as string]) : null, total };
  }
  /** Totals and unread totals per folder and per label, for the navigation pane. */
  async function counts(ctx: ServiceContext, query: { mailboxId?: string } = {}): Promise<{ folders: Record<string, { total: number; unread: number }>; labels: View[] }> {
    requireCapability(ctx, 'correspondence:read');
    const mailbox = query.mailboxId === undefined ? null : id(query.mailboxId);
    const unread = `exists (select 1 from ${S}.messages m where m.thread_id=t.id and m.direction='inbound' and not m.is_read)`;
    const row = (await sql.query(`select ${FOLDERS.map((f) => `count(*) filter (where ${FOLDER_SQL[f]})::int as ${f}_total, count(*) filter (where ${FOLDER_SQL[f]} and ${unread})::int as ${f}_unread`).join(', ')}
      from ${S}.threads t where ${W('t')} and ($4::uuid is null or t.mailbox_id=$4)`, sc(ctx, mailbox)))[0] ?? {};
    const folders: Record<string, { total: number; unread: number }> = {};
    for (const f of FOLDERS) folders[f] = { total: Number(row[`${f}_total`] ?? 0), unread: Number(row[`${f}_unread`] ?? 0) };
    const labels = views(await sql.query(`select l.id, l.name, l.color,
      (select count(*)::int from ${S}.thread_labels tl join ${S}.threads t on t.id=tl.thread_id where tl.label_id=l.id and ${W('t')} and not t.trashed and ($4::uuid is null or t.mailbox_id=$4)) as total,
      (select count(*)::int from ${S}.thread_labels tl join ${S}.threads t on t.id=tl.thread_id where tl.label_id=l.id and ${W('t')} and not t.trashed and ($4::uuid is null or t.mailbox_id=$4) and ${unread}) as unread
      from ${S}.labels l where ${P('l')} order by l.name`, sc(ctx, mailbox)));
    return { folders, labels };
  }
  async function getThread(ctx: ServiceContext, threadId: string, options: { markRead?: boolean } = {}): Promise<View> {
    requireCapability(ctx, 'correspondence:read');
    const params = sc(ctx, id(threadId));
    if (options.markRead === true) { requireCapability(ctx, 'correspondence:write'); await sql.query(`update ${S}.messages m set is_read=true where ${W('m')} and m.thread_id=$4 and not m.is_read`, params); }
    const thread = threadView((await sql.query(`${THREAD_SELECT} where ${W('t')} and t.id=$4`, params))[0]);
    const attachments = views(await sql.query(`select a.id, a.message_id, a.filename, a.media_type, a.size, a.sha256, a.content_id, a.evidence_ref, a.created_at from ${S}.attachments a where ${W('a')} and a.thread_id=$4 and not a.removed order by a.created_at`, params));
    thread.messages = (await sql.query(`select ${MESSAGE_COLS} from ${S}.messages m where ${W('m')} and m.thread_id=$4 and m.state<>'discarded' order by coalesce(m.received_at, m.sent_at, m.created_at), m.created_at`, params)).map((r) => {
      const m = messageView(r); m.attachments = attachments.filter((a) => a.messageId === m.id); return m;
    });
    thread.dispatches = views(await sql.query(`select d.* from ${S}.dispatches d where ${W('d')} and d.thread_id=$4 order by d.created_at`, params)).map(dispatchView);
    thread.assertions = views(await sql.query(`select a.* from ${S}.assertions a where ${W('a')} and a.thread_id=$4 order by a.created_at`, params));
    thread.labels = views(await sql.query(`select l.id, l.name, l.color from ${S}.labels l join ${S}.thread_labels tl on tl.label_id=l.id where ${P('l')} and tl.thread_id=$4 order by l.name`, params));
    thread.contact = thread.contactId === null ? null : contactView((await sql.query(`select c.* from ${S}.contacts c where ${W('c')} and c.id=$4`, sc(ctx, thread.contactId)))[0] ?? notFound());
    return thread;
  }
  type Modify = { threadIds: string[]; addLabelIds?: string[]; removeLabelIds?: string[]; archived?: boolean; trashed?: boolean; spam?: boolean; starred?: boolean; read?: boolean; assignee?: string | null; idempotencyKey?: string };
  /** Bulk action over threads. Threads outside the caller's scope are silently not matched; `updated` lists what changed. */
  async function modifyThreads(ctx: ServiceContext, input: Modify): Promise<{ updated: string[] }> {
    return command(core, ctx, 'correspondence:write', input.idempotencyKey, input, async (tx) => {
      invariant(Array.isArray(input.threadIds) && input.threadIds.length >= 1 && input.threadIds.length <= 500, 'invalid_input', 'Give 1 to 500 thread ids');
      const ids = [...new Set(input.threadIds.map(id))];
      for (const f of ['archived', 'trashed', 'spam', 'starred', 'read'] as const) invariant(input[f] === undefined || typeof input[f] === 'boolean', 'invalid_input', `${f} must be boolean`);
      const assignee = input.assignee === undefined || input.assignee === null ? null : line(input.assignee, 'assignee', 200);
      const rows = await tx.query<{ id: string }>(`update ${S}.threads t set archived=coalesce($5, archived), trashed=coalesce($6, trashed), spam=coalesce($7, spam), starred=coalesce($8, starred),
        assignee=case when $9 then $10 else assignee end, updated_at=$11 where ${W('t')} and t.id = any($4::uuid[]) returning t.id`,
        sc(ctx, ids, input.archived ?? null, input.trashed ?? null, input.spam ?? null, input.starred ?? null, input.assignee !== undefined, assignee, ctx.now));
      const updated = rows.map((r) => r.id);
      if (input.read !== undefined) await tx.query(`update ${S}.messages m set is_read=$5 where ${T('m')} and m.thread_id = any($4::uuid[]) and m.direction='inbound'`, sc(ctx, updated, input.read));
      const labels = async (list: string[] | undefined): Promise<string[]> => {
        if (list === undefined || list.length === 0) return [];
        const found = await tx.query<{ id: string }>(`select l.id from ${S}.labels l where ${P('l')} and l.id = any($4::uuid[])`, sc(ctx, list.map(id)));
        invariant(found.length === new Set(list).size, 'not_found', 'Not found');
        return found.map((r) => r.id);
      };
      const add = await labels(input.addLabelIds); const remove = await labels(input.removeLabelIds);
      if (add.length > 0) await tx.query(`insert into ${S}.thread_labels (tenant_id, project_id, thread_id, label_id) select $1, $2, t, l from unnest($3::uuid[]) t, unnest($4::uuid[]) l on conflict do nothing`, [ctx.tenantId, ctx.projectId, updated, add]);
      if (remove.length > 0) await tx.query(`delete from ${S}.thread_labels where tenant_id=$1 and project_id=$2 and thread_id = any($3::uuid[]) and label_id = any($4::uuid[])`, [ctx.tenantId, ctx.projectId, updated, remove]);
      const { threadIds: _ids, idempotencyKey: _key, ...change } = input;
      for (const t of updated) await record(tx, ctx, 'conversation.modified', ref('conversation', t), change as Json, input.assignee !== undefined ? { type: 'conversation.assigned', payload: { assignee } } : undefined);
      return { updated };
    });
  }
  /** Full-text search over message subject, body and participants (PostgreSQL tsvector, `simple` configuration). */
  async function searchMessages(ctx: ServiceContext, query: { q: string; mailboxId?: string; limit?: number; cursor?: string }): Promise<Page<View>> {
    requireCapability(ctx, 'correspondence:read');
    if (typeof query.q !== 'string' || query.q.trim() === '') return { items: [], nextCursor: null, total: 0 };
    const limit = page(query); const offset = Number(decodeCursor(query.cursor, 1)?.[0] ?? 0);
    const where = `${W('m')} and m.state<>'discarded' and m.search @@ websearch_to_tsquery('simple', $4) and ($5::uuid is null or m.mailbox_id=$5)`;
    const params = sc(ctx, query.q.slice(0, 300), query.mailboxId === undefined ? null : id(query.mailboxId));
    const rows = await sql.query(`select ${MESSAGE_COLS}, ts_rank(m.search, websearch_to_tsquery('simple', $4)) as rank,
      ts_headline('simple', m.body_text, websearch_to_tsquery('simple', $4), 'MaxFragments=1, MaxWords=24, MinWords=8, StartSel=[[, StopSel=]]') as headline
      from ${S}.messages m where ${where} order by rank desc, m.created_at desc, m.id limit ${limit + 1} offset ${Number.isInteger(offset) && offset > 0 ? offset : 0}`, params);
    const total = (await sql.query<{ n: number }>(`select count(*)::int as n from ${S}.messages m where ${where}`, params))[0]?.n ?? 0;
    return { items: rows.slice(0, limit).map(messageView), nextCursor: rows.length > limit ? encodeCursor([String(offset + limit)]) : null, total };
  }
  async function getMessage(ctx: ServiceContext, messageId: string): Promise<View> {
    requireCapability(ctx, 'correspondence:read');
    const row = (await sql.query(`select ${MESSAGE_COLS}, m.body_html as untrusted_html from ${S}.messages m where ${W('m')} and m.id=$4`, sc(ctx, id(messageId))))[0] ?? notFound();
    const v = messageView(row);
    v.attachments = views(await sql.query(`select a.id, a.message_id, a.filename, a.media_type, a.size, a.sha256, a.content_id, a.evidence_ref, a.created_at from ${S}.attachments a where ${W('a')} and a.message_id=$4 and not a.removed order by a.created_at`, sc(ctx, row.id)));
    v.versions = views(await sql.query(`select v.revision, v.actor_id, v.at, v.snapshot from ${S}.message_versions v where ${P('v')} and v.message_id=$4 order by v.revision`, sc(ctx, row.id)));
    return v;
  }
  /** Original RFC822 bytes exactly as received (inbound) or as handed to the provider (outbound). */
  async function getRawMessage(ctx: ServiceContext, messageId: string): Promise<{ bytes: Uint8Array; sha256: string; filename: string }> {
    requireCapability(ctx, 'correspondence:read');
    const row = (await sql.query<{ id: string; raw_key: string | null; raw_sha256: string }>(`select m.id, m.raw_key, m.raw_sha256 from ${S}.messages m where ${W('m')} and m.id=$4`, sc(ctx, id(messageId))))[0] ?? notFound();
    if (row.raw_key === null) return notFound();
    const bytes = await objects(core).get(row.raw_key);
    invariant(hashBytes(bytes) === row.raw_sha256, 'unavailable', 'Stored message bytes do not match their recorded digest');
    return { bytes, sha256: row.raw_sha256, filename: `${row.id}.eml` };
  }

  // ───────────── Drafts ─────────────
  type DraftInput = { mailboxId?: string; threadId?: string; replyToMessageId?: string; contactId?: string; planId?: string; questionRef?: string; to?: string[]; cc?: string[]; subject?: string; body?: string; structured?: Json; compartment?: string };
  type Content = { subject: string; body: string; structured: StructuredInquiry | null; flags: string[] };
  /** Agents may only submit structured inquiries; the server renders them and screens for identity claims. */
  function content(ctx: ServiceContext, profile: SenderProfile, input: { subject?: string | undefined; body?: string | undefined; structured?: Json | undefined }, fallbackSubject: string): Content {
    const human = ctx.actor.kind === 'human';
    if (input.structured !== undefined && input.structured !== null) {
      invariant(input.body === undefined, 'invalid_input', 'Give either structured content or a body, not both');
      const structured = validateStructured(input.structured);
      invariant(typeof profile.organizationName === 'string', 'invalid_state', 'The mailbox has no sender profile; a structured inquiry cannot be rendered');
      const rendered = renderStructured(structured, profile, core.rules);
      const flags = findIdentityClaims(`${rendered.subject}\n${rendered.body}`, profile, core.rules);
      invariant(human || flags.length === 0, 'invalid_identity_claim', `Automated messages may not claim an identity outside the sender profile (${flags.join(', ')})`);
      return { ...rendered, structured, flags };
    }
    invariant(human, 'invalid_input', 'Agents must provide structured content (purpose, 1-3 questions, optional context)');
    const subject = input.subject === undefined || input.subject === '' ? fallbackSubject : line(input.subject, 'subject', 300);
    const body = input.body === undefined ? '' : freeText(input.body, 'body', 100_000, true);
    return { subject, body, structured: null, flags: typeof profile.organizationName === 'string' ? findIdentityClaims(`${subject}\n${body}`, profile, core.rules) : [] };
  }
  async function snapshot(tx: Sql, ctx: ServiceContext, row: Row): Promise<void> {
    await tx.query(`insert into ${S}.message_versions (tenant_id, project_id, message_id, revision, snapshot, actor_id, at) values ($1,$2,$3,$4,$5::jsonb,$6,$7)`,
      [ctx.tenantId, ctx.projectId, row.id, row.revision, JSON.stringify({ to: row.to_addrs, cc: row.cc_addrs, subject: row.subject, body: row.body_text, structured: row.structured, origin: row.origin }), ctx.actor.id, ctx.now]);
  }
  async function createDraftTx(tx: Sql, ctx: ServiceContext, input: DraftInput): Promise<Row> {
    const human = ctx.actor.kind === 'human';
    let thread: Row | undefined, replyTo: Row | undefined, contact: Row | undefined, plan: Row | undefined;
    if (input.replyToMessageId !== undefined) {
      replyTo = (await tx.query(`select m.* from ${S}.messages m where ${W('m')} and m.id=$4 and m.state in ('received','sent','uncertain')`, sc(ctx, id(input.replyToMessageId))))[0] ?? notFound();
      invariant(input.threadId === undefined || input.threadId === replyTo.thread_id, 'invalid_input', 'replyToMessageId belongs to another thread');
    }
    const threadId = replyTo?.thread_id as string | undefined ?? input.threadId;
    if (threadId !== undefined) thread = (await tx.query(`select t.* from ${S}.threads t where ${W('t')} and t.id=$4 for update`, sc(ctx, id(threadId))))[0] ?? notFound();
    const contactId = input.contactId ?? (thread?.contact_id as string | null | undefined) ?? undefined;
    if (contactId !== undefined) contact = (await tx.query(`select c.* from ${S}.contacts c where ${W('c')} and c.id=$4`, sc(ctx, id(contactId))))[0] ?? notFound();
    if (input.planId !== undefined) plan = (await tx.query(`select p.* from ${S}.plans p where ${W('p')} and p.id=$4`, sc(ctx, id(input.planId))))[0] ?? notFound();
    const mailbox = await loadMailbox(tx, ctx, (thread?.mailbox_id as string | undefined) ?? input.mailboxId ?? notFound());
    invariant(thread === undefined || input.mailboxId === undefined || input.mailboxId === thread.mailbox_id, 'invalid_input', 'Thread belongs to another mailbox');
    // Recipients: agents can address only the contact on record; inbound text never supplies recipients for them.
    let to: string[];
    if (!human) {
      invariant(input.to === undefined && input.cc === undefined, 'invalid_input', 'Agents address a contact by contactId, not by free recipients');
      invariant(contact !== undefined, 'invalid_input', 'Agents must address a recorded contact (contactId or a thread with a contact)');
      to = [contact.address as string];
    } else to = input.to !== undefined ? addressList(input.to, core.cfg.maxRecipients, 'to') : replyTo !== undefined && replyTo.direction === 'inbound' ? [replyTo.from_addr as string] : replyTo !== undefined ? [...(replyTo.to_addrs as string[])] : contact !== undefined ? [contact.address as string] : [];
    const cc = human && input.cc !== undefined ? addressList(input.cc, core.cfg.maxRecipients, 'cc') : [];
    const base = (replyTo?.subject as string | undefined) ?? (thread?.subject as string | undefined) ?? '';
    const c = content(ctx, mailbox.sender_profile, input, base === '' ? '' : /^re:/i.test(base) ? base : `Re: ${base}`);
    const comp = thread !== undefined ? thread.compartment as string | null : compartment(ctx, input.compartment) ?? (contact?.compartment as string | null | undefined) ?? (plan?.compartment as string | null | undefined) ?? null;
    const questionRef = optionalUref(input.questionRef, 'questionRef') ?? (plan?.question_ref as string | undefined) ?? (thread?.question_ref as string | null | undefined) ?? null;
    if (thread === undefined) {
      const sources = [questionRef, contact?.route_source as string | null | undefined].filter((s): s is string => typeof s === 'string');
      thread = (await tx.query(`insert into ${S}.threads (tenant_id, project_id, id, mailbox_id, subject, question_ref, plan_id, contact_id, compartment, sources, last_message_at, created_by, created_at, updated_at)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$11,$11) returning *`, [ctx.tenantId, ctx.projectId, randomUUID(), mailbox.id, c.subject, questionRef, plan?.id ?? null, contact?.id ?? null, comp, sources, ctx.now, ctx.actor.id]))[0] as Row;
    }
    const refs = replyTo === undefined ? [] : [...new Set([...(replyTo.refs as string[]), replyTo.message_id_header as string | null].filter((r): r is string => typeof r === 'string'))].slice(-20);
    const row = (await tx.query(`insert into ${S}.messages (tenant_id, project_id, id, thread_id, mailbox_id, compartment, direction, state, origin, author_id, from_addr, from_name, to_addrs, cc_addrs, subject, body_text, structured, identity_flags,
      in_reply_to, refs, created_at, updated_at, search) values ($1,$2,$3,$4,$5,$6,'outbound','draft',$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16::jsonb,$17,$18,$19,$19, ${TSV('$13', '$14', `$9 || ' ' || array_to_string($11::text[], ' ')`)}) returning *`,
      [ctx.tenantId, ctx.projectId, randomUUID(), thread.id, mailbox.id, comp, human ? 'human' : 'agent', ctx.actor.id, mailbox.address, mailbox.display_name, to, cc, c.subject, c.body, c.structured === null ? null : JSON.stringify(c.structured), JSON.stringify(c.flags),
        (replyTo?.message_id_header as string | null | undefined) ?? null, refs, ctx.now]))[0] as Row;
    await snapshot(tx, ctx, row);
    if (plan !== undefined && contact !== undefined) await tx.query(`update ${S}.plan_candidates set state='drafted', thread_id=$3, updated_at=$4 where plan_id=$1 and contact_id=$2 and state='proposed'`, [plan.id, contact.id, thread.id, ctx.now]);
    await record(tx, ctx, 'message.drafted', ref('message', row.id as string, 1), { thread: thread.id as string, origin: row.origin as string, structured: c.structured !== null }, { type: 'message.drafted', payload: { thread: ref('conversation', thread.id as string), origin: row.origin as string } });
    return row;
  }
  async function createDraft(ctx: ServiceContext, input: DraftInput & { idempotencyKey?: string }): Promise<View> {
    return command(core, ctx, 'correspondence:write', input.idempotencyKey, input, async (tx) => messageView(await createDraftTx(tx, ctx, input)));
  }
  async function updateDraft(ctx: ServiceContext, messageId: string, input: { expectedRevision: number; to?: string[]; cc?: string[]; subject?: string; body?: string; structured?: Json; idempotencyKey?: string }): Promise<View> {
    return command(core, ctx, 'correspondence:write', input.idempotencyKey, { messageId, ...input }, async (tx) => {
      const row = (await tx.query(`select m.* from ${S}.messages m where ${W('m')} and m.id=$4 for update`, sc(ctx, id(messageId))))[0] ?? notFound();
      invariant(['draft', 'cancelled', 'failed'].includes(row.state as string), 'invalid_state', 'Only drafts can be edited');
      invariant(row.revision === input.expectedRevision, 'revision_conflict', 'The draft was changed by someone else');
      const human = ctx.actor.kind === 'human';
      invariant(human || (input.to === undefined && input.cc === undefined), 'invalid_input', 'Agents cannot change recipients');
      const mailbox = await loadMailbox(tx, ctx, row.mailbox_id as string);
      const changed = input.subject !== undefined || input.body !== undefined || input.structured !== undefined;
      const c = changed ? content(ctx, mailbox.sender_profile, input.structured !== undefined ? { structured: input.structured } : { subject: input.subject ?? row.subject as string, body: input.body ?? row.body_text as string }, row.subject as string)
        : { subject: row.subject as string, body: row.body_text as string, structured: row.structured as StructuredInquiry | null, flags: row.identity_flags as string[] };
      const to = input.to === undefined ? row.to_addrs as string[] : addressList(input.to, core.cfg.maxRecipients, 'to');
      const cc = input.cc === undefined ? row.cc_addrs as string[] : addressList(input.cc, core.cfg.maxRecipients, 'cc');
      const next = (await tx.query(`update ${S}.messages m set state='draft', to_addrs=$5, cc_addrs=$6, subject=$7, body_text=$8, structured=$9::jsonb, identity_flags=$10::jsonb, origin=$11, author_id=$12, revision=revision+1, updated_at=$13,
        search=${TSV('$7', '$8', `m.from_addr || ' ' || array_to_string($5::text[], ' ')`)} where ${T('m')} and m.id=$4 returning *`,
        sc(ctx, row.id, to, cc, c.subject, c.body, c.structured === null ? null : JSON.stringify(c.structured), JSON.stringify(c.flags), changed ? (human ? 'human' : 'agent') : row.origin, changed ? ctx.actor.id : row.author_id, ctx.now)))[0] as Row;
      await snapshot(tx, ctx, next);
      await record(tx, ctx, 'message.draft_updated', ref('message', row.id as string, next.revision as number), { revision: next.revision as number, by: ctx.actor.kind });
      return messageView(next);
    });
  }
  async function discardDraft(ctx: ServiceContext, messageId: string): Promise<View> {
    requireCapability(ctx, 'correspondence:write');
    return sql.tx(async (tx) => {
      const rows = await tx.query(`update ${S}.messages m set state='discarded', updated_at=$5 where ${W('m')} and m.id=$4 and m.state in ('draft','cancelled','failed') returning *`, sc(ctx, id(messageId), ctx.now));
      const row = rows[0] ?? (((await tx.query(`select 1 from ${S}.messages m where ${W('m')} and m.id=$4`, sc(ctx, messageId))).length === 0) ? notFound() : (() => { throw new DomainError('invalid_state', 'Only drafts can be discarded'); })());
      await record(tx, ctx, 'message.draft_discarded', ref('message', row.id as string), {});
      return messageView(row);
    });
  }

  // ───────────── Attachments ─────────────
  async function addAttachment(ctx: ServiceContext, messageId: string, input: { filename: string; mediaType: string; bytes: Uint8Array }): Promise<View> {
    requireCapability(ctx, 'correspondence:write');
    // Files are attached by people; automated inquiries are plain text.
    requireHuman(ctx, 'Attaching a file');
    invariant(input.bytes instanceof Uint8Array && input.bytes.byteLength > 0 && input.bytes.byteLength <= core.cfg.maxAttachmentBytes, 'payload_too_large', `Attachments are limited to ${core.cfg.maxAttachmentBytes} bytes`);
    const filename = line(input.filename, 'filename', 180).replace(/[\\/]/g, '_');
    invariant(typeof input.mediaType === 'string' && /^[\w.+-]+\/[\w.+-]+$/.test(input.mediaType), 'invalid_input', 'Invalid media type');
    return sql.tx(async (tx) => {
      const msg = (await tx.query(`select m.* from ${S}.messages m where ${W('m')} and m.id=$4 for update`, sc(ctx, id(messageId))))[0] ?? notFound();
      invariant(msg.state === 'draft' && msg.direction === 'outbound', 'invalid_state', 'Attachments can be added to drafts only');
      const attachmentId = randomUUID(); const key = objectKey(ctx, 'attachments', attachmentId);
      const info = await objects(core).put(key, input.bytes);
      const row = (await tx.query(`insert into ${S}.attachments (tenant_id, project_id, id, message_id, thread_id, compartment, filename, media_type, size, sha256, object_key, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        returning id, message_id, filename, media_type, size, sha256, created_at`, [ctx.tenantId, ctx.projectId, attachmentId, msg.id, msg.thread_id, msg.compartment, filename, input.mediaType.toLowerCase(), info.size, info.sha256, key, ctx.now]))[0];
      await record(tx, ctx, 'attachment.added', ref('attachment', attachmentId), { message: msg.id as string, size: info.size, sha256: info.sha256 });
      return view(row);
    });
  }
  async function removeAttachment(ctx: ServiceContext, attachmentId: string): Promise<{ removed: true }> {
    requireCapability(ctx, 'correspondence:write');
    return sql.tx(async (tx) => {
      const rows = await tx.query(`update ${S}.attachments a set removed=true where ${W('a')} and a.id=$4 and not a.removed and exists (select 1 from ${S}.messages m where m.id=a.message_id and m.state='draft') returning a.id`, sc(ctx, id(attachmentId)));
      if (rows[0] === undefined) notFound();
      await record(tx, ctx, 'attachment.removed', ref('attachment', attachmentId), {});
      return { removed: true as const };
    });
  }
  async function getAttachment(ctx: ServiceContext, attachmentId: string): Promise<{ meta: View; bytes: Uint8Array }> {
    requireCapability(ctx, 'correspondence:read');
    const row = (await sql.query(`select a.* from ${S}.attachments a where ${W('a')} and a.id=$4 and not a.removed`, sc(ctx, id(attachmentId))))[0] ?? notFound();
    const bytes = await objects(core).get(row.object_key as string);
    invariant(hashBytes(bytes) === row.sha256, 'unavailable', 'Stored attachment bytes do not match their recorded digest');
    return { meta: view(row), bytes };
  }

  // ───────────── Outreach plans ─────────────
  type Candidate = { contactId?: string; contact?: ContactInput; rank?: number; rationale?: string };
  type PlanInput = { questionRef: string; question: string; context?: string; allowedDisclosure?: string; compartment?: string; candidates: Candidate[] };
  async function planView(tx: Sql, ctx: ServiceContext, row: Row | undefined): Promise<View> {
    const v = view(row); v.ref = ref('plan', String(v.id));
    v.candidates = (await tx.query(`select pc.contact_id, pc.rank, pc.rationale, pc.state, pc.thread_id, c.address, c.display_name, c.organization, c.why_may_know, c.route_source, c.state as contact_state, c.blocked as contact_blocked
      from ${S}.plan_candidates pc join ${S}.contacts c on c.id=pc.contact_id where pc.plan_id=$4 and ${W('c')} order by pc.rank, c.address`, sc(ctx, v.id))).map((r) => view(r));
    return v;
  }
  async function createPlanTx(tx: Sql, ctx: ServiceContext, input: PlanInput): Promise<Row> {
    const questionRef = optionalUref(input.questionRef, 'questionRef') ?? (() => { throw new DomainError('invalid_reference', 'questionRef is required'); })();
    invariant(Array.isArray(input.candidates) && input.candidates.length <= 50, 'invalid_input', 'A plan lists at most 50 candidates');
    const comp = compartment(ctx, input.compartment);
    const planId = randomUUID(); const sources = new Set([questionRef]);
    const resolved: { contact: Row; rank: number; rationale: string }[] = [];
    for (const [i, cand] of input.candidates.entries()) {
      const contact = cand.contactId !== undefined ? (await tx.query(`select c.* from ${S}.contacts c where ${W('c')} and c.id=$4`, sc(ctx, id(cand.contactId))))[0] ?? notFound()
        : await upsertContactTx(tx, ctx, { ...(cand.contact ?? (() => { throw new DomainError('invalid_input', 'Each candidate needs contactId or contact'); })()), ...(comp === null ? {} : { compartment: comp }) });
      if (typeof contact.route_source === 'string') sources.add(contact.route_source);
      if (resolved.some((r) => r.contact.id === contact.id)) continue;
      resolved.push({ contact, rank: cand.rank === undefined ? i + 1 : int(cand.rank, 'rank', 1, 1000), rationale: cand.rationale === undefined ? contact.why_may_know as string : freeText(cand.rationale, 'rationale', 1000) });
    }
    const row = (await tx.query(`insert into ${S}.plans (tenant_id, project_id, id, question_ref, question, context, allowed_disclosure, compartment, sources, created_by, created_at, updated_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11) returning *`,
      [ctx.tenantId, ctx.projectId, planId, questionRef, freeText(input.question, 'question', 2000), input.context === undefined ? '' : freeText(input.context, 'context', 4000, true),
        input.allowedDisclosure === undefined ? '' : freeText(input.allowedDisclosure, 'allowedDisclosure', 2000, true), comp, [...sources], ctx.actor.id, ctx.now]))[0] as Row;
    for (const r of resolved) await tx.query(`insert into ${S}.plan_candidates (tenant_id, project_id, plan_id, contact_id, rank, rationale, updated_at) values ($1,$2,$3,$4,$5,$6,$7)`, [ctx.tenantId, ctx.projectId, planId, r.contact.id, r.rank, r.rationale, ctx.now]);
    await record(tx, ctx, 'outreach.plan.created', ref('plan', planId), { questionRef, candidates: resolved.length }, { type: 'outreach.plan.created', payload: { questionRef, candidates: resolved.map((r) => ref('contact', r.contact.id as string)) } });
    return row;
  }
  /** Turns an unresolved question into a ranked list of people who may know, each with route provenance. */
  async function createOutreachPlan(ctx: ServiceContext, input: PlanInput & { idempotencyKey?: string }): Promise<View> {
    return command(core, ctx, 'correspondence:contact', input.idempotencyKey, input, async (tx) => planView(tx, ctx, await createPlanTx(tx, ctx, input)));
  }
  async function getPlan(ctx: ServiceContext, planId: string): Promise<View> {
    requireCapability(ctx, 'correspondence:read');
    return planView(sql, ctx, (await sql.query(`select p.* from ${S}.plans p where ${W('p')} and p.id=$4`, sc(ctx, id(planId))))[0]);
  }
  async function listPlans(ctx: ServiceContext, query: { questionRef?: string; limit?: number } = {}): Promise<View[]> {
    requireCapability(ctx, 'correspondence:read');
    const rows = await sql.query(`select p.* from ${S}.plans p where ${W('p')} and ($4::text is null or p.question_ref=$4) order by p.created_at desc limit ${page(query)}`, sc(ctx, query.questionRef ?? null));
    return Promise.all(rows.map((r) => planView(sql, ctx, r)));
  }
  type InquiryInput = { planId: string; contactId: string; mailboxId: string; structured?: Json; subject?: string; body?: string };
  /** Drafts a truthful, concise inquiry to one plan candidate. Nothing is sent. */
  async function draftInquiry(ctx: ServiceContext, input: InquiryInput & { idempotencyKey?: string }): Promise<View> {
    return command(core, ctx, 'correspondence:contact', input.idempotencyKey, input, async (tx) => {
      requireCapability(ctx, 'correspondence:write');
      const cand = (await tx.query(`select pc.thread_id from ${S}.plan_candidates pc join ${S}.plans p on p.id=pc.plan_id where ${W('p')} and pc.plan_id=$4 and pc.contact_id=$5`, sc(ctx, id(input.planId), id(input.contactId))))[0] ?? notFound();
      invariant(cand.thread_id === null, 'conflict', 'An inquiry to this candidate already exists for the plan');
      return messageView(await createDraftTx(tx, ctx, { mailboxId: input.mailboxId, planId: input.planId, contactId: input.contactId,
        ...(input.structured === undefined ? {} : { structured: input.structured }), ...(input.subject === undefined ? {} : { subject: input.subject }), ...(input.body === undefined ? {} : { body: input.body }) }));
    });
  }
  /** One call for an orchestrator: contact plan for a question plus (optionally) a drafted inquiry per candidate. */
  async function planOutreach(ctx: ServiceContext, input: PlanInput & { mailboxId?: string; inquiry?: Json; idempotencyKey?: string }): Promise<{ plan: View; drafts: View[] }> {
    return command(core, ctx, 'correspondence:contact', input.idempotencyKey, input, async (tx) => {
      const { mailboxId, inquiry, idempotencyKey: _k, ...planInput } = input;
      const plan = await planView(tx, ctx, await createPlanTx(tx, ctx, planInput));
      const drafts: View[] = [];
      if (inquiry !== undefined) {
        requireCapability(ctx, 'correspondence:write');
        invariant(mailboxId !== undefined, 'invalid_input', 'mailboxId is required to draft inquiries');
        for (const cand of plan.candidates as View[]) drafts.push(messageView(await createDraftTx(tx, ctx, { mailboxId, planId: plan.id as string, contactId: cand.contactId as string, structured: inquiry })));
      }
      return { plan: drafts.length === 0 ? plan : await planView(tx, ctx, (await tx.query(`select p.* from ${S}.plans p where ${T('p')} and p.id=$4`, sc(ctx, plan.id)))[0]), drafts };
    }) as Promise<{ plan: View; drafts: View[] }>;
  }
  /** Everything known about outreach for one question: plans, conversations, replies and attributed assertions. */
  async function questionStatus(ctx: ServiceContext, questionRef: string): Promise<View> {
    requireCapability(ctx, 'correspondence:read');
    const q = optionalUref(questionRef, 'questionRef') ?? notFound();
    const threads = (await sql.query(`${THREAD_SELECT} where ${W('t')} and t.question_ref=$4 order by t.last_message_at desc limit 200`, sc(ctx, q))).map(threadView);
    const replies = (await sql.query(`select ${MESSAGE_COLS} from ${S}.messages m join ${S}.threads t on t.id=m.thread_id where ${W('m')} and t.question_ref=$4 and m.direction='inbound' order by m.received_at desc limit 200`, sc(ctx, q))).map(messageView);
    const assertions = views(await sql.query(`select a.* from ${S}.assertions a where ${W('a')} and a.question_ref=$4 order by a.created_at limit 500`, sc(ctx, q)));
    const state = threads.length === 0 ? 'not_contacted' : replies.some((r) => r.classification === 'reply') ? 'answered_unverified' : threads.every((t) => t.refused === true) ? 'refused'
      : threads.some((t) => Number(t.inTransitCount) > 0 || Number(t.queuedCount) > 0) ? 'awaiting_response' : 'drafted';
    return { questionRef: q, state, plans: await listPlans(ctx, { questionRef: q }), conversations: threads, replies, assertions };
  }

  // ───────────── Sending grants ─────────────
  type GrantInput = { granteeId: string; mailboxId: string; purpose: string; questionRefs?: string[]; recipientAllowlist?: string[]; domainAllowlist?: string[]; maxMessages: number; perRecipientCap?: number; cooldownSeconds?: number; followUpLimit?: number; expiresAt: string };
  const grantView = (row: Row | undefined): View => { const v = view(row); v.ref = ref('grant', String(v.id)); v.remaining = Math.max(0, Number(v.maxMessages) - Number(v.usedMessages)); return v; };
  /** An explicit, bounded authority for one agent to send from one mailbox. Only a human can give it. */
  async function createGrant(ctx: ServiceContext, input: GrantInput & { idempotencyKey?: string }): Promise<View> {
    return command(core, ctx, 'correspondence:grant', input.idempotencyKey, input, async (tx) => {
      requireHuman(ctx, 'Granting sending authority');
      const mailbox = await loadMailbox(tx, ctx, input.mailboxId);
      const allow = input.recipientAllowlist === undefined ? [] : addressList(input.recipientAllowlist, 500, 'recipientAllowlist');
      const domains = (input.domainAllowlist ?? []).map((d) => address(`x@${d}`).slice(2));
      invariant(allow.length + domains.length > 0, 'invalid_input', 'A grant must bound its recipients (recipientAllowlist or domainAllowlist)');
      const expires = time(input.expiresAt, 'expiresAt');
      invariant(expires.getTime() > Date.parse(ctx.now) && expires.getTime() <= Date.parse(ctx.now) + 366 * 86_400_000, 'invalid_input', 'expiresAt must be in the future and within one year');
      const questions = (input.questionRefs ?? []).map((q) => optionalUref(q, 'questionRefs') as string);
      const row = (await tx.query(`insert into ${S}.grants (tenant_id, project_id, id, grantee_id, mailbox_id, purpose, question_refs, recipient_allowlist, domain_allowlist, max_messages, per_recipient_cap, cooldown_seconds, follow_up_limit, expires_at, granted_by, granted_at)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) returning *`, [ctx.tenantId, ctx.projectId, randomUUID(), line(input.granteeId, 'granteeId', 200), mailbox.id, line(input.purpose, 'purpose', 500), questions, allow, domains,
        int(input.maxMessages, 'maxMessages', 1, 10_000), int(input.perRecipientCap ?? 1, 'perRecipientCap', 1, 100), int(input.cooldownSeconds ?? 86_400, 'cooldownSeconds', 0, 366 * 86_400),
        int(input.followUpLimit ?? 0, 'followUpLimit', 0, core.cfg.maxFollowUps), expires.toISOString(), ctx.actor.id, ctx.now]))[0] as Row;
      await record(tx, ctx, 'grant.created', ref('grant', row.id as string), { grantee: row.grantee_id as string, mailbox: mailbox.id, maxMessages: row.max_messages as number, expiresAt: expires.toISOString() }, { type: 'grant.created', payload: { grantee: row.grantee_id as string, mailbox: ref('mailbox', mailbox.id) } });
      return grantView(row);
    });
  }
  async function listGrants(ctx: ServiceContext, query: { granteeId?: string; mailboxId?: string; state?: string } = {}): Promise<View[]> {
    requireCapability(ctx, 'correspondence:read');
    return (await sql.query(`select g.*, (g.state='active' and g.expires_at > now() and g.used_messages < g.max_messages) as usable from ${S}.grants g where ${P('g')} and ($4::text is null or g.grantee_id=$4) and ($5::uuid is null or g.mailbox_id=$5) and ($6::text is null or g.state=$6) order by g.granted_at desc limit 500`,
      sc(ctx, query.granteeId ?? null, query.mailboxId === undefined ? null : id(query.mailboxId), query.state ?? null))).map(grantView);
  }
  async function getGrant(ctx: ServiceContext, grantId: string): Promise<View> {
    requireCapability(ctx, 'correspondence:read');
    return grantView((await sql.query(`select g.*, (g.state='active' and g.expires_at > now() and g.used_messages < g.max_messages) as usable from ${S}.grants g where ${P('g')} and g.id=$4`, sc(ctx, id(grantId))))[0]);
  }
  /** Revocation takes effect at once: queued dispatches under the grant are cancelled; accepted mail stays in transit. */
  async function revokeGrant(ctx: ServiceContext, grantId: string, input: { reason: string }): Promise<View> {
    requireCapability(ctx, 'correspondence:grant'); requireHuman(ctx, 'Revoking sending authority');
    return sql.tx(async (tx) => {
      const prior = (await tx.query(`select g.* from ${S}.grants g where ${P('g')} and g.id=$4 for update`, sc(ctx, id(grantId))))[0] ?? notFound();
      if (prior.state === 'revoked') return grantView(prior);
      const row = (await tx.query(`update ${S}.grants g set state='revoked', revoked_by=$5, revoked_at=$6, revoke_reason=$7 where ${P('g')} and g.id=$4 returning *`, sc(ctx, prior.id, ctx.actor.id, ctx.now, line(input.reason, 'reason', 500))))[0] as Row;
      const cancelled = await tx.query<{ id: string; message_id: string; job_id: string | null }>(`update ${S}.dispatches d set state='cancelled', state_reason='grant_revoked', settled_at=$5, updated_at=$5 where ${T('d')} and d.grant_id=$4 and d.state='queued' returning d.id, d.message_id, d.job_id`, sc(ctx, prior.id, ctx.now));
      await releaseCancelled(tx, ctx, cancelled, 'grant_revoked');
      await record(tx, ctx, 'grant.revoked', ref('grant', row.id as string), { reason: input.reason, cancelledDispatches: cancelled.map((c) => c.id) }, { type: 'grant.revoked', payload: { cancelledDispatches: cancelled.map((c) => c.id) } });
      return grantView(row);
    });
  }

  // ───────────── Human takeover ─────────────
  type Target = { threadId?: string; mailboxId?: string; reason?: string };
  async function control(ctx: ServiceContext, target: Target, mode: 'human' | 'automation'): Promise<View> {
    requireCapability(ctx, 'correspondence:write'); requireHuman(ctx, mode === 'human' ? 'Taking over' : 'Resuming automation');
    invariant((target.threadId === undefined) !== (target.mailboxId === undefined), 'invalid_input', 'Give exactly one of threadId or mailboxId');
    const reason = target.reason === undefined ? '' : freeText(target.reason, 'reason', 500, true);
    return sql.tx(async (tx) => {
      const byThread = target.threadId !== undefined;
      const table = byThread ? 'threads' : 'mailboxes'; const scope = byThread ? W('x') : P('x'); const targetId = id(byThread ? target.threadId : target.mailboxId);
      const prior = (await tx.query(`select x.id, x.control_mode, x.control_epoch from ${S}.${table} x where ${scope} and x.id=$4 for update`, sc(ctx, targetId)))[0] ?? notFound();
      // The epoch moves on every change of hands; a dispatch queued under an older epoch can never be sent.
      const row = prior.control_mode === mode ? prior : (await tx.query(`update ${S}.${table} x set control_mode=$5, control_epoch=control_epoch+1, control_reason=$6, control_by=$7, control_at=$8, updated_at=$8 where ${T('x')} and x.id=$4 returning x.id, x.control_mode, x.control_epoch`, sc(ctx, targetId, mode, reason, ctx.actor.id, ctx.now)))[0] as Row;
      const col = byThread ? 'thread_id' : 'mailbox_id';
      let cancelled: { id: string; message_id: string; job_id: string | null }[] = [];
      if (mode === 'human') {
        cancelled = await tx.query(`update ${S}.dispatches d set state='cancelled', state_reason='takeover', settled_at=$5, updated_at=$5 where ${T('d')} and d.${col}=$4 and d.mode='automated' and d.state='queued' returning d.id, d.message_id, d.job_id`, sc(ctx, targetId, ctx.now));
        await releaseCancelled(tx, ctx, cancelled, 'takeover');
      }
      // Already handed to a provider: cannot be recalled, so it stays visible as in transit.
      const inTransit = (await tx.query(`select d.* from ${S}.dispatches d where ${W('d')} and d.${col}=$4 and d.state in ('dispatching','accepted','uncertain') order by d.created_at`, sc(ctx, targetId))).map((r) => dispatchView(view(r)));
      const subject = ref(byThread ? 'conversation' : 'mailbox', targetId);
      const detail = { controlEpoch: row.control_epoch as number, reason, cancelledDispatches: cancelled.map((c) => c.id), inTransit: inTransit.map((d) => d.id) } as Json;
      if (prior.control_mode !== mode || cancelled.length > 0) await record(tx, ctx, mode === 'human' ? 'conversation.taken_over' : 'conversation.resumed', subject, detail, { type: mode === 'human' ? 'conversation.taken_over' : 'conversation.resumed', payload: detail });
      return { target: subject, controlMode: row.control_mode as string, controlEpoch: row.control_epoch as number, cancelledDispatches: cancelled.map((c) => c.id), inTransit };
    });
  }
  /** Immediate human takeover of a thread or a whole mailbox: fences every queued automated dispatch in one transaction. */
  const takeover = (ctx: ServiceContext, target: Target): Promise<View> => control(ctx, target, 'human');
  const resume = (ctx: ServiceContext, target: Target): Promise<View> => control(ctx, target, 'automation');

  // ───────────── Attributed assertions ─────────────
  async function listAssertions(ctx: ServiceContext, query: { messageId?: string; threadId?: string; questionRef?: string } = {}): Promise<View[]> {
    requireCapability(ctx, 'correspondence:read');
    return views(await sql.query(`select a.* from ${S}.assertions a where ${W('a')} and ($4::uuid is null or a.message_id=$4) and ($5::uuid is null or a.thread_id=$5) and ($6::text is null or a.question_ref=$6) order by a.created_at limit 1000`,
      sc(ctx, query.messageId === undefined ? null : id(query.messageId), query.threadId === undefined ? null : id(query.threadId), query.questionRef ?? null)));
  }
  /** Adds reviewer-selected quotes from a reply as attributed candidates. Each quote must occur verbatim in the message. */
  async function proposeAssertions(ctx: ServiceContext, messageId: string, input: { quotes: string[]; idempotencyKey?: string }): Promise<View[]> {
    return command(core, ctx, 'correspondence:write', input.idempotencyKey, { messageId, ...input }, async (tx) => {
      const msg = (await tx.query(`select m.*, t.question_ref, t.contact_id from ${S}.messages m join ${S}.threads t on t.id=m.thread_id where ${W('m')} and m.id=$4 and m.direction='inbound'`, sc(ctx, id(messageId))))[0] ?? notFound();
      invariant(Array.isArray(input.quotes) && input.quotes.length >= 1 && input.quotes.length <= 20, 'invalid_input', 'Give 1 to 20 quotes');
      const out: View[] = []; const candidates: Json[] = [];
      for (const q of input.quotes) {
        const quote = freeText(q, 'quote', 1200); const start = (msg.body_text as string).indexOf(quote);
        invariant(start >= 0, 'invalid_input', 'A quote must appear verbatim in the message');
        const row = (await tx.query(`insert into ${S}.assertions (tenant_id, project_id, id, message_id, thread_id, compartment, question_ref, quote, attributed_to, contact_id, extraction, proposed_by, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'proposed',$11,$12) returning *`,
          [ctx.tenantId, ctx.projectId, randomUUID(), msg.id, msg.thread_id, msg.compartment, msg.question_ref, quote, msg.from_addr, msg.contact_id, ctx.actor.id, ctx.now]))[0] as Row;
        out.push(view(row)); candidates.push({ ref: ref('assertion', row.id as string), text: quote.slice(0, 300), start, end: start + quote.length });
      }
      await record(tx, ctx, 'answer.proposed', ref('message', msg.id as string), { assertions: out.map((a) => a.id as string) }, { type: 'answer.proposed', payload: { questionRef: msg.question_ref as Json, source: ref('message', msg.id as string), attributedTo: msg.from_addr as string, status: 'attributed_unverified', candidates } });
      return out;
    });
  }
  /** Records where another engine is evaluating an assertion. The assertion itself stays attributed and unverified here. */
  async function linkAssertion(ctx: ServiceContext, assertionId: string, input: { verificationRef: string }): Promise<View> {
    requireCapability(ctx, 'correspondence:write');
    const rows = await sql.query(`update ${S}.assertions a set verification_ref=$5 where ${W('a')} and a.id=$4 returning *`, sc(ctx, id(assertionId), optionalUref(input.verificationRef, 'verificationRef') ?? notFound()));
    return view(rows[0]);
  }

  return { createMailbox, updateMailbox, setMailboxCredentials, setSenderProfile, verifySenderProfile, listMailboxes, getMailbox, testMailboxConnection,
    upsertContact, verifyContact, listContacts, getContact, addSuppression, listSuppressions, liftSuppression, createLabel, listLabels, updateLabel, deleteLabel,
    listThreads, counts, getThread, modifyThreads, searchMessages, getMessage, getRawMessage, createDraft, updateDraft, discardDraft, addAttachment, removeAttachment, getAttachment,
    createOutreachPlan, getPlan, listPlans, draftInquiry, planOutreach, questionStatus, createGrant, listGrants, getGrant, revokeGrant, takeover, resume, listAssertions, proposeAssertions, linkAssertion,
    internal: { addSuppressionTx, releaseCancelled, createDraftTx } };
}
/** Adds the honest reading of a dispatch state for a UI. */
export function dispatchView(v: View): View {
  const labels: Record<string, string> = {
    queued: 'Waiting to be sent', dispatching: 'Being handed to the provider', accepted: 'Accepted by the provider; in transit', delivered: 'Delivery evidence received',
    bounced: 'The provider reported a delivery failure', uncertain: 'Outcome unknown; being reconciled, not resent', not_sent: 'Confirmed not sent', failed: 'Not sent: the provider refused', cancelled: 'Cancelled before sending',
  };
  v.ref = ref('dispatch', String(v.id));
  v.inTransit = ['dispatching', 'accepted', 'uncertain'].includes(String(v.state));
  v.stateLabel = labels[String(v.state)] ?? String(v.state);
  return v;
}
