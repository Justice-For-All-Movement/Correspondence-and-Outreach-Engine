// Content erasure after preservation elsewhere ("seal on arrival"). A host that has preserved a message somewhere it trusts
// more (for example as an encrypted record in the evidence engine) asks this engine to forget the message's readable
// content, so that a later copy of this engine's database and object store yields only a tombstone.
//
// Removed: subject, body text and HTML, sender and recipient names and addresses (an inbound author id is the address), the original RFC822 bytes and every
// attachment's bytes (object store), attachment names, types and digests, derived text (search vector, assertion quotes,
// thread subject and snippet, draft snapshots) and readable text in this engine's own outbox event payloads and stored
// idempotent results that name the message.
// Kept: the row itself and its ids, direction, state, classification kind, dates (received/sent, declared Date header),
// Message-ID, In-Reply-To and References (threading, duplicate detection and reconciliation match on them), the dedupe key
// (so a provider re-delivering the message does not bring the plaintext back), provider ids, and the thread and contact
// links of conversations we started (a thread holding only erased mail drops its contact link, and contact history drops
// its pointer to the message). Suppressions are kept: an address that asked not to be contacted stays suppressed (delivery state).
// The audit trail is hash-chained and is not rewritten; it never held message content (ids, digests and counts only).
import { DomainError, invariant } from '../contracts.ts';
import type { Json } from '../contracts.ts';
import { parseUref, requireCapability } from '../service-kit.ts';
import type { Row, ServiceContext, Sql } from '../service-kit.ts';
import { freeText } from './mail.ts';
import { S, T, W, id, notFound, objects, record, ref, sc } from './core.ts';
import type { Core, View } from './core.ts';
import { MESSAGE_COLS, messageView } from './workspace.ts';

export const ERASE_CAPABILITY = 'correspondence:erase';
export const ERASED_ADDRESS = 'erased@sealed.invalid';
export const ERASED_SUBJECT = 'Content sealed and erased';
export const tombstoneText = (preservedAs: string): string => `Content sealed and erased; preserved as ${preservedAs}`;
const ERASABLE_OUTBOUND = ['sent', 'failed', 'cancelled'];

/** A universal reference to where the content now lives. It must name another engine: erasing in favour of itself is refused. */
function preservedRef(value: unknown): string {
  invariant(typeof value === 'string' && /^E\d\d:[a-z][a-z0-9_]*:[A-Za-z0-9._~-]+(?:@\d+)?$/.test(value) && value.length <= 300, 'invalid_reference', 'preservedAs must be a universal reference (for example E05:evidence_version:<id>@<revision>)');
  invariant(!value.startsWith('E03:'), 'invalid_reference', 'preservedAs must name where the content is preserved outside this engine');
  return value;
}

/** Replaces readable text in this engine's outbox payloads about the message (reply candidates, attributed sender). */
function scrubPayload(payload: Json, preservedAs: string): Json {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return payload;
  const out: { [k: string]: Json } = { ...payload };
  if (Array.isArray(out.candidates)) out.candidates = out.candidates.map((c) => (c !== null && typeof c === 'object' && !Array.isArray(c) ? { ...c, text: tombstoneText(preservedAs) } : c));
  if (typeof out.attributedTo === 'string') out.attributedTo = ERASED_ADDRESS;
  out.contentErased = true;
  return out;
}

export function erasure(core: Core) {
  const { sql } = core;

  /**
   * Erases the readable content of one message after it was preserved elsewhere. Requires the exact capability
   * `correspondence:erase` (a `correspondence:*` wildcard does not satisfy it) held by a person or a service.
   * Idempotent: erasing an erased message returns it unchanged.
   */
  async function eraseMessageContent(ctx: ServiceContext, messageId: string, input: { reason: string; preservedAs: string }): Promise<View> {
    requireCapability(ctx, ERASE_CAPABILITY);
    invariant(ctx.capabilities.includes(ERASE_CAPABILITY), 'forbidden', `Missing capability ${ERASE_CAPABILITY} (it must be granted exactly)`);
    invariant(ctx.actor.kind === 'human' || ctx.actor.kind === 'service', 'forbidden', 'Erasing message content requires a person or a service, not an agent');
    const reason = freeText(input?.reason, 'reason', 500).trim();
    const preservedAs = preservedRef(input?.preservedAs);
    const mid = id(messageId);

    const current = (await sql.query(`select ${MESSAGE_COLS} from ${S}.messages m where ${W('m')} and m.id=$4`, sc(ctx, mid)))[0] ?? notFound();
    if (current.content_erased_at !== null) return messageView(current);
    // Where a preservation can be checked, it is: an unknown or unavailable evidence reference refuses the erasure.
    let parsed: ReturnType<typeof parseUref>;
    try { parsed = parseUref(preservedAs); } catch { throw new DomainError('invalid_reference', 'preservedAs is not a valid universal reference'); }
    if (parsed.engine === 'E05' && core.ports.evidence !== undefined) {
      const info = await core.ports.evidence.describe(ctx, preservedAs).catch((error: unknown) => {
        if (error instanceof DomainError && ['not_found', 'forbidden', 'invalid_reference'].includes(error.code)) return null;
        throw new DomainError('unavailable', 'The evidence service could not confirm the preserved copy; nothing was erased');
      });
      invariant(info !== null && info.available, 'invalid_state', 'The preserved copy could not be confirmed in evidence storage; nothing was erased');
    }
    // Erasure is irreversible: confirm the actor may still do it immediately before the effect.
    if (core.ports.authorization !== undefined) {
      const decision = await core.ports.authorization.authorize(ctx, { capability: ERASE_CAPABILITY, resource: ref('message', mid) });
      invariant(decision.allowed, 'forbidden', 'Erasing message content is not authorized');
    }

    return sql.tx(async (tx) => {
      const msg = (await tx.query(`select m.* from ${S}.messages m where ${W('m')} and m.id=$4 for update`, sc(ctx, mid)))[0] ?? notFound();
      if (msg.content_erased_at !== null) return messageView((await tx.query(`select ${MESSAGE_COLS} from ${S}.messages m where ${T('m')} and m.id=$4`, sc(ctx, mid)))[0]);
      if (msg.direction === 'inbound') invariant(msg.state === 'received', 'invalid_state', 'Only received messages can be erased');
      else {
        invariant(ERASABLE_OUTBOUND.includes(msg.state as string), 'invalid_state', 'Drafts and messages still being sent cannot be erased');
        const active = await tx.query(`select 1 from ${S}.dispatches d where ${T('d')} and d.message_id=$4 and d.state in ('queued','dispatching','uncertain') limit 1`, sc(ctx, mid));
        invariant(active.length === 0, 'invalid_state', 'A send of this message is still pending or unreconciled');
      }
      const attachments = await tx.query<{ id: string; object_key: string }>(`select a.id, a.object_key from ${S}.attachments a where ${T('a')} and a.message_id=$4`, sc(ctx, mid));
      // Bytes first, inside the transaction: if the database update then fails, a retry finds the message unerased and
      // repeats everything (deletion is idempotent). A crash can never leave the bytes behind an "erased" row.
      const keys = [...(typeof msg.raw_key === 'string' && msg.raw_key !== '' ? [msg.raw_key] : []), ...attachments.map((a) => a.object_key).filter((k) => k !== '')];
      if (keys.length > 0) { const store = objects(core); for (const k of keys) await store.delete(k); }
      const tomb = tombstoneText(preservedAs);
      const detail = (msg.classification_detail ?? {}) as { [k: string]: Json };
      const keptDetail: { [k: string]: Json } = {};
      for (const k of ['rule', 'action', 'status', 'declaredDate'] as const) if (detail[k] !== undefined) keptDetail[k] = detail[k] as Json;
      const row = (await tx.query(`update ${S}.messages m set subject=$5, body_text=$6, body_html=null, from_addr=$7, from_name='', author_id=case when m.direction='inbound' then $7 else m.author_id end, to_addrs='{}', cc_addrs='{}', structured=null, disclosure=null,
        identity_flags='[]'::jsonb, raw_key=null, raw_sha256=null, raw_size=null, classification_detail=$8::jsonb, search=to_tsvector('simple', ''),
        content_erased_at=$9, content_erased_by=$10, content_erasure_reason=$11, preserved_as=$12, updated_at=$9 where ${T('m')} and m.id=$4 returning *`,
        sc(ctx, mid, ERASED_SUBJECT, tomb, ERASED_ADDRESS, JSON.stringify(keptDetail), ctx.now, ctx.actor.id, reason, preservedAs)))[0] as Row;
      await tx.query(`update ${S}.attachments a set filename='erased', media_type='application/octet-stream', size=0, sha256='', object_key='', content_id=null, removed=true, erased_at=$5 where ${T('a')} and a.message_id=$4`, sc(ctx, mid, ctx.now));
      await tx.query(`update ${S}.assertions a set quote=$5, attributed_to=$6 where ${T('a')} and a.message_id=$4`, sc(ctx, mid, tomb, ERASED_ADDRESS));
      await tx.query(`update ${S}.message_versions v set snapshot=jsonb_build_object('erased', true, 'preservedAs', $5::text) where ${T('v')} and v.message_id=$4`, sc(ctx, mid, preservedAs));
      // The thread's subject came from its first message; once no readable message carries it, it goes too.
      await tx.query(`update ${S}.threads t set subject=$6, updated_at=$7 where ${T('t')} and t.id=$4 and (t.subject=$5 or not exists (
        select 1 from ${S}.messages x where x.thread_id=t.id and x.state<>'discarded' and x.content_erased_at is null))`, sc(ctx, msg.thread_id, msg.subject, ERASED_SUBJECT, ctx.now));
      // A thread left with no readable message (mail that arrived unprompted) no longer names a contact, and contact history
      // no longer points at the message: otherwise a recorded contact's address would identify who sent the sealed content.
      await tx.query(`update ${S}.threads t set contact_id=null where ${T('t')} and t.id=$4 and t.plan_id is null and not exists (
        select 1 from ${S}.messages x where x.thread_id=t.id and x.state<>'discarded' and x.content_erased_at is null)`, sc(ctx, msg.thread_id));
      await tx.query(`update ${S}.contact_events c set ref=null where ${T('c')} and c.ref=$4`, sc(ctx, ref('message', mid)));
      // Readable text in this engine's own outbox payloads and stored command results about the message.
      const subject = ref('message', mid);
      for (const e of await tx.query<{ seq: string; payload: Json }>(`select seq::text as seq, payload from ${S}._events where tenant_id=$1 and project_id=$2 and subject=$3 and (payload ? 'candidates' or payload ? 'attributedTo')`, [ctx.tenantId, ctx.projectId, subject])) {
        await tx.query(`update ${S}._events set payload=$2::jsonb where seq=$1::bigint`, [e.seq, JSON.stringify(scrubPayload(e.payload, preservedAs))]);
      }
      await tx.query(`update ${S}._idempotency set result=jsonb_build_object('erased', true, 'preservedAs', $4::text) where tenant_id=$1 and project_id=$2 and result is not null and strpos(result::text, $3) > 0`, [ctx.tenantId, ctx.projectId, mid, preservedAs]);
      const counts = { objectsDeleted: keys.length, attachments: attachments.length };
      await record(tx, ctx, 'message.content_erased', subject, { reason, preservedAs, ...counts },
        { type: 'correspondence.message_content_erased', payload: { preservedAs, conversation: ref('conversation', msg.thread_id as string), ...counts } });
      return messageView(row);
    });
  }
  return { eraseMessageContent };
}
