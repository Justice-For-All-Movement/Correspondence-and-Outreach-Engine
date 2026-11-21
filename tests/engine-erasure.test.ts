// Content erasure after preservation elsewhere: the readable content leaves the database rows, the object store, the
// search index and derived text; headers needed for threading stay; the exact capability is enforced; idempotent.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { DomainError } from '../src/contracts.ts';
import { listAudit } from '../src/service-kit.ts';
import type { ServiceContext } from '../src/service-kit.ts';
import { routes } from '../src/engine/index.ts';
import { DB, agent, controlledMailbox, drain, eventsOf, human, reply, service, withHarness } from './engine-helpers.ts';

const skip = DB === undefined ? 'TEST_DATABASE_URL is not set' : false;
const code = (c: string) => (e: unknown): boolean => e instanceof DomainError && e.code === c;
function walk(dir: string): string[] { return readdirSync(dir).flatMap((n) => { const p = join(dir, n); return statSync(p).isDirectory() ? walk(p) : [p]; }); }
const PRESERVED = 'E05:evidence_version:sealed-copy-1@1';
const known = new Set([PRESERVED]);
const evidence = {
  describe: async (_c: ServiceContext, r: string) => (known.has(r) ? { ref: r, evidenceId: 'sealed-copy-1', revision: 1, sha256: '', size: 10, mediaType: 'application/vnd.pam.sealed+json', filename: 'x.sealed.json', compartment: null, available: true } : null),
  getBytes: async () => new Uint8Array(), accept: async () => { throw new Error('unused'); }, addDerivative: async () => { throw new Error('unused'); },
};
const eraser = (over: Partial<ServiceContext> = {}): ServiceContext => service({ capabilities: ['correspondence:read', 'correspondence:events', 'correspondence:erase'], ...over });
const SECRET = 'quorvellian';

test('erase-content: readable content leaves rows, objects, search and derived text; capability enforced; idempotent', { skip }, async () => {
  await withHarness(async (h) => {
    const e = h.engine; const me = human();
    const mailboxId = await controlledMailbox(h);
    // A standalone message from someone at risk: text, HTML, an attachment, a display name.
    const mime = ['From: "Mira Holloway" <source-person@example.net>', 'To: desk@example.org', `Subject: Ledger ${SECRET} pages`, 'Message-ID: <src-1@mail.example.net>', 'Date: Mon, 02 Nov 2026 10:00:00 +0000',
      'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="x"', '',
      '--x', 'Content-Type: multipart/alternative; boundary="y"', '', '--y', 'Content-Type: text/plain; charset=utf-8', '', `The ${SECRET} ledger was moved on 3 March.`, '--y', 'Content-Type: text/html; charset=utf-8', '', `<p>The <b>${SECRET}</b> ledger was moved on 3 March.</p>`, '--y--',
      '--x', 'Content-Type: application/pdf; name="holloway-notes.pdf"', 'Content-Disposition: attachment; filename="holloway-notes.pdf"', 'Content-Transfer-Encoding: base64', '', Buffer.from(`%PDF-fake ${SECRET} scan`).toString('base64'), '--x--', ''].join('\r\n');
    const src = await e.ingestRawMessage(service(), mailboxId, Buffer.from(mime), { providerId: 'p-1' });
    const srcId = src.message.id as string;
    // A reply to something we sent: produces attributed assertion candidates and a reply_received event carrying text.
    const draft = await e.createDraft(me, { mailboxId, to: ['clerk@example.net'], subject: 'Depot ledger', body: 'Which ledger?' });
    const sent = await e.sendMessage(me, draft.id as string); await drain(e);
    const header = (await e.getDispatch(me, sent.id as string)).messageIdHeader as string;
    const answer = await e.ingestRawMessage(service(), mailboxId, reply({ from: 'clerk@example.net', to: 'desk@example.org', inReplyTo: header, body: `The ${SECRET} delivery was entered in ledger B on page twelve.` }));
    const answerId = answer.message.id as string;
    assert.ok((await eventsOf(e, service(), 'correspondence.reply_received')).some((x) => JSON.stringify(x.payload).includes(SECRET)));
    assert.ok((await e.listAssertions(me, { messageId: answerId })).length >= 1);
    assert.equal((await e.searchMessages(me, { q: SECRET })).total, 2);
    const before = walk(h.objectsDir).length;
    assert.ok(walk(h.objectsDir).some((f) => readFileSync(f).toString('latin1').includes(SECRET)));

    const ee = h.make({}, { evidence });
    // Capability: exact, never through a wildcard; never an agent; reason and an outside reference are required.
    await assert.rejects(ee.eraseMessageContent(human({ capabilities: ['correspondence:*', 'correspondence:read'] }), srcId, { reason: 'sealed', preservedAs: PRESERVED }), code('forbidden'));
    await assert.rejects(ee.eraseMessageContent(human({ capabilities: ['correspondence:read', 'correspondence:write', 'correspondence:admin'] }), srcId, { reason: 'sealed', preservedAs: PRESERVED }), code('forbidden'));
    await assert.rejects(ee.eraseMessageContent(agent({ capabilities: ['correspondence:read', 'correspondence:erase'] }), srcId, { reason: 'sealed', preservedAs: PRESERVED }), code('forbidden'));
    await assert.rejects(ee.eraseMessageContent(eraser(), srcId, { reason: 'sealed', preservedAs: `E03:message:${srcId}` }), code('invalid_reference'));
    await assert.rejects(ee.eraseMessageContent(eraser(), srcId, { reason: 'sealed', preservedAs: 'not a reference' }), code('invalid_reference'));
    await assert.rejects(ee.eraseMessageContent(eraser(), srcId, { reason: '', preservedAs: PRESERVED }), code('invalid_input'));
    // An evidence reference that cannot be confirmed refuses the erasure and changes nothing.
    await assert.rejects(ee.eraseMessageContent(eraser(), srcId, { reason: 'sealed', preservedAs: 'E05:evidence_version:missing@1' }), code('invalid_state'));
    await assert.rejects(ee.eraseMessageContent(eraser({ compartments: [], tenantId: 'org-b' }), srcId, { reason: 'sealed', preservedAs: PRESERVED }), code('not_found'));
    assert.equal(walk(h.objectsDir).length, before);
    assert.equal((await e.getMessage(me, srcId)).contentErased, false);

    const erased = await ee.eraseMessageContent(eraser(), srcId, { reason: 'Sealed on arrival for the project researchers', preservedAs: PRESERVED });
    const erasedAnswer = await ee.eraseMessageContent(human({ capabilities: ['correspondence:read', 'correspondence:erase'] }), answerId, { reason: 'Sealed by a researcher', preservedAs: PRESERVED });
    assert.equal(erased.contentErased, true); assert.equal(erased.preservedAs, PRESERVED);
    assert.equal(erased.tombstone, `Content sealed and erased; preserved as ${PRESERVED}`);
    assert.equal(erasedAnswer.contentErased, true);
    // Idempotent: the same call again changes nothing and emits nothing.
    const again = await ee.eraseMessageContent(eraser(), srcId, { reason: 'again', preservedAs: PRESERVED });
    assert.equal(again.contentErasedAt, erased.contentErasedAt); assert.equal(again.contentErasureReason, 'Sealed on arrival for the project researchers');

    // Views: a clear tombstone; threading headers and dates kept.
    const m = await e.getMessage(me, srcId);
    assert.equal(m.bodyText, `Content sealed and erased; preserved as ${PRESERVED}`);
    assert.equal(m.subject, 'Content sealed and erased'); assert.equal(m.fromAddr, 'erased@sealed.invalid'); assert.equal(m.fromName, '');
    assert.deepEqual(m.toAddrs, []); assert.equal(m.untrustedHtml, null); assert.equal(m.sanitizedHtml, null); assert.deepEqual(m.attachments, []);
    assert.equal(m.messageIdHeader, '<src-1@mail.example.net>'); assert.ok(m.receivedAt); assert.equal((m.classificationDetail as any).declaredDate !== undefined, true);
    const thread = await e.getThread(me, m.threadId as string);
    assert.equal(thread.subject, 'Content sealed and erased'); assert.match(String(thread.snippet), /Content sealed and erased; preserved as/);
    assert.equal((await e.inspect(me, `E03:message:${srcId}`))!.state, 'content_erased');
    await assert.rejects(e.getRawMessage(me, srcId), code('not_found'));
    await assert.rejects(e.createDraft(me, { replyToMessageId: srcId, body: 'Thanks' }), code('invalid_state'));
    await assert.rejects(e.handToEvidence(me, srcId), code('unavailable'));
    // Search no longer finds it, through any surface.
    assert.equal((await e.searchMessages(me, { q: SECRET })).total, 0);
    assert.equal((await e.listThreads(me, { folder: 'all', q: SECRET })).total, 0);
    assert.equal((await e.search(me, { q: SECRET })).length, 0);
    assert.equal((await e.searchMessages(me, { q: 'Holloway' })).total, 0);
    // Object store: the original and the attachment are gone; no stored file holds the content.
    assert.equal(walk(h.objectsDir).length, before - 3, 'two originals and one attachment deleted');
    assert.ok(!walk(h.objectsDir).some((f) => readFileSync(f).toString('latin1').includes(SECRET)));
    // Database: no row of any table in the engine's schema still holds the content, the sender or its name.
    const tables = await h.sql.query<{ table_name: string }>(`select table_name from information_schema.tables where table_schema='e03_correspondence'`);
    for (const { table_name } of tables) {
      const rows = await h.sql.query<{ t: string }>(`select x::text as t from e03_correspondence.${table_name} x`);
      for (const r of rows) {
        assert.ok(!r.t.includes(SECRET), `${table_name} still holds message content`);
        assert.ok(!r.t.includes('source-person@example.net') && !r.t.includes('Holloway'), `${table_name} still holds the sender`);
      }
    }
    // Audit entry and event naming the preserved copy.
    const audit = await listAudit(h.sql, 'e03_correspondence', me, { subject: `E03:message:${srcId}` });
    const entry = audit.find((a) => a.action === 'message.content_erased');
    assert.ok(entry); assert.equal((entry!.detail as any).preservedAs, PRESERVED); assert.equal(entry!.actorKind, 'service');
    const events = (await eventsOf(e, service(), 'correspondence.message_content_erased', 2)).filter((x) => x.subject === `E03:message:${srcId}`);
    assert.equal(events.length, 1, 'one event, even after a repeated call'); assert.equal(events[0]!.payload.preservedAs, PRESERVED);
    // A provider re-delivering the same message does not bring the plaintext back.
    const redelivered = await e.ingestRawMessage(service(), mailboxId, Buffer.from(mime), { providerId: 'p-2' });
    assert.equal(redelivered.duplicate, true); assert.equal(redelivered.message.id, srcId); assert.equal(redelivered.message.contentErased, true);
    assert.equal((await e.searchMessages(me, { q: SECRET })).total, 0);
    // A draft (or a send still pending) cannot be erased.
    const d2 = await e.createDraft(me, { mailboxId, to: ['other@example.net'], subject: 'x', body: 'y' });
    await assert.rejects(ee.eraseMessageContent(eraser(), d2.id as string, { reason: 'sealed', preservedAs: PRESERVED }), code('invalid_state'));
    // Unprompted mail from a recorded contact: once erased, the thread no longer names the contact.
    const known = await e.upsertContact(me, { address: 'known-person@example.net', whyMayKnow: 'met before' });
    const fromKnown = await e.ingestRawMessage(service(), mailboxId, reply({ from: 'known-person@example.net', to: 'desk@example.org', subject: 'Unprompted', body: 'A note.' }));
    assert.equal((await e.getThread(me, fromKnown.message.threadId as string)).contactId, known.id);
    await ee.eraseMessageContent(eraser(), fromKnown.message.id as string, { reason: 'sealed', preservedAs: PRESERVED });
    assert.equal((await e.getThread(me, fromKnown.message.threadId as string)).contactId, null);
    assert.equal((await h.sql.query(`select 1 from e03_correspondence.contact_events where ref=$1`, [`E03:message:${fromKnown.message.id}`])).length, 0);
    // HTTP route exists.
    assert.ok(routes(e).some((r) => r.method === 'POST' && r.path === '/v1/messages/:id/erase-content'));
  });
});
