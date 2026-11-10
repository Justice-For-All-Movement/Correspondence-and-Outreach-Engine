// Workspace surface, security boundaries, IMAP synchronization, HTTP routes and upstream blocking. Real PostgreSQL and sockets.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { DomainError } from '../src/contracts.ts';
import { createHttpHandler, createTokenVerifier, generateSigningKey, serve, signAccessToken, verifyAuditChain, listAudit } from '../src/service-kit.ts';
import type { ServiceContext } from '../src/service-kit.ts';
import { correspondencePort, manifest, routes } from '../src/engine/index.ts';
import { ALL, DB, PROFILE, agent, controlledMailbox, ctxOf, drain, eventsOf, human, reply, service, withHarness } from './engine-helpers.ts';

const skip = DB === undefined ? 'TEST_DATABASE_URL is not set' : false;
const code = (c: string) => (e: unknown): boolean => e instanceof DomainError && e.code === c;
const soon = (ms: number): string => new Date(Date.now() + ms).toISOString();
const INQUIRY = { subject: 'Question about the depot ledger', purpose: 'We are trying to establish which ledger recorded the delivery.', questions: ['Which ledger recorded the delivery?'] };
function walk(dir: string): string[] { return readdirSync(dir).flatMap((n) => { const p = join(dir, n); return statSync(p).isDirectory() ? walk(p) : [p]; }); }

test('mail workspace: folders, counts, labels, bulk actions, assignment, search, threads, drafts, attachments, pagination', { skip }, async () => {
  await withHarness(async (h) => {
    const me = human(); const e = h.engine;
    const mailboxId = await controlledMailbox(h);
    for (let i = 1; i <= 5; i++) await e.ingestRawMessage(service(), mailboxId, reply({ from: `writer${i}@example.net`, to: 'desk@example.org', subject: `Ledger note ${i}`, body: i === 3 ? 'The zeppelin manifest is attached for your records.' : `Routine note number ${i}.`, messageId: `<n${i}@mail.example.net>` }));
    let counts = await e.counts(me, { mailboxId });
    assert.deepEqual(counts.folders.inbox, { total: 5, unread: 5 });
    const p1 = await e.listThreads(me, { folder: 'inbox', limit: 2 });
    assert.equal(p1.total, 5); assert.equal(p1.items.length, 2); assert.ok(p1.nextCursor);
    const p2 = await e.listThreads(me, { folder: 'inbox', limit: 2, cursor: p1.nextCursor as string });
    const p3 = await e.listThreads(me, { folder: 'inbox', limit: 2, cursor: p2.nextCursor as string });
    assert.equal(new Set([...p1.items, ...p2.items, ...p3.items].map((t) => t.id)).size, 5);
    assert.equal(p3.nextCursor, null);
    const ids = p1.items.map((t) => t.id as string);
    // Labels: CRUD and per-label counts.
    const label = await e.createLabel(me, { name: 'Depot', color: 'teal' });
    await assert.rejects(e.createLabel(me, { name: 'Depot' }), code('conflict'));
    await e.modifyThreads(me, { threadIds: ids, addLabelIds: [label.id as string], starred: true, assignee: 'human-2' });
    assert.equal((await e.listThreads(me, { folder: 'all', labelId: label.id as string })).total, 2);
    assert.equal((await e.listThreads(me, { folder: 'starred' })).total, 2);
    assert.equal((await e.listThreads(me, { folder: 'all', assignee: 'human-2' })).total, 2);
    counts = await e.counts(me);
    assert.deepEqual(counts.labels.map((l) => [l.name, l.total, l.unread]), [['Depot', 2, 2]]);
    assert.equal((await e.updateLabel(me, label.id as string, { name: 'Depot records' })).name, 'Depot records');
    // Read / archive / trash / spam.
    await e.modifyThreads(me, { threadIds: [ids[0]!], read: true, archived: true });
    await e.modifyThreads(me, { threadIds: [ids[1]!], trashed: true });
    counts = await e.counts(me);
    assert.deepEqual([counts.folders.inbox, counts.folders.archive, counts.folders.trash], [{ total: 3, unread: 3 }, { total: 1, unread: 0 }, { total: 1, unread: 1 }]);
    assert.equal((await e.listThreads(me, { folder: 'inbox', unread: true })).total, 3);
    // A new message in an archived thread brings it back to the inbox.
    await e.ingestRawMessage(service(), mailboxId, reply({ from: 'writer9@example.net', to: 'desk@example.org', inReplyTo: `<n${p1.items[0]!.subject === 'Ledger note 5' ? 5 : String(p1.items[0]!.subject).slice(-1)}@mail.example.net>`, body: 'One more detail about the ledger.' }));
    assert.equal((await e.counts(me)).folders.archive!.total, 0);
    // Full-text search over subject, body and participants.
    const hits = await e.searchMessages(me, { q: 'zeppelin manifest' });
    assert.equal(hits.total, 1); assert.match(hits.items[0]!.headline as string, /\[\[zeppelin\]\]/);
    assert.equal((await e.searchMessages(me, { q: 'writer4@example.net' })).total, 1);
    assert.equal((await e.listThreads(me, { folder: 'all', q: 'zeppelin' })).total, 1);
    assert.equal((await e.search(me, { q: 'zeppelin' }))[0]!.kind, 'message');
    // Compose: draft → edit → attachment → schedule → cancel → send; reply threading.
    const draft = await e.createDraft(me, { mailboxId, to: ['Clerk@Example.net'], subject: 'Depot ledger', body: 'First version.' });
    assert.deepEqual(draft.toAddrs, ['clerk@example.net']);
    assert.equal((await e.counts(me)).folders.drafts!.total, 1);
    const edited = await e.updateDraft(me, draft.id as string, { expectedRevision: 1, body: 'Second version with the page number.' });
    const att = await e.addAttachment(me, draft.id as string, { filename: '../ledger page.txt', mediaType: 'text/plain', bytes: Buffer.from('page 12 of the ledger') });
    assert.equal(att.filename, '.._ledger page.txt');
    const scheduled = await e.sendMessage(me, draft.id as string, { sendAt: soon(3600_000) });
    assert.equal((await e.counts(me)).folders.outbox!.total, 1);
    await drain(e);
    assert.equal(h.world.smtpTransactions, 0);
    assert.equal((await e.cancelDispatch(me, scheduled.id as string)).state, 'cancelled');
    const sentNow = await e.sendMessage(me, draft.id as string);
    await drain(e);
    assert.equal((await e.getDispatch(me, sentNow.id as string)).state, 'accepted');
    await assert.rejects(e.cancelDispatch(me, sentNow.id as string), code('invalid_state'));
    const wire = h.world.folders.get('Sent')!.messages[0]!.raw.toString('utf8');
    assert.match(wire, /filename="?\.\._ledger page\.txt"?/); assert.match(wire, /Second version/);
    assert.equal((await e.counts(me)).folders.sent!.total, 1);
    const got = await e.getMessage(me, draft.id as string);
    assert.deepEqual((got.versions as any[]).map((v) => v.revision), [1, 2]);
    assert.equal(edited.revision, 2);
    assert.equal(Buffer.from((await e.getAttachment(me, att.id as string)).bytes).toString(), 'page 12 of the ledger');
    // Inbound attachment preserved and downloadable; reply draft threads and addresses the sender.
    const mime = ['From: clerk@example.net', 'To: desk@example.org', 'Subject: Re: Depot ledger', 'Message-ID: <att-1@mail.example.net>', `In-Reply-To: ${sentNow.messageIdHeader}`, 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="x"', '',
      '--x', 'Content-Type: text/plain', '', 'The delivery was recorded in ledger B, page 12.', '--x', 'Content-Type: application/pdf; name="scan.pdf"', 'Content-Disposition: attachment; filename="scan.pdf"', 'Content-Transfer-Encoding: base64', '', Buffer.from('%PDF-fake').toString('base64'), '--x--', ''].join('\r\n');
    const inbound = await e.ingestRawMessage(service(), mailboxId, Buffer.from(mime));
    const thread = await e.getThread(me, inbound.message.threadId as string, { markRead: true });
    assert.equal(thread.id, draft.threadId);
    assert.equal((thread.messages as any[]).length, 2);
    const scan = (thread.messages as any[])[1].attachments[0];
    assert.equal(scan.filename, 'scan.pdf');
    assert.equal(Buffer.from((await e.getAttachment(me, scan.id)).bytes).toString(), '%PDF-fake');
    const re = await e.createDraft(me, { replyToMessageId: inbound.message.id as string, body: 'Thank you.' });
    assert.deepEqual([re.toAddrs, re.subject, re.inReplyTo, re.threadId], [['clerk@example.net'], 'Re: Depot ledger', '<att-1@mail.example.net>', draft.threadId]);
    assert.equal((await e.discardDraft(me, re.id as string)).state, 'discarded');
    // Deleting a label removes it from threads; audit chain is intact and holds no message text.
    await e.deleteLabel(me, label.id as string);
    assert.equal((await e.listLabels(me)).length, 0);
    const audit = await listAudit(h.sql, 'e03_correspondence', me, { allProjects: true, limit: 1000 });
    assert.ok(verifyAuditChain(audit));
    assert.ok(!JSON.stringify(audit).includes('page 12'));
    // Inspect shows sources, dependents and history.
    const ins = await e.inspect(me, `E03:conversation:${draft.threadId}`);
    assert.ok(ins !== null && ins.dependents.length >= 3 && ins.history.length > 0);
    assert.equal(await e.inspect(me, 'E03:conversation:00000000-0000-4000-8000-000000000000'), null);
  });
});

test('IMAP synchronization: UID checkpoints, UIDVALIDITY reset, idempotent ingestion, own sent mail recognised', { skip }, async () => {
  await withHarness(async (h) => {
    const e = h.engine; const svc = service();
    const mailboxId = await controlledMailbox(h);
    h.world.deliver('INBOX', reply({ from: 'a@example.net', to: 'desk@example.org', body: 'First message body.', messageId: '<s1@mail.example.net>' }));
    h.world.deliver('INBOX', reply({ from: 'b@example.net', to: 'desk@example.org', body: 'Second message body.', messageId: '<s2@mail.example.net>' }));
    h.world.deliver('INBOX', reply({ from: 'c@example.net', to: 'desk@example.org', body: 'Third message body.', messageId: '<s3@mail.example.net>' }));
    const first = await e.syncMailboxNow(svc, mailboxId, { limit: 2 });
    assert.deepEqual(first, { ingested: 2, duplicates: 0, skipped: 0, resets: 0, more: true });
    assert.deepEqual(await e.syncMailboxNow(svc, mailboxId), { ingested: 1, duplicates: 0, skipped: 0, resets: 0, more: false });
    // Nothing new: nothing fetched again.
    const before = h.world.imapCommands.filter((c) => /BODY/i.test(c)).length;
    assert.deepEqual(await e.syncMailboxNow(svc, mailboxId), { ingested: 0, duplicates: 0, skipped: 0, resets: 0, more: false });
    assert.equal(h.world.imapCommands.filter((c) => /BODY/i.test(c)).length, before);
    h.world.deliver('INBOX', reply({ from: 'd@example.net', to: 'desk@example.org', body: 'Fourth message body.', messageId: '<s4@mail.example.net>' }));
    assert.equal((await e.syncMailboxNow(svc, mailboxId)).ingested, 1);
    // The server renumbers the folder (new UIDVALIDITY): everything is rescanned, nothing is duplicated.
    const inbox = h.world.folders.get('INBOX')!;
    inbox.uidValidity = 7777; inbox.messages.forEach((m, i) => { m.uid = 100 + i; }); inbox.nextUid = 200;
    assert.deepEqual(await e.syncMailboxNow(svc, mailboxId), { ingested: 0, duplicates: 4, skipped: 0, resets: 1, more: false });
    assert.equal((await e.counts(human())).folders.inbox!.total, 4);
    // Via the job queue as well.
    h.world.deliver('INBOX', reply({ from: 'e@example.net', to: 'desk@example.org', body: 'Fifth message body.', messageId: '<s5@mail.example.net>' }));
    await e.syncMailbox(svc, mailboxId); await drain(e);
    assert.equal((await e.counts(human())).folders.inbox!.total, 5);
    assert.equal((await e.getMailbox(human(), mailboxId)).lastSyncStatus, 'ok');
    // A copy of our own outbound message in the mailbox is delivery evidence, not new inbound mail.
    const draft = await e.createDraft(human(), { mailboxId, to: ['a@example.net'], subject: 'Hello', body: 'A note.' });
    const d = await e.sendMessage(human(), draft.id as string); await drain(e);
    h.world.deliver('INBOX', h.world.folders.get('Sent')!.messages[0]!.raw);
    assert.deepEqual(await e.syncMailboxNow(svc, mailboxId), { ingested: 0, duplicates: 1, skipped: 0, resets: 0, more: false });
    assert.ok(((await e.getDispatch(human(), d.id as string)).evidence as any[]).some((x) => x.kind === 'observed_in_mailbox'));
    // Wrong password: explicit failure state, checkpoint untouched, no secret in the error.
    await e.setMailboxCredentials(human(), mailboxId, { smtpPassword: h.world.password, imapPassword: 'wrong-password-value' });
    await assert.rejects(e.syncMailboxNow(svc, mailboxId), (err) => err instanceof DomainError && err.code === 'provider_auth_failed' && !err.message.includes('wrong-password-value'));
    const mb = await e.getMailbox(human(), mailboxId);
    assert.equal(mb.lastSyncStatus, 'failed');
    assert.deepEqual(await e.testMailboxConnection(human(), mailboxId), { send: 'ok', read: 'failed: IMAP authentication was rejected' });
  });
});

test('tenant isolation, compartments and fail-closed authorization', { skip }, async () => {
  await withHarness(async (h) => {
    const e = h.engine; const a = human();
    const mailboxId = await controlledMailbox(h);
    const inbound = await e.ingestRawMessage(service(), mailboxId, reply({ from: 'writer@example.net', to: 'desk@example.org', subject: 'Quartz inventory', body: 'The quartz inventory was moved to the annex.' }));
    const contact = await e.upsertContact(a, { address: 'writer@example.net', whyMayKnow: 'Wrote about the quartz inventory', routeSource: 'E04:lead:l9' });
    const plan = await e.createOutreachPlan(a, { questionRef: 'E08:question:q9', question: 'Where is the quartz inventory?', candidates: [{ contactId: contact.id as string }] });
    const draft = await e.createDraft(a, { mailboxId, to: ['writer@example.net'], subject: 'Quartz', body: 'A question about quartz.' });
    const att = await e.addAttachment(a, draft.id as string, { filename: 'q.txt', mediaType: 'text/plain', bytes: Buffer.from('quartz') });
    const d = await e.sendMessage(a, draft.id as string);
    const label = await e.createLabel(a, { name: 'Quartz' });
    const grant = await e.createGrant(a, { granteeId: 'agent-1', mailboxId, purpose: 'p', recipientAllowlist: ['writer@example.net'], maxMessages: 1, expiresAt: soon(60_000) });
    await e.addSuppression(a, { address: 'blocked@example.net', reason: 'asked by phone' });
    // A second tenant and a second project see nothing through any method.
    for (const other of [human({ tenantId: 'org-b' }), human({ projectId: 'proj-2' })]) {
      assert.equal((await e.listThreads(other, { folder: 'all' })).total, 0);
      assert.deepEqual((await e.counts(other)).folders.inbox, { total: 0, unread: 0 });
      assert.equal((await e.searchMessages(other, { q: 'quartz' })).total, 0);
      assert.deepEqual(await e.search(other, { q: 'quartz' }), []);
      assert.equal((await e.listContacts(other)).total, 0);
      assert.deepEqual([await e.listMailboxes(other), await e.listLabels(other), await e.listGrants(other), await e.listSuppressions(other), await e.listPlans(other), await e.listDispatches(other), await e.listAssertions(other)], [[], [], [], [], [], [], []]);
      assert.equal(await e.inspect(other, `E03:message:${inbound.message.id}`), null);
      assert.equal(await e.inspect(other, `E03:mailbox:${mailboxId}`), null);
      assert.deepEqual(await e.audit(other), []);
      assert.equal((await e.questionStatus(other, 'E08:question:q9')).state, 'not_contacted');
      for (const call of [() => e.getThread(other, inbound.message.threadId as string), () => e.getMessage(other, inbound.message.id as string), () => e.getRawMessage(other, inbound.message.id as string), () => e.getAttachment(other, att.id as string),
        () => e.getMailbox(other, mailboxId), () => e.getContact(other, contact.id as string), () => e.getPlan(other, plan.id as string), () => e.getDispatch(other, d.id as string), () => e.getGrant(other, grant.id as string),
        () => e.createDraft(other, { mailboxId, to: ['x@example.net'], subject: 's', body: 'b' }), () => e.sendMessage(other, draft.id as string), () => e.takeover(other, { threadId: draft.threadId as string }), () => e.takeover(other, { mailboxId }),
        () => e.ingestRawMessage(ctxOf({ ...other, kind: 'service' }), mailboxId, reply({ from: 'z@example.net', to: 'desk@example.org', body: 'x' })), () => e.revokeGrant(other, grant.id as string, { reason: 'r' }), () => e.cancelDispatch(other, d.id as string),
        () => e.updateLabel(other, label.id as string, { name: 'n' }), () => e.setMailboxCredentials(other, mailboxId, { smtpPassword: 'p' }), () => e.syncMailboxNow(other, mailboxId), () => e.modifyThreads(other, { threadIds: [draft.threadId as string], addLabelIds: [label.id as string] })])
        await assert.rejects(call(), code('not_found'));
      assert.deepEqual(await e.modifyThreads(other, { threadIds: [draft.threadId as string], trashed: true }), { updated: [] });
    }
    assert.ok((await eventsOf(e, service(), 'message.received')).length === 1);
    assert.deepEqual((await e.events(service({ tenantId: 'org-b' }))), []);
    // Object keys are tenant/project prefixed.
    const keys = walk(h.objectsDir).map((p) => p.slice(h.objectsDir.length + 1));
    assert.ok(keys.length >= 2 && keys.every((k) => k.startsWith('org-a/proj-1/e03/')));
    // Compartments: hidden objects are indistinguishable from missing ones, in lists, search and counts too.
    const insider = human({ compartments: ['witness'] });
    const secret = await e.upsertContact(insider, { address: 'source@example.net', displayName: 'Protected Source', whyMayKnow: 'obsidian witness', compartment: 'witness' });
    const sDraft = await e.createDraft(insider, { mailboxId, contactId: secret.id as string, subject: 'Obsidian', body: 'obsidian question' });
    assert.equal(sDraft.compartment, 'witness');
    await assert.rejects(e.upsertContact(a, { address: 'x@example.net', compartment: 'witness' }), code('forbidden'));
    await assert.rejects(e.getContact(a, secret.id as string), code('not_found'));
    await assert.rejects(e.getMessage(a, sDraft.id as string), code('not_found'));
    await assert.rejects(e.sendMessage(a, sDraft.id as string), code('not_found'));
    assert.equal((await e.searchMessages(a, { q: 'obsidian' })).total, 0);
    assert.equal((await e.listContacts(a, { q: 'obsidian' })).total, 0);
    assert.equal((await e.searchMessages(insider, { q: 'obsidian' })).total, 1);
    assert.equal((await e.counts(a)).folders.drafts!.total, 0);
    assert.equal((await e.counts(insider)).folders.drafts!.total, 1);
    assert.equal(await e.inspect(a, `E03:contact:${secret.id}`), null);
    // Fail closed: each capability is separate; wildcard never grants send, grant, admin or events.
    const none = human({ capabilities: [] }); const reader = human({ capabilities: ['correspondence:read'] }); const wild = human({ capabilities: ['correspondence:*'] });
    for (const call of [() => e.listThreads(none), () => e.counts(none), () => e.search(none, { q: 'quartz' }), () => e.inspect(none, `E03:mailbox:${mailboxId}`), () => e.createDraft(reader, { mailboxId, to: ['x@example.net'], subject: 's', body: 'b' }),
      () => e.sendMessage(reader, draft.id as string), () => e.sendMessage(wild, draft.id as string), () => e.createGrant(wild, { granteeId: 'x', mailboxId, purpose: 'p', recipientAllowlist: ['a@example.net'], maxMessages: 1, expiresAt: soon(1000) }),
      () => e.createMailbox(wild, { address: 'n@example.org', provider: 'ingest_only' }), () => e.events(wild), () => e.audit(reader), () => e.createOutreachPlan(wild, { questionRef: 'E08:question:q1', question: 'q', candidates: [] }),
      () => e.ingestRawMessage(reader, mailboxId, reply({ from: 'z@example.net', to: 'desk@example.org', body: 'x' })), () => e.takeover(reader, { mailboxId }), () => e.liftSuppression(wild, mailboxId, { reason: 'r' }), () => e.setMailboxCredentials(wild, mailboxId, { smtpPassword: 'p' })])
      await assert.rejects(call(), code('forbidden'));
    await assert.rejects(e.listThreads(undefined as unknown as ServiceContext), code('unauthenticated'));
    await assert.rejects(e.listThreads({ ...a, tenantId: '' }), code('unauthenticated'));
  });
});

test('credentials are sealed, never returned, never written to jobs, audit, events or logs', { skip }, async () => {
  await withHarness(async (h) => {
    const e = h.engine; const a = human();
    const mailboxId = await controlledMailbox(h);
    const draft = await e.createDraft(a, { mailboxId, to: ['x@example.net'], subject: 'Hello', body: 'Text' });
    await e.sendMessage(a, draft.id as string); await drain(e);
    const views = JSON.stringify([await e.getMailbox(a, mailboxId), await e.listMailboxes(a), await e.inspect(a, `E03:mailbox:${mailboxId}`), await e.audit(a), await e.events(service())]);
    assert.ok(!views.includes(h.world.password) && !views.includes('secretEnc') && !views.includes('secret_enc'));
    assert.deepEqual((await e.getMailbox(a, mailboxId)).credentials, { configured: ['imapPassword', 'smtpPassword'], setAt: (await e.getMailbox(a, mailboxId) as any).credentials.setAt });
    for (const table of ['_jobs', '_audit', '_events', '_idempotency', 'mailboxes', 'dispatches', 'delivery_events']) {
      const dump = JSON.stringify(await h.sql.query(`select * from e03_correspondence.${table}`));
      assert.ok(!dump.includes(h.world.password), `${table} holds a plaintext credential`);
    }
    const sealed = (await h.sql.query<{ secret_enc: string }>(`select secret_enc from e03_correspondence.mailboxes`))[0]!.secret_enc;
    assert.match(sealed, /^v1\./);
    // Ciphertext is bound to its mailbox: moved to another row it cannot be opened.
    const other = await e.createMailbox(a, { address: 'second@example.org', provider: 'smtp_imap', senderProfile: PROFILE, config: { smtp: { host: '127.0.0.1', port: h.world.smtpPort, auth: 'password', username: 'mailbox-user' } } });
    await h.sql.query(`update e03_correspondence.mailboxes set secret_enc=$1, secret_fields='{smtpPassword}' where id=$2`, [sealed, other.id]);
    assert.match((await e.testMailboxConnection(a, other.id as string).catch((err: Error) => ({ send: err.message }))).send, /cannot be decrypted/);
    // No key configured: storing or using credentials is explicitly unavailable; config cannot smuggle secrets; private hosts refused by default.
    const keyless = h.make({ secretKey: '' });
    await assert.rejects(keyless.setMailboxCredentials(a, mailboxId, { smtpPassword: 'x' }), code('unavailable'));
    const d2 = await keyless.sendMessage(a, (await keyless.createDraft(a, { mailboxId, to: ['y@example.net'], subject: 'Hello', body: 'Text' })).id as string);
    await drain(keyless);
    const failed = await keyless.getDispatch(a, d2.id as string);
    assert.equal(failed.state, 'failed'); assert.equal(failed.stateReason, 'unavailable');
    await assert.rejects(e.createMailbox(a, { address: 'third@example.org', provider: 'smtp_imap', config: { smtp: { host: '127.0.0.1', port: 25, auth: 'password', username: 'u', password: 'p' } } as any }), code('invalid_input'));
    const strict = h.make({ provider: { allowPrivateHosts: false } });
    for (const host of ['127.0.0.1', 'localhost', '10.0.0.5', '169.254.169.254', 'intranet'])
      await assert.rejects(strict.createMailbox(a, { address: `h-${host.length}@example.org`, provider: 'smtp_imap', config: { smtp: { host, port: 465, secure: true, auth: 'password', username: 'u' } } }), code('invalid_input'));
    await assert.rejects(strict.createMailbox(a, { address: 'g@example.org', provider: 'gmail', config: { oauth: { tokenUrl: 'https://tokens.example.net/x', clientId: 'c' } } }), code('invalid_input'));
    // An ingest-only mailbox has no outbound provider: explicit unavailable, never a pretended send.
    const io = await e.createMailbox(a, { address: 'archive@example.org', provider: 'ingest_only', senderProfile: PROFILE });
    await e.verifySenderProfile(a, io.id as string);
    const d3 = await e.sendMessage(a, (await e.createDraft(a, { mailboxId: io.id as string, to: ['y@example.net'], subject: 'Hello', body: 'Text' })).id as string);
    await drain(e);
    assert.match((await e.getDispatch(a, d3.id as string)).providerResponse as string, /unavailable|no provider/i);
    assert.equal((await e.getDispatch(a, d3.id as string)).state, 'failed');
  });
});

test('upstream changes block or mark stale, cancel queued automation, are idempotent and visible in inspect', { skip }, async () => {
  await withHarness(async (h) => {
    const e = h.engine; const a = human(); const bot = agent();
    const mailboxId = await controlledMailbox(h);
    const { plan, drafts } = await e.planOutreach(bot, { questionRef: 'E08:question:q7', question: 'Which ledger?', mailboxId, inquiry: INQUIRY, candidates: [{ contact: { address: 'keeper@example.net', whyMayKnow: 'Kept the ledger', routeSource: 'E04:lead:l7' } }] });
    const contactId = (plan.candidates as any[])[0].contactId as string;
    await e.verifyContact(a, contactId);
    const grant = await e.createGrant(a, { granteeId: bot.actor.id, mailboxId, purpose: 'p', recipientAllowlist: ['keeper@example.net'], maxMessages: 3, expiresAt: soon(3600_000) });
    const queued = await e.sendMessage(bot, drafts[0]!.id as string, { grantId: grant.id as string, sendAt: soon(600_000) });
    // The question changed upstream: stale; queued automated send is cancelled; a human review clears it.
    const change = { eventId: 'evt-100', kind: 'claim_changed' as const, refs: ['E08:question:q7@3'], reason: 'Question was reworded' };
    const res = await e.applyUpstreamChange(service(), change);
    assert.deepEqual(res.affected.map((r) => r.split(':')[1]).sort(), ['conversation', 'plan']);
    assert.deepEqual(await e.applyUpstreamChange(service(), change), res);
    assert.equal((await e.getDispatch(a, queued.id as string)).stateReason, 'upstream_stale');
    const ins = await e.inspect(a, `E03:conversation:${drafts[0]!.threadId}`);
    assert.ok(ins !== null && ins.stale && ins.staleReasons.includes('Question was reworded') && ins.sources.includes('E08:question:q7'));
    assert.equal((await eventsOf(e, service(), 'conversation.stale')).length, 1);
    await assert.rejects(e.sendMessage(bot, drafts[0]!.id as string, { grantId: grant.id as string }), code('stale'));
    await assert.rejects(e.reviewStale(bot, drafts[0]!.threadId as string, { note: 'n' }), code('forbidden'));
    await e.reviewStale(a, drafts[0]!.threadId as string, { note: 'Inquiry still matches the question' });
    const q2 = await e.sendMessage(bot, drafts[0]!.id as string, { grantId: grant.id as string, sendAt: soon(600_000) });
    // Consent withdrawn for the contact route: blocked for automation, permanently; nothing is deleted.
    const blocked = await e.applyUpstreamChange(service(), { eventId: 'evt-101', kind: 'permission_withdrawn', refs: ['E04:lead:l7'], reason: 'Contact permission withdrawn' });
    assert.deepEqual(blocked.affected.map((r) => r.split(':')[1]).sort(), ['contact', 'conversation', 'plan']);
    assert.equal((await e.getDispatch(a, q2.id as string)).state, 'cancelled');
    await assert.rejects(e.sendMessage(bot, drafts[0]!.id as string, { grantId: grant.id as string }), code('consent_denied'));
    const thread = await e.getThread(a, drafts[0]!.threadId as string);
    assert.equal(thread.automation, 'blocked'); assert.equal((thread.messages as any[]).length, 1);
    assert.equal((await e.inspect(a, `E03:contact:${contactId}`))!.blocked, true);
    assert.equal((await eventsOf(e, service(), 'contact.blocked'))[0]!.payload.cause, 'evt-101');
    await drain(e);
    assert.equal(h.world.smtpTransactions, 0);
    // Unrelated refs and other tenants affect nothing.
    assert.deepEqual((await e.applyUpstreamChange(service(), { eventId: 'evt-102', kind: 'permission_withdrawn', refs: ['E04:lead:other'], reason: 'r' })).affected, []);
    assert.deepEqual((await e.applyUpstreamChange(service({ tenantId: 'org-b' }), { eventId: 'evt-103', kind: 'permission_withdrawn', refs: ['E04:lead:l7'], reason: 'r' })).affected, []);
    await assert.rejects(e.applyUpstreamChange(human({ capabilities: ['correspondence:read'] }), change), code('forbidden'));
  });
});

test('ports: budget reservation per send, evidence hand-off, sensitive contacts, E08 correspondence port', { skip }, async () => {
  const calls: string[] = [];
  const budget = { reserve: async (_c: ServiceContext, r: { idempotencyKey: string }) => { calls.push(`reserve:${r.idempotencyKey.slice(0, 12)}`); if (calls.filter((c) => c.startsWith('reserve')).length > 1) throw new DomainError('budget_exhausted', 'ceiling'); return { reservationId: 'res-1' }; },
    commit: async () => { calls.push('commit'); }, release: async () => { calls.push('release'); } };
  const accepted: { mediaType: string; origin: any; size: number }[] = [];
  const evidence = { describe: async () => null, getBytes: async () => new Uint8Array(), addDerivative: async () => { throw new Error('unused'); },
    accept: async (_c: ServiceContext, i: { bytes: Uint8Array; mediaType: string; filename: string; origin: any }) => { accepted.push({ mediaType: i.mediaType, origin: i.origin, size: i.bytes.byteLength }); return { ref: `E05:evidence_version:ev${accepted.length}@1`, evidenceId: `ev${accepted.length}`, revision: 1, sha256: '', size: i.bytes.byteLength, mediaType: i.mediaType, filename: i.filename, compartment: null, available: true }; } };
  await withHarness(async (h) => {
    const e = h.engine; const a = human();
    const mailboxId = await controlledMailbox(h);
    const send = async (to: string) => { const d = await e.sendMessage(a, (await e.createDraft(a, { mailboxId, to: [to], subject: 'Hello', body: 'Text' })).id as string); await drain(e); return e.getDispatch(a, d.id as string); };
    assert.equal((await send('one@example.net')).state, 'accepted');
    assert.deepEqual(calls.map((c) => c.split(':')[0]), ['reserve', 'commit']);
    const refused = await send('two@example.net');
    assert.equal(refused.state, 'cancelled'); assert.equal(refused.stateReason, 'authorization_or_budget');
    assert.equal(h.world.smtpTransactions, 1);
    const inbound = await e.ingestRawMessage(service(), mailboxId, reply({ from: 'one@example.net', to: 'desk@example.org', body: 'A statement worth preserving.' }));
    const handed = await e.handToEvidence(a, inbound.message.id as string);
    assert.equal(handed.evidenceRef, 'E05:evidence_version:ev1@1');
    assert.deepEqual([accepted[0]!.mediaType, accepted[0]!.origin.verification, accepted[0]!.origin.source], ['message/rfc822', 'attributed_unverified', `E03:message:${inbound.message.id}`]);
    await assert.rejects(h.make({}, {}).handToEvidence(a, inbound.message.id as string), code('unavailable'));
    // Sensitive contact: never automated; human contact denied without a use-decision service.
    const witness = await e.upsertContact(a, { address: 'witness@example.net', sensitive: true, whyMayKnow: 'saw it' });
    const wd = await e.createDraft(a, { mailboxId, contactId: witness.id as string, subject: 'Hello', body: 'Text' });
    await assert.rejects(e.sendMessage(a, wd.id as string), code('consent_denied'));
    const asked: string[][] = [];
    const decided = h.make({}, { useDecision: { decide: async (_c, r) => { asked.push([...r.subjects, r.action]); return { decision: asked.length === 1 ? 'review' : 'allow', reasons: [], permissionRefs: [], restrictions: [], decidedAt: new Date().toISOString() }; } } });
    await assert.rejects(decided.sendMessage(a, wd.id as string), code('consent_denied'));
    assert.equal((await decided.sendMessage(a, wd.id as string)).state, 'queued');
    assert.deepEqual(asked[0], [`E03:contact:${witness.id}`, 'contact']);
    // E08 port: plan for a question from a lead, draft (not sent), thread state.
    await e.upsertContact(a, { address: 'lead@example.net', whyMayKnow: 'named in the register', routeSource: 'E04:lead:l55' });
    const port = correspondencePort(e, { mailboxId });
    const planned = await port.createContactPlan(a, { subject: 'E08:question:q55', question: 'Who kept the register?', contactLeadRef: 'E04:lead:l55', purpose: 'Establish who kept the register in 2019.', idempotencyKey: 'k1' });
    assert.equal(planned.state, 'planned');
    assert.equal((await port.createContactPlan(a, { subject: 'E08:question:q55', question: 'Who kept the register?', contactLeadRef: 'E04:lead:l55', purpose: 'Establish who kept the register in 2019.', idempotencyKey: 'k1' })).planRef, planned.planRef);
    const drafted = await port.draftInquiry(a, { subject: 'E08:question:q55', questions: ['Who kept the register in 2019?'], contactPlanRef: planned.planRef, idempotencyKey: 'k2' });
    assert.equal(drafted.state, 'drafted_not_sent');
    assert.deepEqual(await port.getThreadState(a, drafted.threadRef as string), { threadRef: drafted.threadRef, state: 'drafted_not_sent', replies: [] });
    assert.equal(h.world.smtpTransactions, 1);
  }, { ports: { budget, evidence } });
});

test('HTTP API: authenticated routes, raw ingest, downloads, explicit error statuses', { skip }, async () => {
  await withHarness(async (h) => {
    const key = generateSigningKey('k1');
    const server = await serve(createHttpHandler({ name: manifest.name, version: manifest.version, routes: routes(h.engine), verify: createTokenVerifier({ publicKeys: { k1: key.publicKeyPem } }), health: () => h.engine.health() }), 0);
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    const token = (caps: string[], kind: 'human' | 'service' = 'human', tid = 'org-a'): string => signAccessToken({ iss: 'test', sub: `${kind}-1`, kind, tid, pid: 'proj-1', roles: [], caps, cmp: [], purpose: 'test', pv: '1', iat: Math.floor(Date.now() / 1000) - 1, exp: Math.floor(Date.now() / 1000) + 300, jti: 'j1' }, key);
    const call = async (method: string, path: string, body?: unknown, caps: string[] = ALL, headers: Record<string, string> = {}, tid = 'org-a') => {
      const res = await fetch(base + path, { method, headers: { authorization: `Bearer ${token(caps, 'human', tid)}`, ...(body === undefined || body instanceof Uint8Array ? {} : { 'content-type': 'application/json' }), ...headers }, ...(body === undefined ? {} : { body: (body instanceof Uint8Array ? body : JSON.stringify(body)) as BodyInit }) });
      const type = res.headers.get('content-type') ?? '';
      return { status: res.status, body: type.includes('json') ? await res.json() as any : Buffer.from(await res.arrayBuffer()), headers: res.headers };
    };
    try {
      assert.equal((await fetch(`${base}/healthz`)).status, 200);
      assert.equal((await fetch(`${base}/v1/inbox`)).status, 401);
      assert.equal((await call('GET', '/v1/manifest')).body.id, 'E03');
      const mb = await call('POST', '/v1/mailboxes', { address: 'desk@example.org', provider: 'smtp_imap', senderProfile: PROFILE, config: { smtp: { host: '127.0.0.1', port: h.world.smtpPort, auth: 'password', username: 'mailbox-user' } }, credentials: { smtpPassword: h.world.password } });
      assert.equal(mb.status, 200); assert.ok(!JSON.stringify(mb.body).includes(h.world.password));
      const id = mb.body.id as string;
      assert.equal((await call('POST', `/v1/mailboxes/${id}/sender-profile/verify`)).status, 200);
      const raw = reply({ from: 'writer@example.net', to: 'desk@example.org', subject: 'Basalt survey', body: 'The basalt survey was filed in June.', messageId: '<h1@mail.example.net>' });
      const ing = await call('POST', `/v1/mailboxes/${id}/ingest?providerId=w1`, raw, ALL, { 'content-type': 'message/rfc822' });
      assert.equal(ing.status, 201);
      assert.equal((await call('POST', `/v1/mailboxes/${id}/ingest?providerId=w1`, raw, ALL, { 'content-type': 'message/rfc822' })).status, 200);
      const inbox = await call('GET', `/v1/inbox?mailboxId=${id}`);
      assert.equal(inbox.body.total, 1);
      assert.equal((await call('GET', '/v1/counts')).body.folders.inbox.unread, 1);
      assert.equal((await call('GET', '/v1/messages/search?q=basalt')).body.total, 1);
      const conv = await call('GET', `/v1/conversations/${inbox.body.items[0].id}?markRead=true`);
      assert.equal(conv.body.messages[0].bodyText.trim(), 'The basalt survey was filed in June.');
      const rawOut = await call('GET', `/v1/messages/${ing.body.message.id}/raw`);
      assert.ok((rawOut.body as Buffer).equals(raw)); assert.match(rawOut.headers.get('content-disposition') ?? '', /attachment/);
      const draft = await call('POST', '/v1/messages', { mailboxId: id, to: ['writer@example.net'], subject: 'Re: Basalt survey', body: 'Thank you.' });
      assert.equal(draft.status, 201);
      const att = await call('POST', `/v1/messages/${draft.body.id}/attachments?filename=note.txt`, Buffer.from('note'), ALL, { 'content-type': 'text/plain' });
      assert.equal(att.status, 201);
      assert.equal(((await call('GET', `/v1/attachments/${att.body.id}`)).body as Buffer).toString(), 'note');
      const sent = await call('POST', `/v1/messages/${draft.body.id}/send`, {}, ALL, { 'idempotency-key': 'http-send-1' });
      assert.equal(sent.status, 202);
      assert.equal((await call('POST', `/v1/messages/${draft.body.id}/send`, {}, ALL, { 'idempotency-key': 'http-send-1' })).body.id, sent.body.id);
      await drain(h.engine);
      assert.equal((await call('GET', `/v1/dispatches?state=accepted`)).body.length, 1);
      const took = await call('POST', `/v1/conversations/${draft.body.threadId}/takeover`, { reason: 'mine' });
      assert.equal(took.body.controlMode, 'human');
      assert.equal((await call('POST', `/v1/conversations/${draft.body.threadId}/resume`, {})).body.controlMode, 'automation');
      const planRes = await call('POST', '/v1/outreach/plans', { questionRef: 'E08:question:q1', question: 'When?', candidates: [{ contact: { address: 'writer@example.net', whyMayKnow: 'author' } }] });
      assert.equal(planRes.status, 201);
      assert.equal((await call('GET', '/v1/outreach/questions?ref=E08:question:q1')).body.state, 'not_contacted');
      // Errors: explicit statuses, no leakage across tenants, masked 404 for foreign objects.
      assert.equal((await call('GET', `/v1/conversations/${draft.body.threadId}`, undefined, ALL, {}, 'org-b')).status, 404);
      assert.equal((await call('GET', '/v1/inbox', undefined, [])).status, 403);
      assert.equal((await call('POST', `/v1/messages/${draft.body.id}/send`, {})).status, 409);
      assert.equal((await call('POST', '/v1/suppressions', { address: 'no@example.net', reason: 'asked' })).status, 200);
      const blocked = await call('POST', '/v1/messages', { mailboxId: id, to: ['no@example.net'], subject: 's', body: 'b' });
      const sup = await call('POST', `/v1/messages/${blocked.body.id}/send`, {});
      assert.deepEqual([sup.status, sup.body.error.code], [409, 'suppressed']);
      const ev = await call('POST', `/v1/messages/${ing.body.message.id}/evidence`, {});
      assert.deepEqual([ev.status, ev.body.error.code], [503, 'unavailable']);
      assert.equal((await call('POST', '/v1/messages', { mailboxId: id, to: ['not an address'], subject: 's', body: 'b' })).status, 400);
    } finally { await new Promise((r) => server.close(r)); }
  });
});
