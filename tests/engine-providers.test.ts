// Gmail API and Microsoft Graph adapters against a local stand-in HTTP server (request shapes, OAuth2 refresh, outcomes).
// This exercises the adapter code; it is not verification against the live providers.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { assertionCandidates, findIdentityClaims, parseInbound, renderDisclosure } from '../src/engine/index.ts';
import { DB, PROFILE, drain, human, reply, service, withHarness } from './engine-helpers.ts';

const skip = DB === undefined ? 'TEST_DATABASE_URL is not set' : false;
type Seen = { method: string; path: string; auth: string; type: string; body: string };
async function fakeApi(handler: (r: Seen) => { status: number; json?: unknown; text?: string } | undefined) {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const r = { method: req.method ?? '', path: decodeURIComponent((req.url ?? '').replaceAll('+', ' ')), auth: String(req.headers.authorization ?? ''), type: String(req.headers['content-type'] ?? ''), body: Buffer.concat(chunks).toString('utf8') };
      seen.push(r);
      const out = handler(r) ?? { status: 404, json: { error: 'unhandled' } };
      if (out.status === -1) return void req.socket.destroy();
      res.writeHead(out.status, { 'content-type': out.text === undefined ? 'application/json' : 'message/rfc822' });
      res.end(out.text ?? JSON.stringify(out.json ?? {}));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  return { seen, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, close: () => new Promise((r) => server.close(r)) };
}

test('Gmail adapter: refresh-token exchange, send, uncertain outcome reconciled by rfc822msgid, history sync of raw messages', { skip }, async () => {
  let tokens = 0; let sendMode: 'ok' | 'drop' | 'deny' = 'ok'; const sentIds = new Map<string, string>();
  const inboundRaw = reply({ from: 'writer@example.net', to: 'desk@example.org', body: 'Gmail delivered this statement to the mailbox.', messageId: '<g-in-1@mail.example.net>' });
  const api = await fakeApi((r) => {
    if (r.path === '/token') { tokens++; const f = new URLSearchParams(r.body); return f.get('refresh_token') === 'refresh-secret-1' && f.get('client_secret') === 'client-secret-1' ? { status: 200, json: { access_token: `access-${tokens}`, expires_in: 3600 } } : { status: 400, json: { error: 'invalid_grant', error_description: 'refresh-secret-1 is bad' } }; }
    if (!r.auth.startsWith('Bearer access-')) return { status: 401, json: {} };
    if (r.method === 'POST' && r.path === '/gmail/v1/users/me/messages/send') {
      const raw = Buffer.from((JSON.parse(r.body) as { raw: string }).raw, 'base64url').toString('utf8');
      const mid = /^Message-ID: (<[^>]+>)/m.exec(raw)![1]!;
      if (sendMode === 'deny') return { status: 403, json: {} };
      sentIds.set(mid, `gm-${sentIds.size + 1}`);
      return sendMode === 'drop' ? { status: -1 } : { status: 200, json: { id: sentIds.get(mid), labelIds: ['SENT'] } };
    }
    if (r.path.startsWith('/gmail/v1/users/me/messages?q=rfc822msgid:')) { const mid = /rfc822msgid:(<[^>]+>)/.exec(r.path)![1]!; return { status: 200, json: { messages: sentIds.has(mid) ? [{ id: sentIds.get(mid) }] : [] } }; }
    const meta = /^\/gmail\/v1\/users\/me\/messages\/(gm-\d+)\?format=metadata/.exec(r.path);
    if (meta) { const mid = [...sentIds].find(([, v]) => v === meta[1])![0]; return { status: 200, json: { id: meta[1], labelIds: ['SENT'], payload: { headers: [{ name: 'Message-ID', value: mid }] } } }; }
    if (r.path === '/gmail/v1/users/me/profile') return { status: 200, json: { emailAddress: 'desk@example.org', historyId: '500' } };
    if (r.path.startsWith('/gmail/v1/users/me/messages?maxResults')) return { status: 200, json: { messages: [{ id: 'in1' }] } };
    if (r.path === '/gmail/v1/users/me/messages/in1?format=full') return { status: 200, json: { id: 'in1' } };
    if (r.path === '/gmail/v1/users/me/messages/in1?format=raw') return { status: 200, json: { id: 'in1', raw: inboundRaw.toString('base64url') } };
    if (r.path.startsWith('/gmail/v1/users/me/history?')) return { status: 200, json: { historyId: '500' } };
    return undefined;
  });
  try {
    await withHarness(async (h) => {
      const e = h.engine; const a = human();
      const mb = await e.createMailbox(a, { address: 'desk@example.org', provider: 'gmail', senderProfile: PROFILE, config: { oauth: { tokenUrl: `${api.url}/token`, clientId: 'client-1' }, apiBaseUrl: api.url }, credentials: { oauthClientSecret: 'client-secret-1', oauthRefreshToken: 'refresh-secret-1' } });
      const mailboxId = mb.id as string;
      await e.verifySenderProfile(a, mailboxId);
      assert.deepEqual(await e.testMailboxConnection(a, mailboxId), { send: 'ok', read: 'ok' });
      const send = async (to: string) => { const d = await e.sendMessage(a, (await e.createDraft(a, { mailboxId, to: [to], subject: 'Hello', body: 'Text' })).id as string); await e.runWorkerOnce(); return d.id as string; };
      const ok = await e.getDispatch(a, await send('one@example.net'));
      assert.deepEqual([ok.state, ok.providerId], ['accepted', 'gm-1']);
      assert.equal(tokens, 1, 'access token is cached between calls');
      // The provider took the message but the response was lost: uncertain, then found by Message-ID in Sent; one send request only.
      sendMode = 'drop';
      const lostId = await send('two@example.net');
      assert.equal((await e.getDispatch(a, lostId)).state, 'uncertain');
      sendMode = 'ok'; await drain(e);
      const rec = await e.getDispatch(a, lostId);
      assert.deepEqual([rec.state, rec.providerId, (rec.reconciliation as any).where], ['accepted', 'gm-2', 'SENT']);
      assert.equal(api.seen.filter((r) => r.path.endsWith('/messages/send')).length, 2);
      sendMode = 'deny';
      const denied = await e.getDispatch(a, await send('three@example.net'));
      assert.deepEqual([denied.state, denied.stateReason], ['failed', 'policy-denied']);
      // Sync: full listing then history cursor; the original bytes are fetched and preserved.
      const first = await e.syncMailboxNow(service(), mailboxId);
      assert.equal(first.ingested, 1);
      const inbox = await e.listThreads(a, { folder: 'inbox' });
      const raw = await e.getRawMessage(a, ((await e.getThread(a, inbox.items[0]!.id as string)).messages as any[])[0].id);
      assert.ok(Buffer.from(raw.bytes).equals(inboundRaw));
      assert.equal((await e.syncMailboxNow(service(), mailboxId)).ingested, 0);
      assert.ok(api.seen.some((r) => r.path.startsWith('/gmail/v1/users/me/history?startHistoryId=500')));
      // A rejected refresh token is an explicit failure and its value never appears in errors or stored state.
      await e.setMailboxCredentials(a, mailboxId, { oauthClientSecret: 'client-secret-1', oauthRefreshToken: 'refresh-secret-2' });
      sendMode = 'ok';
      const bad = await e.getDispatch(a, await send('four@example.net'));
      assert.equal(bad.state, 'failed');
      assert.ok(!JSON.stringify([bad, await e.audit(a), await h.sql.query('select * from e03_correspondence._jobs')]).match(/refresh-secret|client-secret|access-\d/));
    });
  } finally { await api.close(); }
});

test('Microsoft Graph adapter: MIME sendMail, acceptance without id, lookup by internetMessageId', { skip }, async () => {
  const held = new Set<string>(); let drop = false;
  const api = await fakeApi((r) => {
    if (r.path === '/token') return { status: 200, json: { access_token: 'access-1', expires_in: 3600, refresh_token: 'rotated-refresh' } };
    if (r.method === 'POST' && r.path === '/v1.0/users/desk@example.org/sendMail') {
      assert.equal(r.type, 'text/plain');
      held.add(/^Message-ID: (<[^>]+>)/m.exec(Buffer.from(r.body, 'base64').toString('utf8'))![1]!);
      return drop ? { status: -1 } : { status: 202 };
    }
    if (r.path.startsWith('/v1.0/users/desk@example.org/messages?')) { const mid = /internetMessageId eq '(<[^>]+>)'/.exec(r.path)![1]!; return { status: 200, json: { value: held.has(mid) ? [{ id: 'AAMk1', internetMessageId: mid, isDraft: false }] : [] } }; }
    return undefined;
  });
  try {
    await withHarness(async (h) => {
      const e = h.engine; const a = human();
      const mb = await e.createMailbox(a, { address: 'desk@example.org', provider: 'graph', senderProfile: PROFILE, config: { oauth: { tokenUrl: `${api.url}/token`, clientId: 'c', scope: 'https://graph.microsoft.com/.default offline_access' }, accountId: 'desk@example.org', apiBaseUrl: api.url }, credentials: { oauthRefreshToken: 'first-refresh' } });
      await e.verifySenderProfile(a, mb.id as string);
      const send = async () => { const d = await e.sendMessage(a, (await e.createDraft(a, { mailboxId: mb.id as string, to: ['one@example.net'], subject: 'Hello', body: 'Text' })).id as string); await e.runWorkerOnce(); return d.id as string; };
      assert.equal((await e.getDispatch(a, await send())).state, 'accepted');
      // The token endpoint rotated the refresh token: it was re-sealed, not exposed.
      const sealed = (await h.sql.query<{ secret_enc: string }>('select secret_enc from e03_correspondence.mailboxes'))[0]!.secret_enc;
      assert.ok(!sealed.includes('rotated-refresh'));
      drop = true; const lost = await send(); drop = false;
      assert.equal((await e.getDispatch(a, lost)).state, 'uncertain');
      await drain(e);
      assert.deepEqual([(await e.getDispatch(a, lost)).state, (await e.getDispatch(a, lost)).providerId], ['accepted', 'AAMk1']);
      assert.equal(api.seen.filter((r) => r.path.endsWith('/sendMail')).length, 2);
    });
  } finally { await api.close(); }
});

test('deterministic mail rules: classification, opt-out, candidates with offsets, disclosure, identity claims', async () => {
  const cls = async (headers: string[], body: string) => (await parseInbound(reply({ from: 'a@example.net', to: 'b@example.org', body, headers }))).classification.kind;
  assert.equal(await cls([], 'The answer is in the ledger.'), 'reply');
  assert.equal(await cls(['Auto-Submitted: auto-replied'], 'Out of office.'), 'auto_reply');
  assert.equal(await cls(['Precedence: bulk'], 'Newsletter.'), 'auto_reply');
  assert.equal(await cls(['X-Failed-Recipients: gone@example.net'], 'Delivery failed.'), 'bounce');
  for (const text of ['STOP', 'unsubscribe', 'Please remove me from your list.', "Don't email me again.", 'I want no further contact on this matter.']) assert.equal(await cls([], text), 'refusal', text);
  assert.equal(await cls([], 'We could not stop the transfer in time.\r\n\r\n> reply STOP to opt out'), 'reply');
  const parsed = await parseInbound(Buffer.from('Subject: no id\r\n\r\nbody'));
  assert.match(parsed.dedupeKey, /^sha256:[0-9a-f]{64}$/); assert.equal(parsed.from, null);
  const body = 'Hi,\n\nThe depot closed in 2018 after the flood.\n\nOn Mon, 2 Nov 2026 someone wrote:\n> The depot closed when?\n';
  const c = assertionCandidates(body);
  assert.deepEqual(c.map((x) => x.text), ['The depot closed in 2018 after the flood.']);
  assert.equal(body.slice(c[0]!.start, c[0]!.end), c[0]!.text);
  assert.match(renderDisclosure(PROFILE, true), /automated research assistant operated by Example Records Project.*not written by a person.*editors@example\.org.*STOP/);
  assert.doesNotMatch(renderDisclosure(PROFILE, false), /automated/);
  assert.deepEqual(findIdentityClaims('I am a senior investigative reporter. As your attorney, I advise it.', PROFILE), ['attorney', 'reporter']);
  assert.deepEqual(findIdentityClaims('We believe you were the custodian, as the official register lists you as a person who may know.', PROFILE), []);
  assert.deepEqual(findIdentityClaims('Regards, Dr. A. Person', PROFILE), ['title']);
});
