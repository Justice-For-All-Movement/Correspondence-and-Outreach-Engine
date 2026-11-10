// Controlled mailbox for engine tests: a real SMTP sink (smtp-server) and a small IMAP4rev1 server on loopback sockets.
// This is test infrastructure, not proof against a live provider.
import { createServer } from 'node:net';
import type { AddressInfo, Server, Socket } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';
import { SMTPServer } from 'smtp-server';
import { FsObjectStore, withDisposableDatabase } from '../src/service-kit.ts';
import type { ServiceContext, Sql } from '../src/service-kit.ts';
import { createEngine, migrate } from '../src/engine/index.ts';
import type { CorrespondenceEngine, EngineConfig, Ports } from '../src/engine/index.ts';

export const DB = process.env.TEST_DATABASE_URL;
export const ALL = ['correspondence:read', 'correspondence:write', 'correspondence:send', 'correspondence:contact', 'correspondence:grant', 'correspondence:admin', 'correspondence:ingest', 'correspondence:sync', 'correspondence:upstream', 'correspondence:events'];
let seq = 0;
export function ctxOf(over: Partial<ServiceContext> & { kind?: 'human' | 'agent' | 'service'; actorId?: string } = {}): ServiceContext {
  const { kind, actorId, ...rest } = over;
  return { tenantId: 'org-a', projectId: 'proj-1', purpose: 'test', requestId: `req-${++seq}`, now: new Date().toISOString(),
    actor: { id: actorId ?? (kind === 'agent' ? 'agent-1' : kind === 'service' ? 'svc-1' : 'human-1'), kind: kind ?? 'human', roles: [] }, capabilities: ALL, compartments: [], ...rest };
}
export const human = (over: Partial<ServiceContext> = {}): ServiceContext => ctxOf({ kind: 'human', ...over });
export const agent = (over: Partial<ServiceContext> = {}): ServiceContext => ctxOf({ kind: 'agent', capabilities: ['correspondence:read', 'correspondence:write', 'correspondence:send', 'correspondence:contact'], ...over });
export const service = (over: Partial<ServiceContext> = {}): ServiceContext => ctxOf({ kind: 'service', capabilities: ['correspondence:ingest', 'correspondence:sync', 'correspondence:read', 'correspondence:events', 'correspondence:upstream'], ...over });

export type StoredMail = { uid: number; raw: Buffer; from: string; to: string[] };
export type MailWorld = {
  smtpPort: number; imapPort: number; password: string;
  /** What the provider actually holds, keyed by IMAP folder. */
  folders: Map<string, { uidValidity: number; nextUid: number; messages: StoredMail[] }>;
  /** `drop-after-data`: accept the message, then cut the connection before replying. */
  smtpMode: 'accept' | 'drop-after-data' | 'drop-after-data-lose' | 'reject-data' | 'reject-rcpt' | 'tempfail';
  smtpTransactions: number; imapCommands: string[];
  deliver(folder: string, raw: Buffer | string): StoredMail;
  close(): Promise<void>;
};
const messageIdOf = (raw: Buffer): string => /^Message-ID:\s*(<[^>]+>)/im.exec(raw.toString('latin1'))?.[1] ?? '';

export async function startMailWorld(): Promise<MailWorld> {
  const password = randomBytes(9).toString('base64url');
  const folders: MailWorld['folders'] = new Map([['INBOX', { uidValidity: 1001, nextUid: 1, messages: [] }], ['Sent', { uidValidity: 2001, nextUid: 1, messages: [] }]]);
  const world = { password, folders, smtpMode: 'accept', smtpTransactions: 0, imapCommands: [] } as unknown as MailWorld;
  world.deliver = (folder, raw) => {
    const f = folders.get(folder)!; const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw.replace(/\r?\n/g, '\r\n'));
    const mail = { uid: f.nextUid++, raw: bytes, from: '', to: [] }; f.messages.push(mail); return mail;
  };
  const sockets = new Set<Socket>();
  const smtp = new SMTPServer({ authOptional: false, disabledCommands: ['STARTTLS'], logger: false, allowInsecureAuth: true,
    onAuth(auth, _session, cb) { if (auth.username === 'mailbox-user' && auth.password === password) cb(null, { user: 'mailbox-user' }); else cb(new Error('Invalid credentials')); },
    onRcptTo(address, _session, cb) { if (world.smtpMode === 'reject-rcpt') { const e = Object.assign(new Error('No such user'), { responseCode: 550 }); cb(e); } else { void address; cb(); } },
    onData(stream, session, cb) {
      const chunks: Buffer[] = [];
      stream.on('data', (c: Buffer) => chunks.push(c));
      stream.on('end', () => {
        world.smtpTransactions++;
        const raw = Buffer.concat(chunks); const mode = world.smtpMode;
        if (mode === 'reject-data') return cb(Object.assign(new Error('Message refused by policy'), { responseCode: 554 }));
        if (mode === 'tempfail') return cb(Object.assign(new Error('Try again later'), { responseCode: 451 }));
        // The provider files its copy in Sent, as hosted mail services do.
        if (mode !== 'drop-after-data-lose') { const f = folders.get('Sent')!; f.messages.push({ uid: f.nextUid++, raw, from: session.envelope.mailFrom === false ? '' : session.envelope.mailFrom.address, to: session.envelope.rcptTo.map((r) => r.address) }); }
        if (mode === 'drop-after-data' || mode === 'drop-after-data-lose') { for (const s of sockets) s.destroy(); return; }
        cb();
      });
    } });
  smtp.server.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  smtp.on('error', () => undefined);
  await new Promise<void>((resolve) => smtp.listen(0, '127.0.0.1', () => resolve()));
  world.smtpPort = (smtp.server.address() as AddressInfo).port;

  const imapSockets = new Set<Socket>();
  const imap: Server = createServer((socket) => {
    imapSockets.add(socket); socket.on('close', () => imapSockets.delete(socket)); socket.on('error', () => undefined);
    let buffer = Buffer.alloc(0); let authed = false; let selected: string | null = null;
    let pending: { head: string; need: number } | null = null;
    const send = (line: string): void => { socket.write(`${line}\r\n`); };
    const tokens = (line: string): string[] => [...line.matchAll(/"((?:[^"\\]|\\.)*)"|(\([^)]*\))|(\S+)/g)].map((m) => m[1] !== undefined ? m[1].replace(/\\(.)/g, '$1') : (m[2] ?? m[3]) as string);
    const uidSet = (set: string, f: { messages: StoredMail[] }): StoredMail[] => {
      const max = f.messages.reduce((a, m) => Math.max(a, m.uid), 0);
      const wanted = new Set<number>();
      for (const part of set.split(',')) {
        const [a, b] = part.split(':'); const lo = a === '*' ? max : Number(a); const hi = b === undefined ? lo : b === '*' ? Math.max(max, lo) : Number(b);
        for (const m of f.messages) if (m.uid >= Math.min(lo, hi) && m.uid <= Math.max(lo, hi)) wanted.add(m.uid);
        if (b === '*' && lo > max && max > 0) wanted.add(max); // RFC 3501: n:* always includes the last message
      }
      return f.messages.filter((m) => wanted.has(m.uid));
    };
    const handle = (line: string): void => {
      const sp = line.indexOf(' '); const tag = line.slice(0, sp); const rest = line.slice(sp + 1); const t = tokens(rest); const cmd = (t[0] ?? '').toUpperCase();
      world.imapCommands.push(rest.replace(/^(LOGIN \S+ ).*/i, '$1***'));
      if (cmd === 'CAPABILITY') { send('* CAPABILITY IMAP4rev1'); return send(`${tag} OK done`); }
      if (cmd === 'LOGIN') { authed = t[1] === 'mailbox-user' && t[2] === password; return send(authed ? `${tag} OK logged in` : `${tag} NO [AUTHENTICATIONFAILED] invalid credentials`); }
      if (cmd === 'LOGOUT') { send('* BYE bye'); send(`${tag} OK bye`); return void socket.end(); }
      if (cmd === 'NOOP') return send(`${tag} OK noop`);
      if (!authed) return send(`${tag} BAD not authenticated`);
      if (cmd === 'LIST' || cmd === 'LSUB') {
        if (cmd === 'LIST' && t[2] === '') send('* LIST (\\Noselect) "/" ""');
        else if (cmd === 'LIST') for (const name of folders.keys()) if (t[2] === '*' || t[2] === '%' || t[2] === name) send(`* LIST (\\HasNoChildren) "/" "${name}"`);
        return send(`${tag} OK listed`);
      }
      if (cmd === 'SELECT' || cmd === 'EXAMINE') {
        const f = folders.get(t[1] ?? '');
        if (f === undefined) return send(`${tag} NO no such mailbox`);
        selected = t[1] as string;
        send(`* ${f.messages.length} EXISTS`); send('* 0 RECENT'); send('* FLAGS (\\Seen)'); send(`* OK [UIDVALIDITY ${f.uidValidity}] ok`); send(`* OK [UIDNEXT ${f.nextUid}] ok`);
        return send(`${tag} OK [${cmd === 'SELECT' ? 'READ-WRITE' : 'READ-ONLY'}] selected`);
      }
      if (cmd === 'CLOSE' || cmd === 'UNSELECT') { selected = null; return send(`${tag} OK closed`); }
      const f = selected === null ? undefined : folders.get(selected);
      if (cmd === 'UID' && f !== undefined) {
        const sub = (t[1] ?? '').toUpperCase();
        if (sub === 'SEARCH') {
          let found = f.messages;
          for (let i = 2; i < t.length; i++) {
            const k = (t[i] as string).toUpperCase();
            if (k === 'UID') found = uidSet(t[++i] as string, { messages: found }).filter((m) => f.messages.includes(m));
            else if (k === 'HEADER') { const name = (t[++i] as string).toLowerCase(); const value = t[++i] as string; found = found.filter((m) => name === 'message-id' && messageIdOf(m.raw) === value); }
            else if (k !== 'ALL') return send(`${tag} BAD unsupported search key ${k}`);
          }
          send(`* SEARCH${found.map((m) => ` ${m.uid}`).join('')}`); return send(`${tag} OK search done`);
        }
        if (sub === 'FETCH') {
          const items = (t[3] ?? '').toUpperCase();
          for (const m of uidSet(t[2] as string, f)) {
            const seqNo = f.messages.indexOf(m) + 1;
            const parts = [`UID ${m.uid}`];
            if (items.includes('RFC822.SIZE')) parts.push(`RFC822.SIZE ${m.raw.byteLength}`);
            if (items.includes('FLAGS')) parts.push('FLAGS ()');
            if (items.includes('BODY')) { socket.write(`* ${seqNo} FETCH (${parts.join(' ')} BODY[] {${m.raw.byteLength}}\r\n`); socket.write(m.raw); socket.write(')\r\n'); }
            else send(`* ${seqNo} FETCH (${parts.join(' ')})`);
          }
          return send(`${tag} OK fetch done`);
        }
      }
      send(`${tag} BAD unsupported command`);
    };
    send('* OK IMAP4rev1 test server ready');
    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        if (pending !== null) {
          if (buffer.byteLength < pending.need) return;
          pending.head += `"${buffer.subarray(0, pending.need).toString('utf8').replace(/(["\\])/g, '\\$1')}"`; buffer = buffer.subarray(pending.need); pending.need = 0;
        }
        const eol = buffer.indexOf('\r\n');
        if (eol < 0) return;
        const line = (pending?.head ?? '') + buffer.subarray(0, eol).toString('utf8'); buffer = buffer.subarray(eol + 2);
        const literal = /\{(\d+)(\+?)\}$/.exec(line);
        if (literal !== null) { pending = { head: line.slice(0, literal.index), need: Number(literal[1]) }; if (literal[2] !== '+') send('+ go ahead'); continue; }
        pending = null; handle(line);
      }
    });
  });
  await new Promise<void>((resolve) => imap.listen(0, '127.0.0.1', () => resolve()));
  world.imapPort = (imap.address() as AddressInfo).port;
  world.close = async () => {
    for (const s of [...sockets, ...imapSockets]) s.destroy();
    await new Promise<void>((resolve) => smtp.close(() => resolve()));
    await new Promise<void>((resolve) => imap.close(() => resolve()));
  };
  return world;
}

export type Harness = { sql: Sql; engine: CorrespondenceEngine; world: MailWorld; objectsDir: string; secretKey: string; make(config?: EngineConfig, ports?: Ports): CorrespondenceEngine };
/** Real PostgreSQL (disposable database), filesystem object store and the controlled mailbox. */
export async function withHarness(fn: (h: Harness) => Promise<void>, options: { config?: EngineConfig; ports?: Ports } = {}): Promise<void> {
  const world = await startMailWorld();
  const objectsDir = mkdtempSync(join(tmpdir(), 'e03-objects-'));
  const secretKey = randomBytes(32).toString('base64');
  try {
    await withDisposableDatabase(pg, DB as string, async (_url, sql) => {
      await migrate(sql);
      const make = (config: EngineConfig = {}, ports: Ports = options.ports ?? {}): CorrespondenceEngine => createEngine({ sql, objects: new FsObjectStore(objectsDir), ports,
        config: { secretKey, reconcileDelayMs: 0, ...options.config, ...config, provider: { allowPrivateHosts: true, allowEndpointOverride: true, timeoutMs: 4000, ...options.config?.provider, ...config.provider } } });
      await fn({ sql, engine: make(), world, objectsDir, secretKey, make });
    });
  } finally { await world.close(); rmSync(objectsDir, { recursive: true, force: true }); }
}
export const PROFILE = { organizationName: 'Example Records Project', assistantName: 'the Example Records assistant', humanContact: 'editors@example.org' };
/** A verified SMTP+IMAP mailbox on the controlled servers. */
export async function controlledMailbox(h: Harness, ctx: ServiceContext = human(), address = 'desk@example.org'): Promise<string> {
  const mb = await h.engine.createMailbox(ctx, { address, displayName: 'Example Records Desk', provider: 'smtp_imap', senderProfile: PROFILE,
    config: { smtp: { host: '127.0.0.1', port: h.world.smtpPort, auth: 'password', username: 'mailbox-user' }, imap: { host: '127.0.0.1', port: h.world.imapPort, auth: 'password', username: 'mailbox-user', inbox: 'INBOX', sentFolder: 'Sent' } },
    credentials: { smtpPassword: h.world.password, imapPassword: h.world.password } });
  await h.engine.verifySenderProfile(ctx, mb.id as string);
  return mb.id as string;
}
export async function drain(engine: CorrespondenceEngine, max = 20): Promise<void> { for (let i = 0; i < max; i++) if ((await engine.runWorkerOnce({ limit: 10 })) === 0) return; }
/** The outbox feed withholds rows while other transactions are open on the server, so tests poll. */
export async function eventsOf(engine: CorrespondenceEngine, ctx: ServiceContext, type: string, min = 1): Promise<{ type: string; subject: string; payload: any }[]> {
  for (let i = 0; i < 100; i++) {
    const found = (await engine.events(ctx, { limit: 1000 })).filter((e) => e.type === type);
    if (found.length >= min) return found as { type: string; subject: string; payload: any }[];
    await new Promise((r) => setTimeout(r, 100));
  }
  return [];
}
export function reply(input: { from: string; to: string; inReplyTo?: string; subject?: string; body: string; messageId?: string; headers?: string[] }): Buffer {
  const lines = [`From: ${input.from}`, `To: ${input.to}`, `Subject: ${input.subject ?? 'Re: your question'}`, `Message-ID: ${input.messageId ?? `<${randomUUID()}@mail.example.net>`}`, 'Date: Mon, 02 Nov 2026 10:00:00 +0000',
    ...(input.inReplyTo === undefined ? [] : [`In-Reply-To: ${input.inReplyTo}`, `References: ${input.inReplyTo}`]), ...(input.headers ?? []), 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8', '', input.body, ''];
  return Buffer.from(lines.join('\r\n'));
}
