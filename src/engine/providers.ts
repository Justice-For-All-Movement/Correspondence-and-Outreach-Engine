// Real provider adapters: SMTP (nodemailer), IMAP (imapflow), Gmail API and Microsoft Graph (fetch + OAuth2 refresh tokens).
// Credentials are decrypted only here, held in memory for one operation, and never returned, logged or placed in errors.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import SMTPConnection from 'nodemailer/lib/smtp-connection';
import MailComposer from 'nodemailer/lib/mail-composer';
import XOAuth2 from 'nodemailer/lib/xoauth2';
import { ImapFlow } from 'imapflow';
import { DomainError, invariant } from '../contracts.ts';
import type { Json } from '../contracts.ts';
import { parseProviderSendResponse } from '../adapters.ts';
import { readSyncPage } from '../sync-providers.ts';
import { syncLimits } from '../sync-http.ts';
import type { MailboxSyncState, ReadOnlyMailboxTransport, SyncBinding, SyncCursor } from '../sync-types.ts';

// ───────────────────────────── Secrets (AES-256-GCM) ─────────────────────────────
export type MailboxSecrets = Readonly<{ smtpPassword?: string; imapPassword?: string; oauthClientSecret?: string; oauthRefreshToken?: string }>;
export const SECRET_FIELDS: readonly (keyof MailboxSecrets)[] = ['smtpPassword', 'imapPassword', 'oauthClientSecret', 'oauthRefreshToken'];

/** Accepts 32 bytes as base64, base64url or 64 hex characters. */
export function parseSecretKey(value: string | undefined): Buffer | null {
  if (value === undefined || value === '') return null;
  const key = /^[0-9a-fA-F]{64}$/.test(value) ? Buffer.from(value, 'hex') : Buffer.from(value, value.includes('-') || value.includes('_') ? 'base64url' : 'base64');
  invariant(key.byteLength === 32, 'invalid_config', 'CORRESPONDENCE_SECRET_KEY must decode to 32 bytes');
  return key;
}
export function sealSecrets(key: Buffer, aad: string, secrets: MailboxSecrets): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(JSON.stringify(secrets), 'utf8'), cipher.final()]);
  return `v1.${iv.toString('base64url')}.${cipher.getAuthTag().toString('base64url')}.${ct.toString('base64url')}`;
}
export function openSecrets(key: Buffer, aad: string, sealed: string): MailboxSecrets {
  try {
    const [v, iv, tag, ct] = sealed.split('.');
    if (v !== 'v1' || iv === undefined || tag === undefined || ct === undefined) throw new Error('format');
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
    decipher.setAAD(Buffer.from(aad)); decipher.setAuthTag(Buffer.from(tag, 'base64url'));
    return JSON.parse(Buffer.concat([decipher.update(Buffer.from(ct, 'base64url')), decipher.final()]).toString('utf8')) as MailboxSecrets;
  } catch { throw new DomainError('unavailable', 'Stored mailbox credentials cannot be decrypted with the configured key'); }
}

// ───────────────────────────── Configuration ─────────────────────────────
export type MailboxProvider = 'smtp_imap' | 'gmail' | 'graph' | 'ingest_only';
export type MailboxConfig = Readonly<{
  smtp?: Readonly<{ host: string; port: number; secure?: boolean; requireTLS?: boolean; auth: 'password' | 'xoauth2' | 'none'; username?: string }>;
  imap?: Readonly<{ host: string; port: number; secure?: boolean; auth: 'password' | 'xoauth2'; username?: string; inbox?: string; sentFolder?: string; extraFolders?: readonly string[] }>;
  oauth?: Readonly<{ tokenUrl: string; clientId: string; scope?: string }>;
  /** Gmail/Graph account id as the provider names it ("me", an address or an object id). */
  accountId?: string;
  /** Graph mail folder to synchronize; defaults to "inbox". */
  folderId?: string;
  /** Replacement origin for the Gmail/Graph API; accepted only when the engine allows endpoint overrides (tests). */
  apiBaseUrl?: string;
}>;
export type ProviderPolicy = Readonly<{
  /** Permit loopback/private hosts and plain http endpoints. For controlled test servers only. */
  allowPrivateHosts: boolean; allowEndpointOverride: boolean; allowInsecureTls: boolean;
  allowedOAuthHosts: readonly string[]; timeoutMs: number; maxMessageBytes: number;
}>;
export const DEFAULT_PROVIDER_POLICY: ProviderPolicy = {
  allowPrivateHosts: false, allowEndpointOverride: false, allowInsecureTls: false,
  allowedOAuthHosts: ['oauth2.googleapis.com', 'login.microsoftonline.com'], timeoutMs: 30_000, maxMessageBytes: 25 * 1024 * 1024,
};

function privateHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || !h.includes('.') && isIP(h) === 0) return true;
  if (isIP(h) === 4) { const [a, b] = h.split('.').map(Number) as [number, number]; return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127); }
  if (isIP(h) === 6) return h === '::1' || h === '::' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80') || h.startsWith('::ffff:');
  return false;
}
function host(value: unknown, policy: ProviderPolicy): string {
  invariant(typeof value === 'string' && /^[A-Za-z0-9.:[\]-]{1,253}$/.test(value), 'invalid_input', 'Invalid host');
  invariant(policy.allowPrivateHosts || !privateHost(value), 'invalid_input', 'Private, loopback and unqualified hosts are not allowed');
  return value;
}
function port(value: unknown): number { invariant(Number.isInteger(value) && (value as number) > 0 && (value as number) < 65536, 'invalid_input', 'Invalid port'); return value as number; }
function httpsUrl(value: unknown, policy: ProviderPolicy, label: string): URL {
  let url: URL;
  try { url = new URL(String(value)); } catch { throw new DomainError('invalid_input', `Invalid ${label}`); }
  invariant(url.username === '' && url.password === '' && url.hash === '', 'invalid_input', `Invalid ${label}`);
  invariant(url.protocol === 'https:' || (policy.allowPrivateHosts && url.protocol === 'http:'), 'invalid_input', `${label} must use https`);
  invariant(policy.allowPrivateHosts || !privateHost(url.hostname), 'invalid_input', `${label} host is not allowed`);
  return url;
}
const folder = (value: unknown): string => { invariant(typeof value === 'string' && value.length > 0 && value.length <= 200 && !/[\r\n\u0000]/.test(value), 'invalid_input', 'Invalid folder'); return value; };
const short = (value: unknown, label: string, max = 320): string => { invariant(typeof value === 'string' && value.length > 0 && value.length <= max && !/[\r\n\u0000]/.test(value), 'invalid_input', `Invalid ${label}`); return value; };

/** Validates non-secret connection settings. Unknown fields are rejected so secrets cannot be smuggled into config. */
export function validateMailboxConfig(provider: MailboxProvider, value: unknown, policy: ProviderPolicy): MailboxConfig {
  invariant(value !== null && typeof value === 'object' && !Array.isArray(value), 'invalid_input', 'Mailbox config must be an object');
  const v = value as Record<string, Record<string, unknown> | string | undefined>;
  const only = (o: Record<string, unknown>, keys: string[]): void => invariant(Object.keys(o).every((k) => keys.includes(k)), 'invalid_input', 'Unknown mailbox config field');
  only(v, ['smtp', 'imap', 'oauth', 'accountId', 'folderId', 'apiBaseUrl']);
  const out: { -readonly [K in keyof MailboxConfig]: MailboxConfig[K] } = {};
  if (provider === 'smtp_imap') {
    invariant(typeof v.smtp === 'object' || typeof v.imap === 'object', 'invalid_input', 'smtp or imap settings are required');
    if (typeof v.smtp === 'object') {
      const s = v.smtp; only(s, ['host', 'port', 'secure', 'requireTLS', 'auth', 'username']);
      invariant(['password', 'xoauth2', 'none'].includes(s.auth as string), 'invalid_input', 'smtp.auth must be password, xoauth2 or none');
      out.smtp = { host: host(s.host, policy), port: port(s.port), secure: s.secure === true, requireTLS: s.requireTLS === true, auth: s.auth as 'password', ...(s.username === undefined ? {} : { username: short(s.username, 'username') }) };
      invariant(out.smtp.auth === 'none' || out.smtp.username !== undefined, 'invalid_input', 'smtp.username is required');
      invariant(policy.allowPrivateHosts || out.smtp.secure === true || out.smtp.requireTLS === true, 'invalid_input', 'SMTP must use TLS (secure or requireTLS)');
    }
    if (typeof v.imap === 'object') {
      const s = v.imap; only(s, ['host', 'port', 'secure', 'auth', 'username', 'inbox', 'sentFolder', 'extraFolders']);
      invariant(['password', 'xoauth2'].includes(s.auth as string), 'invalid_input', 'imap.auth must be password or xoauth2');
      const extra = s.extraFolders ?? [];
      invariant(Array.isArray(extra) && extra.length <= 10, 'invalid_input', 'Invalid extraFolders');
      out.imap = { host: host(s.host, policy), port: port(s.port), secure: s.secure === true, auth: s.auth as 'password', username: short(s.username, 'username'), inbox: folder(s.inbox ?? 'INBOX'),
        ...(s.sentFolder === undefined ? {} : { sentFolder: folder(s.sentFolder) }), extraFolders: (extra as unknown[]).map(folder) };
      invariant(policy.allowPrivateHosts || out.imap.secure === true, 'invalid_input', 'IMAP must use TLS');
    }
  } else invariant(v.smtp === undefined && v.imap === undefined, 'invalid_input', 'smtp/imap settings apply only to smtp_imap mailboxes');
  const needsOAuth = provider === 'gmail' || provider === 'graph' || out.smtp?.auth === 'xoauth2' || out.imap?.auth === 'xoauth2';
  if (needsOAuth) {
    invariant(typeof v.oauth === 'object', 'invalid_input', 'oauth settings are required');
    const o = v.oauth; only(o, ['tokenUrl', 'clientId', 'scope']);
    const url = httpsUrl(o.tokenUrl, policy, 'oauth.tokenUrl');
    invariant(policy.allowPrivateHosts || policy.allowedOAuthHosts.includes(url.hostname), 'invalid_input', 'oauth.tokenUrl host is not an allowed token endpoint');
    out.oauth = { tokenUrl: url.toString(), clientId: short(o.clientId, 'clientId', 500), ...(o.scope === undefined ? {} : { scope: short(o.scope, 'scope', 1000) }) };
  } else invariant(v.oauth === undefined, 'invalid_input', 'oauth settings are not used by this mailbox');
  if (provider === 'gmail' || provider === 'graph') {
    out.accountId = v.accountId === undefined ? 'me' : short(v.accountId, 'accountId');
    invariant(/^[A-Za-z0-9_+=./:@-]+$/.test(out.accountId), 'invalid_input', 'Invalid accountId');
    if (provider === 'graph') { out.folderId = v.folderId === undefined ? 'inbox' : short(v.folderId, 'folderId'); invariant(/^[A-Za-z0-9_+=./:@-]+$/.test(out.folderId), 'invalid_input', 'Invalid folderId'); }
    if (v.apiBaseUrl !== undefined) { invariant(policy.allowEndpointOverride, 'invalid_input', 'apiBaseUrl overrides are disabled'); out.apiBaseUrl = httpsUrl(v.apiBaseUrl, policy, 'apiBaseUrl').origin; }
  } else invariant(v.accountId === undefined && v.folderId === undefined && v.apiBaseUrl === undefined, 'invalid_input', 'accountId/folderId/apiBaseUrl apply only to gmail and graph mailboxes');
  return out;
}
export function validateSecrets(value: unknown): MailboxSecrets {
  invariant(value !== null && typeof value === 'object' && !Array.isArray(value), 'invalid_input', 'Credentials must be an object');
  const v = value as Record<string, unknown>;
  invariant(Object.keys(v).length > 0 && Object.keys(v).every((k) => (SECRET_FIELDS as readonly string[]).includes(k)), 'invalid_input', 'Unknown credential field');
  for (const k of Object.keys(v)) invariant(typeof v[k] === 'string' && (v[k] as string).length > 0 && (v[k] as string).length <= 8192, 'invalid_input', 'Invalid credential value');
  return v as MailboxSecrets;
}
/** Names what is missing before a provider can be used; an empty list means configured. */
export function missingCredentials(provider: MailboxProvider, config: MailboxConfig, secrets: MailboxSecrets | null, use: 'send' | 'read'): string[] {
  const missing: string[] = []; const s = secrets ?? {};
  const oauth = (): void => { if (s.oauthRefreshToken === undefined) missing.push('oauthRefreshToken'); };
  if (provider === 'ingest_only') missing.push(use === 'send' ? 'an outbound provider (mailbox is ingest-only)' : 'a readable provider (mailbox is ingest-only)');
  else if (provider === 'smtp_imap') {
    if (use === 'send') { if (config.smtp === undefined) missing.push('smtp settings'); else if (config.smtp.auth === 'password' && s.smtpPassword === undefined) missing.push('smtpPassword'); else if (config.smtp.auth === 'xoauth2') oauth(); }
    else if (config.imap === undefined) missing.push('imap settings'); else if (config.imap.auth === 'password' && s.imapPassword === undefined) missing.push('imapPassword'); else if (config.imap.auth === 'xoauth2') oauth();
  } else oauth();
  return missing;
}

// ───────────────────────────── MIME ─────────────────────────────
export type ComposeInput = Readonly<{
  from: Readonly<{ name: string; address: string }>; to: readonly string[]; cc: readonly string[]; subject: string; text: string;
  messageId: string; inReplyTo: string | null; references: readonly string[]; date: Date; automated: boolean;
  attachments: readonly Readonly<{ filename: string; mediaType: string; content: Uint8Array }>[];
}>;
/** Plain text only: no HTML part, no remote content, no tracking. Automated mail is labelled per RFC 3834. */
export async function composeMime(input: ComposeInput): Promise<Buffer> {
  const composer = new MailComposer({
    from: { name: input.from.name, address: input.from.address }, to: [...input.to], ...(input.cc.length === 0 ? {} : { cc: [...input.cc] }),
    subject: input.subject, text: input.text.replace(/\r?\n/g, '\r\n'), newline: '\r\n', messageId: input.messageId, date: input.date,
    ...(input.inReplyTo === null ? {} : { inReplyTo: input.inReplyTo }), ...(input.references.length === 0 ? {} : { references: [...input.references] }),
    headers: input.automated ? { 'Auto-Submitted': 'auto-generated', 'X-Automated-Sender': 'research-assistant' } : {},
    attachments: input.attachments.map((a) => ({ filename: a.filename, contentType: a.mediaType, content: Buffer.from(a.content) })),
    disableFileAccess: true, disableUrlAccess: true, xMailer: false, textEncoding: 'quoted-printable',
  });
  return composer.compile().build();
}

// ───────────────────────────── Outcomes ─────────────────────────────
export type SendOutcome =
  | Readonly<{ kind: 'accepted'; providerId: string | null; response: string }>
  /** The provider answered that it did not take the message, or it was never offered: safe to retry or fix. */
  | Readonly<{ kind: 'rejected'; permanent: boolean; code: string; response: string }>
  /** The message may or may not have been accepted. Must be reconciled, never resent blindly. */
  | Readonly<{ kind: 'uncertain'; reason: string }>;
export type LookupOutcome =
  | Readonly<{ kind: 'found'; providerId: string | null; where: string }>
  | Readonly<{ kind: 'absent'; searched: readonly string[]; conclusive: boolean }>
  | Readonly<{ kind: 'unavailable'; reason: string }>;
export type SyncBatch = Readonly<{ messages: readonly Readonly<{ providerId: string; raw: Uint8Array }>[]; skipped: readonly Readonly<{ providerId: string; reason: string }>[]; state: Json; more: boolean; resets: number }>;
export interface MailAdapter {
  send(envelope: { from: string; to: readonly string[] }, raw: Buffer, messageId: string): Promise<SendOutcome>;
  lookup(messageId: string): Promise<LookupOutcome>;
  sync(state: Json, limit: number): Promise<SyncBatch>;
  verify(): Promise<{ send: string; read: string }>;
}
export type AdapterInput = Readonly<{
  provider: MailboxProvider; address: string; config: MailboxConfig; secrets: MailboxSecrets | null; policy: ProviderPolicy;
  scope: Readonly<{ tenantId: string; projectId: string; mailboxId: string; authEpoch: number }>;
  /** Called when the token endpoint rotates the refresh token, so the caller can re-seal it. */
  onRefreshTokenRotated?: (token: string) => Promise<void>;
}>;
/** Removes anything that could echo a credential or split a log line; provider text is kept short. */
export function sanitizeResponse(value: unknown): string { return String(value ?? '').replace(/[\r\n\t]+/g, ' ').replace(/[^\x20-\x7e]/g, '?').slice(0, 300); }

// ───────────────────────────── OAuth2 refresh ─────────────────────────────
const tokenCache = new Map<string, { token: string; expires: number }>();
async function accessToken(input: AdapterInput): Promise<string> {
  const { config, secrets, scope } = input;
  if (config.oauth === undefined || secrets?.oauthRefreshToken === undefined) throw new DomainError('provider_unavailable', 'OAuth credentials are not configured');
  const key = `${scope.tenantId}/${scope.projectId}/${scope.mailboxId}/${scope.authEpoch}`;
  const cached = tokenCache.get(key);
  if (cached !== undefined && cached.expires > Date.now() + 60_000) return cached.token;
  const form = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: secrets.oauthRefreshToken, client_id: config.oauth.clientId });
  if (secrets.oauthClientSecret !== undefined) form.set('client_secret', secrets.oauthClientSecret);
  if (config.oauth.scope !== undefined) form.set('scope', config.oauth.scope);
  let response: Response;
  try { response = await fetch(config.oauth.tokenUrl, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' }, body: form, redirect: 'error', signal: AbortSignal.timeout(input.policy.timeoutMs) }); }
  catch { throw new DomainError('provider_unavailable', 'OAuth token endpoint could not be reached'); }
  // The response body may echo tokens; only the status and the standard error code are surfaced.
  let body: Record<string, unknown> = {};
  try { body = await response.json() as Record<string, unknown>; } catch { /* non-JSON body is discarded */ }
  if (!response.ok || typeof body.access_token !== 'string') {
    const code = typeof body.error === 'string' && /^[a-z_]{1,40}$/.test(body.error) ? body.error : 'unknown';
    throw new DomainError(response.status >= 500 ? 'provider_unavailable' : 'provider_auth_failed', `OAuth refresh was not accepted (status ${response.status}, ${code})`);
  }
  tokenCache.set(key, { token: body.access_token, expires: Date.now() + (typeof body.expires_in === 'number' ? body.expires_in : 300) * 1000 });
  if (typeof body.refresh_token === 'string' && body.refresh_token !== secrets.oauthRefreshToken && input.onRefreshTokenRotated !== undefined) await input.onRefreshTokenRotated(body.refresh_token);
  return body.access_token;
}
/** Drops cached access tokens for a mailbox (credentials changed or revoked). */
export function forgetTokens(scope: { tenantId: string; projectId: string; mailboxId: string }): void {
  for (const key of tokenCache.keys()) if (key.startsWith(`${scope.tenantId}/${scope.projectId}/${scope.mailboxId}/`)) tokenCache.delete(key);
}

// ───────────────────────────── SMTP + IMAP ─────────────────────────────
type SmtpError = Error & { code?: string; responseCode?: number; response?: string; command?: string };
async function smtpAuth(input: AdapterInput): Promise<Record<string, unknown> | null> {
  const smtp = input.config.smtp!;
  if (smtp.auth === 'none') return null;
  if (smtp.auth === 'password') return { user: smtp.username, pass: input.secrets!.smtpPassword };
  return { type: 'OAuth2', user: smtp.username, oauth2: new XOAuth2({ user: smtp.username, accessToken: await accessToken(input) }, false) };
}
function smtpConnection(input: AdapterInput): SMTPConnection {
  const smtp = input.config.smtp!; const t = input.policy.timeoutMs;
  return new SMTPConnection({ host: smtp.host, port: smtp.port, secure: smtp.secure === true, requireTLS: smtp.requireTLS === true,
    ignoreTLS: input.policy.allowPrivateHosts && smtp.secure !== true && smtp.requireTLS !== true, connectionTimeout: t, greetingTimeout: t, socketTimeout: t, dnsTimeout: t,
    tls: { rejectUnauthorized: !input.policy.allowInsecureTls }, logger: false });
}
function smtpSession<T>(input: AdapterInput, auth: Record<string, unknown> | null, run: (conn: SMTPConnection, finish: (value: T) => void, setPhase: (p: 'send') => void) => void,
  failed: (phase: 'connect' | 'auth' | 'send', error: SmtpError) => T): Promise<T> {
  return new Promise((resolve) => {
    const conn = smtpConnection(input);
    let phase: 'connect' | 'auth' | 'send' = 'connect'; let done = false;
    const finish = (value: T): void => { if (done) return; done = true; clearTimeout(timer); try { conn.close(); } catch { /* already closed */ } resolve(value); };
    const timer = setTimeout(() => finish(failed(phase, Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }))), input.policy.timeoutMs * 3);
    conn.on('error', (error: SmtpError) => finish(failed(phase, error)));
    conn.connect(() => {
      const go = (): void => run(conn, finish, (p) => { phase = p; });
      if (auth === null) return go();
      phase = 'auth';
      conn.login(auth, (error) => (error ? finish(failed('auth', error as SmtpError)) : go()));
    });
  });
}
async function imapClient(input: AdapterInput): Promise<ImapFlow> {
  const imap = input.config.imap!;
  const auth = imap.auth === 'password' ? { user: imap.username!, pass: input.secrets!.imapPassword! } : { user: imap.username!, accessToken: await accessToken(input) };
  const client = new ImapFlow({ host: imap.host, port: imap.port, secure: imap.secure === true, auth, logger: false, disableAutoIdle: true,
    tls: { rejectUnauthorized: !input.policy.allowInsecureTls }, connectionTimeout: input.policy.timeoutMs, greetingTimeout: input.policy.timeoutMs, socketTimeout: input.policy.timeoutMs * 2 } as ConstructorParameters<typeof ImapFlow>[0]);
  client.on('error', () => { /* surfaced through the awaiting command */ });
  try { await client.connect(); }
  catch (error) {
    try { client.close(); } catch { /* not open */ }
    const authFailed = (error as { authenticationFailed?: boolean }).authenticationFailed === true;
    throw new DomainError(authFailed ? 'provider_auth_failed' : 'provider_unavailable', authFailed ? 'IMAP authentication was rejected' : 'IMAP server could not be reached');
  }
  return client;
}
async function withImap<T>(input: AdapterInput, fn: (client: ImapFlow) => Promise<T>): Promise<T> {
  const client = await imapClient(input);
  try { return await fn(client); }
  catch (error) { if (error instanceof DomainError) throw error; throw new DomainError('provider_unavailable', 'IMAP operation failed'); }
  finally { try { await client.logout(); } catch { try { client.close(); } catch { /* closed */ } } }
}
type ImapState = { folders: Record<string, { uidValidity: string; lastUid: number }> };

function smtpImapAdapter(input: AdapterInput): MailAdapter {
  const { config, policy } = input;
  return {
    async send(envelope, raw) {
      let auth: Record<string, unknown> | null;
      try { auth = await smtpAuth(input); }
      catch (error) { return { kind: 'rejected', permanent: error instanceof DomainError && error.code === 'provider_auth_failed', code: 'oauth', response: error instanceof DomainError ? error.message : 'OAuth failed' }; }
      return smtpSession<SendOutcome>(input, auth, (conn, finish, setPhase) => {
        setPhase('send');
        conn.send({ from: envelope.from, to: [...envelope.to] }, raw, (error, info) => {
          if (error) return finish(sendFailure('send', error as SmtpError));
          conn.quit();
          finish({ kind: 'accepted', providerId: info.serverMessageId ?? null, response: sanitizeResponse(`${info.response}${info.rejected.length > 0 ? ` (rejected recipients: ${info.rejected.length})` : ''}`) });
        });
      }, sendFailure);
      function sendFailure(phase: 'connect' | 'auth' | 'send', error: SmtpError): SendOutcome {
        // Before the message was offered nothing can have been delivered.
        if (phase === 'connect') return { kind: 'rejected', permanent: false, code: error.code ?? 'ECONNECTION', response: 'SMTP server could not be reached' };
        if (phase === 'auth') return { kind: 'rejected', permanent: true, code: 'EAUTH', response: 'SMTP authentication was rejected' };
        // The server replied with an explicit refusal (envelope, DATA or end-of-data): not accepted.
        if (typeof error.responseCode === 'number' && error.responseCode >= 400) return { kind: 'rejected', permanent: error.responseCode >= 500, code: error.code ?? 'EMESSAGE', response: sanitizeResponse(error.response ?? `SMTP ${error.responseCode}`) };
        // Timeout or connection loss after the transaction started: the server may hold the message.
        return { kind: 'uncertain', reason: `connection ended during SMTP transaction (${sanitizeResponse(error.code ?? 'unknown')})` };
      }
    },
    async lookup(messageId) {
      if (config.imap === undefined) return { kind: 'unavailable', reason: 'no IMAP settings: the provider cannot be queried for the message' };
      const missing = missingCredentials('smtp_imap', config, input.secrets, 'read');
      if (missing.length > 0) return { kind: 'unavailable', reason: `missing ${missing.join(', ')}` };
      const folders = [...new Set([config.imap.sentFolder, config.imap.inbox ?? 'INBOX', ...(config.imap.extraFolders ?? [])].filter((f): f is string => f !== undefined))];
      try {
        return await withImap<LookupOutcome>(input, async (client) => {
          for (const path of folders) {
            const lock = await client.getMailboxLock(path, { readOnly: true });
            try {
              const found = await client.search({ header: { 'message-id': messageId } }, { uid: true });
              if (Array.isArray(found) && found.length > 0) return { kind: 'found', providerId: `imap:${path}:${String((client.mailbox as { uidValidity: bigint }).uidValidity)}:${found[0]}`, where: path };
            } finally { lock.release(); }
          }
          // A generic SMTP relay does not file sent mail in IMAP, so absence proves nothing unless a sent folder is kept by the provider.
          return { kind: 'absent', searched: folders, conclusive: false };
        });
      } catch (error) { return { kind: 'unavailable', reason: error instanceof DomainError ? error.message : 'IMAP lookup failed' }; }
    },
    async sync(stateJson, limit) {
      const state: ImapState = { folders: structuredClone((stateJson as unknown as ImapState | null)?.folders ?? {}) };
      const imap = config.imap!;
      const messages: { providerId: string; raw: Uint8Array }[] = []; const skipped: { providerId: string; reason: string }[] = [];
      let more = false, resets = 0;
      await withImap(input, async (client) => {
        for (const path of [imap.inbox ?? 'INBOX', ...(imap.extraFolders ?? [])]) {
          if (messages.length >= limit) { more = true; break; }
          const lock = await client.getMailboxLock(path, { readOnly: true });
          try {
            const box = client.mailbox as { uidValidity: bigint; exists: number };
            const validity = String(box.uidValidity);
            let cp = state.folders[path];
            // A changed UIDVALIDITY invalidates every stored UID: rescan; ingestion stays idempotent by Message-ID.
            if (cp === undefined || cp.uidValidity !== validity) { if (cp !== undefined) resets++; cp = { uidValidity: validity, lastUid: 0 }; }
            if (box.exists > 0) {
              const found = await client.search({ uid: `${cp.lastUid + 1}:*` }, { uid: true });
              const uids = (Array.isArray(found) ? found : []).filter((u) => u > cp!.lastUid).sort((a, b) => a - b);
              const take = uids.slice(0, limit - messages.length);
              if (take.length < uids.length) more = true;
              if (take.length > 0) {
                const sizes = new Map<number, number>();
                for await (const m of client.fetch(take.join(','), { uid: true, size: true }, { uid: true })) sizes.set(m.uid, m.size ?? 0);
                const wanted = take.filter((u) => (sizes.get(u) ?? 0) <= policy.maxMessageBytes);
                for (const u of take) if (!wanted.includes(u)) skipped.push({ providerId: `imap:${path}:${validity}:${u}`, reason: 'message exceeds the size limit' });
                if (wanted.length > 0) for await (const m of client.fetch(wanted.join(','), { uid: true, source: true }, { uid: true })) {
                  if (m.source !== undefined) messages.push({ providerId: `imap:${path}:${validity}:${m.uid}`, raw: m.source });
                }
                cp.lastUid = take[take.length - 1] as number;
              }
            }
            state.folders[path] = cp;
          } finally { lock.release(); }
        }
      });
      return { messages, skipped, state: state as unknown as Json, more, resets };
    },
    async verify() {
      const out = { send: 'not configured', read: 'not configured' };
      if (config.smtp !== undefined) {
        const missing = missingCredentials('smtp_imap', config, input.secrets, 'send');
        if (missing.length > 0) out.send = `unavailable: missing ${missing.join(', ')}`;
        else try {
          const auth = await smtpAuth(input);
          out.send = await smtpSession<string>(input, auth, (conn, finish) => { conn.quit(); finish('ok'); }, (phase) => (phase === 'auth' ? 'failed: authentication rejected' : 'failed: server could not be reached'));
        } catch (error) { out.send = `failed: ${error instanceof DomainError ? error.message : 'error'}`; }
      }
      if (config.imap !== undefined) {
        const missing = missingCredentials('smtp_imap', config, input.secrets, 'read');
        if (missing.length > 0) out.read = `unavailable: missing ${missing.join(', ')}`;
        else try { await withImap(input, async (client) => { (await client.getMailboxLock(config.imap!.inbox ?? 'INBOX', { readOnly: true })).release(); }); out.read = 'ok'; }
        catch (error) { out.read = `failed: ${error instanceof DomainError ? error.message : 'error'}`; }
      }
      return out;
    },
  };
}

// ───────────────────────────── Gmail API and Microsoft Graph ─────────────────────────────
const ORIGINS = { gmail: 'https://gmail.googleapis.com', graph: 'https://graph.microsoft.com' } as const;
type HttpResult = { status: number; json: unknown; bytes: Uint8Array };
function httpApiAdapter(input: AdapterInput): MailAdapter {
  const provider = input.provider as 'gmail' | 'graph';
  const { config, policy } = input;
  const account = config.accountId ?? 'me';
  const origin = config.apiBaseUrl ?? ORIGINS[provider];
  const root = provider === 'gmail' ? `/gmail/v1/users/${encodeURIComponent(account)}` : account === 'me' ? '/v1.0/me' : `/v1.0/users/${encodeURIComponent(account)}`;
  const binding: SyncBinding = { tenantId: input.scope.tenantId, projectId: input.scope.projectId, mailboxId: input.scope.mailboxId, provider, accountRef: input.scope.mailboxId,
    authEpoch: input.scope.authEpoch, address: input.address, providerAccountId: account, folderId: provider === 'graph' ? (config.folderId ?? 'inbox') : null };
  // The API host is fixed; only the path and query of a request are caller-shaped. Redirects are refused.
  const target = (url: string): string => { const u = new URL(url, ORIGINS[provider]); invariant(u.origin === ORIGINS[provider], 'invalid_state', 'Provider request left its API host'); return `${origin}${u.pathname}${u.search}`; };
  async function call(method: string, path: string, body?: { type: string; data: string }, maxBytes = policy.maxMessageBytes * 2): Promise<HttpResult> {
    const token = await accessToken(input);
    const response = await fetch(target(path), { method, redirect: 'error', signal: AbortSignal.timeout(policy.timeoutMs),
      headers: { authorization: `Bearer ${token}`, accept: 'application/json', ...(body === undefined ? {} : { 'content-type': body.type }) }, ...(body === undefined ? {} : { body: body.data }) });
    const bytes = new Uint8Array(await response.arrayBuffer());
    invariant(bytes.byteLength <= maxBytes, 'provider_unavailable', 'Provider response exceeds the size limit');
    let json: unknown = null;
    if ((response.headers.get('content-type') ?? '').includes('json')) { try { json = JSON.parse(Buffer.from(bytes).toString('utf8')); } catch { /* treated as absent */ } }
    return { status: response.status, json, bytes };
  }
  const transport: ReadOnlyMailboxTransport = { binding, async read(request) {
    const token = await accessToken(input);
    const response = await fetch(target(request.url), { method: 'GET', redirect: 'error', headers: { ...request.headers, authorization: `Bearer ${token}` }, ...(request.signal === undefined ? {} : { signal: request.signal }) });
    return { status: response.status, body: (response.body ?? new ReadableStream<Uint8Array>({ start(c) { c.close(); } })) as unknown as AsyncIterable<Uint8Array> };
  } };
  const record = (v: unknown): Record<string, unknown> => (v !== null && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {});
  return {
    async send(_envelope, raw) {
      let result: HttpResult;
      try { await accessToken(input); }
      catch (error) { return { kind: 'rejected', permanent: error instanceof DomainError && error.code === 'provider_auth_failed', code: 'oauth', response: error instanceof DomainError ? error.message : 'OAuth failed' }; }
      try {
        result = provider === 'gmail' ? await call('POST', `${root}/messages/send`, { type: 'application/json', data: JSON.stringify({ raw: raw.toString('base64url') }) })
          : await call('POST', `${root}/sendMail`, { type: 'text/plain', data: raw.toString('base64') });
      } catch { return { kind: 'uncertain', reason: 'no response to the provider send request' }; }
      const outcome = parseProviderSendResponse(provider, result.status, result.json);
      if (outcome.kind === 'accepted') return { kind: 'accepted', providerId: outcome.providerMessageId, response: `HTTP ${result.status}` };
      if (outcome.kind === 'rejected') return { kind: 'rejected', permanent: true, code: outcome.code, response: `HTTP ${result.status}` };
      // Any other 4xx is an explicit refusal of this request; 5xx and malformed successes stay uncertain.
      if (result.status >= 400 && result.status < 500) return { kind: 'rejected', permanent: result.status !== 429 && result.status !== 408, code: `http-${result.status}`, response: `HTTP ${result.status}` };
      return { kind: 'uncertain', reason: `provider answered HTTP ${result.status} without confirming acceptance` };
    },
    async lookup(messageId) {
      try {
        if (provider === 'gmail') {
          const list = await call('GET', `${root}/messages?${new URLSearchParams({ q: `rfc822msgid:${messageId}`, maxResults: '10' })}`);
          if (list.status !== 200) return { kind: 'unavailable', reason: `provider lookup answered HTTP ${list.status}` };
          for (const item of (Array.isArray(record(list.json).messages) ? record(list.json).messages as unknown[] : []).slice(0, 10)) {
            const id = record(item).id;
            if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,200}$/.test(id)) continue;
            const meta = await call('GET', `${root}/messages/${id}?format=metadata&metadataHeaders=Message-ID`);
            const m = record(meta.json); const headers = Array.isArray(record(m.payload).headers) ? record(m.payload).headers as unknown[] : [];
            // A search hit alone is not evidence: the header must match and the message must be in Sent.
            if (meta.status === 200 && Array.isArray(m.labelIds) && m.labelIds.includes('SENT') && headers.some((h) => String(record(h).name).toLowerCase() === 'message-id' && record(h).value === messageId)) return { kind: 'found', providerId: id, where: 'SENT' };
          }
          return { kind: 'absent', searched: ['SENT'], conclusive: true };
        }
        const list = await call('GET', `${root}/messages?${new URLSearchParams({ $filter: `internetMessageId eq '${messageId.replaceAll("'", "''")}'`, $select: 'id,internetMessageId,isDraft', $top: '10' })}`);
        if (list.status !== 200) return { kind: 'unavailable', reason: `provider lookup answered HTTP ${list.status}` };
        for (const item of (Array.isArray(record(list.json).value) ? record(list.json).value as unknown[] : [])) {
          const m = record(item);
          if (typeof m.id === 'string' && m.internetMessageId === messageId && m.isDraft === false) return { kind: 'found', providerId: m.id.slice(0, 500), where: 'mailbox' };
        }
        return { kind: 'absent', searched: ['mailbox'], conclusive: true };
      } catch (error) { return { kind: 'unavailable', reason: error instanceof DomainError ? error.message : 'provider lookup failed' }; }
    },
    async sync(stateJson, limit) {
      const prior = record(stateJson);
      const state: MailboxSyncState = { binding, revision: typeof prior.revision === 'number' ? prior.revision : 0, cursor: (prior.cursor ?? null) as SyncCursor | null, records: [], quarantine: [] };
      const limits = syncLimits({ maxPages: 1, pageSize: Math.min(Math.max(limit, 1), 100), timeoutMs: Math.min(policy.timeoutMs, 60_000) });
      let page;
      try { page = await readSyncPage(binding, state, transport, limits); }
      catch (error) { throw new DomainError(error instanceof DomainError && error.code === 'sync_auth_denied' ? 'provider_auth_failed' : 'provider_unavailable', `Mailbox read failed (${error instanceof DomainError ? error.code : 'error'})`); }
      const messages: { providerId: string; raw: Uint8Array }[] = []; const skipped: { providerId: string; reason: string }[] = [];
      for (const change of page.changes) {
        if (change.message === null && !change.invalid) continue; // deleted at the provider: preserved copies are kept
        if (change.message?.draft === true) continue;
        const id = encodeURIComponent(change.id);
        const res = provider === 'gmail' ? await call('GET', `${root}/messages/${id}?format=raw`) : await call('GET', `${root}/messages/${id}/$value`);
        if (res.status === 404) continue;
        if (res.status !== 200) throw new DomainError('provider_unavailable', `Mailbox read answered HTTP ${res.status}`);
        const raw = provider === 'gmail' ? (typeof record(res.json).raw === 'string' ? new Uint8Array(Buffer.from(record(res.json).raw as string, 'base64url')) : null) : res.bytes;
        if (raw === null || raw.byteLength === 0) { skipped.push({ providerId: `${provider}:${change.id}`, reason: 'provider returned no original message bytes' }); continue; }
        if (raw.byteLength > policy.maxMessageBytes) { skipped.push({ providerId: `${provider}:${change.id}`, reason: 'message exceeds the size limit' }); continue; }
        messages.push({ providerId: `${provider}:${change.id}`, raw });
      }
      return { messages, skipped, state: { revision: state.revision + 1, cursor: page.cursor as unknown as Json }, more: page.cursor.kind === 'gmail-full' || (page.cursor.kind === 'graph-delta' && page.cursor.phase === 'next') || (page.cursor.kind === 'gmail-history' && page.cursor.pageToken !== null), resets: page.reset ? 1 : 0 };
    },
    async verify() {
      try {
        const res = provider === 'gmail' ? await call('GET', `${root}/profile`) : await call('GET', `${root}?$select=id,mail,userPrincipalName`);
        const status = res.status === 200 ? 'ok' : `failed: HTTP ${res.status}`;
        return { send: status, read: status };
      } catch (error) { const s = `failed: ${error instanceof DomainError ? error.message : 'provider could not be reached'}`; return { send: s, read: s }; }
    },
  };
}

export function createAdapter(input: AdapterInput): MailAdapter {
  if (input.provider === 'smtp_imap') return smtpImapAdapter(input);
  if (input.provider === 'gmail' || input.provider === 'graph') return httpApiAdapter(input);
  throw new DomainError('provider_unavailable', 'This mailbox has no provider connection (ingest-only)');
}
