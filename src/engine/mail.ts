// Deterministic mail rules: truthful identity rendering, role-claim screening, inbound parsing and classification.
// Everything here is pure; inbound content is treated as data and never yields recipients, grants or instructions.
import { createHash } from 'node:crypto';
import { simpleParser } from 'mailparser';
import type { AddressObject, ParsedMail } from 'mailparser';
import { invariant } from '../contracts.ts';
import { detectsOptOut, normalizeAddress } from '../validation.ts';

export type SenderProfile = Readonly<{
  /** Legal or public name of the operating organization; shown on every outbound message. */
  organizationName: string;
  /** Name of the automated assistant (not a personal name). */
  assistantName?: string;
  /** How a recipient reaches an accountable human (address, URL or phone as text). */
  humanContact: string;
  /** Professional roles the sender may truthfully claim; anything else on the deny list is rejected for agents. */
  permittedRoleClaims?: readonly string[];
  locale?: string;
}>;
export type DisclosureTemplate = Readonly<{
  automated: string; human: string; optOut: string; greeting: string; closing: string; contextLabel: string;
}>;
/** Wording is deployment data. Placeholders: {organizationName} {assistantName} {humanContact} {optOut}. */
export const DEFAULT_TEMPLATES: Readonly<Record<string, DisclosureTemplate>> = {
  en: {
    automated: 'This message was composed and sent by {assistantName}, an automated research assistant operated by {organizationName}. It was not written by a person. To reach a person, contact {humanContact}. {optOut}',
    human: 'Sent on behalf of {organizationName}. Contact: {humanContact}. {optOut}',
    optOut: 'Replying is optional. To receive no further messages, reply STOP.',
    greeting: 'Hello,', closing: 'Thank you for considering this request.', contextLabel: 'Context:',
  },
};
export const DEFAULT_ROLE_TERMS: readonly string[] = [
  'professor', 'scholar', 'academic', 'lecturer', 'researcher', 'scientist', 'historian', 'student', 'lawyer', 'attorney', 'solicitor',
  'barrister', 'counsel', 'paralegal', 'advocate', 'journalist', 'reporter', 'correspondent', 'editor', 'official', 'officer', 'inspector',
  'investigator', 'detective', 'prosecutor', 'judge', 'magistrate', 'notary', 'auditor', 'regulator', 'civil servant', 'public servant',
  'doctor', 'physician', 'representative of', 'member of', 'employee of', 'human', 'person', 'colleague',
];
export const DEFAULT_CLAIM_PREFIXES: readonly string[] = [
  "i am", "i'm", "i’m", "we are", "we're", "i work as", "i serve as", "i act as", "writing as", "writing to you as", "in my capacity as",
  "my role as", "speaking as",
];
/** Prefixes that claim an identity only at the start of a sentence ("As a journalist, …"). */
export const DEFAULT_SENTENCE_CLAIM_PREFIXES: readonly string[] = ['as'];
export const DEFAULT_OPT_OUT_PATTERNS: readonly string[] = [
  'unsubscribe', 'opt[- ]?out', 'do not (?:contact|email|write)', "don['’]?t (?:contact|email|write)", 'stop (?:contacting|emailing|writing|messaging)',
  'remove me', 'no further (?:contact|emails?|messages?|correspondence)', 'leave me alone',
];
export const DEFAULT_QUOTE_MARKERS: readonly string[] = ['^on .{0,200}wrote:\\s*$', '^-{2,}\\s*original message\\s*-{2,}', '^from:\\s.+', '^_{10,}$'];

export type MailRules = Readonly<{
  templates: Readonly<Record<string, DisclosureTemplate>>; roleTerms: readonly string[]; claimPrefixes: readonly string[]; sentenceClaimPrefixes: readonly string[];
  optOutPatterns: readonly string[]; quoteMarkers: readonly string[]; maxAutomatedBodyChars: number; defaultLocale: string;
}>;
export const DEFAULT_RULES: MailRules = {
  templates: DEFAULT_TEMPLATES, roleTerms: DEFAULT_ROLE_TERMS, claimPrefixes: DEFAULT_CLAIM_PREFIXES, sentenceClaimPrefixes: DEFAULT_SENTENCE_CLAIM_PREFIXES, optOutPatterns: DEFAULT_OPT_OUT_PATTERNS,
  quoteMarkers: DEFAULT_QUOTE_MARKERS, maxAutomatedBodyChars: 2400, defaultLocale: 'en',
};

const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u2028\u2029]/u;
const CONTROL_G = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/gu;
export function line(value: unknown, label: string, max: number): string {
  invariant(typeof value === 'string' && value.trim().length > 0 && value.length <= max, 'invalid_input', `${label} must be non-empty and at most ${max} characters`);
  invariant(!CONTROL.test(value) && !/[\r\n]/.test(value), 'invalid_input', `${label} must be a single line without control characters`);
  return value.trim();
}
export function freeText(value: unknown, label: string, max: number, allowEmpty = false): string {
  invariant(typeof value === 'string' && value.length <= max && (allowEmpty || value.trim().length > 0), 'invalid_input', `${label} must be text of at most ${max} characters`);
  invariant(!CONTROL.test(value), 'invalid_input', `${label} contains control characters`);
  return value.replace(/\r\n?/g, '\n');
}

export function validateSenderProfile(value: unknown): SenderProfile {
  invariant(value !== null && typeof value === 'object' && !Array.isArray(value), 'invalid_input', 'Sender profile required');
  const v = value as Record<string, unknown>;
  invariant(Object.keys(v).every((k) => ['organizationName', 'assistantName', 'humanContact', 'permittedRoleClaims', 'locale'].includes(k)), 'invalid_input', 'Unknown sender profile field');
  const roles = v.permittedRoleClaims === undefined ? [] : v.permittedRoleClaims;
  invariant(Array.isArray(roles) && roles.length <= 20 && roles.every((r) => typeof r === 'string'), 'invalid_input', 'permittedRoleClaims must be a list of strings');
  return {
    organizationName: line(v.organizationName, 'organizationName', 120), humanContact: line(v.humanContact, 'humanContact', 200),
    ...(v.assistantName === undefined ? {} : { assistantName: line(v.assistantName, 'assistantName', 80) }),
    permittedRoleClaims: (roles as string[]).map((r) => line(r, 'role', 60).toLowerCase()),
    ...(v.locale === undefined ? {} : { locale: line(v.locale, 'locale', 20) }),
  };
}

function template(rules: MailRules, profile: SenderProfile): DisclosureTemplate {
  return rules.templates[profile.locale ?? rules.defaultLocale] ?? rules.templates[rules.defaultLocale] ?? (DEFAULT_TEMPLATES.en as DisclosureTemplate);
}
/** Server-composed and appended to every outbound message; callers cannot supply or remove it. */
export function renderDisclosure(profile: SenderProfile, automated: boolean, rules: MailRules = DEFAULT_RULES): string {
  const t = template(rules, profile);
  const fill = (s: string): string => s.replaceAll('{organizationName}', profile.organizationName)
    .replaceAll('{assistantName}', profile.assistantName ?? `the ${profile.organizationName} research assistant`)
    .replaceAll('{humanContact}', profile.humanContact).replaceAll('{optOut}', t.optOut);
  return fill(automated ? t.automated : t.human).trim();
}

export type StructuredInquiry = Readonly<{ subject: string; purpose: string; questions: readonly string[]; context?: string }>;
export function validateStructured(value: unknown): StructuredInquiry {
  invariant(value !== null && typeof value === 'object' && !Array.isArray(value), 'invalid_input', 'Structured inquiry required');
  const v = value as Record<string, unknown>;
  invariant(Object.keys(v).every((k) => ['subject', 'purpose', 'questions', 'context'].includes(k)), 'invalid_input', 'Unknown structured inquiry field');
  invariant(Array.isArray(v.questions) && v.questions.length >= 1 && v.questions.length <= 3, 'invalid_input', 'An inquiry carries one to three questions');
  const questions = (v.questions as unknown[]).map((q) => {
    const s = line(q, 'question', 300);
    invariant(s.endsWith('?'), 'invalid_input', 'Each question must end with a question mark');
    return s;
  });
  return { subject: line(v.subject, 'subject', 140), purpose: line(v.purpose, 'purpose', 400), questions,
    ...(v.context === undefined || v.context === '' ? {} : { context: line(v.context, 'context', 700) }) };
}
export function renderStructured(inquiry: StructuredInquiry, profile: SenderProfile, rules: MailRules = DEFAULT_RULES): { subject: string; body: string } {
  const t = template(rules, profile);
  const parts = [t.greeting, inquiry.purpose];
  if (inquiry.context !== undefined) parts.push(`${t.contextLabel} ${inquiry.context}`);
  parts.push(inquiry.questions.map((q, i) => `${i + 1}. ${q}`).join('\n'), t.closing);
  const body = parts.join('\n\n');
  invariant(body.length <= rules.maxAutomatedBodyChars, 'invalid_input', `Automated inquiries are limited to ${rules.maxAutomatedBodyChars} characters`);
  return { subject: inquiry.subject, body };
}
export function withDisclosure(body: string, disclosure: string): string { return `${body.replace(/\s+$/, '')}\n\n-- \n${disclosure}\n`; }

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/**
 * Finds first-person claims to a professional or personal identity ("I am a lawyer", "as a journalist").
 * A role listed in the sender profile's permittedRoleClaims is not reported.
 */
export function findIdentityClaims(text: string, profile: SenderProfile, rules: MailRules = DEFAULT_RULES): string[] {
  const permitted = new Set((profile.permittedRoleClaims ?? []).map((r) => r.toLowerCase()));
  const terms = rules.roleTerms.filter((t) => !permitted.has(t.toLowerCase()));
  if (terms.length === 0) return [];
  const prefixes = [...rules.claimPrefixes].sort((a, b) => b.length - a.length).map(escapeRe).join('|');
  const starts = rules.sentenceClaimPrefixes.map(escapeRe).join('|');
  const lead = `(?:(?<![\\p{L}\\p{N}])(?:${prefixes})${starts === '' ? '' : `|(?:^|[.!?:;]\\s+|\\n\\s*)(?:${starts})`})`;
  const re = new RegExp(`${lead}\\s+(?:(?:a|an|the|your|one of the)\\s+)?(?:[\\p{L}'’-]+\\s+){0,3}?(${terms.map(escapeRe).join('|')})(?:s|es)?(?![\\p{L}\\p{N}])`, 'giu');
  const found = new Set<string>();
  for (const m of text.matchAll(re)) found.add((m[1] as string).toLowerCase());
  // Honorifics and credentials in a self-description are identity claims as well.
  if (/(?<![\p{L}\p{N}])(?:dr|prof|esq|ph\.?d|j\.?d|ll\.?m)\.?(?![\p{L}\p{N}])/iu.test(text) && !permitted.has('title')) found.add('title');
  return [...found].sort();
}

// ───────────────────────────── Inbound ─────────────────────────────
export type ParsedInbound = Readonly<{
  messageId: string | null; dedupeKey: string; inReplyTo: string | null; references: readonly string[];
  from: string | null; fromName: string; to: readonly string[]; cc: readonly string[]; subject: string;
  text: string; html: string | null; date: string | null; sha256: string; size: number;
  attachments: readonly Readonly<{ filename: string; mediaType: string; content: Buffer; contentId: string | null }>[];
  classification: Classification;
}>;
export type Classification = Readonly<{
  kind: 'bounce' | 'delivery_report' | 'auto_reply' | 'refusal' | 'reply';
  rule: string;
  /** Message-IDs named by a delivery report (the original outbound message). */
  reportedMessageIds?: readonly string[]; action?: string; status?: string; failedRecipients?: readonly string[];
}>;

const MSGID = /<[^<>\s@]+@[^<>\s@]+>/g;
function ids(value: unknown): string[] {
  const text = Array.isArray(value) ? value.join(' ') : typeof value === 'string' ? value : '';
  return [...new Set(text.match(MSGID) ?? [])].slice(0, 50);
}
function addresses(value: AddressObject | AddressObject[] | undefined): { address: string; name: string }[] {
  const out: { address: string; name: string }[] = [];
  for (const group of value === undefined ? [] : Array.isArray(value) ? value : [value]) {
    for (const entry of group.value) {
      if (typeof entry.address !== 'string') continue;
      try { out.push({ address: normalizeAddress(entry.address), name: (entry.name ?? '').replace(CONTROL_G, ' ').slice(0, 200) }); } catch { /* unusable address: ignored */ }
    }
  }
  return out;
}
function safeFilename(name: string | undefined, index: number): string {
  const base = (name ?? '').replace(/[\\/\u0000-\u001f\u007f]/g, '_').replace(/^\.+/, '').trim().slice(0, 180);
  return base === '' ? `attachment-${index + 1}` : base;
}
/** New text of a reply: quoted history and signature removed by configured markers. */
export function replyText(text: string, rules: MailRules = DEFAULT_RULES): string {
  const markers = rules.quoteMarkers.map((m) => new RegExp(m, 'i'));
  const out: string[] = [];
  for (const raw of text.replace(/\r\n?/g, '\n').split('\n')) {
    const l = raw.trimEnd();
    if (l === '-- ' || l === '--' || markers.some((m) => m.test(l.trim()))) break;
    if (l.trimStart().startsWith('>')) continue;
    out.push(l);
  }
  return out.join('\n').trim();
}
export function isOptOut(text: string, rules: MailRules = DEFAULT_RULES): boolean {
  const fresh = replyText(text, rules).slice(0, 2000);
  if (fresh === '') return false;
  if (detectsOptOut(fresh)) return true;
  return rules.optOutPatterns.some((p) => new RegExp(`(?<![\\p{L}\\p{N}])(?:${p})(?![\\p{L}\\p{N}])`, 'iu').test(fresh));
}
export type AssertionCandidate = Readonly<{ text: string; start: number; end: number }>;
/**
 * Paragraphs of the new reply text, offered as attributed (never verified) assertion candidates.
 * `text` is the verbatim slice `body.slice(start, end)` so a reviewer can locate it in the preserved message.
 */
export function assertionCandidates(body: string, rules: MailRules = DEFAULT_RULES, max = 8): AssertionCandidate[] {
  const markers = rules.quoteMarkers.map((m) => new RegExp(m, 'i'));
  const out: AssertionCandidate[] = [];
  let start = -1, end = -1, offset = 0;
  const flush = (): void => {
    if (start >= 0) {
      const text = body.slice(start, end);
      if (text.trim().length >= 16 && /\p{L}/u.test(text) && out.length < max) out.push({ text: text.slice(0, 1200), start, end: Math.min(end, start + 1200) });
    }
    start = -1;
  };
  for (const raw of body.split('\n')) {
    const l = raw.replace(/\r$/, ''); const t = l.trim(); const at = offset; offset += raw.length + 1;
    if (t === '--' || markers.some((m) => m.test(t))) break;
    if (t === '' || t.startsWith('>')) { flush(); continue; }
    const lead = l.length - l.trimStart().length;
    if (start < 0) start = at + lead;
    end = at + lead + t.length;
  }
  flush();
  return out;
}

function classify(mail: ParsedMail, raw: Buffer, text: string, rules: MailRules): Classification {
  const header = (name: string): string => { const v = mail.headers.get(name); return typeof v === 'string' ? v : v === undefined ? '' : JSON.stringify(v); };
  const contentType = mail.headers.get('content-type') as { value?: string; params?: Record<string, string> } | undefined;
  const isReport = contentType?.value?.toLowerCase() === 'multipart/report' && (contentType.params?.['report-type'] ?? '').toLowerCase() === 'delivery-status';
  const hasStatusPart = mail.attachments.some((a) => a.contentType.toLowerCase() === 'message/delivery-status');
  const failedHeader = header('x-failed-recipients');
  if (isReport || hasStatusPart || failedHeader !== '') {
    const rawText = raw.subarray(0, 512 * 1024).toString('latin1');
    const action = /^Action:\s*([a-z-]+)/im.exec(rawText)?.[1]?.toLowerCase() ?? (failedHeader !== '' ? 'failed' : 'unknown');
    const status = /^Status:\s*(\d\.\d{1,3}\.\d{1,3})/im.exec(rawText)?.[1] ?? '';
    const failed = [...rawText.matchAll(/^(?:Final|Original)-Recipient:\s*[^;\r\n]*;\s*([^\s\r\n]+)/gim)].map((m) => m[1] as string).concat(failedHeader.split(',').map((s) => s.trim()))
      .flatMap((a) => { try { return [normalizeAddress(a.replace(/^<|>$/g, ''))]; } catch { return []; } });
    const own = mail.messageId;
    const reported = ids(rawText.match(/^(?:Message-ID|Original-Message-ID):\s*<[^>\r\n]+>/gim)?.join(' ') ?? '').filter((id) => id !== own).concat(ids(mail.inReplyTo), ids(mail.references));
    return { kind: action === 'failed' ? 'bounce' : 'delivery_report', rule: isReport || hasStatusPart ? 'rfc3464-delivery-status' : 'x-failed-recipients', action, status,
      failedRecipients: [...new Set(failed)].slice(0, 20), reportedMessageIds: [...new Set(reported)].slice(0, 20) };
  }
  // A refusal is honoured even when an autoresponder phrased it; checked before the auto-reply rule.
  if (isOptOut(text, rules)) return { kind: 'refusal', rule: 'opt-out-phrase' };
  const auto = header('auto-submitted').toLowerCase();
  if (auto !== '' && !auto.startsWith('no')) return { kind: 'auto_reply', rule: 'auto-submitted' };
  if (header('x-autoreply') !== '' || header('x-autorespond') !== '' || header('x-auto-response-suppress') !== '') return { kind: 'auto_reply', rule: 'autoresponder-header' };
  if (/^(?:auto_reply|bulk|junk|list)$/i.test(header('precedence').trim())) return { kind: 'auto_reply', rule: 'precedence' };
  return { kind: 'reply', rule: 'default' };
}

/** Parses original RFC822 bytes. The bytes themselves are preserved by the caller; this is a derived view. */
export async function parseInbound(raw: Uint8Array, rules: MailRules = DEFAULT_RULES): Promise<ParsedInbound> {
  const bytes = Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength);
  invariant(bytes.byteLength > 0, 'invalid_input', 'Empty message');
  let mail: ParsedMail;
  try { mail = await simpleParser(bytes, { skipHtmlToText: false, skipTextToHtml: true, skipImageLinks: true, skipTextLinks: true }); }
  catch { throw Object.assign(new Error('unparseable'), { code: 'unparseable' }); }
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const messageId = ids(mail.messageId)[0] ?? null;
  const from = addresses(mail.from)[0] ?? null;
  const text = (mail.text ?? '').replace(/\u0000/g, '').slice(0, 500_000);
  return {
    messageId, dedupeKey: messageId ?? `sha256:${sha256}`, inReplyTo: ids(mail.inReplyTo)[0] ?? null, references: ids(mail.references),
    from: from?.address ?? null, fromName: from?.name ?? '', to: addresses(mail.to).map((a) => a.address).slice(0, 100), cc: addresses(mail.cc).map((a) => a.address).slice(0, 100),
    subject: (mail.subject ?? '').replace(CONTROL_G, ' ').slice(0, 500), text, html: typeof mail.html === 'string' ? mail.html.replace(/\u0000/g, '').slice(0, 1_000_000) : null,
    date: mail.date instanceof Date && Number.isFinite(mail.date.getTime()) ? mail.date.toISOString() : null, sha256, size: bytes.byteLength,
    attachments: mail.attachments.slice(0, 50).map((a, i) => ({ filename: safeFilename(a.filename, i), mediaType: /^[\w.+-]+\/[\w.+-]+$/.test(a.contentType) ? a.contentType.toLowerCase() : 'application/octet-stream', content: a.content, contentId: a.contentId ?? null })),
    classification: classify(mail, bytes, text, rules),
  };
}
