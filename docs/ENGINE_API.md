# Correspondence and Outreach engine (E03) — service API

Schema `e03_correspondence` · capability prefix `correspondence` · kit `src/service-kit.ts` 1.0.1
(sha256 `95475a907267ba1fdd54b557aabe5645c37add9788a5b2d0854d9accfd5d8ea5`, byte-identical to the Identity engine copy;
checked by `scripts/verify-contracts.mjs`). `src/contracts.ts` is the Identity version.

## Entry points

```ts
import { SCHEMA, manifest, migrations, migrate, createEngine, routes, correspondencePort } from '@accountability/correspondence/engine';

await migrate(sql);
const engine = createEngine({
  sql,                                   // kit Sql (pgSql(pool))
  objects,                               // kit ObjectStore; required for raw messages, attachments and sending
  ports: { authorization?, budget?, evidence?, useDecision? },   // kit AuthorizationPort, BudgetPort, EvidencePort, UseDecisionPort
  config: {
    secretKey?: string,                  // 32 bytes, base64/base64url/hex (env CORRESPONDENCE_SECRET_KEY)
    rules?: Partial<MailRules>,          // templates per locale, roleTerms, claimPrefixes, sentenceClaimPrefixes, optOutPatterns, quoteMarkers, maxAutomatedBodyChars, defaultLocale
    provider?: Partial<ProviderPolicy>,  // allowPrivateHosts, allowEndpointOverride, allowInsecureTls, allowedOAuthHosts, timeoutMs, maxMessageBytes
    requireVerifiedContactForAutomation?: boolean,  // default true
    maxFollowUps?: number,               // default 3 (ceiling over any grant)
    reconcileDelayMs?: number, reconcileAttempts?: number,   // default 60000, 5
    maxAttachmentBytes?: number, maxRecipients?: number,     // default 20 MiB, 10
    standaloneAllowSensitiveContact?: boolean,               // default false
    workerId?: string,
  },
});
http.createServer(createHttpHandler({ name: manifest.name, version: manifest.version, routes: routes(engine), verify }));
await engine.runWorkerOnce({ limit: 5 });   // job runner: dispatch, reconcile and sync jobs; returns number of jobs processed
```

Standalone: `npm run serve` (`src/engine/serve.ts`). Environment: `DATABASE_URL`, `PORT` (default 8703), `HOST`,
`IDENTITY_PUBLIC_KEYS` (JSON map kid→PEM) or `IDENTITY_JWKS_FILE` (same JSON in a file), `IDENTITY_ISSUER`,
`OBJECT_STORE` / `OBJECT_STORE_PATH` / `S3_*`, `CORRESPONDENCE_SECRET_KEY`, `CORRESPONDENCE_RULES_FILE` (JSON `MailRules` overrides),
`CORRESPONDENCE_WORKER=off`, `CORRESPONDENCE_WORKER_POLL_MS`, `CORRESPONDENCE_SYNC_INTERVAL_MS` (0 = no periodic sync),
`CORRESPONDENCE_PROVIDER_TIMEOUT_MS`, and for controlled test servers only `CORRESPONDENCE_ALLOW_PRIVATE_HOSTS=true`,
`CORRESPONDENCE_ALLOW_INSECURE_TLS=true`.

## Capabilities

| Capability | Grants |
|---|---|
| `correspondence:read` | lists, counts, search, threads, messages, raw/attachment download, contacts, plans, grants, dispatch queue, inspect |
| `correspondence:write` | drafts, attachments (human), labels, bulk thread actions, assignment, contacts, suppression add, takeover/resume (human), stale review (human), assertions, evidence hand-off |
| `correspondence:send` | queue/schedule/cancel a send, follow-ups, reconcile; resolve uncertain (human) |
| `correspondence:contact` | create outreach plans, draft plan inquiries, verify a contact route (human) |
| `correspondence:grant` | create/revoke sending grants (human only) |
| `correspondence:admin` | mailboxes, credentials, sender profile and its verification (human), connection test, lift suppression (human), audit |
| `correspondence:ingest` | raw RFC822 ingest |
| `correspondence:sync` | provider synchronization |
| `correspondence:upstream` | `applyUpstreamChange` (falls back to `correspondence:write`) |
| `correspondence:events` | outbox feed |

`send`, `contact`, `grant`, `admin`, `events` are never satisfied by `correspondence:*`. Every method takes `ctx` first and
filters on tenant, project and compartments; a foreign or hidden object is `not_found`.

## Service methods

All views are plain JSON objects with camelCase keys (`View`). `Page<T> = { items: T[]; nextCursor: string | null; total: number }`.
Mutating methods marked † accept `idempotencyKey`.

Mailboxes (provider `smtp_imap` | `gmail` | `graph` | `ingest_only`)
```ts
createMailbox(ctx, { address, displayName?, provider, config?, senderProfile?, credentials?, idempotencyKey? }): Promise<View>            // †
updateMailbox(ctx, mailboxId, { displayName?, config?, state?: 'active'|'disabled', idempotencyKey? }): Promise<View>                    // †
setMailboxCredentials(ctx, mailboxId, { smtpPassword?, imapPassword?, oauthClientSecret?, oauthRefreshToken? }): Promise<View>
setSenderProfile(ctx, mailboxId, { organizationName, assistantName?, humanContact, permittedRoleClaims?, locale? }): Promise<View>
verifySenderProfile(ctx, mailboxId): Promise<View>                       // human
listMailboxes(ctx): Promise<View[]>;  getMailbox(ctx, mailboxId): Promise<View>
testMailboxConnection(ctx, mailboxId): Promise<{ send: string; read: string }>    // real network call
```
`config`: `{ smtp?: { host, port, secure?, requireTLS?, auth: 'password'|'xoauth2'|'none', username? }, imap?: { host, port, secure?, auth: 'password'|'xoauth2', username, inbox?, sentFolder?, extraFolders? }, oauth?: { tokenUrl, clientId, scope? }, accountId?, folderId?, apiBaseUrl? }`.
Mailbox views expose `credentials: { configured: string[] (field names), setAt }` and never a value.

Contacts and suppression
```ts
upsertContact(ctx, { address, displayName?, organization?, roleTitle?, whyMayKnow?, routeSource? /* uref, e.g. E04 lead */, routeNote?, sensitive?, compartment?, idempotencyKey? }): Promise<View>   // †
verifyContact(ctx, contactId, { note?, reject? }): Promise<View>         // human; emits outreach.candidate.verified
listContacts(ctx, { q?, state?, limit?, cursor? }): Promise<Page<View>>
getContact(ctx, contactId): Promise<View>                                // + history[], threads[], suppressed
addSuppression(ctx, { address? | domain?, reason, idempotencyKey? }): Promise<View>   // †
listSuppressions(ctx, { includeLifted?, limit? }): Promise<View[]>
liftSuppression(ctx, suppressionId, { reason }): Promise<View>           // human, admin
```

Folder views, threads, search, labels
```ts
listThreads(ctx, { mailboxId?, folder?: 'inbox'|'sent'|'drafts'|'outbox'|'archive'|'trash'|'spam'|'starred'|'all'|'attention', labelId?, assignee?, unread?, questionRef?, contactId?, q?, limit?, cursor? }): Promise<Page<View>>
counts(ctx, { mailboxId? }): Promise<{ folders: Record<Folder, { total, unread }>; labels: { id, name, color, total, unread }[] }>
getThread(ctx, threadId, { markRead? }): Promise<View>                   // + messages[] (with attachments[]), dispatches[], assertions[], labels[], contact, automation
modifyThreads(ctx, { threadIds, addLabelIds?, removeLabelIds?, archived?, trashed?, spam?, starred?, read?, assignee?: string|null, idempotencyKey? }): Promise<{ updated: string[] }>   // †
searchMessages(ctx, { q, mailboxId?, limit?, cursor? }): Promise<Page<View>>   // tsvector 'simple', websearch syntax, headline
getMessage(ctx, messageId): Promise<View>                                // + attachments[], versions[], untrustedHtml
getRawMessage(ctx, messageId): Promise<{ bytes: Uint8Array; sha256: string; filename: string }>
createLabel(ctx, { name, color?, idempotencyKey? }): Promise<View>;  listLabels(ctx): Promise<View[]>
updateLabel(ctx, labelId, { name?, color? }): Promise<View>;  deleteLabel(ctx, labelId): Promise<{ deleted: true }>
```
Thread view fields include `controlMode`, `controlEpoch`, `mailboxControlMode`, `automation`
(`human_control | blocked | stale | refused | permitted_under_grant`), `unreadCount`, `messageCount`, `snippet`, `participants`,
`labelIds`, `inTransitCount`, `queuedCount`, `hasAttachments`, `assignee`, `questionRef`, `contactId`, `planId`, `stale`, `blocked`, `refused`.

Compose
```ts
createDraft(ctx, { mailboxId?, threadId?, replyToMessageId?, contactId?, planId?, questionRef?, to?, cc?, subject?, body?, structured?, compartment?, idempotencyKey? }): Promise<View>   // †
updateDraft(ctx, messageId, { expectedRevision, to?, cc?, subject?, body?, structured?, idempotencyKey? }): Promise<View>   // †
discardDraft(ctx, messageId): Promise<View>
addAttachment(ctx, messageId, { filename, mediaType, bytes }): Promise<View>      // human; drafts only
removeAttachment(ctx, attachmentId): Promise<{ removed: true }>
getAttachment(ctx, attachmentId): Promise<{ meta: View; bytes: Uint8Array }>
```
`structured = { subject, purpose, questions: string[1..3] (each ends with "?"), context? }`. Agents (actor kind ≠ human)
must use `structured`, address a recorded contact (`contactId` or a thread with one) and cannot set `to`/`cc`/`body`.

Sending and the dispatch queue
```ts
sendMessage(ctx, messageId, { grantId?, sendAt?, idempotencyKey? }): Promise<View /* dispatch */>     // †; agents must pass grantId
scheduleFollowUp(ctx, threadId, { grantId, sendAt, structured, idempotencyKey? }): Promise<View /* dispatch */>
cancelDispatch(ctx, dispatchId, { reason? }): Promise<View>              // queued only
listDispatches(ctx, { states?, mailboxId?, threadId?, limit? }): Promise<View[]>
getDispatch(ctx, dispatchId): Promise<View>                              // + evidence[] (delivery events)
reconcileDispatch(ctx, dispatchId): Promise<View>                        // provider lookup by Message-ID now; never resends
resolveDispatch(ctx, dispatchId, { outcome: 'sent'|'not_sent', note, resend? }): Promise<View>   // human
runWorkerOnce({ limit? }): Promise<number>
```
Dispatch states: `queued → dispatching → accepted` (in transit) `→ delivered | bounced`; `dispatching → uncertain →`
`accepted` (reconciled: `reconciledAt`, `reconciliation`) `| not_sent | delivered | bounced`; `failed` (provider refused);
`cancelled` (before hand-off). `inTransit` is true for `dispatching`, `accepted`, `uncertain`.

Takeover
```ts
takeover(ctx, { threadId? | mailboxId?, reason? }): Promise<{ target, controlMode, controlEpoch, cancelledDispatches: string[], inTransit: View[] }>   // human
resume(ctx, { threadId? | mailboxId?, reason? }): Promise<same>          // human
```

Outreach plans and questions
```ts
createOutreachPlan(ctx, { questionRef, question, context?, allowedDisclosure?, compartment?, candidates: { contactId? | contact?, rank?, rationale? }[], idempotencyKey? }): Promise<View>   // †
planOutreach(ctx, { ...plan input, mailboxId?, inquiry?: structured, idempotencyKey? }): Promise<{ plan: View; drafts: View[] }>   // † plan + one draft per candidate
getPlan(ctx, planId): Promise<View>;  listPlans(ctx, { questionRef?, limit? }): Promise<View[]>
draftInquiry(ctx, { planId, contactId, mailboxId, structured? | subject?/body?, idempotencyKey? }): Promise<View>   // †
questionStatus(ctx, questionRef): Promise<{ questionRef, state, plans, conversations, replies, assertions }>
correspondencePort(engine, { mailboxId })   // adapter with E08's CorrespondencePort shape: createContactPlan, draftInquiry, getThreadState
```

Grants
```ts
createGrant(ctx, { granteeId, mailboxId, purpose, questionRefs?, recipientAllowlist?, domainAllowlist?, maxMessages, perRecipientCap? (1), cooldownSeconds? (86400), followUpLimit? (0), expiresAt, idempotencyKey? }): Promise<View>   // † human
listGrants(ctx, { granteeId?, mailboxId?, state? }): Promise<View[]>;  getGrant(ctx, grantId): Promise<View>
revokeGrant(ctx, grantId, { reason }): Promise<View>                     // human; cancels queued dispatches under the grant
```

Inbound, sync, assertions, evidence, upstream
```ts
ingestRawMessage(ctx, mailboxId, raw: Uint8Array, { providerId? }): Promise<{ message: View; duplicate: boolean; observedOutbound: boolean }>
syncMailboxNow(ctx, mailboxId, { limit? }): Promise<{ ingested, duplicates, skipped, resets, more }>
syncMailbox(ctx, mailboxId): Promise<{ jobId: string }>
listAssertions(ctx, { messageId?, threadId?, questionRef? }): Promise<View[]>
proposeAssertions(ctx, messageId, { quotes: string[], idempotencyKey? }): Promise<View[]>   // † verbatim quotes only
linkAssertion(ctx, assertionId, { verificationRef }): Promise<View>
handToEvidence(ctx, messageId): Promise<{ message, evidenceRef, attachments }>     // needs EvidencePort
reviewStale(ctx, threadId, { note }): Promise<View>                      // human
applyUpstreamChange(ctx, change): Promise<{ affected: string[] }>
inspect / search / audit / events / health                                // kit StandardEngine
```

### The acceptance flow in calls
```ts
const { plan, drafts } = await engine.planOutreach(agentCtx, { questionRef: 'E08:question:<id>', question, mailboxId, inquiry: structured,
  candidates: [{ contact: { address, whyMayKnow, routeSource: 'E04:lead:<id>' } }] });
await engine.verifyContact(humanCtx, plan.candidates[0].contactId);
const grant = await engine.createGrant(humanCtx, { granteeId: agentCtx.actor.id, mailboxId, purpose, recipientAllowlist: [address], maxMessages: 3, followUpLimit: 1, expiresAt });
const dispatch = await engine.sendMessage(agentCtx, drafts[0].id, { grantId: grant.id, idempotencyKey });
await engine.runWorkerOnce();                                            // real SMTP/Gmail/Graph call happens here
await engine.ingestRawMessage(serviceCtx, mailboxId, rfc822Bytes, { providerId });   // or syncMailboxNow
await engine.takeover(humanCtx, { threadId: drafts[0].threadId, reason });
```

## HTTP routes

Bearer token (kit `createTokenVerifier`) on everything except `/healthz` and `/v1/manifest`. Kit standard routes:
`GET /v1/manifest`, `/v1/inspect?ref=`, `/v1/search?q=`, `/v1/audit`, `/v1/events`, `POST /v1/upstream-changes`.

| Route | Method |
|---|---|
| `GET/POST /v1/mailboxes`, `GET/PATCH /v1/mailboxes/:id` | list/create, get/update |
| `PUT /v1/mailboxes/:id/credentials`, `PUT /v1/mailboxes/:id/sender-profile`, `POST …/sender-profile/verify`, `POST …/test` | credentials, profile, verify, connection test |
| `POST /v1/mailboxes/:id/sync[?wait=true&limit=]` | `syncMailbox` / `syncMailboxNow` |
| `POST /v1/mailboxes/:id/ingest[?providerId=]` (body = raw RFC822) | `ingestRawMessage` (201 new, 200 duplicate) |
| `POST /v1/mailboxes/:id/takeover`, `…/resume` | mailbox takeover |
| `GET /v1/inbox`, `GET /v1/folders`, `GET /v1/counts`, `GET /v1/conversations?folder=&labelId=&assignee=&unread=&questionRef=&contactId=&q=&limit=&cursor=` | views |
| `POST /v1/conversations/modify`, `GET /v1/conversations/:id[?markRead=true]` | bulk action, thread |
| `POST /v1/conversations/:id/takeover`, `…/resume`, `…/review-stale`, `…/follow-ups` | control, follow-up |
| `GET /v1/messages/search?q=` | full-text search |
| `POST /v1/messages`, `GET/PATCH/DELETE /v1/messages/:id` | draft create/get/update/discard |
| `POST /v1/messages/:id/send` (202; header `Idempotency-Key`) | `sendMessage` |
| `GET /v1/messages/:id/raw`, `POST /v1/messages/:id/evidence`, `GET/POST /v1/messages/:id/assertions` | raw download, evidence, assertions |
| `POST /v1/messages/:id/attachments?filename=` (body = bytes), `GET/DELETE /v1/attachments/:id` | attachments |
| `PATCH /v1/assertions/:id`, `GET /v1/assertions?conversationId=&questionRef=` | link, list |
| `GET /v1/dispatches?state=a,b&mailboxId=&conversationId=`, `GET /v1/dispatches/:id`, `POST …/cancel`, `…/reconcile`, `…/resolve` | dispatch queue |
| `GET/POST /v1/labels`, `PATCH/DELETE /v1/labels/:id` | labels |
| `GET/POST /v1/contacts`, `GET /v1/contacts/:id`, `POST /v1/contacts/:id/verify` | contacts |
| `GET/POST /v1/suppressions`, `POST /v1/suppressions/:id/lift` | suppression |
| `GET/POST /v1/outreach/plans` (with `inquiry` → `planOutreach`), `GET /v1/outreach/plans/:id`, `POST …/inquiries`, `GET /v1/outreach/questions?ref=` | plans |
| `GET/POST /v1/grants`, `GET /v1/grants/:id`, `POST /v1/grants/:id/revoke` | grants |

Error statuses: kit mapping plus `suppressed` 409, `unavailable`/`provider_unavailable` 503, `provider_auth_failed` 502,
`invalid_identity_claim` 400, `takeover_active` 409, `grant_invalid` 403, `consent_denied` 403, `stale` 409.

## Events (type → subject)

`mailbox.created` → mailbox · `message.drafted`, `message.queued`, `message.sent` (payload `state:'accepted', inTransit:true`),
`message.send.uncertain`, `message.send.reconciled` (`outcome`, `resent:false`), `message.send.failed`, `message.send.cancelled`,
`message.delivered`, `message.bounced` → `E03:message:<id>` (the outbound message) · `message.received` → inbound message ·
`correspondence.reply_received` → `E03:message:<id>` with `{ questionRef, conversation, source, attributedTo, contact, status:'attributed_unverified', candidates:[{ ref:'E03:assertion:<id>', text (≤300 chars), start, end }] }`
(`start`/`end` are offsets into the message `bodyText`) · `answer.proposed` → message (reviewer-selected quotes, same shape) ·
`message.preserved_as_evidence` → message · `contact.refused` → message · `suppression.added|lifted` → suppression ·
`outreach.plan.created` → plan · `outreach.candidate.verified` → contact · `grant.created|revoked` → grant ·
`conversation.taken_over|resumed` → conversation or mailbox · `conversation.assigned`, `conversation.stale|blocked|stale_reviewed` → conversation ·
`contact.stale|blocked` → contact · `plan.stale|blocked` → plan (`{ reason, cause: eventId, kind }`).

Nothing in this engine marks an assertion verified: the `assertions.status` column has a check constraint allowing only
`attributed_unverified`.

## Behaviour

- **Truthful identity.** Every outbound message is plain text and ends with a server-composed disclosure from the mailbox's
  human-verified sender profile (organization, automated-assistant statement when sent by a non-human actor, how to reach a
  human, how to opt out). Automated mail carries `Auto-Submitted: auto-generated`. No HTML part, no tracking. Agent content is
  structured, length-capped and rejected when it claims a role outside `permittedRoleClaims` (`invalid_identity_claim`); human
  content is sent as written with `identityFlags` shown on the message. A changed profile must be verified again before any send.
- **Grants.** Bounded by grantee, mailbox, recipients/domains (required), questions, `maxMessages`, per-recipient cap,
  cooldown, follow-up limit and expiry. Checked at request time and again under row locks inside the dispatch job together
  with suppression, takeover state and control epochs, contact/plan/thread blocks, and `AuthorizationPort.authorize`
  (`correspondence:send`) when supplied. Without the port, the capability stored with the job is required.
- **Takeover.** One transaction flips the control mode, bumps the control epoch and cancels queued automated dispatches of the
  thread or mailbox. Dispatches already `dispatching`/`accepted`/`uncertain` are returned as `inTransit` and stay visible.
  A dispatch queued under an older epoch is refused in the job even if control later returns.
- **Uncertain sends.** A connection lost or timed out after the SMTP transaction began, a missing HTTP response, a 5xx, or a
  worker that died after marking `dispatching` yields `uncertain`. Reconciliation looks the Message-ID up at the provider (IMAP
  header search in the sent folder/inbox, Gmail `rfc822msgid:` + Sent label check, Graph `internetMessageId`), or uses a reply,
  bounce or the message's own copy seen during ingestion. Nothing is resent automatically; after the configured lookups a
  person decides (`resolveDispatch`), and an explicit re-send reuses the same Message-ID.
- **Inbound.** Original bytes are stored in the object store (`<tenant>/<project>/e03/raw/<id>.eml`), attachments under
  `…/e03/attachments/<id>`. Idempotent by Message-ID (or sha256 when absent) and by provider id. Classification is rule-based:
  delivery report/bounce (RFC 3464, `X-Failed-Recipients`), refusal (opt-out phrases), auto-reply (RFC 3834 headers), reply.
  Refusal suppresses the sender project-wide and cancels queued sends; a permanent bounce suppresses the failed address; any
  reply cancels queued automated follow-ups. Inbound text never supplies recipients, grants or instructions.
- **Upstream.** `permission_withdrawn`, `permission_changed`, `source_removed` mark matching contacts, plans and conversations
  `blocked` (automation refused with `consent_denied`); other kinds mark them `stale` until a human `reviewStale`. Matching is
  by `sources` (question uref, contact route uref) with `urefMatches`. Queued automated dispatches are cancelled. Idempotent by `eventId`.
- **Budget.** With a `BudgetPort`, one unit (`correspondence.send`, `message`) is reserved per dispatch, committed on
  accepted/uncertain and released otherwise; `budget_exhausted` cancels the dispatch.

## Status

Tested locally against real PostgreSQL 16, a real SMTP server (`smtp-server`) and an in-test IMAP4rev1 server over loopback
sockets (`tests/engine*.test.ts`, 18 tests): acceptance B, refusal, duplicate inbound, grant revocation, takeover fencing,
ambiguous send and reconciliation, crash recovery, bounces, workspace surface, IMAP checkpoints and UIDVALIDITY reset, tenant
and compartment isolation, capability checks, credential sealing, upstream blocking, ports, HTTP routes.

Implemented, **not verified against a live provider**:
- Gmail API and Microsoft Graph adapters (send, lookup, sync, OAuth2 refresh-token exchange and rotation). Tested only against
  a local stand-in HTTP server. The Graph synchronization path (delta + `$value`) has no test at all.
- SMTP and IMAP against real servers, TLS/STARTTLS, and XOAUTH2 for SMTP/IMAP (code paths exist; tests use password auth without TLS on loopback).
- S3 object storage (kit), periodic sync scheduling in `serve.ts`.

Not implemented / limits:
- No push notifications (Gmail watch, Graph subscriptions, IMAP IDLE); sync is polled. Provider-side read/label state is not written back.
- Gmail/Graph sync fetches each changed message twice (normalized by the existing sync core, then raw bytes).
- Host checks reject private/loopback literals and unqualified names but do not defend against DNS rebinding.
- Inbound HTML is stored and returned as `untrustedHtml` without sanitization; a UI must sandbox or not render it. No malware scanning of attachments.
- Role-claim, opt-out and quote-marker rules ship with English defaults; other languages need `rules` configuration.
  Role-claim screening is pattern-based and can be evaded or over-trigger.
- Assertion candidates are paragraphs of the new reply text (deterministic), not semantic extraction.
- `delivered` is set only from evidence (reply, DSN `delivered`); DSNs and opt-outs are not authenticated, so a forged one can
  mark a bounce or add a suppression (fail-safe direction; a human can lift a suppression).
- Follow-ups are scheduled explicitly per call; there is no automatic cadence.
- Concurrent syncs of one mailbox are safe (idempotent ingestion) but may fetch the same messages twice.
- The earlier functional-core modules (`machine.ts`, `operator.ts`, `durable.ts`, `projections.ts`) remain exported and tested
  but the service layer does not use them; it reuses `validation.ts`, `adapters.ts` and the `sync-*` provider core.
- No independent security review has been performed.
