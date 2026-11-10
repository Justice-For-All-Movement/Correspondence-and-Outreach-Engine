# Correspondence and Outreach Engine

Standalone Node 24 / strict TypeScript dependency engine for drafts, ordinary mailbox views, human takeover, bounded send grants and unverified reply evidence. Outbound execution remains fake-only. The read-only mailbox synchronization SDK uses an injected Gmail/Graph HTTP transport whose credentials stay private to that transport. No built-in network client or OAuth provisioning is provided.

```sh
npm ci
npm run check
```

`check` runs strict typechecking, adversarial domain tests, the declaration/JavaScript build, canonical PR registry validation and pinned contract verification. The domain library and tests need no monorepo files, external database, network service or provider account; persistence integration uses embedded PGlite with the installed dependency migration. Read-only synchronization uses caller-provided transport and transactional store interfaces. Installing dev dependencies uses the lockfile. Node 24 is required for native TypeScript test execution; package consumers load compiled JavaScript from `dist`.

```ts
import { createCorrespondenceState, transitionCorrespondence, projectMail } from '@accountability/correspondence';
import type { Context } from '@accountability/correspondence/contracts';

// A trusted host supplies context after authentication, never from mail content.
const human: Context = {
  tenantId: 'example', projectId: 'research', purpose: 'records-inquiry',
  requestId: 'draft-example', now: '2030-01-01T00:00:00Z',
  actor: { id: 'editor', kind: 'human', roles: ['correspondence:control', 'correspondence:write', 'correspondence:read'] },
};
const initial = createCorrespondenceState(human, { mailboxId: 'research', brand: 'Example Research' });
const created = transitionCorrespondence(initial, human, {
  type: 'createThread', inputId: 'thread-1', threadId: 'records',
  recipient: 'reader@example.org', subject: 'Record availability',
});
const drafted = transitionCorrespondence(created.state, human, {
  type: 'createDraft', inputId: 'draft-1', draftId: 'inquiry', threadId: 'records',
  content: { kind: 'research', topic: 'Record availability', questions: ['Where can I find the records?'] },
});
console.log(projectMail(drafted.state, human, { view: 'drafts' }));
// drafted.gatewayCommands is empty. There is no connection or send grant.
```

The constructor defaults to human control with no connection or grant. Agents draft transparent, structured research inquiries with one to three short questions. Automation requires an explicit human-issued grant binding actor, recipient, purpose, epochs, time, budget and cooldown.

Mailbox projections provide inbox, archive, sent, drafts, unread, starred, trash, spam and All Mail, plus search and pagination. All Mail excludes trash/spam. These are local projections, not provider folder synchronization or a user interface.

`createAlphaCorrespondenceFixture()` is a deterministic fictional integration example, including a fake provider receipt and an unverified STOP reply. It sends nothing.

Consumers must authenticate contexts. The optional durable adapter persists state with atomic revision comparison and requires one-shot handoff consumption before command execution; pure-library consumers must supply the same guarantees. A committed handoff is the point after which takeover reports an unrecallable send. Unknown external outcomes block repeat sends to that recipient and permit read-only reconciliation. Provider acceptance is not proof of delivery.

For provider synchronization and reply ingestion, see the [SDK contract and official endpoint sources](docs/SYNC.md). `synchronizeMailbox` bounds pages and messages, fences scope/account/auth epochs, quarantines HTML/attachments and commits each page with its ingested evidence and cursor atomically through the host store. No live provider calls were made during development.

For the durable aggregate and real `MailboxSyncStore`, use `CorrespondenceRepository` from `@accountability/correspondence/durable` and read the [dedicated-database persistence contract](docs/DURABILITY.md). It reuses the pinned Evidence generic persistence SDK in a separate correspondence database; it never connects to upstream operational databases.

See [architecture](docs/ARCHITECTURE.md), [source provenance](docs/PROVENANCE.md), and the [canonical work registry](registry/prs.json). Contracts are vendored byte-identical from Identity commit `2ecac5a7ec01e4470774ef545060b99dba38014d`. The merged foundation is tracked in [PR #1](https://github.com/neophilism/Correspondence-and-Outreach-Engine/pull/1). The merged synchronization SDK is tracked in [PR #2](https://github.com/neophilism/Correspondence-and-Outreach-Engine/pull/2); durable persistence is tracked in [PR #3](https://github.com/neophilism/Correspondence-and-Outreach-Engine/pull/3). Local checks, CI, merge and live acceptance are separate evidence.

## Service layer

`src/engine/` adds the persisted service used by the Public Accountability Machine: a Gmail-like mail workspace API, contact plans for unresolved questions, bounded sending grants, human takeover, a dispatch queue with reconciliation of uncertain sends, and inbound ingestion with deterministic classification. Full surface, events, limits and honest status: [`docs/ENGINE_API.md`](docs/ENGINE_API.md).

```sh
npm ci
TEST_DATABASE_URL=postgresql://user:pass@127.0.0.1:5432/postgres npm run check   # engine tests are skipped visibly without it
DATABASE_URL=postgresql://… IDENTITY_PUBLIC_KEYS='{"kid":"-----BEGIN PUBLIC KEY-----…"}' \
  CORRESPONDENCE_SECRET_KEY="$(head -c 32 /dev/urandom | base64)" OBJECT_STORE_PATH=./data/objects npm run serve
```

```ts
import { createEngine, migrate, routes } from '@accountability/correspondence/engine';
```

The note above that outbound execution is fake-only describes the earlier foundation modules; the service layer sends through real SMTP, Gmail API or Microsoft Graph adapters when a mailbox is configured with credentials, and reports `unavailable` otherwise. Gmail and Graph adapters are implemented but not verified against live providers.
