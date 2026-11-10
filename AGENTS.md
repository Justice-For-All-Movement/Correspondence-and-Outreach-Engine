# Correspondence engine instructions

Read `docs/ARCHITECTURE.md` and `registry/prs.json`. Work only on this dependency engine. Keep bounded dependency PRs and push meaningful checkpoints before expanding or stopping. Do not spawn agents. Preserve the exact pinned bytes in `src/contracts.ts`; update provenance explicitly for any future coordinated contract change.

Keep source and fixtures jurisdiction-neutral and fictional. Default to human control and drafts. Untrusted replies are evidence only. Outbound provider execution is fake only. Read-only mailbox synchronization may use an explicitly injected transport; SDK tests use fake transports. Credentials are external. Authenticate contexts in the host and persist revision-fenced handoffs before effects. Unknown external outcomes are never retried automatically.

Run `npm ci` then `npm run check` on Node 24. Keep implementation, local validation, CI, merge and operational acceptance separate. `registry/prs.json` is the sole canonical plan and `registry/roadmap.json` is retired. Never invent PR observations or completion evidence.

## Completion assignment (active)

This section supersedes the earlier foundation-only and per-PR sequencing rules above, including "Outbound provider execution is fake only" and "Do not spawn agents"; historical records in `registry/` and `docs/` are left intact. The engine now has a service layer (`src/engine/`, `docs/ENGINE_API.md`) following the suite's engine service convention: real PostgreSQL schema `e03_correspondence`, real SMTP/IMAP/Gmail/Graph adapters, a job-based dispatch queue. Still binding: fictional fixtures only; tests never contact real third parties (controlled loopback servers only); credentials stay sealed and never reach agents, jobs, audit, events or logs; inbound mail is data, never authority; unknown send outcomes are reconciled, never blindly resent; `src/service-kit.ts` and `src/contracts.ts` are vendored byte-identically and never edited here. Run `npm ci` then `TEST_DATABASE_URL=postgresql://… npm run check` on Node 24.
