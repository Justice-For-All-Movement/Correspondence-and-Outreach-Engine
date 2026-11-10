import type { Migration } from '../service-kit.ts';

export const SCHEMA = 'e03_correspondence';

/** `{s}` is replaced by the schema name. Applied migrations are checksummed: append new ones, never edit. */
export const migrations: readonly Migration[] = [{ id: '001_correspondence_service', sql: `
create table {s}.mailboxes (
  tenant_id text not null, project_id text not null, id uuid primary key,
  address text not null, display_name text not null default '',
  provider text not null check (provider in ('smtp_imap','gmail','graph','ingest_only')),
  config jsonb not null default '{}', secret_enc text, secret_fields text[] not null default '{}', secret_set_at timestamptz, auth_epoch int not null default 0,
  sender_profile jsonb not null default '{}', profile_verified_at timestamptz, profile_verified_by text,
  control_mode text not null default 'automation' check (control_mode in ('automation','human')),
  control_epoch int not null default 0, control_reason text, control_by text, control_at timestamptz,
  state text not null default 'active' check (state in ('active','disabled')),
  sync_state jsonb not null default '{}', last_sync_at timestamptz, last_sync_status text, last_sync_error text,
  created_by text not null, created_at timestamptz not null, updated_at timestamptz not null,
  unique (tenant_id, project_id, address)
);
create table {s}.contacts (
  tenant_id text not null, project_id text not null, id uuid primary key,
  address text not null, display_name text not null default '', organization text not null default '', role_title text not null default '',
  why_may_know text not null default '', route_source text, route_note text not null default '', sources text[] not null default '{}',
  state text not null default 'candidate' check (state in ('candidate','verified','rejected')),
  verified_by text, verified_at timestamptz, sensitive boolean not null default false, compartment text,
  blocked boolean not null default false, block_reasons jsonb not null default '[]',
  stale boolean not null default false, stale_reasons jsonb not null default '[]',
  revision int not null default 1, created_by text not null, created_at timestamptz not null, updated_at timestamptz not null,
  search tsvector
);
create unique index contacts_address on {s}.contacts (tenant_id, project_id, address, coalesce(compartment, ''));
create index contacts_search on {s}.contacts using gin (search);
create table {s}.contact_events (
  seq bigint generated always as identity primary key, tenant_id text not null, project_id text not null,
  contact_id uuid not null, kind text not null, ref text, detail jsonb not null default '{}', actor_id text not null, at timestamptz not null
);
create index contact_events_contact on {s}.contact_events (tenant_id, project_id, contact_id, seq);
create table {s}.suppressions (
  tenant_id text not null, project_id text not null, id uuid primary key,
  scope text not null check (scope in ('address','domain')), value text not null,
  reason text not null, source text not null check (source in ('refusal','manual','bounce','upstream')), source_ref text,
  created_by text not null, created_at timestamptz not null, lifted_at timestamptz, lifted_by text, lift_reason text
);
create unique index suppressions_active on {s}.suppressions (tenant_id, project_id, scope, value) where lifted_at is null;
create table {s}.labels (
  tenant_id text not null, project_id text not null, id uuid primary key, name text not null, color text not null default '',
  created_by text not null, created_at timestamptz not null, unique (tenant_id, project_id, name)
);
create table {s}.plans (
  tenant_id text not null, project_id text not null, id uuid primary key,
  question_ref text not null, question text not null, context text not null default '', allowed_disclosure text not null default '',
  state text not null default 'open' check (state in ('open','closed')), compartment text, sources text[] not null default '{}',
  blocked boolean not null default false, block_reasons jsonb not null default '[]',
  stale boolean not null default false, stale_reasons jsonb not null default '[]',
  created_by text not null, created_at timestamptz not null, updated_at timestamptz not null
);
create index plans_question on {s}.plans (tenant_id, project_id, question_ref);
create table {s}.plan_candidates (
  tenant_id text not null, project_id text not null, plan_id uuid not null, contact_id uuid not null,
  rank int not null, rationale text not null default '',
  state text not null default 'proposed' check (state in ('proposed','drafted','contacted','responded','refused','bounced','skipped')),
  thread_id uuid, updated_at timestamptz not null, primary key (plan_id, contact_id)
);
create table {s}.threads (
  tenant_id text not null, project_id text not null, id uuid primary key, mailbox_id uuid not null,
  subject text not null default '', question_ref text, plan_id uuid, contact_id uuid, compartment text, assignee text,
  control_mode text not null default 'automation' check (control_mode in ('automation','human')),
  control_epoch int not null default 0, control_reason text, control_by text, control_at timestamptz,
  archived boolean not null default false, trashed boolean not null default false, spam boolean not null default false,
  starred boolean not null default false, refused boolean not null default false,
  blocked boolean not null default false, block_reasons jsonb not null default '[]',
  stale boolean not null default false, stale_reasons jsonb not null default '[]',
  sources text[] not null default '{}', last_message_at timestamptz not null,
  created_by text not null, created_at timestamptz not null, updated_at timestamptz not null
);
create index threads_list on {s}.threads (tenant_id, project_id, mailbox_id, last_message_at desc);
create table {s}.thread_labels (
  tenant_id text not null, project_id text not null, thread_id uuid not null, label_id uuid not null, primary key (thread_id, label_id)
);
create table {s}.messages (
  tenant_id text not null, project_id text not null, id uuid primary key, thread_id uuid not null, mailbox_id uuid not null, compartment text,
  direction text not null check (direction in ('inbound','outbound')),
  state text not null check (state in ('draft','queued','sending','sent','uncertain','failed','cancelled','received','discarded')),
  origin text not null check (origin in ('human','agent','external')), author_id text not null,
  from_addr text not null, from_name text not null default '', to_addrs text[] not null default '{}', cc_addrs text[] not null default '{}',
  subject text not null default '', body_text text not null default '', body_html text,
  structured jsonb, disclosure text, identity_flags jsonb not null default '[]',
  message_id_header text, in_reply_to text, refs text[] not null default '{}', dedupe_key text,
  raw_key text, raw_sha256 text, raw_size int,
  classification text, classification_detail jsonb not null default '{}',
  is_read boolean not null default true, revision int not null default 1,
  sent_at timestamptz, received_at timestamptz, created_at timestamptz not null, updated_at timestamptz not null,
  search tsvector
);
create unique index messages_inbound_dedupe on {s}.messages (tenant_id, project_id, mailbox_id, dedupe_key) where direction = 'inbound';
create index messages_thread on {s}.messages (tenant_id, project_id, thread_id, created_at);
create index messages_header on {s}.messages (tenant_id, project_id, mailbox_id, message_id_header);
create index messages_search on {s}.messages using gin (search);
create table {s}.message_provider_ids (
  tenant_id text not null, project_id text not null, mailbox_id uuid not null, provider_id text not null, message_id uuid not null,
  primary key (mailbox_id, provider_id)
);
create table {s}.message_versions (
  tenant_id text not null, project_id text not null, message_id uuid not null, revision int not null,
  snapshot jsonb not null, actor_id text not null, at timestamptz not null, primary key (message_id, revision)
);
create table {s}.attachments (
  tenant_id text not null, project_id text not null, id uuid primary key, message_id uuid not null, thread_id uuid not null, compartment text,
  filename text not null, media_type text not null, size int not null, sha256 text not null, object_key text not null,
  content_id text, evidence_ref text, removed boolean not null default false, created_at timestamptz not null
);
create index attachments_message on {s}.attachments (tenant_id, project_id, message_id);
create table {s}.grants (
  tenant_id text not null, project_id text not null, id uuid primary key,
  grantee_id text not null, mailbox_id uuid not null, purpose text not null, question_refs text[] not null default '{}',
  recipient_allowlist text[] not null default '{}', domain_allowlist text[] not null default '{}',
  max_messages int not null check (max_messages > 0), per_recipient_cap int not null check (per_recipient_cap > 0),
  cooldown_seconds int not null check (cooldown_seconds >= 0), follow_up_limit int not null check (follow_up_limit >= 0),
  expires_at timestamptz not null, used_messages int not null default 0,
  state text not null default 'active' check (state in ('active','revoked')),
  granted_by text not null, granted_at timestamptz not null, revoked_by text, revoked_at timestamptz, revoke_reason text
);
create table {s}.dispatches (
  tenant_id text not null, project_id text not null, id uuid primary key, message_id uuid not null, thread_id uuid not null,
  mailbox_id uuid not null, compartment text,
  mode text not null check (mode in ('automated','human')), kind text not null check (kind in ('initial','reply','follow_up')),
  grant_id uuid, requested_by text not null, recipients text[] not null, message_id_header text not null,
  thread_epoch int not null, mailbox_epoch int not null,
  state text not null check (state in ('queued','dispatching','accepted','delivered','bounced','uncertain','not_sent','failed','cancelled')),
  state_reason text, reconciled_at timestamptz, reconciliation jsonb, provider_id text, provider_response text,
  run_at timestamptz not null, dispatching_at timestamptz, accepted_at timestamptz, settled_at timestamptz,
  attempts int not null default 0, reconcile_attempts int not null default 0, budget_reservation text, job_id uuid,
  created_at timestamptz not null, updated_at timestamptz not null
);
create index dispatches_state on {s}.dispatches (tenant_id, project_id, state, run_at);
create index dispatches_thread on {s}.dispatches (tenant_id, project_id, thread_id);
create index dispatches_header on {s}.dispatches (tenant_id, project_id, mailbox_id, message_id_header);
create table {s}.delivery_events (
  seq bigint generated always as identity primary key, tenant_id text not null, project_id text not null,
  dispatch_id uuid not null, kind text not null, detail jsonb not null default '{}', at timestamptz not null
);
create index delivery_events_dispatch on {s}.delivery_events (tenant_id, project_id, dispatch_id, seq);
create table {s}.assertions (
  tenant_id text not null, project_id text not null, id uuid primary key, message_id uuid not null, thread_id uuid not null, compartment text,
  question_ref text, quote text not null, attributed_to text not null, contact_id uuid,
  -- This engine never verifies: replies are attributed information for another engine to evaluate.
  status text not null default 'attributed_unverified' check (status = 'attributed_unverified'),
  extraction text not null check (extraction in ('deterministic','proposed')), proposed_by text not null,
  verification_ref text, created_at timestamptz not null
);
create index assertions_message on {s}.assertions (tenant_id, project_id, message_id);
create table {s}.upstream_changes (
  tenant_id text not null, project_id text not null, event_id text not null, kind text not null, result jsonb not null, at timestamptz not null,
  primary key (tenant_id, project_id, event_id)
);
` }];
