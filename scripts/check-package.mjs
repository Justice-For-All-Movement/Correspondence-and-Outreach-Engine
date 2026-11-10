import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const temporary = await mkdtemp(join(root, '.package-check-'));
try {
  const result = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', temporary],
    { cwd: root, encoding: 'utf8' }));
  const archive = result[0];
  assert.ok(archive.files.some(file => file.path === 'dist/index.js'));
  assert.ok(archive.files.some(file => file.path === 'dist/index.d.ts'));
  assert.ok(!archive.files.some(file => file.path.startsWith('src/') || file.path.startsWith('node_modules/')));
  const consumer = join(temporary, 'consumer');
  await mkdir(consumer);
  const archivePath = join(temporary, archive.filename);
  const packageManifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  const rootLock = JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8'));
  const consumerManifest = { name: 'correspondence-consumer', version: '1.0.0', private: true, type: 'module',
    dependencies: { [packageManifest.name]: `file:${archivePath}` } };
  await writeFile(join(consumer, 'package.json'), JSON.stringify(consumerManifest));
  // npm ci caches exact tarballs, not necessarily registry packuments. Retain its exact production
  // closure so this second install needs no metadata request and still tests the real pinned SDK.
  const production = Object.fromEntries(Object.entries(rootLock.packages).filter(([path, item]) => path && !item.dev));
  const packages = { '': { name: consumerManifest.name, version: consumerManifest.version, dependencies: consumerManifest.dependencies },
    ...production, [`node_modules/${packageManifest.name}`]: { version: packageManifest.version,
      resolved: `file:${archivePath}`, integrity: archive.integrity, dependencies: packageManifest.dependencies,
      engines: packageManifest.engines } };
  await writeFile(join(consumer, 'package-lock.json'), JSON.stringify({ name: consumerManifest.name, version: consumerManifest.version,
    lockfileVersion: 3, requires: true, packages }));
  execFileSync('npm', ['ci', '--offline', '--no-audit', '--no-fund'], { cwd: consumer, stdio: 'pipe' });
  const installed = join(consumer, 'node_modules/@accountability/correspondence');
  const manifest = JSON.parse(await readFile(join(installed, 'package.json'), 'utf8'));
  assert.equal(manifest.exports['.'].default, './dist/index.js');
  assert.equal(manifest.exports['./contracts'].default, './dist/contracts.js');
  assert.equal(manifest.exports['./durable'].default, './dist/durable.js');
  assert.equal(manifest.exports['./operator'].default, './dist/operator.js');
  assert.equal(manifest.exports['./engine'].default, './dist/engine/index.js');
  assert.equal(manifest.exports['./serve'].default, './dist/engine/serve.js');
  await writeFile(join(consumer, 'smoke.mjs'), `
import assert from 'node:assert/strict';
import { createAlphaCorrespondenceFixture, projectMail, createMailboxSyncState, synchronizeMailbox, transitionCorrespondence } from '@accountability/correspondence';
import { DomainError } from '@accountability/correspondence/contracts';
import { CorrespondenceRepository } from '@accountability/correspondence/durable';
import { createOperatorHandler } from '@accountability/correspondence/operator';
import { scoped } from '@accountability/evidence/database';
assert.match(import.meta.resolve('@accountability/correspondence'), /node_modules\\/.*\\/dist\\/index\\.js$/);
assert.equal(typeof CorrespondenceRepository, 'function');
assert.equal(typeof createOperatorHandler, 'function');
const privateOperator = createOperatorHandler({load:async()=>{throw Error('must not load');},execute:async()=>{throw Error('must not execute');}},{authenticate:async()=>null},{tenantId:'example',projectId:'research',mailboxId:'mailbox',origin:'https://workspace.example'});
assert.equal((await privateOperator(new Request('https://workspace.example/operator/mail'))).status,401);
assert.equal(typeof scoped, 'function');
const engineModule = await import('@accountability/correspondence/engine');
assert.equal(engineModule.SCHEMA, 'e03_correspondence');
assert.equal(typeof engineModule.createEngine, 'function');
assert.equal(engineModule.manifest.id, 'E03');
const fixture = createAlphaCorrespondenceFixture();
const human = fixture.steps[0].context;
assert.equal(projectMail(fixture.state, human).total, 1);
assert.equal(fixture.providerState.attempts[0].calls, 1);
assert.equal(new DomainError('example', 'example').code, 'example');
const syncBinding = { tenantId: 'example', projectId: 'research', mailboxId: 'mailbox', provider: 'gmail',
  accountRef: 'example-account', authEpoch: 1, address: 'reader@example.org', providerAccountId: 'reader@example.org', folderId: null };
assert.equal(createMailboxSyncState(syncBinding).cursor, null);
assert.equal(typeof synchronizeMailbox, 'function');
const connected = transitionCorrespondence(fixture.initial, human, { type: 'connectMailbox', inputId: 'installed-sync',
  connection: { provider: 'gmail', accountRef: 'example-account', connectionRef: 'external-handle', address: 'reader@example.org' } }).state;
const binding = { ...syncBinding, tenantId: connected.tenantId, projectId: connected.projectId, mailboxId: connected.mailbox.id };
let snapshot = { correspondence: connected, sync: createMailboxSyncState(binding) };
const pages = [{ emailAddress: binding.address, historyId: '100' }, { messages: [] }];
const transport = { binding, async read(request) {
  assert.equal(request.method, 'GET');
  return { status: 200, body: (async function* () { yield Buffer.from(JSON.stringify(pages.shift())); })() };
} };
const store = { async load() { return structuredClone(snapshot); }, async commit(input) {
  assert.equal(input.expectedSyncRevision, snapshot.sync.revision);
  assert.equal(input.expectedCorrespondenceRevision, snapshot.correspondence.revision);
  snapshot = structuredClone(input.next); return true;
} };
const ingress = fixture.steps.find(step => step.context.actor.kind === 'service').context;
const synchronized = await synchronizeMailbox({ context: ingress, binding, transport, store, limits: { maxPages: 1 } });
assert.equal(synchronized.pagesCommitted, 1);
assert.equal(snapshot.sync.cursor.kind, 'gmail-history');
assert.equal(pages.length, 0);
console.log('Installed compiled ESM package works from node_modules with fake fixture');
`);
  process.stdout.write(execFileSync(process.execPath, ['smoke.mjs'], { cwd: consumer, encoding: 'utf8' }));
} finally {
  await rm(temporary, { recursive: true, force: true });
}
