import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const bytes = await readFile(new URL('../src/contracts.ts', import.meta.url));
const sha = createHash('sha256').update(bytes).digest('hex');
if (sha !== 'd86141cb7546a723f837a298e4ea6fef62692918f78f5aab2d72d6639987fcc5') throw new Error('Vendored Identity contracts differ from pinned provenance');
console.log('Identity contracts match pinned commit 2ecac5a7ec01e4470774ef545060b99dba38014d');

const pin = 'git+https://github.com/Justice-For-All-Movement/evidence-storage-and-provenance-engine.git#dce7105a70b42d77afe4cd48d34723331447037c';
const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const lock = JSON.parse(await readFile(new URL('../package-lock.json', import.meta.url), 'utf8'));
if (manifest.dependencies?.['@accountability/evidence'] !== pin || lock.packages[''].dependencies?.['@accountability/evidence'] !== pin ||
    lock.packages['node_modules/@accountability/evidence']?.resolved !== pin)
  throw new Error('Evidence persistence dependency must retain its exact approved HTTPS git commit');
if (!import.meta.resolve('@accountability/evidence/database').endsWith('/dist/database.js'))
  throw new Error('Evidence persistence must resolve to compiled ESM');
console.log('Evidence database SDK matches approved lockfile pin and compiled ESM export');
