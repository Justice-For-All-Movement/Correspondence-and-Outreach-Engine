import {readFile} from 'node:fs/promises';
import {parsePrRegistry} from '../registry/pr-contract.mjs';
const body = await readFile(new URL('../registry/prs.json', import.meta.url), 'utf8');
// The repository moved organizations. The register is a historical record under its original name; CI in the
// successor repository validates it against that recorded name. Any other repository identity still fails.
const SUCCESSORS = { 'justice-for-all-movement/correspondence-and-outreach-engine': 'neophilism/Correspondence-and-Outreach-Engine' };
const current = process.env.GITHUB_REPOSITORY || JSON.parse(body).repository;
const repository = SUCCESSORS[current.toLowerCase()] ?? current;
const {document} = parsePrRegistry(body, repository);
const retired = JSON.parse(await readFile(new URL('../registry/roadmap.json', import.meta.url), 'utf8'));
if (retired.repository !== repository || retired.deprecated !== true || retired.redirectTo !== 'registry/prs.json' ||
    Object.hasOwn(retired, 'milestones') || Object.hasOwn(retired, 'units') || Object.hasOwn(retired, 'plannedPrCount'))
  throw new Error('Only registry/prs.json may contain the active PR plan');
console.log(`Valid PR registry: ${repository}, ${document.units.length} approved units; runtime acceptance is separate.`);
