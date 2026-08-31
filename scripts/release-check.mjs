import { readFile, readdir, stat } from 'node:fs/promises';
import { relative, resolve, sep } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const excluded = new Set(['.git', 'node_modules', 'dist']);
const expectedDist = new Set([
  '.nojekyll', 'app.js', 'index.html', 'studio-bundle.js', 'studio.css', 'studio.html',
  'submit-bundle.js', 'submit.css', 'submit.html',
  'styles.css', 'vault-bundle.js', 'vault.css', 'vault.html', 'data/index.json',
  'data/passports/hyeon-hermes.json'
]);
const forbiddenNames = [/(^|\/)\.env(?:\.|$)/i, /\.pem$/i, /\.agent-passport-key$/i, /(^|\/)private(\/|$)/i, /(^|\/)logs?(\/|$)/i];
const forbiddenContent = [
  { name: 'private PEM', regex: /-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/ },
  { name: 'private home path', regex: /\/Users\/kimjonghyeon(?:\/|\\)/ },
  { name: 'GitHub token', regex: /\bgh[opsu]_[A-Za-z0-9]{20,}\b/ },
  { name: 'AWS access key', regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'generic assigned secret', regex: /\b(?:api[_-]?key|secret|token|password)\s*[=:]\s*["'][A-Za-z0-9_\-]{24,}["']/i }
];
const textExtensions = new Set(['.css', '.html', '.js', '.json', '.md', '.mjs', '.txt', '.yml', '.yaml', '']);

async function walk(dir, skipTopLevel = false) {
  const output = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (!skipTopLevel && dir === root && excluded.has(entry.name)) continue;
    const path = resolve(dir, entry.name);
    if (entry.isDirectory()) output.push(...await walk(path, true));
    else output.push(path);
  }
  return output;
}

function extension(path) {
  const name = path.split(sep).at(-1);
  const dot = name.lastIndexOf('.');
  return dot < 0 ? '' : name.slice(dot).toLowerCase();
}

async function scan(paths, label) {
  for (const path of paths) {
    const rel = relative(root, path).split(sep).join('/');
    for (const pattern of forbiddenNames) if (pattern.test(rel)) throw new Error(`${label}: forbidden path ${rel}`);
    if (!textExtensions.has(extension(path))) continue;
    const body = await readFile(path, 'utf8');
    for (const rule of forbiddenContent) if (rule.regex.test(body)) throw new Error(`${label}: ${rule.name} found in ${rel}`);
  }
}

const sourceFiles = await walk(root);
await scan(sourceFiles, 'source');

const distRoot = resolve(root, 'dist');
if (!(await stat(distRoot)).isDirectory()) throw new Error('dist is missing; run npm run prepare:dist');
const distFiles = await walk(distRoot, true);
await scan(distFiles, 'dist');
const actualDist = new Set(distFiles.map(path => relative(distRoot, path).split(sep).join('/')));
if (actualDist.size !== expectedDist.size || [...actualDist].some(path => !expectedDist.has(path))) {
  throw new Error(`dist allowlist mismatch: ${JSON.stringify([...actualDist].sort())}`);
}

const index = JSON.parse(await readFile(resolve(distRoot, 'data/index.json'), 'utf8'));
if (index.schema !== 'agent-passport-public-index-v1' || !Array.isArray(index.passports) || !index.passports.length) throw new Error('Invalid public index');
const dids = new Set();
for (const entry of index.passports) {
  if (dids.has(entry.did)) throw new Error(`Duplicate DID: ${entry.did}`);
  dids.add(entry.did);
  if (!/^data\/passports\/[a-z0-9-]+\.json$/.test(entry.manifest)) throw new Error(`Unsafe manifest path: ${entry.manifest}`);
  const manifest = JSON.parse(await readFile(resolve(distRoot, entry.manifest), 'utf8'));
  if (manifest.profile?.did !== entry.did) throw new Error(`Index/manifest DID mismatch: ${entry.did}`);
}

for (const bundle of ['vault-bundle.js', 'studio-bundle.js', 'submit-bundle.js']) {
  if ((await stat(resolve(distRoot, bundle))).size < 10_000) throw new Error(`${bundle} appears incomplete`);
}
console.log(`Release check passed: ${sourceFiles.length} source files, ${distFiles.length} allowlisted deployment files, ${dids.size} Passport DID.`);
