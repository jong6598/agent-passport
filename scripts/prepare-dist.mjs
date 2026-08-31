import { cp, mkdir, rm } from 'node:fs/promises';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const dist = resolve(root, 'dist');
const files = [
  '.nojekyll',
  'index.html',
  'app.js',
  'styles.css',
  'vault.html',
  'vault.css',
  'vault-bundle.js',
  'studio.html',
  'studio.css',
  'studio-bundle.js',
  'submit.html',
  'submit.css',
  'submit-bundle.js',
  'publish.html',
  'publish.css',
  'publish-bundle.js',
  'activate.html',
  'activate-bundle.js',
  'registration-config.js'
];

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });
for (const file of files) await cp(resolve(root, file), resolve(dist, file));
await cp(resolve(root, 'data'), resolve(dist, 'data'), { recursive: true });
console.log(`Prepared ${dist} from an explicit public-site allowlist.`);
