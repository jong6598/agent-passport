import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright-core';
import { createRecoveryFile, serializeRecoveryFile, verifyDidSignature } from './key-vault-core.js';

const origin = process.env.PASSPORT_ORIGIN || 'http://127.0.0.1:8765';
const executablePath = process.env.CHROME_EXECUTABLE_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const password = 'studio browser recovery password 2026';
const temp = await mkdtemp(join(tmpdir(), 'agent-passport-studio-'));
const recoveryPath = join(temp, 'studio.agent-passport-key');
const recovery = await createRecoveryFile(password);
await writeFile(recoveryPath, serializeRecoveryFile(recovery), { mode: 0o600 });
const browser = await chromium.launch({ headless: true, executablePath });

try {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, acceptDownloads: true });
  const page = await context.newPage();
  const errors = [];
  const external = [];
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => { if (new URL(request.url()).origin !== origin) external.push(request.url()); });

  await page.goto(`${origin}/studio.html`, { waitUntil: 'networkidle' });
  await page.setInputFiles('#studio-key-file', recoveryPath);
  await page.fill('#artifact-url', 'javascript:alert(1)');
  await page.fill('#contribution-title', 'Safe Adapter Documentation');
  await page.selectOption('#contribution-category', 'CODE');
  await page.fill('#contribution-date', '2026-08-31');
  await page.fill('#contribution-summary', 'A public integration guide and tested adapter for human-approved Technocore contributions.');
  await page.click('#preview-button');
  await page.waitForFunction(() => document.querySelector('#studio-status')?.textContent.includes('public HTTP(S)'));
  assert.match(await page.textContent('#studio-status'), /public HTTP\(S\)/);
  assert.equal(await page.isHidden('#preview-panel'), true);

  await page.fill('#artifact-url', 'https://github.com/jong6598/technocore-safe-adapter');
  await page.fill('#artifact-commit', 'c1121b1f6ed43a60e1700d8517cb1bded17658b1');
  await page.fill('#technocore-room', 'lobby');
  await page.fill('#technocore-sequence', '3671396');
  await page.click('#preview-button');
  await page.waitForSelector('#preview-panel:not([hidden])');
  const firstHash = await page.textContent('#preview-hash');
  assert.match(firstHash, /^[0-9a-f]{64}$/);
  assert.equal(await page.textContent('#preview-did'), recovery.did);

  await page.fill('#contribution-title', 'Changed title invalidates preview');
  assert.equal(await page.isHidden('#preview-panel'), true);
  assert.match(await page.textContent('#studio-status'), /Fields changed/);
  await page.fill('#contribution-title', 'Safe Adapter Documentation');
  await page.click('#preview-button');
  await page.waitForSelector('#preview-panel:not([hidden])');
  const reviewedHash = await page.textContent('#preview-hash');

  await page.fill('#studio-password', password);
  await page.click('#sign-button');
  await page.waitForSelector('#signed-panel:not([hidden])');
  assert.equal(await page.textContent('#signed-hash'), reviewedHash);
  assert.match(await page.textContent('#studio-status'), /Nothing was published/);

  const [download] = await Promise.all([page.waitForEvent('download'), page.click('#download-contribution')]);
  const downloadedPath = await download.path();
  const signedDocument = JSON.parse(await readFile(downloadedPath, 'utf8'));
  assert.equal(signedDocument.schema, 'agent-passport-signed-contribution-v1');
  assert.equal(signedDocument.publication.status, 'not-published');
  assert.equal(signedDocument.publication.separateApprovalRequired, true);
  assert.equal(createHash('sha256').update(signedDocument.canonicalJson).digest('hex'), signedDocument.payloadSha256);
  assert.equal(await verifyDidSignature(signedDocument.signature.did, signedDocument.canonicalJson, signedDocument.signature.value), true);

  await page.click('#prepare-publication');
  await page.waitForSelector('#publication-panel:not([hidden])');
  assert.match(await page.textContent('#publication-draft'), /Signed manifest SHA-256:/);
  assert.match(await page.textContent('#studio-status'), /separate explicit approval/);
  const storage = await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length, cookies: document.cookie }));
  assert.deepEqual(storage, { local: 0, session: 0, cookies: '' });
  const geometry = await page.evaluate(() => ({ body: document.body.scrollWidth, viewport: document.documentElement.clientWidth }));
  assert.equal(geometry.body, geometry.viewport);
  assert.deepEqual(external, []);
  assert.deepEqual(errors, []);
  await page.screenshot({ path: '/tmp/agent-passport-studio-browser-smoke.png', fullPage: true });
  console.log(JSON.stringify({ did: recovery.did, payloadSha256: reviewedHash, signatureVerified: true, publicationStatus: 'not-published', storage, geometry, externalRequests: external, consoleErrors: errors, status: 'PASS' }, null, 2));
  await context.close();
} finally {
  await browser.close();
  await rm(temp, { recursive: true, force: true });
}
