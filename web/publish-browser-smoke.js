import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright-core';
import { createRecoveryFile, serializeRecoveryFile } from './key-vault-core.js';
import { validateSignedSelfRegistration } from '../shared/self-registration-core.js';

const origin = process.env.PASSPORT_ORIGIN || 'http://127.0.0.1:8765';
const executablePath = process.env.CHROME_EXECUTABLE_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const api = 'https://agent-passport-api.jong6598.workers.dev';
const password = 'publish browser recovery password';
const temp = await mkdtemp(join(tmpdir(), 'agent-passport-publish-'));
const recovery = await createRecoveryFile(password);
const keyPath = join(temp, 'owner.agent-passport-key');
await writeFile(keyPath, serializeRecoveryFile(recovery), { mode: 0o600 });
const challenge = { id: crypto.randomUUID(), nonce: 'A'.repeat(32), did: recovery.did, expiresAt: new Date(Date.now() + 600000).toISOString() };
const browser = await chromium.launch({ headless: true, executablePath });

try {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  const errors = [];
  const requests = [];
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => requests.push({ url: request.url(), method: request.method(), body: request.postData() }));
  await page.route(`${api}/v1/challenges`, async route => {
    const body = JSON.parse(route.request().postData());
    assert.deepEqual(body, { did: recovery.did });
    await route.fulfill({ status: 201, contentType: 'application/json', headers: { 'access-control-allow-origin': origin }, body: JSON.stringify({ ok: true, challenge }) });
  });
  await page.route('https://challenges.cloudflare.com/turnstile/v0/api.js', route => route.fulfill({ status: 200, contentType: 'application/javascript', body: '' }));

  await page.goto(`${origin}/publish.html`, { waitUntil: 'networkidle' });
  assert.equal(requests.some(item => item.url.startsWith('https://challenges.cloudflare.com')), false);
  await page.fill('#publish-name', 'PUBLISH TEST');
  await page.selectOption('#publish-type', 'BUILDER');
  await page.fill('#publish-region', 'KOREA');
  await page.fill('#publish-languages', 'KO, EN');
  await page.fill('#publish-motto', 'KEY CONTROL IS NOT IDENTITY');
  await page.setInputFiles('#publish-key-file', keyPath);
  await page.fill('#publish-password', password);
  await page.check('#publish-consent');
  await page.click('#publish-button');
  await page.waitForURL(`${origin}/activate.html`);
  await page.waitForFunction(() => document.querySelector('#activate-did')?.textContent.startsWith('did:key:'));

  const raw = await page.evaluate(() => sessionStorage.getItem('agent-passport-pending-registration'));
  const pending = JSON.parse(raw);
  const verified = await validateSignedSelfRegistration(pending.registration, challenge);
  assert.equal(verified.did, recovery.did);
  assert.equal(raw.includes(password), false);
  assert.equal(raw.includes('ciphertext'), false);
  assert.equal(await page.textContent('#activate-name'), 'PUBLISH TEST');
  assert.equal(await page.textContent('#activate-did'), recovery.did);
  assert.equal((await page.textContent('#activate-hash')).length, 64);
  assert.equal((await page.textContent('body')).includes(password), false);
  const storage = await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length, cookies: document.cookie }));
  const geometry = await page.evaluate(() => ({ body: document.body.scrollWidth, viewport: document.documentElement.clientWidth }));
  assert.deepEqual(storage, { local: 0, session: 1, cookies: '' });
  assert.equal(geometry.body, geometry.viewport);
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ did: recovery.did, signatureVerified: true, challengeRequestFields: ['did'], secretOnActivatePage: false, storage, geometry, consoleErrors: errors, status: 'PASS' }, null, 2));
  await context.close();
} finally {
  await browser.close();
  await rm(temp, { recursive: true, force: true });
}
