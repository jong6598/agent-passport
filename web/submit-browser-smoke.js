import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright-core';
import { createRecoveryFile, serializeRecoveryFile, signWithRecoveryFile } from './key-vault-core.js';
import { canonicalJson, sha256Hex, validateSignedRegistration } from './registration-core.js';

const origin = process.env.PASSPORT_ORIGIN || 'http://127.0.0.1:8765';
const executablePath = process.env.CHROME_EXECUTABLE_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const password = 'registration browser recovery password';
const temp = await mkdtemp(join(tmpdir(), 'agent-passport-registration-'));
const recovery = await createRecoveryFile(password);
const wrongRecovery = await createRecoveryFile('a different recovery password 2026');
const recoveryPath = join(temp, 'owner.agent-passport-key');
const wrongRecoveryPath = join(temp, 'wrong.agent-passport-key');
const contributionPath = join(temp, 'signed-contribution.json');
await writeFile(recoveryPath, serializeRecoveryFile(recovery), { mode: 0o600 });
await writeFile(wrongRecoveryPath, serializeRecoveryFile(wrongRecovery), { mode: 0o600 });

const payload = {
  schema: 'agent-passport-contribution-v1',
  id: '2026-08-31-public-registration-test',
  did: recovery.did,
  title: 'Public registration browser test',
  summary: 'A public artifact used to test the human-approved registration application flow.',
  category: 'CODE',
  date: '2026-08-31',
  artifact: { url: 'https://github.com/example/public-registration-test', commit: 'abcdef1' }
};
const contributionCanonical = canonicalJson(payload);
const contributionSignature = await signWithRecoveryFile(recovery, password, contributionCanonical);
const signedContribution = {
  schema: 'agent-passport-signed-contribution-v1',
  payload,
  canonicalJson: contributionCanonical,
  payloadSha256: await sha256Hex(contributionCanonical),
  signature: { algorithm: 'Ed25519', did: contributionSignature.did, value: contributionSignature.signature },
  publication: { status: 'not-published', separateApprovalRequired: true }
};
await writeFile(contributionPath, `${JSON.stringify(signedContribution, null, 2)}\n`, { mode: 0o600 });
const browser = await chromium.launch({ headless: true, executablePath });

try {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, acceptDownloads: true });
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin });
  const page = await context.newPage();
  const errors = [];
  const external = [];
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => { if (new URL(request.url()).origin !== new URL(origin).origin) external.push(request.url()); });

  await page.goto(`${origin}/submit.html`, { waitUntil: 'networkidle' });
  await page.setInputFiles('#signed-contribution-file', contributionPath);
  await page.fill('#display-name-input', 'TEST PASSPORT OWNER');
  await page.selectOption('#passport-type', 'BUILDER');
  await page.fill('#operator-region-input', 'KOREA');
  await page.fill('#languages-input', 'KO, EN');
  await page.fill('#motto-input', 'VERIFY BEFORE TRUST');
  for (const id of ['consent-index', 'consent-manifest', 'consent-links', 'consent-sensitive']) await page.check(`#${id}`);

  await page.setInputFiles('#registration-key-file', wrongRecoveryPath);
  await page.click('#registration-preview-button');
  await page.waitForFunction(() => document.querySelector('#registration-status')?.textContent.includes('does not match'));
  assert.equal(await page.isHidden('#registration-preview-panel'), true);

  await page.setInputFiles('#registration-key-file', recoveryPath);
  await page.click('#registration-preview-button');
  await page.waitForSelector('#registration-preview-panel:not([hidden])');
  const firstHash = await page.textContent('#registration-preview-hash');
  assert.match(firstHash, /^[0-9a-f]{64}$/);
  assert.equal(await page.textContent('#registration-preview-did'), recovery.did);
  assert.match(await page.textContent('#contribution-check'), /Verified:/);

  await page.fill('#display-name-input', 'CHANGED PASSPORT OWNER');
  assert.equal(await page.isHidden('#registration-preview-panel'), true);
  assert.match(await page.textContent('#registration-status'), /Fields changed/);
  await page.fill('#display-name-input', 'TEST PASSPORT OWNER');
  await page.click('#registration-preview-button');
  await page.waitForSelector('#registration-preview-panel:not([hidden])');

  await page.fill('#registration-password', 'wrong password long enough');
  await page.click('#registration-sign-button');
  await page.waitForFunction(() => document.querySelector('#registration-status')?.textContent.includes('wrong or the file was modified'));
  assert.equal(await page.isHidden('#registration-signed-panel'), true);

  await page.fill('#registration-password', password);
  await page.click('#registration-sign-button');
  await page.waitForSelector('#registration-signed-panel:not([hidden])');
  assert.match(await page.textContent('#registration-status'), /nothing was registered/i);
  assert.match(await page.getAttribute('#open-registration-issue', 'href'), /^https:\/\/github\.com\/jong6598\/agent-passport\/issues\/new\?/);

  const [download] = await Promise.all([page.waitForEvent('download'), page.click('#download-registration')]);
  const registration = JSON.parse(await readFile(await download.path(), 'utf8'));
  const validated = await validateSignedRegistration(registration);
  assert.equal(validated.did, recovery.did);
  assert.equal(registration.review.status, 'pending');
  assert.equal(registration.publication.status, 'not-registered');
  if (process.env.REGISTRATION_TEST_OUTPUT) {
    await writeFile(process.env.REGISTRATION_TEST_OUTPUT, `${JSON.stringify(registration, null, 2)}\n`, { mode: 0o600 });
  }

  await page.click('#copy-registration');
  await page.waitForFunction(() => document.querySelector('#registration-status')?.textContent.includes('copied'));
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  assert.deepEqual(JSON.parse(copied), registration);

  const storage = await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length, cookies: document.cookie }));
  const geometry = await page.evaluate(() => ({ body: document.body.scrollWidth, viewport: document.documentElement.clientWidth }));
  assert.deepEqual(storage, { local: 0, session: 0, cookies: '' });
  assert.equal(geometry.body, geometry.viewport);
  assert.deepEqual(external, []);
  assert.deepEqual(errors, []);
  await page.screenshot({ path: '/tmp/agent-passport-registration-browser-smoke.png', fullPage: true });
  console.log(JSON.stringify({ did: recovery.did, requestSha256: registration.payloadSha256, nestedContributionVerified: true, registrationSignatureVerified: true, reviewStatus: registration.review.status, publicationStatus: registration.publication.status, storage, geometry, externalRequests: external, consoleErrors: errors, status: 'PASS' }, null, 2));
  await context.close();
} finally {
  await browser.close();
  await rm(temp, { recursive: true, force: true });
}
