import assert from 'node:assert/strict';
import { chromium } from 'playwright-core';

const baseUrl = process.env.PASSPORT_BASE_URL || 'http://127.0.0.1:8765/vault.html';
const executablePath = process.env.CHROME_EXECUTABLE_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const browser = await chromium.launch({ headless: true, executablePath });
const context = await browser.newContext({ viewport: { width: 390, height: 844 }, acceptDownloads: true });
const page = await context.newPage();
let importedDid = null;
const consoleErrors = [];
const externalRequests = [];
const allRequests = [];
page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
page.on('pageerror', error => consoleErrors.push(error.message));
page.on('request', request => {
  allRequests.push(request.url());
  const url = new URL(request.url());
  if (url.origin !== new URL(baseUrl).origin) externalRequests.push(request.url());
});

try {
  await page.goto(baseUrl, { waitUntil: 'networkidle' });
  const password = 'browser recovery password 2026';
  await page.fill('#new-password', password);
  await page.fill('#confirm-password', password);
  await page.check('#loss-ack');
  await page.click('#create-button');
  await page.waitForSelector('#created-panel:not([hidden])');
  const createdDid = await page.textContent('#created-did');
  assert.match(createdDid, /^did:key:z6Mk/);

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.click('#download-button')
  ]);
  const downloadPath = await download.path();
  assert.ok(downloadPath);

  await page.setInputFiles('#recovery-file', downloadPath);
  await page.fill('#restore-password', password);
  await page.click('#verify-backup-button');
  await page.waitForSelector('#success-panel:not([hidden])');
  const verifiedDid = await page.textContent('#verified-did');
  assert.equal(verifiedDid, createdDid);
  assert.equal(await page.textContent('#issuance-state'), 'PASSPORT IDENTITY ISSUED');
  assert.match(await page.textContent('#vault-status'), /challenge signature verified/i);

  await page.reload({ waitUntil: 'networkidle' });
  await page.click('#import-details summary');
  const externalIdentity = await page.evaluate(async () => {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    const base58 = bytes => {
      const digits = [0];
      for (const byte of bytes) {
        let carry = byte;
        for (let index = 0; index < digits.length; index++) {
          carry += digits[index] << 8;
          digits[index] = carry % 58;
          carry = Math.floor(carry / 58);
        }
        while (carry) {
          digits.push(carry % 58);
          carry = Math.floor(carry / 58);
        }
      }
      for (let index = 0; index < bytes.length - 1 && bytes[index] === 0; index++) digits.push(0);
      return digits.reverse().map(digit => alphabet[digit]).join('');
    };
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const publicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
    const multicodec = new Uint8Array(34);
    multicodec.set([0xed, 0x01]);
    multicodec.set(publicRaw, 2);
    return { did: `did:key:z${base58(multicodec)}`, seed: privateJwk.d };
  });
  importedDid = externalIdentity.did;
  const importPassword = 'imported recovery password 2026';

  await page.fill('#import-did', externalIdentity.did);
  await page.fill('#import-private-key', `${externalIdentity.seed.slice(0, -1)}${externalIdentity.seed.endsWith('A') ? 'B' : 'A'}`);
  await page.fill('#import-password', importPassword);
  await page.fill('#import-confirm-password', importPassword);
  await page.check('#import-risk-ack');
  await page.click('#import-button');
  await page.waitForFunction(() => /does not control this DID/i.test(document.querySelector('#vault-status')?.textContent || ''));
  assert.equal(await page.inputValue('#import-private-key'), '');

  await page.fill('#import-did', externalIdentity.did);
  await page.fill('#import-private-key', externalIdentity.seed);
  await page.fill('#import-password', importPassword);
  await page.fill('#import-confirm-password', importPassword);
  await page.check('#import-risk-ack');
  const requestsBeforeImport = allRequests.length;
  await page.click('#import-button');
  await page.waitForSelector('#created-panel:not([hidden])');
  assert.equal(await page.textContent('#created-did'), externalIdentity.did);
  assert.equal(await page.inputValue('#import-private-key'), '');
  assert.equal(allRequests.length, requestsBeforeImport);

  const [importDownload] = await Promise.all([
    page.waitForEvent('download'),
    page.click('#download-button')
  ]);
  const importDownloadPath = await importDownload.path();
  assert.ok(importDownloadPath);
  await page.setInputFiles('#recovery-file', importDownloadPath);
  await page.fill('#restore-password', importPassword);
  await page.click('#verify-backup-button');
  await page.waitForSelector('#success-panel:not([hidden])');
  assert.equal(await page.textContent('#verified-did'), externalIdentity.did);
  assert.equal(await page.textContent('#issuance-state'), 'EXISTING DID IMPORTED');

  const browserStorage = await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length, cookies: document.cookie }));
  assert.deepEqual(browserStorage, { local: 0, session: 0, cookies: '' });
  const geometry = await page.evaluate(() => ({ body: document.body.scrollWidth, viewport: document.documentElement.clientWidth }));
  assert.equal(geometry.body, geometry.viewport);
  assert.deepEqual(externalRequests, []);
  assert.deepEqual(consoleErrors, []);
  await page.screenshot({ path: '/tmp/agent-passport-vault-browser-smoke.png', fullPage: true });
  console.log(JSON.stringify({ createdDid, verifiedDid, importedDid, browserStorage, geometry, externalRequests, consoleErrors, status: 'PASS' }, null, 2));
} catch (error) {
  console.error(JSON.stringify({
    status: 'FAIL',
    message: error.message,
    vaultStatus: await page.textContent('#vault-status').catch(() => null),
    consoleErrors,
    externalRequests
  }, null, 2));
  throw error;
} finally {
  await browser.close();
}
