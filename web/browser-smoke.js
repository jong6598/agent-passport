import assert from 'node:assert/strict';
import { chromium } from 'playwright-core';

const baseUrl = process.env.PASSPORT_BASE_URL || 'http://127.0.0.1:8765/vault.html';
const executablePath = process.env.CHROME_EXECUTABLE_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const browser = await chromium.launch({ headless: true, executablePath });
const context = await browser.newContext({ viewport: { width: 390, height: 844 }, acceptDownloads: true });
const page = await context.newPage();
const consoleErrors = [];
const externalRequests = [];
page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
page.on('pageerror', error => consoleErrors.push(error.message));
page.on('request', request => {
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

  const browserStorage = await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length, cookies: document.cookie }));
  assert.deepEqual(browserStorage, { local: 0, session: 0, cookies: '' });
  const geometry = await page.evaluate(() => ({ body: document.body.scrollWidth, viewport: document.documentElement.clientWidth }));
  assert.equal(geometry.body, geometry.viewport);
  assert.deepEqual(externalRequests, []);
  assert.deepEqual(consoleErrors, []);
  await page.screenshot({ path: '/tmp/agent-passport-vault-browser-smoke.png', fullPage: true });
  console.log(JSON.stringify({ createdDid, verifiedDid, browserStorage, geometry, externalRequests, consoleErrors, status: 'PASS' }, null, 2));
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
