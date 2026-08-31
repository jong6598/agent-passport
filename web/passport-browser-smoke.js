import assert from 'node:assert/strict';
import { chromium } from 'playwright-core';

const origin = process.env.PASSPORT_ORIGIN || 'http://127.0.0.1:8765';
const did = 'did:key:z6MkuzX9QWN1nTpPGoURcLHS8r2xqXyu3UuNh2rcBbVQ7MKN';
const executablePath = process.env.CHROME_EXECUTABLE_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const browser = await chromium.launch({ headless: true, executablePath });

try {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  const errors = [];
  const external = [];
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => { if (new URL(request.url()).origin !== new URL(origin).origin) external.push(request.url()); });

  await page.goto(`${origin}/index.html?did=${encodeURIComponent(did)}`, { waitUntil: 'networkidle' });
  await page.waitForFunction(() => document.querySelector('#verification-label')?.textContent === '2 SIGNATURES VERIFIED');
  assert.equal(await page.inputValue('#did-search-input'), did);
  assert.match(await page.textContent('#search-status'), /Registered Passport found/);
  assert.equal(await page.getAttribute('.artifact-link', 'href'), 'https://github.com/jong6598/technocore-safe-adapter');

  await page.fill('#did-search-input', 'did:key:z6Mkunregistered');
  await page.click('#did-search button');
  assert.match(await page.textContent('#search-status'), /No registered public Passport/);
  assert.equal(await page.isHidden('#passport'), true);

  await page.fill('#did-search-input', did);
  await page.click('#did-search button');
  await page.waitForFunction(() => {
    const passport = document.querySelector('#passport');
    return passport && !passport.hidden && document.querySelector('#search-status')?.textContent.includes('Registered Passport found');
  });
  await page.waitForFunction(() => document.querySelector('#verification-label')?.textContent === '2 SIGNATURES VERIFIED');
  assert.equal(await page.isVisible('#passport'), true);
  assert.match(page.url(), /\?did=did%3Akey%3A/);
  const geometry = await page.evaluate(() => ({ body: document.body.scrollWidth, viewport: document.documentElement.clientWidth }));
  assert.equal(geometry.body, geometry.viewport);
  assert.deepEqual(external, []);
  assert.deepEqual(errors, []);
  await page.screenshot({ path: '/tmp/agent-passport-search-smoke.png', fullPage: true });
  await context.close();

  const hostileContext = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const hostilePage = await hostileContext.newPage();
  const hostileErrors = [];
  hostilePage.on('pageerror', error => hostileErrors.push(error.message));
  hostilePage.on('console', message => { if (message.type() === 'error') hostileErrors.push(message.text()); });
  const hostileDid = did;
  await hostilePage.route('**/data/index.json', route => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ schema: 'agent-passport-public-index-v1', passports: [{ did: hostileDid, displayName: '<img src=x onerror=alert(1)>', manifest: 'data/passports/hostile.json', status: 'active' }] })
  }));
  const source = JSON.parse(await (await fetch(`${origin}/data/passports/hyeon-hermes.json`)).text());
  source.profile.displayName = '<img id="injected-image" src=x onerror=alert(1)>';
  source.contributions[0].title = '<script>globalThis.injected=true</script>';
  source.contributions[0].summary = '<img id="summary-image" src=x onerror=alert(1)>';
  await hostilePage.route('**/data/passports/hostile.json', route => route.fulfill({ contentType: 'application/json', body: JSON.stringify(source) }));
  await hostilePage.goto(`${origin}/index.html?did=${encodeURIComponent(hostileDid)}`, { waitUntil: 'networkidle' });
  assert.equal(await hostilePage.locator('#display-name').textContent(), source.profile.displayName);
  assert.equal(await hostilePage.locator('.visa-main h3').first().textContent(), source.contributions[0].title);
  assert.equal(await hostilePage.locator('#injected-image').count(), 0);
  assert.equal(await hostilePage.locator('#summary-image').count(), 0);
  assert.equal(await hostilePage.evaluate(() => globalThis.injected), undefined);
  assert.deepEqual(hostileErrors, []);
  await hostileContext.close();

  console.log(JSON.stringify({ did, signatureLabel: '2 SIGNATURES VERIFIED', geometry, externalRequests: external, consoleErrors: errors, hostileManifestRenderedAsText: true, status: 'PASS' }, null, 2));
} finally {
  await browser.close();
}
