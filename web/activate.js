const $ = id => document.getElementById(id);
const config = globalThis.AGENT_PASSPORT_CONFIG;
let pending = null;
let submitting = false;

function status(message, tone = '') {
  $('activate-status').textContent = message;
  $('activate-status').dataset.tone = tone;
}

function clearPending() {
  sessionStorage.removeItem('agent-passport-pending-registration');
}

async function submit(token) {
  if (submitting || !pending) return;
  submitting = true;
  status('Verifying anti-bot token and publishing the signed Passport…', 'working');
  try {
    const response = await fetch(`${config.apiBase}/v1/passports`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ registration: pending.registration, turnstileToken: token }),
      cache: 'no-store',
      referrerPolicy: 'no-referrer'
    });
    let body;
    try { body = await response.json(); } catch { throw new Error(`Registration API returned HTTP ${response.status}`); }
    if (!response.ok || !body.ok) throw new Error(body.error || `Registration API returned HTTP ${response.status}`);
    clearPending();
    $('activate-panel').hidden = true;
    $('activate-success').hidden = false;
    $('activate-result-did').textContent = pending.registration.payload.did;
    $('open-created-passport').href = `index.html?did=${encodeURIComponent(pending.registration.payload.did)}`;
    status('Passport published as SELF-REGISTERED · UNVERIFIED.', 'success');
  } catch (error) {
    status(error.message, 'error');
    submitting = false;
    if (globalThis.turnstile) globalThis.turnstile.reset();
  }
}

globalThis.onTurnstileSuccess = submit;
globalThis.onTurnstileExpired = () => status('Anti-bot check expired. Complete it again.', 'error');
globalThis.onTurnstileError = () => status('Anti-bot check could not load. Retry in a moment.', 'error');

try {
  const raw = sessionStorage.getItem('agent-passport-pending-registration');
  if (!raw) throw new Error('No signed registration is waiting. Return to Publish Passport.');
  pending = JSON.parse(raw);
  if (!pending.registration?.payload?.did || Date.now() - Date.parse(pending.createdAt) > 10 * 60_000) {
    clearPending();
    throw new Error('The signed registration expired. Return and create a fresh request.');
  }
  $('activate-did').textContent = pending.registration.payload.did;
  $('activate-name').textContent = pending.registration.payload.profile.displayName;
  $('activate-hash').textContent = pending.registration.payloadSha256;
  const widget = $('turnstile-widget');
  widget.dataset.sitekey = config.turnstileSiteKey;
  status('Complete the Cloudflare check. Only the already-signed public request will be submitted.', 'working');
} catch (error) {
  $('activate-panel').hidden = true;
  status(error.message, 'error');
}
