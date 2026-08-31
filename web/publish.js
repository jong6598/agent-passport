import { parseRecoveryFile, signWithRecoveryFile } from './key-vault-core.js';
import { buildSelfRegistrationPayload, canonicalJson, sha256Hex, validateSignedSelfRegistration } from '../shared/self-registration-core.js';

const $ = id => document.getElementById(id);
const config = globalThis.AGENT_PASSPORT_CONFIG;

function status(message, tone = '') {
  $('publish-status').textContent = message;
  $('publish-status').dataset.tone = tone;
}

function clean(value, name, min, max) {
  const normalized = value.trim().replace(/\s+/g, ' ');
  if (normalized.length < min || normalized.length > max || /[\u0000-\u001f\u007f]/.test(normalized)) throw new Error(`${name} must be ${min}-${max} safe characters`);
  return normalized;
}

function profile() {
  const languages = $('publish-languages').value.split(',').map(value => value.trim().toUpperCase()).filter(Boolean);
  if (languages.length < 1 || languages.length > 8 || new Set(languages).size !== languages.length || languages.some(value => !/^[A-Z]{2,8}(?:-[A-Z0-9]{2,8})?$/.test(value))) throw new Error('Use 1-8 unique language codes such as KO, EN');
  const output = {
    displayName: clean($('publish-name').value, 'Display name', 2, 80),
    type: $('publish-type').value,
    operatorRegion: clean($('publish-region').value, 'Operator region', 2, 64),
    languages
  };
  const motto = $('publish-motto').value.trim();
  if (motto) output.motto = clean(motto, 'Motto', 2, 120);
  return output;
}

async function jsonResponse(response) {
  let body;
  try { body = await response.json(); } catch { throw new Error(`Registration API returned HTTP ${response.status}`); }
  if (!response.ok || !body.ok) throw new Error(body.error || `Registration API returned HTTP ${response.status}`);
  return body;
}

async function prepare(event) {
  event.preventDefault();
  if (!config?.apiBase?.startsWith('https://')) return status('Registration API configuration is unavailable.', 'error');
  if (!$('publish-consent').checked) return status('Confirm the public self-registration status and trust limits.', 'error');
  const file = $('publish-key-file').files[0];
  if (!file || file.size > 131072) return status('Select a valid encrypted recovery file under 128 KiB.', 'error');
  const password = $('publish-password').value;
  const button = $('publish-button');
  button.disabled = true;
  status('Requesting a short-lived server challenge…', 'working');
  try {
    const recovery = parseRecoveryFile(await file.text());
    const challengeResponse = await fetch(`${config.apiBase}/v1/challenges`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ did: recovery.did }),
      cache: 'no-store',
      referrerPolicy: 'no-referrer'
    });
    const { challenge } = await jsonResponse(challengeResponse);
    const payload = buildSelfRegistrationPayload({ did: recovery.did, profile: profile(), challenge });
    const canonical = canonicalJson(payload);
    const signed = await signWithRecoveryFile(recovery, password, canonical);
    const registration = {
      schema: 'agent-passport-signed-self-registration-v1',
      payload,
      canonicalJson: canonical,
      payloadSha256: await sha256Hex(canonical),
      signature: { algorithm: 'Ed25519', did: signed.did, value: signed.signature }
    };
    await validateSignedSelfRegistration(registration, { ...challenge, did: recovery.did });
    sessionStorage.setItem('agent-passport-pending-registration', JSON.stringify({ registration, createdAt: new Date().toISOString() }));
    status('Signed request verified. Moving to the separate anti-bot submission page…', 'success');
    location.assign('activate.html');
  } catch (error) {
    status(error.message, 'error');
  } finally {
    $('publish-password').value = '';
    button.disabled = false;
  }
}

$('publish-form').addEventListener('submit', prepare);
