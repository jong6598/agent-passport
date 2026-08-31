import { parseRecoveryFile, signWithRecoveryFile, verifyDidSignature } from './key-vault-core.js';
import { buildRegistrationPayload, canonicalJson, sha256Hex, validateSignedContribution, validateSignedRegistration } from './registration-core.js';

const state = { signedContribution: null, preview: null, signedRegistration: null };
const $ = id => document.getElementById(id);
const ISSUE_URL = 'https://github.com/jong6598/agent-passport/issues/new?template=passport-registration.yml';

function setStatus(message, tone = '') {
  $('registration-status').textContent = message;
  $('registration-status').dataset.tone = tone;
}

function clean(value, name, min, max) {
  const normalized = value.trim().replace(/\s+/g, ' ');
  if (normalized.length < min || normalized.length > max) throw new Error(`${name} must be ${min}–${max} characters`);
  if (/[\u0000-\u001f\u007f]/.test(normalized)) throw new Error(`${name} contains unsupported control characters`);
  return normalized;
}

function languages() {
  const values = $('languages-input').value.split(',').map(value => value.trim().toUpperCase()).filter(Boolean);
  if (values.length < 1 || values.length > 8) throw new Error('Enter 1–8 comma-separated language codes');
  if (new Set(values).size !== values.length) throw new Error('Language codes must not be duplicated');
  if (values.some(value => !/^[A-Z]{2,8}(?:-[A-Z0-9]{2,8})?$/.test(value))) throw new Error('Use short language codes such as KO, EN, or ZH-HANT');
  return values;
}

async function readJsonFile(input, label, maxBytes = 262144) {
  const file = input.files[0];
  if (!file) throw new Error(`Select ${label}`);
  if (file.size > maxBytes) throw new Error(`${label} is too large`);
  try { return JSON.parse(await file.text()); } catch { throw new Error(`${label} is not valid JSON`); }
}

async function selectedRecovery() {
  const file = $('registration-key-file').files[0];
  if (!file) throw new Error('Select your encrypted .agent-passport-key file');
  if (file.size > 131072) throw new Error('Recovery file is too large');
  return parseRecoveryFile(await file.text());
}

function requireConsent() {
  const ids = ['consent-index', 'consent-manifest', 'consent-links', 'consent-sensitive'];
  if (ids.some(id => !$(id).checked)) throw new Error('Every public registration consent must be checked');
}

function publicProfile() {
  const type = $('passport-type').value;
  const profile = {
    displayName: clean($('display-name-input').value, 'Display name', 2, 80),
    type,
    operatorRegion: clean($('operator-region-input').value, 'Operator region', 2, 64),
    languages: languages()
  };
  const motto = $('motto-input').value.trim();
  if (motto) profile.motto = clean(motto, 'Motto', 2, 120);
  return profile;
}

function invalidatePreview() {
  if (!state.preview && !state.signedRegistration) return;
  state.preview = null;
  state.signedRegistration = null;
  $('registration-preview-panel').hidden = true;
  $('registration-signed-panel').hidden = true;
  setStatus('Fields changed. Generate and review a new registration preview before signing.', 'working');
}

async function previewRegistration(event) {
  event.preventDefault();
  try {
    requireConsent();
    const signedContribution = await readJsonFile($('signed-contribution-file'), 'a signed contribution JSON');
    const contribution = await validateSignedContribution(signedContribution);
    $('contribution-check').textContent = `Verified: ${contribution.title} · ${contribution.payloadSha256}`;
    $('contribution-check').dataset.valid = 'true';
    const recovery = await selectedRecovery();
    if (recovery.did !== contribution.did) throw new Error('Recovery file DID does not match the signed contribution DID');
    const payload = buildRegistrationPayload({
      profile: publicProfile(),
      signedContribution,
      submittedAt: new Date().toISOString()
    });
    const canonical = canonicalJson(payload);
    const payloadSha256 = await sha256Hex(canonical);
    state.signedContribution = signedContribution;
    state.preview = { payload, canonical, payloadSha256 };
    state.signedRegistration = null;
    $('registration-preview-did').textContent = payload.did;
    $('registration-preview-hash').textContent = payloadSha256;
    $('registration-preview-json').textContent = canonical;
    $('registration-preview-panel').hidden = false;
    $('registration-signed-panel').hidden = true;
    setStatus('Contribution verified. Review the exact public registration payload and hash below.', 'working');
  } catch (error) {
    $('contribution-check').dataset.valid = 'false';
    setStatus(error.message, 'error');
  }
}

async function signRegistration() {
  if (!state.preview) return setStatus('Generate and review a registration preview first.', 'error');
  const button = $('registration-sign-button');
  button.disabled = true;
  setStatus('Unlocking locally and signing the exact registration request…', 'working');
  try {
    const recovery = await selectedRecovery();
    if (recovery.did !== state.preview.payload.did) throw new Error('Recovery file no longer matches the reviewed DID');
    const signed = await signWithRecoveryFile(recovery, $('registration-password').value, state.preview.canonical);
    if (!await verifyDidSignature(signed.did, state.preview.canonical, signed.signature)) throw new Error('Local registration signature verification failed');
    const request = {
      schema: 'agent-passport-signed-registration-v1',
      payload: state.preview.payload,
      canonicalJson: state.preview.canonical,
      payloadSha256: state.preview.payloadSha256,
      signature: { algorithm: 'Ed25519', did: signed.did, value: signed.signature },
      review: { status: 'pending', humanApprovalRequired: true },
      publication: { status: 'not-registered', automaticPublication: false }
    };
    await validateSignedRegistration(request);
    state.signedRegistration = request;
    $('registration-signed-hash').textContent = request.payloadSha256;
    $('open-registration-issue').href = `${ISSUE_URL}&title=${encodeURIComponent(`Passport registration: ${request.payload.did}`)}`;
    $('registration-signed-panel').hidden = false;
    setStatus('Registration request signed and verified locally. Human review is pending; nothing was registered.', 'success');
  } catch (error) {
    setStatus(error.message, 'error');
  } finally {
    $('registration-password').value = '';
    button.disabled = false;
  }
}

function requestBody() {
  if (!state.signedRegistration) throw new Error('No signed registration request is ready');
  return `${JSON.stringify(state.signedRegistration, null, 2)}\n`;
}

function downloadRegistration() {
  try {
    const body = requestBody();
    const link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([body], { type: 'application/json' }));
    link.download = `${state.signedRegistration.payload.did.replace(/[^a-zA-Z0-9]+/g, '-').slice(0, 80)}.agent-passport-registration.json`;
    link.click();
    URL.revokeObjectURL(link.href);
  } catch (error) { setStatus(error.message, 'error'); }
}

async function copyRegistration() {
  try {
    await navigator.clipboard.writeText(requestBody());
    setStatus('Signed registration request copied. Paste it into the GitHub application form.', 'success');
  } catch {
    setStatus('Clipboard access was blocked. Download the JSON and paste its contents manually.', 'error');
  }
}

$('registration-form').addEventListener('submit', previewRegistration);
$('registration-form').addEventListener('input', invalidatePreview);
$('registration-sign-button').addEventListener('click', signRegistration);
$('download-registration').addEventListener('click', downloadRegistration);
$('copy-registration').addEventListener('click', copyRegistration);
