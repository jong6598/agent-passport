import { parseRecoveryFile, signWithRecoveryFile, verifyDidSignature } from './key-vault-core.js';

const state = { preview: null, signedDocument: null };
const $ = id => document.getElementById(id);
const encoder = new TextEncoder();

function setStatus(message, tone = '') {
  $('studio-status').textContent = message;
  $('studio-status').dataset.tone = tone;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(text));
  return [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, '0')).join('');
}

function clean(value, name, min, max) {
  const normalized = value.trim().replace(/\s+/g, ' ');
  if (normalized.length < min || normalized.length > max) throw new Error(`${name} must be ${min}–${max} characters`);
  return normalized;
}

function safePublicUrl(value) {
  let url;
  try { url = new URL(value.trim()); } catch { throw new Error('Artifact URL must be a valid public URL'); }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) throw new Error('Artifact URL must use public HTTP(S) without embedded credentials');
  if (url.href.length > 2048) throw new Error('Artifact URL is too long');
  return url.href;
}

function slug(value) {
  const output = value.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48);
  return output || 'contribution';
}

async function selectedRecovery() {
  const file = $('studio-key-file').files[0];
  if (!file) throw new Error('Select your encrypted .agent-passport-key file');
  return parseRecoveryFile(await file.text());
}

async function buildPayload() {
  const recovery = await selectedRecovery();
  const title = clean($('contribution-title').value, 'Title', 3, 120);
  const summary = clean($('contribution-summary').value, 'Summary', 10, 1000);
  const category = $('contribution-category').value;
  if (!['CODE', 'RESEARCH', 'DESIGN', 'LOCALIZATION', 'COMMUNITY', 'OTHER'].includes(category)) throw new Error('Unsupported contribution category');
  const date = $('contribution-date').value;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error('Contribution date is required');
  const artifact = { url: safePublicUrl($('artifact-url').value) };
  const commit = $('artifact-commit').value.trim();
  if (commit) {
    if (!/^[0-9a-f]{7,64}$/i.test(commit)) throw new Error('Commit must be a 7–64 character hexadecimal revision');
    artifact.commit = commit.toLowerCase();
  }
  const evidence = {};
  const room = $('technocore-room').value.trim();
  const sequence = $('technocore-sequence').value.trim();
  if (room || sequence) {
    if (!/^[a-z0-9][a-z0-9_-]{0,47}$/.test(room)) throw new Error('Technocore room is invalid');
    if (!/^\d+$/.test(sequence)) throw new Error('Technocore sequence must be an integer');
    evidence.technocore = { room, sequence: Number(sequence) };
  }
  return {
    schema: 'agent-passport-contribution-v1',
    id: `${date}-${slug(title)}`,
    did: recovery.did,
    title,
    summary,
    category,
    date,
    artifact,
    ...(Object.keys(evidence).length ? { evidence } : {})
  };
}

function invalidatePreview() {
  if (!state.preview && !state.signedDocument) return;
  state.preview = null;
  state.signedDocument = null;
  $('preview-panel').hidden = true;
  $('signed-panel').hidden = true;
  $('publication-panel').hidden = true;
  setStatus('Fields changed. Generate and review a new canonical preview before signing.', 'working');
}

async function previewContribution(event) {
  event.preventDefault();
  try {
    const payload = await buildPayload();
    const canonical = canonicalJson(payload);
    const payloadSha256 = await sha256Hex(canonical);
    state.preview = { payload, canonical, payloadSha256 };
    state.signedDocument = null;
    $('preview-json').textContent = canonical;
    $('preview-hash').textContent = payloadSha256;
    $('preview-did').textContent = payload.did;
    $('preview-panel').hidden = false;
    $('signed-panel').hidden = true;
    $('publication-panel').hidden = true;
    setStatus('Review the exact canonical JSON and SHA-256 below. Signing does not publish it.', 'working');
  } catch (error) {
    setStatus(error.message, 'error');
  }
}

async function signContribution() {
  if (!state.preview) {
    setStatus('Generate and review a canonical preview first.', 'error');
    return;
  }
  const password = $('studio-password').value;
  const button = $('sign-button');
  button.disabled = true;
  setStatus('Unlocking locally and signing the exact reviewed hash…', 'working');
  try {
    const recovery = await selectedRecovery();
    if (recovery.did !== state.preview.payload.did) throw new Error('Selected recovery file no longer matches the preview DID');
    const signed = await signWithRecoveryFile(recovery, password, state.preview.canonical);
    const verified = await verifyDidSignature(signed.did, state.preview.canonical, signed.signature);
    if (!verified) throw new Error('Local signature verification failed');
    state.signedDocument = {
      schema: 'agent-passport-signed-contribution-v1',
      payload: state.preview.payload,
      canonicalJson: state.preview.canonical,
      payloadSha256: state.preview.payloadSha256,
      signature: { algorithm: 'Ed25519', did: signed.did, value: signed.signature },
      publication: { status: 'not-published', separateApprovalRequired: true }
    };
    $('signed-hash').textContent = state.preview.payloadSha256;
    $('signed-did').textContent = signed.did;
    $('signed-panel').hidden = false;
    setStatus('Signed and independently verified locally. Nothing was published.', 'success');
  } catch (error) {
    setStatus(error.message, 'error');
  } finally {
    $('studio-password').value = '';
    button.disabled = false;
  }
}

function downloadSignedContribution() {
  if (!state.signedDocument) return;
  const body = `${JSON.stringify(state.signedDocument, null, 2)}\n`;
  const blob = new Blob([body], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `${state.signedDocument.payload.id}.agent-passport-contribution.json`;
  link.click();
  URL.revokeObjectURL(link.href);
}

function preparePublicationDraft() {
  if (!state.signedDocument) return;
  const { payload, payloadSha256, signature } = state.signedDocument;
  const draft = `Contribution: ${payload.title}\nArtifact: ${payload.artifact.url}\nDID: ${signature.did}\nSigned manifest SHA-256: ${payloadSha256}`;
  $('publication-draft').textContent = draft;
  $('publication-panel').hidden = false;
  setStatus('External publication draft prepared locally. A separate explicit approval is still required to post it.', 'working');
}

$('contribution-form').addEventListener('submit', previewContribution);
$('contribution-form').addEventListener('input', invalidatePreview);
$('sign-button').addEventListener('click', signContribution);
$('download-contribution').addEventListener('click', downloadSignedContribution);
$('prepare-publication').addEventListener('click', preparePublicationDraft);
