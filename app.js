const state = { index: null, manifest: null, verification: 'idle', sound: true };
const $ = (id) => document.getElementById(id);
const apiBase = globalThis.AGENT_PASSPORT_CONFIG?.apiBase || '';

const base58Alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Decode(value) {
  let bytes = [0];
  for (const char of value) {
    const digit = base58Alphabet.indexOf(char);
    if (digit < 0) throw new Error('Invalid base58btc character');
    let carry = digit;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let i = 0; i < value.length - 1 && value[i] === '1'; i++) bytes.push(0);
  return new Uint8Array(bytes.reverse());
}

function base64UrlDecode(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function publicKeyFromDid(did) {
  if (!did.startsWith('did:key:z')) throw new Error('Only base58btc did:key is supported');
  const decoded = base58Decode(did.slice('did:key:z'.length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('DID is not an Ed25519 public key');
  }
  return decoded.slice(2);
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map(x => x.toString(16).padStart(2, '0')).join('');
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

async function verifyContribution(contribution, did) {
  const key = await crypto.subtle.importKey('raw', publicKeyFromDid(did), { name: 'Ed25519' }, false, ['verify']);
  let verifiedSignatures = 0;

  if (contribution.signature) {
    const canonical = new TextEncoder().encode(`${contribution.room}|${contribution.nonce}|${contribution.text}`);
    const canonicalHash = await sha256Hex(canonical);
    if (canonicalHash !== contribution.canonicalPayloadSha256) {
      return { ok: false, reason: 'Technocore payload hash mismatch' };
    }
    const ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, base64UrlDecode(contribution.signature), canonical);
    if (!ok) return { ok: false, reason: 'Invalid Technocore Ed25519 signature' };
    verifiedSignatures += 1;
  }

  if (contribution.artifactAttestation) {
    const attestation = contribution.artifactAttestation;
    if (attestation.did !== did) return { ok: false, reason: 'Artifact attestation DID mismatch' };
    const payload = JSON.parse(attestation.canonicalJson);
    if (canonicalJson(payload) !== attestation.canonicalJson) return { ok: false, reason: 'Artifact canonical JSON mismatch' };
    if (payload.did !== did || canonicalJson(payload.artifact) !== canonicalJson(contribution.artifact)) {
      return { ok: false, reason: 'Displayed artifact does not match signed payload' };
    }
    const canonical = new TextEncoder().encode(attestation.canonicalJson);
    if (await sha256Hex(canonical) !== attestation.payloadSha256) return { ok: false, reason: 'Artifact payload hash mismatch' };
    const ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, base64UrlDecode(attestation.signature), canonical);
    if (!ok) return { ok: false, reason: 'Invalid artifact Ed25519 signature' };
    verifiedSignatures += 1;
  }

  return verifiedSignatures ? { ok: true, verifiedSignatures } : { ok: false, skipped: true };
}

async function verifySelfRegistration(registration, did) {
  if (!registration || registration.schema !== 'agent-passport-signed-self-registration-v1') return { ok: false };
  if (registration.payload?.did !== did || registration.signature?.did !== did || registration.signature?.algorithm !== 'Ed25519') return { ok: false };
  const canonical = canonicalJson(registration.payload);
  if (canonical !== registration.canonicalJson) return { ok: false };
  const bytes = new TextEncoder().encode(canonical);
  if (await sha256Hex(bytes) !== registration.payloadSha256) return { ok: false };
  const key = await crypto.subtle.importKey('raw', publicKeyFromDid(did), { name: 'Ed25519' }, false, ['verify']);
  const ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, base64UrlDecode(registration.signature.value), bytes);
  return { ok, verifiedSignatures: ok ? 1 : 0 };
}

function formatDate(value) {
  if (value === 'NEXT') return value;
  return new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
    .format(new Date(`${value}T00:00:00Z`)).toUpperCase();
}

function statusDetail(item) {
  if (item.status === 'verified') return `SEQ ${item.seq} · ${item.verification.artifactSource.replaceAll('-', ' ').toUpperCase()}`;
  if (item.status === 'draft') return 'LOCAL ARTIFACT · NOT ANCHORED';
  return 'NO SIGNATURE · NO PUBLIC CLAIM';
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderContribution(item) {
  const article = element('article', `visa ${item.status}`);

  const code = element('div', 'visa-code');
  const stamp = element('div', 'round-stamp');
  stamp.append(element('b', '', item.countryCode), element('small', '', formatDate(item.date)));
  code.append(stamp);

  const main = element('div', 'visa-main');
  const meta = element('div', 'meta');
  meta.append(element('span', '', item.category), element('span', '', '·'), element('span', '', item.id.toUpperCase()));
  main.append(meta, element('h3', '', item.title), element('p', '', item.summary));
  if (item.artifact?.url) {
    const artifactLink = element('a', 'artifact-link', 'Open public artifact ↗');
    artifactLink.href = item.artifact.url;
    artifactLink.target = '_blank';
    artifactLink.rel = 'noreferrer';
    main.append(artifactLink);
  }
  if (item.status === 'verified') {
    const proofButton = element('button', '', 'Inspect signed proof →');
    proofButton.type = 'button';
    proofButton.addEventListener('click', () => showProof(item));
    main.append(proofButton);
  }

  const visaState = element('div', 'visa-state');
  visaState.append(element('b', '', item.statusLabel), element('small', '', statusDetail(item)));
  article.append(code, main, visaState);
  return article;
}

function showProof(item) {
  const details = [
    `DID signature: ${item.verification.signature}`,
    `Technocore: ${item.verification.technocoreReadback}`,
    `Room / sequence: ${item.room} / ${item.seq}`,
    `Payload hash: ${item.canonicalPayloadSha256.slice(0, 16)}…`,
    `Source: ${item.verification.artifactSource}`,
    item.artifact?.commitUrl ? `Public commit: ${item.artifact.commitUrl}` : null,
    item.artifactAttestation?.payloadSha256 ? `Artifact hash: ${item.artifactAttestation.payloadSha256.slice(0, 16)}…` : null
  ].filter(Boolean);
  alert(`${item.title}\n\n${details.join('\n')}`);
}

function render(manifest) {
  const p = manifest.profile;
  $('passport-number').textContent = p.passportNumber;
  $('display-name').textContent = p.displayName;
  $('agent-type').textContent = p.type;
  $('operator-region').textContent = p.operatorRegion;
  $('languages').textContent = p.languages.join(' · ');
  $('issuer').textContent = p.issuer;
  $('issued-on').textContent = formatDate(p.issuedOn);
  $('valid-until').textContent = p.validUntil;
  $('did-value').textContent = p.did;
  $('disclaimer').textContent = manifest.disclaimer;
  $('mrz-2').textContent = `${p.passportNumber.replaceAll('-', '')}${p.operatorRegion.slice(0, 2)}${p.issuedOn.replaceAll('-', '').slice(2)}${p.validUntil}<<<<<<`;
  const list = $('contribution-list');
  if (manifest.contributions.length) {
    list.replaceChildren(...manifest.contributions.map(renderContribution));
  } else {
    const empty = element('article', 'visa draft');
    const main = element('div', 'visa-main');
    main.append(element('div', 'meta', 'NO CONTRIBUTIONS YET'), element('h3', '', 'Passport created'), element('p', '', 'This DID has a signed self-registration but no published work history yet.'));
    empty.append(element('div', 'visa-code', '—'), main, element('div', 'visa-state', 'UNVERIFIED'));
    list.replaceChildren(empty);
  }
}

function toast(message) {
  const el = $('toast');
  el.textContent = message;
  el.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.remove('show'), 2200);
}

async function verifyPassport({ silent = false } = {}) {
  const lamp = $('verification-lamp');
  const label = $('verification-label');
  label.textContent = 'CHECKING…';
  lamp.className = 'verification-lamp';
  try {
    const signed = state.manifest.contributions.filter(x => x.signature || x.artifactAttestation?.signature);
    let results;
    let selfRegistration = false;
    if (signed.length) {
      results = await Promise.all(signed.map(x => verifyContribution(x, state.manifest.profile.did)));
    } else if (state.manifest.signedRegistration) {
      selfRegistration = true;
      results = [await verifySelfRegistration(state.manifest.signedRegistration, state.manifest.profile.did)];
    } else {
      throw new Error('No signed records');
    }
    const pass = results.every(x => x.ok);
    const signatureCount = results.reduce((sum, result) => sum + (result.verifiedSignatures || 0), 0);
    state.verification = pass ? 'pass' : 'fail';
    lamp.classList.add(pass ? 'pass' : 'fail');
    label.textContent = pass ? (selfRegistration ? 'KEY CONTROL VERIFIED · UNVERIFIED PROFILE' : `${signatureCount} SIGNATURES VERIFIED`) : 'VERIFICATION FAILED';
    if (!silent) toast(pass ? (selfRegistration ? 'DID key control verified. Profile claims remain unverified.' : 'Ed25519 signature and payload hash verified locally.') : 'The signed record did not verify.');
  } catch (error) {
    state.verification = 'fail';
    lamp.classList.add('fail');
    label.textContent = 'CHECK UNAVAILABLE';
    if (!silent) toast(`Verification unavailable: ${error.message}`);
  }
}

function downloadManifest() {
  const blob = new Blob([JSON.stringify(state.manifest, null, 2) + '\n'], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'agent-passport-manifest-v1.json';
  link.click();
  URL.revokeObjectURL(link.href);
  toast('Portable passport manifest downloaded.');
}

function validManifestPath(path) {
  return typeof path === 'string' && path.startsWith('data/passports/') && path.endsWith('.json') && !path.includes('..') && !path.includes('://');
}

async function loadPassport(did, { updateUrl = false } = {}) {
  const normalized = did.trim();
  const status = $('search-status');
  status.classList.remove('error');
  const entry = state.index.passports.find(item => item.did === normalized && item.status === 'active');
  let manifest;
  let displayName;
  let sourceLabel;
  if (entry) {
    if (!validManifestPath(entry.manifest)) throw new Error('Unsafe manifest path in public index');
    const response = await fetch(entry.manifest, { cache: 'no-store' });
    if (!response.ok) throw new Error(`Manifest HTTP ${response.status}`);
    manifest = await response.json();
    if (manifest.profile?.did !== entry.did) throw new Error('Index DID does not match manifest DID');
    displayName = entry.displayName;
    sourceLabel = 'Registered Passport';
  } else {
    let validDid = true;
    try { publicKeyFromDid(normalized); } catch { validDid = false; }
    if (!apiBase || !validDid) {
      state.manifest = null;
      $('passport').hidden = true;
      status.textContent = 'No registered public Passport was found for this exact DID.';
      status.classList.add('error');
      return false;
    }
    const response = await fetch(`${apiBase}/v1/passports?did=${encodeURIComponent(normalized)}`, { cache: 'no-store', referrerPolicy: 'no-referrer' });
    if (response.status === 404) {
      state.manifest = null;
      $('passport').hidden = true;
      status.textContent = 'No registered public Passport was found for this exact DID.';
      status.classList.add('error');
      return false;
    }
    const body = await response.json();
    if (!response.ok || !body.ok || body.passport?.profile?.did !== normalized) throw new Error(body.error || `Self-registration API HTTP ${response.status}`);
    manifest = body.passport;
    displayName = manifest.profile.displayName;
    sourceLabel = 'Self-registered · unverified Passport';
  }
  state.manifest = manifest;
  render(manifest);
  $('passport').hidden = false;
  $('did-search-input').value = normalized;
  status.textContent = `${sourceLabel} found for ${displayName}. Viewing requires no private key.`;
  document.title = `Agent Passport · ${displayName}`;
  if (updateUrl) history.pushState({ did: normalized }, '', `?did=${encodeURIComponent(normalized)}`);
  await verifyPassport({ silent: true });
  return true;
}

async function init() {
  $('open-passport').addEventListener('click', () => { if (state.manifest) $('passport').scrollIntoView({ behavior: 'smooth', block: 'center' }); });
  $('verify-top').addEventListener('click', async () => { if (!state.manifest) return; $('passport').scrollIntoView({ behavior: 'smooth', block: 'center' }); await verifyPassport(); });
  $('verify-button').addEventListener('click', verifyPassport);
  $('download-manifest').addEventListener('click', () => { if (state.manifest) downloadManifest(); });
  $('copy-did').addEventListener('click', async () => { if (!state.manifest) return; await navigator.clipboard.writeText(state.manifest.profile.did); toast('Public DID copied.'); });
  $('sound-toggle').addEventListener('click', () => { state.sound = !state.sound; $('sound-toggle').textContent = state.sound ? '◒' : '○'; toast(`Page sound ${state.sound ? 'on' : 'off'} — visual prototype only.`); });
  $('did-search').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      await loadPassport($('did-search-input').value, { updateUrl: true });
    } catch (error) {
      $('search-status').textContent = `Passport unavailable: ${error.message}`;
      $('search-status').classList.add('error');
    }
  });
  window.addEventListener('popstate', async () => {
    const requested = new URLSearchParams(location.search).get('did') || state.index.passports[0]?.did || '';
    await loadPassport(requested);
  });

  try {
    const response = await fetch('data/index.json', { cache: 'no-store' });
    if (!response.ok) throw new Error(`Index HTTP ${response.status}`);
    state.index = await response.json();
    if (state.index.schema !== 'agent-passport-public-index-v1' || !Array.isArray(state.index.passports)) throw new Error('Unsupported public index');
    const requested = new URLSearchParams(location.search).get('did') || state.index.passports[0]?.did || '';
    $('did-search-input').value = requested;
    await loadPassport(requested);
  } catch (error) {
    state.manifest = null;
    $('passport').hidden = true;
    $('search-status').textContent = `Passport index unavailable: ${error.message}`;
    $('search-status').classList.add('error');
  }
}

init();
