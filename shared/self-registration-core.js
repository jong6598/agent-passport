const encoder = new TextEncoder();
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const TYPES = new Set(['AGENT', 'BUILDER', 'RESEARCHER', 'CREATOR', 'COMMUNITY', 'OTHER']);
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function safeShape(root) {
  const stack = [{ value: root, depth: 0 }];
  let nodes = 0;
  while (stack.length) {
    const { value, depth } = stack.pop();
    if (++nodes > 2000) throw new Error('Registration JSON is too complex');
    if (depth > 16) throw new Error('Registration JSON is nested too deeply');
    if (!value || typeof value !== 'object') continue;
    const keys = Object.keys(value);
    if (keys.length > 50) throw new Error('Registration object has too many fields');
    for (const key of keys) {
      if (FORBIDDEN_KEYS.has(key)) throw new Error(`Unsafe JSON field: ${key}`);
      stack.push({ value: value[key], depth: depth + 1 });
    }
  }
}

export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Canonical JSON cannot contain non-finite numbers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new Error('Unsupported canonical JSON value');
}

export async function sha256Hex(text, cryptoApi = globalThis.crypto) {
  const digest = await cryptoApi.subtle.digest('SHA-256', encoder.encode(text));
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function base58Decode(value) {
  let bytes = [0];
  for (const char of value) {
    const digit = B58.indexOf(char);
    if (digit < 0) throw new Error('Invalid did:key');
    let carry = digit;
    for (let index = 0; index < bytes.length; index++) {
      carry += bytes[index] * 58;
      bytes[index] = carry & 255;
      carry >>= 8;
    }
    while (carry) {
      bytes.push(carry & 255);
      carry >>= 8;
    }
  }
  for (let index = 0; index < value.length - 1 && value[index] === '1'; index++) bytes.push(0);
  return Uint8Array.from(bytes.reverse());
}

function base64UrlDecode(value) {
  if (typeof value !== 'string' || value.length < 80 || value.length > 100 || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid Ed25519 signature encoding');
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
  if (bytes.length !== 64) throw new Error('Invalid Ed25519 signature length');
  return bytes;
}

export function publicKeyFromDid(did) {
  if (typeof did !== 'string' || did.length < 45 || did.length > 90 || !did.startsWith('did:key:z')) throw new Error('Only Ed25519 did:key is supported');
  const decoded = base58Decode(did.slice(9));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) throw new Error('DID is not Ed25519');
  return decoded.slice(2);
}

function text(value, name, min, max) {
  if (typeof value !== 'string' || value.length < min || value.length > max || value !== value.trim()) throw new Error(`${name} must be ${min}-${max} trimmed characters`);
  if (/[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${name} contains unsupported control characters`);
  return value;
}

export function validatePublicProfile(profile) {
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)) throw new Error('Public profile is missing');
  const keys = Object.keys(profile).sort();
  const allowed = ['displayName', 'languages', 'motto', 'operatorRegion', 'type'];
  if (keys.some(key => !allowed.includes(key))) throw new Error('Public profile contains unsupported fields');
  text(profile.displayName, 'Display name', 2, 80);
  text(profile.operatorRegion, 'Operator region', 2, 64);
  if (!TYPES.has(profile.type)) throw new Error('Unsupported Passport type');
  if (!Array.isArray(profile.languages) || profile.languages.length < 1 || profile.languages.length > 8) throw new Error('Choose 1-8 languages');
  const seen = new Set();
  for (const language of profile.languages) {
    if (typeof language !== 'string' || !/^[A-Z]{2,8}(?:-[A-Z0-9]{2,8})?$/.test(language) || seen.has(language)) throw new Error('Languages must be unique short codes');
    seen.add(language);
  }
  if (profile.motto !== undefined) text(profile.motto, 'Motto', 2, 120);
  return profile;
}

export function buildSelfRegistrationPayload({ did, profile, challenge, submittedAt = new Date().toISOString() }) {
  publicKeyFromDid(did);
  validatePublicProfile(profile);
  if (!challenge || typeof challenge.id !== 'string' || typeof challenge.nonce !== 'string') throw new Error('Server challenge is missing');
  if (!/^[0-9a-f-]{36}$/.test(challenge.id) || !/^[A-Za-z0-9_-]{32,64}$/.test(challenge.nonce)) throw new Error('Server challenge is invalid');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(submittedAt)) throw new Error('Submission timestamp is invalid');
  return {
    schema: 'agent-passport-self-registration-v1',
    did,
    profile,
    challenge: { id: challenge.id, nonce: challenge.nonce },
    consent: { publicIndex: true, publicProfile: true, selfRegisteredUnverified: true },
    submittedAt
  };
}

export async function validateSignedSelfRegistration(document, expectedChallenge = null, cryptoApi = globalThis.crypto) {
  safeShape(document);
  if (!document || document.schema !== 'agent-passport-signed-self-registration-v1') throw new Error('Unsupported self-registration document');
  const payload = document.payload;
  if (!payload || payload.schema !== 'agent-passport-self-registration-v1') throw new Error('Self-registration payload is missing');
  publicKeyFromDid(payload.did);
  validatePublicProfile(payload.profile);
  if (!payload.challenge || !/^[0-9a-f-]{36}$/.test(payload.challenge.id) || !/^[A-Za-z0-9_-]{32,64}$/.test(payload.challenge.nonce)) throw new Error('Registration challenge is invalid');
  if (expectedChallenge && (payload.challenge.id !== expectedChallenge.id || payload.challenge.nonce !== expectedChallenge.nonce || payload.did !== expectedChallenge.did)) throw new Error('Registration challenge does not match');
  const consent = payload.consent;
  if (!consent || consent.publicIndex !== true || consent.publicProfile !== true || consent.selfRegisteredUnverified !== true) throw new Error('Public registration consent is incomplete');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(payload.submittedAt)) throw new Error('Submission timestamp is invalid');
  const canonical = canonicalJson(payload);
  if (document.canonicalJson !== canonical) throw new Error('Canonical JSON does not match the registration payload');
  const digest = await sha256Hex(canonical, cryptoApi);
  if (document.payloadSha256 !== digest) throw new Error('Registration SHA-256 does not match');
  if (document.signature?.algorithm !== 'Ed25519' || document.signature.did !== payload.did) throw new Error('Registration signature metadata does not match');
  const publicKey = await cryptoApi.subtle.importKey('raw', publicKeyFromDid(payload.did), { name: 'Ed25519' }, false, ['verify']);
  const verified = await cryptoApi.subtle.verify({ name: 'Ed25519' }, publicKey, base64UrlDecode(document.signature.value), encoder.encode(canonical));
  if (!verified) throw new Error('Registration signature is invalid');
  return { did: payload.did, profile: payload.profile, payloadSha256: digest, submittedAt: payload.submittedAt };
}
