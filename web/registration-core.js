import { verifyDidSignature } from './key-vault-core.js';

const encoder = new TextEncoder();
const CONTRIBUTION_SCHEMA = 'agent-passport-signed-contribution-v1';
const REGISTRATION_PAYLOAD_SCHEMA = 'agent-passport-registration-v1';
const REGISTRATION_SCHEMA = 'agent-passport-signed-registration-v1';
const CATEGORIES = new Set(['CODE', 'RESEARCH', 'DESIGN', 'LOCALIZATION', 'COMMUNITY', 'OTHER']);
const AGENT_TYPES = new Set(['AGENT', 'BUILDER', 'RESEARCHER', 'CREATOR', 'COMMUNITY', 'OTHER']);

export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Canonical JSON cannot contain a non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => {
      if (typeof value[key] === 'undefined') throw new Error('Canonical JSON cannot contain undefined');
      return `${JSON.stringify(key)}:${canonicalJson(value[key])}`;
    }).join(',')}}`;
  }
  throw new Error('Unsupported canonical JSON value');
}

export async function sha256Hex(text, cryptoApi = globalThis.crypto) {
  const digest = await cryptoApi.subtle.digest('SHA-256', encoder.encode(text));
  return [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, '0')).join('');
}

function text(value, name, min, max) {
  if (typeof value !== 'string' || value.length < min || value.length > max) throw new Error(`${name} must be ${min}–${max} characters`);
  if (value !== value.trim() || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${name} contains unsupported whitespace or control characters`);
  return value;
}

function publicHttpsUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Artifact URL is invalid'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.href.length > 2048) throw new Error('Public registration requires an HTTPS artifact URL without embedded credentials');
  return url.href;
}

function validateProfile(profile) {
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)) throw new Error('Registration profile is missing');
  text(profile.displayName, 'Display name', 2, 80);
  if (!AGENT_TYPES.has(profile.type)) throw new Error('Unsupported Passport type');
  text(profile.operatorRegion, 'Operator region', 2, 64);
  if (!Array.isArray(profile.languages) || profile.languages.length < 1 || profile.languages.length > 8) throw new Error('Choose 1–8 languages');
  const seen = new Set();
  for (const language of profile.languages) {
    if (typeof language !== 'string' || !/^[A-Z]{2,8}(?:-[A-Z0-9]{2,8})?$/.test(language)) throw new Error('Languages must use short codes such as KO, EN, or ZH-HANT');
    if (seen.has(language)) throw new Error(`Duplicate language: ${language}`);
    seen.add(language);
  }
  if (profile.motto !== undefined) text(profile.motto, 'Motto', 2, 120);
}

export async function validateSignedContribution(document, cryptoApi = globalThis.crypto) {
  if (!document || document.schema !== CONTRIBUTION_SCHEMA) throw new Error('Unsupported signed contribution file');
  const payload = document.payload;
  if (!payload || payload.schema !== 'agent-passport-contribution-v1') throw new Error('Contribution payload is missing or unsupported');
  text(payload.id, 'Contribution ID', 3, 80);
  text(payload.did, 'DID', 20, 160);
  text(payload.title, 'Contribution title', 3, 120);
  text(payload.summary, 'Contribution summary', 10, 1000);
  if (!CATEGORIES.has(payload.category)) throw new Error('Unsupported contribution category');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(payload.date)) throw new Error('Contribution date is invalid');
  if (!payload.artifact || publicHttpsUrl(payload.artifact.url) !== payload.artifact.url) throw new Error('Artifact URL must be normalized HTTPS');
  if (payload.artifact.commit !== undefined && !/^[0-9a-f]{7,64}$/.test(payload.artifact.commit)) throw new Error('Artifact revision is invalid');

  const canonical = canonicalJson(payload);
  if (document.canonicalJson !== canonical) throw new Error('Contribution canonical JSON does not match its payload');
  const digest = await sha256Hex(canonical, cryptoApi);
  if (document.payloadSha256 !== digest) throw new Error('Contribution SHA-256 does not match');
  if (document.signature?.algorithm !== 'Ed25519' || document.signature.did !== payload.did) throw new Error('Contribution signature metadata does not match the DID');
  if (!await verifyDidSignature(payload.did, canonical, document.signature.value, cryptoApi)) throw new Error('Contribution signature is invalid');
  return { did: payload.did, payloadSha256: digest, artifactUrl: payload.artifact.url, title: payload.title };
}

export function buildRegistrationPayload({ profile, signedContribution, submittedAt }) {
  validateProfile(profile);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(submittedAt)) throw new Error('Submission timestamp is invalid');
  return {
    schema: REGISTRATION_PAYLOAD_SCHEMA,
    did: signedContribution.payload.did,
    profile,
    contributions: [signedContribution],
    consent: {
      publicIndex: true,
      publicManifest: true,
      publicArtifactLinks: true,
      sensitiveDataReviewed: true
    },
    submittedAt
  };
}

export async function validateSignedRegistration(document, cryptoApi = globalThis.crypto) {
  if (!document || document.schema !== REGISTRATION_SCHEMA) throw new Error('Unsupported registration request');
  const payload = document.payload;
  if (!payload || payload.schema !== REGISTRATION_PAYLOAD_SCHEMA) throw new Error('Registration payload is missing or unsupported');
  text(payload.did, 'DID', 20, 160);
  validateProfile(payload.profile);
  if (!Array.isArray(payload.contributions) || payload.contributions.length !== 1) throw new Error('Registration must contain exactly one signed contribution');
  const contribution = await validateSignedContribution(payload.contributions[0], cryptoApi);
  if (contribution.did !== payload.did) throw new Error('Registration DID does not match the contribution DID');
  const consent = payload.consent;
  if (!consent || consent.publicIndex !== true || consent.publicManifest !== true || consent.publicArtifactLinks !== true || consent.sensitiveDataReviewed !== true) throw new Error('Every publication consent must be explicit');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(payload.submittedAt)) throw new Error('Submission timestamp is invalid');

  const canonical = canonicalJson(payload);
  if (document.canonicalJson !== canonical) throw new Error('Registration canonical JSON does not match its payload');
  const digest = await sha256Hex(canonical, cryptoApi);
  if (document.payloadSha256 !== digest) throw new Error('Registration SHA-256 does not match');
  if (document.signature?.algorithm !== 'Ed25519' || document.signature.did !== payload.did) throw new Error('Registration signature metadata does not match the DID');
  if (!await verifyDidSignature(payload.did, canonical, document.signature.value, cryptoApi)) throw new Error('Registration signature is invalid');
  if (document.review?.status !== 'pending' || document.review?.humanApprovalRequired !== true || document.publication?.status !== 'not-registered') throw new Error('Registration request must remain pending human review');
  return { did: payload.did, payloadSha256: digest, artifactUrl: contribution.artifactUrl, displayName: payload.profile.displayName };
}

export const registrationSchemas = Object.freeze({ contribution: CONTRIBUTION_SCHEMA, payload: REGISTRATION_PAYLOAD_SCHEMA, signed: REGISTRATION_SCHEMA });
