import { publicKeyFromDid, sha256Hex, validateSignedSelfRegistration } from './shared/self-registration-core.js';

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };
const DAY_MS = 86_400_000;

function response(body, status = 200, origin = null) {
  const headers = new Headers(JSON_HEADERS);
  if (origin) {
    headers.set('access-control-allow-origin', origin);
    headers.set('vary', 'Origin');
  }
  return new Response(JSON.stringify(body), { status, headers });
}

function errorResponse(error, status, origin) {
  return response({ ok: false, error: error.message }, status, origin);
}

export function configuredValueMatches(value, configuredValues) {
  if (!value || !configuredValues) return false;
  return configuredValues.split(',').map(item => item.trim()).filter(Boolean).includes(value);
}

function allowedOrigin(request, env) {
  const origin = request.headers.get('Origin');
  if (!configuredValueMatches(origin, env.ALLOWED_ORIGIN)) return null;
  return origin;
}

function dayKey(now = Date.now()) {
  return new Date(now).toISOString().slice(0, 10);
}

function clientIp(request, env) {
  const ip = request.headers.get('CF-Connecting-IP');
  if (ip) return ip;
  if (env.ENVIRONMENT !== 'production') return request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || '127.0.0.1';
  throw new Error('Client IP is unavailable');
}

async function ipHash(ip, day, secret, cryptoApi = globalThis.crypto) {
  if (!secret || secret.length < 32) throw new Error('IP hash secret is not configured');
  const key = await cryptoApi.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await cryptoApi.subtle.sign('HMAC', key, new TextEncoder().encode(`${day}|${ip}`));
  return [...new Uint8Array(signature)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

async function readJson(request, maxBytes = 131072) {
  const declared = Number(request.headers.get('content-length') || 0);
  if (declared > maxBytes) throw new Error('Request is too large');
  const raw = await request.text();
  if (new TextEncoder().encode(raw).length > maxBytes) throw new Error('Request is too large');
  try { return JSON.parse(raw); } catch { throw new Error('Request body is not valid JSON'); }
}

async function verifyTurnstile(token, ip, env) {
  if (env.REQUIRE_TURNSTILE !== 'true') return;
  if (!env.TURNSTILE_SECRET) throw new Error('Turnstile is not configured');
  if (typeof token !== 'string' || token.length < 10 || token.length > 2048) throw new Error('Complete the anti-bot check');
  const form = new FormData();
  form.set('secret', env.TURNSTILE_SECRET);
  form.set('response', token);
  form.set('remoteip', ip);
  const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
  const verdict = await result.json();
  if (!verdict.success) throw new Error('Anti-bot verification failed');
  if (!configuredValueMatches(verdict.hostname, env.TURNSTILE_HOSTNAME)) throw new Error('Anti-bot token was issued for a different host');
}

function randomNonce(cryptoApi = globalThis.crypto) {
  const bytes = cryptoApi.getRandomValues(new Uint8Array(24));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function issueChallenge(request, env, origin) {
  const body = await readJson(request, 4096);
  publicKeyFromDid(body.did);
  const now = Date.now();
  const day = dayKey(now);
  const hash = await ipHash(clientIp(request, env), day, env.IP_HASH_SECRET);
  const existing = await env.DB.prepare('SELECT challenge_count FROM ip_limits WHERE day = ?1 AND ip_hash = ?2').bind(day, hash).first();
  if ((existing?.challenge_count || 0) >= Number(env.IP_CHALLENGES_PER_DAY || 10)) throw Object.assign(new Error('Daily challenge limit reached for this network'), { status: 429 });
  const challenge = { id: crypto.randomUUID(), nonce: randomNonce(), did: body.did, expiresAt: new Date(now + 10 * 60_000).toISOString() };
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO ip_limits(day, ip_hash, challenge_count, registration_count) VALUES(?1, ?2, 1, 0)
      ON CONFLICT(day, ip_hash) DO UPDATE SET challenge_count = challenge_count + 1`).bind(day, hash),
    env.DB.prepare('INSERT INTO challenges(id, did, nonce, ip_hash, expires_at, created_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6)')
      .bind(challenge.id, challenge.did, challenge.nonce, hash, challenge.expiresAt, new Date(now).toISOString())
  ]);
  return response({ ok: true, challenge }, 201, origin);
}

async function createManifest(document) {
  const payload = document.payload;
  const digest = await sha256Hex(payload.did);
  return {
    schema: 'agent-passport-manifest-v1',
    profile: {
      passportNumber: `AP-${digest.slice(0, 12).toUpperCase()}`,
      displayName: payload.profile.displayName,
      type: payload.profile.type,
      operatorRegion: payload.profile.operatorRegion,
      languages: payload.profile.languages,
      motto: payload.profile.motto,
      issuer: 'SELF-REGISTERED',
      issuedOn: payload.submittedAt.slice(0, 10),
      validUntil: 'OPEN',
      did: payload.did,
      registrationStatus: 'self-registered-unverified'
    },
    signedRegistration: document,
    contributions: [],
    disclaimer: 'Self-registered and cryptographically signed. This Passport is unverified and does not prove personhood, uniqueness, truth, ownership, endorsement, or reward eligibility.'
  };
}

async function registerPassport(request, env, origin) {
  const body = await readJson(request);
  const document = body.registration;
  const challengeId = document?.payload?.challenge?.id;
  if (typeof challengeId !== 'string') throw new Error('Registration challenge is missing');
  const challenge = await env.DB.prepare('SELECT id, did, nonce, ip_hash, expires_at, created_at, used_at FROM challenges WHERE id = ?1').bind(challengeId).first();
  if (!challenge || challenge.used_at) throw Object.assign(new Error('Registration challenge is missing or already used'), { status: 409 });
  if (Date.parse(challenge.expires_at) <= Date.now()) throw Object.assign(new Error('Registration challenge expired'), { status: 410 });
  const ip = clientIp(request, env);
  const day = dayKey();
  const challengeDay = dayKey(Date.parse(challenge.created_at));
  const challengeHash = await ipHash(ip, challengeDay, env.IP_HASH_SECRET);
  if (challenge.ip_hash !== challengeHash) throw Object.assign(new Error('Registration must use the same network as the challenge'), { status: 403 });
  const hash = await ipHash(ip, day, env.IP_HASH_SECRET);
  const verified = await validateSignedSelfRegistration(document, challenge);
  const submitted = Date.parse(verified.submittedAt);
  if (!Number.isFinite(submitted) || Math.abs(Date.now() - submitted) > 15 * 60_000) throw new Error('Registration timestamp is outside the allowed window');
  await verifyTurnstile(body.turnstileToken, ip, env);

  const duplicate = await env.DB.prepare('SELECT did FROM passports WHERE did = ?1').bind(verified.did).first();
  if (duplicate) throw Object.assign(new Error('This DID already has a Passport'), { status: 409 });
  const ipLimit = await env.DB.prepare('SELECT registration_count FROM ip_limits WHERE day = ?1 AND ip_hash = ?2').bind(day, hash).first();
  if ((ipLimit?.registration_count || 0) >= Number(env.IP_REGISTRATIONS_PER_DAY || 3)) throw Object.assign(new Error('Daily Passport limit reached for this network'), { status: 429 });
  const globalLimit = await env.DB.prepare('SELECT registration_count FROM global_limits WHERE day = ?1').bind(day).first();
  if ((globalLimit?.registration_count || 0) >= Number(env.GLOBAL_REGISTRATIONS_PER_DAY || 100)) throw Object.assign(new Error('Daily global Passport limit reached'), { status: 429 });

  const now = new Date().toISOString();
  const manifest = await createManifest(document);
  await env.DB.batch([
    env.DB.prepare('UPDATE challenges SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL').bind(now, challenge.id),
    env.DB.prepare(`INSERT INTO ip_limits(day, ip_hash, challenge_count, registration_count) VALUES(?1, ?2, 0, 1)
      ON CONFLICT(day, ip_hash) DO UPDATE SET registration_count = registration_count + 1`).bind(day, hash),
    env.DB.prepare(`INSERT INTO global_limits(day, registration_count) VALUES(?1, 1)
      ON CONFLICT(day) DO UPDATE SET registration_count = registration_count + 1`).bind(day),
    env.DB.prepare(`INSERT INTO passports(did, display_name, status, profile_json, registration_json, manifest_json, created_at, updated_at)
      VALUES(?1, ?2, 'self-registered-unverified', ?3, ?4, ?5, ?6, ?6)`)
      .bind(verified.did, verified.profile.displayName, JSON.stringify(verified.profile), JSON.stringify(document), JSON.stringify(manifest), now)
  ]);
  return response({ ok: true, status: 'self-registered-unverified', passport: manifest }, 201, origin);
}

async function getPassport(url, env, origin) {
  const did = url.searchParams.get('did');
  publicKeyFromDid(did);
  const row = await env.DB.prepare("SELECT manifest_json FROM passports WHERE did = ?1 AND status != 'blocked'").bind(did).first();
  if (!row) return response({ ok: false, error: 'Passport not found' }, 404, origin);
  return response({ ok: true, passport: JSON.parse(row.manifest_json) }, 200, origin);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = allowedOrigin(request, env);
    if (request.method === 'OPTIONS') {
      if (!origin) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers: {
        'access-control-allow-origin': origin,
        'access-control-allow-methods': 'GET, POST, OPTIONS',
        'access-control-allow-headers': 'content-type',
        'access-control-max-age': '600',
        vary: 'Origin'
      } });
    }
    if (url.pathname === '/v1/health' && request.method === 'GET') return response({ ok: true, service: 'agent-passport-api', plan: 'free-fail-closed' }, 200, origin);
    if (!origin) return response({ ok: false, error: 'Origin is not allowed' }, 403);
    try {
      if (url.pathname === '/v1/challenges' && request.method === 'POST') return await issueChallenge(request, env, origin);
      if (url.pathname === '/v1/passports' && request.method === 'POST') return await registerPassport(request, env, origin);
      if (url.pathname === '/v1/passports' && request.method === 'GET') return await getPassport(url, env, origin);
      return response({ ok: false, error: 'Route not found' }, 404, origin);
    } catch (error) {
      return errorResponse(error, error.status || (error.message.includes('too large') ? 413 : 400), origin);
    }
  }
};
