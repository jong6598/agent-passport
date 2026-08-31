import { argon2id } from 'hash-wasm';

const encoder = new TextEncoder();
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export const SCHEMA = 'agent-passport-key-v1';
export const DEFAULT_KDF = Object.freeze({ name: 'Argon2id', memoryKiB: 65536, iterations: 3, parallelism: 1, hashLength: 32 });

function bytesToBase64Url(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid recovery encoding');
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function base58Encode(bytes) {
  let digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  for (let i = 0; i < bytes.length - 1 && bytes[i] === 0; i++) digits.push(0);
  return digits.reverse().map(digit => B58[digit]).join('');
}

function base58Decode(value) {
  let bytes = [0];
  for (const char of value) {
    const digit = B58.indexOf(char);
    if (digit < 0) throw new Error('Invalid did:key');
    let carry = digit;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let i = 0; i < value.length - 1 && value[i] === '1'; i++) bytes.push(0);
  return Uint8Array.from(bytes.reverse());
}

export function didFromPublicKey(publicKey) {
  const multicodec = new Uint8Array(34);
  multicodec.set([0xed, 0x01]);
  multicodec.set(publicKey, 2);
  return `did:key:z${base58Encode(multicodec)}`;
}

export function publicKeyFromDid(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) throw new Error('Only did:key is supported');
  const decoded = base58Decode(did.slice('did:key:z'.length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) throw new Error('DID is not Ed25519');
  return decoded.slice(2);
}

function validatePassword(password) {
  if (typeof password !== 'string' || password.length < 14) throw new Error('Recovery password must be at least 14 characters');
}

function validateRecovery(recovery) {
  if (!recovery || recovery.schema !== SCHEMA || recovery.version !== 1) throw new Error('Unsupported recovery file');
  if (recovery.keyType !== 'Ed25519' || recovery.cipher?.name !== 'AES-256-GCM') throw new Error('Unsupported recovery cryptography');
  const kdf = recovery.kdf;
  if (kdf?.name !== 'Argon2id' || kdf.hashLength !== 32) throw new Error('Unsupported recovery KDF');
  if (!Number.isInteger(kdf.memoryKiB) || kdf.memoryKiB < 8192 || kdf.memoryKiB > 262144) throw new Error('Unsafe recovery memory parameter');
  if (!Number.isInteger(kdf.iterations) || kdf.iterations < 1 || kdf.iterations > 10) throw new Error('Unsafe recovery iteration parameter');
  if (!Number.isInteger(kdf.parallelism) || kdf.parallelism < 1 || kdf.parallelism > 4) throw new Error('Unsafe recovery parallelism parameter');
  if (base64UrlToBytes(recovery.kdf.salt).length !== 16 || base64UrlToBytes(recovery.cipher.nonce).length !== 12) throw new Error('Invalid recovery salt or nonce');
  if (base64UrlToBytes(recovery.ciphertext).length < 32) throw new Error('Invalid recovery ciphertext');
  publicKeyFromDid(recovery.did);
}

async function deriveWrappingKey(password, kdf) {
  return argon2id({
    password: encoder.encode(password),
    salt: base64UrlToBytes(kdf.salt),
    iterations: kdf.iterations,
    parallelism: kdf.parallelism,
    memorySize: kdf.memoryKiB,
    hashLength: kdf.hashLength,
    outputType: 'binary'
  });
}

async function encryptPrivateKey(did, privatePkcs8, password, cryptoApi = globalThis.crypto) {
  validatePassword(password);
  publicKeyFromDid(did);
  const salt = cryptoApi.getRandomValues(new Uint8Array(16));
  const nonce = cryptoApi.getRandomValues(new Uint8Array(12));
  const kdf = { ...DEFAULT_KDF, salt: bytesToBase64Url(salt) };
  const wrappingBytes = await deriveWrappingKey(password, kdf);
  try {
    const wrappingKey = await cryptoApi.subtle.importKey('raw', wrappingBytes, 'AES-GCM', false, ['encrypt']);
    const additionalData = encoder.encode(`${SCHEMA}|${did}`);
    const ciphertext = new Uint8Array(await cryptoApi.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData, tagLength: 128 }, wrappingKey, privatePkcs8));
    return {
      schema: SCHEMA,
      version: 1,
      did,
      keyType: 'Ed25519',
      kdf,
      cipher: { name: 'AES-256-GCM', nonce: bytesToBase64Url(nonce), tagLength: 128 },
      ciphertext: bytesToBase64Url(ciphertext),
      createdAt: new Date().toISOString()
    };
  } finally {
    wrappingBytes.fill(0);
  }
}

export async function createRecoveryFile(password, cryptoApi = globalThis.crypto) {
  validatePassword(password);
  const keyPair = await cryptoApi.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicRaw = new Uint8Array(await cryptoApi.subtle.exportKey('raw', keyPair.publicKey));
  const privatePkcs8 = new Uint8Array(await cryptoApi.subtle.exportKey('pkcs8', keyPair.privateKey));
  const did = didFromPublicKey(publicRaw);
  try {
    return await encryptPrivateKey(did, privatePkcs8, password, cryptoApi);
  } finally {
    privatePkcs8.fill(0);
  }
}

function parseExternalSeed(rawSeed) {
  if (typeof rawSeed !== 'string') throw new Error('Enter a 32-byte Ed25519 seed as 64 hex characters or base64url');
  const compact = rawSeed.trim().replace(/\s+/g, '').replace(/^0x/i, '');
  if (/^[0-9a-fA-F]{64}$/.test(compact)) {
    return Uint8Array.from(compact.match(/../g), byte => Number.parseInt(byte, 16));
  }
  if (/^[A-Za-z0-9_-]{43}$/.test(compact)) {
    const decoded = base64UrlToBytes(compact);
    if (decoded.length === 32) return decoded;
  }
  throw new Error('Enter a 32-byte Ed25519 seed as 64 hex characters or base64url');
}

export async function createRecoveryFileFromSeed(did, rawSeed, password, cryptoApi = globalThis.crypto) {
  validatePassword(password);
  const publicRaw = publicKeyFromDid(did);
  const seed = parseExternalSeed(rawSeed);
  let privatePkcs8;
  try {
    const privateJwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      d: bytesToBase64Url(seed),
      x: bytesToBase64Url(publicRaw),
      key_ops: ['sign'],
      ext: true
    };
    let privateKey;
    try {
      privateKey = await cryptoApi.subtle.importKey('jwk', privateJwk, { name: 'Ed25519' }, true, ['sign']);
      const publicKey = await cryptoApi.subtle.importKey('raw', publicRaw, { name: 'Ed25519' }, false, ['verify']);
      const challenge = cryptoApi.getRandomValues(new Uint8Array(32));
      const signature = await cryptoApi.subtle.sign({ name: 'Ed25519' }, privateKey, challenge);
      if (!(await cryptoApi.subtle.verify({ name: 'Ed25519' }, publicKey, signature, challenge))) {
        throw new Error('mismatch');
      }
    } catch {
      throw new Error('This private key does not control this DID');
    }
    privatePkcs8 = new Uint8Array(await cryptoApi.subtle.exportKey('pkcs8', privateKey));
    return await encryptPrivateKey(did, privatePkcs8, password, cryptoApi);
  } finally {
    seed.fill(0);
    privatePkcs8?.fill(0);
  }
}

async function unlockPrivateKey(recovery, password, cryptoApi = globalThis.crypto) {
  validatePassword(password);
  validateRecovery(recovery);
  const wrappingBytes = await deriveWrappingKey(password, recovery.kdf);
  try {
    const wrappingKey = await cryptoApi.subtle.importKey('raw', wrappingBytes, 'AES-GCM', false, ['decrypt']);
    const additionalData = encoder.encode(`${SCHEMA}|${recovery.did}`);
    let privatePkcs8;
    try {
      privatePkcs8 = new Uint8Array(await cryptoApi.subtle.decrypt({
        name: 'AES-GCM',
        iv: base64UrlToBytes(recovery.cipher.nonce),
        additionalData,
        tagLength: recovery.cipher.tagLength
      }, wrappingKey, base64UrlToBytes(recovery.ciphertext)));
    } catch {
      throw new Error('Recovery password is wrong or the file was modified');
    }
    try {
      return await cryptoApi.subtle.importKey('pkcs8', privatePkcs8, { name: 'Ed25519' }, false, ['sign']);
    } finally {
      privatePkcs8.fill(0);
    }
  } finally {
    wrappingBytes.fill(0);
  }
}

export async function verifyRecoveryFile(recovery, password, cryptoApi = globalThis.crypto) {
  const privateKey = await unlockPrivateKey(recovery, password, cryptoApi);
  const publicKey = await cryptoApi.subtle.importKey('raw', publicKeyFromDid(recovery.did), { name: 'Ed25519' }, false, ['verify']);
  const challenge = cryptoApi.getRandomValues(new Uint8Array(32));
  const signature = await cryptoApi.subtle.sign({ name: 'Ed25519' }, privateKey, challenge);
  const verified = await cryptoApi.subtle.verify({ name: 'Ed25519' }, publicKey, signature, challenge);
  if (!verified) throw new Error('Recovery key does not match the DID');
  return { did: recovery.did, verified: true };
}

export async function signWithRecoveryFile(recovery, password, canonicalText, cryptoApi = globalThis.crypto) {
  if (typeof canonicalText !== 'string' || !canonicalText.length) throw new Error('Canonical text is required');
  const privateKey = await unlockPrivateKey(recovery, password, cryptoApi);
  const bytes = encoder.encode(canonicalText);
  const signature = new Uint8Array(await cryptoApi.subtle.sign({ name: 'Ed25519' }, privateKey, bytes));
  return { did: recovery.did, signature: bytesToBase64Url(signature) };
}

export async function verifyDidSignature(did, canonicalText, signature, cryptoApi = globalThis.crypto) {
  if (typeof canonicalText !== 'string' || !canonicalText.length) throw new Error('Canonical text is required');
  const publicKey = await cryptoApi.subtle.importKey('raw', publicKeyFromDid(did), { name: 'Ed25519' }, false, ['verify']);
  return cryptoApi.subtle.verify({ name: 'Ed25519' }, publicKey, base64UrlToBytes(signature), encoder.encode(canonicalText));
}

export function serializeRecoveryFile(recovery) {
  validateRecovery(recovery);
  return `${JSON.stringify(recovery, null, 2)}\n`;
}

export function parseRecoveryFile(text) {
  let recovery;
  try {
    recovery = JSON.parse(text);
  } catch {
    throw new Error('Recovery file is not valid JSON');
  }
  validateRecovery(recovery);
  return recovery;
}
