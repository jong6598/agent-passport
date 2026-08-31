import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createRecoveryFile,
  parseRecoveryFile,
  publicKeyFromDid,
  serializeRecoveryFile,
  signWithRecoveryFile,
  verifyDidSignature,
  verifyRecoveryFile
} from './key-vault-core.js';

const PASSWORD = 'correct horse battery staple 2026';
let recoveryPromise;
const recovery = () => recoveryPromise ||= createRecoveryFile(PASSWORD);

test('creates a portable encrypted Ed25519 did:key recovery file', async () => {
  const value = await recovery();
  assert.equal(value.schema, 'agent-passport-key-v1');
  assert.equal(value.kdf.name, 'Argon2id');
  assert.equal(value.kdf.memoryKiB, 65536);
  assert.equal(value.kdf.iterations, 3);
  assert.equal(value.cipher.name, 'AES-256-GCM');
  assert.equal(publicKeyFromDid(value.did).length, 32);
  const serialized = serializeRecoveryFile(value);
  assert.deepEqual(parseRecoveryFile(serialized), value);
  assert.equal(serialized.includes(PASSWORD), false);
  assert.equal(serialized.includes('PRIVATE KEY'), false);
});

test('requires a real restore challenge before issuance completes', async () => {
  const result = await verifyRecoveryFile(await recovery(), PASSWORD);
  assert.equal(result.verified, true);
  assert.match(result.did, /^did:key:z6Mk/);
});

test('fails closed for a wrong password', async () => {
  await assert.rejects(
    verifyRecoveryFile(await recovery(), 'this password is definitely wrong'),
    /wrong or the file was modified/
  );
});

test('fails closed for modified ciphertext', async () => {
  const original = await recovery();
  const modified = structuredClone(original);
  const last = modified.ciphertext.at(-1);
  modified.ciphertext = `${modified.ciphertext.slice(0, -1)}${last === 'A' ? 'B' : 'A'}`;
  await assert.rejects(verifyRecoveryFile(modified, PASSWORD), /wrong or the file was modified/);
});

test('signs only after unlocking the recovery file', async () => {
  const canonical = '{"hello":"passport"}';
  const signed = await signWithRecoveryFile(await recovery(), PASSWORD, canonical);
  assert.match(signed.did, /^did:key:z6Mk/);
  assert.match(signed.signature, /^[A-Za-z0-9_-]+$/);
  assert.equal(await verifyDidSignature(signed.did, canonical, signed.signature), true);
  assert.equal(await verifyDidSignature(signed.did, `${canonical} `, signed.signature), false);
});

test('rejects hostile KDF parameters before allocating memory', async () => {
  const modified = structuredClone(await recovery());
  modified.kdf.memoryKiB = 999999999;
  await assert.rejects(verifyRecoveryFile(modified, PASSWORD), /Unsafe recovery memory parameter/);
});
