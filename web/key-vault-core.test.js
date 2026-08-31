import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createRecoveryFile,
  createRecoveryFileFromSeed,
  didFromPublicKey,
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
  const first = modified.ciphertext[0];
  modified.ciphertext = `${first === 'A' ? 'B' : 'A'}${modified.ciphertext.slice(1)}`;
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

test('imports a matching external Ed25519 seed into the encrypted recovery format', async () => {
  const seedHex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
  const publicHex = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
  const publicKey = Uint8Array.from(publicHex.match(/../g), byte => Number.parseInt(byte, 16));
  const did = didFromPublicKey(publicKey);
  const imported = await createRecoveryFileFromSeed(did, seedHex, PASSWORD);

  assert.equal(imported.did, did);
  assert.equal(imported.schema, 'agent-passport-key-v1');
  assert.equal(imported.kdf.name, 'Argon2id');
  assert.equal(await verifyRecoveryFile(imported, PASSWORD).then(result => result.verified), true);
  const serialized = serializeRecoveryFile(imported);
  assert.equal(serialized.includes(seedHex), false);
  assert.equal(serialized.includes(PASSWORD), false);
});

test('rejects an external seed that does not control the requested DID', async () => {
  const seedHex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f61';
  const publicHex = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
  const publicKey = Uint8Array.from(publicHex.match(/../g), byte => Number.parseInt(byte, 16));
  await assert.rejects(
    createRecoveryFileFromSeed(didFromPublicKey(publicKey), seedHex, PASSWORD),
    /does not control this DID/
  );
});

test('rejects ambiguous or malformed external private key input', async () => {
  const publicKey = new Uint8Array(32);
  await assert.rejects(
    createRecoveryFileFromSeed(didFromPublicKey(publicKey), 'not-a-32-byte-seed', PASSWORD),
    /32-byte Ed25519 seed/
  );
});

test('rejects hostile KDF parameters before allocating memory', async () => {
  const modified = structuredClone(await recovery());
  modified.kdf.memoryKiB = 999999999;
  await assert.rejects(verifyRecoveryFile(modified, PASSWORD), /Unsafe recovery memory parameter/);
});
