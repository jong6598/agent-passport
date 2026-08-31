import assert from 'node:assert/strict';
import test from 'node:test';
import { createRecoveryFile, signWithRecoveryFile } from '../web/key-vault-core.js';
import { buildSelfRegistrationPayload, canonicalJson, sha256Hex, validateSignedSelfRegistration } from './self-registration-core.js';

const password = 'self registration test password';

async function fixture(overrides = {}) {
  const recovery = await createRecoveryFile(password);
  const challenge = { id: crypto.randomUUID(), nonce: 'A'.repeat(32) };
  const payload = buildSelfRegistrationPayload({
    did: recovery.did,
    profile: { displayName: 'SELF TEST', type: 'BUILDER', operatorRegion: 'KOREA', languages: ['KO', 'EN'] },
    challenge,
    submittedAt: '2026-08-31T12:00:00.000Z',
    ...overrides
  });
  const canonical = canonicalJson(payload);
  const signed = await signWithRecoveryFile(recovery, password, canonical);
  return {
    recovery,
    challenge,
    document: {
      schema: 'agent-passport-signed-self-registration-v1',
      payload,
      canonicalJson: canonical,
      payloadSha256: await sha256Hex(canonical),
      signature: { algorithm: 'Ed25519', did: signed.did, value: signed.signature }
    }
  };
}

test('validates a signed self-registration bound to the server challenge', async () => {
  const { recovery, challenge, document } = await fixture();
  const result = await validateSignedSelfRegistration(document, { ...challenge, did: recovery.did });
  assert.equal(result.did, recovery.did);
  assert.equal(result.profile.displayName, 'SELF TEST');
});

test('rejects a challenge mismatch and replay substitution', async () => {
  const { recovery, challenge, document } = await fixture();
  await assert.rejects(() => validateSignedSelfRegistration(document, { ...challenge, nonce: 'B'.repeat(32), did: recovery.did }), /does not match/);
});

test('rejects profile mutation after signing', async () => {
  const { recovery, challenge, document } = await fixture();
  document.payload.profile.displayName = 'MUTATED';
  await assert.rejects(() => validateSignedSelfRegistration(document, { ...challenge, did: recovery.did }), /Canonical JSON/);
});

test('rejects incomplete consent and hostile fields', async () => {
  const first = await fixture();
  first.document.payload.consent.publicIndex = false;
  first.document.canonicalJson = canonicalJson(first.document.payload);
  first.document.payloadSha256 = await sha256Hex(first.document.canonicalJson);
  await assert.rejects(() => validateSignedSelfRegistration(first.document), /consent/);

  const second = await fixture();
  second.document.payload.profile = JSON.parse('{"displayName":"SELF TEST","type":"BUILDER","operatorRegion":"KOREA","languages":["KO"],"__proto__":{"admin":true}}');
  await assert.rejects(() => validateSignedSelfRegistration(second.document), /Unsafe JSON field/);
});
