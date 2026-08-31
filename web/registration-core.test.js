import assert from 'node:assert/strict';
import test from 'node:test';
import { createRecoveryFile, signWithRecoveryFile } from './key-vault-core.js';
import { buildRegistrationPayload, canonicalJson, sha256Hex, validateSignedContribution, validateSignedRegistration } from './registration-core.js';

const password = 'registration test recovery password';

async function signedContribution(recovery) {
  const payload = {
    schema: 'agent-passport-contribution-v1',
    id: '2026-08-31-registration-test',
    did: recovery.did,
    title: 'Registration test artifact',
    summary: 'A public artifact used to verify the approved registration request flow.',
    category: 'CODE',
    date: '2026-08-31',
    artifact: { url: 'https://github.com/example/public-artifact', commit: 'abcdef1' }
  };
  const canonical = canonicalJson(payload);
  const signed = await signWithRecoveryFile(recovery, password, canonical);
  return {
    schema: 'agent-passport-signed-contribution-v1',
    payload,
    canonicalJson: canonical,
    payloadSha256: await sha256Hex(canonical),
    signature: { algorithm: 'Ed25519', did: signed.did, value: signed.signature },
    publication: { status: 'not-published', separateApprovalRequired: true }
  };
}

async function signedRegistration() {
  const recovery = await createRecoveryFile(password);
  const contribution = await signedContribution(recovery);
  const payload = buildRegistrationPayload({
    profile: { displayName: 'TEST BUILDER', type: 'BUILDER', operatorRegion: 'KOREA', languages: ['KO', 'EN'], motto: 'VERIFY BEFORE TRUST' },
    signedContribution: contribution,
    submittedAt: '2026-08-31T12:00:00.000Z'
  });
  const canonical = canonicalJson(payload);
  const signed = await signWithRecoveryFile(recovery, password, canonical);
  return {
    recovery,
    document: {
      schema: 'agent-passport-signed-registration-v1',
      payload,
      canonicalJson: canonical,
      payloadSha256: await sha256Hex(canonical),
      signature: { algorithm: 'Ed25519', did: signed.did, value: signed.signature },
      review: { status: 'pending', humanApprovalRequired: true },
      publication: { status: 'not-registered', automaticPublication: false }
    }
  };
}

test('validates nested contribution and signed pending registration', async () => {
  const { document } = await signedRegistration();
  const contribution = await validateSignedContribution(document.payload.contributions[0]);
  assert.equal(contribution.did, document.payload.did);
  const result = await validateSignedRegistration(document);
  assert.equal(result.did, document.payload.did);
  assert.equal(result.displayName, 'TEST BUILDER');
});

test('rejects profile mutation after review', async () => {
  const { document } = await signedRegistration();
  document.payload.profile.displayName = 'MUTATED BUILDER';
  await assert.rejects(() => validateSignedRegistration(document), /canonical JSON does not match/);
});

test('rejects an invalid nested contribution signature', async () => {
  const { document } = await signedRegistration();
  const nested = document.payload.contributions[0];
  nested.signature.value = `${nested.signature.value.startsWith('A') ? 'B' : 'A'}${nested.signature.value.slice(1)}`;
  nested.canonicalJson = canonicalJson(nested.payload);
  nested.payloadSha256 = await sha256Hex(nested.canonicalJson);
  document.canonicalJson = canonicalJson(document.payload);
  document.payloadSha256 = await sha256Hex(document.canonicalJson);
  await assert.rejects(() => validateSignedRegistration(document), /Contribution signature is invalid/);
});

test('rejects registration without explicit pending human review', async () => {
  const { document } = await signedRegistration();
  document.review.status = 'approved';
  await assert.rejects(() => validateSignedRegistration(document), /pending human review/);
});
