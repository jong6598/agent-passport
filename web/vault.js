import { createRecoveryFile, parseRecoveryFile, serializeRecoveryFile, verifyRecoveryFile } from './key-vault-core.js';

const state = { encryptedBackup: null, pendingDid: null, downloaded: false };
const $ = id => document.getElementById(id);

function setStatus(message, tone = '') {
  const status = $('vault-status');
  status.textContent = message;
  status.dataset.tone = tone;
}

function clearSecretInputs() {
  $('new-password').value = '';
  $('confirm-password').value = '';
  $('restore-password').value = '';
}

function downloadBackup() {
  if (!state.encryptedBackup || !state.pendingDid) return;
  const blob = new Blob([state.encryptedBackup], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `agent-passport-${state.pendingDid.slice(-10)}.agent-passport-key`;
  link.click();
  URL.revokeObjectURL(link.href);
  state.downloaded = true;
  $('restore-panel').hidden = false;
  setStatus('Encrypted backup downloaded. Re-import that file below to finish issuance.', 'working');
}

async function createIdentity(event) {
  event.preventDefault();
  const password = $('new-password').value;
  const confirmation = $('confirm-password').value;
  if (password !== confirmation) {
    setStatus('The recovery passwords do not match.', 'error');
    return;
  }
  if (!$('loss-ack').checked) {
    setStatus('Confirm that a lost key and every backup cannot be centrally recovered.', 'error');
    return;
  }
  const button = $('create-button');
  button.disabled = true;
  setStatus('Creating Ed25519 identity and encrypting it locally…', 'working');
  try {
    const recovery = await createRecoveryFile(password);
    state.encryptedBackup = serializeRecoveryFile(recovery);
    state.pendingDid = recovery.did;
    state.downloaded = false;
    $('created-did').textContent = recovery.did;
    $('created-panel').hidden = false;
    $('restore-panel').hidden = false;
    $('download-button').disabled = false;
    setStatus('Identity created locally. Download and verify the encrypted backup to finish.', 'working');
  } catch (error) {
    setStatus(error.message, 'error');
  } finally {
    clearSecretInputs();
    button.disabled = false;
  }
}

async function verifyBackup(event) {
  event.preventDefault();
  const file = $('recovery-file').files[0];
  const password = $('restore-password').value;
  if (!file) {
    setStatus('Select the encrypted .agent-passport-key file.', 'error');
    return;
  }
  if (state.pendingDid && !state.downloaded) {
    setStatus('Download the encrypted backup before completing issuance.', 'error');
    return;
  }
  const button = $('verify-backup-button');
  button.disabled = true;
  setStatus('Decrypting locally and signing a one-time challenge…', 'working');
  try {
    const recovery = parseRecoveryFile(await file.text());
    if (state.pendingDid && recovery.did !== state.pendingDid) throw new Error('This backup does not match the newly created DID');
    const result = await verifyRecoveryFile(recovery, password);
    $('verified-did').textContent = result.did;
    $('success-panel').hidden = false;
    $('issuance-state').textContent = state.pendingDid ? 'PASSPORT IDENTITY ISSUED' : 'EXISTING IDENTITY RECOVERED';
    state.encryptedBackup = null;
    state.pendingDid = null;
    setStatus('Backup restored and challenge signature verified. No private key was uploaded.', 'success');
  } catch (error) {
    setStatus(error.message, 'error');
  } finally {
    $('restore-password').value = '';
    button.disabled = false;
  }
}

$('create-form').addEventListener('submit', createIdentity);
$('download-button').addEventListener('click', downloadBackup);
$('restore-form').addEventListener('submit', verifyBackup);
