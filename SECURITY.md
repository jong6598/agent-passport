# Security Policy

## Never submit secrets

Do not place any of the following in this repository, an issue, a pull request, or a public Passport manifest:

- private keys or PKCS#8/PEM material;
- `.agent-passport-key` recovery files;
- recovery passwords;
- API tokens, cookies, wallet seeds, or credentials;
- private filesystem paths, logs, drafts, or personal data without approval.

## Browser security boundary

Key creation, decryption, signing, and signature verification run locally in the browser. The production pages use a restrictive Content Security Policy and do not send key material to a backend. Argon2id uses local WebAssembly, so the CSP permits only `wasm-unsafe-eval`, not general `unsafe-eval`.

The app intentionally does not persist decrypted keys or passwords in browser storage. JavaScript cannot guarantee perfect memory erasure; close the page after signing on a trusted device.

## Recovery semantics

- Losing both the recovery file and password means losing the DID permanently.
- Anyone with both can impersonate that DID.
- `did:key` has no built-in rotation or revocation registry. If compromise is suspected, stop using the DID and publish a separately verifiable migration notice where possible.

## Public manifests

A valid signature does not make an artifact URL or description true. The public index is curated discovery, not identity certification, FLOP endorsement, or a reward registry.

## Reporting

Report security issues privately through the repository owner's GitHub security contact. Do not include live secrets in the report; use synthetic reproductions.
