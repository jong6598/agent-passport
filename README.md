# Agent Passport

A public, verifiable contribution passport for persistent `did:key` identities.

## What works

- **Public lookup:** enter an exact DID and open its registered public manifest without a private key.
- **Local verification:** verify Ed25519 signatures and payload hashes in the browser.
- **Key Vault:** create an Ed25519 DID locally, export an Argon2id + AES-256-GCM encrypted recovery file, and complete a mandatory restore challenge.
- **Contribution Studio:** review canonical JSON and SHA-256, sign locally, independently verify the signature, and download a portable signed record.
- **Publication boundary:** signing never posts or registers anything automatically. External publication requires a separate explicit action.

## Trust limits

A DID signature proves control of a key over exact bytes. It does **not** prove personhood, uniqueness, truth, endorsement, rewards, token eligibility, or ownership of a linked artifact. Artifact links and contribution descriptions remain claims that viewers must inspect.

## Local development

Requirements: Node.js 24+ and Python 3 for the static server.

```bash
npm ci --ignore-scripts
npm test
python3 -m http.server 8765 --bind 127.0.0.1
```

Open:

- `http://127.0.0.1:8765/` — public Passport lookup
- `http://127.0.0.1:8765/vault.html` — Key Vault
- `http://127.0.0.1:8765/studio.html` — Contribution Studio

Optional browser smoke tests use Google Chrome. On non-macOS systems, set `CHROME_EXECUTABLE_PATH` to the browser binary:

```bash
export CHROME_EXECUTABLE_PATH=/path/to/chrome  # omit on macOS with standard Chrome install
npm run test:browser
npm run test:passport
npm run test:studio
```

## Cryptography

- Identity/signature: Ed25519 via Web Crypto
- DID encoding: `did:key` with Ed25519 multicodec prefix
- Password KDF: Argon2id, 64 MiB, 3 iterations, parallelism 1
- Backup encryption: AES-256-GCM with random 128-bit salt and 96-bit nonce
- Contribution digest: SHA-256 over deterministic canonical JSON

The encrypted recovery file contains public metadata plus encrypted PKCS#8 bytes. The password is never written into the file, localStorage, sessionStorage, cookies, or this repository.

## Public registry

`data/index.json` is a curated discovery index. A DID is viewable only when its entry points to a same-origin manifest under `data/passports/` and the manifest DID exactly matches the index DID.

Adding a public Passport is a publication action. Review the manifest for sensitive information and obtain the DID holder's approval before opening a pull request.

## Build and release

```bash
npm run build
npm run prepare:dist
npm run release:check
```

GitHub Pages publishes only the allowlisted `dist/` output, not the development tree or `node_modules`.

## Security

Read [SECURITY.md](SECURITY.md). Do not submit private keys, recovery files, passwords, cookies, tokens, private logs, or unapproved personal data in issues or pull requests.

## License

MIT
