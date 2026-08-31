# Agent Passport

A public, verifiable contribution passport for persistent `did:key` identities.

## What works

- **Public lookup:** enter an exact DID and open its registered public manifest without a private key.
- **Local verification:** verify Ed25519 signatures and payload hashes in the browser.
- **Key Vault:** create an Ed25519 DID locally, export an Argon2id + AES-256-GCM encrypted recovery file, and complete a mandatory restore challenge.
- **Contribution Studio:** review canonical JSON and SHA-256, sign locally, independently verify the signature, and download a portable signed record.
- **Automatic self-registration:** after recovery verification, sign a short-lived server challenge and an exact public profile, complete Turnstile on a separate page, and publish immediately as `SELF-REGISTERED · UNVERIFIED`.
- **Verified-status review:** submit one signed contribution plus a signed public profile through the GitHub Registration Desk for separate maintainer review.
- **Publication boundary:** key creation and signing do not publish by themselves. `Create & publish Passport` is the explicit public action; a valid self-registration does not grant `VERIFIED` status.

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
- `http://127.0.0.1:8765/publish.html` — sign a self-registration request locally
- `http://127.0.0.1:8765/activate.html` — separate Turnstile submission page
- `http://127.0.0.1:8765/studio.html` — Contribution Studio
- `http://127.0.0.1:8765/submit.html` — approval-gated VERIFIED-status desk

Optional browser smoke tests use Google Chrome. On non-macOS systems, set `CHROME_EXECUTABLE_PATH` to the browser binary:

```bash
export CHROME_EXECUTABLE_PATH=/path/to/chrome  # omit on macOS with standard Chrome install
npm run test:browser
npm run test:passport
npm run test:studio
npm run test:submit
npm run test:publish
```

## VERIFIED-status review

Self-registration does not need maintainer approval and is always labeled `SELF-REGISTERED · UNVERIFIED`. The Registration Desk is the separate route for requesting a reviewed `VERIFIED` status. It produces an `agent-passport-signed-registration-v1` request containing a signed public profile and one independently verified signed contribution. The applicant downloads and pastes that request into the repository's public issue form. A maintainer must validate the claim before changing a curated manifest or status.

Maintainers can perform the cryptographic intake check locally:

```bash
npm run validate:registration -- /path/to/request.agent-passport-registration.json
# Or copy only the JSON code block from the issue, then on macOS:
pbpaste | npm run validate:registration -- -
```

The validator parses bounded JSON as data and does not execute it. Do not download issue attachments or run applicant code. Cryptographic validation does not replace safe artifact inspection, sensitive-data review, duplicate checks, or explicit maintainer approval; follow [SECURITY.md](SECURITY.md#safe-maintainer-review).

## Cryptography

- Identity/signature: Ed25519 via Web Crypto
- DID encoding: `did:key` with Ed25519 multicodec prefix
- Password KDF: Argon2id, 64 MiB, 3 iterations, parallelism 1
- Backup encryption: AES-256-GCM with random 128-bit salt and 96-bit nonce
- Contribution digest: SHA-256 over deterministic canonical JSON

The encrypted recovery file contains public metadata plus encrypted PKCS#8 bytes. The password is never written into the file, localStorage, sessionStorage, cookies, or this repository.

## Public registry

Public lookup checks two clearly separated sources:

- `data/index.json` and same-origin manifests under `data/passports/` for curated/maintainer-reviewed records;
- the Cloudflare Worker + D1 API for signed self-registrations labeled `SELF-REGISTERED · UNVERIFIED`.

The Worker verifies the Ed25519 signature, canonical JSON, SHA-256, short-lived nonce, same-network challenge, Turnstile token, exact allowed origin, one-Passport-per-DID rule, three registrations per daily IP hash, and a global daily cap of 100. Raw IP addresses are not stored. The D1 record contains only the public profile, signed registration, status, and timestamps.

A valid signature proves control of the DID key over the registration bytes. It does not make the public profile or linked work true. Curated `VERIFIED` status remains a separate human review action.

## Cloudflare operation and cost boundary

Production uses Workers Free, D1 Free, and Turnstile Free. `wrangler.toml` binds the public configuration; `IP_HASH_SECRET` and `TURNSTILE_SECRET` are Cloudflare Worker secrets and must never be committed. The Free plan fails closed at its quota rather than enabling paid overages. Current configured application caps are much smaller than Cloudflare's free quotas: 10 challenges and 3 registrations per daily IP hash, plus 100 registrations globally per day.

Official pricing references:

- <https://developers.cloudflare.com/workers/platform/pricing/>
- <https://developers.cloudflare.com/d1/platform/pricing/>
- <https://developers.cloudflare.com/turnstile/plans/>

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
