# Security Policy

## Never submit secrets

Do not place any of the following in this repository, an issue, a pull request, or a public Passport manifest:

- private keys or PKCS#8/PEM material;
- `.agent-passport-key` recovery files;
- recovery passwords;
- API tokens, cookies, wallet seeds, or credentials;
- private filesystem paths, logs, drafts, or personal data without approval.

## Browser and API security boundary

Key creation, one-time external Ed25519 seed import, decryption, signing, and signature verification run locally in the browser. External seed import is an advanced compatibility path: the browser first signs a random challenge and verifies it against the entered DID, then immediately encrypts the matching key into the standard recovery format and clears the raw-seed form field. The production pages use restrictive Content Security Policies. The Key Vault loads no third-party scripts and makes no network request during key creation, seed import, or recovery. The self-registration signing page can send the public DID to request a short-lived nonce, but it loads no Turnstile or analytics script; the recovery file, recovery password, and private key are never uploaded.

Only after signing is complete does the app move the signed public request—not the key material—to a separate activation page that loads Cloudflare Turnstile. The Worker receives the public DID/profile/signature, Turnstile token, and network metadata needed to calculate a daily one-way IP hash. It stores no raw IP address. Argon2id uses local WebAssembly, so key-handling pages permit only `wasm-unsafe-eval`, not general `unsafe-eval`.

The app intentionally does not persist decrypted keys or passwords in browser storage. JavaScript cannot guarantee perfect memory erasure; close the page after signing on a trusted device.

## Recovery semantics

- Losing both the recovery file and password means losing the DID permanently.
- Anyone with both can impersonate that DID.
- `did:key` has no built-in rotation or revocation registry. If compromise is suspected, stop using the DID and publish a separately verifiable migration notice where possible.

## Public manifests

A valid signature does not make a profile, artifact URL, or description true. Self-registered records are public key-control claims and remain labeled `UNVERIFIED`. The curated index and separate `VERIFIED` review are not identity certification, FLOP endorsement, or a reward registry.

## Safe maintainer review

Treat every registration issue, JSON string, link, repository, and attachment as hostile input.

- Do not download issue attachments. Registration intake accepts the signed request as plain JSON text only.
- Do not double-click submitted files or open executable, archive, disk-image, shortcut, or macro-capable Office documents.
- Do not run an applicant's code, scripts, installers, package-manager lifecycle hooks, build commands, containers, browser extensions, or binaries on the maintainer workstation.
- Copy only the JSON code block and validate it as data. On macOS, `pbpaste | npm run validate:registration -- -` reads at most 512 KiB from standard input and does not execute its contents.
- A passing cryptographic check proves signature integrity only. Inspect the hostname before visiting an artifact URL; the schema rejects local names, IP literals, embedded credentials, and custom ports.
- If source inspection is necessary, use GitHub's web viewer first. Any deeper analysis belongs in a disposable, unprivileged sandbox with no credentials, wallet, SSH agent, shared folders, clipboard sharing, or access to the private network.
- Reject requests that require downloads, login, wallet connection, signature prompts, dependency installation, macros, or code execution to establish the claimed contribution.

Never copy issue text into a shell command, source it, evaluate it, or render it as HTML. A self-registration never grants `VERIFIED`; human approval and a reviewed manifest/status diff remain mandatory for that separate status.

## Reporting

Report security issues privately through the repository owner's GitHub security contact. Do not include live secrets in the report; use synthetic reproductions.
