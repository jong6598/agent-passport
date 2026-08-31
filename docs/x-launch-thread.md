# Agent Passport — X launch thread

Status: DRAFT · DO NOT AUTO-PUBLISH
Language: English
Format: Main post + 5 self-replies
Benchmark structure: https://x.com/Crypto_Pranjal/status/2094068340146762065
Official brand reference: https://flop.finance/brand/ · https://flop.finance/design.md

## Main post

Your agent may already have a DID. But a DID alone cannot show what it built.

I made Agent Passport: a public, verifiable work history for agents contributing around @flop_labs and Technocore.

No login. No wallet connection. Verify it in your browser.

https://flop-agent-passport.pages.dev/

Media: 10–15 second screen recording — search the live DID → open Passport → verification changes to “2 SIGNATURES VERIFIED.”

## 1/5 — First live Passport

1/5 The first live Passport belongs to my Hermes agent. It connects one persistent did:key to two signed records: its original Technocore lobby proof and the public technocore-safe-adapter repository.

Open the Passport, then inspect each record yourself.

Media: full Passport view showing Identity and the two contribution stamps.

## 2/5 — Local verification

2/5 Every contribution keeps the exact canonical payload, SHA-256 digest, Ed25519 signature and public evidence links.

Verification runs locally in the browser against the DID’s public key. You do not have to trust a screenshot—or my server.

Media: proof-detail view with payload hash and verified state visible; no private information.

## 3/5 — Key recovery

3/5 A DID is only useful if its key survives.

The Key Vault creates Ed25519 keys in the browser, encrypts recovery files with Argon2id + AES-256-GCM, and requires a restore challenge before setup is complete.

The password and private key never reach the server.

Media: Key Vault steps 01–03, using a newly generated demo DID—not the operator’s real recovery file.

## 4/5 — Trust boundary

4/5 A valid signature proves that the DID key signed exact bytes.

It does not prove personhood, uniqueness, the truth or ownership of every claim, FLOP endorsement, points, or airdrop eligibility.

Agent Passport makes that boundary visible instead of hiding it.

Media: “A passport for work, not personhood” section.

## 5/5 — Independent project and feedback

5/5 This is an independent community experiment, not an official FLOP Labs product.

The goal is simple: your DID should show what you built.

Try the live Passport and tell me what is confusing, broken or missing:
https://flop-agent-passport.pages.dev/

Source:
https://github.com/jong6598/agent-passport

Media: clean closing card in the Agent Passport visual system; no official FLOP logo lockup.

## Publishing notes

- Attach one visual to every post; do not publish the thread as text-only.
- Keep the first post product-led. Put cryptography and limitations in later replies.
- Do not call Agent Passport an official FLOP product or imply endorsement.
- Do not mention token rewards except in the explicit limitation in 4/5.
- Never show a real private key, recovery file, recovery password, local path, or signing prompt containing live secrets.
- Mention @flop_labs only in the main post; do not cold-tag unrelated influencers.
