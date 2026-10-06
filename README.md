# Otter Vault

Otter Vault is a Chrome extension that catches API keys the moment a site shows them once, keeps them in an encrypted vault on your device, and fills passwords only on the exact site they were saved for. **Otter Teams**, the optional paid tier, shares keys with your team end to end encrypted: each key records where it is deployed, and when someone leaves, Otter re-keys the team and lists what to rotate.

- Install: [Chrome Web Store](https://chromewebstore.google.com/detail/otter-vault/lmoadcfiocdehnbdppfhimonghalcmgl)
- Website: [ottervault.mechaclips.workers.dev](https://ottervault.mechaclips.workers.dev)
- How Teams protects your keys: [security page](https://ottervault.mechaclips.workers.dev/security)

## Why the code is public

Teams asks you to trust a server with your team's production keys. You shouldn't have to take our word that the server can't read them. Everything that encrypts, signs and checks happens in this extension, so this code is all you need to verify that claim. The Teams server isn't published: the design treats it as untrusted, so the guarantees don't depend on it.

## Verify it yourself

| Claim | Where to look |
| --- | --- |
| The personal vault is encrypted with AES-256-GCM under a key derived from your passphrase (PBKDF2-SHA-256, 600,000 rounds), and makes no network requests | `extension/lib/crypto-vault.js`, `extension/background.js` |
| Shared keys, their labels, sites and key map are encrypted on your device; the server only ever gets ciphertext | `extension/lib/team-crypto.js` (records, names, key wraps), `extension/lib/team-sync.js` (what is sent) |
| The team key is wrapped to each device separately (ECDH P-256, HKDF-SHA-256, AES-256-GCM) and every wrap is signed | `extension/lib/team-crypto.js`, `extension/lib/team-chain.js` (`signWrap`, `verifyWrap`) |
| A server can't add a member, splice in history or roll back a key without the client noticing | `extension/lib/team-chain.js` (`verifyMemberChain`, `verifyEvents`), the pins in `extension/lib/team-sync.js` |
| Removing someone re-keys the team | `rotateOut` in `extension/lib/team-sync.js` |
| Web pages can't talk to Teams, and saved secrets fill only on the exact origin | `extension/lib/request-security.js`, `extension/content/content.js` |
| Each construction is checked against OpenSSL and known-answer vectors | `test/team-crypto.test.js`, `test/crypto-kat.test.js` |

The threat model, including what Otter does **not** defend against, is in [THREAT_MODEL.md](THREAT_MODEL.md). The controls and the testing behind them are in [SECURITY.md](SECURITY.md), and the Teams design in [docs/teams-phase1.md](docs/teams-phase1.md). Some evidence links there point at `test/server/`, the server's own test suite, which is kept with the private server code.

## Run the tests and build

You need Node.js 22 or newer. No dependencies to install.

```bash
npm test
```

```bash
npm run package
```

The second command writes `dist/otter-vault-<version>.zip`, the same package that goes to the Chrome Web Store. To try the extension, open `chrome://extensions`, turn on Developer mode, choose **Load unpacked** and pick the `extension` folder.

`security/` has the real-browser checks: a hostile page that tries to clickjack or trick the prompt, and a provider lab that runs stand-in key pages for ten providers plus lookalike decoys.

## Report a vulnerability

Email krishna091718@gmail.com with "otter vault security" in the subject, and use made-up credentials only. We acknowledge reports within three days and credit you if you'd like. Otter has not had an independent security audit; this public source is how it can be reviewed.

## License

[Functional Source License 1.1, Apache 2.0 future license](LICENSE.md) (FSL-1.1-ALv2). You may read, run, modify and share this code for any purpose except offering a product or service that competes with Otter Vault. Each version becomes available under the Apache License 2.0 two years after it's released.

This is source-available, not open source under the OSI definition, until each version converts to Apache 2.0.

Copyright 2026 Krishna Ganga.
