# Otter Vault threat model

What Otter Vault protects, from whom, and where the protection stops. This is the document a reviewer should read first; `SECURITY.md` lists the controls and the testing behind each claim here.

Version 0.6.0, October 2026. Teams (optional, below) is new in this version.

## What Otter Vault is

A Chrome (MV3) extension that notices passwords and one-time API-key reveals on web pages, saves them to a vault encrypted on the user's device only when the user clicks, and gives a secret back in two ways: filling it on the exact origin it was saved from, or copying it from the extension popup after the passphrase is entered again.

The personal vault has no server, account, sync, telemetry or network access. **Teams** is an optional feature for sharing keys with a group: someone who turns it on signs in with Google and the extension talks to one server, `otter-teams.mechaclips.workers.dev`. Everything that server stores is encrypted or signed on the members' devices. Its threat model is the section "Otter Vault Teams" below; the rest of this document is about the personal vault.

## Assets

| asset | why it matters |
| --- | --- |
| saved secrets (passwords, API keys) | the thing users are trusting us with |
| secret metadata (site, label, username, time) | reveals which services a user has accounts on |
| vault passphrase | unlocks everything; never stored |
| master secret while unlocked | equivalent to the passphrase until the vault locks |

## Trust boundaries

```
 web page (untrusted)  ──DOM──▶  content script (isolated world)  ──runtime messages──▶  service worker (trusted)
                                                                                        │
 extension popup (trusted, user-driven)  ─────────────────────runtime messages────────┘
                                                                                        │
                                                            chrome.storage.local (ciphertext at rest)
                                                            chrome.storage.session (master secret while unlocked)
 offscreen document (trusted) ◀── clipboard wipe only
```

- **Web pages are hostile.** Any page, including a lookalike of a real site, may try to read secrets, trigger saves or fills, forge messages, or trick the user into clicking.
- **The content script is semi-trusted.** It runs in Chrome's isolated world, so page scripts cannot read its variables or call extension APIs, but everything it reports about the page (text, field values) is page-controlled data.
- **The service worker is the only place that decrypts.** It decides every request from Chrome-supplied sender metadata (`sender.url`, `origin`, `frameId`, `documentId`, `documentLifecycle`), never from values inside a message.
- **The popup is trusted** because only the user can open it and Chrome identifies it by its extension URL with no tab.

## Adversaries and what we defend against

| # | adversary | goal | defence | evidence |
| --- | --- | --- | --- | --- |
| A1 | malicious or lookalike website | get a saved secret filled into its page | fills require the saved origin to equal the sender's exact origin (scheme, host, port); no fill on plain http except loopback | `test/attacks.test.js` lookalike/subdomain/userinfo/port/scheme/punycode cases; provider lab lookalike checks |
| A2 | malicious page script | forge messages, spoof its origin, act as the popup, pollute prototypes | strict per-type message schemas; origin taken from Chrome sender data; popup-only types refused from tabs; top frame and active document required | `test/attacks.test.js`, `test/fuzz.test.js` (seeded, thousands of hostile messages per run) |
| A3 | clickjacking page | make the user click Save or Fill unknowingly | trusted clicks only; prompt must be unobstructed per IntersectionObserver v2 for 500 ms, re-checked 160 ms after the click | `security/browser-attacks/` in real Chrome |
| A4 | someone who copies the browser profile or disk | read secrets at rest | AES-256-GCM over the whole record (secret and metadata); key from PBKDF2-SHA256, 600,000 iterations, random 128-bit salt, split with HKDF; origin looked up through an HMAC index | `test/crypto-kat.test.js` cross-checks every primitive against Node/OpenSSL and RFC 7914; plaintext-at-rest test |
| A5 | attacker who tampers with stored data | swap, re-index or corrupt records to decrypt one site's secret for another, or weaken the KDF | origin index bound as AES-GCM additional data; record ID checked inside the ciphertext; stored KDF parameters must equal the built-in ones | tamper tests in `test/attacks.test.js` |
| A6 | person at an unlocked computer | lift keys from the popup | Copy re-derives from the passphrase; five wrong tries lock the vault; the popup never displays a full secret; auto-lock after 5, 15 or 30 minutes | `test/attacks.test.js` copy tests |
| A7 | other apps reading the clipboard later | pick up a copied secret | clipboard cleared after 5 minutes for API keys, 1 minute for passwords, only if it still holds that secret (compared by hash) | manual real-Chrome check; documented in `SECURITY.md` |
| A8 | a page trying to fingerprint the extension | detect that Otter is installed | no web-accessible resources; UI injected only once a secret field or reveal is found; art drawn from inline data onto a canvas | code review |

## Otter Vault Teams

Teams shares keys between the devices of a group of people. The design is in `docs/teams-phase1.md`; this is what it protects and from whom.

### Additional assets

| asset | why it matters |
| --- | --- |
| shared secrets and their key map (project, environment, where deployed) | a team's production credentials and a map of where they live |
| team key (one per epoch) | decrypts every shared record and the team and vault names |
| device identity keys (ECDSA and ECDH P-256) | sign team history and receive the team key; sealed under the personal vault's master secret |
| the member list and access log | who is on the team and who used which key; both must be impossible to rewrite quietly |
| the recovery code | together with an admin's Google account and two-step code, restores that admin's access |

### What the server sees

The server (a Cloudflare Worker with a D1 database) stores: email addresses and Google account ids; device public keys; the signed member chain; team-key wraps (one per device, encrypted to that device); encrypted records, team and vault names; signed access-log events; invites; the recovery kit sealed under its code; and the two-step secret, encrypted with a server-held key. It learns team size, membership, which opaque record id was touched by which device and when, and approximate record sizes. It never receives a secret, a label, a site, a key-map field, a team or vault name, the vault passphrase or the recovery code.

### Adversaries

| # | adversary | goal | defence | evidence |
| --- | --- | --- | --- | --- |
| T1 | someone who breaches the server or its database | read shared secrets or their metadata | records, names and the key map are AES-256-GCM under a team key the server never holds; team keys are wrapped to device ECDH keys (ECIES with HKDF bound to team, epoch and recipient) | `test/team-crypto.test.js` cross-checks every construction with OpenSSL |
| T2 | a malicious or compromised server | add an attacker as a member, or hand a device a key it made up | the member list is a hash-chained list of entries signed by admin devices and replayed by every client against a pinned team anchor; key wraps must be signed by a device on the team; members and devices are added only after comparing a 96-bit fingerprint out of band, re-checked by the client before it signs | `test/team-chain.test.js`, `test/server/team-sync.test.js` |
| T3 | a malicious server | drop, reorder or edit access-log events; serve an old version of a key; move a record to another vault | events are signed and hash-chained and each device pins the last head it verified; records carry a signed revision and are bound to team, vault, record, epoch and revision as AES-GCM additional data; each device pins the highest revision it has seen | rollback and log-trimming tests in `test/server/team-sync.test.js` |
| T4 | a removed member or a lost device | read keys added or changed after removal | removal re-keys the team: a new team key for everyone left, every record and name re-encrypted in one transaction; the server refuses writes under the old epoch | `test/server/teams-server.test.js` |
| T5 | a removed member who copied keys before leaving | keep using them at the provider | no vault can prevent this; the offboarding report lists every key they could read, which ones they used through Otter, and where each is deployed, production first | `offboardingReports` tests |
| T6 | someone with a stolen session token | act as that person | a token is bound to one device, expires after 30 days, and cannot decrypt or sign anything; admin actions also need a two-step code passed in that session | `test/server/teams-server.test.js` |
| T7 | someone with an admin's Google account | run the team | admin actions need a two-step (TOTP) code: single use, five misses lock it for 15 minutes | two-step tests with RFC 6238 vectors |
| T8 | someone who steals a recovery kit | take over an admin's access | the kit only works with that admin's Google account and two-step code, after a 24-hour hold that every other admin sees and can cancel; the account's own remaining device can cancel it too; only a different admin can approve early; a used kit is spent; a kit can only add a device for an owner or admin and cannot sign anything else | recovery tests in `test/server/team-sync.test.js` and `test/team-chain.test.js` |
| T9 | a web page | reach Teams | Teams messages are accepted only from the Teams extension page (exact URL) and, for Copy, the popup; never from a tab | `test/team-requests.test.js` |

### Stated limits of Teams

- **Membership and timing are visible to the server.** It cannot read what a record is, but it sees who is on a team and which device touched which record id when.
- **The access log covers access through Otter only.** A member who has a key can still paste it elsewhere.
- **A server can refuse service or withhold new events.** Clients detect gaps and rollbacks against what they saw before, but a device that has never seen a team trusts the history it is given until a fingerprint comparison or another member's view says otherwise.
- **The fingerprint comparison is the trust anchor.** If an admin adds someone without comparing the code out of band, a malicious server could substitute keys at that moment.
- **The server knows the two-step secret.** It checks the codes, so it holds the secret, encrypted with a key that is also on the server. Two-step protects against a stolen Google login, not against a breached server, which still cannot read any shared key.
- **One team key per team.** Every member can read every shared key; there are no per-vault permissions yet.
- **Read-only after the trial** is enforced by the server, not by cryptography.

## Out of scope: what Otter Vault does not defend against

These are stated so nobody assumes otherwise.

- **A compromised browser, OS or device**, including malware, keyloggers, and other extensions with broad permissions.
- **Script running on the exact saved site** (for example an XSS bug on it). A filled value sits in that page's own input, as with any autofill.
- **A weak passphrase.** Only a 12-character minimum is enforced; PBKDF2 slows guessing but cannot save a guessable passphrase.
- **Phishing that uses the real origin**, such as a compromised account page on the genuine domain.
- **Memory forensics while unlocked.** The master secret lives in the service worker and `chrome.storage.session` until lock; JavaScript cannot guarantee memory is wiped.
- **Metadata inference from storage shape**: record count, order, approximate payload length, and equality of origins through the deterministic HMAC index.
- **Browsers without IntersectionObserver v2**, where the clickjacking defence falls back to trusted-click and timing checks only.
- **Loss of the passphrase.** There is no recovery by design.

## Assumptions

- Chrome's extension isolation, sender metadata and WebCrypto implementation are correct.
- The user installed the genuine extension and reads the prompt before clicking.
- The device is not already compromised.

## Verification

| layer | how | when |
| --- | --- | --- |
| unit, integration and attack tests | `npm test` | every commit (CI) |
| cryptographic known-answer tests | `test/crypto-kat.test.js` | every commit (CI) |
| fuzzing | `test/fuzz.test.js`, fixed seed plus a random seed in CI (`FUZZ_SEED`, `FUZZ_ROUNDS`) | every commit (CI) |
| static analysis | Semgrep (`p/javascript`, `p/xss`, `p/secrets`) | every commit (CI) |
| real-browser attack page | `security/browser-attacks/` | before each release |
| provider detection | `security/provider-lab/`, 10 providers and decoys | weekly (CI) and before each release |
| live provider consoles | manual checklist in `docs/live-checks.md` | before each release |
| Teams cryptography (OpenSSL cross-checks) | `test/team-crypto.test.js` | every commit (CI) |
| Teams history: forged members, splices, recovery misuse, log tampering | `test/team-chain.test.js` | every commit (CI) |
| Teams server routes, sign-in, two-step, recovery, re-key, client pins | `test/server/` (real routes on SQLite), plus manual runs under `wrangler dev` with two browser profiles | every commit (CI) and before each release |
| independent audit | none | the extension's source is public for anyone to review |

## Reporting a vulnerability

Email krishna091718@gmail.com with "otter vault security" in the subject. Please use synthetic credentials only. We aim to acknowledge within 3 days and will credit reporters who want it.
