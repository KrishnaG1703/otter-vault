# Security status

## Current classification

**Not independently audited. The extension's source is public so anyone can review it.**

The extension uses authenticated encryption and strict origin binding, and is tested in-house as described below. There is no independent audit; instead the extension's source is public for review, and confirmed reports are fixed and credited. See `THREAT_MODEL.md` for what it defends against and what it does not.

## Implemented controls

- AES-256-GCM authenticated encryption
- random 96-bit IV for every encrypted secret
- one PBKDF2-SHA-256 run with a random 128-bit salt and 600,000 iterations, split into encryption and HMAC index keys with HKDF-SHA-256
- passphrase is never persisted
- while unlocked, the 256-bit master secret is held in service-worker memory and `chrome.storage.session` (in-memory, cleared on browser exit, trusted extension contexts only); working keys are non-extractable
- credential payloads are encrypted, including labels, usernames, origins, timestamps, kinds, and secrets; stable outer record IDs remain visible
- exact origins are looked up through a passphrase-derived HMAC index rather than stored as plaintext
- the HMAC origin index is authenticated as AES-GCM additional data
- inactivity locking provides an upper bound of the chosen auto-lock time (5, 15, or 30 minutes; default 5) after approved save/fill/remove or popup interaction; DOM-driven match probes do not extend it
- a service-worker restart restores the session only before its stored deadline, never extends it, and re-verifies the secret against the vault verifier
- the trusted origin comes from the active top-frame sending document (`sender.url`, checked against `sender.origin` when present), never `sender.tab.url` or a content-script message value
- the personal vault makes no network requests; only the optional Teams feature talks to one server (`otter-teams.mechaclips.workers.dev`), and only from the service worker
- no analytics or telemetry
- clipboard use only when the user clicks Copy in the popup and re-enters the passphrase; the clipboard is cleared after 5 minutes (API keys) or 1 minute (passwords) if it still holds that secret
- explicit user action before save or fill
- fill is refused on plain `http:` origins other than localhost
- the page cannot disable the content script by pre-creating DOM elements, and the companion UI is attached only when a secret field or key reveal is detected
- shadow DOM isolates the injected companion interface from page styling

## Teams controls (optional feature)

See the "Otter Vault Teams" section of `THREAT_MODEL.md` for the adversaries these answer.

- shared records, team names and vault names are AES-256-GCM under a per-epoch team key; additional data binds each record to its team, vault, id, epoch and revision
- team keys reach each device as an ECIES wrap (ECDH P-256, HKDF-SHA-256 salted with the ephemeral key and bound to team, epoch and recipient, AES-256-GCM), signed by the wrapping device
- device identities are ECDSA and ECDH P-256 key pairs sealed under the personal vault's master secret (HKDF, AES-256-GCM)
- the member list is a hash-chained, signed history replayed by every client and by the server; only admins add, remove or re-role people, only the owner changes roles, and removals move to a new epoch
- adding a member or a device requires comparing a 96-bit fingerprint out of band; the client re-fetches the keys and refuses if the fingerprint changed
- removing a member or device re-keys the team and re-encrypts every record and name in one server transaction; writes under the old epoch are refused
- every write that depends on an earlier read (revision, epoch, log head) is guarded so a concurrent change aborts it instead of being overwritten
- the access log is signed per event and hash-chained; clients pin the last verified head and the highest record revisions, and refuse rollbacks or trimmed logs
- sign-in is Google only; the ID token's nonce is a hash of the registering device's keys, so a stolen token cannot register another device; sessions are bound to one device, last 30 days, and are stored only as a hash
- owners and admins need a two-step code (RFC 6238, single use, five misses lock it for 15 minutes) before admin actions; the secret is encrypted with a Worker secret
- the recovery kit's private keys are sealed under a 256-bit printed code the server never sees; use needs the admin's Google account and two-step code and a 24-hour hold visible to every admin; a used kit is spent
- Teams requests are accepted only from the Teams extension page and, for Copy, the popup; never from web pages
- the server's CORS headers answer only Chrome extension origins; requests carry a bearer token and no cookies
- the QR code for two-step setup is drawn locally by a vendored, unmodified MIT library (`extension/vendor/`); no remote code

## Security testing (internal)

This is internal testing by the development team, not an independent audit.

- **Cryptographic known-answer tests** (`test/crypto-kat.test.js`): PBKDF2 against the RFC 7914 vector and Node's OpenSSL implementation at 600,000 iterations; HKDF labels, AES-GCM with origin AAD, and the HMAC origin index decrypted or recomputed independently in Node; no IV reuse across 200 records.
- **Fuzzing** (`test/fuzz.test.js`): seeded, thousands of malformed, oversized, mistyped and forged messages from random senders per run. Invariants: every request gets a well-formed response, no secret is returned except a legitimate exact-origin fill or a passphrase-confirmed popup copy, pages never reach popup-only operations, and stored records and key material are unchanged. CI adds a fresh random seed with 20,000 rounds on every push.
- **Static analysis**: Semgrep (`p/javascript`, `p/xss`, `p/secrets`, `p/default`) reports no findings on `extension/` as of 0.5.9, and runs in CI.
- **Background worker attacks** (`test/attacks.test.js`, run with `npm test`): swapped, bit-flipped, truncated and re-indexed encrypted records; lookalike, subdomain, userinfo (`bank.example@evil.test`), port, scheme and punycode origins; forged sender origins, subframes, prerendered documents, other extensions and popup-only requests from pages; prototype-pollution and oversized payloads; wrong passphrases; weakened KDF settings; locked-vault probing; plaintext at rest. All fail closed with no secret, metadata or unlocked session returned.
- **Content-script attacks in real Chrome** (`security/browser-attacks/`): synthetic clicks, clickjacking decoys layered above the prompt, a near-transparent page, pop-under double clicks, page access to extension APIs, and pages tampering with DOM APIs or the load guard.
- **Provider key reveals in real Chrome** (`security/provider-lab/`): OpenAI, Anthropic, Google AI Studio, AWS IAM, Stripe, GitHub, Hugging Face, Vercel, Cloudflare and Supabase stand-in pages on their real hostnames. Each key must be caught, saved, filled back exactly on the same origin and refused on a lookalike domain; decoy tokens must not trigger a prompt. This found that AWS access key IDs were saved instead of the secret access key (fixed in 0.5.4), and in 0.5.7 that Vercel's 24-character tokens and Supabase access tokens were missed, Supabase's publishable key was saved instead of the secret key beside it, and fields labelled "API token" were not offered a fill (all fixed).
- **Teams** (`test/team-crypto.test.js`, `test/team-chain.test.js`, `test/team-requests.test.js`, `test/server/`): every Teams construction is opened or verified a second time with OpenSSL; a hostile server is played against the member chain (forged admins, splices from other teams, recovery-kit misuse, dropped or edited log events); the real Worker routes run on SQLite for sign-in, two-step, invites, re-keying, concurrent writes, read-only trials, device requests and recovery; and the client's pins are tested against a server that rolls keys back or trims the log. Each defence was checked by disabling it and confirming a test fails. Manual end-to-end runs use `wrangler dev` with two Chrome profiles.
- **Found and fixed:** clickjacking. A page could cover the save/fill prompt with a click-through decoy, or pop the prompt up under a click already in progress, and silently receive a filled password. Prompt actions now require a trusted click, a prompt that Chromium's IntersectionObserver v2 reports as unobstructed for at least 500 ms, and a second visibility check 160 ms after the click.

## Known gaps

- no Secure Enclave, TPM, or hardware security key integration
- no independent penetration test or cryptographic review, including of Teams and its server
- Teams: the server sees membership, timing and record sizes, holds the two-step secrets, and can withhold service; a brand-new device trusts the team history it is first given; there are no per-vault permissions (see `THREAT_MODEL.md`)

- PBKDF2 is used because WebCrypto does not provide Argon2id
- while unlocked, any code running in a trusted extension context can read the master secret from `chrome.storage.session`; this trades memory-only custody for sessions that survive worker restarts
- the personal vault has no cross-device sync or recovery; Teams syncs shared vaults only
- no compromised-browser or malicious-extension defense
- a filled value lives in the page's own input, so script running on that exact site (for example through an XSS bug on it) can read it; this is true of browser autofill in general
- the occlusion check relies on IntersectionObserver v2, which only Chromium ships; other browsers get the trusted-click and timing checks only
- the vault passphrase only has a 12-character minimum, with no strength estimation
- JavaScript cannot reliably wipe key material from memory after locking
- no lookalike-domain scoring beyond exact-origin matching
- no import/export, backups, rotation, or breach monitoring
- deleting a record does not guarantee physical erasure from browser storage media
- encrypted storage does not provide complete metadata secrecy: deterministic HMAC origin indexes leak origin equality/frequency; stable outer record IDs permit cross-snapshot correlation; array position/order and record count are visible; and ciphertext length leaks approximate payload length
- when several credentials of the same kind exist for one exact origin, this release fills the newest record by default rather than presenting an account picker

## Production security architecture

The production direction is a native companion that owns all key operations. The browser extension should receive short-lived capabilities and plaintext only for the exact approved origin. On macOS, the root key should be wrapped by a Secure Enclave key guarded by user presence. Equivalent TPM/passkey-backed designs are needed for Windows and Linux.

## Reporting a vulnerability

Email krishna091718@gmail.com with "otter vault security" in the subject. We aim to acknowledge within 3 days, fix confirmed issues before disclosing them, and credit reporters who want it.

Keep test credentials synthetic. Do not include real secrets in reports, screenshots, fixtures, or logs.
