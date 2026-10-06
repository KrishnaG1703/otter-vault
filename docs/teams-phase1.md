# Otter Vault Teams: Phase 1 design

Status: draft, October 2026. Scope: shared vaults for teams of up to 10 developers, a key map that records where every key is used, a team access log, and an offboarding report. Billing, the repo scanner (`otter scan`) and provider integrations are Phase 2 and later.

## Goals

1. A team can share API keys and passwords in one or more shared vaults, end to end encrypted. The server never sees a secret, a label, a site or any key-map field.
2. Every shared key carries a **key map**: project, environment, where it is deployed, owner, rotation date.
3. Every reveal, copy, fill, edit and delete made through Otter is recorded in a **team access log** that the server cannot silently rewrite.
4. Removing a member re-keys the vault and produces an **offboarding report**: which keys they could read, which they actually used, and what to rotate first.
5. The personal vault stays exactly as it is today: local only, no account, no network. Teams is opt-in.

## Non-goals for Phase 1

- Stripe billing (Phase 2). Phase 1 already records who pays and when the trial ends (see Plans and trial), so billing only has to switch enforcement on.
- Repo scanning, Vercel/GitHub/AWS integrations, SSO, SCIM.
- Cloud recovery from a passphrase. A second device is added by approval from an existing device (see Devices), and lost admins recover with a recovery kit (see Recovery kit). There is no server-held, passphrase-protected backup, because that would give anyone who breaches the server an offline guessing target.
- A web dashboard. The team UI is an extension page (`extension/team/team.html`) opened in a tab, because only the extension holds the keys. A web page could not decrypt anything without shipping keys to the browser origin.

## What changes in the threat model

Today `THREAT_MODEL.md` says there is "no server, account, sync, telemetry or network access". Teams changes that for users who turn it on, so the threat model gets a new section before any Teams code ships.

New adversaries:

| # | adversary | goal | defence (details below) |
| --- | --- | --- | --- |
| T1 | someone who breaches the server or database | read secrets or key-map metadata | everything sensitive is encrypted on the client with keys the server never holds |
| T2 | a malicious or compromised server | add itself (or an attacker) as a member and receive the team key | the member list is a chain of admin-signed entries; clients refuse key wraps for anyone not on a chain they verified, and new members are confirmed by fingerprint |
| T3 | a malicious server | hide or reorder access-log events, roll records back to an old version, or swap records between vaults | events are signed and hash-chained per team; records carry a signed revision and are bound to team, vault, record and epoch as AES-GCM additional data |
| T4 | a removed member | keep reading new or changed secrets | removal rotates the team key (new epoch) and re-encrypts every record; the server refuses writes under an old epoch |
| T5 | a removed member who already copied secrets | keep using keys they saw before removal | cannot be prevented by any vault. The offboarding report lists those keys so they get rotated at the provider |
| T6 | a member's stolen session token | act as that member against the server | the token alone cannot decrypt anything or sign events; it only allows fetching ciphertext. Tokens expire after 30 days and are bound to a device |
| T7 | someone who steals a recovery kit | take over an admin's access | the kit also needs the admin's email and TOTP; a 24-hour hold with emails to every other admin; a new kit revokes the old one |

Stated limits, to be added to the out-of-scope list:

- The access log records access through Otter only. A member who has a key can still paste it anywhere.
- The server learns metadata: team size, member emails, which (opaque) record IDs exist, record sizes, and who touched which record ID when. It does not learn what any record is.
- A malicious server can refuse service or withhold events. Clients detect gaps in the event chain and show a warning; they cannot force the server to deliver.

## Identity and accounts

- **Account**: email plus a 6-digit code sent by email (Resend for delivery), typed into the extension popup or the Mac app. A code rather than a magic link, because a link opens a browser tab and would have to find its way back into the extension or the Mac app. No server password, so there is no second secret to manage and nothing for the server to verify that is related to the vault passphrase. Codes last 10 minutes, five wrong tries burn a code, and an address gets at most five codes an hour.
- **Email domain**: Resend only sends from a domain you own and have verified, so going live needs a domain (workers.dev cannot be one). Until then the Worker runs with `MAIL_MODE = "log"`, which prints codes to the `wrangler dev` console and refuses to run over https.
- **Two-factor for admins**: owners and admins must set up TOTP (any authenticator app) before their admin role takes effect. Sign-in for them is the email code plus a TOTP code. Members can opt in. The TOTP secret is stored server-side (encrypted with a Worker secret) because the server is the one checking it; it protects the account, not the vault.
- **Session token**: random 256-bit token returned after the code is checked; only its SHA-256 is stored, bound to one device ID, stored in `chrome.storage.local` (it unlocks nothing cryptographic), expires after 30 days.
- **Device identity keys**, generated on the device when Teams is turned on:
  - `kx`: ECDH P-256 key pair for receiving wrapped team keys.
  - `sig`: ECDSA P-256 key pair for signing events, membership entries and record revisions.
  - P-256 rather than X25519 because WebCrypto supports it on every Chrome version the extension targets (`minimum_chrome_version` 109), Node/OpenSSL can cross-check it in `test/crypto-kat.test.js`, and CryptoKit has `P256`.
  - The private keys are stored in `chrome.storage.local`, encrypted with a key derived from the existing master secret: `HKDF(master, info = "otter-identity-v1")` with AES-256-GCM. So they are as safe at rest as the personal vault and unlock with the same passphrase.
- **Fingerprint**: `SHA-256(sig public key || kx public key)`, shown as 6 groups of 4 hex characters. Used when an admin confirms a new member.

## Teams, members and the signed member list

Roles: `owner` (one per team, the person who created it and who pays), `admin` (invite, remove, rotate, manage the recovery kit), `member` (read and write records in the team's vaults). Plus one non-person identity, `recovery`, described under Recovery kit.

The member list is an append-only chain of **membership entries**:

```json
{
  "teamId": "t_…",
  "seq": 7,
  "prev": "<sha-256 of entry 6>",
  "op": "add" | "remove" | "set-role" | "add-device" | "remove-device" | "add-recovery" | "remove-recovery" | "recover",
  "subject": { "userId": "u_…", "deviceId": "d_…", "sigPub": "…", "kxPub": "…", "role": "member" },
  "epoch": 3,
  "at": "2026-10-03T10:00:00Z",
  "by": "d_<admin device>",
  "signature": "<ECDSA P-256 over the canonical JSON without signature>"
}
```

- Entry 0 is the team creation, signed by the owner's device; its hash is the **team anchor**. Each client pins the anchor the first time it joins.
- Every client replays the whole chain on load: each entry must be signed by a device that was an admin at that point, `seq` must be contiguous and `prev` must match. Anything else fails closed with a "team history doesn't check out" error.
- Only the owner changes roles, and there is never a second owner. Adding a member or a device keeps the epoch; `remove` and `remove-device` must move to exactly the next epoch; `remove-recovery` may do either, so an admin who suspects a leaked kit can re-key at the same time.
- Device, user and recovery IDs are never reused within a team.
- A client only wraps the team key for devices present in its verified chain. That is what stops a malicious server from inserting a member (T2).

## Invites

1. Admin creates an invite in the team page: email and role. The server stores a random invite ID and emails a link.
2. The invitee signs in, turns on Teams (generating device keys if needed) and accepts. Their public keys go to the server, attached to the invite.
3. The admin's team page shows the pending member with their fingerprint and asks the admin to compare it with the invitee over a separate channel (in person, Slack, a call). The invitee sees their own fingerprint on screen.
4. On confirmation the admin's client appends an `add` entry, wraps the current team key for the new device, and uploads both.

Step 3 is what makes the server untrusted. For small teams a short comparison is acceptable; Phase 2 can add QR-code confirmation.

## Devices

- A member's second device generates its own keys and asks to be added. Any existing device of the same member (or an admin) approves it after a fingerprint comparison, which appends `add-device` and wraps the team key to it.
- A lost device is removed by the member or an admin with `remove-device`, which triggers a re-key exactly like removing a member.
- A **member** who loses every device is re-added by an admin: they turn on Teams on a new device and the admin approves it with a fingerprint comparison, like an invite. No recovery kit is involved.

## Recovery kit

For the case where an admin, or the whole team, loses every device. The server must never be able to produce a recovery key itself, or "end to end encrypted" stops being true. So the kit is generated on an admin's device, the secret part only ever exists on paper or in the admin's own storage, and the server only holds an encrypted blob it cannot open.

**Creating a kit** (owner or admin, from the team page; the team page asks for one when the team is created and nags until it exists):

1. The client generates a random 256-bit **recovery secret** and shows it as a code of 52 base32 characters in groups of 4, plus a printable PDF ("Otter Vault recovery kit for Acme, created 3 Oct 2026 by Krishna"). The admin confirms by retyping the last group.
2. The client generates a fresh recovery identity: `kx` and `sig` P-256 key pairs, like a device.
3. The private keys are encrypted with `HKDF(recovery secret, info = "otter-recovery-v1|" + teamId)` and AES-256-GCM, and the resulting blob is uploaded. Because the secret is 256 random bits rather than a passphrase, a server breach gives nothing to guess.
4. The admin's client appends an `add-recovery` entry to the member chain with the recovery public keys, and wraps the current team key for the recovery identity. Every later re-key also wraps for it automatically.
5. Only one kit is active per team. Creating a new one appends `remove-recovery` for the old one in the same batch, so a lost or leaked kit is revoked by making a new one.

**What a kit can do**: the recovery identity's only permission in the chain is signing a `recover` entry that adds one new device for an existing owner or admin. It cannot invite, remove, change roles or write records. Clients enforce this when replaying the chain.

**Using a kit**, when an admin has lost every device:

1. Sign in on a new device with an email code plus TOTP. TOTP is required here even if the admin's authenticator was the thing lost; losing both means another admin, or Otter support with identity checks, resets TOTP first.
2. Request recovery. The server starts a **24-hour hold** and emails every other admin with a "this wasn't us, cancel" link. If another admin approves from the team page, the hold ends immediately. For a team with a single admin the hold always runs its full 24 hours.
3. After the hold, the server releases the encrypted blob. The admin types the recovery code, the client decrypts the recovery keys, unwraps the team key, and signs a `recover` entry adding the new device. It then wraps the team key for that device.
4. The used kit is spent: the client immediately makes the admin create a new kit, which revokes the old one.
5. A `recover` event goes into the access log, and all members see "Krishna's access was restored with the recovery kit" on the team page.

Someone who has the kit, the admin's email and their authenticator can take over that admin's access. The 24-hour hold and the emails to other admins are there so the real team notices first.

## Team keys and epochs

- Each team has a random 256-bit **team key** per **epoch**. Epoch 1 is created with the team; each removal of a member or device creates a new epoch.
- One team key per team, shared by all its vaults: everyone on the team can read every shared key. Decided for launch, since teams of 3–10 usually share everything. Per-vault keys (so a member can be in "frontend" but not "payments") can come later if customers ask; the record format already carries `vaultId` so that can be added without migrating records.
- **Key wrap** for each device (ECIES pattern, all WebCrypto):
  1. Generate an ephemeral ECDH P-256 key pair.
  2. `shared = ECDH(ephemeral private, device kxPub)`.
  3. `wrapKey = HKDF-SHA-256(shared, salt = ephemeral public key, info = "otter-team-wrap-v1|" + teamId + "|" + epoch + "|" + deviceId)`.
  4. `AES-256-GCM(wrapKey, teamKey)` with the same info string as additional data.
  5. Upload `{ deviceId, epoch, ephemeralPub, iv, ciphertext, by, signature }`, signed by the wrapping admin's device.
- A client accepts a wrap only if the signer was an admin in the verified chain at that epoch.

## Records

Shared records reuse the payload of today's personal records (`id`, `kind`, `label`, `origin`, `username`, `secret`, `createdAt`) and add the key map and history fields:

```json
{
  "id": "r_…",
  "kind": "api-key" | "login",
  "label": "Stripe live secret",
  "origin": "https://dashboard.stripe.com",
  "username": "",
  "secret": "sk_live_…",
  "createdAt": "…",
  "map": {
    "project": "checkout-api",
    "environment": "prod" | "staging" | "dev" | "other",
    "locations": [
      { "type": "vercel-env", "name": "STRIPE_SECRET_KEY", "ref": "checkout-api" },
      { "type": "github-actions", "name": "STRIPE_SECRET_KEY", "ref": "acme/checkout" }
    ],
    "owner": "u_…",
    "rotateEveryDays": 90,
    "lastRotatedAt": "…",
    "notes": ""
  },
  "updatedAt": "…",
  "updatedBy": "d_…"
}
```

- Location `type` is one of `vercel-env`, `github-actions`, `aws-ssm`, `aws-secrets-manager`, `gcp-secret-manager`, `cloudflare-secret`, `env-file`, `other`. Phase 2's scanner and integrations fill these in automatically; in Phase 1 they are typed in when a key is saved or edited.
- **Encryption**: the whole payload is AES-256-GCM under the team key of the current epoch. Additional data is `"otter-team-record-v1|" + teamId + "|" + vaultId + "|" + recordId + "|" + epoch + "|" + revision`. This binds a ciphertext to its place, so the server cannot swap records between vaults or replay an old epoch's copy (T3).
- **What the server stores** per record: `teamId`, `vaultId`, `recordId`, `epoch`, `revision`, ciphertext, `updatedBy` device, a signature by that device over the hash of all of the above, and `updatedAt`. No origin index: shared vaults are small (hundreds of records at most), so clients decrypt the whole vault into memory after unlock and match origins locally. That leaks less than the HMAC index the personal vault uses.
- **Revisions**: each write increments `revision`. Clients remember the highest revision they have seen per record and refuse a lower one (rollback, T3). Conflicting writes from two members are resolved by the server accepting only `revision = current + 1`; the losing client refetches and shows "Rahul changed this a moment ago".
- **Fill and copy** work exactly as for personal records: exact-origin fill, copy only after the passphrase is entered again, clipboard wiping. Shared records appear in the popup with a small team badge.

## Access log

Every reveal-like action through Otter produces an **event**:

```json
{
  "teamId": "t_…",
  "seq": 1042,
  "prev": "<sha-256 of event 1041>",
  "action": "create" | "edit" | "delete" | "copy" | "fill" | "view-hint" | "rotate-mark",
  "recordId": "r_…",
  "device": "d_…",
  "chainSeq": 12,
  "at": "…",
  "signature": "…"
}
```

- `chainSeq` is the member-chain position the device acted under. It may never go backwards through the log and the device must have been on the team at that position, so a removed member cannot backdate events to before their removal.
- Events are signed by the acting device and hash-chained per team. The server assigns `seq` and `prev`; the client signs after receiving them, so ordering conflicts are resolved server-side but tampering is still detectable.
- Clients verify the chain when the team page loads and show the log as plain sentences ("Rahul copied Stripe live secret · 2 days ago"). A broken chain or a gap shows a red "the access log has a gap after event 1041" banner instead of quietly showing partial history.
- The server sees which device acted on which opaque record ID and when. It does not see record names.
- If an event cannot be sent (offline), the action still happens and the event is queued in `chrome.storage.local` and sent on reconnect, with its original timestamp. Phase 1 does not block copy on the network, because a vault that won't open offline is worse than a late log entry. This is stated in the UI.

## Removing a member and the offboarding report

Removal, run by an admin's client:

1. Append a `remove` entry to the member chain.
2. Generate the team key for epoch N+1 and wrap it for every remaining device.
3. Decrypt every record under epoch N and re-encrypt it under N+1 with `revision + 1`.
4. Upload all of it as one batch. The server switches the team to epoch N+1 atomically and refuses later writes under epoch N.

For 10 members and a few hundred records this takes a few seconds in the browser. A progress bar is shown, and if the batch fails nothing changes.

The **offboarding report** is built from data the admin's client already has after decrypting:

- **Could read**: every record that existed under any epoch the person held a wrap for.
- **Did use**: the subset with a `copy`, `fill` or `create` event from any of their devices.
- **Sort order**: environment (`prod` first), then whether they used it, then key type.
- Each row shows where the key is deployed (from the key map) so whoever rotates knows where to paste the new value, plus a "Mark rotated" button that writes a `rotate-mark` event and updates `lastRotatedAt`.
- It can be exported as a Markdown checklist.

## Rotation reminders

- `rotateEveryDays` defaults to 90 for `api-key` and is off for `login`.
- The team page shows amber at 14 days before due and red when overdue. The popup shows a count. No email or push in Phase 1, because the server doesn't know which records are due (it can't read `map`).

## Plans and trial

- **The owner pays, everyone else uses it.** The person who creates the team is the owner and the only billing contact. Invited members never see a payment screen and never need their own plan.
- **Price**: Team is $29/month flat for up to 10 members ($290/year). Personal stays free.
- **Early-bird**: teams that subscribe early pay $20/month instead of $29 (shown on the landing page and the Teams page).
- **Free trial**: every new team gets 21 days free with full features and no card. The team page shows the days left from day 14.
- **After the trial**, if the owner hasn't paid, the team goes **read-only** instead of locked. Members can still open, fill and copy every shared key, and admins can still remove members and re-key, so nobody is cut off from their own secrets. Adding or editing keys, inviting and creating vaults are blocked until the owner pays. Read-only lasts until the owner pays or deletes the team.
- **Phase 1** stores `trial_ends_at` and `read_only_since` and enforces read-only. Taking payments (Stripe) is Phase 2, so until then the trial can be extended by hand for early teams.

## Mac app

The Mac menu bar app (`mac/`, SwiftPM) is a full Teams client in Phase 1, not an afterthought: the server is the sync channel, so a key saved from Chrome shows up in the Mac app and the other way round.

- `OtterCore` gains `TeamCrypto.swift` and `TeamChain.swift`, ports of the two JavaScript modules using CryptoKit (`P256.Signing`, `P256.KeyAgreement`, `HKDF<SHA256>`, `AES.GCM`). Same formats, same canonical JSON, same error codes.
- **Shared test vectors**: a script exports fixtures from the JavaScript side (identities, wraps, records, a member chain with good and doctored entries, an access log) into `mac/Tests/OtterCoreTests/Fixtures/teams/`. Swift tests must open, verify and reject exactly what JavaScript does, and Swift-made values are checked by the JavaScript tests the other way.
- The Mac app registers as its own device with its own keys. Linking it to an existing member is the normal `add-device` flow with a fingerprint comparison.
- **Personal vault sync** between Chrome and the Mac (the Pro plan) reuses the same machinery as a one-person team, so it needs no separate protocol.

## Server

Code: `server/` in this repo. Cloudflare Worker `otter-teams` at `https://otter-teams.mechaclips.workers.dev` (a custom domain can come later; workers.dev also avoids the LinkedIn block on pages.dev links), D1 for storage, Resend for email. Same stack as the rice API.

Tables:

| table | columns |
| --- | --- |
| `users` | id, email, totp_secret_enc, totp_enabled_at, created_at |
| `devices` | id, user_id, sig_pub, kx_pub, created_at, revoked_at |
| `sessions` | token_hash, device_id, expires_at |
| `email_codes` | email, code_hash (HMAC), expires_at, attempts, window_start, sent_in_window |
| `teams` | id, name_ciphertext, owner_user_id, epoch, plan, trial_ends_at, read_only_since, created_at |
| `recovery_kits` | team_id, id, blob_ciphertext, created_by, created_at, revoked_at |
| `recovery_requests` | id, team_id, user_id, new_device_id, hold_until, approved_by, cancelled_by, completed_at |
| `member_entries` | team_id, seq, body_json, signature |
| `invites` | id, team_id, email, role, device_id (after accept), expires_at, status |
| `vaults` | id, team_id, name_ciphertext, created_at |
| `key_wraps` | team_id, epoch, device_id, body_json, signature |
| `records` | team_id, vault_id, id, epoch, revision, ciphertext, updated_by, signature, updated_at, deleted |
| `events` | team_id, seq, prev, body_json, signature |

Team and vault names are encrypted under the team key, so the server doesn't learn them either.

API (JSON, bearer session token, all writes checked against membership and epoch). The route list at the top of `server/src/teams.js` is the reference:

```
POST /auth/email-code   POST /auth/verify   POST /auth/sign-out
POST /teams             GET  /teams         GET  /teams/:id/state
POST /teams/:id/entries                     POST /teams/:id/rotate
POST /teams/:id/vaults
GET  /teams/:id/records?since=<cursor>      PUT  /teams/:id/records/:rid
POST /teams/:id/invites GET /teams/:id/invites   DELETE /teams/:id/invites/:iid
GET  /invites           POST /invites/:iid/accept
POST /teams/:id/events  GET  /teams/:id/events?after=<seq>
```

Step 7 added:

```
GET  /auth/me                 POST /auth/totp/setup | enable | verify
GET  /teams/:id/access        POST /teams/:id/device-requests      DELETE /teams/:id/device-requests/:deviceId
PUT  /teams/:id/recovery-kit  POST /teams/:id/recovery-requests
POST /teams/:id/recovery-requests/:rid/approve | cancel
GET  /teams/:id/recovery-requests/:rid/kit                         POST /teams/:id/recovery-requests/:rid/complete
```

Two-step is required for admin actions only (inviting, vaults after the first, adding or removing people and other people's devices, the recovery kit, approving a recovery); members never need it. A recovery can be cancelled by any admin or by the account's own device that is still on the team, and approved only by a different admin. A device that is not on a team sees the team labelled by its owner's email, since the name is encrypted.

The server replays the member chain with the same `team-chain.js` the clients use, so it refuses bad history early; clients still verify everything themselves. Multi-statement writes are D1 batches (one transaction). A write that depends on what it read earlier (a record revision, the epoch, the access-log head) starts with a guard statement that aborts the batch if that changed in the meantime, so a re-key can never silently overwrite an edit that landed while it was being built.

Server rules that don't depend on trusting clients:

- A team has at most 10 active members on the Team plan.
- During read-only (see Plans and trial) the server refuses record writes, invites and new vaults, but still serves everything needed to read, fill, copy, remove members and re-key.
- Request bodies limited to 64 KB, except `/rotate` at 5 MB.
- Rate limits per session and per IP on auth routes.
- The server checks signatures it can check (device signed with its registered key) so junk is rejected early, but clients never rely on that check.

## Extension changes

- **Manifest**: add `host_permissions` for the Teams API origin only. This is the first network permission, so the Chrome Web Store listing, `PRIVACY.md`, the public `ottice-privacy` repo and the landing page all need updating in the same release. The content script never talks to the network; only the service worker does.
- **New popup-only message types**, refused from tabs exactly like today's popup-only types: `team-enable`, `team-state`, `team-create`, `team-invite`, `team-confirm-member`, `team-remove-member`, `team-save`, `team-edit`, `team-delete`, `team-copy`, `team-mark-rotated`, `team-report`. Each gets a strict schema in `lib/request-security.js` and fuzz coverage.
- **`fill` and `has-match`** also search decrypted team records for the sender's exact origin. The fill prompt names the team ("from Acme team vault").
- **New files**: `extension/lib/team-crypto.js` (identity keys, wrap and unwrap, record and event signing), `extension/lib/team-chain.js` (member and event chain verification), `extension/lib/team-sync.js` (API client, offline event queue), `extension/team/team.html|css|js` (team page: members, vaults, key map, access log, offboarding report).
- **Locking**: locking the vault also drops decrypted team keys and records from memory. Team state follows the same auto-lock timer.

## Testing

- `test/crypto-kat.test.js`: ECDH, ECDSA and the wrap construction checked against Node/OpenSSL, plus fixed vectors the Mac app will reuse in Phase 2.
- `test/team-attacks.test.js`, against a fake hostile server:
  - inserting an unsigned or wrongly signed member entry;
  - an entry signed by a non-admin, or by an admin who was removed;
  - a wrap for a device not in the chain;
  - a record moved to another vault or team, an old epoch's copy served, a lower revision served;
  - events dropped, reordered or edited;
  - writes under an old epoch after rotation.
  Every case must fail closed with a visible error.
  - a `recover` entry signed by a revoked kit, or one that adds a device for a plain member, or that tries anything other than adding a device.
- Recovery flow tests: hold not yet expired, request cancelled by another admin, wrong recovery code, kit reuse after it was spent.
- `test/fuzz.test.js` extended to the new message types.
- **Two-browser end-to-end test**: two Chrome for Testing profiles with a local Worker (`wrangler dev`). Create a team, invite, confirm fingerprint, share a key, fill it on the other profile, remove the member, check the report and that the removed profile can no longer decrypt new data.
- The provider lab keeps running unchanged against personal records and gains one shared-record fill case.

## Build order

1. `team-crypto.js` and `team-chain.js` with KAT and attack tests (no network).
2. Worker and D1 schema, auth, and the state and record routes, tested with `wrangler dev`.
3. `team-sync.js` and the new worker message types; in parallel, the Swift port and shared fixtures for the Mac app.
4. Team page: create team, invite and confirm, shared vault list, key map editor.
5. Access log and offboarding report.
6. Removal and re-key flow, then the two-browser end-to-end test.
7. TOTP for admins and the recovery kit (create, revoke, hold, recover).
8. Threat model, `SECURITY.md`, `PRIVACY.md` and store listing updates; landing page Teams section.

Status: steps 1–6 done (October 2026): crypto and chain, Worker, extension sync with Google sign-in, the Teams page (create, invite and confirm by fingerprint, vaults, key map editor, share from your own vault, activity), the offboarding report with Mark rotated and a Markdown checklist, and removing members or devices with a full re-key. Step 7 (two-step sign-in for admins, the recovery kit with its 24-hour hold, and new devices asking to join) is done too. Step 8 (docs and privacy) and the Mac app remain.

Estimate: about 5–6 weeks of focused work for one developer, including TOTP, the recovery kit and the Mac app.

## Decisions (3 Oct 2026)

- **API domain**: `otter-teams.mechaclips.workers.dev` for now (see Server).
- **Mac app**: a full Teams client in Phase 1 (see Mac app).
- **Sign-in**: 6-digit email codes instead of magic links.
- **Recovery**: admins create a recovery kit for the team; recovering needs the kit plus the admin's email and TOTP, with a 24-hour hold (see Recovery kit). Members who lose every device are re-added by an admin.
- **Access**: one key per team, so every member can read every shared key. The owner who creates the team pays; members use it at no cost to them.
- **Free tier**: no permanent free team plan. Every team gets a 21-day free trial, then read-only until the owner pays (see Plans and trial).
