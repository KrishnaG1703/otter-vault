# Otter Vault privacy policy

_Last updated: October 4, 2026_

Otter Vault is a browser extension that helps you save passwords and API keys to an encrypted vault on your own device, and, if you choose, share some of them with a team. This policy explains what it handles and what it does not do.

## The short version

- Your personal vault stays on your device. It has no server, no account and makes no network requests.
- **Teams is optional.** If you turn it on, you sign in with Google and the extension talks to one server we run. Keys you share are encrypted on your device first: the server stores them, but cannot read them.
- Nothing is saved unless you click to save it.
- We do not sell or share your data, use it for advertising, or run analytics or tracking.

## Your personal vault

**Credentials you choose to save.** When you click **Keep it safe**, the extension saves the password or API key you approved, together with a label (the page title), the username field's value on login forms, the website's origin (for example `https://platform.claude.com`), and the time it was saved. All of this is encrypted with AES-256-GCM before it is written to your browser's local extension storage (`chrome.storage.local`).

**Your vault passphrase.** Your passphrase is used only to derive encryption keys on your device. It is never stored or transmitted. We cannot recover it for you: if you forget it, the vault cannot be decrypted.

**Page content, in the moment.** To offer help, the extension's content script looks at the web pages you visit: it notices password and API-key fields, and text that looks like a newly generated API key. This happens locally in your browser. Page content is not recorded, stored, or sent anywhere unless you explicitly save a credential.

**Copying a saved secret.** When you click **Copy** and re-enter your passphrase, the secret is placed on your clipboard. Otter keeps only a SHA-256 hash of it in `chrome.storage.session` and, after 5 minutes for API keys or 1 minute for passwords, reads the clipboard once: if it still holds that secret, Otter clears it; if you have copied anything else since, it is left untouched. Clipboard contents are never stored or sent anywhere.

**Unlocked session.** While the vault is unlocked, a key needed to use it is kept in memory in `chrome.storage.session`, which Chrome clears when the browser closes. It locks automatically after the auto-lock time you choose (5, 15, or 30 minutes).

## Otter Vault Teams (only if you turn it on)

Teams lets a group share API keys and passwords. It uses a server we operate at `otter-teams.mechaclips.workers.dev`, hosted on Cloudflare.

**Signing in with Google.** When you click **Sign in with Google**, Google tells Otter your email address, that it is verified, and your Google account ID. Otter does not receive your Google password and does not ask for access to anything else in your Google account (the only scopes are `openid` and `email`).

**What the server stores, readable by it:**

- your email address and Google account ID;
- the public keys of each device you use with Teams, and a 30-day session for each (stored as a hash);
- which teams you belong to, your role, and the invites sent to or by you;
- the team's signed member history and access log: which device added, edited, copied or filled which shared key, and when (keys are identified only by a random ID);
- if you are an owner or admin, your two-step sign-in secret, encrypted with a key held by the server, so it can check your codes;
- the team's plan and trial dates, and, once the owner subscribes, the subscription's status, renewal date and the IDs Dodo Payments gives the subscription and the paying customer.

**What the server stores but cannot read:** the shared keys themselves and everything about them (names, sites, usernames, projects, environments, where they are deployed, notes), team and vault names, the team keys, and the recovery kit. These are encrypted on members' devices with keys the server never receives. Your vault passphrase and the printed recovery code never leave your devices.

**Who can see your shared data.** Members of the team you shared it with, on devices that were added to the team. Members can see each other's email addresses and the team's activity, including what you copied or filled.

**Payments.** A team owner who subscribes pays on a checkout page run by Dodo Payments (dodopayments.com), which sells the subscription as the merchant of record. Card details, billing address and receipts are handled by Dodo under its own privacy policy; Otter never receives or stores card numbers. We send Dodo the owner's email address and the team's random ID, and Dodo tells our server when the subscription starts, renews, fails or ends. Members who don't pay share nothing with Dodo.

**Hosting.** Cloudflare runs the server and its database as our hosting provider and processes requests to it, including your IP address, to deliver the service.

**Email.** Teams may send invite and recovery notices by email once email sending is set up. It sends no marketing.

**Keeping and deleting it.** Team data is kept while the team exists, including after a free trial ends (the team becomes read-only, not deleted). Sessions expire after 30 days and sign-in codes after 10 minutes. To delete your Teams account and the data tied to it, email us at the address below from the email you sign in with, and we will delete it within 30 days. Keys you shared stay with the team for its other members until an admin deletes them. Leaving a team or signing out does not touch your personal vault.

## What Otter Vault does not do

- It does not send your personal vault, or anything from the pages you visit, to us or anyone else.
- It does not use analytics, advertising, telemetry, or crash reporting.
- It does not read your browsing history.
- It does not use or transfer your data for purposes unrelated to saving, filling and sharing the credentials you approve, for creditworthiness, or for lending.

## Your control

- Delete any saved credential from the extension popup, and any shared key from the Teams page (if you have access).
- Teams is off until you sign in, and you can sign out at any time.
- Removing the extension deletes its local storage, including the encrypted personal vault.
- Deleted data may remain on your device's storage media until the browser overwrites it.

## Chrome Web Store user data policy

The use of information received by Otter Vault adheres to the Chrome Web Store User Data Policy, including the Limited Use requirements.

## Changes and contact

If this policy changes, the updated version will be published at this address with a new date. Questions or deletion requests: krishna091718@gmail.com.
