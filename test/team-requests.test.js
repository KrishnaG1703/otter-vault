// Who may send Teams messages to the service worker, and what shape they must have. A web page
// must never reach Teams, the popup only gets Copy, and the Teams page is known by its exact URL.
import test from 'node:test';
import assert from 'node:assert/strict';
import { authorizeRequest } from '../extension/lib/request-security.js';

const extensionId = 'test-extension';
const popupUrl = `chrome-extension://${extensionId}/popup/popup.html`;
const teamPageUrl = `chrome-extension://${extensionId}/team/team.html`;
const options = { extensionId, popupUrl, teamPageUrl };
const teamPage = { id: extensionId, url: teamPageUrl, frameId: 0, tab: { id: 9, url: teamPageUrl } };
const popup = { id: extensionId, url: popupUrl };
const web = { id: extensionId, url: 'https://evil.example/', origin: 'https://evil.example', frameId: 0, documentLifecycle: 'active', tab: { id: 1 } };

const TEAM = 't_abcdefgh12';
const VAULT = 'v_abcdefgh12';
const RECORD = 'r_abcdefgh12';
const INVITE = 'i_abcdefgh12';
const MAP = { project: 'checkout-api', environment: 'prod', locations: [{ type: 'vercel-env', name: 'STRIPE_SECRET_KEY', ref: 'checkout' }], rotateEveryDays: 90, notes: '' };
const ITEM = { kind: 'api-key', label: 'Stripe', origin: 'https://dashboard.stripe.com', username: '', secret: 'sk_live_x' };

const valid = {
  'team-overview': { type: 'team-overview' },
  'team-sign-in': { type: 'team-sign-in' },
  'team-sign-out': { type: 'team-sign-out' },
  'team-create': { type: 'team-create', name: 'Acme' },
  'team-open': { type: 'team-open', teamId: TEAM },
  'team-vault-create': { type: 'team-vault-create', teamId: TEAM, name: 'Payments' },
  'team-save': { type: 'team-save', teamId: TEAM, vaultId: VAULT, recordId: null, item: ITEM, map: MAP },
  'team-share': { type: 'team-share', teamId: TEAM, vaultId: VAULT, personalId: '123e4567-e89b-42d3-a456-426614174000', map: MAP },
  'team-delete': { type: 'team-delete', teamId: TEAM, recordId: RECORD },
  'team-invite': { type: 'team-invite', teamId: TEAM, email: 'Rahul@Example.com', role: 'member' },
  'team-invite-cancel': { type: 'team-invite-cancel', teamId: TEAM, inviteId: INVITE },
  'team-accept': { type: 'team-accept', inviteId: INVITE },
  'team-confirm': { type: 'team-confirm', teamId: TEAM, inviteId: INVITE, fingerprint: '0a1b 2c3d 4e5f 6a7b 8c9d 0e1f' },
  'team-copy': { type: 'team-copy', teamId: TEAM, recordId: RECORD, passphrase: 'correct horse battery' },
  'team-export': { type: 'team-export', teamId: TEAM, passphrase: 'correct horse battery' },
  'team-remove-member': { type: 'team-remove-member', teamId: TEAM, userId: 'u_abcdefgh12' },
  'team-remove-device': { type: 'team-remove-device', teamId: TEAM, userId: 'u_abcdefgh12', deviceId: 'd_abcdefgh12' },
  'team-mark-rotated': { type: 'team-mark-rotated', teamId: TEAM, recordId: RECORD, secret: '' },
  'team-totp-setup': { type: 'team-totp-setup' },
  'team-totp-enable': { type: 'team-totp-enable', code: '123456' },
  'team-totp-verify': { type: 'team-totp-verify', code: '654321' },
  'team-device-request': { type: 'team-device-request', teamId: TEAM },
  'team-device-confirm': { type: 'team-device-confirm', teamId: TEAM, deviceId: 'd_abcdefgh12', fingerprint: '0a1b 2c3d 4e5f 6a7b 8c9d 0e1f' },
  'team-device-cancel': { type: 'team-device-cancel', teamId: TEAM, deviceId: 'd_abcdefgh12' },
  'team-kit-create': { type: 'team-kit-create', teamId: TEAM },
  'team-recovery-start': { type: 'team-recovery-start', teamId: TEAM },
  'team-recovery-decide': { type: 'team-recovery-decide', teamId: TEAM, requestId: 'q_abcdefgh12', decision: 'approve' },
  'team-recovery-finish': { type: 'team-recovery-finish', teamId: TEAM, requestId: 'q_abcdefgh12', code: 'AAAA-'.repeat(12) + 'AAAA' }
};

test('the Teams page may send every Teams message, and they come back normalised', () => {
  for (const [type, message] of Object.entries(valid)) assert.equal(authorizeRequest(message, teamPage, options).type, type);
  assert.equal(authorizeRequest(valid['team-invite'], teamPage, options).email, 'rahul@example.com');
  assert.equal(authorizeRequest({ type: 'status' }, teamPage, options).type, 'status');
  assert.throws(() => authorizeRequest({ type: 'remove', id: 'x' }, teamPage, options), /not allowed from the Teams page/);
});

test('web pages can never reach Teams, and the popup only gets Copy', () => {
  for (const message of Object.values(valid)) {
    assert.throws(() => authorizeRequest(message, web, options), /not allowed from web tabs/);
    if (message.type !== 'team-copy') assert.throws(() => authorizeRequest(message, popup, options), /not allowed from the extension popup/);
  }
  assert.equal(authorizeRequest(valid['team-copy'], popup, options).type, 'team-copy');
  // a page that only looks like the Teams page: wrong path, a frame, or another extension
  assert.equal(authorizeRequest(valid['team-open'], { ...teamPage, url: `${teamPageUrl}#t_abcdefgh12` }, options).type, 'team-open');
  assert.throws(() => authorizeRequest(valid['team-open'], { ...teamPage, url: `${teamPageUrl}?x=1` }, options));
  assert.throws(() => authorizeRequest(valid['team-open'], { ...teamPage, url: `chrome-extension://${extensionId}/team/other.html` }, options));
  assert.throws(() => authorizeRequest(valid['team-open'], { ...teamPage, frameId: 1 }, options));
  assert.throws(() => authorizeRequest(valid['team-open'], { ...teamPage, id: 'other-extension' }, options), /not authorized/);
  // without a configured Teams page URL nothing is treated as one
  assert.throws(() => authorizeRequest(valid['team-open'], teamPage, { extensionId, popupUrl }));
});

test('Teams messages are refused when any field is off', () => {
  const bad = [
    { ...valid['team-open'], teamId: 'v_abcdefgh12' },
    { ...valid['team-open'], teamId: "t_abc'; drop" },
    { ...valid['team-open'], extra: 1 },
    { ...valid['team-create'], name: '' },
    { ...valid['team-create'], name: 'a'.repeat(101) },
    { ...valid['team-create'], name: 'line\nbreak' },
    { ...valid['team-save'], item: { ...ITEM, origin: 'javascript:alert(1)' } },
    { ...valid['team-save'], item: { ...ITEM, kind: 'wallet' } },
    { ...valid['team-save'], item: { ...ITEM, extra: true } },
    { ...valid['team-save'], recordId: 'r_x' },
    { ...valid['team-save'], map: { ...MAP, environment: 'production' } },
    { ...valid['team-save'], map: { ...MAP, rotateEveryDays: 0 } },
    { ...valid['team-save'], map: { ...MAP, locations: [{ type: 'ftp', name: 'X', ref: '' }] } },
    { ...valid['team-save'], map: { ...MAP, locations: Array(21).fill({ type: 'other', name: 'X', ref: '' }) } },
    { ...valid['team-save'], map: { ...MAP, owner: 'u_x' } },
    { ...valid['team-invite'], email: 'not-an-email' },
    { ...valid['team-invite'], role: 'owner' },
    { ...valid['team-confirm'], fingerprint: '0a1b2c3d4e5f6a7b8c9d0e1f' },
    { ...valid['team-copy'], passphrase: 'short' },
    { ...valid['team-export'], passphrase: 'short' },
    { ...valid['team-export'], recordId: RECORD },
    { ...valid['team-remove-member'], userId: 'd_abcdefgh12' },
    { ...valid['team-remove-device'], deviceId: 'u_abcdefgh12' },
    { ...valid['team-mark-rotated'], secret: 42 },
    { ...valid['team-totp-verify'], code: '12345' },
    { ...valid['team-totp-verify'], code: '12345a' },
    { ...valid['team-recovery-decide'], decision: 'skip' },
    { ...valid['team-recovery-finish'], code: 'short' },
    { ...valid['team-recovery-finish'], requestId: 'r_abcdefgh12' }
  ];
  for (const message of bad) assert.throws(() => authorizeRequest(message, teamPage, options), undefined, JSON.stringify(message));
});
