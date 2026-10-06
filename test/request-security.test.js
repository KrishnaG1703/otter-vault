import test from 'node:test';
import assert from 'node:assert/strict';
import { authorizeRequest, trustedSenderOrigin } from '../extension/lib/request-security.js';

const extensionId = 'test-extension';
const popupUrl = `chrome-extension://${extensionId}/popup/popup.html`;
const documentId = '2D1B0C8E4F7A6B5C9D3E2F1A0B9C8D7E';

function webSender(overrides = {}) {
  return {
    id: extensionId,
    url: 'https://example.com/login?next=1',
    origin: 'https://example.com',
    frameId: 0,
    documentId,
    documentLifecycle: 'active',
    tab: { id: 1, url: 'https://different-tab-value.invalid/' },
    ...overrides
  };
}

test('derives trusted origin from the sending document rather than the tab', () => {
  assert.equal(trustedSenderOrigin(webSender()), 'https://example.com');
});

test('accepts a missing optional sender.origin but requires sender.url', () => {
  assert.equal(trustedSenderOrigin(webSender({ origin: undefined })), 'https://example.com');
  assert.throws(() => trustedSenderOrigin(webSender({ url: undefined })), /sending document/i);
});

test('rejects inconsistent document URL and origin', () => {
  assert.throws(() => trustedSenderOrigin(webSender({ origin: 'https://evil.example' })), /consistent/i);
});

test('rejects non-top, inactive, malformed-document, and non-http senders', () => {
  assert.throws(() => trustedSenderOrigin(webSender({ frameId: 2 })), /top frame/i);
  assert.throws(() => trustedSenderOrigin(webSender({ documentLifecycle: 'prerender' })), /active/i);
  assert.throws(() => trustedSenderOrigin(webSender({ documentId: 'not-a-document-id' })), /documentId/i);
  assert.throws(() => trustedSenderOrigin(webSender({ documentId: '123e4567-e89b-42d3-a456-426614174000' })), /documentId/i);
  assert.throws(() => trustedSenderOrigin(webSender({ url: 'file:///tmp/secret.html', origin: 'null' })), /http or https/i);
});

test('allows Chrome versions that do not provide documentId', () => {
  assert.equal(trustedSenderOrigin(webSender({ documentId: undefined })), 'https://example.com');
});

test('authorization requires the extension id and kind for web matching operations', () => {
  const options = { extensionId, popupUrl };
  assert.deepEqual(authorizeRequest({ type: 'fill', kind: 'login' }, webSender(), options), { type: 'fill', kind: 'login' });
  assert.deepEqual(authorizeRequest({ type: 'has-match', kind: 'api-key' }, webSender(), options), { type: 'has-match', kind: 'api-key' });
  assert.throws(() => authorizeRequest({ type: 'fill', kind: 'login' }, webSender({ id: 'other-extension' }), options), /not authorized/i);
  assert.throws(() => authorizeRequest({ type: 'fill' }, webSender(), options), /kind|schema/i);
});

test('rejects extension messages without a web document sender', () => {
  assert.throws(() => trustedSenderOrigin({ url: popupUrl }), /trusted web tab|sending document/i);
});
