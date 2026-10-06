import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifySecretField,
  classifyRevealedSecret,
  evaluateSecurityChecks,
  maskSecret,
  createVaultItem,
  transitionCompanion
} from '../src/vault-core.js';

test('security posture distinguishes implemented controls from production gaps', () => {
  const checks = evaluateSecurityChecks({
    algorithm: 'AES-256-GCM',
    exactOrigin: true,
    autoLockMinutes: 5,
    hardwareBacked: false,
    metadataEncrypted: false
  });
  assert.deepEqual(checks.map(check => [check.id, check.status]), [
    ['encryption', 'pass'],
    ['origin', 'pass'],
    ['auto-lock', 'pass'],
    ['hardware-key', 'warning'],
    ['metadata', 'warning']
  ]);
});

test('classifies a newly revealed API key using its semantic context', () => {
  assert.equal(classifyRevealedSecret({
    value: 'sk-ant-demo-1234567890abcdef',
    context: 'API key created. Copy this secret now because it will not be shown again.'
  }), 'api-key');
});

test('ignores token-like page text without secret reveal context', () => {
  assert.equal(classifyRevealedSecret({
    value: 'sk-ant-demo-1234567890abcdef',
    context: 'Example identifier in our documentation'
  }), null);
});

test('classifies password fields as login secrets', () => {
  assert.equal(classifySecretField({ type: 'password', name: 'password', autocomplete: 'current-password' }), 'login');
});

test('classifies API key fields from accessible metadata', () => {
  assert.equal(classifySecretField({ type: 'text', name: 'openai_api_key', ariaLabel: 'Secret API key' }), 'api-key');
});

test('does not classify ordinary text fields as secrets', () => {
  assert.equal(classifySecretField({ type: 'text', name: 'display_name', ariaLabel: 'Display name' }), null);
});

test('masks a secret without exposing its body', () => {
  assert.equal(maskSecret('sk-proj-1234567890'), 'sk-••••••••••••890');
});

test('creates vault metadata without retaining plaintext secret', () => {
  const item = createVaultItem({ kind: 'api-key', label: 'OpenAI', origin: 'platform.openai.com', secret: 'sk-secret-value' });
  assert.deepEqual(item, {
    kind: 'api-key',
    label: 'OpenAI',
    origin: 'platform.openai.com',
    masked: 'sk-•••••••••lue'
  });
  assert.equal('secret' in item, false);
});

test('companion moves from resting to offering save and back', () => {
  assert.equal(transitionCompanion('resting', 'secret-focused'), 'noticing');
  assert.equal(transitionCompanion('noticing', 'offer-ready'), 'offering');
  assert.equal(transitionCompanion('offering', 'saved'), 'celebrating');
  assert.equal(transitionCompanion('celebrating', 'settled'), 'resting');
});
