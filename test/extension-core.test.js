import test from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveVaultKey,
  deriveVaultKeys,
  encryptSecret,
  decryptSecret,
  decryptVaultRecord,
  computeOriginIndex,
  normalizeOrigin,
  matchesOrigin,
  createEncryptedVaultRecord,
  deriveMasterSecret,
  importVaultKeys
} from '../extension/lib/crypto-vault.js';

test('normalizes origins without retaining paths or credentials', () => {
  assert.equal(normalizeOrigin('https://user:pass@example.com/login?q=1'), 'https://example.com');
});

test('matches only the exact protocol and hostname', () => {
  assert.equal(matchesOrigin('https://example.com', 'https://example.com/login'), true);
  assert.equal(matchesOrigin('https://example.com', 'https://evil.example.com'), false);
  assert.equal(matchesOrigin('https://example.com', 'http://example.com'), false);
});

test('encrypts and decrypts a secret with AES-GCM', async () => {
  const salt = new Uint8Array(16).fill(7);
  const key = await deriveVaultKey('correct horse battery staple', salt, 10_000);
  const encrypted = await encryptSecret(key, 'sk-test-secret', 'https://example.com');
  assert.notEqual(encrypted.ciphertext, 'sk-test-secret');
  assert.equal(await decryptSecret(key, encrypted, 'https://example.com'), 'sk-test-secret');
});

test('rejects decryption when the origin binding changes', async () => {
  const salt = new Uint8Array(16).fill(8);
  const key = await deriveVaultKey('vault passphrase', salt, 10_000);
  const encrypted = await encryptSecret(key, 'password', 'https://example.com');
  await assert.rejects(() => decryptSecret(key, encrypted, 'https://lookalike.example'));
});

test('encrypted vault records hide secrets and identifying metadata', async () => {
  const salt = new Uint8Array(16).fill(9);
  const keys = await deriveVaultKeys('vault passphrase', salt, 10_000);
  const record = await createEncryptedVaultRecord(keys, {
    id: 'record-1',
    kind: 'login',
    label: 'Example',
    origin: 'https://example.com/login',
    username: 'person@example.com',
    secret: 'super-secret-password'
  });
  const serialized = JSON.stringify(record);
  for (const plaintext of ['Example', 'https://example.com', 'person@example.com', 'super-secret-password', 'login']) {
    assert.equal(serialized.includes(plaintext), false);
  }
  assert.deepEqual(Object.keys(record).sort(), ['encrypted', 'id', 'originIndex', 'version']);
  const decrypted = await decryptVaultRecord(keys, record);
  assert.deepEqual({ ...decrypted, createdAt: '<timestamp>' }, {
    id: 'record-1', kind: 'login', label: 'Example', origin: 'https://example.com',
    username: 'person@example.com', secret: 'super-secret-password', createdAt: '<timestamp>'
  });
  assert.match(decrypted.createdAt, /^\d{4}-\d{2}-\d{2}T/);
});

test('origin indexes match normalized origins without revealing the domain', async () => {
  const salt = new Uint8Array(16).fill(10);
  const keys = await deriveVaultKeys('vault passphrase', salt, 10_000);
  const first = await computeOriginIndex(keys.indexKey, 'https://example.com/login');
  const same = await computeOriginIndex(keys.indexKey, 'https://example.com/settings');
  const other = await computeOriginIndex(keys.indexKey, 'https://other.example');
  assert.equal(first, same);
  assert.notEqual(first, other);
  assert.equal(first.includes('example.com'), false);
});

test('v3 keys come from one PBKDF2 run split with HKDF', async () => {
  const salt = new Uint8Array(16).fill(11);
  const master = await deriveMasterSecret('vault passphrase', salt, 10_000);
  assert.equal(master.length, 32);
  assert.deepEqual(await deriveMasterSecret('vault passphrase', salt, 10_000), master);
  const keys = await importVaultKeys(master);
  const record = await createEncryptedVaultRecord(keys, {
    id: 'v3', kind: 'login', label: 'V3', origin: 'https://example.com', username: '', secret: 'pw'
  });
  assert.equal((await decryptVaultRecord(await importVaultKeys(master), record)).secret, 'pw');
  const legacy = await deriveVaultKeys('vault passphrase', salt, 10_000);
  await assert.rejects(() => decryptVaultRecord(legacy, record));
  await assert.rejects(() => importVaultKeys(new Uint8Array(16)));
});
