// Known-answer and cross-implementation checks for the vault cryptography. WebCrypto results are
// compared with Node's independent OpenSSL-backed implementation, so a wrong parameter anywhere
// (hash, iteration count, HKDF info, AAD) fails here rather than silently weakening the vault.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createDecipheriv, hkdfSync, pbkdf2Sync, createHmac } from 'node:crypto';
import {
  computeOriginIndex,
  createEncryptedVaultRecord,
  decryptVaultRecord,
  deriveMasterSecret,
  encryptSecret,
  importVaultKeys
} from '../extension/lib/crypto-vault.js';

const PASSPHRASE = 'correct horse battery staple';
const SALT = Uint8Array.from({ length: 16 }, (_, i) => i * 7 + 1);
const b64 = value => Buffer.from(value, 'base64');

// Node's AES-256-GCM decrypt; WebCrypto appends the 16-byte tag to the ciphertext
function nodeDecrypt(key, { iv, ciphertext }, aad) {
  const data = b64(ciphertext);
  const decipher = createDecipheriv('aes-256-gcm', key, b64(iv));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(data.subarray(-16));
  return Buffer.concat([decipher.update(data.subarray(0, -16)), decipher.final()]).toString('utf8');
}

test('kat: PBKDF2-HMAC-SHA256 matches the RFC 7914 test vector through the same WebCrypto call', async () => {
  // RFC 7914 §11 vector 2 uses an 8-character password, below the vault minimum, so check the
  // primitive directly with identical parameters to the ones deriveMasterSecret passes.
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode('Password'), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: new TextEncoder().encode('NaCl'), iterations: 80000, hash: 'SHA-256' }, material, 512);
  assert.equal(Buffer.from(bits).toString('hex'),
    '4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d');
});

test('kat: the vault master secret is PBKDF2-SHA256, 600,000 iterations, 32 bytes', async () => {
  const master = await deriveMasterSecret(PASSPHRASE, SALT);
  const reference = pbkdf2Sync(PASSPHRASE, SALT, 600_000, 32, 'sha256');
  assert.equal(Buffer.from(master).toString('hex'), reference.toString('hex'));
});

test('kat: HKDF splits the master secret into the encryption key Node derives independently', async () => {
  const master = pbkdf2Sync(PASSPHRASE, SALT, 1000, 32, 'sha256');
  const keys = await importVaultKeys(new Uint8Array(master));
  const encryptionKey = Buffer.from(hkdfSync('sha256', master, Buffer.alloc(0), 'otter-encryption-v3', 32));
  const encrypted = await encryptSecret(keys.encryptionKey, 'sk-live-KAT-SECRET', 'https://api.example');
  assert.equal(encrypted.algorithm, 'AES-256-GCM');
  assert.equal(b64(encrypted.iv).length, 12);
  // the origin is bound as additional authenticated data
  assert.equal(nodeDecrypt(encryptionKey, encrypted, 'https://api.example'), 'sk-live-KAT-SECRET');
  assert.throws(() => nodeDecrypt(encryptionKey, encrypted, 'https://evil.example'));
  // a key from the wrong HKDF label must not open it
  const wrongLabel = Buffer.from(hkdfSync('sha256', master, Buffer.alloc(0), 'otter-origin-index-v3', 32));
  assert.throws(() => nodeDecrypt(wrongLabel, encrypted, 'https://api.example'));
});

test('kat: the origin index is HMAC-SHA256 over the normalised origin with the HKDF index key', async () => {
  const master = pbkdf2Sync(PASSPHRASE, SALT, 1000, 32, 'sha256');
  const keys = await importVaultKeys(new Uint8Array(master));
  const indexKey = Buffer.from(hkdfSync('sha256', master, Buffer.alloc(0), 'otter-origin-index-v3', 32));
  const expected = createHmac('sha256', indexKey).update('https://api.example').digest('base64url');
  assert.equal(await computeOriginIndex(keys.indexKey, 'https://api.example/some/path?q=1'), expected);
});

test('kat: every record uses a fresh 96-bit IV and binds its ciphertext to the origin index', async () => {
  const master = pbkdf2Sync(PASSPHRASE, SALT, 1000, 32, 'sha256');
  const keys = await importVaultKeys(new Uint8Array(master));
  const encryptionKey = Buffer.from(hkdfSync('sha256', master, Buffer.alloc(0), 'otter-encryption-v3', 32));
  const item = { kind: 'api-key', label: 'k', origin: 'https://api.example', secret: 'same-secret' };
  const ivs = new Set();
  for (let i = 0; i < 200; i++) {
    const record = await createEncryptedVaultRecord(keys, item);
    ivs.add(record.encrypted.iv);
    if (i === 0) {
      const payload = JSON.parse(nodeDecrypt(encryptionKey, record.encrypted, record.originIndex));
      assert.equal(payload.secret, 'same-secret');
      assert.equal((await decryptVaultRecord(keys, record)).secret, 'same-secret');
    }
  }
  assert.equal(ivs.size, 200, 'an IV was reused');
});

test('kat: short passphrases are refused before any derivation', async () => {
  await assert.rejects(deriveMasterSecret('elevenchars', SALT), /at least 12/);
});
