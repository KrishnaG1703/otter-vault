const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function base64Url(bytes) {
  return bytesToBase64(bytes).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function domainSeparatedSalt(salt, label) {
  const suffix = encoder.encode(label);
  const result = new Uint8Array(salt.length + suffix.length);
  result.set(salt);
  result.set(suffix, salt.length);
  return result;
}

export function normalizeOrigin(value) {
  const url = new URL(value);
  return url.origin;
}

export function matchesOrigin(savedOrigin, candidateUrl) {
  try {
    return normalizeOrigin(savedOrigin) === normalizeOrigin(candidateUrl);
  } catch {
    return false;
  }
}

async function importPassphrase(passphrase, usage = 'deriveKey') {
  if (!passphrase || String(passphrase).length < 12) throw new Error('Passphrase must be at least 12 characters');
  return crypto.subtle.importKey('raw', encoder.encode(String(passphrase)), 'PBKDF2', false, [usage]);
}

export async function deriveVaultKey(passphrase, salt, iterations = 310_000) {
  const material = await importPassphrase(passphrase);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function deriveIndexKey(passphrase, salt, iterations) {
  const material = await importPassphrase(passphrase);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: domainSeparatedSalt(salt, 'otter-origin-index-v1'), iterations, hash: 'SHA-256' },
    material,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign']
  );
}

export async function deriveVaultKeys(passphrase, salt, iterations = 310_000) {
  const [encryptionKey, indexKey] = await Promise.all([
    deriveVaultKey(passphrase, salt, iterations),
    deriveIndexKey(passphrase, salt, iterations)
  ]);
  return { encryptionKey, indexKey };
}

// Legacy (config v1/v2) derivation above runs PBKDF2 twice, which doubles unlock time without
// slowing an attacker, who only needs the encryption key to test a guess against the verifier.
// Config v3 runs PBKDF2 once and splits the 256-bit master secret into both keys with HKDF.
export async function deriveMasterSecret(passphrase, salt, iterations = 600_000) {
  const material = await importPassphrase(passphrase, 'deriveBits');
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, material, 256);
  return new Uint8Array(bits);
}

export async function importVaultKeys(masterSecret) {
  if (!(masterSecret instanceof Uint8Array) || masterSecret.length !== 32) throw new Error('Invalid vault master secret');
  const material = await crypto.subtle.importKey('raw', masterSecret, 'HKDF', false, ['deriveKey']);
  const hkdf = info => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode(info) });
  const [encryptionKey, indexKey] = await Promise.all([
    crypto.subtle.deriveKey(hkdf('otter-encryption-v3'), material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
    crypto.subtle.deriveKey(hkdf('otter-origin-index-v3'), material, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign'])
  ]);
  return { encryptionKey, indexKey };
}

export async function computeOriginIndex(indexKey, origin) {
  const signature = await crypto.subtle.sign('HMAC', indexKey, encoder.encode(normalizeOrigin(origin)));
  return base64Url(new Uint8Array(signature));
}

async function encryptValue(key, plaintext, additionalData) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(additionalData) },
    key,
    encoder.encode(plaintext)
  );
  return { algorithm: 'AES-256-GCM', iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext)) };
}

async function decryptValue(key, encrypted, additionalData) {
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(encrypted.iv), additionalData: encoder.encode(additionalData) },
    key,
    base64ToBytes(encrypted.ciphertext)
  );
  return decoder.decode(plaintext);
}

export async function encryptSecret(key, secret, origin) {
  return encryptValue(key, String(secret), normalizeOrigin(origin));
}

export async function decryptSecret(key, encrypted, origin) {
  return decryptValue(key, encrypted, normalizeOrigin(origin));
}

export async function createEncryptedVaultRecord(keys, item) {
  const id = item.id || crypto.randomUUID();
  const origin = normalizeOrigin(item.origin);
  const originIndex = await computeOriginIndex(keys.indexKey, origin);
  const payload = {
    id,
    kind: item.kind,
    label: item.label,
    origin,
    username: item.username || '',
    secret: String(item.secret),
    createdAt: item.createdAt || new Date().toISOString()
  };
  return {
    version: 2,
    id,
    originIndex,
    encrypted: await encryptValue(keys.encryptionKey, JSON.stringify(payload), originIndex)
  };
}

export async function decryptVaultRecord(keys, record) {
  if (record.version !== 2) throw new Error('Unsupported encrypted record version');
  const plaintext = await decryptValue(keys.encryptionKey, record.encrypted, record.originIndex);
  const payload = JSON.parse(plaintext);
  if (payload.id !== record.id) throw new Error('Record identity mismatch');
  const expectedIndex = await computeOriginIndex(keys.indexKey, payload.origin);
  if (expectedIndex !== record.originIndex) throw new Error('Record origin index mismatch');
  return payload;
}
