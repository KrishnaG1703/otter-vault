// Cryptography for Otter Vault Teams (docs/teams-phase1.md). Everything here runs on the client;
// the Teams server only ever stores what these functions produce. Pure WebCrypto, no network.
import { normalizeOrigin } from './crypto-vault.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const ECDSA = Object.freeze({ name: 'ECDSA', namedCurve: 'P-256' });
const ECDH = Object.freeze({ name: 'ECDH', namedCurve: 'P-256' });
const SIGN_PARAMS = Object.freeze({ name: 'ECDSA', hash: 'SHA-256' });
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export const ENVIRONMENTS = Object.freeze(['prod', 'staging', 'dev', 'other']);
export const LOCATION_TYPES = Object.freeze([
  'vercel-env', 'github-actions', 'aws-ssm', 'aws-secrets-manager',
  'gcp-secret-manager', 'cloudflare-secret', 'env-file', 'other'
]);

export class TeamCryptoError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'TeamCryptoError';
    this.code = code;
  }
}

const fail = (code, message) => { throw new TeamCryptoError(code, message); };

// ---- encoding ----

export function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBytes(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 !== 0) {
    fail('encoding', 'Invalid base64 value');
  }
  const binary = atob(value);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

export function base64Url(bytes) {
  return bytesToBase64(bytes).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

export function randomId(prefix) {
  return `${prefix}_${base64Url(crypto.getRandomValues(new Uint8Array(16)))}`;
}

function concatBytes(...parts) {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

// Deterministic JSON: object keys sorted, no undefined, finite numbers only. Every signature and
// hash in Teams is taken over this form, so the client and the server agree byte for byte.
export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('encoding', 'Numbers must be finite');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const keys = Object.keys(value).sort();
    return `{${keys.map(key => {
      if (value[key] === undefined) fail('encoding', `Field ${key} is undefined`);
      return `${JSON.stringify(key)}:${canonicalJson(value[key])}`;
    }).join(',')}}`;
  }
  return fail('encoding', 'Only plain JSON values can be signed');
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export async function hashJson(value) {
  return base64Url(await sha256(encoder.encode(canonicalJson(value))));
}

// ---- device identities ----

function checkPublicKey(value, name) {
  const bytes = base64ToBytes(value);
  if (bytes.length !== 65 || bytes[0] !== 0x04) fail('key', `${name} must be an uncompressed P-256 public key`);
  return bytes;
}

// Fresh signing (ECDSA) and key-agreement (ECDH) key pairs for one device or recovery identity.
// The returned private keys are PKCS#8 bytes, meant to be sealed immediately and never stored plain.
export async function generateIdentity(prefix = 'd') {
  const [sig, kx] = await Promise.all([
    crypto.subtle.generateKey(ECDSA, true, ['sign', 'verify']),
    crypto.subtle.generateKey(ECDH, true, ['deriveBits'])
  ]);
  const [sigPub, kxPub, sigPkcs8, kxPkcs8] = await Promise.all([
    crypto.subtle.exportKey('raw', sig.publicKey),
    crypto.subtle.exportKey('raw', kx.publicKey),
    crypto.subtle.exportKey('pkcs8', sig.privateKey),
    crypto.subtle.exportKey('pkcs8', kx.privateKey)
  ]);
  return {
    id: randomId(prefix),
    sigPub: bytesToBase64(new Uint8Array(sigPub)),
    kxPub: bytesToBase64(new Uint8Array(kxPub)),
    sigPkcs8: bytesToBase64(new Uint8Array(sigPkcs8)),
    kxPkcs8: bytesToBase64(new Uint8Array(kxPkcs8))
  };
}

// Turns stored identity material into non-extractable CryptoKeys for signing and unwrapping.
export async function loadIdentity(material) {
  const [sigPrivate, kxPrivate] = await Promise.all([
    crypto.subtle.importKey('pkcs8', base64ToBytes(material.sigPkcs8), ECDSA, false, ['sign']),
    crypto.subtle.importKey('pkcs8', base64ToBytes(material.kxPkcs8), ECDH, false, ['deriveBits'])
  ]);
  checkPublicKey(material.sigPub, 'sigPub');
  checkPublicKey(material.kxPub, 'kxPub');
  return Object.freeze({ id: material.id, sigPub: material.sigPub, kxPub: material.kxPub, sigPrivate, kxPrivate });
}

// 96-bit fingerprint over both public keys, shown as six groups of four hex characters, which is
// what an admin and a new member compare over a separate channel.
export async function fingerprint(sigPub, kxPub) {
  const digest = await sha256(concatBytes(checkPublicKey(sigPub, 'sigPub'), checkPublicKey(kxPub, 'kxPub')));
  const hex = Array.from(digest.subarray(0, 12), byte => byte.toString(16).padStart(2, '0')).join('');
  return hex.match(/.{4}/g).join(' ');
}

async function hkdfAesKey(secret, info, usages) {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) fail('key', 'Expected a 32-byte secret');
  const material = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode(info) },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    usages
  );
}

async function sealJson(key, value, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(aad) }, key, encoder.encode(JSON.stringify(value))
  );
  return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext)) };
}

async function openJson(key, sealed, aad, code) {
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(sealed.iv), additionalData: encoder.encode(aad) },
      key,
      base64ToBytes(sealed.ciphertext)
    );
    return JSON.parse(decoder.decode(plaintext));
  } catch (error) {
    if (error instanceof TeamCryptoError && error.code !== 'encoding') throw error;
    return fail(code, 'Could not decrypt');
  }
}

const IDENTITY_FIELDS = ['id', 'sigPub', 'kxPub', 'sigPkcs8', 'kxPkcs8'];

function checkIdentityMaterial(material) {
  if (!material || typeof material !== 'object' || IDENTITY_FIELDS.some(field => typeof material[field] !== 'string') ||
      Object.keys(material).length !== IDENTITY_FIELDS.length) {
    fail('identity', 'Invalid identity material');
  }
  return material;
}

// The device's private keys at rest, under a key derived from the personal vault's master secret.
export async function sealDeviceIdentity(masterSecret, material) {
  checkIdentityMaterial(material);
  const key = await hkdfAesKey(masterSecret, 'otter-identity-v1', ['encrypt']);
  return { version: 1, id: material.id, ...(await sealJson(key, material, `otter-identity-v1|${material.id}`)) };
}

export async function openDeviceIdentity(masterSecret, sealed) {
  if (sealed?.version !== 1) fail('identity', 'Unsupported identity version');
  const key = await hkdfAesKey(masterSecret, 'otter-identity-v1', ['decrypt']);
  const material = checkIdentityMaterial(await openJson(key, sealed, `otter-identity-v1|${sealed.id}`, 'identity'));
  if (material.id !== sealed.id) fail('identity', 'Identity mismatch');
  return material;
}

// ---- signatures ----

export async function signJson(identity, value) {
  const signature = await crypto.subtle.sign(SIGN_PARAMS, identity.sigPrivate, encoder.encode(canonicalJson(value)));
  return bytesToBase64(new Uint8Array(signature));
}

export async function verifyJson(sigPub, value, signature) {
  try {
    const key = await crypto.subtle.importKey('raw', checkPublicKey(sigPub, 'sigPub'), ECDSA, false, ['verify']);
    const bytes = base64ToBytes(signature);
    if (bytes.length !== 64) return false;
    return await crypto.subtle.verify(SIGN_PARAMS, key, bytes, encoder.encode(canonicalJson(value)));
  } catch {
    return false;
  }
}

// ---- team keys ----

export function generateTeamKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

export async function importTeamKey(teamKey) {
  if (!(teamKey instanceof Uint8Array) || teamKey.length !== 32) fail('key', 'Team key must be 32 bytes');
  return crypto.subtle.importKey('raw', teamKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

function checkEpoch(epoch) {
  if (!Number.isSafeInteger(epoch) || epoch < 1) fail('epoch', 'Epoch must be a positive integer');
  return epoch;
}

function wrapInfo(teamId, epoch, recipientId) {
  return `otter-team-wrap-v1|${teamId}|${checkEpoch(epoch)}|${recipientId}`;
}

async function wrapKeyFor(privateKey, publicRaw, ephemeralPub, info, usage) {
  const peer = await crypto.subtle.importKey('raw', publicRaw, ECDH, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: peer }, privateKey, 256));
  const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: ephemeralPub, info: encoder.encode(info) },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage]
  );
}

// ECIES: an ephemeral ECDH key agrees a secret with the recipient, HKDF binds it to team, epoch
// and recipient, and AES-GCM carries the team key with the same binding as additional data.
export async function wrapTeamKey({ teamKey, teamId, epoch, recipientId, recipientKxPub }) {
  if (!(teamKey instanceof Uint8Array) || teamKey.length !== 32) fail('key', 'Team key must be 32 bytes');
  const info = wrapInfo(teamId, epoch, recipientId);
  const ephemeral = await crypto.subtle.generateKey(ECDH, true, ['deriveBits']);
  const ephemeralPub = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
  const key = await wrapKeyFor(ephemeral.privateKey, checkPublicKey(recipientKxPub, 'kxPub'), ephemeralPub, info, 'encrypt');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(info) }, key, teamKey);
  return {
    teamId,
    epoch,
    recipientId,
    ephemeralPub: bytesToBase64(ephemeralPub),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  };
}

export async function unwrapTeamKey(identity, wrap, { teamId, epoch }) {
  if (wrap.teamId !== teamId || wrap.epoch !== epoch || wrap.recipientId !== identity.id) {
    fail('wrap', 'Key wrap is for a different team, epoch or device');
  }
  try {
    const info = wrapInfo(teamId, epoch, identity.id);
    const ephemeralPub = checkPublicKey(wrap.ephemeralPub, 'ephemeralPub');
    const key = await wrapKeyFor(identity.kxPrivate, ephemeralPub, ephemeralPub, info, 'decrypt');
    const teamKey = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(wrap.iv), additionalData: encoder.encode(info) }, key, base64ToBytes(wrap.ciphertext)
    ));
    if (teamKey.length !== 32) fail('wrap', 'Unwrapped key has the wrong length');
    return teamKey;
  } catch (error) {
    if (error instanceof TeamCryptoError && error.code === 'epoch') throw error;
    return fail('wrap', 'Could not unwrap the team key');
  }
}

// ---- records ----

const RECORD_FIELDS = ['id', 'kind', 'label', 'origin', 'username', 'secret', 'createdAt', 'map', 'updatedAt', 'updatedBy'];
const MAP_FIELDS = ['project', 'environment', 'locations', 'owner', 'rotateEveryDays', 'lastRotatedAt', 'notes'];

const isString = (value, max) => typeof value === 'string' && value.length <= max;
const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

export function validateRecordPayload(payload) {
  if (!exactKeys(payload, RECORD_FIELDS)) fail('record', 'Record has missing or unexpected fields');
  if (!isString(payload.id, 64) || !payload.id.startsWith('r_')) fail('record', 'Invalid record id');
  if (!['api-key', 'login'].includes(payload.kind)) fail('record', 'Invalid record kind');
  if (!isString(payload.label, 200) || !isString(payload.username, 320)) fail('record', 'Invalid label or username');
  if (!isString(payload.secret, 16_384) || payload.secret.length === 0) fail('record', 'Invalid secret');
  if (!isString(payload.createdAt, 40) || !isString(payload.updatedAt, 40) || !isString(payload.updatedBy, 64)) {
    fail('record', 'Invalid timestamps or author');
  }
  try {
    if (normalizeOrigin(payload.origin) !== payload.origin) fail('record', 'Origin is not normalised');
  } catch (error) {
    if (error instanceof TeamCryptoError) throw error;
    fail('record', 'Invalid origin');
  }
  const map = payload.map;
  if (!exactKeys(map, MAP_FIELDS)) fail('record', 'Key map has missing or unexpected fields');
  if (!isString(map.project, 200) || !ENVIRONMENTS.includes(map.environment) || !isString(map.owner, 64) ||
      !isString(map.notes, 2000)) {
    fail('record', 'Invalid key map');
  }
  if (map.rotateEveryDays !== null && !(Number.isSafeInteger(map.rotateEveryDays) && map.rotateEveryDays >= 1 && map.rotateEveryDays <= 3650)) {
    fail('record', 'Invalid rotation period');
  }
  if (map.lastRotatedAt !== null && !isString(map.lastRotatedAt, 40)) fail('record', 'Invalid rotation date');
  if (!Array.isArray(map.locations) || map.locations.length > 20) fail('record', 'Invalid locations');
  for (const location of map.locations) {
    if (!exactKeys(location, ['type', 'name', 'ref']) || !LOCATION_TYPES.includes(location.type) ||
        !isString(location.name, 200) || !isString(location.ref, 200)) {
      fail('record', 'Invalid location');
    }
  }
  return payload;
}

function recordAad({ teamId, vaultId, recordId, epoch, revision }) {
  if (!Number.isSafeInteger(revision) || revision < 1) fail('record', 'Revision must be a positive integer');
  return `otter-team-record-v1|${teamId}|${vaultId}|${recordId}|${checkEpoch(epoch)}|${revision}`;
}

// Encrypts a whole record (secret and key map) under the team key. The additional data pins the
// ciphertext to its team, vault, record, epoch and revision, so the server cannot move or replay it.
export async function encryptRecord(teamCryptoKey, place, payload) {
  validateRecordPayload(payload);
  if (payload.id !== place.recordId) fail('record', 'Record id does not match its place');
  return { ...place, ...(await sealJson(teamCryptoKey, payload, recordAad(place))) };
}

export async function decryptRecord(teamCryptoKey, envelope) {
  const payload = await openJson(teamCryptoKey, envelope, recordAad(envelope), 'record');
  validateRecordPayload(payload);
  if (payload.id !== envelope.recordId) fail('record', 'Record identity mismatch');
  return payload;
}

// What the writing device signs for a stored record: its place plus a hash of the ciphertext.
export async function recordSignatureBody(envelope, { updatedBy, updatedAt, deleted = false }) {
  return {
    type: 'otter-team-record-v1',
    teamId: envelope.teamId,
    vaultId: envelope.vaultId,
    recordId: envelope.recordId,
    epoch: envelope.epoch,
    revision: envelope.revision,
    iv: envelope.iv,
    ciphertextHash: base64Url(await sha256(base64ToBytes(envelope.ciphertext))),
    updatedBy,
    updatedAt,
    deleted
  };
}

// ---- recovery kit ----

export function generateRecoverySecret() {
  return crypto.getRandomValues(new Uint8Array(32));
}

// 256 bits as 52 base32 characters (RFC 4648 alphabet), grouped in fours for printing.
export function formatRecoveryCode(secret) {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) fail('recovery', 'Recovery secret must be 32 bytes');
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of secret) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) output += BASE32[(value << (5 - bits)) & 31];
  return output.match(/.{1,4}/g).join('-');
}

// Accepts the code as printed or typed: any case, spaces or dashes, and 0/1/8 for O/I/B.
export function parseRecoveryCode(text) {
  if (typeof text !== 'string') fail('recovery', 'Recovery code must be text');
  const clean = text.toUpperCase().replace(/[\s-]/g, '').replaceAll('0', 'O').replaceAll('1', 'I').replaceAll('8', 'B');
  if (clean.length !== 52 || ![...clean].every(character => BASE32.includes(character))) {
    fail('recovery', 'A recovery code is 52 letters and digits');
  }
  const secret = new Uint8Array(32);
  let bits = 0;
  let value = 0;
  let index = 0;
  for (const character of clean) {
    value = (value << 5) | BASE32.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      secret[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
      value &= (1 << bits) - 1;
    }
  }
  if (value !== 0) fail('recovery', 'Recovery code has a typo');
  return secret;
}

// The recovery identity's private keys, sealed under the 256-bit recovery secret. The server
// stores this blob; without the printed code it is a random 256-bit key away from being readable.
export async function sealRecoveryIdentity(secret, teamId, material) {
  checkIdentityMaterial(material);
  const info = `otter-recovery-v1|${teamId}`;
  const key = await hkdfAesKey(secret, info, ['encrypt']);
  return { version: 1, teamId, id: material.id, ...(await sealJson(key, material, `${info}|${material.id}`)) };
}

export async function openRecoveryIdentity(secret, sealed) {
  if (sealed?.version !== 1) fail('recovery', 'Unsupported recovery kit version');
  const info = `otter-recovery-v1|${sealed.teamId}`;
  const key = await hkdfAesKey(secret, info, ['decrypt']);
  const material = checkIdentityMaterial(await openJson(key, sealed, `${info}|${sealed.id}`, 'recovery'));
  if (material.id !== sealed.id) fail('recovery', 'Recovery kit mismatch');
  return material;
}

// ---- team and vault names ----

function nameAad({ teamId, kind, id, epoch }) {
  if (!['team', 'vault'].includes(kind)) fail('name', 'Invalid name kind');
  return `otter-team-name-v1|${teamId}|${kind}|${id}|${checkEpoch(epoch)}`;
}

// Team and vault names are encrypted under the team key too, so the server never learns them.
// They are re-encrypted at every re-key so members who join later can read them.
export async function encryptName(teamCryptoKey, place, name) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 100) fail('name', 'Names are 1 to 100 characters');
  return { epoch: place.epoch, ...(await sealJson(teamCryptoKey, name, nameAad(place))) };
}

export async function decryptName(teamCryptoKey, place, sealed) {
  if (sealed?.epoch !== place.epoch) fail('name', 'Name is from another epoch');
  const name = await openJson(teamCryptoKey, sealed, nameAad(place), 'name');
  if (typeof name !== 'string') fail('name', 'Invalid name');
  return name;
}

// What a device signs when it registers with the server: proof it holds the signing key.
export function deviceRegistrationBody({ email, deviceId, sigPub, kxPub }) {
  return { type: 'otter-device-register-v1', email, deviceId, sigPub, kxPub };
}

// The nonce a client puts in its Google sign-in request. Google copies it into the ID token, so
// the token only works for registering the device whose keys it was requested for.
export async function googleNonce({ deviceId, sigPub, kxPub, salt }) {
  return hashJson({ type: 'otter-google-nonce-v1', deviceId, sigPub, kxPub, salt });
}
