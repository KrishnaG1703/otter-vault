// Known-answer and cross-implementation checks for the Teams cryptography. Every construction is
// opened or verified a second time with Node's OpenSSL-backed crypto, so a wrong curve, HKDF salt,
// info string or additional-data binding fails here rather than shipping.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createDecipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman, hkdfSync, sign as nodeSign, verify as nodeVerify
} from 'node:crypto';
import {
  TeamCryptoError,
  canonicalJson,
  decryptRecord,
  encryptRecord,
  fingerprint,
  formatRecoveryCode,
  generateIdentity,
  generateRecoverySecret,
  generateTeamKey,
  importTeamKey,
  loadIdentity,
  openDeviceIdentity,
  openRecoveryIdentity,
  parseRecoveryCode,
  sealDeviceIdentity,
  sealRecoveryIdentity,
  signJson,
  unwrapTeamKey,
  validateRecordPayload,
  verifyJson,
  wrapTeamKey
} from '../extension/lib/team-crypto.js';

const b64 = value => Buffer.from(value, 'base64');
const b64url = bytes => Buffer.from(bytes).toString('base64url');

function nodeDecrypt(key, { iv, ciphertext }, aad) {
  const data = b64(ciphertext);
  const decipher = createDecipheriv('aes-256-gcm', key, b64(iv));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(data.subarray(-16));
  return Buffer.concat([decipher.update(data.subarray(0, -16)), decipher.final()]);
}

function nodePublicKey(raw) {
  const bytes = b64(raw);
  return createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b64url(bytes.subarray(1, 33)), y: b64url(bytes.subarray(33)) }, format: 'jwk' });
}

const nodePrivateKey = pkcs8 => createPrivateKey({ key: b64(pkcs8), format: 'der', type: 'pkcs8' });

function payload(overrides = {}) {
  return {
    id: 'r_stripe',
    kind: 'api-key',
    label: 'Stripe live secret',
    origin: 'https://dashboard.stripe.com',
    username: '',
    secret: 'sk_live_TEAM_KAT_SECRET',
    createdAt: '2026-10-03T10:00:00.000Z',
    map: {
      project: 'checkout-api',
      environment: 'prod',
      locations: [{ type: 'vercel-env', name: 'STRIPE_SECRET_KEY', ref: 'checkout-api' }],
      owner: 'u_krishna',
      rotateEveryDays: 90,
      lastRotatedAt: null,
      notes: ''
    },
    updatedAt: '2026-10-03T10:00:00.000Z',
    updatedBy: 'd_laptop',
    ...overrides
  };
}

const PLACE = Object.freeze({ teamId: 't_acme', vaultId: 'v_main', recordId: 'r_stripe', epoch: 2, revision: 1 });

test('canonical JSON sorts keys at every depth and refuses values that are not plain JSON', () => {
  assert.equal(canonicalJson({ b: 1, a: { d: [2, { z: true, y: null }], c: 'x' } }), '{"a":{"c":"x","d":[2,{"y":null,"z":true}]},"b":1}');
  assert.throws(() => canonicalJson({ a: undefined }), TeamCryptoError);
  assert.throws(() => canonicalJson({ a: Number.NaN }), TeamCryptoError);
  assert.throws(() => canonicalJson({ a: new Date(0) }), TeamCryptoError);
  assert.throws(() => canonicalJson(new Map()), TeamCryptoError);
});

test('kat: device signatures are ECDSA P-256 / SHA-256 in IEEE P1363 form, checked both ways with OpenSSL', async () => {
  const material = await generateIdentity();
  const identity = await loadIdentity(material);
  const value = { op: 'add', seq: 3, subject: { role: 'member' } };
  const signature = await signJson(identity, value);
  assert.equal(b64(signature).length, 64);
  assert.ok(nodeVerify('sha256', Buffer.from(canonicalJson(value)), { key: nodePublicKey(material.sigPub), dsaEncoding: 'ieee-p1363' }, b64(signature)));

  const fromNode = nodeSign('sha256', Buffer.from(canonicalJson(value)), { key: nodePrivateKey(material.sigPkcs8), dsaEncoding: 'ieee-p1363' });
  assert.equal(await verifyJson(material.sigPub, value, fromNode.toString('base64')), true);
  assert.equal(await verifyJson(material.sigPub, { ...value, seq: 4 }, signature), false);
  const other = await generateIdentity();
  assert.equal(await verifyJson(other.sigPub, value, signature), false);
  assert.equal(await verifyJson(material.sigPub, value, 'not base64!'), false);
  assert.equal(await verifyJson('AAAA', value, signature), false);
});

test('kat: fingerprint is the first 96 bits of SHA-256(sigPub || kxPub) in six groups of four', async () => {
  const material = await generateIdentity();
  const digest = createHash('sha256').update(Buffer.concat([b64(material.sigPub), b64(material.kxPub)])).digest('hex');
  const shown = await fingerprint(material.sigPub, material.kxPub);
  assert.match(shown, /^([0-9a-f]{4} ){5}[0-9a-f]{4}$/);
  assert.equal(shown.replaceAll(' ', ''), digest.slice(0, 24));
});

test('kat: a team key wrap opens in OpenSSL with ECDH P-256, HKDF(salt = ephemeral key) and the bound info', async () => {
  const material = await generateIdentity();
  const teamKey = generateTeamKey();
  const wrap = await wrapTeamKey({ teamKey, teamId: 't_acme', epoch: 3, recipientId: material.id, recipientKxPub: material.kxPub });
  const info = `otter-team-wrap-v1|t_acme|3|${material.id}`;
  const shared = diffieHellman({ privateKey: nodePrivateKey(material.kxPkcs8), publicKey: nodePublicKey(wrap.ephemeralPub) });
  const wrapKey = Buffer.from(hkdfSync('sha256', shared, b64(wrap.ephemeralPub), info, 32));
  assert.deepEqual(new Uint8Array(nodeDecrypt(wrapKey, wrap, info)), teamKey);
  assert.throws(() => nodeDecrypt(wrapKey, wrap, `otter-team-wrap-v1|t_acme|2|${material.id}`));

  const identity = await loadIdentity(material);
  assert.deepEqual(await unwrapTeamKey(identity, wrap, { teamId: 't_acme', epoch: 3 }), teamKey);
});

test('a wrap only opens for its own team, epoch and device, and not after tampering', async () => {
  const material = await generateIdentity();
  const identity = await loadIdentity(material);
  const teamKey = generateTeamKey();
  const wrap = await wrapTeamKey({ teamKey, teamId: 't_acme', epoch: 3, recipientId: material.id, recipientKxPub: material.kxPub });
  const reject = (candidate, expected) => assert.rejects(unwrapTeamKey(identity, candidate, expected), { code: 'wrap' });

  await reject(wrap, { teamId: 't_other', epoch: 3 });
  await reject(wrap, { teamId: 't_acme', epoch: 2 });
  // relabelled by a server to look like another epoch or recipient: the HKDF info no longer matches
  await reject({ ...wrap, epoch: 4 }, { teamId: 't_acme', epoch: 4 });
  const other = await loadIdentity(await generateIdentity());
  await assert.rejects(unwrapTeamKey(other, { ...wrap, recipientId: other.id }, { teamId: 't_acme', epoch: 3 }), { code: 'wrap' });
  const flipped = b64(wrap.ciphertext);
  flipped[0] ^= 1;
  await reject({ ...wrap, ciphertext: flipped.toString('base64') }, { teamId: 't_acme', epoch: 3 });
  const swappedEphemeral = (await wrapTeamKey({ teamKey, teamId: 't_acme', epoch: 3, recipientId: material.id, recipientKxPub: material.kxPub })).ephemeralPub;
  await reject({ ...wrap, ephemeralPub: swappedEphemeral }, { teamId: 't_acme', epoch: 3 });
  await assert.rejects(wrapTeamKey({ teamKey: new Uint8Array(16), teamId: 't_acme', epoch: 3, recipientId: material.id, recipientKxPub: material.kxPub }), TeamCryptoError);
  await assert.rejects(wrapTeamKey({ teamKey, teamId: 't_acme', epoch: 3, recipientId: material.id, recipientKxPub: 'AAAA' }), TeamCryptoError);
});

test('kat: a team record is AES-256-GCM under the team key with team, vault, record, epoch and revision as additional data', async () => {
  const teamKey = generateTeamKey();
  const envelope = await encryptRecord(await importTeamKey(teamKey), PLACE, payload());
  const aad = 'otter-team-record-v1|t_acme|v_main|r_stripe|2|1';
  assert.deepEqual(JSON.parse(nodeDecrypt(Buffer.from(teamKey), envelope, aad).toString('utf8')), payload());
  assert.ok(!JSON.stringify(envelope).includes('sk_live'));
  assert.ok(!JSON.stringify(envelope).includes('checkout-api'));
});

test('a record cannot be moved to another vault, record, team, epoch or revision', async () => {
  const key = await importTeamKey(generateTeamKey());
  const envelope = await encryptRecord(key, PLACE, payload());
  assert.deepEqual(await decryptRecord(key, envelope), payload());
  for (const change of [{ vaultId: 'v_other' }, { recordId: 'r_other' }, { teamId: 't_other' }, { epoch: 1 }, { epoch: 3 }, { revision: 2 }]) {
    await assert.rejects(decryptRecord(key, { ...envelope, ...change }), { code: 'record' }, JSON.stringify(change));
  }
  await assert.rejects(decryptRecord(await importTeamKey(generateTeamKey()), envelope), { code: 'record' });
  await assert.rejects(encryptRecord(key, { ...PLACE, recordId: 'r_other' }, payload()), { code: 'record' });
  await assert.rejects(encryptRecord(key, { ...PLACE, revision: 0 }, payload()), { code: 'record' });
});

test('record payloads are validated strictly, including the key map', () => {
  assert.equal(validateRecordPayload(payload()).id, 'r_stripe');
  const bad = [
    { kind: 'wallet' },
    { origin: 'https://dashboard.stripe.com/path' },
    { origin: 'not a url' },
    { secret: '' },
    { extra: true },
    { map: { ...payload().map, environment: 'production' } },
    { map: { ...payload().map, rotateEveryDays: 0 } },
    { map: { ...payload().map, rotateEveryDays: 1.5 } },
    { map: { ...payload().map, locations: [{ type: 'ftp', name: 'X', ref: '' }] } },
    { map: { ...payload().map, locations: [{ type: 'env-file', name: 'X' }] } },
    { map: { ...payload().map, locations: Array(21).fill({ type: 'other', name: 'X', ref: '' }) } },
    { map: { ...payload().map, secretLeak: 'x' } }
  ];
  for (const change of bad) assert.throws(() => validateRecordPayload(payload(change)), { code: 'record' }, JSON.stringify(change));
});

test('kat: the device identity is sealed with HKDF(master, "otter-identity-v1") and AES-GCM', async () => {
  const master = Uint8Array.from({ length: 32 }, (_, i) => i);
  const material = await generateIdentity();
  const sealed = await sealDeviceIdentity(master, material);
  assert.ok(!JSON.stringify(sealed).includes(material.sigPkcs8));
  const key = Buffer.from(hkdfSync('sha256', master, Buffer.alloc(0), 'otter-identity-v1', 32));
  assert.deepEqual(JSON.parse(nodeDecrypt(key, sealed, `otter-identity-v1|${material.id}`)), material);
  assert.deepEqual(await openDeviceIdentity(master, sealed), material);
  await assert.rejects(openDeviceIdentity(Uint8Array.from({ length: 32 }, () => 7), sealed), { code: 'identity' });
  await assert.rejects(openDeviceIdentity(master, { ...sealed, id: 'd_other' }), { code: 'identity' });
});

test('kat: recovery codes are RFC 4648 base32 of the 256-bit secret, grouped in fours', () => {
  assert.equal(formatRecoveryCode(new Uint8Array(32)), Array(13).fill('AAAA').join('-'));
  assert.equal(formatRecoveryCode(new Uint8Array(32).fill(255)), `${Array(12).fill('7777').join('-')}-777Q`);
  for (let round = 0; round < 50; round += 1) {
    const secret = generateRecoverySecret();
    const code = formatRecoveryCode(secret);
    assert.match(code, /^([A-Z2-7]{4}-){12}[A-Z2-7]{4}$/);
    assert.deepEqual(parseRecoveryCode(code), secret);
    // typed back lowercase, with spaces, and 0/1/8 instead of O/I/B
    const typed = code.toLowerCase().replaceAll('-', ' ').replaceAll('o', '0').replaceAll('i', '1').replaceAll('b', '8');
    assert.deepEqual(parseRecoveryCode(typed), secret);
  }
  assert.throws(() => parseRecoveryCode('AAAA'), { code: 'recovery' });
  assert.throws(() => parseRecoveryCode(`${Array(12).fill('7777').join('-')}-7777`), { code: 'recovery' });
  assert.throws(() => parseRecoveryCode(`${Array(12).fill('AAAA').join('-')}-AA9A`), { code: 'recovery' });
});

test('kat: the recovery identity is sealed under HKDF(recovery secret) bound to the team', async () => {
  const secret = generateRecoverySecret();
  const material = await generateIdentity('k');
  const sealed = await sealRecoveryIdentity(secret, 't_acme', material);
  const key = Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(0), 'otter-recovery-v1|t_acme', 32));
  assert.deepEqual(JSON.parse(nodeDecrypt(key, sealed, `otter-recovery-v1|t_acme|${material.id}`)), material);
  assert.deepEqual(await openRecoveryIdentity(parseRecoveryCode(formatRecoveryCode(secret)), sealed), material);
  await assert.rejects(openRecoveryIdentity(generateRecoverySecret(), sealed), { code: 'recovery' });
  await assert.rejects(openRecoveryIdentity(secret, { ...sealed, teamId: 't_other' }), { code: 'recovery' });
});
