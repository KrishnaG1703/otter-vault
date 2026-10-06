// Adversarial tests: each one plays an attacker against the background worker and asserts
// that no plaintext secret, metadata, or unlocked session comes back.
import test from 'node:test';
import assert from 'node:assert/strict';

const CONFIG_KEY = 'otterVaultConfig';
const RECORDS_KEY = 'otterVaultRecords';
const SESSION_KEY = 'otterVaultSession';
const EXTENSION_ID = 'test-extension';
const PASSPHRASE = 'correct horse battery staple';

const popup = () => ({ id: EXTENSION_ID, url: `chrome-extension://${EXTENSION_ID}/popup/popup.html` });
const web = (url, overrides = {}) => {
  let origin;
  try { origin = new URL(url).origin; } catch { origin = undefined; }
  return {
    id: EXTENSION_ID,
    tab: { id: 7, url },
    url,
    origin,
    frameId: 0,
    documentId: '2D1B0C8E4F7A6B5C9D3E2F1A0B9C8D7E',
    documentLifecycle: 'active',
    ...overrides
  };
};

function makeChrome() {
  const local = {};
  const session = {};
  const listeners = [];
  const area = data => ({
    async get(keys) { return Object.fromEntries(keys.filter(k => k in data).map(k => [k, structuredClone(data[k])])); },
    async set(values) { Object.assign(data, structuredClone(values)); },
    async remove(keys) { for (const k of [].concat(keys)) delete data[k]; },
    async setAccessLevel() {}
  });
  return {
    local,
    session,
    chrome: {
      runtime: {
        id: EXTENSION_ID,
        getURL: path => `chrome-extension://${EXTENSION_ID}/${path}`,
        onMessage: { addListener: fn => listeners.push(fn) }
      },
      storage: { local: area(local), session: area(session) },
      __listeners: listeners
    }
  };
}

async function boot(mock = makeChrome()) {
  globalThis.chrome = mock.chrome;
  await import(`../extension/background.js?attack=${crypto.randomUUID()}`);
  const listener = mock.chrome.__listeners.at(-1);
  const send = (message, sender) => new Promise(resolve => listener(message, sender, resolve));
  return { mock, send };
}

async function vaultWith(items) {
  const api = await boot();
  assert.equal((await api.send({ type: 'setup', passphrase: PASSPHRASE }, popup())).ok, true);
  for (const [url, kind, secret] of items) {
    const saved = await api.send({ type: 'save', item: { kind, label: `label for ${secret}`, username: `user-${secret}`, secret } }, web(url));
    assert.equal(saved.ok, true, saved.error);
  }
  return api;
}

const noSecret = (response, secret) => {
  assert.equal(JSON.stringify(response).includes(secret), false, `response leaked ${secret}: ${JSON.stringify(response)}`);
};

test('attack: swapping encrypted payloads between sites never decrypts the other site\'s secret', async () => {
  const api = await vaultWith([['https://bank.example/login', 'login', 'BANK-SECRET'], ['https://evil.example/login', 'login', 'EVIL-SECRET']]);
  // records are stored newest first
  const [evil, bankRecord] = api.mock.local[RECORDS_KEY];
  // put the bank ciphertext under the evil site's index
  [evil.encrypted, bankRecord.encrypted] = [bankRecord.encrypted, evil.encrypted];
  const response = await api.send({ type: 'fill', kind: 'login' }, web('https://evil.example/login'));
  assert.equal(response.ok, false);
  noSecret(response, 'BANK-SECRET');
});

test('attack: re-pointing a record\'s origin index to another site is rejected', async () => {
  const api = await vaultWith([['https://bank.example/login', 'login', 'BANK-SECRET'], ['https://evil.example/login', 'login', 'EVIL-SECRET']]);
  const [evil, bank] = api.mock.local[RECORDS_KEY];
  bank.originIndex = evil.originIndex;
  const response = await api.send({ type: 'fill', kind: 'login' }, web('https://evil.example/login'));
  noSecret(response, 'BANK-SECRET');
});

test('attack: flipped ciphertext bits, forged ids and truncated tags fail closed', async () => {
  for (const tamper of [
    record => { const bytes = Buffer.from(record.encrypted.ciphertext, 'base64'); bytes[3] ^= 1; record.encrypted.ciphertext = bytes.toString('base64'); },
    record => { record.id = 'forged-id'; },
    record => { record.encrypted.ciphertext = Buffer.from(record.encrypted.ciphertext, 'base64').subarray(0, -4).toString('base64'); },
    record => { record.encrypted.iv = Buffer.alloc(12).toString('base64'); }
  ]) {
    const api = await vaultWith([['https://bank.example/login', 'login', 'BANK-SECRET']]);
    tamper(api.mock.local[RECORDS_KEY][0]);
    const response = await api.send({ type: 'fill', kind: 'login' }, web('https://bank.example/login'));
    assert.equal(response.ok, false);
    noSecret(response, 'BANK-SECRET');
  }
});

test('attack: lookalike, subdomain, userinfo, port and scheme variants never fill', async () => {
  const api = await vaultWith([['https://bank.example/login', 'login', 'BANK-SECRET']]);
  for (const url of [
    'https://bank.examp1e/login',
    'https://login.bank.example/',
    'https://bank.example.evil.test/',
    'https://bank.example@evil.test/',
    'https://bank.example:8443/login',
    'http://bank.example/login',
    'https://xn--bnk-sna.example/'
  ]) {
    const fill = await api.send({ type: 'fill', kind: 'login' }, web(url));
    noSecret(fill, 'BANK-SECRET');
    const match = await api.send({ type: 'has-match', kind: 'login' }, web(url));
    assert.notEqual(match.data?.hasMatch, true, `${url} reported a match`);
  }
  assert.equal((await api.send({ type: 'fill', kind: 'login' }, web('https://bank.example/other-path'))).data.secret, 'BANK-SECRET');
});

test('attack: a page cannot claim a different origin or act as the popup', async () => {
  const api = await vaultWith([['https://bank.example/login', 'login', 'BANK-SECRET']]);
  const forged = [
    [{ type: 'fill', kind: 'login' }, web('https://evil.example/', { origin: 'https://bank.example' })],
    [{ type: 'fill', kind: 'login', origin: 'https://bank.example' }, web('https://evil.example/')],
    [{ type: 'fill', kind: 'login' }, web('https://bank.example/', { frameId: 3 })],
    [{ type: 'fill', kind: 'login' }, web('https://bank.example/', { documentLifecycle: 'prerender' })],
    [{ type: 'fill', kind: 'login' }, web('https://bank.example/', { id: 'some-other-extension' })],
    [{ type: 'fill', kind: 'login' }, { id: EXTENSION_ID, url: 'https://bank.example/' }],
    [{ type: 'status' }, web('https://bank.example/')],
    [{ type: 'remove', id: api.mock.local[RECORDS_KEY][0].id }, web('https://bank.example/')],
    [{ type: 'set-auto-lock', minutes: 30 }, web('https://bank.example/')],
    [{ type: 'unlock', passphrase: PASSPHRASE }, web('https://bank.example/')],
    [JSON.parse('{"type":"fill","kind":"login","__proto__":{"admin":true}}'), web('https://bank.example/')],
    [{ type: 'save', item: { kind: 'login', label: 'x', secret: 'y'.repeat(20_000) } }, web('https://bank.example/')]
  ];
  for (const [message, sender] of forged) {
    const response = await api.send(message, sender);
    assert.equal(response.ok, false, `accepted ${JSON.stringify(message)} from ${JSON.stringify(sender)}`);
    noSecret(response, 'BANK-SECRET');
  }
  assert.equal(api.mock.local[RECORDS_KEY].length, 1);
});

test('attack: a locked vault reveals neither secrets nor whether a site has one', async () => {
  const api = await vaultWith([['https://bank.example/login', 'login', 'BANK-SECRET']]);
  await api.send({ type: 'lock' }, popup());
  const fill = await api.send({ type: 'fill', kind: 'login' }, web('https://bank.example/login'));
  assert.equal(fill.ok, false);
  noSecret(fill, 'BANK-SECRET');
  const match = await api.send({ type: 'has-match', kind: 'login' }, web('https://bank.example/login'));
  assert.deepEqual(match.data, { hasMatch: false, unlocked: false, hiddenWhileLocked: true });
  const status = await api.send({ type: 'status' }, popup());
  assert.deepEqual(status.data.records, []);
  noSecret(status, 'bank.example');
});

test('attack: wrong passphrases never unlock, even after many attempts', async () => {
  const api = await vaultWith([['https://bank.example/login', 'login', 'BANK-SECRET']]);
  await api.send({ type: 'lock' }, popup());
  for (const guess of ['correct horse battery stapl', 'Correct horse battery staple', 'correct horse battery staple ', 'password1234']) {
    const response = await api.send({ type: 'unlock', passphrase: guess }, popup());
    assert.equal(response.ok, false);
  }
  assert.equal((await api.send({ type: 'status' }, popup())).data.unlocked, false);
  assert.equal(api.mock.session[SESSION_KEY], undefined);
});

test('attack: storage at rest holds no plaintext secret, username, label, or site', async () => {
  const api = await vaultWith([['https://bank.example/login', 'login', 'BANK-SECRET'], ['https://api.example/keys', 'api-key', 'sk-live-ABCDEF123456']]);
  const disk = JSON.stringify(api.mock.local);
  for (const plaintext of ['BANK-SECRET', 'sk-live-ABCDEF123456', 'user-BANK-SECRET', 'label for', 'bank.example', 'api.example', PASSPHRASE]) {
    assert.equal(disk.includes(plaintext), false, `found ${plaintext} in storage`);
  }
});

test('attack: weakening the stored key-derivation settings is refused before any unlock', async () => {
  const api = await vaultWith([['https://bank.example/login', 'login', 'BANK-SECRET']]);
  await api.send({ type: 'lock' }, popup());
  const config = api.mock.local[CONFIG_KEY];
  for (const kdf of [{ ...config.kdf, iterations: 1 }, { ...config.kdf, hash: 'SHA-1' }, { ...config.kdf, saltBytes: 1 }]) {
    api.mock.local[CONFIG_KEY] = { ...config, kdf };
    const response = await api.send({ type: 'unlock', passphrase: PASSPHRASE }, popup());
    assert.equal(response.ok, false, `accepted kdf ${JSON.stringify(kdf)}`);
  }
  api.mock.local[CONFIG_KEY] = { ...config, autoLockMinutes: 99999 };
  assert.equal((await api.send({ type: 'unlock', passphrase: PASSPHRASE }, popup())).ok, false);
});

test('verify: the popup gets a yes or no, never the secret; pages and locked vaults get nothing', async () => {
  const api = await vaultWith([['https://bank.example/login', 'login', 'BANK-SECRET']]);
  const id = api.mock.local[RECORDS_KEY][0].id;
  const right = await api.send({ type: 'verify', id, secret: 'BANK-SECRET' }, popup());
  assert.deepEqual(right.data, { match: true });
  const wrong = await api.send({ type: 'verify', id, secret: 'BANK-SECRE' }, popup());
  assert.deepEqual(wrong.data, { match: false });
  noSecret(wrong, 'BANK-SECRET');
  const fromPage = await api.send({ type: 'verify', id, secret: 'BANK-SECRET' }, web('https://bank.example/login'));
  assert.equal(fromPage.ok, false);
  assert.equal((await api.send({ type: 'verify', id, secret: 'x', extra: 1 }, popup())).ok, false);
  await api.send({ type: 'lock' }, popup());
  const locked = await api.send({ type: 'verify', id, secret: 'BANK-SECRET' }, popup());
  assert.equal(locked.ok, false);
  assert.equal(locked.data, undefined);
});

test('copy: needs the passphrase again, never works from a page, and locks after repeated wrong tries', async () => {
  const alarms = [];
  const api = await vaultWith([['https://api.example/keys', 'api-key', 'sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd']]);
  globalThis.chrome.alarms = { create: async (name, info) => alarms.push({ name, ...info }), onAlarm: { addListener() {} } };
  const id = api.mock.local[RECORDS_KEY][0].id;
  const status = await api.send({ type: 'status' }, popup());
  assert.equal(status.data.records[0].hint, 'sk-proj-…abcd');

  const fromPage = await api.send({ type: 'copy', id, passphrase: PASSPHRASE }, web('https://api.example/keys'));
  assert.equal(fromPage.ok, false);

  const good = await api.send({ type: 'copy', id, passphrase: PASSPHRASE }, popup());
  assert.equal(good.data.secret, 'sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd');
  assert.equal(good.data.clearsInSeconds, 300);
  assert.equal(alarms.length, 1);
  assert.equal(JSON.stringify(api.mock.session).includes('ABCDEFGH'), false, 'plaintext left in session storage');

  for (let i = 0; i < 4; i++) {
    const wrong = await api.send({ type: 'copy', id, passphrase: 'not the passphrase at all' }, popup());
    assert.equal(wrong.ok, false);
    noSecret(wrong, 'ABCDEFGH');
  }
  const fifth = await api.send({ type: 'copy', id, passphrase: 'not the passphrase at all' }, popup());
  assert.match(fifth.error, /locked/i);
  assert.equal((await api.send({ type: 'status' }, popup())).data.unlocked, false);
  assert.equal((await api.send({ type: 'copy', id, passphrase: PASSPHRASE }, popup())).ok, false);
});
