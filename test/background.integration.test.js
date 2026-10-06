import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createEncryptedVaultRecord,
  deriveVaultKeys,
  encryptSecret
} from '../extension/lib/crypto-vault.js';

const CONFIG_KEY = 'otterVaultConfig';
const RECORDS_KEY = 'otterVaultRecords';
const MIGRATION_KEY = 'otterVaultMigration';
const SESSION_KEY = 'otterVaultSession';
const V3_KDF = { version: 2, name: 'PBKDF2', hash: 'SHA-256', iterations: 600000, saltBytes: 16, split: 'HKDF-SHA-256' };
const popupSender = () => ({ id: 'test-extension', url: 'chrome-extension://test-extension/popup/popup.html' });
const webSender = (url = 'https://example.com/login', overrides = {}) => ({
  id: 'test-extension',
  tab: { id: 1, url: 'https://stale-tab-url.invalid/' },
  url,
  origin: new URL(url).origin,
  frameId: 0,
  documentId: '2D1B0C8E4F7A6B5C9D3E2F1A0B9C8D7E',
  documentLifecycle: 'active',
  ...overrides
});

function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function makeChrome(initial = {}) {
  const data = structuredClone(initial);
  const sessionData = {};
  const listeners = [];
  const suspendListeners = [];
  let beforeGet = null;
  let beforeSet = null;
  let setFailure = null;
  return {
    data,
    sessionData,
    gateNextGet(promise) { beforeGet = promise; },
    gateNextSet(promise) {
      let signal;
      const entered = new Promise(resolve => { signal = resolve; });
      beforeSet = { remaining: 1, promise, signal };
      return entered;
    },
    gateSetNumber(number, promise) {
      let signal;
      const entered = new Promise(resolve => { signal = resolve; });
      beforeSet = { remaining: number, promise, signal };
      return entered;
    },
    failNextSet(error, partialValues = null) { setFailure = { remaining: 1, error, partialValues }; },
    failSetNumber(number, error, partialValues = null) { setFailure = { remaining: number, error, partialValues }; },
    chrome: {
      runtime: {
        id: 'test-extension',
        getURL: path => `chrome-extension://test-extension/${path}`,
        onMessage: { addListener: listener => listeners.push(listener) },
        onSuspend: { addListener: listener => suspendListeners.push(listener) }
      },
      storage: { local: {
        async get(keys) {
          if (beforeGet) {
            const gate = beforeGet;
            beforeGet = null;
            await gate;
          }
          return Object.fromEntries(keys.filter(key => key in data).map(key => [key, structuredClone(data[key])]));
        },
        async set(values) {
          if (beforeSet) {
            beforeSet.remaining -= 1;
            if (beforeSet.remaining === 0) {
              const gate = beforeSet;
              beforeSet = null;
              gate.signal();
              await gate.promise;
            }
          }
          if (setFailure) {
            setFailure.remaining -= 1;
            if (setFailure.remaining === 0) {
              const failure = setFailure;
              setFailure = null;
              if (failure.partialValues) Object.assign(data, structuredClone(failure.partialValues(values)));
              throw failure.error;
            }
          }
          Object.assign(data, structuredClone(values));
        },
        async remove(keys) {
          for (const key of Array.isArray(keys) ? keys : [keys]) delete data[key];
        }
      },
      session: {
        async get(keys) {
          return Object.fromEntries(keys.filter(key => key in sessionData).map(key => [key, structuredClone(sessionData[key])]));
        },
        async set(values) { Object.assign(sessionData, structuredClone(values)); },
        async remove(keys) {
          for (const key of Array.isArray(keys) ? keys : [keys]) delete sessionData[key];
        },
        async setAccessLevel() {}
      } },
      __listeners: listeners,
      __suspendListeners: suspendListeners
    }
  };
}

async function loadBackground(mock) {
  globalThis.chrome = mock.chrome;
  await import(`../extension/background.js?test=${crypto.randomUUID()}`);
  const listener = mock.chrome.__listeners.at(-1);
  return {
    send(message, sender) {
      return new Promise(resolve => {
        const async = listener(message, sender, resolve);
        assert.equal(async, true);
      });
    },
    suspend() { mock.chrome.__suspendListeners.at(-1)?.(); }
  };
}

async function setupVault(api, passphrase = 'correct horse battery staple') {
  const response = await api.send({ type: 'setup', passphrase }, popupSender());
  assert.equal(response.ok, true, response.error);
}

test('authorizes message types by sender context and validates schemas', async () => {
  const mock = makeChrome();
  const api = await loadBackground(mock);
  await setupVault(api);

  assert.match((await api.send({ type: 'status' }, webSender())).error, /not allowed/i);
  assert.match((await api.send({ type: 'fill', kind: 'login' }, popupSender())).error, /not allowed/i);
  assert.match((await api.send({ type: 'has-match', kind: 'login' }, webSender('file:///tmp/a'))).error, /http or https/i);
  assert.match((await api.send({ type: 'save', item: { kind: 'other', label: 'x', secret: 'y' } }, webSender())).error, /kind/i);
  assert.match((await api.send({ type: 'save', item: { kind: 'login', label: '', secret: 'y' } }, webSender())).error, /label/i);
  assert.match((await api.send({ type: 'fill', kind: 'login', url: 'https://evil.example' }, webSender())).error, /schema/i);
  assert.match((await api.send({ type: 'remove', id: '<bad>' }, popupSender())).error, /id/i);
  await api.send({ type: 'lock' }, popupSender());
});

test('manual lock during an awaited fill prevents plaintext return', async () => {
  const mock = makeChrome();
  const api = await loadBackground(mock);
  await setupVault(api);
  assert.equal((await api.send({ type: 'save', item: { kind: 'login', label: 'Example', username: 'a', secret: 'secret' } }, webSender())).ok, true);

  let release;
  mock.gateNextGet(new Promise(resolve => { release = resolve; }));
  const fill = api.send({ type: 'fill', kind: 'login' }, webSender());
  assert.equal((await api.send({ type: 'lock' }, popupSender())).ok, true);
  release();
  const response = await fill;
  assert.equal(response.ok, false);
  assert.match(response.error, /locked/i);
});

test('deadline expiry during an awaited fill prevents plaintext return', async () => {
  const realNow = Date.now;
  let now = realNow();
  Date.now = () => now;
  const mock = makeChrome();
  const api = await loadBackground(mock);
  Date.now = realNow;
  try {
    await setupVault(api);
    assert.equal((await api.send({ type: 'save', item: { kind: 'login', label: 'Example', username: '', secret: 'secret' } }, webSender())).ok, true);
    let release;
    mock.gateNextGet(new Promise(resolve => { release = resolve; }));
    const fill = api.send({ type: 'fill', kind: 'login' }, webSender());
    now += 300_001;
    release();
    const response = await fill;
    assert.equal(response.ok, false);
    assert.match(response.error, /locked/i);
  } finally {
    Date.now = realNow;
  }
});

test('DOM has-match probes do not extend the session', async () => {
  const realSetTimeout = globalThis.setTimeout;
  const realClearTimeout = globalThis.clearTimeout;
  let timerCalls = 0;
  globalThis.setTimeout = () => ++timerCalls;
  globalThis.clearTimeout = () => {};
  const mock = makeChrome();
  const api = await loadBackground(mock);
  globalThis.setTimeout = realSetTimeout;
  globalThis.clearTimeout = realClearTimeout;
  try {
    await setupVault(api);
    const afterSetup = timerCalls;
    assert.equal((await api.send({ type: 'has-match', kind: 'login' }, webSender())).ok, true);
    assert.equal(timerCalls, afterSetup);
    assert.equal((await api.send({ type: 'status' }, popupSender())).ok, true);
    assert.equal(timerCalls, afterSetup + 1);
  } finally {
    globalThis.setTimeout = realSetTimeout;
    globalThis.clearTimeout = realClearTimeout;
    await api.send({ type: 'lock' }, popupSender());
  }
});

test('serializes concurrent saves and removes without lost updates', async () => {
  const mock = makeChrome();
  const api = await loadBackground(mock);
  await setupVault(api);
  const sender = webSender();
  const saves = await Promise.all([
    api.send({ type: 'save', item: { kind: 'login', label: 'First', username: '', secret: 'one' } }, sender),
    api.send({ type: 'save', item: { kind: 'login', label: 'Second', username: '', secret: 'two' } }, sender)
  ]);
  assert.equal(saves.every(response => response.ok), true);
  assert.equal(mock.data[RECORDS_KEY].length, 2);
  const ids = saves.map(response => response.data.id);
  const removals = await Promise.all(ids.map(id => api.send({ type: 'remove', id }, popupSender())));
  assert.equal(removals.every(response => response.ok), true);
  assert.deepEqual(mock.data[RECORDS_KEY], []);
  await api.send({ type: 'lock' }, popupSender());
});

test('fill returns the newest matching credential deterministically', async () => {
  const mock = makeChrome();
  const api = await loadBackground(mock);
  await setupVault(api);
  const sender = webSender();
  await api.send({ type: 'save', item: { kind: 'login', label: 'Older', username: '', secret: 'old' } }, sender);
  await new Promise(resolve => setTimeout(resolve, 2));
  await api.send({ type: 'save', item: { kind: 'login', label: 'Newer', username: '', secret: 'new' } }, sender);
  mock.data[RECORDS_KEY].reverse();
  const response = await api.send({ type: 'fill', kind: 'login' }, sender);
  assert.equal(response.ok, true, response.error);
  assert.equal(response.data.secret, 'new');
  await api.send({ type: 'lock' }, popupSender());
});

test('production save contract omits origin and worker injects the sending document origin', async () => {
  const mock = makeChrome();
  const api = await loadBackground(mock);
  await setupVault(api);
  const response = await api.send({
    type: 'save',
    item: { kind: 'login', label: 'Production shape', username: 'person', secret: 'secret' }
  }, webSender('https://accounts.example.test/login'));
  assert.equal(response.ok, true, response.error);
  assert.equal(response.data.origin, 'https://accounts.example.test');
});

test('has-match and fill isolate credentials by exact origin and kind', async () => {
  const mock = makeChrome();
  const api = await loadBackground(mock);
  await setupVault(api);
  const sender = webSender();
  await api.send({ type: 'save', item: { kind: 'api-key', label: 'API', username: '', secret: 'api-secret' } }, sender);
  assert.deepEqual((await api.send({ type: 'has-match', kind: 'login' }, sender)).data, { hasMatch: false, unlocked: true, insecureFill: false });
  assert.equal((await api.send({ type: 'fill', kind: 'login' }, sender)).data, null);
  assert.equal((await api.send({ type: 'fill', kind: 'api-key' }, sender)).data.secret, 'api-secret');
  await api.send({ type: 'save', item: { kind: 'login', label: 'Login', username: '', secret: 'password-secret' } }, sender);
  assert.equal((await api.send({ type: 'fill', kind: 'api-key' }, sender)).data.secret, 'api-secret');
});

test('simultaneous status and fills from one generation all complete', async () => {
  const mock = makeChrome();
  const api = await loadBackground(mock);
  await setupVault(api);
  const sender = webSender();
  await api.send({ type: 'save', item: { kind: 'login', label: 'Login', username: '', secret: 'parallel-secret' } }, sender);
  const responses = await Promise.all([
    api.send({ type: 'status' }, popupSender()),
    api.send({ type: 'fill', kind: 'login' }, sender),
    api.send({ type: 'fill', kind: 'login' }, sender)
  ]);
  assert.equal(responses.every(response => response.ok), true, responses.map(response => response.error).join(', '));
  assert.equal(responses[1].data.secret, 'parallel-secret');
  assert.equal(responses[2].data.secret, 'parallel-secret');
});

test('manual lock requested during setup storage.set runs after a consistent setup commit', async () => {
  const mock = makeChrome();
  const api = await loadBackground(mock);
  let release;
  const enteredSet = mock.gateNextSet(new Promise(resolve => { release = resolve; }));
  const setup = api.send({ type: 'setup', passphrase: 'correct horse battery staple' }, popupSender());
  await enteredSet;
  const lock = api.send({ type: 'lock' }, popupSender());
  release();
  const [setupResponse, lockResponse] = await Promise.all([setup, lock]);
  assert.equal(setupResponse.ok, true, setupResponse.error);
  assert.equal(lockResponse.ok, true, lockResponse.error);
  assert.equal(mock.data[CONFIG_KEY].version, 3);
  assert.deepEqual(mock.data[RECORDS_KEY], []);
  assert.equal((await api.send({ type: 'status' }, popupSender())).data.unlocked, false);
});

test('manual lock requested during save storage.set is serialized after the write', async () => {
  const mock = makeChrome();
  const api = await loadBackground(mock);
  await setupVault(api);
  let release;
  const enteredSet = mock.gateNextSet(new Promise(resolve => { release = resolve; }));
  const save = api.send({ type: 'save', item: { kind: 'login', label: 'Racing save', username: '', secret: 'secret' } }, webSender());
  await enteredSet;
  const lock = api.send({ type: 'lock' }, popupSender());
  release();
  const [saveResponse, lockResponse] = await Promise.all([save, lock]);
  assert.equal(saveResponse.ok, true, saveResponse.error);
  assert.equal(lockResponse.ok, true, lockResponse.error);
  assert.equal(mock.data[RECORDS_KEY].length, 1);
  assert.equal((await api.send({ type: 'status' }, popupSender())).data.unlocked, false);
});

test('manual lock requested during remove storage.set is serialized after the write', async () => {
  const mock = makeChrome();
  const api = await loadBackground(mock);
  await setupVault(api);
  const saved = await api.send({ type: 'save', item: { kind: 'login', label: 'Remove me', username: '', secret: 'secret' } }, webSender());
  let release;
  const enteredSet = mock.gateNextSet(new Promise(resolve => { release = resolve; }));
  const remove = api.send({ type: 'remove', id: saved.data.id }, popupSender());
  await enteredSet;
  const lock = api.send({ type: 'lock' }, popupSender());
  release();
  const [removeResponse, lockResponse] = await Promise.all([remove, lock]);
  assert.equal(removeResponse.ok, true, removeResponse.error);
  assert.equal(lockResponse.ok, true, lockResponse.error);
  assert.deepEqual(mock.data[RECORDS_KEY], []);
  assert.equal((await api.send({ type: 'status' }, popupSender())).data.unlocked, false);
});

test('automatic expiry during save storage.set rolls back the write', async () => {
  const realNow = Date.now;
  let now = realNow();
  Date.now = () => now;
  const mock = makeChrome();
  const api = await loadBackground(mock);
  Date.now = realNow;
  await setupVault(api);
  let release;
  const enteredSet = mock.gateNextSet(new Promise(resolve => { release = resolve; }));
  const save = api.send({ type: 'save', item: { kind: 'login', label: 'Expired save', username: '', secret: 'secret' } }, webSender());
  await enteredSet;
  now += 300_001;
  release();
  const response = await save;
  assert.equal(response.ok, false);
  assert.match(response.error, /locked/i);
  assert.deepEqual(mock.data[RECORDS_KEY], []);
});

test('automatic expiry during remove storage.set restores the removed record', async () => {
  const realNow = Date.now;
  let now = realNow();
  Date.now = () => now;
  const mock = makeChrome();
  const api = await loadBackground(mock);
  Date.now = realNow;
  await setupVault(api);
  const saved = await api.send({ type: 'save', item: { kind: 'login', label: 'Keep me', username: '', secret: 'secret' } }, webSender());
  const before = structuredClone(mock.data[RECORDS_KEY]);
  let release;
  const enteredSet = mock.gateNextSet(new Promise(resolve => { release = resolve; }));
  const remove = api.send({ type: 'remove', id: saved.data.id }, popupSender());
  await enteredSet;
  now += 300_001;
  release();
  const response = await remove;
  assert.equal(response.ok, false);
  assert.match(response.error, /locked/i);
  assert.deepEqual(mock.data[RECORDS_KEY], before);
});

test('a service-worker restart keeps an unlocked session until its deadline', async () => {
  const mock = makeChrome();
  const first = await loadBackground(mock);
  await setupVault(first);
  await first.send({ type: 'save', item: { kind: 'login', label: 'Survives', username: '', secret: 'kept' } }, webSender());
  assert.ok(mock.sessionData[SESSION_KEY]);
  assert.equal(JSON.stringify(mock.data).includes(mock.sessionData[SESSION_KEY].master), false);

  const restarted = await loadBackground(mock);
  const status = await restarted.send({ type: 'status' }, popupSender());
  assert.equal(status.ok, true, status.error);
  assert.equal(status.data.unlocked, true);
  assert.equal((await restarted.send({ type: 'fill', kind: 'login' }, webSender())).data.secret, 'kept');
  await restarted.send({ type: 'lock' }, popupSender());
  assert.equal(mock.sessionData[SESSION_KEY], undefined);
  await first.send({ type: 'lock' }, popupSender());
});

test('a restart after manual lock, expiry, or a tampered session is locked', async () => {
  const mock = makeChrome();
  const first = await loadBackground(mock);
  await setupVault(first);
  const saved = structuredClone(mock.sessionData[SESSION_KEY]);
  await first.send({ type: 'lock' }, popupSender());
  assert.equal((await (await loadBackground(mock)).send({ type: 'status' }, popupSender())).data.unlocked, false);

  mock.sessionData[SESSION_KEY] = { ...saved, deadline: Date.now() - 1 };
  assert.equal((await (await loadBackground(mock)).send({ type: 'status' }, popupSender())).data.unlocked, false);
  assert.equal(mock.sessionData[SESSION_KEY], undefined);

  mock.sessionData[SESSION_KEY] = { ...saved, master: btoa(String.fromCharCode(...new Uint8Array(32))) };
  assert.equal((await (await loadBackground(mock)).send({ type: 'status' }, popupSender())).data.unlocked, false);
  assert.equal(mock.sessionData[SESSION_KEY], undefined);

  mock.sessionData[SESSION_KEY] = { ...saved, deadline: Date.now() + 24 * 60 * 60 * 1000 };
  const extended = await loadBackground(mock);
  assert.equal((await extended.send({ type: 'status' }, popupSender())).data.unlocked, true);
  assert.ok(mock.sessionData[SESSION_KEY].deadline <= Date.now() + 300_000);
  await extended.send({ type: 'lock' }, popupSender());
});

test('fill is blocked on insecure http origins except loopback', async () => {
  const mock = makeChrome();
  const api = await loadBackground(mock);
  await setupVault(api);
  for (const url of ['http://example.com/login', 'http://localhost:8080/login']) {
    assert.equal((await api.send({ type: 'save', item: { kind: 'login', label: 'Plain', username: '', secret: url } }, webSender(url))).ok, true);
  }
  const insecure = webSender('http://example.com/login');
  assert.deepEqual((await api.send({ type: 'has-match', kind: 'login' }, insecure)).data, { hasMatch: true, unlocked: true, insecureFill: true });
  assert.match((await api.send({ type: 'fill', kind: 'login' }, insecure)).error, /insecure http/i);
  const loopback = webSender('http://localhost:8080/login');
  assert.equal((await api.send({ type: 'has-match', kind: 'login' }, loopback)).data.insecureFill, false);
  assert.equal((await api.send({ type: 'fill', kind: 'login' }, loopback)).data.secret, 'http://localhost:8080/login');
  await api.send({ type: 'lock' }, popupSender());
});

test('unlock migrates a v2 vault to the single-derivation v3 key schedule', async () => {
  const passphrase = 'correct horse battery staple';
  const salt = new Uint8Array(16).fill(3);
  const keys = await deriveVaultKeys(passphrase, salt);
  const record = await createEncryptedVaultRecord(keys, {
    id: 'v2-record', kind: 'api-key', label: 'V2', origin: 'https://example.com', username: '', secret: 'v2-secret'
  });
  const mock = makeChrome({
    [CONFIG_KEY]: {
      version: 2,
      salt: bytesToBase64(salt),
      verifier: await encryptSecret(keys.encryptionKey, 'otter-vault-ready', 'https://otter.local'),
      autoLockMinutes: 5,
      kdf: { version: 1, name: 'PBKDF2', hash: 'SHA-256', iterations: 310000, saltBytes: 16 }
    },
    [RECORDS_KEY]: [record]
  });
  const api = await loadBackground(mock);
  const response = await api.send({ type: 'unlock', passphrase }, popupSender());
  assert.equal(response.ok, true, response.error);
  assert.equal(mock.data[CONFIG_KEY].version, 3);
  assert.deepEqual(mock.data[CONFIG_KEY].kdf, V3_KDF);
  assert.notDeepEqual(mock.data[RECORDS_KEY][0].encrypted, record.encrypted);
  assert.equal((await api.send({ type: 'fill', kind: 'api-key' }, webSender())).data.secret, 'v2-secret');
  await api.send({ type: 'lock' }, popupSender());
  assert.equal((await api.send({ type: 'unlock', passphrase }, popupSender())).ok, true);
  await api.send({ type: 'lock' }, popupSender());
});

test('unlock migrates v1 data and persists explicit KDF parameters', async () => {
  const passphrase = 'correct horse battery staple';
  const salt = new Uint8Array(16).fill(4);
  const keys = await deriveVaultKeys(passphrase, salt);
  const origin = 'https://example.com';
  const initial = {
    [CONFIG_KEY]: {
      version: 1,
      salt: bytesToBase64(salt),
      verifier: await encryptSecret(keys.encryptionKey, 'otter-vault-ready', 'https://otter.local'),
      autoLockMinutes: 5
    },
    [RECORDS_KEY]: [{
      id: 'legacy-1', kind: 'login', label: 'Legacy', origin, username: 'old',
      encrypted: await encryptSecret(keys.encryptionKey, 'legacy-secret', origin),
      createdAt: '2025-01-01T00:00:00.000Z'
    }]
  };
  const mock = makeChrome(initial);
  const api = await loadBackground(mock);
  const response = await api.send({ type: 'unlock', passphrase }, popupSender());
  assert.equal(response.ok, true, response.error);
  assert.equal(mock.data[CONFIG_KEY].version, 3);
  assert.deepEqual(mock.data[CONFIG_KEY].kdf, V3_KDF);
  assert.notEqual(mock.data[CONFIG_KEY].salt, bytesToBase64(salt));
  assert.equal(JSON.stringify(mock.data[RECORDS_KEY]).includes('Legacy'), false);
  await api.send({ type: 'lock' }, popupSender());
});

test('manual lock requested during migration commit runs after a consistent unlock write', async () => {
  const passphrase = 'correct horse battery staple';
  const salt = new Uint8Array(16).fill(6);
  const keys = await deriveVaultKeys(passphrase, salt);
  const mock = makeChrome({
    [CONFIG_KEY]: {
      version: 1,
      salt: bytesToBase64(salt),
      verifier: await encryptSecret(keys.encryptionKey, 'otter-vault-ready', 'https://otter.local'),
      autoLockMinutes: 5
    },
    [RECORDS_KEY]: []
  });
  const api = await loadBackground(mock);
  let release;
  const enteredCommit = mock.gateSetNumber(2, new Promise(resolve => { release = resolve; }));
  const unlock = api.send({ type: 'unlock', passphrase }, popupSender());
  await enteredCommit;
  const lock = api.send({ type: 'lock' }, popupSender());
  release();
  const [unlockResponse, lockResponse] = await Promise.all([unlock, lock]);
  assert.equal(unlockResponse.ok, true, unlockResponse.error);
  assert.equal(lockResponse.ok, true, lockResponse.error);
  assert.equal(mock.data[CONFIG_KEY].version, 3);
  assert.equal(mock.data[MIGRATION_KEY], undefined);
  assert.equal((await api.send({ type: 'status' }, popupSender())).data.unlocked, false);
});

test('failed or interrupted v1 migration retains a journal and succeeds on retry', async () => {
  const passphrase = 'correct horse battery staple';
  const salt = new Uint8Array(16).fill(5);
  const keys = await deriveVaultKeys(passphrase, salt);
  const origin = 'https://example.com';
  const legacyConfig = {
    version: 1,
    salt: bytesToBase64(salt),
    verifier: await encryptSecret(keys.encryptionKey, 'otter-vault-ready', 'https://otter.local'),
    autoLockMinutes: 5
  };
  const legacyRecords = [{
    id: 'legacy-retry', kind: 'login', label: 'Legacy retry', origin, username: 'old',
    encrypted: await encryptSecret(keys.encryptionKey, 'legacy-secret', origin),
    createdAt: '2025-01-01T00:00:00.000Z'
  }];
  const mock = makeChrome({ [CONFIG_KEY]: legacyConfig, [RECORDS_KEY]: legacyRecords });
  const api = await loadBackground(mock);
  mock.failSetNumber(2, new Error('simulated interrupted commit'), values => ({ [CONFIG_KEY]: values[CONFIG_KEY] }));
  const failed = await api.send({ type: 'unlock', passphrase }, popupSender());
  assert.equal(failed.ok, false);
  assert.ok(mock.data[MIGRATION_KEY]);
  assert.equal(mock.data[MIGRATION_KEY].config.version, 1);
  assert.equal(mock.data[MIGRATION_KEY].records[0].label, 'Legacy retry');

  const retried = await api.send({ type: 'unlock', passphrase }, popupSender());
  assert.equal(retried.ok, true, retried.error);
  assert.equal(mock.data[CONFIG_KEY].version, 3);
  assert.equal(mock.data[MIGRATION_KEY], undefined);
  assert.equal(JSON.stringify(mock.data[RECORDS_KEY]).includes('Legacy retry'), false);
  assert.equal((await api.send({ type: 'fill', kind: 'login' }, webSender())).data.secret, 'legacy-secret');
});

test('rejects config and record version inconsistency before migration', async () => {
  const passphrase = 'correct horse battery staple';
  const salt = new Uint8Array(16).fill(7);
  const keys = await deriveVaultKeys(passphrase, salt);
  const mock = makeChrome({
    [CONFIG_KEY]: {
      version: 1,
      salt: bytesToBase64(salt),
      verifier: await encryptSecret(keys.encryptionKey, 'otter-vault-ready', 'https://otter.local'),
      autoLockMinutes: 5
    },
    [RECORDS_KEY]: [{
      version: 2,
      id: 'already-new',
      originIndex: 'index',
      encrypted: await encryptSecret(keys.encryptionKey, 'not-a-record', 'https://example.com')
    }]
  });
  const api = await loadBackground(mock);
  const response = await api.send({ type: 'unlock', passphrase }, popupSender());
  assert.equal(response.ok, false);
  assert.match(response.error, /legacy|record/i);
});

test('rejects invalid persisted KDF parameters before deriving a key', async () => {
  const mock = makeChrome({
    [CONFIG_KEY]: { version: 2, salt: 'AAAA', verifier: {}, autoLockMinutes: 5, kdf: { version: 1, name: 'PBKDF2', hash: 'SHA-1', iterations: 1, saltBytes: 3 } },
    [RECORDS_KEY]: []
  });
  const api = await loadBackground(mock);
  const response = await api.send({ type: 'unlock', passphrase: 'correct horse battery staple' }, popupSender());
  assert.equal(response.ok, false);
  assert.match(response.error, /configuration|KDF/i);
});

test('popup can choose a 5, 15, or 30 minute auto-lock that survives worker restarts', async () => {
  const realNow = Date.now;
  let now = realNow();
  Date.now = () => now;
  try {
    const mock = makeChrome();
    const api = await loadBackground(mock);
    await setupVault(api);
    assert.equal((await api.send({ type: 'status' }, popupSender())).data.autoLockMinutes, 5);
    assert.match((await api.send({ type: 'set-auto-lock', minutes: 60 }, popupSender())).error, /auto-lock/i);
    assert.match((await api.send({ type: 'set-auto-lock', minutes: 30 }, webSender())).error, /not allowed/i);

    const changed = await api.send({ type: 'set-auto-lock', minutes: 30 }, popupSender());
    assert.equal(changed.ok, true, changed.error);
    assert.equal(mock.data[CONFIG_KEY].autoLockMinutes, 30);
    assert.equal(mock.sessionData[SESSION_KEY].deadline, now + 30 * 60_000);

    now += 20 * 60_000;
    const restarted = await loadBackground(mock);
    const status = await restarted.send({ type: 'status' }, popupSender());
    assert.equal(status.data.unlocked, true, 'a 30 minute session is still open after 20 idle minutes');
    assert.equal(status.data.autoLockMinutes, 30);

    await restarted.send({ type: 'set-auto-lock', minutes: 5 }, popupSender());
    now += 5 * 60_000 + 1;
    assert.equal((await restarted.send({ type: 'status' }, popupSender())).data.unlocked, false);
    assert.match((await restarted.send({ type: 'set-auto-lock', minutes: 15 }, popupSender())).error, /locked/i);
    await api.send({ type: 'lock' }, popupSender());
  } finally {
    Date.now = realNow;
  }
});
