import {
  computeOriginIndex,
  createEncryptedVaultRecord,
  decryptSecret,
  decryptVaultRecord,
  deriveMasterSecret,
  deriveVaultKeys,
  encryptSecret,
  importVaultKeys,
  matchesOrigin
} from './lib/crypto-vault.js';
import { AUTO_LOCK_MINUTES, authorizeRequest, trustedSenderOrigin } from './lib/request-security.js';
import { createSessionLock } from './lib/session-lock.js';
import { GOOGLE_WEB_CLIENT_ID, TEAMS_API } from './lib/team-config.js';
import { createTeamsService } from './lib/team-service.js';

const CONFIG_KEY = 'otterVaultConfig';
const RECORDS_KEY = 'otterVaultRecords';
const MIGRATION_KEY = 'otterVaultMigration';
const SESSION_KEY = 'otterVaultSession';
const VERIFIER_ORIGIN = 'https://otter.local';
const CLIPBOARD_KEY = 'otterVaultClipboard';
const CLIPBOARD_ALARM = 'otter-clear-clipboard';
// how long a copied secret may sit in the clipboard before Otter wipes it
const CLIPBOARD_SECONDS = Object.freeze({ 'api-key': 300, login: 60 });
const MAX_COPY_FAILURES = 5;
const DEFAULT_AUTO_LOCK_MINUTES = 5;
const LEGACY_KDF = Object.freeze({ version: 1, name: 'PBKDF2', hash: 'SHA-256', iterations: 310_000, saltBytes: 16 });
const KDF = Object.freeze({ version: 2, name: 'PBKDF2', hash: 'SHA-256', iterations: 600_000, saltBytes: 16, split: 'HKDF-SHA-256' });
let vaultKeys = null;
let vaultMaster = null;
let mutationTail = Promise.resolve();
let sessionWrites = Promise.resolve();
let restoring = null;
let copyFailures = 0;

const session = createSessionLock({
  timeoutMs: DEFAULT_AUTO_LOCK_MINUTES * 60_000,
  onLock() {
    vaultKeys = null;
    vaultMaster = null;
    teams.clear();
    persistSession();
  },
  onDeadline() {
    persistSession();
  }
});

// Chrome stops idle MV3 service workers after ~30 seconds, which would wipe a memory-only key
// long before the five-minute auto-lock. chrome.storage.session is held in memory (never written
// to disk), cleared when the browser exits, and readable only by trusted extension contexts, so
// the master secret and deadline live there while unlocked. Writes are chained and read state at
// execution time, so the last scheduled write always reflects the latest lock state.
function persistSession() {
  sessionWrites = sessionWrites.then(() => {
    const store = chrome.storage.session;
    if (!store) return;
    if (!vaultMaster || !session.isUnlocked()) return store.remove(SESSION_KEY);
    return store.set({ [SESSION_KEY]: { master: vaultMaster, deadline: session.capture().deadline } });
  }).catch(() => {});
  return sessionWrites;
}

async function restoreSession() {
  const store = chrome.storage.session;
  if (!store) return;
  await store.setAccessLevel?.({ accessLevel: 'TRUSTED_CONTEXTS' });
  const saved = (await store.get([SESSION_KEY]))[SESSION_KEY];
  if (!saved) return;
  try {
    if (!exactObjectKeys(saved, ['master', 'deadline']) || typeof saved.deadline !== 'number') throw new Error('Invalid session');
    const { config } = await getState();
    if (config?.version !== 3) throw new Error('Session does not match vault');
    const keys = await importVaultKeys(base64ToBytes(saved.master, 'session'));
    if (await decryptSecret(keys.encryptionKey, config.verifier, VERIFIER_ORIGIN) !== 'otter-vault-ready') {
      throw new Error('Session does not match vault');
    }
    vaultKeys = keys;
    vaultMaster = saved.master;
    session.setTimeoutMs(autoLockMinutesOf(config) * 60_000);
    session.unlock(saved.deadline);
  } catch {
    vaultKeys = null;
    vaultMaster = null;
    await store.remove(SESSION_KEY);
  }
}

function autoLockMinutesOf(config) {
  return AUTO_LOCK_MINUTES.includes(config?.autoLockMinutes) ? config.autoLockMinutes : DEFAULT_AUTO_LOCK_MINUTES;
}

function insecureOrigin(origin) {
  const { protocol, hostname } = new URL(origin);
  return protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(hostname);
}

function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value, name = 'vault configuration salt') {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`Invalid ${name}`);
  }
  const binary = atob(value);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function validEncryptedValue(value) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    value.algorithm === 'AES-256-GCM' && typeof value.iv === 'string' && typeof value.ciphertext === 'string';
}

function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Invalid vault configuration');
  if (![1, 2, 3].includes(config.version)) throw new Error('Unsupported vault version');
  const expectedKeys = config.version === 1
    ? ['version', 'salt', 'verifier', 'autoLockMinutes']
    : ['version', 'salt', 'verifier', 'autoLockMinutes', 'kdf'];
  if (Object.keys(config).length !== expectedKeys.length || Object.keys(config).some(key => !expectedKeys.includes(key))) {
    throw new Error('Invalid vault configuration');
  }
  if (config.autoLockMinutes !== undefined && !AUTO_LOCK_MINUTES.includes(config.autoLockMinutes)) {
    throw new Error('Invalid vault configuration timeout');
  }
  const salt = base64ToBytes(config.salt);
  if (salt.length !== KDF.saltBytes || !validEncryptedValue(config.verifier)) throw new Error('Invalid vault configuration');
  const expectedKdf = config.version === 3 ? KDF : LEGACY_KDF;
  if (config.version !== 1) {
    const kdf = config.kdf;
    if (!kdf || typeof kdf !== 'object' || Object.keys(expectedKdf).some(key => kdf[key] !== expectedKdf[key]) ||
        Object.keys(kdf).length !== Object.keys(expectedKdf).length) {
      throw new Error('Invalid vault KDF configuration');
    }
  }
  return { salt, iterations: expectedKdf.iterations };
}

async function deriveForConfig(config, passphrase) {
  const { salt, iterations } = validateConfig(config);
  if (config.version !== 3) return { keys: await deriveVaultKeys(passphrase, salt, iterations), master: null };
  const master = await deriveMasterSecret(passphrase, salt, iterations);
  return { keys: await importVaultKeys(master), master };
}

function exactObjectKeys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === expected.length && Object.keys(value).every(key => expected.includes(key));
}

function validateLegacyRecord(record) {
  const keys = ['id', 'kind', 'label', 'origin', 'username', 'encrypted', 'createdAt'];
  if (!exactObjectKeys(record, keys) || typeof record.id !== 'string' || !['login', 'api-key'].includes(record.kind) ||
      typeof record.label !== 'string' || typeof record.origin !== 'string' || typeof record.username !== 'string' ||
      !validEncryptedValue(record.encrypted) || typeof record.createdAt !== 'string' || !Number.isFinite(Date.parse(record.createdAt))) {
    throw new Error('Invalid legacy vault record');
  }
  try {
    const url = new URL(record.origin);
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== record.origin) throw new Error();
  } catch {
    throw new Error('Invalid legacy vault record origin');
  }
}

function validateEncryptedRecord(record) {
  if (!exactObjectKeys(record, ['version', 'id', 'originIndex', 'encrypted']) || record.version !== 2 ||
      typeof record.id !== 'string' || typeof record.originIndex !== 'string' || !validEncryptedValue(record.encrypted)) {
    throw new Error('Invalid encrypted vault record');
  }
}

function validateStateConsistency(config, records) {
  if (!config) {
    if (records.length) throw new Error('Vault records exist without configuration');
    return;
  }
  validateConfig(config);
  for (const record of records) {
    if (config.version === 1) validateLegacyRecord(record);
    else validateEncryptedRecord(record);
  }
}

async function getState() {
  const stored = await chrome.storage.local.get([CONFIG_KEY, RECORDS_KEY]);
  const records = stored[RECORDS_KEY] || [];
  if (!Array.isArray(records)) throw new Error('Invalid vault record storage');
  const config = stored[CONFIG_KEY] || null;
  validateStateConsistency(config, records);
  return { config, records };
}

function publicRecord(payload) {
  const { secret, ...metadata } = payload;
  return metadata;
}

function requireUnlocked() {
  if (!session.isUnlocked() || !vaultKeys) throw new Error('Vault is locked');
  return { keys: vaultKeys, token: session.capture() };
}

function serializeMutation(work) {
  const result = mutationTail.then(work, work);
  mutationTail = result.catch(() => {});
  return result;
}

async function commitRecordsForSession(previous, next, token) {
  await chrome.storage.local.set({ [RECORDS_KEY]: next });
  try {
    session.assertCurrent(token);
  } catch (error) {
    await chrome.storage.local.set({ [RECORDS_KEY]: previous });
    const restored = await chrome.storage.local.get([RECORDS_KEY]);
    if (JSON.stringify(restored[RECORDS_KEY] || []) !== JSON.stringify(previous)) {
      throw new Error('Vault locked and record rollback verification failed');
    }
    throw error;
  }
}

const HINT_PREFIX = /^(?:cf[ua]t_|vck_|sb_secret_|sbp_|sk-ant-(?:api|admin)\d{2}-|sk-(?:proj|svcacct|admin)-|(?:sk|rk|pk)_(?:live|test)_|github_pat_|gh[pousr]_|xox[abposr]-|glpat-|hf_|gsk_|npm_|r8_|AIza|sk-)/;

// Enough to match a key against the provider's own key list (they show the last few characters),
// never enough to use it. Passwords get no hint.
export function secretHint(kind, secret) {
  if (kind !== 'api-key' || typeof secret !== 'string' || secret.length < 20) return '';
  return `${secret.match(HINT_PREFIX)?.[0] || '••••'}…${secret.slice(-4)}`;
}

// Teams: shared vaults synced through otter-teams. Its keys are sealed under this vault's master
// secret, so Teams opens and closes with the vault.
const teams = createTeamsService({
  storage: chrome.storage.local,
  getMaster() {
    requireUnlocked();
    return base64ToBytes(vaultMaster, 'session');
  },
  base: TEAMS_API,
  clientId: GOOGLE_WEB_CLIENT_ID,
  fetch: (...args) => fetch(...args),
  launchWebAuthFlow: url => chrome.identity.launchWebAuthFlow({ url, interactive: true }),
  redirectUrl: chrome.identity?.getRedirectURL?.() || '',
  hint: (kind, secret) => secretHint(kind, secret)
});

// Shared keys never hold up the popup: if Teams is slow or offline, the list shows without them.
async function sharedRecords() {
  try {
    return await Promise.race([teams.publicRecords(), new Promise(resolve => setTimeout(() => resolve(null), 4000))]) ?? [];
  } catch {
    return [];
  }
}

async function decryptPublicRecords(keys, records, token) {
  const output = [];
  for (const record of records) {
    const payload = await decryptVaultRecord(keys, record);
    session.assertCurrent(token);
    output.push({ ...publicRecord(payload), hint: secretHint(payload.kind, payload.secret) });
  }
  session.assertCurrent(token);
  return output;
}

async function setup(passphrase) {
  return serializeMutation(async () => {
    const mark = session.mark();
    const { config } = await getState();
    session.assertGeneration(mark);
    if (config) throw new Error('Vault is already configured');
    const salt = crypto.getRandomValues(new Uint8Array(KDF.saltBytes));
    const master = await deriveMasterSecret(passphrase, salt, KDF.iterations);
    const keys = await importVaultKeys(master);
    session.assertGeneration(mark);
    const verifier = await encryptSecret(keys.encryptionKey, 'otter-vault-ready', VERIFIER_ORIGIN);
    session.assertGeneration(mark);
    await chrome.storage.local.set({
      [CONFIG_KEY]: { version: 3, salt: bytesToBase64(salt), verifier, autoLockMinutes: 5, kdf: { ...KDF } },
      [RECORDS_KEY]: []
    });
    session.assertGeneration(mark);
    vaultKeys = keys;
    vaultMaster = bytesToBase64(master);
    session.setTimeoutMs(DEFAULT_AUTO_LOCK_MINUTES * 60_000);
    session.unlock();
    return { configured: true, unlocked: true, records: [], recordCount: 0, autoLockMinutes: DEFAULT_AUTO_LOCK_MINUTES };
  });
}

async function recoverInterruptedMigration(mark) {
  const stored = await chrome.storage.local.get([MIGRATION_KEY]);
  session.assertGeneration(mark);
  const journal = stored[MIGRATION_KEY];
  if (!journal) return;
  if (!exactObjectKeys(journal, ['version', 'config', 'records']) || journal.version !== 1 || !Array.isArray(journal.records)) {
    throw new Error('Invalid vault migration journal');
  }
  validateStateConsistency(journal.config, journal.records);
  if (journal.config.version === 3) throw new Error('Invalid vault migration journal');
  await chrome.storage.local.set({ [CONFIG_KEY]: journal.config, [RECORDS_KEY]: journal.records });
  session.assertGeneration(mark);
  const restored = await getState();
  session.assertGeneration(mark);
  if (JSON.stringify(restored.config) !== JSON.stringify(journal.config) || JSON.stringify(restored.records) !== JSON.stringify(journal.records)) {
    throw new Error('Vault migration recovery verification failed');
  }
  await chrome.storage.local.remove(MIGRATION_KEY);
  session.assertGeneration(mark);
}

// Re-encrypts a v1/v2 vault under the v3 key schedule with a fresh salt. The journal keeps the
// legacy state so an interrupted commit is restored on the next unlock.
async function migrateLegacyVault(config, records, legacyKeys, passphrase, mark) {
  validateStateConsistency(config, records);
  const salt = crypto.getRandomValues(new Uint8Array(KDF.saltBytes));
  const master = await deriveMasterSecret(passphrase, salt, KDF.iterations);
  session.assertGeneration(mark);
  const keys = await importVaultKeys(master);
  const migrated = [];
  for (const record of records) {
    const item = config.version === 1
      ? { ...record, encrypted: undefined, secret: await decryptSecret(legacyKeys.encryptionKey, record.encrypted, record.origin) }
      : await decryptVaultRecord(legacyKeys, record);
    session.assertGeneration(mark);
    migrated.push(await createEncryptedVaultRecord(keys, item));
    session.assertGeneration(mark);
  }
  const verifier = await encryptSecret(keys.encryptionKey, 'otter-vault-ready', VERIFIER_ORIGIN);
  const nextConfig = { version: 3, salt: bytesToBase64(salt), verifier, autoLockMinutes: autoLockMinutesOf(config), kdf: { ...KDF } };
  const journal = { version: 1, config, records };
  session.assertGeneration(mark);
  await chrome.storage.local.set({ [MIGRATION_KEY]: journal });
  session.assertGeneration(mark);
  await chrome.storage.local.set({ [CONFIG_KEY]: nextConfig, [RECORDS_KEY]: migrated });
  session.assertGeneration(mark);
  const committed = await getState();
  session.assertGeneration(mark);
  if (JSON.stringify(committed.config) !== JSON.stringify(nextConfig) || JSON.stringify(committed.records) !== JSON.stringify(migrated)) {
    throw new Error('Vault migration commit verification failed');
  }
  for (const record of committed.records) {
    await decryptVaultRecord(keys, record);
    session.assertGeneration(mark);
  }
  await chrome.storage.local.remove(MIGRATION_KEY);
  session.assertGeneration(mark);
  return { ...committed, keys, master };
}

async function unlock(passphrase) {
  return serializeMutation(async () => {
    const mark = session.mark();
    await recoverInterruptedMigration(mark);
    session.assertGeneration(mark);
    let { config, records } = await getState();
    session.assertGeneration(mark);
    if (!config) throw new Error('Vault is not configured');
    let { keys: candidate, master } = await deriveForConfig(config, passphrase);
    session.assertGeneration(mark);
    let result;
    try {
      result = await decryptSecret(candidate.encryptionKey, config.verifier, VERIFIER_ORIGIN);
    } catch {
      session.assertGeneration(mark);
      throw new Error('Incorrect passphrase');
    }
    session.assertGeneration(mark);
    if (result !== 'otter-vault-ready') throw new Error('Incorrect passphrase');
    if (config.version !== 3) {
      ({ config, records, keys: candidate, master } = await migrateLegacyVault(config, records, candidate, passphrase, mark));
    }
    session.assertGeneration(mark);
    vaultKeys = candidate;
    vaultMaster = bytesToBase64(master);
    session.setTimeoutMs(autoLockMinutesOf(config) * 60_000);
    session.unlock();
    let token = session.capture();
    const publicRecords = await decryptPublicRecords(candidate, records, token);
    session.assertCurrent(token);
    token = session.touch(token);
    session.assertCurrent(token);
    return { configured: true, unlocked: true, records: publicRecords, recordCount: records.length, autoLockMinutes: autoLockMinutesOf(config) };
  });
}

async function saveItem(item) {
  return serializeMutation(async () => {
    let { keys, token } = requireUnlocked();
    const { records } = await getState();
    session.assertCurrent(token);
    const record = await createEncryptedVaultRecord(keys, item);
    session.assertCurrent(token);
    const next = [record, ...records];
    session.assertCurrent(token);
    await commitRecordsForSession(records, next, token);
    const payload = await decryptVaultRecord(keys, record);
    session.assertCurrent(token);
    token = session.touch(token);
    session.assertCurrent(token);
    return publicRecord(payload);
  });
}

async function fillFor(origin, kind) {
  if (insecureOrigin(origin)) throw new Error('Filling is blocked on insecure http pages');
  let { keys, token } = requireUnlocked();
  const { records } = await getState();
  session.assertCurrent(token);
  const originIndex = await computeOriginIndex(keys.indexKey, origin);
  session.assertCurrent(token);
  const matches = [];
  for (const record of records.filter(item => item.originIndex === originIndex)) {
    const payload = await decryptVaultRecord(keys, record);
    session.assertCurrent(token);
    if (!matchesOrigin(payload.origin, origin)) throw new Error('Origin verification failed');
    if (payload.kind === kind) matches.push(payload);
  }
  if (!matches.length) {
    const shared = await teams.matches(origin, kind).catch(() => []);
    session.assertCurrent(token);
    token = session.touch(token);
    session.assertCurrent(token);
    if (!shared.length) return null;
    shared.sort((a, b) => Date.parse(b.entry.updatedAt) - Date.parse(a.entry.updatedAt));
    const { team, entry } = shared[0];
    teams.noteFill(team.id, entry.payload.id).catch(() => {});
    const { id, kind: sharedKind, label, origin: savedOrigin, username, secret, createdAt } = entry.payload;
    if (!matchesOrigin(savedOrigin, origin)) throw new Error('Origin verification failed');
    return { id, kind: sharedKind, label, origin: savedOrigin, username, secret, createdAt, team: team.name };
  }
  matches.sort((a, b) => {
    const byDate = Date.parse(b.createdAt) - Date.parse(a.createdAt);
    return Number.isFinite(byDate) && byDate !== 0 ? byDate : String(b.id).localeCompare(String(a.id));
  });
  token = session.touch(token);
  session.assertCurrent(token);
  return matches[0];
}

async function removeItem(id) {
  return serializeMutation(async () => {
    let { keys, token } = requireUnlocked();
    const { records } = await getState();
    session.assertCurrent(token);
    const next = records.filter(record => record.id !== id);
    session.assertCurrent(token);
    await commitRecordsForSession(records, next, token);
    const publicRecords = await decryptPublicRecords(keys, next, token);
    session.assertCurrent(token);
    token = session.touch(token);
    session.assertCurrent(token);
    return publicRecords;
  });
}

// Lets the popup confirm a saved secret matches the original without ever showing it.
// Both sides are hashed first so the comparison takes the same time wherever they differ.
async function verifyItem(id, candidate) {
  let { keys, token } = requireUnlocked();
  const { records } = await getState();
  session.assertCurrent(token);
  const record = records.find(item => item.id === id);
  if (!record) throw new Error('That record is no longer in the vault');
  const payload = await decryptVaultRecord(keys, record);
  session.assertCurrent(token);
  const digest = async value => new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
  const [saved, given] = await Promise.all([digest(payload.secret), digest(candidate)]);
  let difference = 0;
  for (let i = 0; i < saved.length; i++) difference |= saved[i] ^ given[i];
  token = session.touch(token);
  session.assertCurrent(token);
  return { match: difference === 0 };
}

const sha256 = async value => bytesToBase64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))));

// Copying hands the plaintext to the popup, so it needs the passphrase again, not just an unlocked
// vault: someone at an unlocked computer still can't lift keys. Repeated wrong answers lock the vault.
async function checkCopyPassphrase(config, passphrase, token) {
  const { keys: candidate } = await deriveForConfig(config, passphrase);
  session.assertCurrent(token);
  let verified = false;
  try { verified = await decryptSecret(candidate.encryptionKey, config.verifier, VERIFIER_ORIGIN) === 'otter-vault-ready'; } catch {}
  if (!verified) {
    copyFailures += 1;
    if (copyFailures >= MAX_COPY_FAILURES) {
      copyFailures = 0;
      session.lock('copy-failures');
      await persistSession();
      throw new Error('Too many wrong passphrases. The vault is locked.');
    }
    throw new Error('Incorrect passphrase');
  }
  copyFailures = 0;
}

async function copyItem(id, passphrase) {
  const { token } = requireUnlocked();
  const { config, records } = await getState();
  session.assertCurrent(token);
  const record = records.find(item => item.id === id);
  if (!record) throw new Error('That record is no longer in the vault');
  await checkCopyPassphrase(config, passphrase, token);
  const payload = await decryptVaultRecord(vaultKeys, record);
  session.assertCurrent(token);
  return armClipboard(payload);
}

// Same passphrase re-check as a personal copy; the copy is also written to the team's access log.
async function teamCopy(teamId, recordId, passphrase) {
  const { token } = requireUnlocked();
  const { config } = await getState();
  session.assertCurrent(token);
  await checkCopyPassphrase(config, passphrase, token);
  const payload = await teams.secret(teamId, recordId);
  session.assertCurrent(token);
  return armClipboard(payload);
}

// Exporting hands every shared key to the Teams page, so it needs the passphrase again too.
async function teamExport(teamId, passphrase) {
  const { token } = requireUnlocked();
  const { config } = await getState();
  session.assertCurrent(token);
  await checkCopyPassphrase(config, passphrase, token);
  const data = await teams.exportTeam(teamId);
  session.assertCurrent(token);
  return data;
}

async function armClipboard(payload) {
  const clearsInSeconds = CLIPBOARD_SECONDS[payload.kind] || 60;
  // only a hash is kept, so the wipe can tell whether the clipboard still holds this secret
  await chrome.storage.session?.set({ [CLIPBOARD_KEY]: { hash: await sha256(payload.secret) } });
  await chrome.alarms?.create(CLIPBOARD_ALARM, { when: Date.now() + clearsInSeconds * 1000 });
  session.touch(session.capture());
  return { secret: payload.secret, clearsInSeconds };
}

async function clearClipboard() {
  const saved = (await chrome.storage.session.get([CLIPBOARD_KEY]))[CLIPBOARD_KEY];
  await chrome.storage.session.remove(CLIPBOARD_KEY);
  if (!saved?.hash || !chrome.offscreen) return;
  const url = 'offscreen/clipboard.html';
  if (!(await chrome.offscreen.hasDocument?.())) {
    await chrome.offscreen.createDocument({ url, reasons: ['CLIPBOARD'], justification: 'Wipe a copied secret from the clipboard' });
  }
  try {
    // the page's script may still be loading, so give its listener a moment to appear
    for (let attempt = 0; attempt < 10; attempt++) {
      try {
        await chrome.runtime.sendMessage({ target: 'otter-offscreen', type: 'clear-if-matches', hash: saved.hash });
        break;
      } catch {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
  } finally {
    await chrome.offscreen.closeDocument().catch(() => {});
  }
}

chrome.alarms?.onAlarm.addListener(alarm => {
  if (alarm.name === CLIPBOARD_ALARM) clearClipboard().catch(() => {});
});

async function setAutoLock(minutes) {
  return serializeMutation(async () => {
    const { token } = requireUnlocked();
    const { config } = await getState();
    session.assertCurrent(token);
    await chrome.storage.local.set({ [CONFIG_KEY]: { ...config, autoLockMinutes: minutes } });
    session.assertCurrent(token);
    session.setTimeoutMs(minutes * 60_000);
    return { autoLockMinutes: minutes };
  });
}

async function status() {
  const { config, records } = await getState();
  if (!vaultKeys || !session.isUnlocked()) {
    return { configured: Boolean(config), unlocked: false, records: [], recordCount: records.length, autoLockMinutes: autoLockMinutesOf(config), metadataEncrypted: config?.version >= 2 };
  }
  let { keys, token } = requireUnlocked();
  const publicRecords = await decryptPublicRecords(keys, records, token);
  session.assertCurrent(token);
  const shared = await sharedRecords();
  session.assertCurrent(token);
  token = session.touch(token);
  session.assertCurrent(token);
  return { configured: Boolean(config), unlocked: true, records: publicRecords, shared, recordCount: records.length, autoLockMinutes: autoLockMinutesOf(config), metadataEncrypted: config?.version >= 2 };
}

// Copies one of this vault's own keys into a team vault.
async function shareToTeam(teamId, vaultId, personalId, map) {
  const { keys, token } = requireUnlocked();
  const { records } = await getState();
  session.assertCurrent(token);
  const record = records.find(item => item.id === personalId);
  if (!record) throw new Error('That record is no longer in the vault');
  const payload = await decryptVaultRecord(keys, record);
  session.assertCurrent(token);
  const { kind, label, origin, username, secret } = payload;
  return teams.save(teamId, { vaultId, recordId: null, item: { kind, label, origin, username, secret }, map });
}

// Every Teams action needs the vault unlocked, because the device's Teams keys are sealed under it.
async function teamAction(work) {
  const { token } = requireUnlocked();
  const result = await work();
  session.assertCurrent(token);
  session.touch(session.capture());
  return result;
}

async function hasMatch(sender, kind) {
  if (!vaultKeys || !session.isUnlocked()) return { hasMatch: false, unlocked: false, hiddenWhileLocked: true };
  const { keys, token } = requireUnlocked();
  const origin = trustedSenderOrigin(sender);
  const originIndex = await computeOriginIndex(keys.indexKey, origin);
  session.assertCurrent(token);
  const { records } = await getState();
  session.assertCurrent(token);
  let found = false;
  for (const record of records.filter(item => item.originIndex === originIndex)) {
    const payload = await decryptVaultRecord(keys, record);
    session.assertCurrent(token);
    if (!matchesOrigin(payload.origin, origin)) throw new Error('Origin verification failed');
    if (payload.kind === kind) {
      found = true;
      break;
    }
  }
  if (!found) found = (await teams.matches(origin, kind).catch(() => [])).length > 0;
  session.assertCurrent(token);
  const response = { hasMatch: found, unlocked: true, insecureFill: insecureOrigin(origin) };
  session.assertCurrent(token);
  return response;
}

async function handleMessage(rawMessage, sender) {
  const message = authorizeRequest(rawMessage, sender, {
    extensionId: chrome.runtime.id,
    popupUrl: chrome.runtime.getURL('popup/popup.html'),
    teamPageUrl: chrome.runtime.getURL('team/team.html')
  });
  await (restoring ??= restoreSession().catch(() => {}));
  switch (message.type) {
    case 'status': return status();
    case 'setup': return setup(message.passphrase);
    case 'unlock': return unlock(message.passphrase);
    case 'lock': return serializeMutation(async () => {
      session.lock('manual');
      await persistSession();
      return { configured: true, unlocked: false };
    });
    case 'save': return saveItem({ ...message.item, origin: trustedSenderOrigin(sender) });
    case 'fill': return fillFor(trustedSenderOrigin(sender), message.kind);
    case 'remove': return removeItem(message.id);
    case 'verify': return verifyItem(message.id, message.secret);
    case 'copy': return copyItem(message.id, message.passphrase);
    case 'set-auto-lock': return setAutoLock(message.minutes);
    case 'has-match': return hasMatch(sender, message.kind);
    case 'team-copy': return teamCopy(message.teamId, message.recordId, message.passphrase);
    case 'team-export': return teamExport(message.teamId, message.passphrase);
    case 'team-overview':
      if (!vaultKeys || !session.isUnlocked()) return { locked: true };
      return teamAction(() => teams.overview());
    case 'team-sign-in': return teamAction(() => teams.signIn());
    case 'team-sign-out': return teamAction(() => teams.signOut());
    case 'team-create': return teamAction(() => teams.createTeam(message.name));
    case 'team-open': return teamAction(() => teams.detail(message.teamId));
    case 'team-vault-create': return teamAction(() => teams.createVault(message.teamId, message.name));
    case 'team-save': return teamAction(() => teams.save(message.teamId, message));
    case 'team-share': return teamAction(() => shareToTeam(message.teamId, message.vaultId, message.personalId, message.map));
    case 'team-delete': return teamAction(() => teams.remove(message.teamId, message.recordId));
    case 'team-invite': return teamAction(() => teams.invite(message.teamId, message.email, message.role));
    case 'team-invite-cancel': return teamAction(() => teams.cancelInvite(message.teamId, message.inviteId));
    case 'team-accept': return teamAction(() => teams.accept(message.inviteId));
    case 'team-confirm': return teamAction(() => teams.confirm(message.teamId, message.inviteId, message.fingerprint));
    case 'team-remove-member': return teamAction(() => teams.removeMember(message.teamId, message.userId));
    case 'team-remove-device': return teamAction(() => teams.removeDevice(message.teamId, message.userId, message.deviceId));
    case 'team-mark-rotated': return teamAction(() => teams.markRotated(message.teamId, message.recordId, message.secret));
    case 'team-subscribe': return teamAction(() => teams.subscribe(message.teamId));
    case 'team-billing-portal': return teamAction(() => teams.billingPortal(message.teamId));
    case 'team-totp-setup': return teamAction(() => teams.totpSetup());
    case 'team-totp-enable': return teamAction(() => teams.totpEnable(message.code));
    case 'team-totp-verify': return teamAction(() => teams.totpVerify(message.code));
    case 'team-device-request': return teamAction(() => teams.requestDevice(message.teamId));
    case 'team-device-confirm': return teamAction(() => teams.confirmDevice(message.teamId, message.deviceId, message.fingerprint));
    case 'team-device-cancel': return teamAction(() => teams.cancelDevice(message.teamId, message.deviceId));
    case 'team-kit-create': return teamAction(() => teams.createRecoveryKit(message.teamId));
    case 'team-recovery-start': return teamAction(() => teams.startRecovery(message.teamId));
    case 'team-recovery-decide': return teamAction(() => teams.decideRecovery(message.teamId, message.requestId, message.decision));
    case 'team-recovery-finish': return teamAction(() => teams.finishRecovery(message.teamId, message.requestId, message.code));
    default: throw new Error('Unknown Otter Vault request');
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(data => sendResponse({ ok: true, data }))
    .catch(error => sendResponse({ ok: false, error: error.message }));
  return true;
});
