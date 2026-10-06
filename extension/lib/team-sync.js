// The Teams client: talks to the otter-teams Worker and verifies everything it gets back before
// using it. No Chrome APIs here, so the same code runs in the service worker and in tests.
// `pins` is a small plain object the caller persists between runs: the team anchors this device
// joined, the highest record revisions and the last verified access-log head it has seen. With
// it, a server that rolls history back or swaps a team is caught. See docs/teams-phase1.md.
import {
  applyEntry, createEntry, createEvent, eventHash, isAdminDevice, signRecord, signWrap, verifyEvents, verifyMemberChain,
  verifyRecord, verifyWrap, wrapRecipients
} from './team-chain.js';
import {
  decryptName, decryptRecord, deviceRegistrationBody, encryptName, encryptRecord, fingerprint, formatRecoveryCode, generateIdentity,
  generateRecoverySecret, generateTeamKey, googleNonce, importTeamKey, loadIdentity, openRecoveryIdentity, parseRecoveryCode,
  randomId, sealRecoveryIdentity, signJson, unwrapTeamKey, wrapTeamKey
} from './team-crypto.js';

export class TeamsApiError extends Error {
  constructor(status, code, message, body = {}) {
    super(message);
    this.name = 'TeamsApiError';
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

export class TeamsSyncError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'TeamsSyncError';
    this.code = code;
  }
}

export function createApi({ base, fetch: fetchImpl = globalThis.fetch, token = null }) {
  const api = {
    token,
    async request(method, path, body) {
      const headers = { 'Content-Type': 'application/json' };
      if (api.token) headers.Authorization = `Bearer ${api.token}`;
      let response;
      try {
        response = await fetchImpl(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
      } catch {
        throw new TeamsApiError(0, 'offline', 'Could not reach Otter Teams. Check your connection.');
      }
      let data = {};
      try { data = await response.json(); } catch {}
      if (!response.ok) throw new TeamsApiError(response.status, data.error || 'error', data.message || `Request failed (${response.status})`, data);
      return data;
    }
  };
  return api;
}

const stripWrap = ({ by, signature, ...wrap }) => wrap;

// ---- sign-in ----

// Step one: the nonce to put in the Google request, bound to this device's keys.
export async function prepareGoogleSignIn(identity) {
  const salt = randomId('s').slice(2);
  return { salt, nonce: await googleNonce({ deviceId: identity.id, sigPub: identity.sigPub, kxPub: identity.kxPub, salt }) };
}

function emailFromIdToken(idToken) {
  try {
    const payload = JSON.parse(atob(idToken.split('.')[1].replaceAll('-', '+').replaceAll('_', '/')));
    if (typeof payload.email === 'string') return payload.email.trim().toLowerCase();
  } catch {}
  throw new TeamsSyncError('google', 'Google did not return an email address');
}

// Step two: hand the ID token to the server with proof that this device holds its keys.
export async function completeGoogleSignIn(api, identity, { idToken, salt }) {
  const email = emailFromIdToken(idToken);
  const device = { id: identity.id, sigPub: identity.sigPub, kxPub: identity.kxPub };
  const signature = await signJson(identity, deviceRegistrationBody({ email, deviceId: identity.id, sigPub: identity.sigPub, kxPub: identity.kxPub }));
  const session = await api.request('POST', '/auth/google', { idToken, salt, device, signature });
  return { token: session.token, userId: session.userId, email: session.email, totpEnabled: Boolean(session.totpEnabled), mfa: Boolean(session.mfa) };
}

// ---- opening a team ----

function teamPins(pins, teamId) {
  pins.teams ??= {};
  return (pins.teams[teamId] ??= { anchor: null, revisions: {}, eventHead: null });
}

async function fetchAllRecords(api, teamId) {
  const records = [];
  let since = 0;
  for (;;) {
    const page = await api.request('GET', `/teams/${teamId}/records?since=${since}`);
    records.push(...page.records);
    since = page.cursor;
    if (!page.more) return { records, cursor: since };
  }
}

// Loads and verifies one team: member chain (against the pinned anchor), this device's key wrap,
// names, and every record's signature, epoch and revision. Returns everything decrypted.
export async function openTeam(api, identity, teamId, pins) {
  const pin = teamPins(pins, teamId);
  const state = await api.request('GET', `/teams/${teamId}/state`);
  const chain = await verifyMemberChain(state.entries, { anchor: pin.anchor });
  if (!chain.devices.get(identity.id) || chain.devices.get(identity.id).revokedSeq !== null) {
    throw new TeamsSyncError('removed', 'This device is no longer on the team');
  }
  const wrap = state.wraps.find(item => item.epoch === chain.epoch && item.recipientId === identity.id);
  if (!wrap) throw new TeamsSyncError('no-key', 'The team key for this device is missing; ask an admin to re-add the device');
  await verifyWrap(chain, wrap);
  const teamKey = await unwrapTeamKey(identity, stripWrap(wrap), { teamId, epoch: chain.epoch });
  const cryptoKey = await importTeamKey(teamKey);
  const name = await decryptName(cryptoKey, { teamId, kind: 'team', id: teamId, epoch: chain.epoch }, state.team.name);
  const vaults = [];
  for (const vault of state.vaults) {
    vaults.push({ id: vault.id, name: await decryptName(cryptoKey, { teamId, kind: 'vault', id: vault.id, epoch: chain.epoch }, vault.name) });
  }

  const { records: stored, cursor } = await fetchAllRecords(api, teamId);
  const records = new Map();
  for (const record of stored) {
    const { envelope } = record;
    await verifyRecord(chain, envelope, record);
    const seen = pin.revisions[envelope.recordId] || 0;
    if (envelope.revision < seen) throw new TeamsSyncError('rollback', 'The server sent an older version of a key than this device has seen');
    pin.revisions[envelope.recordId] = envelope.revision;
    if (record.deleted) continue;
    const payload = await decryptRecord(cryptoKey, envelope);
    records.set(envelope.recordId, { payload, envelope, updatedBy: record.updatedBy, updatedAt: record.updatedAt });
  }
  pin.anchor = chain.anchor;
  return {
    id: teamId,
    name,
    chain,
    summary: state.team,
    role: chain.users.get(chain.devices.get(identity.id).userId).role,
    admin: isAdminDevice(chain, identity.id),
    teamKey,
    cryptoKey,
    vaults,
    records,
    cursor,
    history: state.entries,
    // things this device may need to act on (see the server's pendingFor)
    deviceRequests: state.deviceRequests || [],
    recoveryKit: state.recoveryKit ?? null,
    recoveryRequests: state.recoveryRequests || []
  };
}

// ---- creating things ----

export async function createTeam(api, identity, session, name) {
  const teamId = randomId('t');
  const teamKey = generateTeamKey();
  const cryptoKey = await importTeamKey(teamKey);
  const entry = await createEntry(null, {
    teamId, op: 'create',
    subject: { userId: session.userId, deviceId: identity.id, sigPub: identity.sigPub, kxPub: identity.kxPub, role: 'owner' }
  }, identity);
  const wrap = await signWrap(identity, await wrapForRecipient(teamKey, teamId, 1, identity));
  const sealedName = await encryptName(cryptoKey, { teamId, kind: 'team', id: teamId, epoch: 1 }, name);
  await api.request('POST', '/teams', { entry, wrap, name: sealedName });
  return teamId;
}

function wrapForRecipient(teamKey, teamId, epoch, recipient) {
  return wrapTeamKey({ teamKey, teamId, epoch, recipientId: recipient.id, recipientKxPub: recipient.kxPub });
}

export async function createVault(api, view, name) {
  const vaultId = randomId('v');
  const sealed = await encryptName(view.cryptoKey, { teamId: view.id, kind: 'vault', id: vaultId, epoch: view.chain.epoch }, name);
  await api.request('POST', `/teams/${view.id}/vaults`, { vaultId, name: sealed });
  return vaultId;
}

// Writes a new or changed record. `payload` is a full record payload (see validateRecordPayload).
export async function saveRecord(api, identity, view, vaultId, payload, pins) {
  const existing = view.records.get(payload.id);
  const pin = teamPins(pins, view.id);
  const revision = Math.max(existing?.envelope.revision || 0, pin.revisions[payload.id] || 0) + 1;
  const updatedAt = new Date().toISOString();
  const body = { ...payload, updatedAt, updatedBy: identity.id };
  const envelope = await encryptRecord(view.cryptoKey, { teamId: view.id, vaultId, recordId: payload.id, epoch: view.chain.epoch, revision }, body);
  const signature = await signRecord(identity, envelope, { updatedAt });
  await api.request('PUT', `/teams/${view.id}/records/${payload.id}`, { envelope, updatedAt, deleted: false, signature });
  pin.revisions[payload.id] = revision;
  view.records.set(payload.id, { payload: body, envelope, updatedBy: identity.id, updatedAt });
  return body;
}

// Deleting overwrites the record with a tombstone whose secret is gone.
export async function deleteRecord(api, identity, view, recordId, pins) {
  const existing = view.records.get(recordId);
  if (!existing) throw new TeamsSyncError('missing', 'That key is not in the team vault');
  const pin = teamPins(pins, view.id);
  const revision = Math.max(existing.envelope.revision, pin.revisions[recordId] || 0) + 1;
  const updatedAt = new Date().toISOString();
  const tombstone = { ...existing.payload, label: 'deleted', username: '', secret: '-', updatedAt, updatedBy: identity.id,
    map: { ...existing.payload.map, notes: '', locations: [] } };
  const envelope = await encryptRecord(view.cryptoKey, {
    teamId: view.id, vaultId: existing.envelope.vaultId, recordId, epoch: view.chain.epoch, revision
  }, tombstone);
  const signature = await signRecord(identity, envelope, { updatedAt, deleted: true });
  await api.request('PUT', `/teams/${view.id}/records/${recordId}`, { envelope, updatedAt, deleted: true, signature });
  pin.revisions[recordId] = revision;
  view.records.delete(recordId);
}

// ---- people ----

export async function invite(api, view, email, role) {
  return api.request('POST', `/teams/${view.id}/invites`, { email, role });
}

// Pending and accepted invites, with the fingerprint an admin must compare before confirming.
export async function teamInvites(api, view) {
  const { invites } = await api.request('GET', `/teams/${view.id}/invites`);
  for (const item of invites) {
    item.fingerprint = item.device ? await fingerprint(item.device.sigPub, item.device.kxPub) : null;
  }
  return invites;
}

// Adds an accepted invitee. `expectedFingerprint` is the one the admin compared; the keys are
// fetched again and must still match it, so the server cannot swap them after the comparison.
export async function confirmMember(api, identity, view, inviteId, expectedFingerprint) {
  const invites = await teamInvites(api, view);
  const item = invites.find(candidate => candidate.id === inviteId);
  if (!item || item.status !== 'accepted' || !item.device) throw new TeamsSyncError('invite', 'That invite has not been accepted yet');
  if (item.fingerprint !== expectedFingerprint) throw new TeamsSyncError('fingerprint', 'The fingerprint changed. Do not add this person; check with them.');
  const entry = await createEntry(view.chain, { op: 'add', subject: { ...item.device, role: item.role } }, identity);
  const next = await applyEntry(view.chain, entry);
  const wrap = await signWrap(identity, await wrapForRecipient(view.teamKey, view.id, next.epoch, { id: item.device.deviceId, kxPub: item.device.kxPub }));
  await api.request('POST', `/teams/${view.id}/entries`, { entry, wraps: [wrap] });
  view.chain = next;
  return item;
}

export async function people(api, view) {
  const { people: list } = await api.request('GET', `/teams/${view.id}/people`);
  const emails = new Map(list.map(person => [person.userId, person.email]));
  const members = [];
  for (const [userId, user] of view.chain.users) {
    const devices = [];
    for (const deviceId of user.devices) {
      const device = view.chain.devices.get(deviceId);
      devices.push({ deviceId, fingerprint: await fingerprint(device.sigPub, device.kxPub) });
    }
    members.push({ userId, email: emails.get(userId) || 'unknown', role: user.role, devices });
  }
  return { members, emails };
}

// ---- access log ----

// Appends an event, re-signing against the new head if someone else wrote first.
export async function logEvent(api, identity, view, { action, recordId = null, at = new Date().toISOString() }) {
  let head = view.summary.eventHead;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const event = await createEvent(view.chain, { seq: head.seq + 1, prev: head.hash, action, recordId, at }, identity);
    try {
      const result = await api.request('POST', `/teams/${view.id}/events`, { event });
      view.summary.eventHead = result.head;
      return result.head;
    } catch (error) {
      if (!(error instanceof TeamsApiError) || error.status !== 409 || !error.body.head) throw error;
      head = error.body.head;
    }
  }
  throw new TeamsSyncError('busy', 'The access log is busy; try again');
}

// Fetches and verifies the whole log. A log shorter than the head this device verified before
// means events were removed.
export async function readLog(api, view, pins) {
  const pin = teamPins(pins, view.id);
  const events = [];
  let after = -1;
  for (;;) {
    const page = await api.request('GET', `/teams/${view.id}/events?after=${after}`);
    events.push(...page.events);
    if (!page.more || !page.events.length) break;
    after = page.events[page.events.length - 1].seq;
  }
  const head = await verifyEvents(view.chain, events);
  // (a pin at seq -1 is an empty log, which any log extends)
  if (pin.eventHead && pin.eventHead.seq >= 0 &&
      (head.seq < pin.eventHead.seq || (await eventHash(events[pin.eventHead.seq])) !== pin.eventHead.hash)) {
    throw new TeamsSyncError('log-gap', 'The access log no longer matches what this device saw before; events were removed or changed');
  }
  pin.eventHead = { seq: head.seq, hash: head.hash };
  return events;
}

// ---- removing people and devices ----

// Re-keys the team without someone: a new team key wrapped for everyone left (and the recovery
// kit), every record and name re-encrypted under it, all sent as one batch. `view` must be fresh.
export async function rotateOut(api, identity, view, op, subject, pins) {
  if (!['remove', 'remove-device'].includes(op)) throw new TeamsSyncError('op', 'Only removals re-key the team');
  const entry = await createEntry(view.chain, { op, subject }, identity);
  const next = await applyEntry(view.chain, entry);
  if (!next.devices.get(identity.id) || next.devices.get(identity.id).revokedSeq !== null) {
    throw new TeamsSyncError('self', 'Ask another admin to remove this device, so someone still holds the team key');
  }
  const teamKey = generateTeamKey();
  const cryptoKey = await importTeamKey(teamKey);
  const wraps = [];
  for (const recipient of wrapRecipients(next)) wraps.push(await signWrap(identity, await wrapForRecipient(teamKey, view.id, next.epoch, recipient)));
  const pin = teamPins(pins, view.id);
  const records = [];
  for (const [recordId, entryForRecord] of view.records) {
    const revision = entryForRecord.envelope.revision + 1;
    const updatedAt = new Date().toISOString();
    const envelope = await encryptRecord(cryptoKey, {
      teamId: view.id, vaultId: entryForRecord.envelope.vaultId, recordId, epoch: next.epoch, revision
    }, entryForRecord.payload);
    records.push({ envelope, updatedAt, signature: await signRecord(identity, envelope, { updatedAt }) });
  }
  const names = {
    team: await encryptName(cryptoKey, { teamId: view.id, kind: 'team', id: view.id, epoch: next.epoch }, view.name),
    vaults: {}
  };
  for (const vault of view.vaults) {
    names.vaults[vault.id] = await encryptName(cryptoKey, { teamId: view.id, kind: 'vault', id: vault.id, epoch: next.epoch }, vault.name);
  }
  await api.request('POST', `/teams/${view.id}/rotate`, { entry, wraps, records, names });
  for (const record of records) pin.revisions[record.envelope.recordId] = record.envelope.revision;
  return next;
}

const ENV_ORDER = { prod: 0, staging: 1, other: 2, dev: 3 };
const USE_ACTIONS = new Set(['copy', 'fill', 'create', 'edit']);

// Who has left the team, and for each of them which keys to rotate. One team key means a removed
// member could read every key that existed while they were on the team; the access log says which
// ones they actually used through Otter. Prod first, then the ones they used.
export function offboardingReports(view, events = []) {
  const reports = [];
  for (const entry of view.history || []) {
    if (entry.op !== 'remove' && entry.op !== 'remove-device') continue;
    const userId = entry.subject.userId;
    const removedAt = entry.at;
    const devices = entry.op === 'remove'
      ? [...view.chain.devices].filter(([, device]) => device.userId === userId && device.revokedSeq === entry.seq).map(([id]) => id)
      : [entry.subject.deviceId];
    const uses = new Map();
    for (const event of events) {
      if (!devices.includes(event.device) || !USE_ACTIONS.has(event.action) || !event.recordId) continue;
      const use = uses.get(event.recordId) || { count: 0, last: null, actions: new Set() };
      use.count += 1;
      use.last = event.at;
      use.actions.add(event.action);
      uses.set(event.recordId, use);
    }
    const rows = [];
    for (const [recordId, { payload }] of view.records) {
      // keys added after they left were never readable by them
      if (Date.parse(payload.createdAt) > Date.parse(removedAt)) continue;
      const use = uses.get(recordId);
      const rotated = Boolean(payload.map.lastRotatedAt && Date.parse(payload.map.lastRotatedAt) > Date.parse(removedAt));
      rows.push({
        recordId,
        label: payload.label,
        origin: payload.origin,
        kind: payload.kind,
        environment: payload.map.environment,
        project: payload.map.project,
        locations: payload.map.locations,
        used: use ? { count: use.count, last: use.last, actions: [...use.actions] } : null,
        rotated
      });
    }
    rows.sort((a, b) => (ENV_ORDER[a.environment] - ENV_ORDER[b.environment]) || (Number(Boolean(b.used)) - Number(Boolean(a.used))) ||
      (Number(b.kind === 'api-key') - Number(a.kind === 'api-key')) || a.label.localeCompare(b.label));
    reports.push({ userId, deviceOnly: entry.op === 'remove-device', deviceId: entry.op === 'remove-device' ? entry.subject.deviceId : null, removedAt, rows });
  }
  return reports.reverse();
}

// ---- two-step sign-in ----

export const account = api => api.request('GET', '/auth/me');
export const totpSetup = api => api.request('POST', '/auth/totp/setup', {});
export const totpEnable = (api, code) => api.request('POST', '/auth/totp/enable', { code });
export const totpVerify = (api, code) => api.request('POST', '/auth/totp/verify', { code });

// ---- new devices ----

export const teamAccess = (api, teamId) => api.request('GET', `/teams/${teamId}/access`);
export const requestDevice = (api, teamId) => api.request('POST', `/teams/${teamId}/device-requests`, {});

// Adds a member's new device after the fingerprint was compared, like confirmMember.
export async function confirmDevice(api, identity, view, deviceId, expectedFingerprint) {
  const state = await api.request('GET', `/teams/${view.id}/state`);
  const request = state.deviceRequests.find(item => item.deviceId === deviceId);
  if (!request) throw new TeamsSyncError('missing', 'That device is no longer waiting');
  if ((await fingerprint(request.sigPub, request.kxPub)) !== expectedFingerprint) {
    throw new TeamsSyncError('fingerprint', 'The fingerprint changed. Do not add this device; check with its owner.');
  }
  const subject = { userId: request.userId, deviceId, sigPub: request.sigPub, kxPub: request.kxPub };
  const entry = await createEntry(view.chain, { op: 'add-device', subject }, identity);
  const next = await applyEntry(view.chain, entry);
  const wrap = await signWrap(identity, await wrapForRecipient(view.teamKey, view.id, next.epoch, { id: deviceId, kxPub: request.kxPub }));
  await api.request('POST', `/teams/${view.id}/entries`, { entry, wraps: [wrap] });
  view.chain = next;
}

// ---- recovery kit ----

// Makes a new kit (revoking the old one in the same step) and returns the code to print. The
// code is only ever shown here; the server gets the kit's keys sealed under it.
export async function createRecoveryKit(api, identity, view) {
  const secret = generateRecoverySecret();
  const material = await generateIdentity('k');
  const blob = await sealRecoveryIdentity(secret, view.id, material);
  const entries = [];
  let state = view.chain;
  if (state.recovery) {
    const revoke = await createEntry(state, { op: 'remove-recovery', subject: { recoveryId: state.recovery.id }, epoch: state.epoch }, identity);
    state = await applyEntry(state, revoke);
    entries.push(revoke);
  }
  const add = await createEntry(state, { op: 'add-recovery', subject: { recoveryId: material.id, sigPub: material.sigPub, kxPub: material.kxPub } }, identity);
  state = await applyEntry(state, add);
  entries.push(add);
  const wrap = await signWrap(identity, await wrapForRecipient(view.teamKey, view.id, state.epoch, { id: material.id, kxPub: material.kxPub }));
  await api.request('PUT', `/teams/${view.id}/recovery-kit`, { entries, wraps: [wrap], blob });
  view.chain = state;
  return { code: formatRecoveryCode(secret), kitId: material.id };
}

export const startRecovery = (api, teamId) => api.request('POST', `/teams/${teamId}/recovery-requests`, {});
export const decideRecovery = (api, teamId, requestId, decision) => api.request('POST', `/teams/${teamId}/recovery-requests/${requestId}/${decision}`, {});

// After the hold: open the kit with the printed code, check it is the kit the team's history
// names, and use it to sign this device onto the team.
export async function finishRecovery(api, identity, session, teamId, requestId, code) {
  const secret = parseRecoveryCode(code);
  const kit = await api.request('GET', `/teams/${teamId}/recovery-requests/${requestId}/kit`);
  const chain = await verifyMemberChain(kit.entries);
  if (!chain.recovery || chain.recovery.id !== kit.blob.id) throw new TeamsSyncError('kit', 'That is not the team’s current recovery kit');
  let material;
  try {
    material = await openRecoveryIdentity(secret, kit.blob);
  } catch {
    throw new TeamsSyncError('code', 'That recovery code does not open this kit');
  }
  if (material.sigPub !== chain.recovery.sigPub || material.kxPub !== chain.recovery.kxPub) {
    throw new TeamsSyncError('kit', 'The kit does not match the team history');
  }
  const recovery = await loadIdentity(material);
  if (!kit.wrap || kit.wrap.recipientId !== recovery.id) throw new TeamsSyncError('kit', 'The team key for the kit is missing');
  await verifyWrap(chain, kit.wrap);
  const teamKey = await unwrapTeamKey(recovery, stripWrap(kit.wrap), { teamId, epoch: chain.epoch });
  const entry = await createEntry(chain, {
    op: 'recover', subject: { userId: session.userId, deviceId: identity.id, sigPub: identity.sigPub, kxPub: identity.kxPub }
  }, recovery);
  const next = await applyEntry(chain, entry);
  const wrap = await signWrap(identity, await wrapForRecipient(teamKey, teamId, next.epoch, identity));
  await api.request('POST', `/teams/${teamId}/recovery-requests/${requestId}/complete`, { entry, wrap });
}

export { wrapRecipients };
