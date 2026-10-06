// Verification of the two signed, hash-chained histories a team keeps on the server: the member
// list (who is on the team, with which devices and keys) and the access log. Clients replay both
// from the start and fail closed, so a malicious server cannot add a member, forge an admin action
// or quietly drop or reorder log events. See docs/teams-phase1.md.
import { canonicalJson, hashJson, recordSignatureBody, signJson, verifyJson } from './team-crypto.js';

export const MEMBER_OPS = Object.freeze([
  'create', 'add', 'remove', 'set-role', 'add-device', 'remove-device', 'add-recovery', 'remove-recovery', 'recover'
]);
export const EVENT_ACTIONS = Object.freeze(['create', 'edit', 'delete', 'copy', 'fill', 'view-hint', 'rotate-mark', 'recover']);

const ENTRY_FIELDS = ['teamId', 'seq', 'prev', 'op', 'subject', 'epoch', 'at', 'by', 'signature'];
const EVENT_FIELDS = ['teamId', 'seq', 'prev', 'action', 'recordId', 'device', 'chainSeq', 'at', 'signature'];
const KEYED_SUBJECT = ['userId', 'deviceId', 'sigPub', 'kxPub'];
const SUBJECT_FIELDS = Object.freeze({
  create: [...KEYED_SUBJECT, 'role'],
  add: [...KEYED_SUBJECT, 'role'],
  remove: ['userId'],
  'set-role': ['userId', 'role'],
  'add-device': KEYED_SUBJECT,
  'remove-device': ['userId', 'deviceId'],
  'add-recovery': ['recoveryId', 'sigPub', 'kxPub'],
  'remove-recovery': ['recoveryId'],
  recover: KEYED_SUBJECT
});

export class TeamChainError extends Error {
  constructor(code, message, seq = null, label = 'entry') {
    super(seq === null ? message : `${message} (${label} ${seq})`);
    this.name = 'TeamChainError';
    this.code = code;
    this.seq = seq;
  }
}

const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const isId = (value, prefix) => typeof value === 'string' && value.length <= 64 && value.startsWith(`${prefix}_`);
const isTime = value => typeof value === 'string' && value.length <= 40 && !Number.isNaN(Date.parse(value));
const withoutSignature = ({ signature, ...body }) => body;

export function entryHash(entry) {
  return hashJson(entry);
}

function checkEntryShape(entry, seq) {
  const bad = message => { throw new TeamChainError('shape', message, seq); };
  if (!exactKeys(entry, ENTRY_FIELDS)) bad('Entry has missing or unexpected fields');
  if (!isId(entry.teamId, 't')) bad('Invalid team id');
  if (!MEMBER_OPS.includes(entry.op)) bad('Unknown operation');
  if (!exactKeys(entry.subject, SUBJECT_FIELDS[entry.op])) bad('Entry subject does not fit its operation');
  if (!Number.isSafeInteger(entry.epoch) || entry.epoch < 1) bad('Invalid epoch');
  if (!isTime(entry.at) || typeof entry.signature !== 'string') bad('Invalid time or signature');
  const subject = entry.subject;
  if ('userId' in subject && !isId(subject.userId, 'u')) bad('Invalid user id');
  if ('deviceId' in subject && !isId(subject.deviceId, 'd')) bad('Invalid device id');
  if ('recoveryId' in subject && !isId(subject.recoveryId, 'k')) bad('Invalid recovery id');
  if ('sigPub' in subject && (typeof subject.sigPub !== 'string' || typeof subject.kxPub !== 'string')) bad('Invalid keys');
  // canonicalJson rejects anything that is not plain JSON, so signatures are well defined
  canonicalJson(withoutSignature(entry));
}

function emptyState(teamId) {
  return {
    teamId,
    anchor: null,
    headHash: null,
    seq: -1,
    epoch: 0,
    users: new Map(),
    devices: new Map(),
    recovery: null,
    recoveries: new Map(),
    usedIds: new Set()
  };
}

function activeDevice(state, deviceId) {
  const device = state.devices.get(deviceId);
  return device && device.revokedSeq === null ? device : null;
}

function roleOfDevice(state, deviceId) {
  const device = activeDevice(state, deviceId);
  return device ? state.users.get(device.userId)?.role ?? null : null;
}

export function isAdminDevice(state, deviceId) {
  return ['owner', 'admin'].includes(roleOfDevice(state, deviceId));
}

// Everyone who must receive the team key: every active device plus the active recovery identity.
export function wrapRecipients(state) {
  const recipients = [];
  for (const [id, device] of state.devices) {
    if (device.revokedSeq === null) recipients.push({ id, kxPub: device.kxPub });
  }
  if (state.recovery) recipients.push({ id: state.recovery.id, kxPub: state.recovery.kxPub });
  return recipients;
}

function addDevice(state, userId, subject, seq, bad) {
  if (state.usedIds.has(subject.deviceId)) bad('Device id was used before');
  state.usedIds.add(subject.deviceId);
  state.devices.set(subject.deviceId, { userId, sigPub: subject.sigPub, kxPub: subject.kxPub, addedSeq: seq, revokedSeq: null });
  state.users.get(userId).devices.add(subject.deviceId);
}

function revokeDevice(state, deviceId, seq) {
  const device = state.devices.get(deviceId);
  device.revokedSeq = seq;
  state.users.get(device.userId)?.devices.delete(deviceId);
}

// Applies one entry on top of a verified state and returns the new state. The input is not changed.
export async function applyEntry(previous, entry, { anchor = null } = {}) {
  const seq = previous ? previous.seq + 1 : 0;
  const bad = (message, code = 'rule') => { throw new TeamChainError(code, message, seq); };
  checkEntryShape(entry, seq);
  if (entry.seq !== seq) bad('Entries are missing or out of order', 'order');
  const state = previous ? structuredClone(previous) : emptyState(entry.teamId);
  if (entry.teamId !== state.teamId) bad('Entry belongs to another team');
  if (entry.prev !== state.headHash) bad('Entry does not follow the previous one', 'order');

  const { op, subject } = entry;
  const body = withoutSignature(entry);
  let signerPub;

  if (op === 'create') {
    if (previous) bad('A team is created only once');
    if (subject.role !== 'owner' || entry.by !== subject.deviceId || entry.epoch !== 1) bad('Invalid team creation');
    signerPub = subject.sigPub;
  } else if (op === 'recover') {
    if (!state.recovery || entry.by !== state.recovery.id) bad('Only the active recovery kit can sign a recovery', 'signer');
    signerPub = state.recovery.sigPub;
  } else {
    const signer = activeDevice(state, entry.by);
    if (!signer) bad('Signed by a device that is not on the team', 'signer');
    signerPub = signer.sigPub;
  }
  if (!(await verifyJson(signerPub, body, entry.signature))) bad('Signature does not check out', 'signature');

  const byAdmin = isAdminDevice(state, entry.by);
  const byOwner = roleOfDevice(state, entry.by) === 'owner';
  const target = 'userId' in subject ? state.users.get(subject.userId) : null;
  const sameEpoch = () => { if (entry.epoch !== state.epoch) bad('Epoch must not change here', 'epoch'); };
  const nextEpoch = () => { if (entry.epoch !== state.epoch + 1) bad('Removing access must start a new epoch', 'epoch'); };

  switch (op) {
    case 'create':
      state.usedIds.add(subject.userId);
      state.users.set(subject.userId, { role: 'owner', devices: new Set() });
      addDevice(state, subject.userId, subject, seq, bad);
      state.epoch = 1;
      break;
    case 'add':
      if (!byAdmin) bad('Only admins can add members', 'permission');
      if (target) bad('Already a member');
      if (!['admin', 'member'].includes(subject.role)) bad('Invalid role');
      sameEpoch();
      state.users.set(subject.userId, { role: subject.role, devices: new Set() });
      addDevice(state, subject.userId, subject, seq, bad);
      break;
    case 'remove':
      if (!byAdmin) bad('Only admins can remove members', 'permission');
      if (!target) bad('Not a member');
      if (target.role === 'owner') bad('The owner cannot be removed');
      nextEpoch();
      for (const deviceId of [...target.devices]) revokeDevice(state, deviceId, seq);
      state.users.delete(subject.userId);
      state.epoch = entry.epoch;
      break;
    case 'set-role':
      if (!byOwner) bad('Only the owner can change roles', 'permission');
      if (!target || target.role === 'owner') bad('Cannot change this role');
      if (!['admin', 'member'].includes(subject.role)) bad('Invalid role');
      sameEpoch();
      target.role = subject.role;
      break;
    case 'add-device': {
      if (!target) bad('Not a member');
      const ownDevice = state.devices.get(entry.by)?.userId === subject.userId;
      if (!ownDevice && !byAdmin) bad('Only the member or an admin can add a device', 'permission');
      sameEpoch();
      addDevice(state, subject.userId, subject, seq, bad);
      break;
    }
    case 'remove-device': {
      if (!target || !target.devices.has(subject.deviceId)) bad('Not an active device of this member');
      const ownDevice = state.devices.get(entry.by)?.userId === subject.userId;
      if (!ownDevice && !byAdmin) bad('Only the member or an admin can remove a device', 'permission');
      nextEpoch();
      revokeDevice(state, subject.deviceId, seq);
      state.epoch = entry.epoch;
      break;
    }
    case 'add-recovery':
      if (!byAdmin) bad('Only admins can create a recovery kit', 'permission');
      if (state.recovery) bad('Revoke the current recovery kit first');
      if (state.usedIds.has(subject.recoveryId)) bad('Recovery id was used before');
      sameEpoch();
      state.usedIds.add(subject.recoveryId);
      state.recovery = { id: subject.recoveryId, sigPub: subject.sigPub, kxPub: subject.kxPub };
      state.recoveries.set(subject.recoveryId, { sigPub: subject.sigPub, kxPub: subject.kxPub, addedSeq: seq, revokedSeq: null });
      break;
    case 'remove-recovery':
      if (!byAdmin) bad('Only admins can revoke a recovery kit', 'permission');
      if (state.recovery?.id !== subject.recoveryId) bad('Not the active recovery kit');
      if (entry.epoch !== state.epoch && entry.epoch !== state.epoch + 1) bad('Invalid epoch', 'epoch');
      state.recoveries.get(subject.recoveryId).revokedSeq = seq;
      state.recovery = null;
      state.epoch = entry.epoch;
      break;
    case 'recover':
      if (!target || !['owner', 'admin'].includes(target.role)) bad('A recovery kit only restores an owner or admin', 'permission');
      sameEpoch();
      addDevice(state, subject.userId, subject, seq, bad);
      break;
  }

  state.seq = seq;
  state.headHash = await entryHash(entry);
  if (seq === 0) {
    state.anchor = state.headHash;
    if (anchor !== null && anchor !== state.anchor) bad('This is not the team you joined', 'anchor');
  }
  return state;
}

// Replays a whole member chain. `anchor` is the creation hash this client pinned when it joined.
export async function verifyMemberChain(entries, { anchor = null } = {}) {
  if (!Array.isArray(entries) || entries.length === 0) throw new TeamChainError('shape', 'Empty team history');
  let state = null;
  for (const entry of entries) state = await applyEntry(state, entry, { anchor });
  return state;
}

function defaultEpoch(state, op) {
  if (op === 'create') return 1;
  if (op === 'remove' || op === 'remove-device') return state.epoch + 1;
  return state.epoch;
}

// Builds and signs the next entry. `signer` is a loaded identity (device or recovery kit).
export async function createEntry(state, { teamId = state?.teamId, op, subject, epoch, at = new Date().toISOString() }, signer) {
  const body = {
    teamId,
    seq: state ? state.seq + 1 : 0,
    prev: state ? state.headHash : null,
    op,
    subject,
    epoch: epoch ?? defaultEpoch(state, op),
    at,
    by: signer.id
  };
  return { ...body, signature: await signJson(signer, body) };
}

// ---- access log ----

function deviceActiveAt(state, deviceId, chainSeq) {
  const device = state.devices.get(deviceId);
  return device && device.addedSeq <= chainSeq && (device.revokedSeq === null || device.revokedSeq > chainSeq) ? device : null;
}

export function eventHash(event) {
  return hashJson(event);
}

// The server assigns seq and prev (so concurrent writers get an order), then the device signs.
// `chainSeq` is the member-chain position the device acted under.
export async function createEvent(state, { seq, prev, action, recordId = null, at = new Date().toISOString() }, identity) {
  const body = { teamId: state.teamId, seq, prev, action, recordId, device: identity.id, chainSeq: state.seq, at };
  return { ...body, signature: await signJson(identity, body) };
}

// Verifies log events against a verified member state. `after` is the last event this client
// already verified ({ seq, hash, chainSeq }), or null to start from the first event.
export async function verifyEvents(state, events, { after = null } = {}) {
  let expectedSeq = after ? after.seq + 1 : 0;
  let prev = after ? after.hash : null;
  let lastChainSeq = after ? after.chainSeq : 0;
  for (const event of events) {
    const seq = event?.seq;
    const bad = (message, code = 'rule') => { throw new TeamChainError(code, message, seq, 'event'); };
    if (!exactKeys(event, EVENT_FIELDS)) bad('Event has missing or unexpected fields', 'shape');
    if (event.teamId !== state.teamId) bad('Event belongs to another team');
    if (event.seq !== expectedSeq) bad(`The access log has a gap after event ${expectedSeq - 1}`, 'gap');
    if (event.prev !== prev) bad('Event does not follow the previous one', 'order');
    if (!EVENT_ACTIONS.includes(event.action)) bad('Unknown action', 'shape');
    if (event.action === 'recover' ? event.recordId !== null : !isId(event.recordId, 'r')) bad('Invalid record id', 'shape');
    if (!isTime(event.at)) bad('Invalid time', 'shape');
    if (!Number.isSafeInteger(event.chainSeq) || event.chainSeq < lastChainSeq || event.chainSeq > state.seq) {
      bad('Event refers to an impossible point in the team history', 'order');
    }
    const device = deviceActiveAt(state, event.device, event.chainSeq);
    if (!device) bad('Event from a device that was not on the team at that point', 'signer');
    if (!(await verifyJson(device.sigPub, withoutSignature(event), event.signature))) bad('Signature does not check out', 'signature');
    prev = await eventHash(event);
    lastChainSeq = event.chainSeq;
    expectedSeq += 1;
  }
  return { seq: expectedSeq - 1, hash: prev, chainSeq: lastChainSeq, count: events.length };
}

// ---- record signatures ----

export async function signRecord(identity, envelope, { updatedAt, deleted = false }) {
  return signJson(identity, await recordSignatureBody(envelope, { updatedBy: identity.id, updatedAt, deleted }));
}

// A stored record must be in the current epoch and signed by a device that is on the team now.
// Re-keying re-signs every record, so older signers never need to be accepted.
export async function verifyRecord(state, envelope, { updatedBy, updatedAt, deleted = false, signature }) {
  if (envelope.teamId !== state.teamId) throw new TeamChainError('rule', 'Record belongs to another team');
  if (envelope.epoch !== state.epoch) throw new TeamChainError('epoch', 'Record is from an old epoch');
  const device = activeDevice(state, updatedBy);
  if (!device) throw new TeamChainError('signer', 'Record written by a device that is not on the team');
  const body = await recordSignatureBody(envelope, { updatedBy, updatedAt, deleted });
  if (!(await verifyJson(device.sigPub, body, signature))) throw new TeamChainError('signature', 'Record signature does not check out');
  return true;
}

// ---- key wraps ----

const WRAP_FIELDS = ['teamId', 'epoch', 'recipientId', 'ephemeralPub', 'iv', 'ciphertext'];

// Wraps are signed by the device that made them, so a server cannot hand a client a team key it
// made up. The signer must be on the team in the epoch the wrap is for.
export async function signWrap(identity, wrap) {
  const body = { ...wrap, by: identity.id };
  return { ...body, signature: await signJson(identity, body) };
}

export async function verifyWrap(state, signed) {
  if (!exactKeys(signed, [...WRAP_FIELDS, 'by', 'signature'])) throw new TeamChainError('shape', 'Invalid key wrap');
  if (signed.teamId !== state.teamId || signed.epoch !== state.epoch) throw new TeamChainError('epoch', 'Key wrap is not for the current epoch');
  const device = activeDevice(state, signed.by);
  if (!device) throw new TeamChainError('signer', 'Key wrap made by a device that is not on the team');
  if (!wrapRecipients(state).some(recipient => recipient.id === signed.recipientId)) {
    throw new TeamChainError('rule', 'Key wrap for someone who is not on the team');
  }
  if (!(await verifyJson(device.sigPub, withoutSignature(signed), signed.signature))) {
    throw new TeamChainError('signature', 'Key wrap signature does not check out');
  }
  return true;
}
