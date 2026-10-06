// Attack tests for the Teams member chain, access log and record signatures. Each test plays a
// malicious server (or a removed member) handing the client forged or doctored history, and
// asserts that verification fails closed with the right error code.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  applyEntry,
  createEntry,
  createEvent,
  entryHash,
  eventHash,
  isAdminDevice,
  verifyEvents,
  verifyMemberChain,
  verifyRecord,
  signRecord,
  wrapRecipients
} from '../extension/lib/team-chain.js';
import { encryptRecord, generateIdentity, generateTeamKey, importTeamKey, loadIdentity } from '../extension/lib/team-crypto.js';

const TEAM = 't_acme';
const identity = async (prefix = 'd') => loadIdentity(await generateIdentity(prefix));
const keyed = (userId, device, role) => ({ userId, deviceId: device.id, sigPub: device.sigPub, kxPub: device.kxPub, ...(role ? { role } : {}) });

// A small team: owner Krishna, admin Asha, member Rahul.
async function makeTeam() {
  const owner = await identity();
  const admin = await identity();
  const member = await identity();
  const entries = [];
  let state = null;
  const push = async (fields, signer) => {
    const entry = await createEntry(state, { teamId: TEAM, ...fields }, signer);
    state = await applyEntry(state, entry);
    entries.push(entry);
    return entry;
  };
  await push({ op: 'create', subject: keyed('u_krishna', owner, 'owner') }, owner);
  await push({ op: 'add', subject: keyed('u_asha', admin, 'admin') }, owner);
  await push({ op: 'add', subject: keyed('u_rahul', member, 'member') }, admin);
  return { owner, admin, member, entries, get state() { return state; }, push };
}

async function createEntryLike(body, signer) {
  const { signJson } = await import('../extension/lib/team-crypto.js');
  return { ...body, signature: await signJson(signer, body) };
}

async function rejects(promise, code) {
  await assert.rejects(promise, error => {
    assert.equal(error.name, 'TeamChainError', error.message);
    assert.equal(error.code, code, error.message);
    return true;
  });
}

test('a well-formed team history replays to the expected members, roles and recipients', async () => {
  const team = await makeTeam();
  const state = await verifyMemberChain(team.entries);
  assert.equal(state.seq, 2);
  assert.equal(state.epoch, 1);
  assert.equal(state.anchor, await entryHash(team.entries[0]));
  assert.equal(state.headHash, await entryHash(team.entries[2]));
  assert.ok(isAdminDevice(state, team.owner.id));
  assert.ok(isAdminDevice(state, team.admin.id));
  assert.ok(!isAdminDevice(state, team.member.id));
  assert.deepEqual(wrapRecipients(state).map(r => r.id).sort(), [team.owner.id, team.admin.id, team.member.id].sort());
  // replaying does not depend on shared mutable state
  assert.deepEqual((await verifyMemberChain(team.entries, { anchor: state.anchor })).headHash, state.headHash);
});

test('a server cannot add a member: unsigned, self-signed or member-signed additions fail', async () => {
  const team = await makeTeam();
  const intruder = await identity();
  const forged = await createEntry(team.state, { op: 'add', subject: keyed('u_mallory', intruder, 'admin') }, intruder);
  await rejects(applyEntry(team.state, forged), 'signer');

  const byMember = await createEntry(team.state, { op: 'add', subject: keyed('u_mallory', intruder, 'member') }, team.member);
  await rejects(applyEntry(team.state, byMember), 'permission');

  const good = await createEntry(team.state, { op: 'add', subject: keyed('u_mallory', intruder, 'member') }, team.admin);
  await rejects(applyEntry(team.state, { ...good, subject: { ...good.subject, role: 'admin' } }), 'signature');
  await rejects(applyEntry(team.state, { ...good, signature: good.signature.replace(/^./, c => (c === 'A' ? 'B' : 'A')) }), 'signature');
  // claiming an admin signed it while signing with another key
  const { signature, ...body } = good;
  await rejects(applyEntry(team.state, await createEntryLike(body, intruder)), 'signature');
});

test('history cannot be reordered, skipped, spliced from another team, or swapped for a different team', async () => {
  const team = await makeTeam();
  await rejects(verifyMemberChain([team.entries[0], team.entries[2]]), 'order');
  await rejects(verifyMemberChain([team.entries[1], team.entries[0]]), 'order');

  const other = await makeTeam();
  await rejects(verifyMemberChain([team.entries[0], other.entries[1]]), 'order');
  await rejects(verifyMemberChain(other.entries, { anchor: (await verifyMemberChain(team.entries)).anchor }), 'anchor');

  const next = await createEntry(team.state, { op: 'set-role', subject: { userId: 'u_rahul', role: 'admin' } }, team.owner);
  await rejects(applyEntry(team.state, { ...next, prev: team.state.anchor }), 'order');
  await rejects(applyEntry(team.state, await createEntryLike({ ...withoutSig(next), teamId: 't_evil' }, team.owner)), 'rule');
  await rejects(verifyMemberChain([]), 'shape');
});

const withoutSig = ({ signature, ...body }) => body;

test('removing a member needs an admin, a new epoch, and revokes all their devices', async () => {
  const team = await makeTeam();
  const sameEpoch = await createEntry(team.state, { op: 'remove', subject: { userId: 'u_rahul' }, epoch: 1 }, team.admin);
  await rejects(applyEntry(team.state, sameEpoch), 'epoch');
  const skipEpoch = await createEntry(team.state, { op: 'remove', subject: { userId: 'u_rahul' }, epoch: 3 }, team.admin);
  await rejects(applyEntry(team.state, skipEpoch), 'epoch');
  const byMember = await createEntry(team.state, { op: 'remove', subject: { userId: 'u_asha' } }, team.member);
  await rejects(applyEntry(team.state, byMember), 'permission');
  const owner = await createEntry(team.state, { op: 'remove', subject: { userId: 'u_krishna' } }, team.admin);
  await rejects(applyEntry(team.state, owner), 'rule');

  await team.push({ op: 'remove', subject: { userId: 'u_rahul' } }, team.admin);
  assert.equal(team.state.epoch, 2);
  assert.ok(!wrapRecipients(team.state).some(r => r.id === team.member.id));
  // the removed member's device can no longer sign anything
  const comeback = await createEntry(team.state, { op: 'add-device', subject: keyed('u_rahul', await identity()) }, team.member);
  await rejects(applyEntry(team.state, comeback), 'signer');
});

test('a removed admin loses admin powers immediately', async () => {
  const team = await makeTeam();
  await team.push({ op: 'remove', subject: { userId: 'u_asha' } }, team.owner);
  const intruder = await identity();
  const late = await createEntry(team.state, { op: 'add', subject: keyed('u_mallory', intruder, 'admin') }, team.admin);
  await rejects(applyEntry(team.state, late), 'signer');
});

test('only the owner changes roles, and nobody can become a second owner', async () => {
  const team = await makeTeam();
  await rejects(applyEntry(team.state, await createEntry(team.state, { op: 'set-role', subject: { userId: 'u_rahul', role: 'admin' } }, team.admin)), 'permission');
  await rejects(applyEntry(team.state, await createEntry(team.state, { op: 'set-role', subject: { userId: 'u_rahul', role: 'owner' } }, team.owner)), 'rule');
  await rejects(applyEntry(team.state, await createEntry(team.state, { op: 'add', subject: keyed('u_new', await identity(), 'owner') }, team.owner)), 'rule');
  await team.push({ op: 'set-role', subject: { userId: 'u_rahul', role: 'admin' } }, team.owner);
  assert.ok(isAdminDevice(team.state, team.member.id));
});

test('devices: a member adds their own, cannot add for others, and ids are never reused', async () => {
  const team = await makeTeam();
  const phone = await identity();
  await rejects(applyEntry(team.state, await createEntry(team.state, { op: 'add-device', subject: keyed('u_asha', phone) }, team.member)), 'permission');
  await team.push({ op: 'add-device', subject: keyed('u_rahul', phone) }, team.member);
  assert.ok(wrapRecipients(team.state).some(r => r.id === phone.id));

  const reuse = await createEntry(team.state, { op: 'add-device', subject: keyed('u_rahul', team.admin) }, team.member);
  await rejects(applyEntry(team.state, reuse), 'rule');

  await rejects(applyEntry(team.state, await createEntry(team.state, { op: 'remove-device', subject: { userId: 'u_rahul', deviceId: phone.id }, epoch: 1 }, team.member)), 'epoch');
  await team.push({ op: 'remove-device', subject: { userId: 'u_rahul', deviceId: phone.id } }, team.member);
  assert.equal(team.state.epoch, 2);
  const again = await createEntry(team.state, { op: 'add-device', subject: keyed('u_rahul', phone) }, team.member);
  await rejects(applyEntry(team.state, again), 'rule');
});

test('a recovery kit can only restore an owner or admin and can do nothing else', async () => {
  const team = await makeTeam();
  const kit = await identity('k');
  await rejects(applyEntry(team.state, await createEntry(team.state, { op: 'add-recovery', subject: { recoveryId: kit.id, sigPub: kit.sigPub, kxPub: kit.kxPub } }, team.member)), 'permission');
  await team.push({ op: 'add-recovery', subject: { recoveryId: kit.id, sigPub: kit.sigPub, kxPub: kit.kxPub } }, team.admin);
  assert.ok(wrapRecipients(team.state).some(r => r.id === kit.id));

  const second = await identity('k');
  await rejects(applyEntry(team.state, await createEntry(team.state, { op: 'add-recovery', subject: { recoveryId: second.id, sigPub: second.sigPub, kxPub: second.kxPub } }, team.admin)), 'rule');

  // the kit tries to act like an admin
  await rejects(applyEntry(team.state, await createEntry(team.state, { op: 'add', subject: keyed('u_mallory', await identity(), 'admin') }, kit)), 'signer');
  await rejects(applyEntry(team.state, await createEntry(team.state, { op: 'remove', subject: { userId: 'u_rahul' } }, kit)), 'signer');
  // the kit tries to restore a plain member, or a stranger
  await rejects(applyEntry(team.state, await createEntry(team.state, { op: 'recover', subject: keyed('u_rahul', await identity()) }, kit)), 'permission');
  await rejects(applyEntry(team.state, await createEntry(team.state, { op: 'recover', subject: keyed('u_mallory', await identity()) }, kit)), 'permission');
  // a device cannot sign a recovery
  await rejects(applyEntry(team.state, await createEntry(team.state, { op: 'recover', subject: keyed('u_asha', await identity()) }, team.owner)), 'signer');

  const newLaptop = await identity();
  await team.push({ op: 'recover', subject: keyed('u_asha', newLaptop) }, kit);
  assert.ok(isAdminDevice(team.state, newLaptop.id));

  // the spent kit is revoked, after which it cannot recover anyone
  await team.push({ op: 'remove-recovery', subject: { recoveryId: kit.id } }, newLaptop);
  assert.ok(!wrapRecipients(team.state).some(r => r.id === kit.id));
  await rejects(applyEntry(team.state, await createEntry(team.state, { op: 'recover', subject: keyed('u_asha', await identity()) }, kit)), 'signer');
  // and its id cannot be brought back
  await rejects(applyEntry(team.state, await createEntry(team.state, { op: 'add-recovery', subject: { recoveryId: kit.id, sigPub: kit.sigPub, kxPub: kit.kxPub } }, team.owner)), 'rule');
});

test('malformed entries are refused before anything else', async () => {
  const team = await makeTeam();
  const good = await createEntry(team.state, { op: 'set-role', subject: { userId: 'u_rahul', role: 'admin' } }, team.owner);
  const cases = [
    { ...good, extra: 1 },
    { ...good, op: 'promote' },
    { ...good, subject: { userId: 'u_rahul', role: 'admin', deviceId: 'd_x' } },
    { ...good, subject: { userId: 'rahul', role: 'admin' } },
    { ...good, epoch: 0 },
    { ...good, at: 'yesterday' },
    { ...good, teamId: 'acme' },
    null,
    []
  ];
  for (const entry of cases) await rejects(applyEntry(team.state, entry), 'shape');
});

async function makeLog(team, count = 3) {
  const events = [];
  let prev = null;
  const devices = [team.owner, team.admin, team.member];
  for (let seq = 0; seq < count; seq += 1) {
    const event = await createEvent(team.state, { seq, prev, action: 'copy', recordId: 'r_stripe' }, devices[seq % devices.length]);
    events.push(event);
    prev = await eventHash(event);
  }
  return events;
}

test('the access log verifies, and resumes from the last verified event', async () => {
  const team = await makeTeam();
  const events = await makeLog(team, 5);
  const head = await verifyEvents(team.state, events);
  assert.equal(head.seq, 4);
  assert.equal(head.count, 5);
  const firstThree = await verifyEvents(team.state, events.slice(0, 3));
  assert.deepEqual(await verifyEvents(team.state, events.slice(3), { after: firstThree }), { ...head, count: 2 });
});

test('a server cannot drop, reorder, edit or forge access-log events', async () => {
  const team = await makeTeam();
  const events = await makeLog(team, 4);
  await rejects(verifyEvents(team.state, [events[0], events[2], events[3]]), 'gap');
  await rejects(verifyEvents(team.state, [events[1], events[0]]), 'gap');
  await rejects(verifyEvents(team.state, [events[0], { ...events[1], action: 'view-hint' }]), 'signature');
  await rejects(verifyEvents(team.state, [events[0], { ...events[1], recordId: 'r_other' }]), 'signature');
  await rejects(verifyEvents(team.state, [events[0], { ...events[1], prev: null }]), 'order');
  // dropping the newest events and replaying the start is caught once the client knows its head
  const head = await verifyEvents(team.state, events);
  await rejects(verifyEvents(team.state, events.slice(2), { after: { ...head } }), 'gap');

  const intruder = await identity();
  const forged = await createEvent(team.state, { seq: 0, prev: null, action: 'copy', recordId: 'r_stripe' }, intruder);
  await rejects(verifyEvents(team.state, [forged]), 'signer');
  // claiming someone else's device id
  await rejects(verifyEvents(team.state, [{ ...forged, device: team.member.id }]), 'signature');
  await rejects(verifyEvents(team.state, [{ ...events[0], action: 'download' }]), 'shape');
  await rejects(verifyEvents(team.state, [{ ...events[0], recordId: null }]), 'shape');
});

test('a removed member cannot backdate events, and chain positions never go backwards', async () => {
  const team = await makeTeam();
  const before = team.state;
  await team.push({ op: 'remove', subject: { userId: 'u_rahul' } }, team.admin);
  // signed while still a member: valid history
  const early = await createEvent(before, { seq: 0, prev: null, action: 'copy', recordId: 'r_stripe' }, team.member);
  await verifyEvents(team.state, [early]);
  // signed after removal, claiming the current chain position
  const late = await createEvent(team.state, { seq: 0, prev: null, action: 'copy', recordId: 'r_stripe' }, team.member);
  await rejects(verifyEvents(team.state, [late]), 'signer');
  // an event after one at chain position 3 cannot claim position 2 to slip under the removal
  const byAdmin = await createEvent(team.state, { seq: 0, prev: null, action: 'edit', recordId: 'r_stripe' }, team.admin);
  const backdated = await createEvent(before, { seq: 1, prev: await eventHash(byAdmin), action: 'copy', recordId: 'r_stripe' }, team.member);
  await rejects(verifyEvents(team.state, [byAdmin, backdated]), 'order');
  // a position from the future is impossible
  const future = await createEvent({ ...team.state, seq: 99 }, { seq: 0, prev: null, action: 'copy', recordId: 'r_stripe' }, team.admin);
  await rejects(verifyEvents(team.state, [future]), 'order');
});

test('stored records must be in the current epoch and signed by a device on the team now', async () => {
  const team = await makeTeam();
  const key = await importTeamKey(generateTeamKey());
  const place = { teamId: TEAM, vaultId: 'v_main', recordId: 'r_stripe', epoch: 1, revision: 1 };
  const payload = {
    id: 'r_stripe', kind: 'api-key', label: 'Stripe', origin: 'https://dashboard.stripe.com', username: '', secret: 'sk_live_x',
    createdAt: '2026-10-03T10:00:00.000Z', updatedAt: '2026-10-03T10:00:00.000Z', updatedBy: team.member.id,
    map: { project: 'checkout', environment: 'prod', locations: [], owner: 'u_rahul', rotateEveryDays: 90, lastRotatedAt: null, notes: '' }
  };
  const envelope = await encryptRecord(key, place, payload);
  const meta = { updatedBy: team.member.id, updatedAt: payload.updatedAt };
  const signature = await signRecord(team.member, envelope, meta);
  assert.equal(await verifyRecord(team.state, envelope, { ...meta, signature }), true);

  await rejects(verifyRecord(team.state, { ...envelope, revision: 2 }, { ...meta, signature }), 'signature');
  await rejects(verifyRecord(team.state, { ...envelope, vaultId: 'v_other' }, { ...meta, signature }), 'signature');
  await rejects(verifyRecord(team.state, envelope, { ...meta, deleted: true, signature }), 'signature');
  await rejects(verifyRecord(team.state, envelope, { ...meta, updatedBy: team.admin.id, signature }), 'signature');

  await team.push({ op: 'remove', subject: { userId: 'u_rahul' } }, team.admin);
  await rejects(verifyRecord(team.state, envelope, { ...meta, signature }), 'epoch');
  const replayed = { ...envelope, epoch: 2 };
  await rejects(verifyRecord(team.state, replayed, { ...meta, signature: await signRecord(team.member, replayed, meta) }), 'signer');
});
