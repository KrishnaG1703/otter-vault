// Teams inside the service worker: this device's identity, the Google session, pins, the event
// queue, and decrypted team views while the vault is unlocked. Chrome APIs are passed in, so the
// service runs under tests too. Everything decrypted lives in memory only and is dropped on lock.
import { matchesOrigin, normalizeOrigin } from './crypto-vault.js';
import { generateIdentity, loadIdentity, openDeviceIdentity, randomId, sealDeviceIdentity, validateRecordPayload, fingerprint } from './team-crypto.js';
import {
  TeamsApiError, TeamsSyncError, account, completeGoogleSignIn, confirmDevice, confirmMember, createApi, createRecoveryKit, createTeam,
  createVault, decideRecovery, deleteRecord, finishRecovery, invite, logEvent, offboardingReports, openTeam, people, prepareGoogleSignIn,
  readLog, requestDevice, rotateOut, saveRecord, startRecovery, teamAccess, teamInvites, totpEnable, totpSetup, totpVerify
} from './team-sync.js';

export const TEAMS_KEY = 'otterTeams';
const SYNC_EVERY_MS = 30_000;
const MAX_QUEUE = 200;

function emptyStore() {
  return { identity: null, session: null, pins: {}, queue: [] };
}

export function createTeamsService({ storage, getMaster, base, clientId, fetch, launchWebAuthFlow, redirectUrl, hint }) {
  let identity = null;
  let views = new Map();
  let lastSync = 0;
  let syncing = null;
  let generation = 0;

  async function load() {
    const stored = (await storage.get([TEAMS_KEY]))[TEAMS_KEY];
    return stored && typeof stored === 'object' ? { ...emptyStore(), ...stored } : emptyStore();
  }
  const save = store => storage.set({ [TEAMS_KEY]: store });

  async function api(store) {
    if (!store.session) throw new TeamsSyncError('signed-out', 'Sign in to Teams first');
    return createApi({ base, fetch, token: store.session.token });
  }

  // Opens (or on first use creates) this device's keys, sealed under the vault master secret.
  async function ensureIdentity(store, { create = false } = {}) {
    if (identity) return identity;
    const master = getMaster();
    if (store.identity) {
      identity = await loadIdentity(await openDeviceIdentity(master, store.identity));
    } else if (create) {
      const material = await generateIdentity();
      store.identity = await sealDeviceIdentity(master, material);
      await save(store);
      identity = await loadIdentity(material);
    }
    return identity;
  }

  // A 401 means the session ended; forget it so the page offers sign-in again.
  async function guarded(store, work) {
    try {
      return await work();
    } catch (error) {
      if (error instanceof TeamsApiError && error.status === 401) {
        store.session = null;
        await save(store);
      }
      throw error;
    }
  }

  async function flushQueue(store, client) {
    if (!store.queue.length) return;
    const pending = store.queue;
    store.queue = [];
    for (const item of pending) {
      const view = views.get(item.teamId);
      if (!view) continue;
      try {
        await logEvent(client, identity, view, item);
      } catch (error) {
        if (error instanceof TeamsApiError && error.status === 0) store.queue.push(item);
      }
    }
    await save(store);
  }

  // Re-reads every team this account is on and replaces the cached views.
  // `maxAge` lets a caller accept views synced a moment ago instead of re-reading every team.
  async function sync({ force = false, maxAge = SYNC_EVERY_MS } = {}) {
    if (!force && Date.now() - lastSync < maxAge && views.size) return views;
    syncing ??= (async () => {
      const mark = generation;
      const store = await load();
      if (!store.session || !(await ensureIdentity(store))) return views;
      const client = await api(store);
      const { teams } = await guarded(store, () => client.request('GET', '/teams'));
      // every team is fetched and verified at the same time, not one after another
      const opened = await Promise.all(teams.map(async team => {
        try {
          return await openTeam(client, identity, team.id, store.pins);
        } catch (error) {
          // a device that is not on the team (yet) gets what it can do instead of an error
          const notOnTeam = (error instanceof TeamsSyncError && error.code === 'removed') || (error instanceof TeamsApiError && error.status === 404);
          const access = notOnTeam ? await teamAccess(client, team.id).catch(() => null) : null;
          return { id: team.id, broken: access ? null : error.message, access, summary: team, records: new Map(), vaults: [] };
        }
      }));
      const next = new Map(opened.map(view => [view.id, view]));
      if (mark !== generation) return views;
      views = next;
      lastSync = Date.now();
      await save(store);
      await flushQueue(store, client);
      return views;
    })().finally(() => { syncing = null; });
    return syncing;
  }

  async function view(teamId, { fresh = false, maxAge } = {}) {
    await sync({ force: fresh, maxAge });
    const found = views.get(teamId);
    if (!found) throw new TeamsSyncError('missing', 'That team is not available');
    if (found.broken) throw new TeamsSyncError('broken', found.broken);
    if (found.access) throw new TeamsSyncError('not-on-team', 'This device is not on that team yet');
    return found;
  }

  async function record(store, action, teamId, recordId) {
    const target = views.get(teamId);
    if (!target) return;
    try {
      await logEvent(await api(store), identity, target, { action, recordId });
    } catch (error) {
      if (error instanceof TeamsApiError && error.status === 0 && store.queue.length < MAX_QUEUE) {
        store.queue.push({ teamId, action, recordId, at: new Date().toISOString() });
        await save(store);
      }
    }
  }

  function publicRecord(team, entry) {
    const { secret, ...rest } = entry.payload;
    return { ...rest, teamId: team.id, teamName: team.name, vaultId: entry.envelope.vaultId, hint: hint(rest.kind, secret), updatedBy: entry.updatedBy };
  }

  function buildPayload(existing, item, map, ownerUserId) {
    const origin = normalizeOrigin(item.origin);
    const payload = {
      id: existing?.id || randomId('r'),
      kind: item.kind,
      label: item.label,
      origin,
      username: item.username || '',
      secret: item.secret || existing?.secret,
      createdAt: existing?.createdAt || new Date().toISOString(),
      map: {
        project: map.project || '',
        environment: map.environment,
        locations: map.locations,
        owner: existing?.map.owner || ownerUserId,
        rotateEveryDays: map.rotateEveryDays,
        lastRotatedAt: existing?.map.lastRotatedAt ?? null,
        notes: map.notes || ''
      },
      updatedAt: '',
      updatedBy: identity.id
    };
    if (!payload.secret) throw new TeamsSyncError('secret', 'Enter the key or password');
    validateRecordPayload({ ...payload, updatedAt: new Date().toISOString() });
    return payload;
  }

  return {
    // Drops everything decrypted. Called when the vault locks.
    clear() {
      identity = null;
      views = new Map();
      lastSync = 0;
      generation += 1;
    },

    async overview() {
      const store = await load();
      const result = { enabled: Boolean(store.identity), signedIn: Boolean(store.session), email: store.session?.email || null };
      if (!store.session) return result;
      await ensureIdentity(store);
      result.fingerprint = await fingerprint(identity.sigPub, identity.kxPub);
      // a device waiting to join, or to recover, checks fresh every time; account and invites load alongside
      const client = await api(store);
      const [, account_, invites] = await Promise.all([
        sync({ force: [...views.values()].some(team => team.access) }),
        guarded(store, () => account(client)),
        guarded(store, () => client.request('GET', '/invites'))
      ]);
      result.teams = [...views.values()].map(team => ({
        id: team.id,
        name: team.name || (team.access?.ownerEmail ? `${team.access.ownerEmail}'s team` : 'Unavailable team'),
        role: team.role || team.summary.role,
        readOnly: team.summary.readOnly,
        trialEndsAt: team.summary.trialEndsAt,
        billing: team.summary.billing || null,
        keys: team.records.size,
        people: team.chain?.users?.size ?? null,
        broken: team.broken || null,
        access: team.access || null
      }));
      result.account = account_;
      result.isAdmin = result.teams.some(team => ['owner', 'admin'].includes(team.role));
      result.invites = invites.invites;
      return result;
    },

    async signIn() {
      const store = await load();
      await ensureIdentity(store, { create: true });
      const { salt, nonce } = await prepareGoogleSignIn(identity);
      const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      url.search = new URLSearchParams({
        client_id: clientId, response_type: 'id_token', redirect_uri: redirectUrl, scope: 'openid email', nonce, prompt: 'select_account'
      }).toString();
      const result = await launchWebAuthFlow(url.toString());
      const idToken = new URLSearchParams(new URL(result).hash.slice(1)).get('id_token');
      if (!idToken) throw new TeamsSyncError('google', 'Google sign-in was cancelled');
      store.session = await completeGoogleSignIn(createApi({ base, fetch }), identity, { idToken, salt });
      await save(store);
      lastSync = 0;
      return { email: store.session.email };
    },

    async signOut() {
      const store = await load();
      if (store.session) await (await api(store)).request('POST', '/auth/sign-out', {}).catch(() => {});
      store.session = null;
      await save(store);
      views = new Map();
      return { signedIn: false };
    },

    async createTeam(name) {
      const store = await load();
      await ensureIdentity(store);
      const client = await api(store);
      const teamId = await guarded(store, () => createTeam(client, identity, store.session, name));
      const fresh = await openTeam(client, identity, teamId, store.pins);
      await createVault(client, fresh, 'Shared');
      await save(store);
      await sync({ force: true });
      return { teamId };
    },

    async detail(teamId) {
      const store = await load();
      // the overview that opened this page usually synced a moment ago; don't fetch it all again
      const team = await view(teamId, { maxAge: 5000 });
      const client = await api(store);
      const [{ members, emails }, events] = await Promise.all([
        people(client, team),
        readLog(client, team, store.pins).catch(error => ({ error: error.message }))
      ]);
      await save(store);
      const deviceOwner = deviceId => emails.get(team.chain.devices.get(deviceId)?.userId) || 'someone';
      const me = team.chain.devices.get(identity.id).userId;
      const pastMembers = Array.isArray(events) ? offboardingReports(team, events).map(report => ({ ...report, email: emails.get(report.userId) || 'someone' })) : [];
      const records = [...team.records.values()].map(entry => ({ ...publicRecord(team, entry), updatedByEmail: deviceOwner(entry.updatedBy) }));
      return {
        id: team.id,
        name: team.name,
        role: team.role,
        admin: team.admin,
        readOnly: team.summary.readOnly,
        trialEndsAt: team.summary.trialEndsAt,
        billing: team.summary.billing || null,
        vaults: team.vaults,
        me,
        myDeviceId: identity.id,
        pastMembers,
        records,
        members,
        invites: team.admin ? await teamInvites(client, team).catch(error => {
          if (error instanceof TeamsApiError && /^totp/.test(error.code)) return [];
          throw error;
        }) : [],
        deviceRequests: await Promise.all(team.deviceRequests.map(async item => ({
          deviceId: item.deviceId, userId: item.userId, email: item.email, createdAt: item.createdAt,
          fingerprint: await fingerprint(item.sigPub, item.kxPub), mine: item.userId === me
        }))),
        recoveryKit: team.recoveryKit,
        recoveryRequests: team.recoveryRequests,
        log: Array.isArray(events)
          ? events.slice(-50).reverse().map(event => ({
            at: event.at,
            action: event.action,
            who: deviceOwner(event.device),
            label: team.records.get(event.recordId)?.payload.label || (event.recordId ? 'a deleted key' : '')
          }))
          : [],
        logError: Array.isArray(events) ? null : events.error
      };
    },

    // ---- two-step sign-in ----

    // Billing links come from the Teams server (Dodo checkout and customer portal). Only the
    // owner gets one; the server checks that, and the page opens the link in a new tab.
    async subscribe(teamId) {
      const store = await load();
      return guarded(store, async () => (await api(store)).request('POST', `/teams/${teamId}/billing/checkout`, {}));
    },

    async billingPortal(teamId) {
      const store = await load();
      return guarded(store, async () => (await api(store)).request('POST', `/teams/${teamId}/billing/portal`, {}));
    },

    async totpSetup() {
      const store = await load();
      return guarded(store, async () => totpSetup(await api(store)));
    },

    async totpEnable(code) {
      const store = await load();
      return guarded(store, async () => totpEnable(await api(store), code));
    },

    async totpVerify(code) {
      const store = await load();
      return guarded(store, async () => totpVerify(await api(store), code));
    },

    // ---- devices and recovery ----

    async requestDevice(teamId) {
      const store = await load();
      await requestDevice(await api(store), teamId);
      lastSync = 0;
      return { fingerprint: await fingerprint(identity.sigPub, identity.kxPub) };
    },

    async confirmDevice(teamId, deviceId, expectedFingerprint) {
      const store = await load();
      await confirmDevice(await api(store), identity, await view(teamId, { fresh: true }), deviceId, expectedFingerprint);
      await sync({ force: true });
      return { ok: true };
    },

    async cancelDevice(teamId, deviceId) {
      const store = await load();
      const result = await (await api(store)).request('DELETE', `/teams/${teamId}/device-requests/${deviceId}`);
      lastSync = 0;
      return result;
    },

    async createRecoveryKit(teamId) {
      const store = await load();
      const result = await createRecoveryKit(await api(store), identity, await view(teamId, { fresh: true }));
      lastSync = 0;
      return { code: result.code };
    },

    async startRecovery(teamId) {
      const store = await load();
      const result = await startRecovery(await api(store), teamId);
      lastSync = 0;
      return result;
    },

    async decideRecovery(teamId, requestId, decision) {
      const store = await load();
      const result = await decideRecovery(await api(store), teamId, requestId, decision);
      lastSync = 0;
      return result;
    },

    async finishRecovery(teamId, requestId, code) {
      const store = await load();
      await ensureIdentity(store);
      await finishRecovery(await api(store), identity, store.session, teamId, requestId, code);
      await sync({ force: true });
      await record(store, 'recover', teamId, null);
      return { ok: true };
    },

    // Removing someone (or one of their devices) re-keys the whole team from this device.
    async removeMember(teamId, userId) {
      const store = await load();
      const team = await view(teamId, { fresh: true });
      if (team.chain.devices.get(identity.id).userId === userId) throw new TeamsSyncError('self', 'You cannot remove yourself. Ask another admin.');
      if (!team.chain.users.has(userId)) throw new TeamsSyncError('missing', 'That person is not on the team');
      await rotateOut(await api(store), identity, team, 'remove', { userId }, store.pins);
      await save(store);
      await sync({ force: true });
      return { ok: true };
    },

    async removeDevice(teamId, userId, deviceId) {
      const store = await load();
      const team = await view(teamId, { fresh: true });
      await rotateOut(await api(store), identity, team, 'remove-device', { userId, deviceId }, store.pins);
      await save(store);
      await sync({ force: true });
      return { ok: true };
    },

    // Marks a key as rotated at its provider, optionally storing the new value at the same time.
    async markRotated(teamId, recordId, secret) {
      const store = await load();
      const team = await view(teamId, { fresh: true });
      const existing = team.records.get(recordId);
      if (!existing) throw new TeamsSyncError('missing', 'That key is not in the team vault');
      const payload = {
        ...existing.payload,
        secret: secret || existing.payload.secret,
        map: { ...existing.payload.map, lastRotatedAt: new Date().toISOString() }
      };
      await saveRecord(await api(store), identity, team, existing.envelope.vaultId, payload, store.pins);
      await save(store);
      await record(store, 'rotate-mark', teamId, recordId);
      return { ok: true };
    },

    async createVault(teamId, name) {
      const store = await load();
      const team = await view(teamId, { fresh: true });
      await createVault(await api(store), team, name);
      await sync({ force: true });
      return { ok: true };
    },

    async save(teamId, { vaultId, recordId, item, map }) {
      const store = await load();
      const team = await view(teamId, { fresh: true });
      if (!team.vaults.some(vault => vault.id === vaultId)) throw new TeamsSyncError('vault', 'No such vault');
      const existing = recordId ? team.records.get(recordId)?.payload : null;
      if (recordId && !existing) throw new TeamsSyncError('missing', 'That key is not in the team vault');
      const userId = team.chain.devices.get(identity.id).userId;
      const payload = buildPayload(existing, item, map, userId);
      const saved = await saveRecord(await api(store), identity, team, vaultId, payload, store.pins);
      await save(store);
      await record(store, existing ? 'edit' : 'create', teamId, saved.id);
      return publicRecord(team, team.records.get(saved.id));
    },

    async remove(teamId, recordId) {
      const store = await load();
      const team = await view(teamId, { fresh: true });
      await deleteRecord(await api(store), identity, team, recordId, store.pins);
      await save(store);
      await record(store, 'delete', teamId, recordId);
      return { ok: true };
    },

    async invite(teamId, email, role) {
      const store = await load();
      return invite(await api(store), await view(teamId), email, role);
    },

    async cancelInvite(teamId, inviteId) {
      const store = await load();
      return (await api(store)).request('DELETE', `/teams/${teamId}/invites/${inviteId}`);
    },

    async accept(inviteId) {
      const store = await load();
      await ensureIdentity(store);
      await (await api(store)).request('POST', `/invites/${inviteId}/accept`, {});
      return { fingerprint: await fingerprint(identity.sigPub, identity.kxPub) };
    },

    async confirm(teamId, inviteId, expectedFingerprint) {
      const store = await load();
      const team = await view(teamId, { fresh: true });
      await confirmMember(await api(store), identity, team, inviteId, expectedFingerprint);
      await sync({ force: true });
      return { ok: true };
    },

    // Plaintext for Copy; the caller has already re-checked the passphrase.
    async secret(teamId, recordId) {
      const store = await load();
      const team = await view(teamId);
      const entry = team.records.get(recordId);
      if (!entry) throw new TeamsSyncError('missing', 'That key is not in the team vault');
      await record(store, 'copy', teamId, recordId);
      return entry.payload;
    },

    // Everything an admin needs to leave Otter: every shared key, decrypted on this device, with
    // its map. Each key is written to the access log as a copy by this person, so the rest of the
    // team sees the export (a dedicated "export" action would break older clients' log checks).
    async exportTeam(teamId) {
      const store = await load();
      const team = await view(teamId, { fresh: true });
      if (!team.admin) throw new TeamsSyncError('forbidden', 'Only owners and admins can export a team');
      const vaultNames = new Map(team.vaults.map(vault => [vault.id, vault.name]));
      const keys = [...team.records.values()].map(entry => {
        const { label, origin, username, secret, kind, map = {} } = entry.payload;
        return {
          label, site: origin, username: username || '', secret, kind,
          vault: vaultNames.get(entry.envelope.vaultId) || '',
          environment: map.environment || '', project: map.project || '',
          locations: (map.locations || []).map(({ type, name, ref }) => ({ type, name, ref: ref || '' })),
          rotateEveryDays: map.rotateEveryDays ?? null, lastRotatedAt: map.lastRotatedAt || null, notes: map.notes || ''
        };
      }).sort((a, b) => a.label.localeCompare(b.label));
      for (const recordId of team.records.keys()) await record(store, 'copy', teamId, recordId);
      return { format: 'otter-teams-export', version: 1, exportedAt: new Date().toISOString(), team: team.name, keys };
    },

    // Shared records in the popup list. Never waits on the network for long.
    async publicRecords() {
      const store = await load();
      if (!store.session || !store.identity) return [];
      await sync().catch(() => {});
      return [...views.values()].flatMap(team => (team.broken ? [] : [...team.records.values()].map(entry => publicRecord(team, entry))));
    },

    // Exact-origin matches for fill and has-match, from the cached views.
    async matches(origin, kind) {
      const store = await load();
      if (!store.session || !store.identity) return [];
      await sync().catch(() => {});
      const found = [];
      for (const team of views.values()) {
        if (team.broken) continue;
        for (const entry of team.records.values()) {
          if (entry.payload.kind === kind && matchesOrigin(entry.payload.origin, origin)) found.push({ team, entry });
        }
      }
      return found;
    },

    async noteFill(teamId, recordId) {
      await record(await load(), 'fill', teamId, recordId);
    }
  };
}
