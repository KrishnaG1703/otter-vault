const WEB_TYPES = new Set(['has-match', 'save', 'fill']);
const POPUP_TYPES = new Set(['status', 'setup', 'unlock', 'lock', 'remove', 'set-auto-lock', 'verify', 'copy', 'team-copy']);
// The Teams page is an extension page opened in a tab (team/team.html), identified by its exact URL.
const TEAM_PAGE_TYPES = new Set([
  'status', 'unlock', 'team-overview', 'team-sign-in', 'team-sign-out', 'team-create', 'team-open', 'team-vault-create',
  'team-save', 'team-share', 'team-delete', 'team-invite', 'team-invite-cancel', 'team-accept', 'team-confirm', 'team-copy',
  'team-remove-member', 'team-remove-device', 'team-mark-rotated', 'team-totp-setup', 'team-totp-enable', 'team-totp-verify',
  'team-device-request', 'team-device-confirm', 'team-device-cancel', 'team-kit-create', 'team-recovery-start',
  'team-recovery-decide', 'team-recovery-finish', 'team-subscribe', 'team-billing-portal', 'team-export'
]);
const TEAM_IDS = Object.freeze({ team: /^t_[A-Za-z0-9_-]{6,40}$/, vault: /^v_[A-Za-z0-9_-]{6,40}$/, record: /^r_[A-Za-z0-9_-]{6,40}$/, invite: /^i_[A-Za-z0-9_-]{6,40}$/,
  user: /^u_[A-Za-z0-9_-]{6,40}$/, device: /^d_[A-Za-z0-9_-]{6,40}$/, request: /^q_[A-Za-z0-9_-]{6,40}$/ });
const TOTP_CODE = /^\d{6}$/;
const ENVIRONMENTS = new Set(['prod', 'staging', 'dev', 'other']);
const LOCATION_TYPES = new Set(['vercel-env', 'github-actions', 'aws-ssm', 'aws-secrets-manager', 'gcp-secret-manager', 'cloudflare-secret', 'env-file', 'other']);
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{1,63}$/;
const FINGERPRINT = /^([0-9a-f]{4} ){5}[0-9a-f]{4}$/;
export const AUTO_LOCK_MINUTES = Object.freeze([5, 15, 30]);
const KINDS = new Set(['login', 'api-key']);
const ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
// Chrome reports documentId as 32 uppercase hex characters, e.g. "2D1B0C8E4F7A6B5C9D3E2F1A0B9C8D7E".
const DOCUMENT_ID_PATTERN = /^[0-9A-F]{32}$/;

function plainObject(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${name} must be an object`);
  }
}

function exactKeys(value, allowed, name) {
  const extras = Object.keys(value).filter(key => !allowed.includes(key));
  if (extras.length) throw new Error(`${name} schema contains unsupported fields`);
}

function boundedString(value, name, { min = 0, max, pattern } = {}) {
  if (typeof value !== 'string' || value.length < min || value.length > max || (pattern && !pattern.test(value))) {
    throw new Error(`Invalid ${name}`);
  }
  return value;
}

export function trustedSenderOrigin(sender) {
  if (!sender?.tab) throw new Error('Request did not come from a trusted web tab');
  if (sender.frameId !== 0) throw new Error('Trusted sender must be the top frame');
  if (sender.documentLifecycle !== 'active') throw new Error('Trusted sender document must be active');
  if (sender.documentId !== undefined &&
      (typeof sender.documentId !== 'string' || !DOCUMENT_ID_PATTERN.test(sender.documentId))) {
    throw new Error('Trusted sender has an invalid documentId');
  }
  const value = sender.url;
  if (!value) throw new Error('Request did not identify the sending document');
  let url;
  try { url = new URL(value); } catch { throw new Error('Request did not come from a valid sending document'); }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Trusted sender must use http or https');
  }
  if (sender.origin !== undefined) {
    let origin;
    try { origin = new URL(sender.origin); } catch { throw new Error('Trusted sender origin is invalid'); }
    if ((origin.protocol !== 'http:' && origin.protocol !== 'https:') || origin.origin !== url.origin) {
      throw new Error('Trusted sender URL and origin must be consistent http(s) origins');
    }
  }
  return url.origin;
}

function teamId(value, kind) {
  return boundedString(value, `${kind} id`, { min: 8, max: 48, pattern: TEAM_IDS[kind] });
}

function cleanText(value, name, max, { min = 0 } = {}) {
  const text = boundedString(value, name, { min, max });
  if (/[\u0000-\u001f\u007f]/.test(text)) throw new Error(`Invalid ${name}`);
  return text;
}

function teamMap(map) {
  plainObject(map, 'Key map');
  exactKeys(map, ['project', 'environment', 'locations', 'rotateEveryDays', 'notes'], 'Key map');
  if (!ENVIRONMENTS.has(map.environment)) throw new Error('Invalid environment');
  if (!Array.isArray(map.locations) || map.locations.length > 20) throw new Error('Invalid locations');
  const locations = map.locations.map(location => {
    plainObject(location, 'Location');
    exactKeys(location, ['type', 'name', 'ref'], 'Location');
    if (!LOCATION_TYPES.has(location.type)) throw new Error('Invalid location type');
    return { type: location.type, name: cleanText(location.name, 'location name', 200), ref: cleanText(location.ref, 'location ref', 200) };
  });
  const days = map.rotateEveryDays;
  if (days !== null && !(Number.isSafeInteger(days) && days >= 1 && days <= 3650)) throw new Error('Invalid rotation period');
  return {
    project: cleanText(map.project, 'project', 200),
    environment: map.environment,
    locations,
    rotateEveryDays: days,
    notes: boundedString(map.notes, 'notes', { max: 2000 })
  };
}

function teamRequest(type, message) {
  switch (type) {
    case 'team-overview':
    case 'team-sign-in':
    case 'team-sign-out':
      exactKeys(message, ['type'], 'Request');
      return { type };
    case 'team-create':
      exactKeys(message, ['type', 'name'], 'Request');
      return { type, name: cleanText(message.name, 'team name', 100, { min: 1 }) };
    case 'team-open':
      exactKeys(message, ['type', 'teamId'], 'Request');
      return { type, teamId: teamId(message.teamId, 'team') };
    case 'team-vault-create':
      exactKeys(message, ['type', 'teamId', 'name'], 'Request');
      return { type, teamId: teamId(message.teamId, 'team'), name: cleanText(message.name, 'vault name', 100, { min: 1 }) };
    case 'team-save': {
      exactKeys(message, ['type', 'teamId', 'vaultId', 'recordId', 'item', 'map'], 'Request');
      plainObject(message.item, 'Item');
      exactKeys(message.item, ['kind', 'label', 'origin', 'username', 'secret'], 'Item');
      if (!KINDS.has(message.item.kind)) throw new Error('Invalid credential kind');
      const origin = boundedString(message.item.origin, 'site', { min: 1, max: 2048 });
      try { if (!['https:', 'http:'].includes(new URL(origin).protocol)) throw new Error(); } catch { throw new Error('Enter the site as a full address, like https://dashboard.stripe.com'); }
      return {
        type,
        teamId: teamId(message.teamId, 'team'),
        vaultId: teamId(message.vaultId, 'vault'),
        recordId: message.recordId === null ? null : teamId(message.recordId, 'record'),
        item: {
          kind: message.item.kind,
          label: cleanText(message.item.label, 'label', 128, { min: 1 }),
          origin,
          username: cleanText(message.item.username, 'username', 320),
          secret: message.item.secret === '' ? '' : boundedString(message.item.secret, 'secret', { min: 1, max: 16_384 })
        },
        map: teamMap(message.map)
      };
    }
    case 'team-share':
      exactKeys(message, ['type', 'teamId', 'vaultId', 'personalId', 'map'], 'Request');
      return {
        type,
        teamId: teamId(message.teamId, 'team'),
        vaultId: teamId(message.vaultId, 'vault'),
        personalId: boundedString(message.personalId, 'record id', { min: 1, max: 128, pattern: ID_PATTERN }),
        map: teamMap(message.map)
      };
    case 'team-delete':
      exactKeys(message, ['type', 'teamId', 'recordId'], 'Request');
      return { type, teamId: teamId(message.teamId, 'team'), recordId: teamId(message.recordId, 'record') };
    case 'team-invite': {
      exactKeys(message, ['type', 'teamId', 'email', 'role'], 'Request');
      const email = boundedString(message.email, 'email', { min: 3, max: 254 }).trim().toLowerCase();
      if (!EMAIL.test(email)) throw new Error('Enter a valid email address');
      if (!['admin', 'member'].includes(message.role)) throw new Error('Invalid role');
      return { type, teamId: teamId(message.teamId, 'team'), email, role: message.role };
    }
    case 'team-invite-cancel':
      exactKeys(message, ['type', 'teamId', 'inviteId'], 'Request');
      return { type, teamId: teamId(message.teamId, 'team'), inviteId: teamId(message.inviteId, 'invite') };
    case 'team-accept':
      exactKeys(message, ['type', 'inviteId'], 'Request');
      return { type, inviteId: teamId(message.inviteId, 'invite') };
    case 'team-confirm':
      exactKeys(message, ['type', 'teamId', 'inviteId', 'fingerprint'], 'Request');
      return {
        type,
        teamId: teamId(message.teamId, 'team'),
        inviteId: teamId(message.inviteId, 'invite'),
        fingerprint: boundedString(message.fingerprint, 'fingerprint', { min: 29, max: 29, pattern: FINGERPRINT })
      };
    case 'team-remove-member':
      exactKeys(message, ['type', 'teamId', 'userId'], 'Request');
      return { type, teamId: teamId(message.teamId, 'team'), userId: teamId(message.userId, 'user') };
    case 'team-remove-device':
      exactKeys(message, ['type', 'teamId', 'userId', 'deviceId'], 'Request');
      return { type, teamId: teamId(message.teamId, 'team'), userId: teamId(message.userId, 'user'), deviceId: teamId(message.deviceId, 'device') };
    case 'team-mark-rotated':
      exactKeys(message, ['type', 'teamId', 'recordId', 'secret'], 'Request');
      return {
        type,
        teamId: teamId(message.teamId, 'team'),
        recordId: teamId(message.recordId, 'record'),
        secret: message.secret === '' ? '' : boundedString(message.secret, 'secret', { min: 1, max: 16_384 })
      };
    case 'team-totp-setup':
      exactKeys(message, ['type'], 'Request');
      return { type };
    case 'team-totp-enable':
    case 'team-totp-verify':
      exactKeys(message, ['type', 'code'], 'Request');
      return { type, code: boundedString(message.code, 'code', { min: 6, max: 6, pattern: TOTP_CODE }) };
    case 'team-device-request':
    case 'team-kit-create':
    case 'team-recovery-start':
    case 'team-subscribe':
    case 'team-billing-portal':
      exactKeys(message, ['type', 'teamId'], 'Request');
      return { type, teamId: teamId(message.teamId, 'team') };
    case 'team-device-confirm':
      exactKeys(message, ['type', 'teamId', 'deviceId', 'fingerprint'], 'Request');
      return {
        type,
        teamId: teamId(message.teamId, 'team'),
        deviceId: teamId(message.deviceId, 'device'),
        fingerprint: boundedString(message.fingerprint, 'fingerprint', { min: 29, max: 29, pattern: FINGERPRINT })
      };
    case 'team-device-cancel':
      exactKeys(message, ['type', 'teamId', 'deviceId'], 'Request');
      return { type, teamId: teamId(message.teamId, 'team'), deviceId: teamId(message.deviceId, 'device') };
    case 'team-recovery-decide':
      exactKeys(message, ['type', 'teamId', 'requestId', 'decision'], 'Request');
      if (!['approve', 'cancel'].includes(message.decision)) throw new Error('Invalid decision');
      return { type, teamId: teamId(message.teamId, 'team'), requestId: teamId(message.requestId, 'request'), decision: message.decision };
    case 'team-recovery-finish':
      exactKeys(message, ['type', 'teamId', 'requestId', 'code'], 'Request');
      return {
        type,
        teamId: teamId(message.teamId, 'team'),
        requestId: teamId(message.requestId, 'request'),
        code: boundedString(message.code, 'recovery code', { min: 52, max: 80, pattern: /^[A-Za-z0-9 -]+$/ })
      };
    case 'team-export':
      exactKeys(message, ['type', 'teamId', 'passphrase'], 'Request');
      return { type, teamId: teamId(message.teamId, 'team'), passphrase: boundedString(message.passphrase, 'passphrase', { min: 12, max: 1024 }) };
    case 'team-copy':
      exactKeys(message, ['type', 'teamId', 'recordId', 'passphrase'], 'Request');
      return {
        type,
        teamId: teamId(message.teamId, 'team'),
        recordId: teamId(message.recordId, 'record'),
        passphrase: boundedString(message.passphrase, 'passphrase', { min: 12, max: 1024 })
      };
    default:
      return null;
  }
}

export function authorizeRequest(message, sender, { extensionId, popupUrl, teamPageUrl = null }) {
  plainObject(message, 'Request');
  const type = boundedString(message.type, 'message type', { min: 1, max: 32, pattern: /^[a-z-]+$/ });
  const isExtension = sender?.id === extensionId;
  // the Teams page is a tab too, so it is recognised by its exact extension URL before web tabs
  // (it keeps the open team in its #fragment, which is ignored; path and query must match exactly)
  const isTeamPage = isExtension && Boolean(teamPageUrl) && typeof sender?.url === 'string' &&
    sender.url.split('#')[0] === teamPageUrl && sender?.frameId === 0;
  const isWeb = isExtension && Boolean(sender?.tab) && !isTeamPage;
  const isPopup = isExtension && !sender?.tab && sender?.url === popupUrl;

  if (isTeamPage) {
    if (!TEAM_PAGE_TYPES.has(type)) throw new Error(`Message type ${type} is not allowed from the Teams page`);
  } else if (isWeb) {
    trustedSenderOrigin(sender);
    if (!WEB_TYPES.has(type)) throw new Error(`Message type ${type} is not allowed from web tabs`);
  } else if (isPopup) {
    if (!POPUP_TYPES.has(type)) throw new Error(`Message type ${type} is not allowed from the extension popup`);
  } else {
    throw new Error('Request sender is not authorized');
  }

  const team = teamRequest(type, message);
  if (team) return team;

  switch (type) {
    case 'status':
    case 'lock':
      exactKeys(message, ['type'], 'Request');
      return { type };
    case 'fill':
    case 'has-match':
      exactKeys(message, ['type', 'kind'], 'Request');
      if (!KINDS.has(message.kind)) throw new Error('Invalid credential kind');
      return { type, kind: message.kind };
    case 'setup':
    case 'unlock':
      exactKeys(message, ['type', 'passphrase'], 'Request');
      return { type, passphrase: boundedString(message.passphrase, 'passphrase', { min: 12, max: 1024 }) };
    case 'remove':
      exactKeys(message, ['type', 'id'], 'Request');
      return { type, id: boundedString(message.id, 'record id', { min: 1, max: 128, pattern: ID_PATTERN }) };
    case 'verify':
      exactKeys(message, ['type', 'id', 'secret'], 'Request');
      return {
        type,
        id: boundedString(message.id, 'record id', { min: 1, max: 128, pattern: ID_PATTERN }),
        secret: boundedString(message.secret, 'secret', { min: 1, max: 16_384 })
      };
    case 'copy':
      exactKeys(message, ['type', 'id', 'passphrase'], 'Request');
      return {
        type,
        id: boundedString(message.id, 'record id', { min: 1, max: 128, pattern: ID_PATTERN }),
        passphrase: boundedString(message.passphrase, 'passphrase', { min: 12, max: 1024 })
      };
    case 'set-auto-lock':
      exactKeys(message, ['type', 'minutes'], 'Request');
      if (!AUTO_LOCK_MINUTES.includes(message.minutes)) throw new Error('Invalid auto-lock minutes');
      return { type, minutes: message.minutes };
    case 'save': {
      exactKeys(message, ['type', 'item'], 'Request');
      plainObject(message.item, 'Save item');
      exactKeys(message.item, ['kind', 'label', 'username', 'secret'], 'Save item');
      if (!KINDS.has(message.item.kind)) throw new Error('Invalid credential kind');
      const label = boundedString(message.item.label, 'label', { min: 1, max: 128 });
      if (!label.trim() || /[\u0000-\u001f\u007f]/.test(label)) throw new Error('Invalid label');
      const username = message.item.username === undefined ? '' : boundedString(message.item.username, 'username', { max: 320 });
      if (/[\u0000-\u001f\u007f]/.test(username)) throw new Error('Invalid username');
      const secret = boundedString(message.item.secret, 'secret', { min: 1, max: 16_384 });
      return { type, item: { kind: message.item.kind, label, username, secret } };
    }
    default:
      throw new Error('Unknown Otter Vault request');
  }
}
