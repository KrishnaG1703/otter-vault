const API_KEY_PATTERN = /(api[-_ ]?key|secret[-_ ]?key|access[-_ ]?token|private[-_ ]?token|client[-_ ]?secret)/i;
const REVEAL_CONTEXT_PATTERN = /(api\s*key|secret|token).{0,80}(created|generated|copy|shown|reveal)|(?:created|generated|copy|shown|reveal).{0,80}(api\s*key|secret|token)/i;
const SECRET_VALUE_PATTERN = /^(?:sk[-_][a-z0-9_-]+|[a-z0-9_-]{24,})$/i;

export function classifySecretField(field = {}) {
  const type = String(field.type || '').toLowerCase();
  const haystack = [field.name, field.id, field.ariaLabel, field.placeholder, field.autocomplete]
    .filter(Boolean)
    .join(' ');

  if (type === 'password' || /(?:new|current)-password/i.test(field.autocomplete || '')) return 'login';
  if (API_KEY_PATTERN.test(haystack)) return 'api-key';
  return null;
}

export function classifyRevealedSecret({ value = '', context = '' } = {}) {
  const candidate = String(value).trim();
  if (candidate.length < 16 || candidate.length > 512) return null;
  if (!SECRET_VALUE_PATTERN.test(candidate)) return null;
  if (!REVEAL_CONTEXT_PATTERN.test(String(context))) return null;
  return 'api-key';
}

export function evaluateSecurityChecks(posture = {}) {
  const autoLockPass = Number(posture.autoLockMinutes) > 0 && Number(posture.autoLockMinutes) <= 15;
  return [
    { id: 'encryption', label: 'Authenticated encryption', detail: 'AES-256-GCM protects secret values at rest.', status: posture.algorithm === 'AES-256-GCM' ? 'pass' : 'warning' },
    { id: 'origin', label: 'Exact-site binding', detail: 'Saved secrets open only for the original protocol, host, and port.', status: posture.exactOrigin ? 'pass' : 'warning' },
    { id: 'auto-lock', label: 'Automatic lock', detail: `Vault locks after ${posture.autoLockMinutes || 'no'} minutes of inactivity.`, status: autoLockPass ? 'pass' : 'warning' },
    { id: 'hardware-key', label: 'Hardware-backed key', detail: 'Secure Enclave or TPM custody is required for production.', status: posture.hardwareBacked ? 'pass' : 'warning' },
    { id: 'metadata', label: 'Encrypted metadata', detail: 'Labels, usernames, and origins should be hidden in production.', status: posture.metadataEncrypted ? 'pass' : 'warning' }
  ];
}

export function maskSecret(secret = '') {
  const value = String(secret);
  if (!value) return '••••••••';
  if (value.length <= 6) return '•'.repeat(value.length);
  const prefixLength = value.startsWith('sk-') ? 3 : 2;
  const suffixLength = 3;
  return `${value.slice(0, prefixLength)}${'•'.repeat(value.length - prefixLength - suffixLength)}${value.slice(-suffixLength)}`;
}

export function createVaultItem({ kind, label, origin, secret }) {
  return { kind, label, origin, masked: maskSecret(secret) };
}

const TRANSITIONS = {
  resting: { 'secret-focused': 'noticing' },
  noticing: { 'offer-ready': 'offering', blur: 'resting' },
  offering: { saved: 'celebrating', dismissed: 'resting' },
  celebrating: { settled: 'resting' }
};

export function transitionCompanion(state, event) {
  return TRANSITIONS[state]?.[event] || state;
}
