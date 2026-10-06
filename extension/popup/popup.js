const $ = selector => document.querySelector(selector);
const views = ['#setup-view', '#unlock-view', '#vault-view'];

function send(message) {
  return new Promise(resolve => chrome.runtime.sendMessage(message, response => {
    if (chrome.runtime.lastError) resolve({ ok: false, error: chrome.runtime.lastError.message });
    else resolve(response || { ok: false, error: 'No response from vault' });
  }));
}

function showView(selector) {
  views.forEach(view => $(view).hidden = view !== selector);
  // Lock sits beside the status in the header, so it only shows when there is something to lock
  $('#lock-button').hidden = selector !== '#vault-view';
}

function showError(message = '') {
  $('#error').textContent = message;
  $('#error').hidden = !message;
}

function setBadge(unlocked) {
  $('#state').textContent = unlocked ? 'Unlocked' : 'Locked';
  $('#state').classList.toggle('unlocked', unlocked);
}

// One inline form under a record at a time: Copy asks for the passphrase, Compare for the original.
function toggleForm(article, trigger, { inputType, placeholder, autocomplete, onSubmit }) {
  const open = trigger.getAttribute('aria-expanded') === 'true';
  // only one form open in the whole list
  document.querySelectorAll('.verify, .verdict').forEach(node => node.remove());
  document.querySelectorAll('.record [aria-expanded]').forEach(button => button.setAttribute('aria-expanded', 'false'));
  if (open) return;
  trigger.setAttribute('aria-expanded', 'true');
  const form = document.createElement('form');
  form.className = 'verify';
  const input = document.createElement('input');
  input.type = inputType;
  input.required = true;
  input.autocomplete = autocomplete;
  input.placeholder = placeholder;
  input.setAttribute('aria-label', placeholder);
  const verdict = document.createElement('p');
  verdict.className = 'verdict';
  verdict.setAttribute('role', 'status');
  form.append(input);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    showError();
    if (input.disabled) return;
    input.disabled = true;
    const value = input.value;
    input.value = '';
    verdict.className = 'verdict';
    verdict.textContent = 'Checking…';
    try {
      const [good, text] = await onSubmit(value);
      verdict.className = `verdict ${good ? 'match' : 'mismatch'}`;
      verdict.textContent = text;
    } finally {
      input.disabled = false;
      input.focus();
    }
  });
  article.append(form, verdict);
  input.focus();
}

// Chrome only allows this while the popup has focus. A copy-event fallback reports success
// without writing when unfocused, so failure is surfaced instead of a false "copied".
async function writeClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

function formatWait(seconds) {
  return seconds >= 60 ? `${Math.round(seconds / 60)} min` : `${seconds} sec`;
}

let allRecords = [];
let activeFilter = 'all';

// search runs over what the popup already has: label, site, username and key hint, never the secret
function matchesSearch(record, query) {
  if (!query) return true;
  const haystack = [record.label, record.origin, record.username, record.hint].filter(Boolean).join(' ').toLowerCase();
  return query.toLowerCase().split(/\s+/).filter(Boolean).every(word => haystack.includes(word));
}

function renderRecords(records = allRecords) {
  allRecords = records;
  $('#empty').hidden = records.length > 0 || sharedRecords.length > 0;
  $('#finder').hidden = records.length === 0 && sharedRecords.length === 0;
  for (const kind of ['all', 'api-key', 'login']) {
    $(`[data-count="${kind}"]`).textContent = [...records, ...sharedRecords].filter(record => kind === 'all' || record.kind === kind).length;
  }
  const query = $('#search').value.trim();
  const shown = records.filter(record => (activeFilter === 'all' || record.kind === activeFilter) && matchesSearch(record, query));
  $('#no-results').hidden = records.length === 0 || shown.length > 0;
  $('#records').hidden = records.length === 0;
  const container = $('#records');
  container.replaceChildren();
  for (const record of shown) {
    const isKey = record.kind === 'api-key';
    const article = document.createElement('article');
    article.className = 'record';

    const glyph = document.createElement('span');
    glyph.className = 'glyph';
    glyph.textContent = isKey ? '{ }' : '•••';

    const details = document.createElement('span');
    const label = document.createElement('strong');
    label.textContent = record.label;
    label.title = record.label;
    const origin = document.createElement('small');
    origin.textContent = record.origin;
    details.append(label, origin);
    // the hint matches the last characters the provider lists for the key, without being usable
    for (const extra of [record.hint, record.username]) {
      if (!extra) continue;
      const line = document.createElement('small');
      line.className = 'user';
      line.textContent = extra;
      details.append(line);
    }

    const actions = document.createElement('span');
    actions.className = 'record-actions';

    const copy = document.createElement('button');
    copy.className = 'check';
    copy.type = 'button';
    copy.textContent = 'Copy';
    copy.setAttribute('aria-expanded', 'false');
    copy.setAttribute('aria-label', `Copy the ${isKey ? 'key' : 'password'} for ${record.label}`);
    copy.addEventListener('click', () => toggleForm(article, copy, {
      inputType: 'password', autocomplete: 'current-password', placeholder: 'Vault passphrase, then press Enter',
      async onSubmit(passphrase) {
        const response = await send({ type: 'copy', id: record.id, passphrase });
        if (!response.ok) {
          if (/locked/i.test(response.error)) await refresh();
          return [false, response.error];
        }
        if (!(await writeClipboard(response.data.secret))) return [false, 'Chrome blocked the clipboard because the popup lost focus. Try again.'];
        return [true, `✓ Copied. Otter clears it from the clipboard in ${formatWait(response.data.clearsInSeconds)}.`];
      }
    }));
    actions.append(copy);

    // a password is something you still know, so it can be checked against the vault copy
    if (!isKey) {
      const check = document.createElement('button');
      check.className = 'check';
      check.type = 'button';
      check.textContent = 'Compare';
      check.setAttribute('aria-expanded', 'false');
      check.setAttribute('aria-label', `Compare the saved password for ${record.label}`);
      check.addEventListener('click', () => toggleForm(article, check, {
        inputType: 'password', autocomplete: 'off', placeholder: 'Type the password, then press Enter',
        async onSubmit(secret) {
          const response = await send({ type: 'verify', id: record.id, secret });
          if (!response.ok) return [false, response.error];
          return response.data.match ? [true, '✓ Exact match.'] : [false, '✗ Not a match.'];
        }
      }));
      actions.append(check);
    }

    const button = document.createElement('button');
    button.className = 'delete';
    button.type = 'button';
    button.textContent = '×';
    button.setAttribute('aria-label', `Delete ${record.label}`);
    button.addEventListener('click', async () => {
      const response = await send({ type: 'remove', id: record.id });
      if (response.ok) renderRecords(response.data);
      else showError(response.error);
    });
    actions.append(button);

    article.append(glyph, details, actions);
    container.append(article);
  }
}

$('#search').addEventListener('input', () => { renderRecords(); renderShared(sharedRecords); });
document.querySelectorAll('[data-filter]').forEach(tab => tab.addEventListener('click', () => {
  activeFilter = tab.dataset.filter;
  document.querySelectorAll('[data-filter]').forEach(other => other.setAttribute('aria-selected', String(other === tab)));
  renderRecords();
  renderShared(sharedRecords);
}));

function renderAutoLock(minutes = 5) {
  $('#auto-lock-label').textContent = minutes;
  document.querySelectorAll('[data-minutes]').forEach(button => {
    button.setAttribute('aria-pressed', String(Number(button.dataset.minutes) === minutes));
  });
}

document.querySelectorAll('[data-minutes]').forEach(button => button.addEventListener('click', async () => {
  showError();
  const response = await send({ type: 'set-auto-lock', minutes: Number(button.dataset.minutes) });
  if (!response.ok) return showError(response.error);
  renderAutoLock(response.data.autoLockMinutes);
}));

// Shared keys from Teams: same Copy (passphrase again, clipboard wiped), plus the team's name.
// They are read-only here; editing and deleting happen on the Teams page.
function renderShared(shared = []) {
  const query = $('#search').value.trim();
  const shown = shared.filter(record => (activeFilter === 'all' || record.kind === activeFilter) && matchesSearch(record, query));
  $('#shared').hidden = shown.length === 0;
  $('#shared-records').replaceChildren(...shown.map(record => {
    const article = document.createElement('article');
    article.className = 'record';
    const glyph = document.createElement('span');
    glyph.className = 'glyph';
    glyph.textContent = record.kind === 'api-key' ? '{ }' : '•••';
    const details = document.createElement('span');
    const label = document.createElement('strong');
    label.textContent = record.label;
    label.title = record.label;
    const badge = document.createElement('span');
    badge.className = 'team-badge';
    badge.textContent = record.teamName;
    label.append(badge);
    const origin = document.createElement('small');
    origin.textContent = record.origin;
    details.append(label, origin);
    for (const extra of [record.hint, record.map?.locations?.[0]?.name]) {
      if (!extra) continue;
      const line = document.createElement('small');
      line.className = 'user';
      line.textContent = extra;
      details.append(line);
    }
    const actions = document.createElement('span');
    actions.className = 'record-actions';
    const copy = document.createElement('button');
    copy.className = 'check';
    copy.type = 'button';
    copy.textContent = 'Copy';
    copy.setAttribute('aria-expanded', 'false');
    copy.setAttribute('aria-label', `Copy ${record.label} from ${record.teamName}`);
    copy.addEventListener('click', () => toggleForm(article, copy, {
      inputType: 'password', autocomplete: 'current-password', placeholder: 'Vault passphrase, then press Enter',
      async onSubmit(passphrase) {
        const response = await send({ type: 'team-copy', teamId: record.teamId, recordId: record.id, passphrase });
        if (!response.ok) {
          if (/locked/i.test(response.error)) await refresh();
          return [false, response.error];
        }
        if (!(await writeClipboard(response.data.secret))) return [false, 'Chrome blocked the clipboard because the popup lost focus. Try again.'];
        return [true, `✓ Copied. Clears in ${formatWait(response.data.clearsInSeconds)}. Logged for ${record.teamName}.`];
      }
    }));
    actions.append(copy);
    article.append(glyph, details, actions);
    return article;
  }));
}

let sharedRecords = [];

$('#teams-link').addEventListener('click', () => chrome.tabs.create({ url: chrome.runtime.getURL('team/team.html') }));

async function refresh() {
  showError();
  const response = await send({ type: 'status' });
  if (!response.ok) return showError(response.error);
  const state = response.data;
  setBadge(state.unlocked);
  renderAutoLock(state.autoLockMinutes);
  if (!state.configured) showView('#setup-view');
  else if (!state.unlocked) showView('#unlock-view');
  else {
    showView('#vault-view');
    sharedRecords = state.shared || [];
    renderRecords(state.records);
    renderShared(sharedRecords);
    if (state.records.length || sharedRecords.length) $('#search').focus();
  }
}

$('#setup-form').addEventListener('submit', async event => {
  event.preventDefault(); showError();
  const passphrase = $('#new-passphrase').value;
  if (passphrase !== $('#confirm-passphrase').value) return showError('The passphrases do not match.');
  const response = await send({ type: 'setup', passphrase });
  if (!response.ok) return showError(response.error);
  $('#setup-form').reset();
  await refresh();
});

$('#unlock-form').addEventListener('submit', async event => {
  event.preventDefault(); showError();
  const response = await send({ type: 'unlock', passphrase: $('#passphrase').value });
  $('#unlock-form').reset();
  if (!response.ok) return showError(response.error);
  await refresh();
});

$('#lock-button').addEventListener('click', async () => {
  await send({ type: 'lock' });
  await refresh();
});

// The follower is a plain preference, read by the content script straight from storage.
const FOLLOW_KEY = 'cursorCompanion';
function renderFollow(on) { $('#follow-toggle').setAttribute('aria-checked', String(on)); }
chrome.storage.local.get(FOLLOW_KEY, stored => renderFollow(Boolean(stored[FOLLOW_KEY])));
$('#follow-toggle').addEventListener('click', () => {
  const on = $('#follow-toggle').getAttribute('aria-checked') !== 'true';
  chrome.storage.local.set({ [FOLLOW_KEY]: on }, () => renderFollow(on));
});

refresh();
