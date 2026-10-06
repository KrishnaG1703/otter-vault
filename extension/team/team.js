import { iconForOrigin } from './provider-icons.js';

// The Teams page. Everything is built with textContent, never innerHTML: key labels, emails and
// notes come from other people (and through a server), so none of it is trusted as markup.
const $ = selector => document.querySelector(selector);

function send(message) {
  return new Promise(resolve => chrome.runtime.sendMessage(message, response => {
    if (chrome.runtime.lastError) resolve({ ok: false, error: chrome.runtime.lastError.message });
    else resolve(response || { ok: false, error: 'No response from Otter' });
  }));
}

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? '' : value);
  }
  node.append(...children.flat().filter(child => child !== null && child !== undefined && child !== false));
  return node;
}

function showError(message = '') {
  $('#error').textContent = message;
  $('#error-box').hidden = !message;
  if (message) $('#notice-box').hidden = true;
}

function notify(message = '') {
  $('#notice').textContent = message;
  $('#notice-box').hidden = !message;
}

// Runs one request with its button disabled, and surfaces the error instead of throwing.
async function act(button, message) {
  showError();
  if (button) button.disabled = true;
  try {
    const response = await send(message);
    if (!response.ok) {
      showError(response.error);
      if (/locked/i.test(response.error)) await refresh();
      return null;
    }
    return response.data;
  } finally {
    if (button) button.disabled = false;
  }
}

const DAY = 86_400_000;
const LOCATION_LABELS = {
  'vercel-env': 'Vercel env', 'github-actions': 'GitHub Actions', 'aws-ssm': 'AWS SSM', 'aws-secrets-manager': 'AWS Secrets Manager',
  'gcp-secret-manager': 'GCP Secret Manager', 'cloudflare-secret': 'Cloudflare secret', 'env-file': '.env file', other: 'Other'
};
const VERBS = { create: 'added', edit: 'edited', delete: 'deleted', copy: 'copied', fill: 'filled in', 'view-hint': 'looked at', 'rotate-mark': 'marked as rotated', recover: 'recovered access' };

const initial = email => (email || '?').trim().charAt(0).toUpperCase();
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

function ago(time) {
  const ms = Date.now() - Date.parse(time);
  if (!Number.isFinite(ms)) return '';
  if (ms < 60_000) return 'just now';
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)} min ago`;
  if (ms < DAY) return `${Math.round(ms / 3_600_000)} h ago`;
  const days = Math.round(ms / DAY);
  return days === 1 ? 'yesterday' : `${days} days ago`;
}

function rotation(record) {
  const days = record.map.rotateEveryDays;
  if (!days) return null;
  const due = Date.parse(record.map.lastRotatedAt || record.createdAt) + days * DAY;
  const left = Math.ceil((due - Date.now()) / DAY);
  if (left < 0) return { text: `Rotation overdue by ${-left} days`, level: 'overdue' };
  if (left <= 14) return { text: `Rotate within ${left} days`, level: 'due' };
  return { text: `Rotate in ${left} days`, level: '' };
}

let overview = null;
let detail = null;
let currentTeamId = location.hash.slice(1) || null;
let personal = [];

// ---- top level ----

async function refresh() {
  const response = await send({ type: 'team-overview' });
  if (!response.ok) return showError(response.error);
  overview = response.data;
  $('#locked-view').hidden = !overview.locked;
  $('#signin-view').hidden = overview.locked || overview.signedIn;
  $('#teams-view').hidden = overview.locked || !overview.signedIn;
  $('#account').hidden = !overview.signedIn;
  if (overview.locked || !overview.signedIn) return;
  $('#account-email').textContent = overview.email;
  $('#account-avatar').textContent = initial(overview.email);
  $('#device-fingerprint').textContent = overview.fingerprint;
  renderTeamList();
  renderMyInvites();
  renderTotp();
  if (currentTeamId && overview.teams.some(team => team.id === currentTeamId)) await openTeam(currentTeamId);
  else if (overview.teams.length === 1) await openTeam(overview.teams[0].id);
}

function renderTeamList() {
  const list = $('#team-list');
  list.replaceChildren(...overview.teams.map(team => el('button', {
    type: 'button',
    'aria-current': String(team.id === currentTeamId),
    onclick: () => openTeam(team.id)
  }, el('span', { text: team.name }), el('small', {
    text: team.broken ? 'needs attention' : team.access ? 'not on this device' : team.people ? plural(team.people, 'person', 'people') : plural(team.keys, 'key')
  }))));
  $('#no-teams').hidden = overview.teams.length > 0;
}

function renderMyInvites() {
  const invites = overview.invites || [];
  $('#invites-card').hidden = invites.length === 0;
  $('#my-invites').replaceChildren(...invites.map(invite => {
    const button = el('button', { class: 'primary small', type: 'button', text: 'Accept' });
    button.addEventListener('click', async () => {
      const data = await act(button, { type: 'team-accept', inviteId: invite.id });
      if (!data) return;
      notify(`Accepted. Read this code to ${invite.invitedBy} so they can add you: ${data.fingerprint}`);
      await refresh();
    });
    return el('div', { class: 'invite' }, el('span', { text: `${invite.invitedBy} invited you as ${invite.role}` }), button);
  }));
}

async function openTeam(teamId) {
  const listed = overview.teams.find(team => team.id === teamId);
  if (listed?.access) {
    currentTeamId = teamId;
    history.replaceState(null, '', `#${teamId}`);
    renderTeamList();
    detail = null;
    renderAccess(listed);
    return;
  }
  $('#access-view').hidden = true;
  clearTimeout(waitingTimer);
  const firstLoad = !detail || detail.id !== teamId;
  currentTeamId = teamId;
  history.replaceState(null, '', `#${teamId}`);
  renderTeamList();
  // the swimming otter only shows when switching teams, not on every refresh of the same one
  if (firstLoad) {
    $('#pick-team').hidden = true;
    $('#team-detail').hidden = true;
    $('#loading-text').textContent = `Fetching ${overview.teams.find(team => team.id === teamId)?.name || 'your team'}…`;
    $('#loading').hidden = false;
  }
  const [data, status] = await Promise.all([act(null, { type: 'team-open', teamId }), send({ type: 'status' })]);
  $('#loading').hidden = true;
  if (!data) {
    if (firstLoad) $('#pick-team').hidden = false;
    return;
  }
  detail = data;
  personal = status.ok ? status.data.records || [] : [];
  renderDetail();
}

async function reopen() {
  if (currentTeamId) await openTeam(currentTeamId);
}

// ---- team detail ----

// What the owner's billing button does: subscribe, fix a failed payment, or manage a subscription.
function billingAction(billing) {
  if (billing.status === 'active' && billing.paid) return { type: 'team-billing-portal', label: 'Manage billing' };
  if (billing.status === 'on_hold') return { type: 'team-billing-portal', label: 'Update payment' };
  return { type: 'team-subscribe', label: billing.earlyBird ? 'Subscribe · $20/month early-bird' : 'Subscribe · $29/month' };
}

function renderBillingButton(billing) {
  const button = $('#billing-button');
  button.hidden = detail.role !== 'owner';
  if (button.hidden) return;
  const action = billingAction(billing);
  button.textContent = action.label;
  button.dataset.action = action.type;
}

// Checkout and the customer portal are Dodo Payments pages; nothing else is ever opened from here.
function openBillingPage(url) {
  let target;
  try { target = new URL(url); } catch { return false; }
  if (target.protocol !== 'https:' || !(target.hostname === 'dodopayments.com' || target.hostname.endsWith('.dodopayments.com'))) return false;
  window.open(target.href, '_blank', 'noopener');
  return true;
}

$('#billing-button').addEventListener('click', async event => {
  const button = event.currentTarget;
  const data = await act(button, { type: button.dataset.action, teamId: detail.id });
  if (data && !openBillingPage(data.url)) showError('The payment page link looked wrong, so it was not opened.');
  else if (data) notify('Finish in the new tab. This page updates by itself once the payment goes through.');
});

// How much trial is left, in the unit that matters: days, then hours, then minutes.
function trialLeft(endsAt) {
  const ms = Math.max(0, endsAt - Date.now());
  if (ms >= 2 * DAY) return `${Math.floor(ms / DAY)} days left`;
  if (ms >= DAY) return '1 day left';
  if (ms >= 2 * 3_600_000) return `ends in ${Math.floor(ms / 3_600_000)} h`;
  return `ends in ${Math.max(1, Math.ceil(ms / 60_000))} min`;
}

function renderDetail() {
  $('#pick-team').hidden = true;
  $('#team-detail').hidden = false;
  $('#team-title').textContent = detail.name;
  $('#team-role').textContent = `Team workspace · ${detail.role}`;
  $('#team-meta').replaceChildren(...[[detail.records.length, 'shared key'], [detail.members.length, 'member'], [detail.vaults.length, 'vault']]
    .map(([n, word]) => el('span', {}, el('b', { text: String(n) }), ` ${plural(n, word).replace(/^\d+ /, '')}`)));
  const billing = detail.billing || {};
  const chip = $('#trial-chip');
  chip.textContent = billing.paid ? 'Subscribed' : detail.readOnly ? 'Read-only · trial ended' : `Free trial · ${trialLeft(detail.trialEndsAt)}`;
  chip.classList.toggle('ok', Boolean(billing.paid));
  chip.classList.toggle('stop', !billing.paid && Boolean(detail.readOnly));
  chip.classList.toggle('soon', !billing.paid && !detail.readOnly && detail.trialEndsAt - Date.now() < 3 * DAY);
  renderBillingButton(billing);
  $('#read-only').hidden = !detail.readOnly;
  $('#add-button').disabled = detail.readOnly;
  $('#share-button').disabled = detail.readOnly;
  $('#export-box').hidden = !detail.admin || detail.records.length === 0;
  const canInvite = detail.admin && !detail.readOnly;
  if (!canInvite) $('#invite-form').hidden = true;
  $('#invite-toggle').hidden = !canInvite || !$('#invite-form').hidden;
  const filter = $('#vault-filter');
  const chosen = filter.value;
  filter.replaceChildren(el('option', { value: '', text: 'All vaults' }), ...detail.vaults.map(vault => el('option', { value: vault.id, text: vault.name })));
  filter.value = detail.vaults.some(vault => vault.id === chosen) ? chosen : '';
  $('#key-form').hidden = true;
  renderKeys();
  renderPeople();
  renderActivity();
  renderAttention();
}

function vaultName(id) {
  return detail.vaults.find(vault => vault.id === id)?.name || 'vault';
}

function renderKeys() {
  const vault = $('#vault-filter').value;
  const words = $('#key-search').value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const shown = detail.records.filter(record => {
    if (vault && record.vaultId !== vault) return false;
    const haystack = [record.label, record.origin, record.username, record.hint, record.map.project, record.map.environment, record.map.notes,
      ...record.map.locations.flatMap(location => [location.name, location.ref])].join(' ').toLowerCase();
    return words.every(word => haystack.includes(word));
  }).sort((a, b) => a.label.localeCompare(b.label));
  $('#no-keys').hidden = detail.records.length > 0;
  $('#keys-head').hidden = detail.records.length === 0;
  $('#key-list').hidden = shown.length === 0;
  $('#key-columns').hidden = shown.length === 0;
  // a search or vault filter that hides every key says so, instead of an empty space
  const filtered = detail.records.length > 0 && shown.length === 0;
  $('#no-match').hidden = !filtered;
  if (filtered) {
    const query = $('#key-search').value.trim();
    $('#no-match-text').textContent = query
      ? `Nothing in ${vault ? vaultName(vault) : 'this team'} matches "${query}".`
      : `${vaultName(vault)} has no keys yet.`;
  }
  $('#key-count').textContent = shown.length === detail.records.length ? plural(shown.length, 'key') : `${shown.length} of ${detail.records.length}`;
  $('#key-list').replaceChildren(...shown.map(keyCard));
  // the otter nudges once a key has no recorded home
  $('#key-tip').hidden = filtered || detail.readOnly || !detail.records.some(record => record.map.locations.length === 0);
}

// A small "⋯" menu for the less common actions on a row.
function rowMenu(label, items) {
  const menu = el('details', { class: 'row-menu' },
    el('summary', { 'aria-label': `More actions for ${label}`, text: '⋯' }),
    el('div', { class: 'menu' }, ...items.filter(Boolean)));
  menu.addEventListener('toggle', () => {
    if (menu.open) document.querySelectorAll('.row-menu[open]').forEach(other => { if (other !== menu) other.open = false; });
  });
  return menu;
}
document.addEventListener('click', event => {
  if (!event.target.closest('.row-menu')) document.querySelectorAll('.row-menu[open]').forEach(menu => { menu.open = false; });
});

function keyCard(record) {
  const due = rotation(record);
  const [first, ...more] = record.map.locations;
  const moreButton = more.length ? el('button', {
    class: 'more-link', type: 'button', 'aria-expanded': 'false', text: `+${more.length} more`,
    'aria-label': `Show all ${record.map.locations.length} places ${record.label} is used`,
    'aria-controls': `places-${record.id}`
  }) : null;
  const where = first
    ? el('div', { class: 'key-col' },
      el('code', { class: 'var', text: first.name || first.ref || LOCATION_LABELS[first.type] }),
      el('small', {}, `${LOCATION_LABELS[first.type]}${first.ref && first.name ? ` · ${first.ref}` : ''}`, moreButton ? ' · ' : '', moreButton))
    : el('div', { class: 'key-col' },
      record.hint ? el('code', { class: 'var', text: record.hint }) : null,
      el('small', { class: 'unset', text: 'Location not recorded' }));
  const card = el('article', { class: 'row key', 'data-env': record.map.environment },
    keyLogo(record),
    el('div', { class: 'key-col key-name' },
      el('div', { class: 'key-title' },
        el('strong', { text: record.label }),
        el('span', { class: `env ${record.map.environment}`, text: record.map.environment })),
      el('small', { text: [record.map.project, vaultName(record.vaultId)].filter(Boolean).join(' · ') })),
    where,
    el('div', { class: 'key-col' },
      el('span', { class: `rotate ${due?.level || ''}`, text: due ? due.text : 'No rotation schedule' }),
      el('small', { title: record.updatedByEmail, text: `Updated ${ago(record.updatedAt)} by ${record.updatedByEmail.split('@')[0]}` })));

  const copy = el('button', { class: 'ghost', type: 'button', text: 'Copy' });
  copy.addEventListener('click', () => toggleCopy(card, record));
  const edit = el('button', { type: 'button', text: 'Edit details', disabled: detail.readOnly });
  edit.addEventListener('click', () => openKeyForm('edit', record));
  const remove = el('button', { class: 'bad', type: 'button', text: 'Delete for everyone' });
  remove.addEventListener('click', async () => {
    if (!confirm(`Delete "${record.label}" for everyone on ${detail.name}?`)) return;
    if (await act(remove, { type: 'team-delete', teamId: detail.id, recordId: record.id })) await reopen();
  });
  const info = el('p', { class: 'menu-note', text: [record.origin, record.username, record.map.notes].filter(Boolean).join(' · ') });
  card.append(el('div', { class: 'row-actions' }, copy, rowMenu(record.label, [info.textContent ? info : null, edit, remove])));
  // "+2 more" opens every place the key is deployed, so a rotation updates all of them
  moreButton?.addEventListener('click', () => {
    const open = card.querySelector('.places');
    moreButton.setAttribute('aria-expanded', String(!open));
    if (open) { open.remove(); return; }
    card.append(el('div', { class: 'places', id: `places-${record.id}` },
      el('strong', { text: `Used in ${record.map.locations.length} places` }),
      el('div', { class: 'place-grid' }, ...record.map.locations.map(location => el('div', { class: 'place' },
        el('span', {}, el('b', { text: LOCATION_LABELS[location.type] }), location.ref ? ` · ${location.ref}` : ''),
        location.name ? el('code', { text: location.name }) : null)))));
  });
  return card;
}

// The provider's mark when the key's site belongs to one we know; otherwise its first letter.
// The marks ship inside the extension (provider-icons.js), so nothing is fetched to draw them.
const SVG = 'http://www.w3.org/2000/svg';
function keyLogo(record) {
  const icon = iconForOrigin(record.origin);
  if (!icon) return el('span', { class: 'key-logo', 'aria-hidden': 'true', text: initial(record.label) });
  const [r, g, b] = [0, 2, 4].map(i => parseInt(icon.hex.slice(i, i + 2), 16));
  // a very light brand colour (Hugging Face yellow) would vanish on white, so it draws in ink
  const light = (0.299 * r + 0.587 * g + 0.114 * b) / 255 > 0.72;
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(SVG, 'path');
  path.setAttribute('d', icon.path);
  path.setAttribute('fill', light ? '#17362f' : `#${icon.hex}`);
  if (icon.evenOdd) path.setAttribute('fill-rule', 'evenodd');
  svg.append(path);
  const tile = el('span', { class: 'key-logo branded', title: icon.title });
  if (light) tile.style.background = `#${icon.hex}`;
  tile.append(svg);
  return tile;
}

function toggleCopy(card, record) {
  const open = card.querySelector('.copy-form');
  document.querySelectorAll('.copy-form').forEach(form => form.remove());
  if (open) return;
  const input = el('input', { type: 'password', required: true, autocomplete: 'current-password', placeholder: 'Vault passphrase, then Enter', 'aria-label': 'Vault passphrase' });
  const status = el('span', { class: 'muted small', role: 'status' });
  const form = el('form', { class: 'copy-form' }, input, status);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const passphrase = input.value;
    input.value = '';
    status.textContent = 'Checking…';
    const data = await act(null, { type: 'team-copy', teamId: detail.id, recordId: record.id, passphrase });
    if (!data) { status.textContent = ''; return; }
    try {
      await navigator.clipboard.writeText(data.secret);
      status.textContent = `Copied. Otter clears the clipboard in ${Math.round(data.clearsInSeconds / 60)} min, and the copy is in the team's activity.`;
    } catch {
      status.textContent = 'Chrome blocked the clipboard. Click the page and try again.';
    }
  });
  card.append(form);
  input.focus();
}

// ---- add, edit, share ----

function field(labelText, control, wide = false) {
  const id = `f-${Math.random().toString(36).slice(2, 8)}`;
  control.id = id;
  return el('div', { class: wide ? 'wide' : '' }, el('label', { for: id, text: labelText }), control);
}

function select(options, value) {
  const node = el('select', {}, ...options.map(([optionValue, text]) => el('option', { value: optionValue, text })));
  if (value !== undefined) node.value = value;
  return node;
}

function locationRow(location = { type: 'vercel-env', name: '', ref: '' }) {
  const row = el('div', { class: 'location-row' },
    select(Object.entries(LOCATION_LABELS), location.type),
    el('input', { placeholder: 'Variable name, e.g. STRIPE_SECRET_KEY', value: location.name, maxlength: 200, 'aria-label': 'Variable name' }),
    el('input', { placeholder: 'Project, repo or path', value: location.ref, maxlength: 200, 'aria-label': 'Where' }));
  row.append(el('button', { class: 'ghost small', type: 'button', text: 'Remove', onclick: () => row.remove() }));
  return row;
}

function openKeyForm(mode, record = null) {
  const form = $('#key-form');
  form.replaceChildren();
  const map = record?.map || { project: '', environment: 'prod', locations: [], rotateEveryDays: 90, notes: '' };
  const controls = {};
  const parts = [];
  if (mode === 'share') {
    const own = personal.map(item => [item.id, `${item.label} · ${item.origin}${item.hint ? ` · ${item.hint}` : ''}`]);
    if (!own.length) { showError('Your own vault is empty. Let Otter catch a key first, or use Add key.'); return; }
    controls.personal = select(own);
    parts.push(field('Key from your vault', controls.personal, true));
  } else {
    controls.kind = select([['api-key', 'API key'], ['login', 'Password']], record?.kind || 'api-key');
    controls.label = el('input', { required: true, maxlength: 128, value: record?.label || '', placeholder: 'Stripe live secret' });
    controls.origin = el('input', { required: true, maxlength: 2048, value: record?.origin || '', placeholder: 'https://dashboard.stripe.com' });
    controls.username = el('input', { maxlength: 320, value: record?.username || '', placeholder: 'Optional' });
    controls.secret = el('input', { type: 'password', autocomplete: 'off', required: mode === 'add', placeholder: mode === 'edit' ? 'Leave empty to keep the current key' : 'Paste the key' });
    parts.push(field('Type', controls.kind), field('Name', controls.label), field('Site (for fill)', controls.origin), field('Username', controls.username),
      field(mode === 'edit' ? 'New key or password' : 'Key or password', controls.secret, true));
  }
  controls.vault = select(detail.vaults.map(vault => [vault.id, vault.name]), record?.vaultId);
  controls.project = el('input', { maxlength: 200, value: map.project, placeholder: 'checkout-api' });
  controls.environment = select([['prod', 'Production'], ['staging', 'Staging'], ['dev', 'Development'], ['other', 'Other']], map.environment);
  controls.rotate = el('input', { type: 'number', min: 1, max: 3650, value: map.rotateEveryDays ?? '', placeholder: 'Never' });
  controls.notes = el('textarea', { rows: 2, maxlength: 2000, placeholder: 'Anything the team should know' });
  controls.notes.value = map.notes;
  const locations = el('div', { class: 'locations' }, ...map.locations.map(locationRow));
  parts.push(field('Vault', controls.vault), field('Project', controls.project), field('Environment', controls.environment),
    field('Rotate every (days)', controls.rotate),
    el('div', { class: 'wide' }, el('label', { text: 'Where it is used' }), locations,
      el('button', { class: 'ghost small', type: 'button', text: 'Add a place', onclick: () => locations.append(locationRow()) })),
    field('Notes', controls.notes, true));

  const save = el('button', { class: 'primary', text: mode === 'share' ? 'Share with team' : mode === 'edit' ? 'Save changes' : 'Add key' });
  const cancel = el('button', { class: 'ghost', type: 'button', text: 'Cancel', onclick: () => { form.hidden = true; } });
  form.append(el('h3', { text: mode === 'share' ? 'Share a key from your vault' : mode === 'edit' ? `Edit ${record.label}` : 'Add a shared key' }),
    el('div', { class: 'grid' }, ...parts), el('div', { class: 'form-actions' }, cancel, save));
  form.hidden = false;
  form.onsubmit = async event => {
    event.preventDefault();
    const days = controls.rotate.value.trim();
    const keyMap = {
      project: controls.project.value.trim(),
      environment: controls.environment.value,
      locations: [...locations.querySelectorAll('.location-row')].map(row => {
        const [type, name, ref] = row.querySelectorAll('select, input');
        return { type: type.value, name: name.value.trim(), ref: ref.value.trim() };
      }).filter(location => location.name || location.ref),
      rotateEveryDays: days ? Number(days) : null,
      notes: controls.notes.value
    };
    const message = mode === 'share'
      ? { type: 'team-share', teamId: detail.id, vaultId: controls.vault.value, personalId: controls.personal.value, map: keyMap }
      : {
        type: 'team-save', teamId: detail.id, vaultId: controls.vault.value, recordId: record?.id || null, map: keyMap,
        item: { kind: controls.kind.value, label: controls.label.value.trim(), origin: controls.origin.value.trim(), username: controls.username.value.trim(), secret: controls.secret.value }
      };
    if (controls.secret) controls.secret.value = '';
    if (await act(save, message)) {
      form.hidden = true;
      notify(mode === 'edit' ? 'Saved.' : 'Shared with the team.');
      await reopen();
    }
  };
  form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ---- people ----

function renderPeople() {
  $('#member-count').textContent = plural(detail.members.length, 'person', 'people');
  $('#member-list').replaceChildren(...detail.members.map(member => {
    const isMe = member.userId === detail.me;
    const body = el('div', { class: 'person-body' }, el('strong', { text: isMe ? `${member.email} (you)` : member.email }));
    const card = el('div', { class: 'row person' },
      el('span', { class: 'avatar', 'aria-hidden': 'true', text: initial(member.email) }),
      body,
      el('span', { class: `role ${member.role}`, text: member.role }));
    for (const device of member.devices) {
      const line = el('small', { class: 'device-line' }, device.deviceId === detail.myDeviceId ? 'This device · ' : 'Device · ', el('code', { text: device.fingerprint }));
      // a member can drop their own other devices; admins can drop anyone's (except the one signing)
      if (device.deviceId !== detail.myDeviceId && (detail.admin || isMe)) {
        const drop = el('button', { class: 'link-button', type: 'button', text: 'Remove device' });
        drop.addEventListener('click', async () => {
          if (!confirm(`Remove this device of ${member.email}?\n\nOtter re-encrypts every shared key with a new team key, so the device can't read anything from now on.`)) return;
          if (await act(drop, { type: 'team-remove-device', teamId: detail.id, userId: member.userId, deviceId: device.deviceId })) {
            notify('Device removed and the team re-keyed. Check Past members below for keys to rotate.');
            await reopen();
          }
        });
        line.append(drop);
      }
      body.append(line);
    }
    if (detail.admin && !isMe && member.role !== 'owner') {
      const remove = el('button', { class: 'bad', type: 'button', text: `Remove ${member.email.split('@')[0]} from the team` });
      remove.addEventListener('click', async () => {
        if (!confirm(`Remove ${member.email} from ${detail.name}?\n\nOtter re-encrypts every shared key with a new team key, so ${member.email} can't read anything added or changed from now on.\n\nKeys they already saw still work at the provider. You'll get a list of which to rotate, starting with production.`)) return;
        if (await act(remove, { type: 'team-remove-member', teamId: detail.id, userId: member.userId })) {
          notify(`${member.email} was removed and the team re-keyed. Their rotation checklist is under Past members.`);
          await reopen();
          $('#past-members').scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      });
      card.append(rowMenu(member.email, [remove]));
    }
    return card;
  }));
  // invites still waiting for the person; accepted ones wait on you, in the attention panel
  const waiting = detail.invites.filter(invite => invite.status !== 'accepted');
  $('#invite-section').hidden = waiting.length === 0;
  $('#invite-count').textContent = `${waiting.length} waiting`;
  $('#invite-list').replaceChildren(...waiting.map(invite => {
    const cancel = el('button', { class: 'ghost', type: 'button', text: 'Cancel invite' });
    cancel.addEventListener('click', async () => {
      if (await act(cancel, { type: 'team-invite-cancel', teamId: detail.id, inviteId: invite.id })) await reopen();
    });
    return el('div', { class: 'row person' },
      el('span', { class: 'avatar faint', 'aria-hidden': 'true', text: initial(invite.email) }),
      el('div', { class: 'person-body' }, el('strong', { text: invite.email }),
        el('small', { text: `${invite.role} · waiting for them to sign in to Otter Teams and accept` })),
      cancel);
  }));
  renderPastMembers();
  renderKitCard();
}

// ---- offboarding ----

function useText(used) {
  if (!used) return 'Not used through Otter';
  const verbs = used.actions.map(action => VERBS[action] || action).join(', ');
  return `${verbs} · ${used.count}× · last ${ago(used.last)}`;
}

function checklist(report) {
  const lines = [`# Rotate after removing ${report.email} from ${detail.name}`, '', `Removed ${new Date(report.removedAt).toLocaleString()}.`, ''];
  for (const row of report.rows) {
    const where = row.locations.map(location => `${LOCATION_LABELS[location.type]} ${location.name}${location.ref ? ` (${location.ref})` : ''}`).join('; ');
    lines.push(`- [${row.rotated ? 'x' : ' '}] **${row.label}** (${row.environment}${row.project ? `, ${row.project}` : ''}) · ${row.origin}` +
      `${where ? ` · update: ${where}` : ''} · ${row.used ? `used ${row.used.count}×` : 'not used through Otter'}`);
  }
  return lines.join('\n');
}

function renderPastMembers() {
  const section = $('#past-members');
  const reports = detail.pastMembers || [];
  section.hidden = reports.length === 0;
  $('#past-count').textContent = plural(reports.length, 'past member');
  $('#past-list').replaceChildren(...reports.map(report => {
    const left = report.rows.filter(row => !row.rotated).length;
    const used = report.rows.filter(row => row.used).length;
    const copy = el('button', { class: 'ghost small', type: 'button', text: 'Copy checklist' });
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(checklist(report));
        notify('Checklist copied as Markdown.');
      } catch {
        showError('Chrome blocked the clipboard. Click the page and try again.');
      }
    });
    const rows = report.rows.map(row => {
      const line = el('div', { class: `offboard-row${row.rotated ? ' done' : ''}` },
        el('span', { class: `env ${row.environment}`, text: row.environment }),
        el('div', {},
          el('strong', { text: row.label }),
          el('div', { class: 'key-meta' },
            el('span', { text: row.project || row.origin }),
            el('span', { class: row.used ? 'used' : '', text: useText(row.used) })),
          row.locations.length
            ? el('div', { class: 'where' }, ...row.locations.map(location => el('code', { text: `${LOCATION_LABELS[location.type]}: ${location.name}` })))
            : null));
      if (row.rotated) {
        line.append(el('span', { class: 'chip ok', text: 'Rotated' }));
      } else {
        const mark = el('button', { class: 'ghost small', type: 'button', text: 'Mark rotated' });
        mark.addEventListener('click', () => {
          line.querySelector('.rotate-form')?.remove();
          const input = el('input', { type: 'password', autocomplete: 'off', placeholder: 'New key from the provider (optional)', 'aria-label': 'New key' });
          const save = el('button', { class: 'primary small', text: 'Save' });
          const form = el('form', { class: 'rotate-form' }, input, save);
          form.addEventListener('submit', async event => {
            event.preventDefault();
            const secret = input.value;
            input.value = '';
            if (await act(save, { type: 'team-mark-rotated', teamId: detail.id, recordId: row.recordId, secret })) {
              notify(`${row.label} marked as rotated${secret ? ' and updated for the team' : ''}.`);
              await reopen();
            }
          });
          line.append(form);
          input.focus();
        });
        line.append(mark);
      }
      return line;
    });
    const who = report.deviceOnly ? `A device of ${report.email}` : report.email;
    return el('div', { class: `list offboard${left === 0 ? ' complete' : ''}` },
      el('div', { class: 'offboard-head' },
        el('div', {},
          el('strong', { text: who }),
          el('span', { class: `role ${left === 0 ? 'done' : 'todo'}`, text: left === 0 ? 'Complete' : `${left} to rotate` }),
          el('div', { class: 'key-meta', text: `Removed ${ago(report.removedAt)} · ` + (report.rows.length
            ? `${plural(report.rows.length, 'key')} they could read · ${used} used by them through Otter`
            : 'no keys existed while they were on the team') })),
        copy),
      left === 0 && report.rows.length
        ? el('div', { class: 'all-done' }, el('span', { class: 'otter happy small-otter', 'aria-hidden': 'true' }), el('span', { text: 'Every key is rotated. Nothing left to do here.' }))
        : el('p', { class: 'fine', text: 'They could read every key below. Rotate each at its provider, paste the new value here, and update it where it is deployed.' }),
      ...rows);
  }));
}

// ---- two-step sign-in ----

let totpMode = null;

function renderTotp() {
  const account = overview.account || {};
  // only owners and admins need it; members never see this card
  totpMode = !overview.isAdmin ? null : !account.totpEnabled ? 'setup' : !account.mfa ? 'verify' : null;
  $('#totp-card').hidden = !totpMode;
  if (!totpMode) return;
  $('#totp-setup').hidden = true;
  if (totpMode === 'setup') {
    $('#totp-title').textContent = 'Turn on two-step sign-in';
    $('#totp-text').textContent = 'Admins need an authenticator code to invite people, make vaults or remove anyone. It keeps a stolen Google login from running your team.';
    $('#totp-start').hidden = false;
    $('#totp-form').hidden = true;
  } else {
    $('#totp-title').textContent = 'Enter your two-step code';
    $('#totp-text').textContent = 'Open your authenticator app. You need this once per sign-in to use admin powers.';
    $('#totp-start').hidden = true;
    $('#totp-form').hidden = false;
  }
}

// Draws the QR code from the vendored generator as plain SVG rectangles.
function drawQr(text) {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  const count = qr.getModuleCount();
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', `-4 -4 ${count + 8} ${count + 8}`);
  svg.setAttribute('shape-rendering', 'crispEdges');
  const back = document.createElementNS(svg.namespaceURI, 'rect');
  for (const [key, value] of Object.entries({ x: -4, y: -4, width: count + 8, height: count + 8, fill: '#fff' })) back.setAttribute(key, value);
  svg.append(back);
  let path = '';
  for (let row = 0; row < count; row += 1) {
    for (let column = 0; column < count; column += 1) if (qr.isDark(row, column)) path += `M${column} ${row}h1v1h-1z`;
  }
  const dots = document.createElementNS(svg.namespaceURI, 'path');
  dots.setAttribute('d', path);
  dots.setAttribute('fill', '#17362f');
  svg.append(dots);
  return svg;
}

$('#totp-start').addEventListener('click', async () => {
  const data = await act($('#totp-start'), { type: 'team-totp-setup' });
  if (!data) return;
  $('#totp-qr').replaceChildren(drawQr(data.uri));
  $('#totp-secret').textContent = data.secret.match(/.{1,4}/g).join(' ');
  $('#totp-setup').hidden = false;
  $('#totp-form').hidden = false;
  $('#totp-start').hidden = true;
  $('#totp-code').focus();
});

$('#totp-form').addEventListener('submit', async event => {
  event.preventDefault();
  const code = $('#totp-code').value.trim();
  $('#totp-code').value = '';
  const data = await act($('#totp-submit'), { type: totpMode === 'setup' ? 'team-totp-enable' : 'team-totp-verify', code });
  if (!data) return;
  notify(totpMode === 'setup' ? 'Two-step sign-in is on. Admin powers unlocked.' : 'Code accepted. Admin powers unlocked for this sign-in.');
  await refresh();
});

// ---- a team this device is not on ----

function holdText(holdUntil) {
  const hours = Math.max(0, Math.ceil((holdUntil - Date.now()) / 3_600_000));
  return hours <= 1 ? 'less than an hour' : `about ${hours} hours`;
}

let waitingTimer = null;

function renderAccess(team) {
  const access = team.access;
  // while waiting to be added (or on hold), look again every 10 seconds
  clearTimeout(waitingTimer);
  if (access.deviceRequest === 'pending' || access.recoveryRequest) {
    waitingTimer = setTimeout(() => { if (!document.hidden && currentTeamId === team.id) refresh(); }, 10_000);
  }
  $('#pick-team').hidden = true;
  $('#team-detail').hidden = true;
  $('#loading').hidden = true;
  $('#access-view').hidden = false;
  $('#access-role').textContent = access.role;
  $('#access-title').textContent = `This device isn't on ${team.name} yet`;

  const device = $('#access-device');
  if (access.deviceRequest === 'pending') {
    device.replaceChildren(
      el('p', { text: 'Waiting for an admin, or your other device, to add it. Read them this code so they know it is really this device:' }),
      el('div', { class: 'fingerprint' }, el('code', { text: overview.fingerprint })));
  } else {
    const ask = el('button', { class: 'primary', type: 'button', text: 'Ask to add this device' });
    ask.addEventListener('click', async () => {
      if (await act(ask, { type: 'team-device-request', teamId: team.id })) {
        notify('Asked. An admin, or another of your devices, can add it from the People tab.');
        await refresh();
      }
    });
    device.replaceChildren(el('p', { class: 'muted', text: 'An admin or one of your other devices can add it after comparing its code.' }), ask);
  }

  const recovery = $('#access-recovery');
  recovery.replaceChildren();
  if (!access.canRecover) return;
  const request = access.recoveryRequest;
  if (!request) {
    const start = el('button', { class: 'ghost', type: 'button', text: 'Use the recovery kit' });
    start.addEventListener('click', async () => {
      if (!confirm('Start a recovery with the team\'s recovery kit?\n\nThe other admins are told, and it can finish after 24 hours unless one of them approves it sooner or cancels it.')) return;
      if (await act(start, { type: 'team-recovery-start', teamId: team.id })) await refresh();
    });
    recovery.append(el('div', { class: 'recovery-box' },
      el('strong', { text: 'Lost all your other devices?' }),
      el('p', { class: 'muted small', text: 'As an owner or admin you can get back in with the printed recovery kit, your Google account and your two-step code.' }),
      start));
  } else if (!request.ready) {
    const cancel = el('button', { class: 'link-button', type: 'button', text: 'Cancel this recovery' });
    cancel.addEventListener('click', async () => {
      if (await act(cancel, { type: 'team-recovery-decide', teamId: team.id, requestId: request.id, decision: 'cancel' })) await refresh();
    });
    recovery.append(el('div', { class: 'recovery-box' },
      el('strong', { text: 'Recovery on hold' }),
      el('p', { class: 'muted small', text: `It can finish in ${holdText(request.holdUntil)}. The other admins can see it, and one of them can approve it to skip the wait.` }),
      cancel));
  } else {
    const input = el('input', { required: true, autocomplete: 'off', spellcheck: 'false', placeholder: 'XXXX-XXXX-…  (52 letters and digits)', 'aria-label': 'Recovery code' });
    const go = el('button', { class: 'primary', text: 'Recover' });
    const form = el('form', { class: 'stack' }, input, go);
    form.addEventListener('submit', async event => {
      event.preventDefault();
      const code = input.value.trim();
      input.value = '';
      if (!(await act(go, { type: 'team-recovery-finish', teamId: team.id, requestId: request.id, code }))) return;
      notify('You are back in. The old kit is used up, so make a new one now.');
      await refresh();
      await openTeam(team.id);
      await makeKit(team.id);
    });
    recovery.append(el('div', { class: 'recovery-box ready' },
      el('strong', { text: 'Ready to recover' }),
      el('p', { class: 'muted small', text: 'Type the code from the printed recovery kit.' }),
      form));
  }
}

// ---- for admins: recoveries in progress, devices waiting, the kit ----

// Everything waiting on you, in one warm panel above the tabs: teammates who accepted an invite,
// new devices, and recoveries. The People tab carries the same count.
function renderAttention() {
  const items = [
    ...(detail.admin ? detail.invites.filter(invite => invite.status === 'accepted').map(acceptedInvite) : []),
    ...deviceRequestItems(),
    ...recoveryItems()
  ];
  $('#attention').hidden = items.length === 0;
  $('#attention-text').textContent = `Needs your approval · ${plural(items.length, 'request')}`;
  $('#attention-list').replaceChildren(...items);
  $('#people-badge').hidden = items.length === 0;
  $('#people-badge').textContent = String(items.length);
}

function attentionItem(pose, title, text, code, ...actions) {
  return el('div', { class: 'attention-item' },
    el('span', { class: `otter ${pose} invite-otter`, 'aria-hidden': 'true' }),
    el('div', { class: 'attention-body' },
      el('strong', { text: title }),
      el('p', { text }),
      el('div', { class: 'attention-actions' }, code ? el('code', { class: 'code-box', text: code }) : null, ...actions)));
}

function acceptedInvite(invite) {
  const name = invite.email.split('@')[0];
  const add = el('button', { class: 'primary', type: 'button', text: `Code matches · add ${name}` });
  add.addEventListener('click', async () => {
    if (await act(add, { type: 'team-confirm', teamId: detail.id, inviteId: invite.id, fingerprint: invite.fingerprint })) {
      notify(`${invite.email} is on the team.`);
      await refresh();
    }
  });
  const cancel = el('button', { class: 'link-button', type: 'button', text: 'Cancel invite' });
  cancel.addEventListener('click', async () => {
    if (await act(cancel, { type: 'team-invite-cancel', teamId: detail.id, inviteId: invite.id })) await reopen();
  });
  return attentionItem('talk', `${invite.email} is ready to join`,
    `Ask ${name} to read you the code shown as "This device" on their Teams page, by call or in person. Add them only if it matches exactly.`,
    invite.fingerprint, add, cancel);
}

function recoveryItems() {
  return (detail.recoveryRequests || []).map(request => {
    const approve = el('button', { class: 'primary', type: 'button', text: 'It was them, approve' });
    const cancel = el('button', { class: 'ghost', type: 'button', text: 'Cancel it' });
    for (const [button, decision] of [[approve, 'approve'], [cancel, 'cancel']]) {
      button.addEventListener('click', async () => {
        if (decision === 'approve' && !confirm(`Only approve if you have checked with ${request.email} directly, by call or in person.`)) return;
        if (await act(button, { type: 'team-recovery-decide', teamId: detail.id, requestId: request.id, decision })) await reopen();
      });
    }
    if (request.mine) {
      // someone is using the kit on your own account from another device
      cancel.textContent = "That wasn't me, cancel it";
      return attentionItem('puzzled', 'Recovery started on your account',
        `A recovery of your account (${request.email}) was started on another device. If that was you, ignore this. If not, cancel it and make a new recovery kit.`, null, cancel);
    }
    return attentionItem('puzzled', `${request.email} is recovering access`,
      request.approved
        ? `${request.email}'s recovery is approved and can finish now.`
        : `${request.email} is recovering access on a new device with the recovery kit. It can finish in ${holdText(request.holdUntil)}.`,
      null, request.approved ? null : approve, cancel);
  });
}

function deviceRequestItems() {
  const waiting = (detail.deviceRequests || []).filter(item => detail.admin || item.mine);
  return waiting.map(item => {
    const add = el('button', { class: 'primary', type: 'button', text: 'Code matches · add device' });
    add.addEventListener('click', async () => {
      if (await act(add, { type: 'team-device-confirm', teamId: detail.id, deviceId: item.deviceId, fingerprint: item.fingerprint })) {
        notify(`${item.email}'s new device is on the team.`);
        await reopen();
      }
    });
    const away = el('button', { class: 'link-button', type: 'button', text: 'Turn away' });
    away.addEventListener('click', async () => {
      if (await act(away, { type: 'team-device-cancel', teamId: detail.id, deviceId: item.deviceId })) await reopen();
    });
    return attentionItem('talk', item.mine ? 'Your new device wants to join' : `${item.email} has a new device`,
      item.mine ? 'Check this matches the code shown on the new device.' : `Ask ${item.email} to read you the code on their new device. Add it only if it matches exactly.`,
      item.fingerprint, add, away);
  });
}

function renderKitCard() {
  const card = $('#kit-card');
  $('#kit-section').hidden = !detail.admin;
  if (!detail.admin) return;
  const kit = detail.recoveryKit;
  const make = el('button', { class: kit ? 'ghost' : 'primary', type: 'button', text: kit ? 'Replace kit' : 'Make a recovery kit' });
  make.addEventListener('click', () => makeKit(detail.id, Boolean(kit)));
  card.replaceChildren(
    el('span', { class: `otter ${kit ? 'happy' : 'puzzled'} small-otter`, 'aria-hidden': 'true' }),
    el('div', {},
      el('strong', { text: kit ? 'Recovery kit ready' : 'No recovery kit yet' }),
      el('p', { class: 'muted small', text: kit
        ? `Made ${ago(new Date(kit.createdAt).toISOString())} by ${kit.createdBy}. Replacing it cancels the old one.`
        : 'If every admin loses their devices, nobody can let them back in. A printed kit fixes that.' })),
    make);
}

async function makeKit(teamId, replacing = false) {
  if (replacing && !confirm('Make a new recovery kit? The old printed kit stops working.')) return;
  const data = await act(null, { type: 'team-kit-create', teamId });
  if (!data) return;
  const groups = data.code.split('-');
  $('#kit-team').textContent = overview.teams.find(team => team.id === teamId)?.name || 'your team';
  $('#kit-meta').textContent = `Made ${new Date().toLocaleString()} by ${overview.email}`;
  $('#kit-code').replaceChildren(...groups.map(group => el('code', { text: group })));
  $('#kit-last').value = '';
  const dialog = $('#kit-dialog');
  dialog.dataset.last = groups[groups.length - 1];
  dialog.showModal();
}

$('#kit-print-button').addEventListener('click', () => window.print());
$('#kit-confirm').addEventListener('submit', async event => {
  event.preventDefault();
  const dialog = $('#kit-dialog');
  if ($('#kit-last').value.trim().toUpperCase() !== dialog.dataset.last) {
    $('#kit-last').setCustomValidity('That does not match the end of the code');
    $('#kit-last').reportValidity();
    return;
  }
  // the code only ever lived on this page; drop it
  $('#kit-code').replaceChildren();
  dialog.dataset.last = '';
  dialog.close();
  notify('Recovery kit saved. Keep it somewhere safe and offline.');
  await reopen();
});
$('#kit-last').addEventListener('input', () => $('#kit-last').setCustomValidity(''));
$('#kit-dialog').addEventListener('cancel', event => event.preventDefault());

// ---- activity ----

function renderActivity() {
  $('#no-activity').hidden = detail.log.length > 0 || Boolean(detail.logError);
  if (detail.logError) showError(detail.logError);
  $('#activity-head').hidden = detail.log.length === 0;
  $('#activity').hidden = detail.log.length === 0;
  $('#activity-count').textContent = plural(detail.log.length, 'event');
  $('#activity').replaceChildren(...detail.log.map(event => el('li', { class: 'row' },
    el('span', { class: 'avatar small', 'aria-hidden': 'true', text: initial(event.who) }),
    el('span', { class: 'activity-text' }, el('strong', { text: event.who }), ` ${VERBS[event.action] || event.action} `, el('strong', { text: event.label || '' })),
    el('time', { datetime: event.at, text: ago(event.at) }))));
}

// ---- wiring ----

document.querySelectorAll('[data-tab]').forEach(tab => tab.addEventListener('click', () => {
  document.querySelectorAll('[data-tab]').forEach(other => other.setAttribute('aria-selected', String(other === tab)));
  document.querySelectorAll('[data-panel]').forEach(panel => { panel.hidden = panel.dataset.panel !== tab.dataset.tab; });
}));
$('#vault-filter').addEventListener('change', renderKeys);
$('#key-search').addEventListener('input', renderKeys);
$('#clear-search').addEventListener('click', () => {
  $('#key-search').value = '';
  $('#vault-filter').value = '';
  renderKeys();
  $('#key-search').focus();
});
$('#add-button').addEventListener('click', () => openKeyForm('add'));
// your own vault can change in another tab (the otter just caught a key), so read it fresh
$('#share-button').addEventListener('click', async () => {
  const status = await send({ type: 'status' });
  if (status.ok) personal = status.data.records || [];
  openKeyForm('share');
});

// Keep the page current without a reload: refresh when you come back to the tab or the window,
// and every 15 seconds while it is open, so a new device, invite or key shows up by itself.
// Never while you are typing in something, have a form open, or the recovery kit is on screen.
let lastQuietRefresh = 0;
function busy() {
  const active = document.activeElement;
  // the two-step QR stays up while someone scans it with their phone
  return !$('#key-form').hidden || !$('#totp-setup').hidden || $('#kit-dialog').open || document.querySelector('.copy-form, .rotate-form, .row-menu[open]') ||
    Boolean(active && ['INPUT', 'TEXTAREA', 'SELECT'].includes(active.tagName) && active.value);
}
async function quietRefresh(minGap) {
  if (document.hidden || Date.now() - lastQuietRefresh < minGap || busy()) return;
  if (!overview?.signedIn) return;
  lastQuietRefresh = Date.now();
  await refresh();
}
document.addEventListener('visibilitychange', () => quietRefresh(5000));
addEventListener('focus', () => quietRefresh(5000));
setInterval(() => quietRefresh(14_000), 15_000);

$('#unlock-form').addEventListener('submit', async event => {
  event.preventDefault();
  const passphrase = $('#unlock-passphrase').value;
  $('#unlock-passphrase').value = '';
  if (await act(event.submitter, { type: 'unlock', passphrase })) await refresh();
});

$('#sign-in').addEventListener('click', async () => {
  if (await act($('#sign-in'), { type: 'team-sign-in' })) await refresh();
});

$('#sign-out').addEventListener('click', async () => {
  if (await act($('#sign-out'), { type: 'team-sign-out' })) await refresh();
});

$('#create-team').addEventListener('submit', async event => {
  event.preventDefault();
  const data = await act(event.submitter, { type: 'team-create', name: $('#team-name').value.trim() });
  if (!data) { await refresh(); return; }
  $('#team-name').value = '';
  currentTeamId = data.teamId;
  await refresh();
});

$('#vault-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (await act(event.submitter, { type: 'team-vault-create', teamId: detail.id, name: $('#vault-name').value.trim() })) {
    $('#vault-name').value = '';
    await reopen();
  }
});

$('#export-form').addEventListener('submit', async event => {
  event.preventDefault();
  const passphrase = $('#export-passphrase').value;
  $('#export-passphrase').value = '';
  const data = await act(event.submitter, { type: 'team-export', teamId: detail.id, passphrase });
  if (!data) return;
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const link = el('a', { href: URL.createObjectURL(blob), download: `otter-teams-${detail.name.replace(/[^\w-]+/g, '-').toLowerCase()}-${new Date().toISOString().slice(0, 10)}.json` });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 10_000);
  notify(`Exported ${plural(data.keys.length, 'key')}. Keep the file safe, and delete it when you no longer need it.`);
  await reopen();
});

$('#invite-toggle').addEventListener('click', () => {
  $('#invite-toggle').hidden = true;
  $('#invite-form').hidden = false;
  $('#invite-email').focus();
});

$('#invite-form').addEventListener('submit', async event => {
  event.preventDefault();
  const email = $('#invite-email').value.trim();
  if (await act(event.submitter, { type: 'team-invite', teamId: detail.id, email, role: $('#invite-role').value })) {
    $('#invite-email').value = '';
    $('#invite-form').hidden = true;
    notify(`Invited ${email}. Tell them to install Otter, open Teams and sign in with Google using that address.`);
    await reopen();
  }
});

refresh();
