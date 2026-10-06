// Drives a real Chrome for Testing with the extension through each provider's key reveal:
// catch the key, save it, fill it back on the same site, refuse the lookalike, ignore decoys.
// Usage: node security/provider-lab/run.mjs   (writes security/provider-lab/results/)
import { spawn } from 'node:child_process';
import { copyFileSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { connect, list, popupSend, sleep, findExtension, base } from '../browser-attacks/cdp.mjs';
import { providers, decoys } from './providers.mjs';
import { sitePages, startLab } from './server.mjs';
import { renderReport } from './report.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..', '..');
const out = join(here, 'results');
const chrome = process.env.CHROME || `${process.env.HOME}/Library/Caches/ms-playwright/chromium-1234/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing`;
const profile = join(tmpdir(), 'otter-provider-lab');
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
rmSync(profile, { recursive: true, force: true });

const { keys, routes } = sitePages();
const lab = await startLab({ dir: join(tmpdir(), 'otter-provider-lab-certs'), routes });
const browser = spawn(chrome, [
  `--user-data-dir=${profile}`, '--remote-debugging-port=9231', '--no-first-run', '--no-default-browser-check',
  '--proxy-server=http://127.0.0.1:8899', '--ignore-certificate-errors', '--window-size=1280,860',
  `--disable-extensions-except=${join(repo, 'extension')}`, `--load-extension=${join(repo, 'extension')}`,
  // CI runners block Chrome's user-namespace sandbox; the lab only visits its own stand-in pages
  ...(process.env.CI ? ['--no-sandbox', '--disable-dev-shm-usage'] : []),
  `https://${providers[0].host}${providers[0].usePath}`
], { stdio: ['ignore', 'ignore', process.env.CI ? 'inherit' : 'ignore'] });

for (let i = 0; i < 40; i++) {
  try { if (await findExtension()) break; } catch {}
  await sleep(500);
}
await sleep(1500);
const extId = await findExtension();
if (!extId) throw new Error('Chrome did not start or the extension did not load');
const tab = await connect((await list()).find(t => t.type === 'page' && t.url.startsWith('https')).webSocketDebuggerUrl);
await tab.cmd('Page.enable');
await tab.cmd('DOM.enable');
await tab.cmd('Page.bringToFront');

const setup = await popupSend({ type: 'setup', passphrase: 'provider lab synthetic passphrase' });
console.log('vault setup', setup.ok);

async function go(url) {
  await tab.cmd('Page.navigate', { url });
  await sleep(1400);
}

// The prompt lives in a closed shadow root. CDP can still reach it with pierce: true.
async function bubble() {
  const { result } = await tab.cmd('DOM.getDocument', { depth: -1, pierce: true });
  const stack = [result.root];
  let found;
  while (stack.length && !found) {
    const node = stack.pop();
    const cls = node.attributes?.[node.attributes.indexOf('class') + 1];
    if (node.nodeName === 'DIV' && node.attributes?.includes('class') && cls === 'bubble') found = node;
    stack.push(...(node.children || []), ...(node.shadowRoots || []));
  }
  if (!found) return { hidden: true, title: '', buttons: [] };
  const { result: { object } } = await tab.cmd('DOM.resolveNode', { nodeId: found.nodeId });
  const { result: { result: { value } } } = await tab.cmd('Runtime.callFunctionOn', {
    objectId: object.objectId, returnByValue: true,
    functionDeclaration: `function () { return { hidden: this.hidden, title: this.querySelector('strong')?.textContent || '', detail: this.querySelector('.content span')?.textContent || '',
      buttons: [...this.querySelectorAll('button')].map(b => { const r = b.getBoundingClientRect(); return { label: b.textContent, x: r.x + r.width / 2, y: r.y + r.height / 2 }; }) }; }`
  });
  return value;
}

async function waitFor(pattern, timeout = 5000) {
  const until = Date.now() + timeout;
  let last;
  while (Date.now() < until) {
    last = await bubble();
    if (!last.hidden && pattern.test(last.title)) return last;
    await sleep(200);
  }
  return last;
}

async function press(state, label) {
  const button = state.buttons.find(b => b.label === label);
  if (!button) return false;
  await sleep(1100); // the prompt only accepts clicks once it has been readable for a moment
  await tab.click(button.x, button.y);
  return true;
}

const fieldValue = () => tab.ev(`document.querySelector('form input')?.value || ''`);
const results = [];

for (const provider of providers) {
  const expected = provider.secret ? keys[provider.id].secret : keys[provider.id].key;
  const row = { id: provider.id, name: provider.name, host: provider.host, lookalike: provider.lookalike, format: expected.slice(0, 12) + '…', length: expected.length };
  console.log(`\n${provider.name}`);

  await go(`https://${provider.host}${provider.keyPath}`);
  await tab.clickSel('#create');
  const offer = await waitFor(/surfaced|spotted/);
  row.caught = !offer.hidden && /surfaced/.test(offer.title);
  row.offerTitle = offer.hidden ? '(no prompt)' : offer.title;
  await tab.shot(join(out, `${provider.id}-1-reveal.png`));

  if (row.caught && await press(offer, 'Keep it safe')) {
    const done = await waitFor(/Safe and sound|wrong|Unlock/);
    row.saved = /Safe and sound/.test(done.title);
    row.savedFor = done.detail;
  }

  await go(`https://${provider.host}${provider.usePath}`);
  await tab.clickSel('form input');
  const known = await waitFor(/know this place|spotted|locked/);
  row.recognised = /know this place/.test(known.title);
  if (row.recognised && await press(known, 'Fill securely')) {
    await waitFor(/Filled/);
    const value = await fieldValue();
    row.filledCorrect = value === expected;
    row.filledWrongValue = value && value !== expected ? (value === keys[provider.id].key ? 'the access key ID, not the secret' : 'a different value') : null;
  }
  await tab.shot(join(out, `${provider.id}-2-fill.png`));

  await go(`https://${provider.lookalike}${provider.usePath}`);
  await tab.clickSel('form input');
  const fake = await waitFor(/know this place|spotted|locked/);
  row.lookalikeOffered = /know this place/.test(fake.title);
  row.lookalikeFilled = Boolean(await fieldValue());
  await tab.shot(join(out, `${provider.id}-3-lookalike.png`));
  console.log(row);
  results.push(row);
}

await go(`https://${decoys.host}${decoys.path}`);
await sleep(2500);
const decoyState = await bubble();
const decoyResult = { values: keys.decoys.map(([name]) => name), prompted: !decoyState.hidden, title: decoyState.title };
await tab.shot(join(out, 'decoys.png'));
console.log('\ndecoys', decoyResult);

const status = await popupSend({ type: 'status' });
const vault = (status.data?.records || []).map(r => ({ origin: r.origin, kind: r.kind, label: r.label }));
await sleep(600);
const popupTarget = (await list()).find(t => t.url.includes(`${extId}/popup`));
if (popupTarget) {
  const popup = await connect(popupTarget.webSocketDebuggerUrl);
  await popup.shot(join(out, 'popup.png'));
}

const report = { ranAt: new Date().toISOString(), chrome: (await (await fetch(`${base}/json/version`)).json()).Browser, results, decoys: decoyResult, vault };
writeFileSync(join(out, 'report.json'), JSON.stringify(report, null, 2));
for (const file of ['mascot.webp', 'logo.webp']) copyFileSync(join(repo, 'store/source/art', file), join(out, file));
writeFileSync(join(out, 'report.html'), renderReport(report));
console.log('\nvault', vault);
console.log(`\nreport: ${join(out, 'report.html')}`);
if (process.argv.includes('--keep-open')) {
  console.log('browser left open with the lab proxy running; press Ctrl+C to stop');
} else {
  lab.close();
  browser.kill();
  process.exit(0);
}
