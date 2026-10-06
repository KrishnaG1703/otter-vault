// Tiny CDP helper for the lab browser on :9231.
import { writeFileSync } from 'node:fs';
export const base = 'http://127.0.0.1:9231';
// Unpacked extension ids depend on the folder path, so find Otter Vault's worker by its manifest name.
export let extId = process.env.OTTER_EXT_ID || '';
export async function findExtension() {
  if (extId) return extId;
  for (const target of (await list()).filter(t => t.type === 'service_worker' && t.url.startsWith('chrome-extension://'))) {
    const worker = await connect(target.webSocketDebuggerUrl);
    const name = await worker.ev('chrome.runtime.getManifest().name');
    worker.ws.close();
    if (name === 'Otter Vault') return (extId = new URL(target.url).host);
  }
  return '';
}
export const sleep = ms => new Promise(r => setTimeout(r, ms));
export const list = async () => (await fetch(`${base}/json/list`)).json();
export async function connect(url) {
  const ws = new WebSocket(url); await new Promise(r => ws.onopen = r);
  let id = 0; const pending = new Map();
  ws.onmessage = e => { const m = JSON.parse(e.data); if (pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } };
  const cmd = (method, params = {}) => new Promise(r => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async expression => { const m = await cmd('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }); return m.result?.result?.value ?? m.result?.exceptionDetails?.exception?.description; };
  const click = async (x, y) => { for (const type of ['mousePressed', 'mouseReleased']) await cmd('Input.dispatchMouseEvent', { type, x, y, button: 'left', clickCount: 1 }); };
  const clickSel = async sel => { const [x, y] = await ev(`(() => { const b = document.querySelector(${JSON.stringify(sel)}).getBoundingClientRect(); return [b.x + b.width / 2, b.y + b.height / 2]; })()`); await click(x, y); };
  const shot = async file => { const m = await cmd('Page.captureScreenshot', { format: 'png' }); writeFileSync(file, Buffer.from(m.result.data, 'base64')); };
  return { cmd, ev, click, clickSel, shot, ws };
}
export async function browser() { return connect((await (await fetch(`${base}/json/version`)).json()).webSocketDebuggerUrl); }
export async function page(match) { const t = (await list()).find(t => t.type === 'page' && t.url.includes(match)); return connect(t.webSocketDebuggerUrl); }
export async function popupSend(msg) {
  await findExtension();
  const w = await connect((await list()).find(t => t.type === 'service_worker' && t.url.includes(extId)).webSocketDebuggerUrl);
  let p = (await list()).find(t => t.url.includes(`${extId}/popup`));
  if (!p) {
    const b = await browser();
    const tab = (await list()).find(t => t.type === 'page' && t.url.startsWith('http'));
    await b.cmd('Target.activateTarget', { targetId: tab.id }); await sleep(300);
    console.log('openPopup', await w.ev('chrome.action.openPopup().then(() => "ok", e => String(e))')); await sleep(1200); p = (await list()).find(t => t.url.includes(`${extId}/popup`)); }
  const popup = await connect(p.webSocketDebuggerUrl);
  return popup.ev(`new Promise(r => chrome.runtime.sendMessage(${JSON.stringify(msg)}, r))`);
}
