// HTTPS site host plus a CONNECT proxy. Chrome is started with --proxy-server pointing here, so
// https://platform.openai.com and friends resolve to the local stand-in pages instead of the internet.
import { createServer as createHttps } from 'node:https';
import { createServer as createHttp } from 'node:http';
import { connect } from 'node:net';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { providers, decoys } from './providers.mjs';

const page = (title, body, script = '') => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${title}</title>
<style>body{margin:0;font:15px system-ui,sans-serif;color:#1d1d1f;background:#f6f6f4}main{max-width:720px;margin:60px auto;padding:0 24px}
.lab{font:11px ui-monospace,monospace;color:#8a8a8a;letter-spacing:.05em;text-transform:uppercase}dialog{display:block;position:static;margin:24px 0;padding:24px;border:1px solid #ddd;border-radius:14px;background:#fff;max-width:640px}
code,.mono,input[readonly]{font:13px ui-monospace,Menlo,monospace;word-break:break-all}input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #ccc;border-radius:8px;margin-top:6px}
button{padding:9px 16px;border:0;border-radius:8px;background:#1d1d1f;color:#fff;font:inherit;cursor:pointer}table{border-collapse:collapse;width:100%}td,th{padding:8px;border-bottom:1px solid #eee;text-align:left;word-break:break-all}label{display:block;font-weight:600}</style></head>
<body><main><p class="lab">otter provider lab · stand-in page, not the real site</p>${body}</main><script>${script}</script></body></html>`;

export function sitePages() {
  const keys = {};
  const routes = new Map();
  for (const provider of providers) {
    const key = provider.key();
    const secret = provider.secret?.();
    keys[provider.id] = { key, secret };
    const reveal = JSON.stringify(provider.reveal(key, secret));
    // the key only enters the DOM after "create", the way a one-time reveal does
    routes.set(`${provider.host}${provider.keyPath}`, {
      csp: provider.csp,
      html: page(`${provider.name} keys`, `<h1>${provider.name} keys</h1><button id="create">Create new key</button><div id="slot"></div>`,
        `document.getElementById('create').onclick = () => { const d = document.createElement(${JSON.stringify(provider.wrapper || 'dialog')}); d.innerHTML = ${reveal}; document.getElementById('slot').append(d); };`)
    });
    const use = page(`${provider.name} settings`, `<h1>${provider.name}</h1><form onsubmit="return false">${provider.field}</form>`);
    routes.set(`${provider.host}${provider.usePath}`, { csp: provider.csp, html: use });
    routes.set(`${provider.lookalike}${provider.usePath}`, { html: use });
  }
  const decoyValues = decoys.values();
  keys.decoys = decoyValues;
  routes.set(`${decoys.host}${decoys.path}`, {
    html: page('Commit details', `<h1>Commit details</h1><div id="slot"></div>`,
      `setTimeout(() => { for (const [name, value] of ${JSON.stringify(decoyValues)}) { const row = document.createElement('section'); row.innerHTML = '<h3></h3><code></code>'; row.querySelector('h3').textContent = name; row.querySelector('code').textContent = value; document.getElementById('slot').append(row); } }, 300);`)
  });
  return { keys, routes };
}

export async function startLab({ dir, httpsPort = 8443, proxyPort = 8899, routes }) {
  mkdirSync(dir, { recursive: true });
  const keyFile = join(dir, 'lab-key.pem');
  const certFile = join(dir, 'lab-cert.pem');
  if (!existsSync(certFile)) {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=otter-lab', '-keyout', keyFile, '-out', certFile], { stdio: 'ignore' });
  }
  const https = createHttps({ key: readFileSync(keyFile), cert: readFileSync(certFile) }, (request, response) => {
    const host = String(request.headers.host || '').replace(/:\d+$/, '');
    const route = routes.get(host + new URL(request.url, 'https://x').pathname);
    if (!route) { response.writeHead(404, { 'content-type': 'text/plain' }).end('not in lab'); return; }
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', ...(route.csp ? { 'content-security-policy': route.csp } : {}) });
    response.end(route.html);
  });
  await new Promise(resolve => https.listen(httpsPort, '127.0.0.1', resolve));

  const proxy = createHttp((request, response) => response.writeHead(403).end('https only'));
  proxy.on('connect', (request, client, head) => {
    const upstream = connect(httpsPort, '127.0.0.1', () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    upstream.on('error', () => client.destroy());
    client.on('error', () => upstream.destroy());
  });
  await new Promise(resolve => proxy.listen(proxyPort, '127.0.0.1', resolve));
  return { close: () => { https.close(); proxy.close(); } };
}
