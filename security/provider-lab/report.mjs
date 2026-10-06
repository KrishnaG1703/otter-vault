// Turns report.json into a one-page results sheet in the Otter Vault look.
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const mark = (ok, good = 'pass', bad = 'fail') => `<span class="pill ${ok ? 'ok' : 'bad'}">${ok ? good : bad}</span>`;

export function renderReport({ ranAt, chrome, results, decoys, vault }) {
  const checks = results.flatMap(r => [r.caught, r.saved, r.recognised, r.filledCorrect, !r.lookalikeOffered && !r.lookalikeFilled]);
  checks.push(!decoys.prompted);
  const passed = checks.filter(Boolean).length;
  const allGood = passed === checks.length;
  const rows = results.map(r => `
    <tr>
      <td><strong>${esc(r.name)}</strong><small>${esc(r.host)}</small></td>
      <td><code>${esc(r.format)}</code><small>${r.length} chars</small></td>
      <td>${mark(r.caught, 'caught', 'missed')}${r.caught ? '' : `<small>${esc(r.offerTitle)}</small>`}</td>
      <td>${mark(r.saved, 'saved', 'not saved')}</td>
      <td>${mark(r.filledCorrect, 'exact key', r.recognised ? 'wrong value' : 'no offer')}${r.filledWrongValue ? `<small>filled ${esc(r.filledWrongValue)}</small>` : ''}</td>
      <td>${mark(!r.lookalikeOffered && !r.lookalikeFilled, 'refused', 'filled!')}<small>${esc(r.lookalike)}</small></td>
      <td class="shots"><a href="${r.id}-1-reveal.png">reveal</a><a href="${r.id}-2-fill.png">fill</a><a href="${r.id}-3-lookalike.png">lookalike</a></td>
    </tr>`).join('');

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Otter provider lab</title>
<style>
:root{--cream:#fffdf7;--paper:#f5f1e6;--mint:#c9f0d3;--ink:#17362f;--deep:#183a33;--muted:#67756f;--line:rgba(23,54,47,.14);--red:#f5ddd6;--redink:#8b3426}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 ui-rounded,"SF Pro Rounded",system-ui,sans-serif}
main{max-width:1180px;margin:0 auto;padding:32px 24px 64px}
header{display:flex;align-items:center;gap:10px;font-weight:800;letter-spacing:-.01em}header img{width:30px;height:30px}
.hero{display:grid;grid-template-columns:1fr auto;align-items:center;gap:24px;margin:28px 0 24px;padding:28px 32px;border-radius:28px;background:var(--deep);color:var(--cream)}
.hero h1{margin:0;font-size:clamp(28px,4vw,44px);line-height:1.05;letter-spacing:-.03em}.hero p{margin:10px 0 0;color:#cfe3d7;max-width:60ch}
.hero img{width:170px;height:auto;padding:14px;border-radius:50%;background:radial-gradient(circle,#e4f7e8 0 58%,#c9f0d3 59%)}.score{display:inline-block;margin-top:16px;padding:6px 14px;border-radius:999px;background:${allGood ? 'var(--mint)' : '#f6d4a8'};color:var(--ink);font-weight:800}
.card{padding:8px;border:1px solid var(--line);border-radius:22px;background:var(--cream);overflow-x:auto}
table{width:100%;min-width:900px;border-collapse:collapse}th{padding:12px;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);text-align:left}
td{padding:14px 12px;border-top:1px solid var(--line);vertical-align:top}td small{display:block;margin-top:4px;color:var(--muted);font-size:12px;word-break:break-all}
code{font:12px ui-monospace,Menlo,monospace}.pill{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:800}.ok{background:var(--mint)}.bad{background:var(--red);color:var(--redink)}
.shots a{display:block;color:#2c7469;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;margin-top:16px}.grid .card{padding:20px 22px}h2{margin:0 0 8px;font-size:18px}
ul{margin:0;padding-left:18px}li{margin:4px 0}.foot{margin-top:24px;color:var(--muted);font-size:12px}
@media(max-width:640px){.hero{grid-template-columns:1fr}.hero img{width:110px}}
</style></head><body><main>
<header><img src="logo.webp" alt="">otter vault · provider lab</header>
<section class="hero"><div>
  <h1>${allGood ? 'otter picked every key correctly.' : 'otter missed some keys.'}</h1>
  <p>${results.length} providers, each on its real hostname: reveal a new key, save it, fill it back on the same site, then try a lookalike domain. Decoy tokens check for false alarms.</p>
  <span class="score">${passed} / ${checks.length} checks passed</span>
</div><img src="mascot.webp" alt="green otter mascot"></section>
<div class="card"><table><thead><tr><th>provider</th><th>key format</th><th>spotted the reveal</th><th>saved</th><th>filled back</th><th>lookalike site</th><th>screenshots</th></tr></thead><tbody>${rows}</tbody></table></div>
<div class="grid">
  <div class="card"><h2>decoys ${mark(!decoys.prompted, 'ignored', 'false alarm')}</h2><p>Not secrets, shown on a page where otter should stay quiet:</p><ul>${decoys.values.map(v => `<li>${esc(v)}</li>`).join('')}</ul>${decoys.prompted ? `<p>prompt: ${esc(decoys.title)}</p>` : ''}<p><a href="decoys.png">screenshot</a></p></div>
  <div class="card"><h2>vault after the run</h2><ul>${vault.map(v => `<li><code>${esc(v.origin)}</code> · ${esc(v.kind)}</li>`).join('') || '<li>empty</li>'}</ul><p><a href="popup.png">popup screenshot</a></p></div>
</div>
<p class="foot">${esc(chrome)} · ${esc(ranAt)} · stand-in pages served through a local proxy; keys are random strings in each provider's format, none are real.</p>
</main></body></html>`;
}
