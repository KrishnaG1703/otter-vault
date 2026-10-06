import { page, popupSend, sleep } from './cdp.mjs';
const out = process.argv[2];
console.log('setup', (await popupSend({ type: 'setup', passphrase: 'attack lab synthetic passphrase' })).ok);
const tab = await page('127.0.0.1:4299');
await tab.cmd('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
await tab.cmd('Page.bringToFront');
const results = {};
const fresh = async () => { await tab.cmd('Page.reload'); await sleep(1500); };
const offer = async () => { await tab.clickSel('#pass'); };

// legit save: a person reads, then clicks
await fresh();
await offer(); await sleep(900);
await tab.ev(`document.querySelector('#pass').value = 'REAL-BANK-PASSWORD'`);
await tab.click(962, 673); await sleep(1200);
await tab.shot(out + '/atk-legit-saved.png');
results.legitSaveListedInVault = JSON.stringify((await popupSend({ type: 'status' })).data?.records?.map(r => r.origin));

// A5 synthetic clicks
await fresh(); await offer(); await sleep(1200);
await tab.ev(`(() => { const el = document.elementFromPoint(962, 673); el?.click(); el?.dispatchEvent(new MouseEvent('click', { bubbles: true, composed: true })); })()`);
await sleep(800);
results.syntheticClickFilled = (await tab.ev('report()')).passValue;

// A6 cover: decoy re-appended above the extension, user clicks the "prize"
await fresh(); await tab.ev('armCover()'); await offer(); await sleep(1500);
await tab.shot(out + '/atk-cover.png');
await tab.click(962, 673); await sleep(1000);
results.coverAttackFilled = (await tab.ev('report()')).passValue;

// A7 see-through page: whole document made nearly transparent
await fresh(); await offer(); await sleep(400);
await tab.ev(`document.documentElement.style.opacity = '0.02'`); await sleep(1200);
await tab.click(962, 673); await sleep(1000);
results.transparentPageFilled = (await tab.ev('report()')).passValue;

// A8 pop-under double click: first click summons the bubble under the pointer, second lands on fill
await fresh(); await tab.ev('armPopUnder()');
await tab.click(962, 673); await sleep(180); await tab.click(962, 673); await sleep(1000);
results.popUnderFilled = (await tab.ev('report()')).passValue;
await tab.shot(out + '/atk-popunder.png');

// legit fill: nothing covering, the user reads then clicks
await fresh(); await offer(); await sleep(1200);
await tab.click(962, 673); await sleep(1000);
results.legitFill = (await tab.ev('report()')).passValue;
await tab.shot(out + '/atk-legit-fill.png');
console.log(JSON.stringify(results, null, 1));
process.exit(0);
