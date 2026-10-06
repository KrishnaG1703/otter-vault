(() => {
  // The guard lives in the content script's isolated world, so page scripts cannot pre-set it to
  // disable Otter the way they could with a DOM element ID.
  if (window.top !== window || globalThis.__otterVaultLoaded) return;
  globalThis.__otterVaultLoaded = true;

  const API_KEY_PATTERN = /(api[-_ ]?(?:key|token)|secret[-_ ]?key|access[-_ ]?token|auth[-_ ]?token|private[-_ ]?token|personal[-_ ]?token|client[-_ ]?secret)/i;
  const inspectedReveals = new WeakMap();
  let activeField = null;
  const NOTICE_MS = 12_000;   // "I'm locked" and other notices
  const OFFER_MS = 45_000;    // "save this new key?": long enough to finish copying it yourself
  const quietElements = new WeakSet();
  let lockedNoticeShown = false;
  // Otter's own website shows a demo key in its hero; never treat that as a real reveal
  const OWN_SITE = location.hostname === 'ottervault.mechaclips.workers.dev' ||
    (location.hostname === 'krishnag1703.github.io' && location.pathname.startsWith('/ottice-site'));
  let currentKind = null;
  let following = true;
  let refocusedByFill = null;

  const host = document.createElement('div');
  host.style.cssText = 'all:initial;position:fixed;z-index:2147483647;left:0;top:0;pointer-events:none';
  const root = host.attachShadow({ mode: 'closed' });
  root.innerHTML = `
    <style>
      :host{all:initial}.otter-wrap{--x:calc(100vw - 66px);--y:calc(100vh - 66px);position:fixed;left:0;top:0;display:grid;place-items:center;width:60px;height:60px;line-height:0;transform:translate(calc(var(--x) - 30px),calc(var(--y) - 30px));transition:transform .32s cubic-bezier(.2,.85,.2,1);pointer-events:none;filter:drop-shadow(0 7px 8px rgba(20,52,45,.22))}.otter-wrap.active{--x:calc(100vw - 58px)!important;--y:calc(100vh - 64px)!important}.cursor-mascot{--facing:1;width:60px;height:60px;transform:scaleX(var(--facing));transform-origin:50% 82%;will-change:transform}.otter-wrap.running .cursor-mascot{animation:run-bob .16s ease-in-out infinite alternate}.cursor-mascot.pop{animation:expression-pop .3s cubic-bezier(.2,1.4,.45,1)}.bubble{position:fixed;z-index:2;right:24px;bottom:92px;width:320px;padding:16px;border:1px solid rgba(159,226,176,.22);border-radius:19px 19px 5px 19px;background:linear-gradient(155deg,#0e2a24,#123d37 60%,#0f3b44);color:#e9f1ec;box-shadow:0 20px 52px rgba(0,0,0,.45);pointer-events:auto;font-family:ui-rounded,"SF Pro Rounded",system-ui,sans-serif}.bubble{display:grid;grid-template-columns:56px minmax(0,1fr);gap:12px;align-items:start;width:340px}.bubble[hidden]{display:none}.mascot{width:56px;height:56px;margin-top:2px;padding:4px;border-radius:50%;background:radial-gradient(circle at 50% 45%,rgba(159,226,176,.32),rgba(159,226,176,.05) 70%);filter:drop-shadow(0 6px 10px rgba(0,0,0,.45))}.brand{display:flex;align-items:center;gap:6px;margin:-4px 0 9px;color:#a8ebc2;font-size:10px;font-weight:800;letter-spacing:.06em;text-transform:uppercase}.logo{width:20px;height:20px;padding:2px;border-radius:50%;background:#f4fbf6}.bubble strong,.bubble span,.bubble .note{display:block}.bubble .note{margin-top:8px;color:#ff9f93;font-size:11px;line-height:1.4}.bubble strong{font-size:14px;line-height:1.25;color:#fbfefc}.bubble span{margin-top:5px;color:#b9cec5;font-size:12px;line-height:1.45}.actions{display:flex;flex-wrap:wrap;gap:7px;margin-top:12px}.actions button{min-height:35px;padding:0 11px;white-space:nowrap;border:0;border-radius:999px;background:linear-gradient(135deg,#e3fbe9,#7fe0c0 55%,#3fbfa8);color:#0c2f28;box-shadow:0 8px 20px rgba(127,224,192,.25);font:800 11px ui-rounded,"SF Pro Rounded",system-ui,sans-serif;cursor:pointer}.actions button.secondary{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.14);color:#e9f1ec;box-shadow:none}.actions button:focus-visible{outline:3px solid rgba(159,226,176,.45);outline-offset:2px}@keyframes run-bob{to{transform:scaleX(var(--facing)) translateY(-2px) rotate(1deg)}}@keyframes expression-pop{0%{transform:scaleX(var(--facing)) scale(.9) rotate(-2deg)}65%{transform:scaleX(var(--facing)) scale(1.08) rotate(2deg)}100%{transform:scaleX(var(--facing)) scale(1)}}@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}@media(max-width:500px){.bubble{right:16px;bottom:82px;width:min(340px,calc(100vw - 32px))}}
    </style>
    <div class="otter-wrap" role="img" aria-label="Otter Vault mascot"><canvas class="cursor-mascot" data-expression="idle" width="136" height="136" aria-hidden="true"></canvas></div>
    <!-- the bubble comes last and sits above the animated otter: visibility tracking treats
         anything that might paint over it as an obstruction and would refuse every click -->
    <div class="bubble" role="status" hidden><canvas class="mascot" width="112" height="112"></canvas><div class="body"><div class="brand"><canvas class="logo" width="36" height="36"></canvas>otter vault</div><div class="content"></div></div></div>`;

  const bubble = root.querySelector('.bubble');
  const otter = root.querySelector('.otter-wrap');
  const cursorMascot = otter.querySelector('.cursor-mascot');
  const content = bubble.querySelector('.content');

  let stopTimer = null;
  let curiousTimer = null;
  let lastRunFrameAt = 0;
  let runFrame = 0;
  let cursorSprite = null;
  const moodFrames = { idle: [0, 0], 'run-a': [1, 0], 'run-b': [0, 1], curious: [1, 1] };

  function drawMood() {
    if (!cursorSprite) return;
    const [column, row] = moodFrames[cursorMascot.dataset.expression] || moodFrames.idle;
    const frameWidth = cursorSprite.width / 2;
    const frameHeight = cursorSprite.height / 2;
    const context = cursorMascot.getContext('2d');
    context.clearRect(0, 0, cursorMascot.width, cursorMascot.height);
    context.drawImage(cursorSprite, column * frameWidth, row * frameHeight, frameWidth, frameHeight, 0, 0, cursorMascot.width, cursorMascot.height);
  }

  async function loadCursorSprite() {
    try {
      const bytes = Uint8Array.from(atob(OtterCursorArt.sprite), character => character.charCodeAt(0));
      cursorSprite = await createImageBitmap(new Blob([bytes], { type: 'image/webp' }));
      drawMood();
    } catch {}
  }

  function setMood(mood, animate = true) {
    if (cursorMascot.dataset.expression === mood) return;
    cursorMascot.dataset.expression = mood;
    drawMood();
    if (!animate || matchMedia('(prefers-reduced-motion:reduce)').matches) return;
    cursorMascot.classList.remove('pop');
    void cursorMascot.offsetWidth;
    cursorMascot.classList.add('pop');
  }

  loadCursorSprite();

  function scheduleCurious() {
    clearTimeout(curiousTimer);
    curiousTimer = setTimeout(() => {
      if (following && host.isConnected) setMood('curious');
    }, 1800);
  }

  function stopRunning() {
    otter.classList.remove('running');
    setMood('idle');
    scheduleCurious();
  }

  // decode the bundled art in script and paint it, so no <img> request is ever made
  async function paint(canvas, base64) {
    try {
      const bytes = Uint8Array.from(atob(base64), character => character.charCodeAt(0));
      const image = await createImageBitmap(new Blob([bytes], { type: 'image/webp' }));
      canvas.getContext('2d').drawImage(image, 0, 0, canvas.width, canvas.height);
    } catch {}
  }
  paint(root.querySelector('.mascot'), OtterArt.mascot);
  paint(root.querySelector('.logo'), OtterArt.logo);

  function send(message) {
    return new Promise(resolve => chrome.runtime.sendMessage(message, response => {
      if (chrome.runtime.lastError) resolve({ ok: false, error: chrome.runtime.lastError.message });
      else resolve(response || { ok: false, error: 'No response' });
    }));
  }

  function classify(input) {
    if (!(input instanceof HTMLInputElement) && !(input instanceof HTMLTextAreaElement)) return null;
    if (input.type === 'password' || /(?:new|current)-password/i.test(input.autocomplete || '')) return 'login';
    const metadata = [input.name, input.id, input.placeholder, input.getAttribute('aria-label')].filter(Boolean).join(' ');
    return API_KEY_PATTERN.test(metadata) ? 'api-key' : null;
  }

  function usernameNear(field) {
    const form = field.form || document;
    const candidate = form.querySelector('input[autocomplete="username"],input[type="email"],input[name*="user" i],input[name*="email" i]');
    return candidate?.value || '';
  }

  // Only a real locked vault should read as "locked"; anything else surfaces the actual error.
  function showFailure(response, lockedTitle, lockedDetail) {
    if (/locked/i.test(response?.error || '')) show(lockedTitle, lockedDetail, [{ label: 'Okay', run: hide }], { autoHide: NOTICE_MS });
    else show('Something went wrong.', response?.error || 'No response from Otter.', [{ label: 'Okay', run: hide }]);
  }

  // Clickjacking defence. A page can cover the bubble with a decoy that lets clicks pass through,
  // or pop the bubble up under a click that is already on its way. Actions therefore run only for
  // real (trusted) clicks on a bubble the browser reports as unobstructed, and only once it has
  // been readable for MIN_VISIBLE_MS.
  const MIN_VISIBLE_MS = 500;
  const RECHECK_MS = 160;
  let shownAt = 0;
  let visibleSince = 0;
  // IntersectionObserver v2 reports occlusion, opacity and filters (Chromium); elsewhere only the timing gate applies
  const tracksVisibility = typeof IntersectionObserverEntry !== 'undefined' && 'isVisible' in IntersectionObserverEntry.prototype;
  if (tracksVisibility) {
    new IntersectionObserver(entries => {
      const entry = entries[entries.length - 1];
      visibleSince = entry.isVisible ? (visibleSince || performance.now()) : 0;
    }, { trackVisibility: true, delay: 100 }).observe(bubble);
  }

  const readableSince = at => at - shownAt >= MIN_VISIBLE_MS &&
    (!tracksVisibility || (visibleSince > 0 && at - visibleSince >= MIN_VISIBLE_MS));

  function pausedClick() {
    let note = bubble.querySelector('.note');
    if (!note) {
      note = document.createElement('small');
      note.className = 'note';
      bubble.querySelector('.actions')?.before(note);
    }
    note.textContent = 'I paused that click. Make sure nothing is covering me, then try again.';
  }

  function guarded(run) {
    return event => {
      if (!event.isTrusted) return;
      const clickedAt = performance.now();
      if (!readableSince(clickedAt)) { pausedClick(); return; }
      // an overlay added just before the click is only reported after the observer delay, so look again
      setTimeout(() => {
        if (tracksVisibility && !(visibleSince > 0 && clickedAt - visibleSince >= MIN_VISIBLE_MS)) { pausedClick(); return; }
        run(event);
      }, tracksVisibility ? RECHECK_MS : 0);
    };
  }

  // Notices that only inform (a locked vault) tuck themselves away; offers wait longer. Hovering
  // or focusing the prompt pauses the countdown, so it never vanishes while you're reading it.
  let autoHideTimer = null;
  let autoHideMs = 0;
  function armAutoHide(ms = autoHideMs) {
    clearTimeout(autoHideTimer);
    if (ms > 0) autoHideTimer = setTimeout(hide, ms);
  }
  bubble.addEventListener('pointerenter', () => clearTimeout(autoHideTimer));
  bubble.addEventListener('focusin', () => clearTimeout(autoHideTimer));
  bubble.addEventListener('pointerleave', () => { if (autoHideMs && !bubble.hidden) armAutoHide(6000); });

  function show(title, detail, actions = [], { autoHide = 0 } = {}) {
    autoHideMs = autoHide;
    armAutoHide();
    // Attach only when there is something to say, so pages without secret fields never see the host.
    if (!host.isConnected) document.documentElement.appendChild(host);
    following = false;
    clearTimeout(stopTimer);
    clearTimeout(curiousTimer);
    otter.classList.remove('running');
    setMood('curious');
    otter.classList.add('active');
    bubble.hidden = false;
    // built as nodes, never markup: whatever the page puts in a message can only ever be text
    content.replaceChildren();
    const heading = document.createElement('strong');
    heading.textContent = title;
    const body = document.createElement('span');
    body.textContent = detail;
    const row = document.createElement('div');
    row.className = 'actions';
    for (const action of actions) {
      const button = document.createElement('button');
      button.type = 'button';
      if (action.secondary) button.className = 'secondary';
      button.textContent = action.label;
      button.addEventListener('click', guarded(action.run));
      row.append(button);
    }
    content.append(heading, body, row);
    shownAt = performance.now();
  }

  function hide() {
    clearTimeout(autoHideTimer);
    autoHideMs = 0;
    bubble.hidden = true;
    otter.classList.remove('active');
    following = true;
    stopRunning();
  }

  async function handleSecretFocus(field, kind) {
    activeField = field;
    currentKind = kind;
    const match = await send({ type: 'has-match', kind: currentKind });
    if (!match.ok) return;
    if (!match.data.unlocked) {
      show('My notebook is locked.', 'Unlock Otter from the browser toolbar before saving or filling secrets.', [
        { label: 'Okay', run: hide }
      ], { autoHide: NOTICE_MS });
    } else if (match.data.hasMatch && match.data.insecureFill) {
      show('This page is not secure.', 'It uses plain http, so anyone on the network could read a filled secret. I won’t fill here.', [
        { label: 'Save another', run: saveSecret },
        { label: 'Not now', secondary: true, run: hide }
      ]);
    } else if (match.data.hasMatch) {
      show('I know this place.', 'Fill the secret saved for this exact website?', [
        { label: 'Fill securely', run: fillSecret },
        { label: 'Not now', secondary: true, run: hide }
      ]);
    } else {
      show(kind === 'api-key' ? 'I spotted a secret key.' : 'I spotted a password.', 'Save it only when you explicitly ask me to.', [
        { label: 'Keep it safe', run: saveSecret }, { label: 'Not now', secondary: true, run: hide }
      ]);
    }
  }

  async function handleSecretReveal(value, context, element = null) {
    if (OWN_SITE) return;
    const kind = OtterDetect.classifyReveal(value, context);
    if (!kind) return;
    // one prompt per element per page: a key that is typed out, re-rendered or animated on a loop
    // (a demo, a live preview) doesn't make the otter pop up again and again
    if (element) quietElements.add(element);
    activeField = { value, username: OtterDetect.companionId(context) };
    currentKind = kind;
    const status = await send({ type: 'has-match', kind: currentKind });
    if (!status.ok || !status.data.unlocked) {
      if (lockedNoticeShown) return;
      lockedNoticeShown = true;
      if (!status.ok) { showFailure(status, 'A new key surfaced, but I’m locked.', 'Unlock Otter from the toolbar, then try again.'); return; }
      show('A new key surfaced, but I’m locked.', 'Unlock Otter from the toolbar, then return here and try again.', [
        { label: 'Try again', run: () => handleSecretReveal(value, context) }, { label: 'Not now', secondary: true, run: hide }
      ], { autoHide: NOTICE_MS });
      return;
    }
    show('A new API key just surfaced.', 'It appeared as one-time page text. Save it before it disappears?', [
      { label: 'Keep it safe', run: saveSecret }, { label: 'Not now', secondary: true, run: hide }
    ], { autoHide: OFFER_MS });
  }

  async function saveSecret() {
    if (!activeField?.value) {
      show('Nothing to save yet.', 'Enter the secret first, then ask me again.', [{ label: 'Okay', run: hide }]);
      return;
    }
    const response = await send({ type: 'save', item: {
      kind: currentKind,
      label: document.title || location.hostname,
      username: currentKind === 'login' ? usernameNear(activeField) : activeField.username || '',
      secret: activeField.value
    }});
    if (!response.ok) {
      showFailure(response, 'Unlock my notebook first.', 'Open Otter from the browser toolbar, unlock the vault, then try again.');
      return;
    }
    show('Safe and sound.', `Saved only for ${location.origin}.`, [{ label: 'Done', run: hide }]);
  }

  async function fillSecret() {
    const response = await send({ type: 'fill', kind: currentKind });
    if (!response.ok) {
      showFailure(response, 'Unlock my notebook first.', 'Open Otter from the browser toolbar, unlock the vault, then try again.');
      return;
    }
    if (!response.data || !activeField) {
      show('I could not unlock that.', 'Open the Otter toolbar and try again.', [{ label: 'Okay', run: hide }]);
      return;
    }
    // Refocusing the field would otherwise re-offer a fill and replace the confirmation below.
    refocusedByFill = activeField;
    activeField.focus();
    refocusedByFill = null;
    activeField.value = response.data.secret;
    activeField.dispatchEvent(new Event('input', { bubbles: true }));
    activeField.dispatchEvent(new Event('change', { bubbles: true }));
    show('Filled for this site.', 'I checked the exact origin before opening the notebook.', [{ label: 'Done', run: hide }]);
  }

  document.addEventListener('focusin', event => {
    if (event.target === refocusedByFill) return;
    const kind = classify(event.target);
    if (kind) handleSecretFocus(event.target, kind);
  }, true);

  // The wording around a reveal ("will not be shown again") decides unknown formats. Sites nest the
  // key in several wrappers that hold nothing else (Cloudflare uses four), so climb until the
  // ancestor has real text beside the key, stopping at a dialog or section boundary.
  function revealContext(element, value) {
    let node = element;
    for (let depth = 0; node && depth < 8; depth++, node = node.parentElement) {
      const text = node.innerText || node.textContent || '';
      if (text.length > value.length + 40 || node.matches?.('[role="dialog"], dialog, section, article, form')) return text.slice(0, 4000);
    }
    return (element.parentElement?.innerText || '').slice(0, 4000);
  }

  function inspectReveal(element, value) {
    const candidate = String(value || '').trim();
    if (!candidate || quietElements.has(element) || inspectedReveals.get(element) === candidate) return;
    inspectedReveals.set(element, candidate);
    handleSecretReveal(candidate, revealContext(element, candidate), element);
  }

  // Sites render one-time keys in arbitrary elements (the Claude Console uses a <p>), so look at
  // any element whose entire text is a single whitespace-free token, plus read-only inputs.
  function scanForReveals(node) {
    const root = node.nodeType === Node.TEXT_NODE ? node.parentElement : node;
    if (!(root instanceof HTMLElement) || root === host) return;
    const texts = node.nodeType === Node.TEXT_NODE ? [node] : [];
    if (!texts.length) {
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      for (let text = walker.nextNode(); text; text = walker.nextNode()) texts.push(text);
    }
    for (const text of texts) {
      const value = text.data.trim();
      if (value.length < 16 || value.length > 512 || /\s/.test(value)) continue;
      const parent = text.parentElement;
      if (parent && parent.textContent.trim() === value) inspectReveal(parent, value);
    }
    const inputs = root.matches('input[readonly], textarea[readonly]') ? [root] : [];
    for (const input of [...inputs, ...root.querySelectorAll('input[readonly], textarea[readonly]')]) inspectReveal(input, input.value);
    // some dialogs show a new key in a plain (not read-only) input; only a value the user isn't
    // typing, inside a dialog, counts, so pasting a key into a form field is not mistaken for one
    const dialogInputs = root.closest?.('[role="dialog"], dialog') ? [root, ...root.querySelectorAll('input')] : root.querySelectorAll('[role="dialog"] input, dialog input');
    for (const input of dialogInputs) {
      if (input instanceof HTMLInputElement && !input.readOnly && input !== document.activeElement && input.value) inspectReveal(input, input.value);
    }
  }

  const revealObserver = new MutationObserver(mutations => {
    for (const mutation of mutations) {
      if (mutation.type === 'characterData') scanForReveals(mutation.target);
      else if (mutation.type === 'attributes') scanForReveals(mutation.target);
      else mutation.addedNodes.forEach(scanForReveals);
    }
  });
  // an eye button that unmasks a key often only flips an input's type or value attribute
  revealObserver.observe(document.documentElement, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ['type', 'value'] });

  // Frameworks set an input's value as a property, which no observer sees, and a key dialog's eye or
  // copy button may change it the same way. After a real click inside a dialog, look at it again.
  document.addEventListener('click', event => {
    if (!event.isTrusted) return;
    const scope = event.target instanceof Element && event.target.closest('[role="dialog"], dialog');
    if (scope) setTimeout(() => scanForReveals(scope), 120);
  }, true);

  // Opt-in from the popup: keep the otter on every page, not only once it has something to say.
  // Off by default so pages without secret fields never see the host element.
  const FOLLOW_KEY = 'cursorCompanion';
  function applyCompanion(on) {
    if (on) {
      if (!host.isConnected) document.documentElement.appendChild(host);
    } else if (bubble.hidden && host.isConnected) {
      host.remove();
    }
  }
  try {
    chrome.storage.local.get(FOLLOW_KEY, stored => applyCompanion(Boolean(stored?.[FOLLOW_KEY])));
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes[FOLLOW_KEY]) applyCompanion(Boolean(changes[FOLLOW_KEY].newValue));
    });
  } catch {}

  document.addEventListener('pointermove', event => {
    if (!following || matchMedia('(pointer:coarse)').matches || matchMedia('(prefers-reduced-motion:reduce)').matches) return;
    const now = performance.now();
    if (event.movementX > 1) cursorMascot.style.setProperty('--facing', '1');
    else if (event.movementX < -1) cursorMascot.style.setProperty('--facing', '-1');
    clearTimeout(curiousTimer);
    otter.classList.add('running');
    if (now - lastRunFrameAt > 110) {
      setMood(runFrame++ % 2 ? 'run-b' : 'run-a', false);
      lastRunFrameAt = now;
    }
    clearTimeout(stopTimer);
    stopTimer = setTimeout(stopRunning, 160);
    const x = Math.min(innerWidth - 42, Math.max(32, event.clientX + 38));
    const y = Math.min(innerHeight - 42, Math.max(32, event.clientY + 34));
    otter.style.setProperty('--x', `${x}px`);
    otter.style.setProperty('--y', `${y}px`);
  }, { passive: true });
})();
