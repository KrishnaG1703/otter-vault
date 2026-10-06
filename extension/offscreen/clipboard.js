// Offscreen page that wipes a copied secret once its time is up. It reads the clipboard first and
// only clears it if it still holds that secret, so anything the user copied since is left alone.
const scratch = document.getElementById('scratch');
const workerUrl = chrome.runtime.getURL('background.js');

async function sha256(value) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
  return btoa(String.fromCharCode(...digest));
}

function readClipboard() {
  scratch.value = '';
  scratch.focus();
  document.execCommand('paste');
  return scratch.value;
}

function emptyClipboard() {
  const wipe = event => { event.clipboardData.setData('text/plain', ''); event.preventDefault(); };
  document.addEventListener('copy', wipe, { once: true });
  document.execCommand('copy');
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // only the service worker may ask; content scripts' messages carry a tab
  if (message?.target !== 'otter-offscreen' || sender.id !== chrome.runtime.id || sender.tab || sender.url !== workerUrl) return;
  sha256(readClipboard()).then(hash => {
    scratch.value = '';
    if (hash === message.hash) emptyClipboard();
    sendResponse({ cleared: hash === message.hash });
  });
  return true;
});
