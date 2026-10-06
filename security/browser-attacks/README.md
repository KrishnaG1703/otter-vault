# Browser attack checks

A hostile page and a script that attack the content script in a real Chrome with the extension loaded. Every attack should leave the password field empty; the two "legit" checks should save and fill normally.

| check | what the page does | expected |
| --- | --- | --- |
| synthetic click | page script calls `.click()` / `dispatchEvent` at the Fill button | not filled |
| cover | re-appends an opaque decoy (`pointer-events: none`) above the extension so the user clicks "claim your prize" | not filled |
| transparent page | sets `html { opacity: 0.02 }` so the prompt is invisible | not filled |
| pop-under | the first click summons the prompt under the pointer, the second lands on Fill | not filled |
| extension access | page looks for `chrome.runtime.sendMessage` | unavailable |
| disable / tamper | pre-sets the load guard and monkeypatches `attachShadow` | otter still appears, shadow stays closed |

## Run

1. Serve the page: `python3 -m http.server 4299 --bind 127.0.0.1 --directory security/browser-attacks` (open `hostile-page.html`, or rename it to `index.html`).
2. Launch Chrome for Testing (branded Chrome ignores `--load-extension`) with a throwaway profile:
   `"<Chrome for Testing>" --user-data-dir=/tmp/otter-attack --remote-debugging-port=9231 --disable-extensions-except=$PWD/extension --load-extension=$PWD/extension http://127.0.0.1:4299/`
   Keep the window in front; `chrome.action.openPopup()` needs an active window.
3. Update `extId` in `cdp.mjs` to the loaded extension's id, then `node security/browser-attacks/run.mjs /tmp`.
