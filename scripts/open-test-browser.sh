#!/bin/sh
# Opens Chrome for Testing with the unpacked extension and a brand-new profile, so the vault
# starts empty and first-run setup shows. Runs nothing else: no lab, no test keys.
repo="$(cd "$(dirname "$0")/.." && pwd)"
chrome="${CHROME:-$HOME/Library/Caches/ms-playwright/chromium-1234/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing}"
profile="$(mktemp -d /tmp/otter-test-profile.XXXXXX)"
exec "$chrome" --user-data-dir="$profile" --no-first-run --no-default-browser-check \
  --disable-extensions-except="$repo/extension" --load-extension="$repo/extension" \
  "https://example.com"
