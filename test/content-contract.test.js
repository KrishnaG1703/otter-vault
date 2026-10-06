import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../extension/content/content.js', import.meta.url), 'utf8');

test('content script sends the production save schema without an origin', () => {
  const savePayload = source.match(/send\(\{ type: 'save', item: \{([\s\S]*?)\n\s*\}\}\)/)?.[1];
  assert.ok(savePayload, 'production save payload was not found');
  assert.match(savePayload, /kind: currentKind/);
  assert.match(savePayload, /label:/);
  assert.match(savePayload, /username:/);
  assert.match(savePayload, /secret:/);
  assert.doesNotMatch(savePayload, /\borigin\s*:/);
});

test('content script passes credential kind for has-match and fill', () => {
  assert.match(source, /send\(\{ type: 'has-match', kind: currentKind \}\)/);
  assert.match(source, /send\(\{ type: 'fill', kind: currentKind \}\)/);
});

test('matching credential UI offers only fill and dismiss, so the choice is unambiguous', () => {
  const matchingBranch = source.match(/else if \(match\.data\.hasMatch\) \{([\s\S]*?)\n\s*\} else \{/)?.[1];
  assert.ok(matchingBranch, 'matching credential UI branch was not found');
  assert.match(matchingBranch, /label: 'Fill securely'/);
  assert.match(matchingBranch, /label: 'Not now'/);
  assert.ok(!/run: saveSecret/.test(matchingBranch), 'a fill prompt should not also offer to save');
});

test('bubble actions are guarded against synthetic clicks, clickjacking overlays and pop-under clicks', () => {
  const wiring = source.match(/button\.addEventListener\('click', [^\n]+/)?.[0];
  assert.ok(wiring, 'bubble action wiring was not found');
  assert.match(wiring, /guarded\(action\.run\)/);
  // the prompt is built from nodes, so a message can never become markup in the page
  assert.ok(!/content\.innerHTML/.test(source), 'the bubble should not be built with innerHTML');
  const guard = source.match(/function guarded\(run\) \{([\s\S]*?)\n  \}\n/)?.[1];
  assert.ok(guard, 'guard was not found');
  assert.match(guard, /event\.isTrusted/);
  assert.match(guard, /readableSince\(clickedAt\)/);
  assert.match(source, /trackVisibility: true/);
  assert.match(source, /MIN_VISIBLE_MS = 500/);
});
