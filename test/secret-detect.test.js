import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../extension/content/secret-detect.js', import.meta.url), 'utf8');
const { classifyReveal, companionId } = new Function(`${source}; return OtterDetect;`)();
const fake = (prefix, length, alphabet = 'aB3dE5gH7jK9mN1pQ2sT4vW6yZ8cF0hL') =>
  prefix + Array.from({ length }, (_, i) => alphabet[(i * 7 + 3) % alphabet.length]).join('');

test('known provider key formats are detected without page wording', () => {
  assert.equal(classifyReveal(fake('sk-ant-api03-', 95), ''), 'api-key');
  assert.equal(classifyReveal(fake('ghp_', 36), ''), 'api-key');
});

test('AWS: the secret access key is caught, the access key ID is not a secret', () => {
  const context = 'Retrieve access keys\nThis is the only time that the secret access key can be viewed or downloaded.\nAccess key\tSecret access key\nAKIAABCDEFGHIJKLMNOP\twJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
  assert.equal(classifyReveal('wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', context), 'api-key');
  assert.equal(classifyReveal('AKIAABCDEFGHIJKLMNOP', context), null);
  assert.equal(companionId(context), 'AKIAABCDEFGHIJKLMNOP');
  // 40 base64-ish characters without the AWS wording stay ignored
  assert.equal(classifyReveal('wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', 'Commit copied'), null);
});

test('Claude Console reveal wording spanning lines counts as context for unknown formats', () => {
  const context = 'Save your API key\n\nThis key expires on Wed.\n\nKeep a record of the key below. You won’t be able to view it again.\n\nCopy key\nDone';
  assert.equal(classifyReveal(fake('', 48), context), 'api-key');
  assert.equal(classifyReveal(fake('', 48), 'Welcome back'), null);
});

test('hashes, UUIDs, masked keys, and prose are not treated as secrets', () => {
  const copyContext = 'Commit copied. Copy the token value';
  assert.equal(classifyReveal('9fceb02d0ae598e95dc970b74767f19372d61af8', copyContext), null);
  assert.equal(classifyReveal('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', copyContext), null);
  assert.equal(classifyReveal('123e4567-e89b-42d3-a456-426614174000', copyContext), null);
  assert.equal(classifyReveal('sk-ant-api03-dFd...WgAA', copyContext), null);
  assert.equal(classifyReveal('sk-ant-api03-...', copyContext), null);
  assert.equal(classifyReveal('this is not a key at all', copyContext), null);
  assert.equal(classifyReveal('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', copyContext), null);
});

test('Vercel, Cloudflare and Supabase reveals are caught; public keys beside them are not', () => {
  const vercel = "Token created\nCopy this token now. For security reasons you won't be able to see it again.";
  assert.equal(classifyReveal('Ab3dE5gH7jK9mN1pQ2sT4vW6', vercel), 'api-key');
  assert.equal(classifyReveal('Ab3dE5gH7jK9mN1pQ2sT4vW6', 'Deployment details'), null);
  const cloudflare = 'API token created\nThis API token will not be shown again.';
  assert.equal(classifyReveal(fake('', 40), cloudflare), 'api-key');
  assert.equal(classifyReveal('sb_secret_' + fake('', 31), ''), 'api-key');
  assert.equal(classifyReveal('sbp_' + '0123456789abcdef'.repeat(2) + '01234567', ''), 'api-key');
  const supabase = 'Secret keys\nThis key can bypass Row Level Security. Reveal and copy it into your server environment.';
  assert.equal(classifyReveal('sb_publishable_' + fake('', 22) + '_' + fake('', 8), supabase), null);
  assert.equal(classifyReveal('pk_live_51' + fake('', 90), 'API keys. Reveal your secret key once.'), null);
});

test('short unprefixed tokens beside one-time wording are caught reliably, readable identifiers are not', () => {
  const context = "Token created\nCopy this token now. For security reasons you won't be able to see it again.";
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let state = 42;
  const next = () => (state = (state * 1664525 + 1013904223) >>> 0);
  let missed = 0;
  for (let i = 0; i < 5000; i++) {
    const token = Array.from({ length: 24 }, () => alphabet[next() % alphabet.length]).join('');
    if (!classifyReveal(token, context)) missed++;
  }
  // CI caught a 6.6% miss rate on random 24-character Vercel-style tokens; keep it under 1%
  assert.ok(missed / 5000 < 0.01, `missed ${missed} of 5000 random tokens`);
  for (const identifier of ['AuthenticationRequiredError', 'getElementsByClassNameForTest', 'PersonalAccessTokenSettings', 'ThisTokenWillNotBeShownAgain', 'useVercelDeploymentTokenHook', 'XMLHttpRequestEventTarget', 'iOSAppStoreConnectAPIKey', 'createdAtTimestampForUser']) {
    assert.equal(classifyReveal(identifier, context), null, identifier);
  }
});

test('Cloudflare cfut_/cfat_ tokens are recognised on sight', () => {
  assert.equal(classifyReveal('cfut_' + fake('', 48), ''), 'api-key');
  assert.equal(classifyReveal('cfat_' + fake('', 48), ''), 'api-key');
});

test('Vercel AI Gateway vck_ keys are recognised on sight', () => {
  assert.equal(classifyReveal('vck_' + fake('', 40), ''), 'api-key');
  assert.equal(classifyReveal('vck_********0zhJ', 'You won’t be able to view it again'), null);
});
