// Stand-in key pages for real providers. Each page is served on the provider's real hostname
// through the lab proxy, so origin binding is tested against the names users actually visit.
// Keys are random strings in each provider's published format; none of them are real.
import { randomBytes } from 'node:crypto';

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const pick = (alphabet, length) => [...randomBytes(length)].map(b => alphabet[b % alphabet.length]).join('');
const alnum = length => pick(ALNUM, length);
const urlsafe = length => pick(ALNUM + '_-', length);

export const providers = [
  {
    id: 'openai', name: 'OpenAI', host: 'platform.openai.com', lookalike: 'platform.openai.com.account-verify.dev',
    keyPath: '/api-keys', usePath: '/playground',
    key: () => `sk-proj-${urlsafe(156)}`,
    // OpenAI shows the new key in a read-only input inside "Save your key"
    reveal: key => `<h2>Save your key</h2><p>Please save your secret key in a safe place since you won't be able to view it again. Keep it secure, as anyone with your API key can make requests on your behalf.</p><input readonly value="${key}"><button>Copy</button>`,
    field: '<label>API key <input name="api_key" placeholder="sk-..."></label>'
  },
  {
    id: 'anthropic', name: 'Anthropic', host: 'console.anthropic.com', lookalike: 'console-anthropic.com',
    keyPath: '/settings/keys', usePath: '/workbench',
    key: () => `sk-ant-api03-${urlsafe(93)}AA`,
    // the Claude Console renders the key in a plain <p>
    reveal: key => `<h2>Save your API key</h2><p>${key}</p><p>Keep a record of the key below. You won't be able to view it again.</p><button>Copy key</button>`,
    field: '<label>Anthropic API key <input id="anthropic-api-key" aria-label="API key"></label>'
  },
  {
    id: 'google', name: 'Google AI Studio', host: 'aistudio.google.com', lookalike: 'aistudio.google.com.gemini-login.app',
    keyPath: '/app/apikey', usePath: '/app/prompts',
    key: () => `AIza${urlsafe(35)}`,
    reveal: key => `<h2>API key generated</h2><p>Use your API keys securely. Do not share them or embed them in code the public can view.</p><div class="row"><code>${key}</code><button>Copy</button></div>`,
    field: '<label>Gemini API key <input name="apiKey" placeholder="API key"></label>'
  },
  {
    id: 'aws', name: 'AWS IAM', host: 'us-east-1.console.aws.amazon.com', lookalike: 'us-east-1.console-aws-amazon.com',
    keyPath: '/iam/home', usePath: '/lambda/home',
    key: () => `AKIA${pick('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 16)}`,
    // AWS shows two values; the secret access key is the part that matters
    secret: () => pick(ALNUM + '/+', 40),
    reveal: (key, secret) => `<h2>Retrieve access keys</h2><p>This is the only time that the secret access key can be viewed or downloaded. You cannot recover it later.</p><table><tr><th>Access key</th><th>Secret access key</th></tr><tr><td><span>${key}</span></td><td><span>${secret}</span></td></tr></table>`,
    field: '<label>Secret access key <input name="secret_key" placeholder="Secret access key"></label>'
  },
  {
    id: 'stripe', name: 'Stripe', host: 'dashboard.stripe.com', lookalike: 'dashboard.strlpe.com',
    keyPath: '/apikeys', usePath: '/settings/integrations',
    key: () => `sk_live_51${alnum(97)}`,
    reveal: key => `<h2>Secret key created</h2><p>Copy the key below and store it somewhere safe. For security reasons, you can only reveal a live secret key once.</p><div class="row"><span class="mono">${key}</span></div>`,
    field: '<label>Stripe secret key <input name="stripe_secret_key" placeholder="sk_live_..."></label>'
  },
  {
    id: 'github', name: 'GitHub', host: 'github.com', lookalike: 'github.com-settings.tokens.dev',
    keyPath: '/settings/personal-access-tokens', usePath: '/settings/codespaces',
    key: () => `github_pat_11${pick('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 20)}_${alnum(59)}`,
    reveal: key => `<h2>Fine-grained personal access tokens</h2><p>Make sure to copy your personal access token now. You won't be able to see it again!</p><code id="new-access-token">${key}</code>`,
    field: '<label>Personal access token <input name="access_token"></label>',
    // GitHub sends a strict CSP; the otter must still draw its art
    csp: "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self'"
  },
  {
    id: 'huggingface', name: 'Hugging Face', host: 'huggingface.co', lookalike: 'hugglngface.co',
    keyPath: '/settings/tokens', usePath: '/settings/inference',
    key: () => `hf_${alnum(34)}`,
    reveal: key => `<h2>Save your Access Token</h2><p>Save your token value somewhere safe. You will not be able to see it again after you close this modal.</p><input readonly value="${key}">`,
    field: '<label>User access token <input name="hf_token" aria-label="Access token"></label>'
  },
  {
    id: 'vercel', name: 'Vercel', host: 'vercel.com', lookalike: 'vercel.com-account.tokens.app',
    keyPath: '/account/settings/tokens', usePath: '/account/settings/integrations',
    // Vercel tokens have no prefix and are only 24 characters
    key: () => alnum(24),
    reveal: key => `<h2>Token created</h2><p>Copy this token now. For security reasons you won't be able to see it again.</p><input readonly value="${key}"><button>Copy</button>`,
    field: '<label>Vercel access token <input name="vercel_token" aria-label="Access token"></label>'
  },
  {
    id: 'cloudflare', name: 'Cloudflare', host: 'dash.cloudflare.com', lookalike: 'dash.cloudfIare.com',
    keyPath: '/profile/api-tokens', usePath: '/profile/integrations',
    // real dashboard (checked live 2026-09-16): a cfut_ token alone inside four nested divs, with the
    // "will not be shown again" wording several levels up
    wrapper: 'div', // no dialog element on the real page
    key: () => `cfut_${urlsafe(48)}`,
    reveal: key => `<div><h2>Read analytics and logs API token was successfully created</h2><p>Copy this token to access the Cloudflare API. For security this will not be shown again.</p><div><div><div><div>${key}</div></div></div></div><p>Test this token</p></div>`,
    field: '<label>Cloudflare API token <input name="api_token" placeholder="API token"></label>'
  },
  {
    id: 'cloudflare-legacy', name: 'Cloudflare (older token format)', host: 'dash.cloudflare.com', lookalike: 'dash.cloudfIare.com',
    keyPath: '/profile/api-tokens-legacy', usePath: '/profile/workers',
    wrapper: 'div',
    key: () => urlsafe(40),
    reveal: key => `<div><p>API token was successfully created. For security this will not be shown again.</p><div><div><div><div>${key}</div></div></div></div></div>`,
    field: '<label>Workers API token <input name="api_token" placeholder="API token"></label>'
  },
  {
    id: 'supabase', name: 'Supabase', host: 'supabase.com', lookalike: 'supabase.com.project-login.dev',
    keyPath: '/dashboard/project/settings/api-keys', usePath: '/dashboard/project/settings/integrations',
    key: () => `sb_secret_${urlsafe(22)}_${alnum(8)}`,
    // secret keys stay masked until "reveal"; the publishable key beside it is meant to be public
    reveal: key => `<h2>Secret keys</h2><p>This key can bypass Row Level Security. Never share it publicly. Reveal and copy it into your server environment.</p><table><tr><th>Name</th><th>API key</th></tr><tr><td>default</td><td><span>${key}</span></td></tr><tr><td>publishable</td><td><span>sb_publishable_${urlsafe(22)}_${alnum(8)}</span></td></tr></table>`,
    field: '<label>Supabase secret key <input name="supabase_secret_key" placeholder="sb_secret_..."></label>'
  },
  {
    id: 'supabase-pat', name: 'Supabase access token', host: 'supabase.com', lookalike: 'supabase.com.project-login.dev',
    keyPath: '/dashboard/account/tokens', usePath: '/dashboard/account/cli',
    key: () => `sbp_${randomBytes(20).toString('hex')}`,
    reveal: key => `<h2>Your new token</h2><p>Copy this access token and store it in a secure place. You will not be able to see it again.</p><code>${key}</code>`,
    field: '<label>Access token <input name="access_token"></label>'
  }
];

// Things that look like tokens but are not secrets. Otter should stay quiet on all of them.
export const decoys = {
  host: 'github.com', path: '/octo/app/commit',
  values: () => [
    ['commit SHA', randomBytes(20).toString('hex')],
    ['UUID', crypto.randomUUID()],
    ['Stripe publishable key', `pk_live_51${alnum(97)}`],
    ['Supabase publishable key', `sb_publishable_${urlsafe(22)}_${alnum(8)}`],
    ['24-character build ID', alnum(24)],
    ['npm integrity hash', `sha512-${randomBytes(48).toString('base64')}`],
    ['file name', 'build-artifact-2026-09-14-release-candidate.tar.gz']
  ]
};
