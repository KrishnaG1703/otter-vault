# Live provider checks

The provider lab proves detection on stand-in pages served on real hostnames. These manual checks confirm it on the real consoles, which can change their markup at any time. Run them before each release with throwaway keys, and revoke every key straight after.

Automation cannot do this part: it needs a signed-in account on each provider, and creating real credentials is left to a person.

## Steps for each provider

1. Load the release build in a clean Chrome profile and create a vault with a test passphrase.
2. Lock the vault, then create a key named `otter-live-check`.
3. Otter should say "A new key surfaced, but I'm locked." Unlock from the toolbar, click **Try again**, then **Keep it safe**.
4. Copy the key from the provider's dialog before closing it. In the popup, check the entry's hint matches the key's start and last four characters.
5. Click **Copy** in the popup, enter the passphrase, paste into a scratch note and compare with the original.
6. Revoke the key on the provider.

## Results

| provider | console | last checked | version | result | notes |
| --- | --- | --- | --- | --- | --- |
| Anthropic | console.anthropic.com | 2026-09-14 | 0.5.1 | pass | key rendered in a plain `<p>` |
| OpenAI | platform.openai.com | 2026-09-15 | 0.5.9 | pass | key in a read-only input; filmed for the demo |
| Google AI Studio | aistudio.google.com | not yet | | | |
| Stripe (test mode) | dashboard.stripe.com | not yet | | | |
| GitHub | github.com/settings/tokens | not yet | | | |
| Hugging Face | huggingface.co/settings/tokens | not yet | | | |
| Vercel | vercel.com/account/tokens | 2026-09-16 | 0.5.10 | pass | |
| Cloudflare | dash.cloudflare.com/profile/api-tokens | 2026-09-16 | 0.5.11 | pass (missed on 0.5.10, fixed) | `cfut_` token alone in four nested divs; the wording sat outside the context otter read |
| Supabase | supabase.com/dashboard/account/tokens | 2026-09-16 | 0.5.10 | pass | |
| AWS IAM | console.aws.amazon.com/iam | not yet | | | optional; IAM keys are higher risk |
