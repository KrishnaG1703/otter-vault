# Provider lab

Checks that Otter catches, saves and fills back real-format API keys on the sites people actually create them on, and refuses lookalike domains.

Each provider gets a stand-in key page served on its real hostname (`platform.openai.com`, `console.anthropic.com`, `aistudio.google.com`, `us-east-1.console.aws.amazon.com`, `dashboard.stripe.com`, `github.com`, `huggingface.co`, `vercel.com`, `dash.cloudflare.com`, `supabase.com`) through a local HTTPS server and CONNECT proxy, so origin binding is exercised with real names. Nothing touches the internet and every key is a random string in the provider's format.

For every provider the script, in Chrome for Testing with the extension loaded:

1. clicks "create" so a one-time key appears the way that provider shows it (read-only input, `<p>`, `<code>`, table cell)
2. checks the otter offered to save it and clicks "Keep it safe" with a real click
3. opens a settings page on the same origin, accepts "Fill securely" and compares the filled value with the original key
4. opens the same page on a lookalike domain and checks nothing was offered or filled

A decoy page (commit SHA, UUID, Stripe publishable key, integrity hash) checks for false alarms. GitHub's stand-in sends a strict CSP to confirm the otter art still draws.

## Run

```bash
node security/provider-lab/run.mjs
```

Add `--keep-open` to leave the browser and proxy running afterwards. Results, screenshots and `report.html` land in `security/provider-lab/results/`. Needs Playwright's Chrome for Testing (or set `CHROME`), and ports 8443, 8899 and 9231 free.
