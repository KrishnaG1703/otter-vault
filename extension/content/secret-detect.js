// Classic script: content scripts cannot import modules, so this defines OtterDetect in the
// extension's isolated world, where content.js (listed after it in the manifest) can use it.
var OtterDetect = (() => {
  // Provider formats specific enough to trust without surrounding page wording.
  const KNOWN_KEY_PATTERNS = [
    /^sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}$/, // Anthropic
    /^sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}$/, // OpenAI project, service account, admin
    /^sk-[A-Za-z0-9]{40,}$/, // OpenAI legacy
    /^gh[pousr]_[A-Za-z0-9]{36,}$/, // GitHub
    /^github_pat_[A-Za-z0-9_]{60,}$/, // GitHub fine-grained
    /^xox[abposr]-[A-Za-z0-9-]{20,}$/, // Slack
    /^AIza[0-9A-Za-z_-]{35}$/, // Google
    /^glpat-[A-Za-z0-9_-]{20,}$/, // GitLab
    /^(?:sk|rk)_live_[A-Za-z0-9]{24,}$/, // Stripe
    /^hf_[A-Za-z0-9]{30,}$/, // Hugging Face
    /^gsk_[A-Za-z0-9]{40,}$/, // Groq
    /^npm_[A-Za-z0-9]{36}$/, // npm
    /^r8_[A-Za-z0-9]{30,}$/, // Replicate
    /^sb_secret_[A-Za-z0-9_-]{24,}$/, // Supabase secret API key
    /^sbp_[a-f0-9]{40}$/, // Supabase personal access token
    /^cf[ua]t_[A-Za-z0-9_-]{40,}$/, // Cloudflare user and account API tokens
    /^vck_[A-Za-z0-9_-]{24,}$/ // Vercel AI Gateway
  ];
  // Keys that are designed to be public, often shown right beside the secret one.
  const PUBLIC_KEY_PATTERNS = [/^pk_(?:live|test)_/, /^sb_publishable_/];
  // Wording that a value is being shown one time only, strong enough to trust shorter unprefixed
  // tokens (Vercel's are 24 characters).
  const ONE_TIME_CONTEXT = /(?:won[’']?t|will not|cannot|can[’']?t|not be able to)\s+(?:be\s+)?(?:able\s+to\s+)?(?:see|view|shown|display|recover|retrieve)\w*[\s\S]{0,24}again|only time|shown (?:only )?once|will not be shown/i;
  // AWS access key IDs (AKIA…) are identifiers, not secrets. The secret access key next to one has
  // no prefix, so it counts only when the page calls it that; the ID is kept as the username.
  const AWS_SECRET = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])[A-Za-z0-9/+]{40}$/;
  const AWS_SECRET_CONTEXT = /secret access key/i;
  const AWS_KEY_ID = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/;
  const REVEAL_CONTEXT = /(api[\s-]*key|secret|token)[\s\S]{0,160}(created|generated|copy|shown|reveal|view it again|see it again|keep a record)|(created|generated|shown once|reveal|save your)[\s\S]{0,160}(api[\s-]*key|secret|token)/i;

  function entropyOf(value) {
    const counts = new Map();
    for (const character of value) counts.set(character, (counts.get(character) || 0) + 1);
    let entropy = 0;
    for (const count of counts.values()) {
      const p = count / value.length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  // Unknown formats must look like random credentials: mixed case and digits, high entropy,
  // and not hex, which rules out commit SHAs, checksums, and UUIDs.
  function looksRandom(value) {
    if (value.length < 32 || /[^A-Za-z0-9_.-]/.test(value)) return false;
    if (/^[0-9a-f]+$/i.test(value.replaceAll('-', ''))) return false;
    if (![/[a-z]/, /[A-Z]/, /[0-9]/].every(pattern => pattern.test(value))) return false;
    return entropyOf(value) >= 4;
  }

  // Shorter unprefixed tokens (Vercel's are 24 characters) only count beside one-time wording.
  // Random 24-character strings often repeat letters or lack a digit, so instead of those tests
  // this rejects what readable identifiers look like: mostly covered by camelCase word chunks, or
  // vowel-rich like English. Tuned on 50,000 random tokens against real camelCase names.
  function looksLikeShortToken(value) {
    if (value.length < 24 || value.length > 64 || /[^A-Za-z0-9_-]/.test(value)) return false;
    if (/^[0-9a-f]+$/i.test(value.replaceAll('-', ''))) return false;
    if (!/[a-z]/.test(value) || !/[A-Z]/.test(value)) return false;
    const wordChunks = (value.match(/[A-Z]?[a-z]{3,}/g) || []).join('').length / value.length;
    const letters = (value.match(/[A-Za-z]/g) || []).length;
    const vowels = (value.match(/[aeiouAEIOU]/g) || []).length / letters;
    if (wordChunks >= 0.75 || (wordChunks >= 0.45 && vowels >= 0.38)) return false;
    return entropyOf(value) >= 3.5;
  }

  function classifyReveal(value, context) {
    const candidate = String(value || '').trim();
    if (candidate.length < 16 || candidate.length > 512 || /\s/.test(candidate)) return null;
    if (PUBLIC_KEY_PATTERNS.some(pattern => pattern.test(candidate))) return null;
    if (KNOWN_KEY_PATTERNS.some(pattern => pattern.test(candidate))) return 'api-key';
    if (AWS_SECRET.test(candidate) && AWS_SECRET_CONTEXT.test(String(context || ''))) return 'api-key';
    const text = String(context || '');
    if (looksRandom(candidate) && REVEAL_CONTEXT.test(text)) return 'api-key';
    return looksLikeShortToken(candidate) && ONE_TIME_CONTEXT.test(text) ? 'api-key' : null;
  }

  // An identifier shown beside the secret, saved as the record's username so the pair stays together.
  function companionId(context) {
    return String(context || '').match(AWS_KEY_ID)?.[0] || '';
  }

  return { classifyReveal, companionId };
})();
