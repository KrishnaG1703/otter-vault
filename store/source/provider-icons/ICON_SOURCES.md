# Teams provider icons

The Teams page labels each shared key with its provider's mark, picked from the key's site. The
marks are bundled in `extension/team/provider-icons.js` (built by `scripts/build-provider-icons.mjs`),
so the page never requests an image from anyone. Sites outside the list keep the letter tile.

- Most marks: Simple Icons 16.34.0, CC0-1.0, https://github.com/simple-icons/simple-icons
- `openai`, `slack`, `amazonwebservices`, `google` (files in this folder): Simple Icons 13.0.0, same
  source. OpenAI, Slack and AWS have since asked Simple Icons to remove their marks.
- `groq` (file in this folder): Lobe Icons static SVG 1.95.1, MIT, https://github.com/lobehub/lobe-icons

Brand marks belong to their owners and are used only to identify which provider a key is for.
