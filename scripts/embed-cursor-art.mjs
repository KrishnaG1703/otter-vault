import { readFileSync, writeFileSync } from 'node:fs';

const source = readFileSync('art/cursor-expressions.webp').toString('base64');
const output = `// Generated from art/cursor-expressions.webp.\nvar OtterCursorArt = { sprite: '${source}' };\n`;

writeFileSync('extension/content/cursor-art.js', output);
console.log('Wrote extension/content/cursor-art.js');
