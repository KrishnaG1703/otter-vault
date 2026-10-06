// Builds the Chrome Web Store upload: dist/otter-vault-<version>.zip with manifest.json at the zip root.
//
// The manifest's "key" field pins the extension ID for unpacked development builds, so Google
// sign-in's redirect works locally. The store item already has its own fixed ID
// (lmoadcfiocdehnbdppfhimonghalcmgl), so the upload leaves the field out.
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const manifest = JSON.parse(readFileSync('extension/manifest.json', 'utf8'));
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
if (manifest.version !== pkg.version) {
  throw new Error(`Version mismatch: manifest ${manifest.version}, package.json ${pkg.version}`);
}
for (const path of Object.values(manifest.icons)) {
  if (!existsSync(`extension/${path}`)) throw new Error(`Missing icon extension/${path}`);
}

const stage = mkdtempSync(join(tmpdir(), 'otter-package-'));
try {
  cpSync('extension', stage, { recursive: true });
  const { key, ...published } = manifest;
  writeFileSync(join(stage, 'manifest.json'), `${JSON.stringify(published, null, 2)}\n`);
  mkdirSync('dist', { recursive: true });
  const out = resolve(`dist/otter-vault-${manifest.version}.zip`);
  rmSync(out, { force: true });
  execFileSync('zip', ['-r', '-X', '-q', out, '.', '-x', '*.DS_Store'], { cwd: stage, stdio: 'inherit' });
  console.log(`Wrote ${out}`);
} finally {
  rmSync(stage, { recursive: true, force: true });
}
