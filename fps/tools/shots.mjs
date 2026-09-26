// Captures screenshots of named camera poses for visual review.
// Usage: node tools/shots.mjs [outDir] [shot1,shot2,...]
// Starts a Vite dev server on a free port, loads ?shot=<name>, waits for
// window.__shotReady, and writes <outDir>/<name>.png at 1920x1080.
import { chromium } from 'playwright-core';
import { createServer } from 'vite';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outDir = path.resolve(process.argv[2] || path.join(root, 'shots'));
const names = (process.argv[3] || 'overview,street,cover,weapon,ads,combat,sky').split(',');
mkdirSync(outDir, { recursive: true });

const server = await createServer({ root, logLevel: 'error', server: { port: 0, host: '127.0.0.1' } });
await server.listen();
const url = server.resolvedUrls.local[0];

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH || '/opt/pw-browsers/chromium-1194/chrome-linux/chrome',
  args: ['--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'],
});
const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
const errors = [];
page.on('pageerror', (e) => errors.push(String(e)));
page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });

for (const name of names) {
  await page.goto(`${url}?shot=${name}`);
  try {
    await page.waitForFunction(() => window.__shotReady === true, null, { timeout: 180000 });
  } catch {
    errors.push(`${name}: timed out waiting for __shotReady`);
  }
  const file = path.join(outDir, `${name}.png`);
  await page.screenshot({ path: file });
  console.log('wrote', file);
}

if (errors.length) console.log('ERRORS:\n' + [...new Set(errors)].join('\n'));
await browser.close();
await server.close();
