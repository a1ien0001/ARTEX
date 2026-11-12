// Only escaped, server-generated SVG is accepted. No target URL is visited.
const fs = require('node:fs');
const path = require('node:path');
async function run() {
  let playwright;
  const candidates = [process.env.ARTEX_REPORT_PLAYWRIGHT, 'playwright', path.join(path.dirname(process.execPath), 'node_modules/playwright'), '/usr/lib/node_modules/playwright', '/usr/local/lib/node_modules/playwright'].filter(Boolean);
  for (const name of candidates) {
    try { playwright = require(name); break; } catch (_) {}
  }
  if (!playwright) throw new Error('Playwright is unavailable');
  const cards = JSON.parse(fs.readFileSync(0, 'utf8'));
  const browser = await playwright.chromium.launch({ headless: true, args: ['--no-sandbox'] });
  try {
    const context = await browser.newContext({ deviceScaleFactor: 1, javaScriptEnabled: false });
    await context.route('**/*', route => route.abort());
    const page = await context.newPage();
    const images = [];
    for (const card of cards) {
      await page.setViewportSize({ width: card.width, height: card.height });
      await page.setContent('<!doctype html><html><head><meta charset="utf-8"><style>html,body{margin:0;padding:0}body>svg{display:block}</style></head><body>' + card.svg + '</body></html>');
      await page.evaluate(() => document.fonts.ready);
      images.push((await page.screenshot({ type: 'png', fullPage: true, animations: 'disabled' })).toString('base64'));
    }
    process.stdout.write(JSON.stringify(images));
  } finally { await browser.close(); }
}
run().catch(error => { process.stderr.write(error.message); process.exitCode = 1; });
