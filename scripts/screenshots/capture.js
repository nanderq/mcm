const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const PAGES = [
  {
    file: 'login.html',
    out: 'screenshot-login.png',
    width: 1280,
    height: 800,
    fullPage: false,
  },
  {
    file: 'dashboard.html',
    out: 'screenshot-dashboard.png',
    width: 1440,
    height: 900,
    fullPage: false,
  },
  {
    file: 'server.html',
    out: 'screenshot-server.png',
    width: 1440,
    height: 900,
    fullPage: true,
  },
];

const ASSETS_DIR = path.resolve(__dirname, '..', '..', 'assets');
const HTML_DIR = __dirname;

async function run() {
  fs.mkdirSync(ASSETS_DIR, { recursive: true });

  const browser = await chromium.launch();
  const context = await browser.newContext();

  for (const page of PAGES) {
    const p = await context.newPage();
    await p.setViewportSize({ width: page.width, height: page.height });
    const url = 'file://' + path.join(HTML_DIR, page.file).replace(/\\/g, '/');
    await p.goto(url, { waitUntil: 'networkidle' });
    // Small pause to let fonts render
    await p.waitForTimeout(300);
    const outPath = path.join(ASSETS_DIR, page.out);
    await p.screenshot({ path: outPath, fullPage: page.fullPage });
    console.log('Saved:', outPath);
    await p.close();
  }

  await browser.close();
}

run().catch(err => {
  console.error(err);
  process.exit(1);
});
