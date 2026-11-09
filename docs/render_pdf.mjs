import { chromium } from '../ultrademo_repo/scaffold/node_modules/playwright/index.mjs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

async function generatePDF() {
  console.log('Launching Playwright Chromium for Executive PDF rendering...');
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  const htmlPath = path.resolve('docs/whitepaper.html');
  const fileUrl = pathToFileURL(htmlPath).href;

  await page.goto(fileUrl, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1000);

  const outputPath = path.resolve('AegisShield_3.0_Executive_Technical_Whitepaper.pdf');
  console.log(`Rendering PDF to: ${outputPath}...`);

  await page.pdf({
    path: outputPath,
    format: 'A4',
    printBackground: true,
    margin: {
      top: '15mm',
      bottom: '15mm',
      left: '15mm',
      right: '15mm'
    }
  });

  await browser.close();
  console.log('Executive Whitepaper PDF generated successfully!');
}

generatePDF().catch(err => {
  console.error('PDF rendering failed:', err);
  process.exit(1);
});
