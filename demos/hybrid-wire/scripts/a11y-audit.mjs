// Automated accessibility + mobile audit.
//
// Builds nothing itself — run `npm run build` first, then this serves the
// production `dist/` with `vite preview` and drives it with a real Chromium via
// Playwright, running axe-core (WCAG 2.0/2.1 A & AA rules) against every tab and
// interactive state, at both desktop and mobile viewports. It also checks for
// horizontal overflow on a 375px phone.
//
//   npm run audit:a11y
//
// Exits non-zero if any serious/critical WCAG violation is found.

import { preview } from 'vite';
import { chromium } from 'playwright';
import { AxeBuilder } from '@axe-core/playwright';

const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function scan(page, label, results) {
  const axe = new AxeBuilder({ page }).withTags(WCAG_TAGS);
  const { violations } = await axe.analyze();
  results.push({ label, violations });
  const serious = violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
  const tag = serious.length ? 'FAIL' : violations.length ? 'warn' : 'pass';
  console.log(
    `  [${tag}] ${label} — ${violations.length} violation(s)` +
      (serious.length ? `, ${serious.length} serious/critical` : ''),
  );
  for (const v of violations) {
    console.log(`        • (${v.impact}) ${v.id}: ${v.help} [${v.nodes.length} node(s)]`);
  }
}

// Walks every tab + interactive state and runs axe on each. `theme` labels the
// pass and is also forced via localStorage so the page boots in that theme.
async function sweepDesktop(browser, BASE, theme, results) {
  console.log(`\nDesktop viewport (1280x800) — ${theme} theme:`);
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  await context.addInitScript((t) => window.localStorage.setItem('theme', t), theme);
  const page = await context.newPage();
  await page.goto(BASE, { waitUntil: 'networkidle' });
  await page.waitForSelector('.stepper', { timeout: 15000 });

  const tag = (label) => `${theme} — ${label}`;

  // Handshake tab, advanced to step 6 so the HKDF combiner view renders.
  for (let i = 0; i < 5; i += 1) {
    await page.click('#next-step');
  }
  await page.waitForSelector('.combiner-flow');
  await scan(page, tag('Handshake tab (step 6, combiner visible)'), results);

  await page.click('#tab-wires');
  await page.waitForSelector('.formula');
  await scan(page, tag('Two wires tab'), results);

  await page.click('#tab-threat');
  await page.waitForSelector('.resilience-card');
  await scan(page, tag('Threat tab (both wires intact)'), results);

  // Flip both resilience switches and re-scan the live verdict region.
  await page.click('#break-x25519');
  await page.click('#break-mlkem');
  await page.waitForSelector('.resilience-verdict.compromised');
  await scan(page, tag('Threat tab (both wires broken — compromised)'), results);

  await page.click('#tab-deployed');
  await page.waitForSelector('.deployment-grid');
  await scan(page, tag('Deployed tab'), results);

  await page.click('#tab-why');
  await page.waitForSelector('.panel');
  await scan(page, tag('Why hybrid tab'), results);

  await context.close();
}

async function main() {
  const server = await preview({ preview: { port: 4173, strictPort: true } });
  const BASE = server.resolvedUrls?.local?.[0] ?? 'http://localhost:4173/crypto-lab-hybrid-wire/';
  console.log(`Preview server: ${BASE}`);
  let exitCode = 0;

  try {
    const browser = await chromium.launch();
    const results = [];

    // Audit both themes — light mode changes every foreground/background pair.
    await sweepDesktop(browser, BASE, 'dark', results);
    await sweepDesktop(browser, BASE, 'light', results);

    // ---- Mobile pass (375x667, iPhone-ish) ----
    console.log('\nMobile viewport (375x667):');
    const mobile = await browser.newContext({
      viewport: { width: 375, height: 667 },
      deviceScaleFactor: 2,
      isMobile: true,
      hasTouch: true,
    });
    const mpage = await mobile.newPage();
    await mpage.goto(BASE, { waitUntil: 'networkidle' });
    await mpage.waitForSelector('.stepper', { timeout: 15000 });

    // Horizontal overflow check across every tab.
    const tabs = ['handshake', 'wires', 'threat', 'deployed', 'why'];
    let overflowFound = false;
    for (const tab of tabs) {
      await mpage.click(`#tab-${tab}`);
      await mpage.waitForTimeout(150);
      const overflow = await mpage.evaluate(() => ({
        scrollWidth: document.documentElement.scrollWidth,
        clientWidth: document.documentElement.clientWidth,
      }));
      const overflows = overflow.scrollWidth > overflow.clientWidth + 1;
      if (overflows) overflowFound = true;
      console.log(
        `  [${overflows ? 'FAIL' : 'pass'}] ${tab} — content ${overflow.scrollWidth}px vs viewport ${overflow.clientWidth}px`,
      );
    }
    if (overflowFound) exitCode = 1;

    await mpage.click('#tab-threat');
    await mpage.waitForSelector('.resilience-card');
    await scan(mpage, 'Mobile — Threat tab', results);

    await mobile.close();
    await browser.close();

    // ---- Summary ----
    const allSerious = results.flatMap((r) =>
      r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical'),
    );
    const totalViolations = results.reduce((n, r) => n + r.violations.length, 0);

    console.log('\n──────── SUMMARY ────────');
    console.log(`States scanned with axe-core: ${results.length}`);
    console.log(`Total WCAG 2.0/2.1 A & AA violations: ${totalViolations}`);
    console.log(`Serious/critical violations: ${allSerious.length}`);
    console.log(`Mobile horizontal overflow: ${overflowFound ? 'YES' : 'none'}`);

    if (allSerious.length || overflowFound) {
      console.log('\nResult: NOT clean — see FAIL lines above.');
      exitCode = 1;
    } else if (totalViolations) {
      console.log('\nResult: No serious/critical issues; minor/needs-review items only.');
    } else {
      console.log('\nResult: CLEAN — zero WCAG A/AA violations, no mobile overflow.');
    }
  } catch (err) {
    console.error('Audit error:', err);
    exitCode = 1;
  } finally {
    await server.close();
  }

  process.exit(exitCode);
}

main();
