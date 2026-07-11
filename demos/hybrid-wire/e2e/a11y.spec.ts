import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate. Scans the fully-expanded page in both themes.
 *
 * This SPA has no <details>: sections are swapped via a tablist. To give axe
 * every rendered surface we walk all five tabs, drive the live handshake to
 * step 6 (which reveals the combiner/match card, the secure-chat form with its
 * styled <select>, and the message list), and toggle the resilience explorer
 * so the "broken wire" verdict states render too.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeAnimations(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;
      opacity:1!important;
    }`,
  });
}

// Advance the live handshake to its final step so every conditional surface
// (match card, HKDF combiner, secure-chat form + <select>, messages) mounts.
async function completeHandshake(page: Page): Promise<void> {
  const next = page.locator('#next-step');
  // The demo boots asynchronously; wait for the stepper controls first.
  await next.waitFor({ state: 'visible', timeout: 15000 });
  for (let i = 0; i < 6; i += 1) {
    if (await next.isDisabled()) break;
    await next.click();
  }
  // Sending a message renders a message card (incl. Decrypt button + status pill).
  const messageInput = page.locator('#message-input');
  if (await messageInput.count()) {
    await messageInput.fill('hybrid handshake authenticated message');
    await page.locator('#send-button').click();
    const decrypt = page.locator('.decrypt-button').first();
    if (await decrypt.count()) await decrypt.click();
  }
}

// Visit every tab panel, revealing all content the tablist swaps in.
async function revealAllTabs(page: Page, scan: (label: string) => Promise<void>): Promise<void> {
  const tabIds = ['handshake', 'wires', 'threat', 'deployed', 'why'];
  for (const id of tabIds) {
    await page.locator(`#tab-${id}`).click();
    await page.locator(`#tab-panel-${id}`).waitFor({ state: 'visible' });
    if (id === 'threat') {
      // Toggle both resilience wires so degraded + compromised verdicts render.
      await page.locator('#break-x25519').click();
      await scan('threat: X25519 broken');
      await page.locator('#break-mlkem').click();
      await scan('threat: both wires broken');
      await page.locator('#break-x25519').click();
      await page.locator('#break-mlkem').click();
    }
    await neutralizeAnimations(page);
    await scan(`tab: ${id}`);
  }
}

async function runScan(page: Page): Promise<void> {
  const makeScanner = () => async (label: string) => {
    const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
    const summary = results.violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      help: v.help,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    }));
    expect(summary, `axe violations at [${label}]`).toEqual([]);
  };
  const scan = makeScanner();

  await completeHandshake(page);
  await neutralizeAnimations(page);
  await scan('handshake complete (step 6, chat + combiner)');
  await revealAllTabs(page, scan);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await runScan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await runScan(page);
});
