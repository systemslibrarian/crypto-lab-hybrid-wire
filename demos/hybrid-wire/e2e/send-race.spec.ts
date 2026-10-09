import { expect, test, type Page } from '@playwright/test';

async function chat(page: Page) {
  await page.goto('.');
  await expect(page.locator('#reset-handshake')).toBeVisible();
  for (let i = 0; i < 5; i++) await page.locator('#next-step').click();
  await expect(page.locator('#message-input')).toBeVisible();
}

async function holdEncryption(page: Page) {
  await page.evaluate(() => {
    const original = crypto.subtle.encrypt.bind(crypto.subtle);
    const pending: Array<() => void> = [];
    const fixture = { entered: 0, release() { pending.splice(0).forEach(resolve => resolve()); } };
    Object.assign(window, { sendRaceFixture: fixture });
    crypto.subtle.encrypt = async (...args: Parameters<SubtleCrypto['encrypt']>) => {
      fixture.entered++;
      await new Promise<void>(resolve => pending.push(resolve));
      return original(...args);
    };
  });
}

async function release(page: Page) {
  await page.evaluate(() => (window as unknown as { sendRaceFixture: { release(): void } }).sendRaceFixture.release());
}

for (const width of [1366, 390]) {
  test(`overlapping sends reserve distinct numbers and real GCM IVs at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await chat(page);
    await holdEncryption(page);
    // Dispatch both actual handlers before either real WebCrypto operation
    // completes. This is a controlled interleaving, not a double-click claim.
    await page.evaluate(() => {
      const input = document.querySelector<HTMLInputElement>('#message-input')!;
      const button = document.querySelector<HTMLButtonElement>('#send-button')!;
      input.value = 'attack at dawn'; button.click();
      input.value = 'attack at dusk'; button.click();
    });
    await page.waitForFunction(() => (window as unknown as { sendRaceFixture: { entered: number } }).sendRaceFixture.entered === 2);
    await release(page);
    await expect(page.locator('.message-card')).toHaveCount(2);
    const texts = await page.locator('.message-card').allTextContents();
    expect(texts.some(t => t.includes('Message number: 1'))).toBe(true);
    expect(texts.some(t => t.includes('Message number: 2'))).toBe(true);
    const ivs = await page.locator('.message-card').evaluateAll(cards => cards.map(card =>
      [...card.querySelectorAll('p')].find(p => p.textContent?.startsWith('IV:'))!.querySelector('code')!.textContent));
    expect(new Set(ivs).size).toBe(2);
    for (let i = 0; i < 2; i++) await page.locator('.decrypt-button').nth(i).click();
    await expect(page.locator('.status-authenticated')).toHaveCount(2);
    expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
  });
}

test('a failed encryption burns its reserved number', async ({ page }) => {
  await chat(page);
  await page.evaluate(() => {
    const original = crypto.subtle.encrypt.bind(crypto.subtle);
    let first = true;
    crypto.subtle.encrypt = async (...args: Parameters<SubtleCrypto['encrypt']>) => {
      if (first) { first = false; throw new Error('Controlled encryption failure'); }
      return original(...args);
    };
  });
  await page.locator('#message-input').fill('failed record');
  await page.locator('#send-button').click();
  await expect(page.locator('.notice-card')).toContainText('Controlled encryption failure');
  await page.locator('#message-input').fill('next record');
  await page.locator('#send-button').click();
  await expect(page.locator('.message-card')).toContainText('Message number: 2');
  await page.locator('.decrypt-button').click();
  await expect(page.locator('.status-authenticated')).toHaveCount(1);
});

test('reset discards an old in-flight send before showing a fresh session', async ({ page }) => {
  await chat(page);
  await holdEncryption(page);
  await page.locator('#message-input').fill('old session message');
  await page.locator('#send-button').click();
  await page.waitForFunction(() => (window as unknown as { sendRaceFixture: { entered: number } }).sendRaceFixture.entered === 1);
  await page.locator('#reset-handshake').click();
  // The new handshake also creates an intercepted AES record; let both real
  // operations complete after reset has invalidated the old session.
  await page.waitForFunction(() => (window as unknown as { sendRaceFixture: { entered: number } }).sendRaceFixture.entered === 2);
  await release(page);
  await expect(page.locator('#reset-handshake')).toBeVisible();
  for (let i = 0; i < 5; i++) await page.locator('#next-step').click();
  await expect(page.locator('#message-input')).toBeVisible();
  await expect(page.locator('.message-card')).toHaveCount(0);
  await expect(page.locator('body')).not.toContainText('old session message');
});
