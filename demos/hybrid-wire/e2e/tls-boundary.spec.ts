import { expect, test } from '@playwright/test';

test('the rendered combiner distinguishes this exchange from the final TLS group', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#next-step')).toBeEnabled();
  for (let step = 1; step < 6; step += 1) {
    await page.locator('#next-step').click();
  }

  const result = page.locator('.match-card');
  await expect(result).toContainText('Teaching construction, not TLS X25519MLKEM768');
  await expect(result).toContainText('X25519 secret ‖ ML-KEM secret');
  await expect(result).toContainText('ML-KEM secret ‖ X25519 secret');
  await expect(result.getByRole('link', { name: 'RFC 10024 §4.3 (August 2026)' }))
    .toHaveAttribute('href', 'https://www.rfc-editor.org/rfc/rfc10024.html#section-4.3');

  await page.locator('#tab-wires').click();
  const wires = page.locator('#tab-panel-wires');
  await expect(wires).toContainText('not wire-compatible with TLS');
  await expect(wires.getByRole('link', { name: 'RFC 9954 TLS hybrid framework (July 2026)' }))
    .toHaveAttribute('href', 'https://www.rfc-editor.org/rfc/rfc9954.html#section-3');
  await expect(wires.locator('.formula')).toContainText('ikm = x25519_secret || mlkem_secret');
});
