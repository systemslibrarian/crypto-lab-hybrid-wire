import { expect, test, type Page, type Locator } from '@playwright/test';

/**
 * Threat-model regression gate.
 *
 * The resilience verdict used to be `evaluateResilience(x25519Broken,
 * mlkemBroken)` — a truth table over the two toggles. Nothing was attempted, so
 * the page asserted "the session is still safe" without its own code ever
 * testing that.
 *
 * The verdict is now produced by running the attack: the handshake encrypts one
 * record under the live session key, breaking a wire hands the attacker that
 * wire's real 32-byte secret, and the attacker runs the real HKDF combiner over
 * it plus a guess for whatever is hidden and tries to open the record. `level`
 * is decided by whether the record opened.
 *
 * The negative case is asserted too: with both wires broken the reconstruction
 * must genuinely succeed and the recovered plaintext must appear on the page.
 */

const PLAINTEXT = 'hybrid-wire session record';

const verdict = (page: Page): Locator => page.locator('#resilience-verdict');
const measurement = (page: Page): Locator => page.locator('#resilience-measurement');

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab-threat').click();
  // The verdict only appears once the handshake has produced a real key.
  await expect(verdict(page)).toHaveClass(/protected/);
});

test('both wires intact: the attack runs and fails', async ({ page }) => {
  await expect(verdict(page)).toContainText('Session protected');
  await expect(verdict(page)).toContainText('none of the keys they produced opened the intercepted record');
  await expect(measurement(page)).toContainText('0 opened the record');
  await expect(measurement(page)).toContainText('derivations');
  await expect(verdict(page)).not.toContainText(PLAINTEXT);
});

test('X25519 broken: the verdict comes from a failed decryption, not the toggle', async ({
  page,
}) => {
  await page.locator('#break-x25519').click();
  await expect(verdict(page)).toHaveClass(/degraded/);
  await expect(verdict(page)).toContainText('Session still safe');
  await expect(verdict(page)).toContainText('the key that came out did not open the intercepted record');
  await expect(measurement(page)).toContainText('0 opened the record');
});

test('ML-KEM broken: the classical half carries it, again by measurement', async ({ page }) => {
  await page.locator('#break-mlkem').click();
  await expect(verdict(page)).toHaveClass(/degraded/);
  await expect(verdict(page)).toContainText('ML-KEM-768 fell');
  await expect(measurement(page)).toContainText('0 opened the record');
});

// The negative verdict. The page can only print this plaintext if the
// attacker's derived key actually opened the AES-256-GCM record.
test('both wires broken: the reconstruction SUCCEEDS and the plaintext is shown', async ({
  page,
}) => {
  await page.locator('#break-x25519').click();
  await page.locator('#break-mlkem').click();
  await expect(verdict(page)).toHaveClass(/compromised/);
  await expect(verdict(page)).toContainText('Session compromised');
  await expect(verdict(page)).toContainText(PLAINTEXT);
  await expect(measurement(page)).toContainText('1 derivation · record decrypted · key matched 32/32 bytes');
});

test('un-breaking a wire re-runs the attack rather than reusing the verdict', async ({ page }) => {
  await page.locator('#break-x25519').click();
  await page.locator('#break-mlkem').click();
  await expect(verdict(page)).toHaveClass(/compromised/);
  await page.locator('#break-mlkem').click();
  await expect(verdict(page)).toHaveClass(/degraded/);
  await expect(verdict(page)).not.toContainText(PLAINTEXT);
  await expect(measurement(page)).toContainText('0 opened the record');
  await page.locator('#break-x25519').click();
  await expect(verdict(page)).toHaveClass(/protected/);
});

test('the toggles keep focus so the explorer stays keyboard-usable', async ({ page }) => {
  await page.locator('#break-x25519').focus();
  await page.keyboard.press('Enter');
  await expect(verdict(page)).toHaveClass(/degraded/);
  await expect(page.locator('#break-x25519')).toBeFocused();
});
