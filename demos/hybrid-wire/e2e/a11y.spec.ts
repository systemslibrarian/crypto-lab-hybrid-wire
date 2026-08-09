import { expect, test } from '@playwright/test';
import { boot, driveAllStates, NARROW, reportCollected, watchPageErrors } from './gate';

/**
 * WCAG A/AA regression gate. Deploys are already gated on the vitest suite and
 * on `resilience.spec.ts`; this gates them on accessibility the same way.
 *
 * The lab is driven along everything it teaches: the arrival state after the
 * async handshake boot, with Prev disabled and neither wire card mounted; both
 * skip links focused; each of the six handshake steps as it lands, plus a step
 * BACK, which unmounts the whole outcome block again; the secure chat's
 * empty-input notice, a message pending, the same message authenticated, the
 * other sender, the tampered session and the decrypt it rejects, and a long
 * unbroken token echoed back into prose; all five tabs, only one of which
 * exists in the DOM at a time; the KEM disclosure opened through its summary;
 * the benchmark; all four combinations of the two resilience switches,
 * including both-broken, which genuinely recovers the intercepted record; and
 * the reset. Every one of those states is scanned, in both themes, at desktop
 * and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page — the gate this
 * replaces pushed `opacity: 1 !important` at every element before every scan,
 * which fabricates contrast results — why the lab's defaults are asserted
 * rather than assumed, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });
}
