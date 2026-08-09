import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures } from './nontext';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, each one a correction of the gate this
 * replaces:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. `neutralizeAnimations()`
 *     pushed `animation-duration:0s!important; transition-duration:0s!important;
 *     opacity:1!important` through `addStyleTag` before every scan. The first
 *     two BYPASSED this stylesheet's own `prefers-reduced-motion` block instead
 *     of exercising it. The third is worse: `opacity: 1 !important` on
 *     `*,*::before,*::after` FABRICATES contrast results. It repainted
 *     `.cl-hero-sub` (`.85`) and `.wire-broken` (`.4`) at full strength, so the
 *     one thing on this page that is deliberately dimmed — a wire the reader has
 *     just declared broken — was measured in a rendering nobody sees. `boot`
 *     asks for reduced motion and ASSERTS the preference took effect instead.
 *
 *  2. IT SCANNED ONE VIEWPORT AND NEVER MEASURED CONTRAST HONESTLY. Everything
 *     ran at the Playwright default width, so the 1.4.10 column was never
 *     exercised at all, and `violations`-only means every ratio over a
 *     `color-mix()` or a translucent surface — which on this page is every
 *     surface, since `--surface` is `rgba(8,15,31,0.88)` and `--surface-raised`
 *     is `rgba(15,23,42,0.92)` — went to axe's `incomplete` bucket and was
 *     silently dropped. This drive runs {dark, light} x {1280, 380}.
 *
 *  3. IT DROVE THE LAB, THEN THREW MOST OF IT AWAY. `completeHandshake()` ran
 *     all six steps and scanned once at the end, so steps 1-5 — where the wire
 *     cards mount one at a time and the outcome is a "step N of 6" hint — were
 *     never scanned. Sending a message and decrypting it happened before the
 *     first scan too. Here every step is scanned as it lands.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. Three things on this
 *     page are invisible to a violations-only assertion in particular: the
 *     translucent surfaces above; SC 1.4.11, which has no axe rule and is where
 *     this lab's real defects were (the resilience switches); and
 *     `aria-controls` pointing at an id that does not exist, which axe files
 *     under `incomplete` and never under `violations`.
 *
 *  5. IT HAD NO REFLOW OR KEYBOARD-SCROLLER ORACLE, and this page needs both.
 *     The message input is echoed into a `<p>` as plaintext, the ciphertext and
 *     IV are unbroken base64 runs, and three `<pre>` blocks are `overflow-x:
 *     auto`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 *
 * Load-bearing here: `.wire-flow` runs `wirePulse 1.2s linear infinite` on the
 * SVG handshake diagram for as long as the handshake tab is open. Reduced
 * motion cancels it (`animation: none`), which is the only reason this settles
 * at all — and asserting that in `boot` is what keeps this from hanging for
 * 20 seconds if the reduced-motion block is ever edited.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page cannot currently be in that shape, and the assertion is what makes
 * that a measurement rather than a reading: the one `@keyframes` here is
 * `wirePulse`, which animates `stroke-dashoffset` and never `opacity`, and the
 * reduced-motion block only cancels animations and transitions. The check runs
 * in every state regardless, because those are properties of the current
 * stylesheet rather than of the page.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. This lab re-renders its entire body from a template string on
 * every state change, so a throw halfway through leaves the PREVIOUS state on
 * screen and a gate that scans it reports green for a page that is broken.
 * Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * The lab's own `<header class="cl-hero">` renders inside `<main
 * id="main-content">`, which scopes it out of the banner role by nesting alone
 * — `index.html`'s `dedupeBanner()` never has to touch it. Asserting the
 * OUTCOME rather than either mechanism means a change to the nesting is caught
 * as well as a change to the script.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/** The five tab ids, in the order the tablist renders them. */
export const TAB_IDS = ['handshake', 'wires', 'threat', 'deployed', 'why'] as const;

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which also pins down a real failure mode: `index.html`'s anti-flash script
 * reads `localStorage.getItem('theme')` and `applyTheme()` in `main.ts` writes
 * `localStorage.setItem('theme', …)`. If those keys drift apart the theme
 * silently stops persisting, and this boot fails on `data-theme` rather than
 * quietly scanning dark twice.
 *
 * The defaults are asserted at length because this lab boots ASYNCHRONOUSLY —
 * `initializeHandshake()` paints a loading card, runs a real ML-KEM keygen,
 * encapsulation and decapsulation, and only then renders the stepper. Every
 * one of the assertions below is therefore also the wait that makes the first
 * scan land on the finished page rather than on the loading card.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // ── The async boot has finished ─────────────────────────────────────────
  await expect(page.locator('#next-step')).toBeVisible();
  await expect(page.locator('.loading-card')).toHaveCount(0);

  // ── Every shipped default ───────────────────────────────────────────────
  // The handshake tab is selected, and it is the ONLY tab whose panel exists:
  // `render()` emits one `<div id="tab-panel-<active>">`, so the other four tab
  // buttons point `aria-controls` at ids that are not in the document.
  await expect(page.locator('#tab-handshake')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('[role="tabpanel"]')).toHaveCount(1);
  await expect(page.locator('[role="tab"]')).toHaveCount(TAB_IDS.length);

  // Step 1 of 6: Prev is disabled, the outcome is still a hint, and neither
  // wire card has mounted.
  await expect(page.locator('#prev-step')).toBeDisabled();
  await expect(page.locator('#next-step')).toBeEnabled();
  await expect(page.locator('.step-hint')).toContainText('step 1 of 6');
  await expect(page.locator('.wire-card')).toHaveCount(0);
  await expect(page.locator('.match-card')).toHaveCount(0);
  await expect(page.locator('#message-input')).toHaveCount(0);

  // The lab's own theme toggle stays in the DOM so its theme JS keeps working,
  // and the shared header's CSS hides it. If that ever stopped being true there
  // would be two visible toggles disagreeing about the current theme.
  await expect(page.locator('#theme-toggle')).toBeHidden();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this page is a
 * plausible offender: the message input is echoed back into a `<p>` verbatim,
 * the ciphertext and IV are unbroken base64 runs, `#app` is sized from `100vw`,
 * and the chat form is a three-column grid that only collapses under 760px.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    // `body { overflow-x: hidden }` propagates to the viewport when `html`
    // leaves `overflow` at `visible`, so `scrollWidth` stays equal to
    // `clientWidth` even when content is CUT OFF — a worse 1.4.10 outcome than
    // a scrollbar, and invisible to the standard check. This lab does NOT have
    // that rule today; the test is kept because adding one is the usual way a
    // reflow failure gets "fixed", and this oracle has to survive that.
    const clippedByViewport = ['hidden', 'clip'].includes(
      getComputedStyle(document.body).overflowX
    );
    if (!clippedByViewport && doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. The
    // threat matrix has a huge bounding rect but is clipped by `.table-card`'s
    // own `overflow-x: auto` and contributes nothing to the document's scroll
    // width — naming it sends you off fixing the wrong element, which has cost
    // a run elsewhere in this fleet.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      // Stop BEFORE <body>. When `body { overflow-x: hidden }` propagates to the
      // viewport, body itself answers "hidden" to this walk — so every element
      // on the page reads as clipped, `escaping` is always empty, and the oracle
      // reports nothing at all. That is the failure this whole check exists to
      // avoid: a viewport-level clip is the DEFECT, not a legitimate scroller.
      // Only a genuine scrolling container INSIDE the page excuses an overflow.
      while (n && n !== doc && n !== document.body) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Anything inside a real scroller is reachable and is not a finding; only
    // what escapes the viewport with no way back is. With the viewport clipping,
    // falling back to the widest CLIPPED element would report a decoy forever.
    const escaping = over.filter((x) => !clipped(x.el));
    if (!escaping.length) return null;
    const widest = escaping[0]!;
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest:
        `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
        `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
        ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`,
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * Four containers on this page can scroll: `.table-card` (the threat matrix,
 * which gets `overflow-x: auto` only under 760px) and the two `.kem-mini`
 * `<pre>` diagrams, all three of which already carry `role="region"`,
 * `tabindex="0"` and a label — and `.formula`, the HKDF snippet, which did not.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * SC 1.4.11 and generated content live in `nontext.ts`.
 *
 * The repo already had a 1.4.11 check — `e2e/border-contrast.spec.ts` — and it
 * is the shape this sweep keeps finding: it measures `.input` and nothing else,
 * which is exactly one of the two selectors `--border` was correctly applied to.
 * A check pointed only at the place a rule is already kept cannot fail. The
 * elements that were never measured are the two `role="switch"` resilience
 * toggles, whose track and thumb are drawn from hardcoded `rgba()` values that
 * appear in no token and in no theme block, and which turned out to be the
 * lab's real 1.4.11 defect. That spec is replaced by this one rather than kept
 * alongside it, so there is one answer to "is a control delineated" instead of
 * two that disagree.
 *
 * One exclusion is applied here rather than in `nontext.ts`: the shared top bar.
 * It is not this lab's to change — every repo in the fleet carries a copy — and
 * its `.cl-btn` boundary (`color-mix(in srgb, var(--accent) 38%, transparent)`
 * over `#0b1512`) measures under 3:1 here as it does everywhere. That is
 * reported upward as a fleet-wide observation rather than patched in one repo,
 * and it is written down so the exclusion is a decision and not an oversight.
 */
const SHARED_HEADER_PREFIXES = ['a.cl-skip-link', 'button#cl-theme-toggle', 'a.cl-btn'];

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label);
  try {
    await expectScrollersReachable(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label);
  try {
    await expectNoHorizontalOverflow(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically — which matters more here than in most labs, since every
 *    surface on this page is a translucent `rgba()` over a gradient canvas.
 *    Everything else in that bucket is a real result axe simply could not
 *    finish — including `aria-valid-attr-value`, which is where an
 *    `aria-controls` pointing at an absent id lands, and `aria-prohibited-attr`,
 *    which is where an `aria-label` on a role-less element hides. Neither ever
 *    reaches the violations array.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast for controls, and the ink of every `::before`/`::after`
 *    — SC 1.4.11 and 1.4.3 for generated content, neither of which axe has any
 *    rule for and neither of which the element walk in `contrast.ts` can reach.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  const nonText = (await auditNonText(page)).filter(
    (f) => !SHARED_HEADER_PREFIXES.some((p) => f.selector.startsWith(p))
  );
  softExpect(
    Array.from(new Set(formatNonTextFailures(nonText))),
    `non-text contrast (SC 1.4.11) and generated content in state: ${label}`,
    []
  );

  await expectScrollersReachableSoft(page, label);
  await expectNoHorizontalOverflowSoft(page, label);
}

// ── The drive ───────────────────────────────────────────────────────────────

/** Focus a skip link so its "visually hidden until focused" state is measured. */
async function focusSkipLink(page: Page, selector: string): Promise<void> {
  await page.locator(selector).focus();
  await expect(page.locator(selector)).toBeFocused();
}

/**
 * Switch tabs by clicking the tab button, and assert the swap landed.
 *
 * `render()` replaces the whole `#app` subtree, so the panel that existed a
 * moment ago is a detached node; asserting on the NEW panel's id is what makes
 * the wait real rather than a race.
 */
async function openTab(page: Page, id: (typeof TAB_IDS)[number]): Promise<void> {
  await page.locator(`#tab-${id}`).click();
  await expect(page.locator(`#tab-panel-${id}`)).toBeVisible();
  await expect(page.locator(`#tab-${id}`)).toHaveAttribute('aria-selected', 'true');
}

/** Advance the handshake one step and assert the step counter moved. */
async function nextStep(page: Page, to: number): Promise<void> {
  await page.locator('#next-step').click();
  if (to < 6) {
    await expect(page.locator('.step-hint')).toContainText(`step ${to} of 6`);
  } else {
    await expect(page.locator('.match-card')).toBeVisible();
  }
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Shaped by the two axes this lab actually has: a six-step handshake whose
 * cards mount progressively (the blue wire card at step 2, the purple at step 3,
 * the shared secrets at steps 4 and 5, and the whole outcome — metrics, HKDF
 * combiner, secure chat — only at step 6), and a five-tab mode fork in which
 * only the ACTIVE panel exists in the DOM at all. Every step, every tab, every
 * message verification state, and all four combinations of the two resilience
 * switches are scanned.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const s = (label: string): Promise<void> => scan(page, `${theme} / ${label}`);

  await s('first paint (handshake step 1)');

  // Both "visually hidden until focused" skip links, in their focused state.
  await focusSkipLink(page, '.cl-skip-link');
  await s('shared skip link focused');
  await focusSkipLink(page, '.skip-link');
  await s('lab skip link focused');

  // ── The six handshake steps, scanned as each one lands ──────────────────
  for (let step = 2; step <= 6; step += 1) {
    await nextStep(page, step);
    await s(`handshake step ${step}`);
  }

  // Stepping BACK is a real state and a different render: the outcome block
  // disappears again and the chat unmounts with it.
  await page.locator('#prev-step').click();
  await expect(page.locator('.step-hint')).toContainText('step 5 of 6');
  await expect(page.locator('#message-input')).toHaveCount(0);
  await s('handshake stepped back to 5');
  await nextStep(page, 6);

  // ── Secure chat: the empty-input error, then every verification state ────
  await expect(page.locator('#sender-select')).toHaveValue('alice');
  await page.locator('#send-button').click();
  await expect(page.locator('.notice-card')).toContainText('Enter a message before sending');
  await s('chat: empty-message notice');

  await page.locator('#message-input').fill('hybrid handshake authenticated message');
  await page.locator('#send-button').click();
  await expect(page.locator('.message-card')).toHaveCount(1);
  await expect(page.locator('.status-pill')).toHaveText('pending');
  await s('chat: message sent (pending)');

  await page.locator('.decrypt-button').first().click();
  await expect(page.locator('.status-pill').first()).toHaveText('authenticated');
  await s('chat: message decrypted (authenticated)');

  // The other branch of the sender fork.
  await page.locator('#sender-select').selectOption('bob');
  await page.locator('#message-input').fill('bob replies over the same session key');
  await page.locator('#send-button').click();
  await expect(page.locator('.message-card')).toHaveCount(2);
  await s('chat: bob sends');

  // Tamper flips a byte of the ML-KEM ciphertext and re-derives BOB's key only,
  // so the decrypt that must now fail is one whose RECIPIENT is Bob — that is,
  // one Alice sent. Re-decrypting Bob's own message would still authenticate,
  // because Alice's key never moved and the message was sealed before the
  // tamper; a drive that clicked the newest card (messages are unshifted, so
  // `.first()` is Bob's) would quietly scan a second "authenticated" state and
  // report it as the rejection. Assert the negative outcome, on the right card.
  await page.locator('#tamper-button').click();
  await expect(page.locator('.notice-card')).toContainText('modified before Bob decapsulated');
  await s('chat: session tampered');

  await page.locator('.message-card.alice .decrypt-button').click();
  await expect(page.locator('.message-card.alice .status-pill')).toHaveText('tampered');
  await s('chat: decrypt rejected (tampered)');

  // A long unbroken token typed into the message input is echoed back verbatim
  // into a `<p>` — the reflow case that only exists in a state built by hand.
  await page.locator('#message-input').fill('a'.repeat(90));
  await page.locator('#send-button').click();
  await expect(page.locator('.message-card')).toHaveCount(3);
  await s('chat: long unbroken message echoed into prose');

  // ── Tab: two wires ──────────────────────────────────────────────────────
  await openTab(page, 'wires');
  await s('tab: wires');

  const aside = page.locator('details.kem-aside');
  await expect(aside).not.toHaveAttribute('open', '');
  await aside.locator('summary').click();
  await expect(aside).toHaveAttribute('open', '');
  await s('tab: wires / KEM aside open');

  await page.locator('#run-benchmark').click();
  await expect(page.locator('.notice-card')).toContainText('Benchmark complete.', {
    timeout: 120_000,
  });
  await expect(page.locator('.benchmark-card').first()).toBeVisible();
  await s('tab: wires / benchmark complete');

  // ── Tab: threat model — all four switch combinations ────────────────────
  await openTab(page, 'threat');
  await expect(page.locator('#break-x25519')).toHaveAttribute('aria-checked', 'false');
  await expect(page.locator('#break-mlkem')).toHaveAttribute('aria-checked', 'false');
  await expect(page.locator('#resilience-verdict')).toHaveClass(/protected/);
  await s('tab: threat (both wires intact)');

  await page.locator('#break-x25519').click();
  await expect(page.locator('#break-x25519')).toHaveAttribute('aria-checked', 'true');
  await expect(page.locator('#resilience-verdict')).toHaveClass(/degraded/);
  await s('tab: threat / X25519 broken');

  await page.locator('#break-mlkem').click();
  await expect(page.locator('#break-mlkem')).toHaveAttribute('aria-checked', 'true');
  // Both wires broken is the only combination that genuinely recovers the
  // record, and it is the one the exhibit exists for.
  await expect(page.locator('#resilience-verdict')).toHaveClass(/compromised/);
  await s('tab: threat / both wires broken (compromised)');

  await page.locator('#break-x25519').click();
  await expect(page.locator('#resilience-verdict')).toHaveClass(/degraded/);
  await s('tab: threat / ML-KEM broken only');

  await page.locator('#break-mlkem').click();
  await expect(page.locator('#resilience-verdict')).toHaveClass(/protected/);
  await s('tab: threat / switches reset');

  // ── The two prose tabs ──────────────────────────────────────────────────
  await openTab(page, 'deployed');
  await s('tab: deployed');
  await openTab(page, 'why');
  await s('tab: why');

  // ── Reset: this lab re-runs the whole handshake from scratch ────────────
  await openTab(page, 'handshake');
  await s('tab: handshake (returned at step 6)');
  await page.locator('#reset-handshake').click();
  await expect(page.locator('.step-hint')).toContainText('step 1 of 6');
  await expect(page.locator('.message-card')).toHaveCount(0);
  await expect(page.locator('#prev-step')).toBeDisabled();
  await s('handshake reset (back to step 1, chat cleared)');
}
