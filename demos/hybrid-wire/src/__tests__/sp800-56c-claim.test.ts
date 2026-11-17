/**
 * What the "Why hybrid?" tab attributes to NIST SP 800-56C.
 *
 * The card used to read "NIST SP 800-56C encourages robust combiners." It does
 * not. SP 800-56C Rev. 2 §2 says it "permits the use of a 'hybrid' shared
 * secret of the form Z' = Z || T, a concatenation consisting of a 'standard'
 * shared secret Z ... followed by an auxiliary shared secret T that has been
 * generated using some other method", and that its key-derivation methods
 * "will process a hybrid Z' in the same way they process a standard Z". It
 * permits rather than encourages, the word "combiner" does not occur anywhere
 * in the document, and it recommends no particular pairing of primitives.
 *
 * Read as source text (?raw) rather than through a mount: the tab's markup is
 * built by a render function the page only calls when that tab is selected.
 */
import { describe, expect, it } from 'vitest';

import source from '../main.ts?raw';

describe('the SP 800-56C attribution on the "Why hybrid?" card', () => {
  it('does not claim the document encourages combiners', () => {
    expect(source).not.toContain('SP 800-56C encourages robust combiners');
    expect(source).not.toMatch(/SP 800-56C[^<]*encourages/);
  });

  it('says what SP 800-56C Rev. 2 actually permits', () => {
    expect(source).toContain('NIST SP 800-56C Rev. 2 <em>permits</em>');
    expect(source).toContain('shared secret of the form Z′ = Z || T');
    expect(source).toContain('It permits rather than recommends, and names no pairing.');
  });
});
