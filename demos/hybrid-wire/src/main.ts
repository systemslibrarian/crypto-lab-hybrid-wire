import './styles.css';

import { runBenchmark, type BenchmarkResult } from './benchmark';
import { combineSecrets, generateHybridKeyPair, hybridDecapsulate, type HybridKeyPair } from './crypto/hybrid';
import { mlkemDecapsulate, mlkemEncapsulate } from './crypto/mlkem768';
import { evaluateResilience } from './crypto/security';
import { decryptMessage, encryptMessage, type EncryptedMessage, type HybridSession } from './crypto/session';
import { bytesEqual, fingerprint, formatMs, nowMs, shortHex, toHex, toHexSpaced } from './crypto/utils';
import { generateX25519KeyPair, x25519SharedSecret, type X25519KeyPair } from './crypto/x25519';

type TabId = 'handshake' | 'wires' | 'threat' | 'deployed' | 'why';

interface HandshakeTimeline {
  bobKeys: HybridKeyPair;
  aliceKeyPair: X25519KeyPair;
  aliceX25519Secret: Uint8Array;
  bobX25519Secret: Uint8Array;
  aliceMlkemSecret: Uint8Array;
  bobMlkemSecret: Uint8Array;
  aliceSessionKey: Uint8Array;
  bobSessionKey: Uint8Array;
  mlkemCiphertext: Uint8Array;
  stepTimes: number[];
  totalTimeMs: number;
}

interface ChatRecord {
  sender: 'alice' | 'bob';
  plaintext: string;
  encrypted: EncryptedMessage;
  verification: 'pending' | 'authenticated' | 'tampered';
  decryptedPlaintext?: string;
  recipientNote?: string;
}

interface AppState {
  activeTab: TabId;
  currentStep: number;
  loading: boolean;
  timeline: HandshakeTimeline | null;
  sessions: { alice: HybridSession; bob: HybridSession } | null;
  messages: ChatRecord[];
  messageNumber: number;
  benchmark: BenchmarkResult | null;
  benchmarkStatus: 'idle' | 'running';
  tamperedSession: boolean;
  breakX25519: boolean;
  breakMlkem: boolean;
  notice: string;
}

const tabs: Array<{ id: TabId; label: string }> = [
  { id: 'handshake', label: 'Live handshake' },
  { id: 'wires', label: 'Two wires' },
  { id: 'threat', label: 'Threat model' },
  { id: 'deployed', label: 'Deployed today' },
  { id: 'why', label: 'Why hybrid' },
];

const stepTitles = [
  'Bob generates keys',
  'Alice creates an ephemeral X25519 key pair',
  'Alice encapsulates the ML-KEM shared secret',
  'Both sides compute the X25519 shared secret',
  'Bob decapsulates the ML-KEM shared secret',
  'Both sides derive the combined session key with HKDF',
];

const stepDetails = [
  'Bob prepares the classical and post-quantum public keys he will publish to Alice.',
  'Alice creates a one-time X25519 private key so forward secrecy still applies.',
  'The purple wire carries the ML-KEM ciphertext back to Bob with a 32-byte shared secret inside.',
  'The blue wire produces the same X25519 shared secret on both sides.',
  'Bob opens the ML-KEM ciphertext and recovers the exact same 32-byte PQ secret as Alice.',
  'HKDF-SHA-256 mixes both wires into a single 32-byte AES-256-GCM session key.',
];

const threatRows = [
  ['Classical attacker today', 'Can watch traffic and record the transcript', 'Needs to break both wires', 'Session stays safe'],
  ['Harvest-now, decrypt-later adversary', 'Can store ciphertext until a future quantum computer exists', 'X25519 may weaken later, ML-KEM still protects the key', 'Session stays safe'],
  ['Hypothetical ML-KEM break', 'Finds a future attack on the PQ wire only', 'X25519 still protects the key exchange', 'Session stays safe'],
  ['Break both wires at once', 'Compromises X25519 and ML-KEM simultaneously', 'Both secrets collapse together', 'Session is compromised'],
];

const deploymentCards = [
  {
    title: 'Chrome 124+',
    scheme: 'Hybrid TLS using X25519 plus ML-KEM / Kyber transition ciphersuites',
    coverage: 'Default browser HTTPS handshakes on modern Chromium paths',
    status: 'Deployed',
  },
  {
    title: 'Cloudflare',
    scheme: 'Hybrid TLS at the edge for client and origin protection',
    coverage: 'Internet-facing traffic on Cloudflare infrastructure',
    status: 'Deployed',
  },
  {
    title: 'Signal PQXDH',
    scheme: 'X25519 plus post-quantum prekeys for secure messaging setup',
    coverage: 'Conversation bootstrapping and asynchronous messaging safety',
    status: 'Deployed',
  },
  {
    title: 'AWS s2n-tls',
    scheme: 'Hybrid TLS support for cloud workloads and service-to-service links',
    coverage: 'Production-ready TLS experimentation and rollout paths',
    status: 'Available',
  },
  {
    title: 'iCloud PQ3',
    scheme: 'Hybrid post-quantum key establishment for Apple messaging security',
    coverage: 'Apple cloud messaging protections and recovery paths',
    status: 'Deployed',
  },
  {
    title: 'OpenSSH 9.0+',
    scheme: 'sntrup761x25519-sha512 hybrid KEX example in day-to-day tooling',
    coverage: 'Secure shell sessions and server administration',
    status: 'Deployed',
  },
];

const appRoot = document.querySelector<HTMLDivElement>('#app');
if (!appRoot) {
  throw new Error('Application root element was not found.');
}

const state: AppState = {
  activeTab: 'handshake',
  currentStep: 1,
  loading: true,
  timeline: null,
  sessions: null,
  messages: [],
  messageNumber: 1,
  benchmark: null,
  benchmarkStatus: 'idle',
  tamperedSession: false,
  breakX25519: false,
  breakMlkem: false,
  notice: '',
};

type ThemeMode = 'dark' | 'light';

function getThemeMode(): ThemeMode {
  return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

function themeButtonState(theme: ThemeMode): { icon: string; label: string } {
  if (theme === 'dark') {
    return { icon: '🌙', label: 'Switch to light mode' };
  }
  return { icon: '☀️', label: 'Switch to dark mode' };
}

function applyTheme(theme: ThemeMode): void {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
  syncThemeToggleButton();
}

function syncThemeToggleButton(): void {
  const button = document.querySelector<HTMLButtonElement>('#theme-toggle');
  if (!button) {
    return;
  }

  const theme = getThemeMode();
  const nextState = themeButtonState(theme);
  button.textContent = nextState.icon;
  button.setAttribute('aria-label', nextState.label);
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function renderTabs(): string {
  return tabs
    .map(function (tab) {
      const isActive = state.activeTab === tab.id;
      const activeClass = isActive ? ' active' : '';
      return '<button class="tab-button' + activeClass + '" data-tab="' + tab.id + '" role="tab" aria-selected="' + isActive + '" aria-controls="tab-panel-' + tab.id + '" id="tab-' + tab.id + '">' + tab.label + '</button>';
    })
    .join('');
}

function renderHero(): string {
  const theme = getThemeMode();
  const toggle = themeButtonState(theme);

  // The shared top bar owns the visible theme toggle; this button stays in the
  // DOM (hidden by the shared-header CSS) so the demo's own theme JS keeps
  // working. It lives outside the hero landmark so the header structure matches
  // the fleet standard exactly.
  return [
    '<button id="theme-toggle" class="theme-toggle" type="button" aria-label="' + toggle.label + '">' + toggle.icon + '</button>',
    '<header class="cl-hero">',
    '<div class="cl-hero-main">',
    '<h1 class="cl-hero-title">Hybrid Wire</h1>',
    '<p class="cl-hero-sub">X25519 + ML-KEM-768 · HKDF combiner</p>',
    '<p class="cl-hero-desc">Step through a live hybrid handshake that runs a classical X25519 exchange alongside an ML-KEM-768 encapsulation, then mixes both secrets through HKDF into one AES-256-GCM session key.</p>',
    '</div>',
    '<aside class="cl-hero-why" aria-label="Why it matters">',
    '<span class="cl-hero-why-label">WHY IT MATTERS</span>',
    '<p class="cl-hero-why-text">A recorded handshake can be broken years later once quantum computers arrive. Binding a classical and a post-quantum secret together means an attacker must defeat both wires at once, so today’s traffic stays confidential well into the future.</p>',
    '</aside>',
    '</header>',
  ].join('');
}

function renderStepList(): string {
  return '<div class="stepper" role="list" aria-label="Handshake steps">' +
    stepTitles
      .map(function (title, index) {
        const stepNumber = index + 1;
        let stepClass = 'step-item';
        const isDone = stepNumber < state.currentStep;
        const isActive = stepNumber === state.currentStep;
        if (isDone) {
          stepClass += ' done';
        }
        if (isActive) {
          stepClass += ' active';
        }

        const ariaCurrent = isActive ? ' aria-current="step"' : '';
        const statusLabel = isDone ? 'completed' : isActive ? 'current' : 'upcoming';
        const timeLabel = state.timeline ? formatMs(state.timeline.stepTimes[index]) : 'pending';
        return [
          '<div class="' + stepClass + '" role="listitem"' + ariaCurrent + ' aria-label="Step ' + stepNumber + ': ' + title + ' (' + statusLabel + ')">',
          '<div class="step-number" aria-hidden="true">' + stepNumber + '</div>',
          '<div><div class="step-title">' + title + '</div><div class="step-detail">' + stepDetails[index] + '</div></div>',
          '<div class="step-time" aria-label="Duration: ' + timeLabel + '">' + timeLabel + '</div>',
          '</div>',
        ].join('');
      })
      .join('') +
    '</div>';
}

// Shared wire-diagram SVG. The handshake animation and the resilience explorer
// draw the same two-wire scaffold (identical geometry); only the path classes,
// aria-label, and any overlay marks differ. Keeping one source of truth means a
// geometry tweak can never drift between the two diagrams.
function renderWireSvg(options: {
  ariaLabel: string;
  blueClass: string;
  purpleClass: string;
  overlay?: string;
}): string {
  return [
    '<div class="wire-diagram">',
    '<svg viewBox="0 0 820 170" role="img" aria-label="' + options.ariaLabel + '">',
    '<text class="diagram-label" x="20" y="28" font-size="14">Bob</text>',
    '<text class="diagram-label" x="760" y="28" font-size="14">Alice</text>',
    '<path class="' + options.blueClass + '" d="M 72 55 C 240 20, 580 20, 748 55"></path>',
    '<path class="' + options.purpleClass + '" d="M 72 115 C 240 150, 580 150, 748 115"></path>',
    '<circle class="node-dot" cx="72" cy="55" r="7"></circle>',
    '<circle class="node-dot" cx="748" cy="55" r="7"></circle>',
    '<circle class="node-dot" cx="72" cy="115" r="7"></circle>',
    '<circle class="node-dot" cx="748" cy="115" r="7"></circle>',
    '<text class="diagram-label-blue" x="280" y="42" font-size="13">X25519 wire</text>',
    '<text class="diagram-label-purple" x="280" y="150" font-size="13">ML-KEM wire</text>',
    options.overlay ?? '',
    '</svg>',
    '</div>',
  ].join('');
}

// Wire coordinates (kept in sync with renderWireSvg's paths). Bob sits at x=72,
// Alice at x=748. Blue wire runs along y≈37 (control-curve apex), purple along
// y≈133. We animate a single labelled token along the wire that is *active this
// step*, in the correct direction, so the motion teaches the mechanism instead of
// decorating. Once the key is derived (step 6) the pulse stops entirely.
const WIRE = {
  bobX: 72,
  aliceX: 748,
  blueY: 34,
  purpleY: 140,
};

// Build an SVG token (rounded rect + label) that slides between two x positions.
// direction 'toAlice' moves left→right (Bob→Alice); 'toBob' moves right→left.
function wireToken(opts: {
  label: string;
  y: number;
  colorClass: string;
  direction: 'toAlice' | 'toBob';
}): string {
  const fromX = opts.direction === 'toAlice' ? WIRE.bobX : WIRE.aliceX;
  const toX = opts.direction === 'toAlice' ? WIRE.aliceX : WIRE.bobX;
  const width = 132;
  // Honour prefers-reduced-motion: freeze the token at the wire's midpoint (still
  // shows WHICH secret is on WHICH wire, just without SMIL motion).
  const reduceMotion = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
  const staticX = (fromX + toX) / 2;
  const motion = reduceMotion
    ? '<g transform="translate(' + staticX + ' 0)">'
    : [
        '<g>',
        '<animateTransform attributeName="transform" attributeType="XML" type="translate" ' +
          'from="' + fromX + ' 0" to="' + toX + ' 0" dur="2.2s" repeatCount="indefinite" />',
      ].join('');
  // y is the wire's height; we lift the chip above the line.
  return [
    '<g class="wire-token ' + opts.colorClass + '" aria-hidden="true">',
    motion,
    '<rect x="' + (-width / 2) + '" y="' + (opts.y - 14) + '" rx="8" ry="8" width="' + width + '" height="20"></rect>',
    '<text x="0" y="' + opts.y + '" text-anchor="middle" font-size="11">' + opts.label + '</text>',
    '</g>',
    '</g>',
  ].join('');
}

// Two tokens converging into a central HKDF box (step 6 reveal moment). Static —
// the pulse has stopped; this is the "both secrets slide into the combiner" beat.
function combinerTokens(): string {
  const midX = 410;
  return [
    '<g class="hkdf-box" aria-hidden="true">',
    '<rect x="' + (midX - 46) + '" y="76" rx="9" ry="9" width="92" height="30"></rect>',
    '<text x="' + midX + '" y="95" text-anchor="middle" font-size="13">HKDF</text>',
    '</g>',
    '<g class="wire-token blue settled" aria-hidden="true"><rect x="' + (midX - 149) + '" y="58" rx="7" width="118" height="18"></rect><text x="' + (midX - 90) + '" y="71" text-anchor="middle" font-size="10">X25519 secret</text></g>',
    '<g class="wire-token purple settled" aria-hidden="true"><rect x="' + (midX + 31) + '" y="106" rx="7" width="118" height="18"></rect><text x="' + (midX + 90) + '" y="119" text-anchor="middle" font-size="10">PQ secret</text></g>',
    '<path class="hkdf-feed" d="M ' + (midX - 31) + ' 67 L ' + (midX - 12) + ' 82" aria-hidden="true"></path>',
    '<path class="hkdf-feed" d="M ' + (midX + 31) + ' 115 L ' + (midX + 12) + ' 100" aria-hidden="true"></path>',
  ].join('');
}

// Choose which token(s) animate for the current step, and describe it for AT.
function renderWireDiagram(): string {
  const step = state.currentStep;
  let overlay = '';
  let motionNote = '';
  // Only the wire in play this step pulses; the other rests.
  let bluePulse = false;
  let purplePulse = false;

  if (step === 3) {
    // Alice encapsulates → ML-KEM ciphertext travels back to Bob (purple, toBob).
    overlay = wireToken({ label: 'ML-KEM ciphertext →', y: WIRE.purpleY, colorClass: 'purple', direction: 'toBob' });
    purplePulse = true;
    motionNote = 'A labelled ML-KEM ciphertext token travels along the purple wire from Alice toward Bob.';
  } else if (step === 4) {
    // Both sides derive the X25519 secret (blue wire lights up, token toAlice).
    overlay = wireToken({ label: 'X25519 secret', y: WIRE.blueY, colorClass: 'blue', direction: 'toAlice' });
    bluePulse = true;
    motionNote = 'A labelled X25519 secret token moves along the blue wire between Bob and Alice.';
  } else if (step === 5) {
    // Bob decapsulates → recovers the PQ secret (purple wire, settling at Bob).
    overlay = wireToken({ label: 'PQ secret recovered', y: WIRE.purpleY, colorClass: 'purple', direction: 'toAlice' });
    purplePulse = true;
    motionNote = 'A labelled PQ secret token moves along the purple wire as Bob decapsulates it.';
  } else if (step >= 6) {
    // Key derived: pulse stops, both tokens slide into the HKDF box.
    overlay = combinerTokens();
    motionNote = 'The X25519 secret and the PQ secret both feed into the central HKDF box; the wires are no longer pulsing because the session key is derived.';
  } else {
    motionNote = 'The two wires are idle; advance the handshake to see each secret move.';
  }

  const blueClass = 'wire-path wire-blue' + (bluePulse ? ' wire-flow' : '');
  const purpleClass = 'wire-path wire-purple' + (purplePulse ? ' wire-flow' : '');

  return [
    renderWireSvg({
      ariaLabel: 'Hybrid wire diagram: X25519 blue wire and ML-KEM purple wire between Bob and Alice. ' + motionNote,
      blueClass,
      purpleClass,
      overlay,
    }),
    '<p class="wire-motion-note">' + escapeHtml(motionNote) + '</p>',
  ].join('');
}

function renderMatchCard(): string {
  if (!state.timeline || state.currentStep < 6) {
    return '';
  }

  const keysMatch = bytesEqual(state.timeline.aliceSessionKey, state.timeline.bobSessionKey);
  const status = keysMatch ? '✅ Session keys match' : '⚠️ Session keys diverged';

  return [
    '<div class="match-card">',
    '<h3>' + status + '</h3>',
    '<p>HKDF-SHA-256 mixes the classical X25519 secret and the post-quantum ML-KEM secret into one 32-byte AES-256-GCM session key. Watch both secrets feed the combiner — neither half alone produces the key.</p>',
    renderCombinerFlow(),
    '<p class="footer-note">This mirrors the combiner design in IETF draft-ietf-tls-hybrid-design and NIST SP 800-56C Rev. 2.</p>',
    '</div>',
  ].join('');
}

function renderCombinerFlow(): string {
  if (!state.timeline) {
    return '';
  }

  const x25519Hex = shortHex(state.timeline.aliceX25519Secret, 8);
  const mlkemHex = shortHex(state.timeline.aliceMlkemSecret, 8);
  const keyHex = shortHex(state.timeline.aliceSessionKey, 16);

  return [
    '<div class="combiner-flow" role="group" aria-label="HKDF combiner">',
    '<p class="sr-only">The 32-byte X25519 secret and the 32-byte ML-KEM secret are concatenated and run through HKDF-SHA-256 to derive the 32-byte session key.</p>',
    '<div class="combiner-input blue"><span class="combiner-tag">X25519 secret · 32 B</span><code>' + x25519Hex + '</code></div>',
    '<div class="combiner-op" aria-hidden="true">‖</div>',
    '<div class="combiner-input purple"><span class="combiner-tag">ML-KEM secret · 32 B</span><code>' + mlkemHex + '</code></div>',
    '<div class="combiner-op" aria-hidden="true">→ HKDF →</div>',
    '<div class="combiner-output"><span class="combiner-tag">Session key · 32 B</span><code>' + keyHex + '</code></div>',
    '</div>',
  ].join('');
}

function renderChatSection(): string {
  if (!state.sessions || state.currentStep < 6 || !state.timeline) {
    return '';
  }

  const aliceFingerprint = fingerprint(state.sessions.alice.sessionKey);
  const bobFingerprint = fingerprint(state.sessions.bob.sessionKey);
  const fingerprintsMatch = aliceFingerprint === bobFingerprint;
  const sessionStateLabel = fingerprintsMatch ? 'matching' : 'mismatched';

  const messagesHtml = state.messages.length === 0
    ? '<div class="chat-card"><p>No encrypted messages yet. Send one after the handshake completes.</p></div>'
    : state.messages
        .map(function (message, index) {
          const statusClass = message.verification === 'authenticated'
            ? 'status-authenticated'
            : message.verification === 'tampered'
              ? 'status-tampered'
              : 'status-pending';
          const label = message.verification === 'authenticated'
            ? 'authenticated'
            : message.verification === 'tampered'
              ? 'tampered'
              : 'pending';

          return [
            '<article class="message-card ' + message.sender + '">',
            '<div class="message-meta"><strong>' + message.sender.toUpperCase() + ' → ' + (message.sender === 'alice' ? 'BOB' : 'ALICE') + '</strong>',
            '<span class="status-pill ' + statusClass + '">' + label + '</span></div>',
            '<p><strong>Plaintext:</strong> ' + escapeHtml(message.plaintext) + '</p>',
            '<p><strong>Ciphertext:</strong><br /><code>' + escapeHtml(message.encrypted.ciphertext) + '</code></p>',
            '<p><strong>IV:</strong> <code>' + escapeHtml(message.encrypted.iv) + '</code></p>',
            '<p><strong>Message number:</strong> ' + message.encrypted.messageNumber + '</p>',
            message.decryptedPlaintext ? '<p><strong>Recipient view:</strong> ' + escapeHtml(message.decryptedPlaintext) + '</p>' : '',
            message.recipientNote ? '<p><strong>Verification note:</strong> ' + escapeHtml(message.recipientNote) + '</p>' : '',
            '<div class="message-status"><button class="action-button decrypt-button" data-index="' + index + '">Decrypt</button></div>',
            '</article>',
          ].join('');
        })
        .join('');

  return [
    '<section class="chat-wrapper">',
    '<div class="chat-card">',
    '<h3>Secure chat</h3>',
    '<p>After step 6, Alice and Bob can encrypt messages with AES-256-GCM using the hybrid-derived session key.</p>',
    '<div class="chat-meta">',
    '<div class="connection-card"><h4>Alice fingerprint</h4><p><code>' + aliceFingerprint + '</code></p></div>',
    '<div class="connection-card"><h4>Bob fingerprint</h4><p><code>' + bobFingerprint + '</code></p></div>',
    '<div class="connection-card"><h4>Session state</h4><p>' + sessionStateLabel + '</p></div>',
    '</div>',
    '<div class="chat-form">',
    '<div class="chat-form-row">',
    '<label for="sender-select" class="sr-only">Select sender</label>',
    '<select class="select" id="sender-select">',
    '<option value="alice">Alice sends</option>',
    '<option value="bob">Bob sends</option>',
    '</select>',
    '<label for="message-input" class="sr-only">Message to encrypt</label>',
    '<input class="input" id="message-input" type="text" placeholder="Type a message to encrypt" />',
    '<button class="action-button" id="send-button">Send</button>',
    '</div>',
    '<div class="button-row">',
    '<button class="action-button" id="tamper-button">Tamper with session</button>',
    '</div>',
    '</div>',
    '</div>',
    '<div class="message-list">' + messagesHtml + '</div>',
    '</section>',
  ].join('');
}

function renderHandshakeTab(): string {
  if (state.loading || !state.timeline || !state.sessions) {
    return '<section class="panel"><div class="loading-card"><p>Preparing the hybrid handshake demo…</p></div></section>';
  }

  return [
    '<section class="panel">',
    '<h2>Live handshake</h2>',
    '<p>Walk through the six phases used to combine the blue X25519 wire and the purple ML-KEM-768 wire.</p>',
    renderStepList(),
    '<div class="button-row">',
    '<button class="action-button" id="prev-step" ' + (state.currentStep === 1 ? 'disabled' : '') + '>Prev</button>',
    '<button class="action-button" id="next-step" ' + (state.currentStep === 6 ? 'disabled' : '') + '>Next</button>',
    '<button class="action-button" id="reset-handshake">Reset</button>',
    '</div>',
    renderWireDiagram(),
    renderLiveWireCards(),
    // Progressive disclosure: the outcome metrics, the combiner, and the secure
    // chat are the *result* of a completed handshake, so they stay hidden until
    // step 6 keeps attention on one idea at a time during steps 1-5.
    renderHandshakeOutcome(),
    '</section>',
  ].join('');
}

// Per-wire key-detail cards. Each card is hidden until it carries its first live
// value, so during steps 1-2 the wire diagram is the focus. The blue card mounts
// at step 2 (Alice's ephemeral key exists); the purple card at step 3 (Alice has
// encapsulated a ciphertext). Bob's public keys, though known from step 1, ride
// along inside the card once it appears rather than showing a lone card early.
function renderLiveWireCards(): string {
  if (!state.timeline) {
    return '';
  }
  const step = state.currentStep;
  const showBlue = step >= 2;
  const showPurple = step >= 3;
  if (!showBlue && !showPurple) {
    return '<p class="live-hint">Advance the handshake — the per-wire byte details appear here as each wire produces its first value.</p>';
  }

  const blueCard = showBlue
    ? [
        '<div class="wire-card blue"><h3>Blue wire — X25519</h3><div class="key-list">',
        '<div><span class="label">Bob public key</span><span class="value">' + shortHex(state.timeline.bobKeys.x25519.publicKeyRaw, 16) + '</span></div>',
        '<div><span class="label">Alice ephemeral public key</span><span class="value">' + shortHex(state.timeline.aliceKeyPair.publicKeyRaw, 16) + '</span></div>',
        '<div><span class="label">Alice shared secret</span><span class="value">' + (step >= 4 ? shortHex(state.timeline.aliceX25519Secret, 16) : 'pending') + '</span></div>',
        '<div><span class="label">Bob shared secret</span><span class="value">' + (step >= 4 ? shortHex(state.timeline.bobX25519Secret, 16) : 'pending') + '</span></div>',
        '</div></div>',
      ].join('')
    : '';

  const purpleCard = showPurple
    ? [
        '<div class="wire-card purple"><h3>Purple wire — ML-KEM-768</h3><div class="key-list">',
        '<div><span class="label">Bob ML-KEM public key</span><span class="value">' + shortHex(state.timeline.bobKeys.mlkem.publicKey, 16) + '</span></div>',
        '<div><span class="label">Ciphertext from Alice</span><span class="value">' + shortHex(state.timeline.mlkemCiphertext, 16) + '</span></div>',
        '<div><span class="label">Alice shared secret</span><span class="value">' + shortHex(state.timeline.aliceMlkemSecret, 16) + '</span></div>',
        '<div><span class="label">Bob shared secret</span><span class="value">' + (step >= 5 ? shortHex(state.timeline.bobMlkemSecret, 16) : 'pending') + '</span></div>',
        '</div></div>',
      ].join('')
    : '';

  return '<div class="live-grid">' + blueCard + purpleCard + '</div>';
}

// The step-6 payoff: outcome metrics, the HKDF combiner/match card, an explicit
// "now try encrypting a message" prompt, and the secure chat. All gated to step 6
// so the six-step narrative isn't competing with a wall of outcome cards.
function renderHandshakeOutcome(): string {
  if (!state.timeline || state.currentStep < 6) {
    return '<p class="live-hint step-hint">You are on step ' + state.currentStep + ' of 6. The combined session key, its metrics, and the secure chat unlock at step 6.</p>';
  }

  const metrics = [
    '<div class="metrics-row">',
    '<div class="metric-card"><div class="label">Total measured handshake time</div><div class="big-number">' + formatMs(state.timeline.totalTimeMs) + '</div></div>',
    '<div class="metric-card"><div class="label">Handshake overhead</div><div class="big-number">+2,272 bytes</div></div>',
    '<div class="metric-card"><div class="label">Session key length</div><div class="big-number">32 bytes</div></div>',
    '</div>',
  ].join('');

  const prompt = '<div class="try-prompt" role="note"><span class="try-prompt-icon" aria-hidden="true">✓</span><div><strong>Handshake complete.</strong> Both wires produced the same session key. Now try encrypting a message below — then use <em>Tamper with session</em> to watch AES-256-GCM reject a flipped ML-KEM ciphertext byte.</div></div>';

  return metrics + prompt + renderMatchCard() + renderChatSection();
}

// Newcomer on-ramp for the encapsulate/decapsulate vocabulary the handshake
// steps assume from step 3 onward. Collapsible so a cryptographer can skip it.
// Contrasts the *symmetric* DH operation (both sides do the same thing) with the
// *asymmetric* KEM flow (one side encapsulates → sends a ciphertext → the other
// decapsulates), which is exactly why the purple wire sends a packet back and the
// blue wire does not.
function renderKemAside(): string {
  return [
    '<details class="kem-aside">',
    '<summary><span class="kem-aside-badge">New to PQ crypto?</span> What is a KEM, and why does it differ from Diffie-Hellman?</summary>',
    '<div class="kem-aside-body">',
    '<p>Both wires end with the <strong>same result</strong> — a shared 32-byte secret — but they get there by opposite mechanisms. That is why one wire sends a packet back and the other does not.</p>',
    '<div class="kem-compare">',
    '<div class="kem-compare-col blue">',
    '<h4>X25519 — a Diffie-Hellman exchange</h4>',
    '<p class="kem-compare-tag">Symmetric: both sides do the identical operation.</p>',
    '<pre class="kem-mini" tabindex="0" role="region" aria-label="X25519 Diffie-Hellman flow">Alice pub ───────▶ Bob\nBob   pub ◀─────── Alice\n(each combines their own\n private key with the\n other\'s public key)\n   ↓            ↓\n same secret  same secret</pre>',
    '<p>Nobody "sends the secret." Each side <em>derives</em> it locally by mixing keys. There is no ciphertext.</p>',
    '</div>',
    '<div class="kem-compare-col purple">',
    '<h4>ML-KEM — a Key Encapsulation Mechanism</h4>',
    '<p class="kem-compare-tag">Asymmetric: the two sides do different operations.</p>',
    '<pre class="kem-mini" tabindex="0" role="region" aria-label="ML-KEM encapsulate decapsulate flow">Bob pub ─────────▶ Alice\n           Alice ENCAPSULATES:\n           makes a fresh secret +\n           a ciphertext holding it\nAlice ◀── ciphertext ── Bob\nBob DECAPSULATES with his\nprivate key → same secret</pre>',
    '<p><strong>Encapsulate</strong> = generate a secret and lock it into a ciphertext using Bob\'s public key. <strong>Decapsulate</strong> = Bob unlocks that ciphertext with his private key to recover the identical secret. The ciphertext is the packet that travels back up the purple wire.</p>',
    '</div>',
    '</div>',
    '<p class="footer-note">Takeaway: DH mixes public keys in place; a KEM ships a ciphertext that carries a secret. Both give the two wires an <em>independent</em> shared secret, which is what lets HKDF combine them into one resilient key.</p>',
    '</div>',
    '</details>',
  ].join('');
}

function renderWiresTab(): string {
  const benchmarkStatus = state.benchmarkStatus === 'running'
    ? '<p>Running 50 iterations without blocking the UI…</p>'
    : state.benchmark
      ? [
          '<div class="cards-grid">',
          '<div class="benchmark-card"><h4>X25519</h4><p><strong>' + state.benchmark.x25519OpsPerSecond.toFixed(2) + '</strong> ops/s</p><p>Total: ' + formatMs(state.benchmark.durationsMs.x25519) + '</p></div>',
          '<div class="benchmark-card"><h4>ML-KEM-768</h4><p><strong>' + state.benchmark.mlkemOpsPerSecond.toFixed(2) + '</strong> ops/s</p><p>Total: ' + formatMs(state.benchmark.durationsMs.mlkem) + '</p></div>',
          '<div class="benchmark-card"><h4>Hybrid</h4><p><strong>' + state.benchmark.hybridOpsPerSecond.toFixed(2) + '</strong> ops/s</p><p>Overhead vs X25519: ' + state.benchmark.hybridOverheadPercent.toFixed(2) + '%</p></div>',
          '</div>',
        ].join('')
      : '<p>No benchmark results yet. Click the button to measure the three handshakes.</p>';

  return [
    '<section class="panel">',
    '<h2>Two wires</h2>',
    renderKemAside(),
    '<div class="cards-grid">',
    '<div class="wire-card blue"><h3>X25519 wire</h3><p>Curve25519 ECDH keeps forward secrecy fast and compact.</p><ul><li>Public key: 32 bytes</li><li>Shared secret: 32 bytes</li><li>Strength: mature classical elliptic-curve exchange</li></ul></div>',
    '<div class="wire-card purple"><h3>ML-KEM-768 wire</h3><p>NIST FIPS 203 key encapsulation adds post-quantum protection.</p><ul><li>Public key: 1,184 bytes</li><li>Ciphertext: 1,088 bytes</li><li>Shared secret: 32 bytes</li></ul></div>',
    '<div class="metric-card"><h3>Total overhead vs pure X25519</h3><div class="big-number">+2,272 bytes</div><p>The extra bytes are the ML-KEM public key plus the returned ciphertext.</p></div>',
    '</div>',
    '<h3>HKDF combiner</h3>',
    '<pre class="formula">session_key = HKDF-SHA-256(\nikm = x25519_secret || mlkem_secret,\nsalt = 32 zero bytes,\ninfo = "hybrid-wire-v1",\nlength = 32 bytes\n)</pre>',
    '<section class="benchmark-card">',
    '<h3>Performance benchmark</h3>',
    '<p>The hybrid handshake is slower than X25519 alone but faster than many people expect. Chrome ships this cost for each protected HTTPS connection.</p>',
    '<div class="button-row"><button class="action-button" id="run-benchmark">Run benchmark</button></div>',
    benchmarkStatus,
    '</section>',
    '</section>',
  ].join('');
}

function renderResilienceExplorer(): string {
  const verdict = evaluateResilience(state.breakX25519, state.breakMlkem);

  const x25519Toggle = [
    '<button type="button" role="switch" class="resilience-toggle blue' + (state.breakX25519 ? ' on' : '') + '" id="break-x25519" aria-checked="' + state.breakX25519 + '">',
    '<span class="resilience-toggle-track" aria-hidden="true"><span class="resilience-toggle-thumb"></span></span>',
    '<span class="resilience-toggle-label">' + (state.breakX25519 ? 'X25519 broken' : 'X25519 secure') + '</span>',
    '</button>',
  ].join('');

  const mlkemToggle = [
    '<button type="button" role="switch" class="resilience-toggle purple' + (state.breakMlkem ? ' on' : '') + '" id="break-mlkem" aria-checked="' + state.breakMlkem + '">',
    '<span class="resilience-toggle-track" aria-hidden="true"><span class="resilience-toggle-thumb"></span></span>',
    '<span class="resilience-toggle-label">' + (state.breakMlkem ? 'ML-KEM-768 broken' : 'ML-KEM-768 secure') + '</span>',
    '</button>',
  ].join('');

  const verdictIcon = verdict.level === 'compromised' ? '🔓' : verdict.level === 'degraded' ? '🛡️' : '🔒';

  return [
    '<div class="resilience-card">',
    '<h3>Prove it yourself: break a wire</h3>',
    '<p>Toggle a wire to "broken" and watch the verdict. The session only fails when <strong>both</strong> wires fall — break either one alone and the other still carries the key.</p>',
    '<p class="resilience-def"><span class="resilience-def-badge">What "broken" means</span> Assume the attacker has recovered <strong>this wire\'s 32-byte secret</strong> — not that the bytes stopped flowing. A broken wire\'s secret is revealed below as <em>known to attacker</em>; the surviving wire stays masked, so you can see HKDF\'s input is still half-unknown.</p>',
    '<div class="resilience-controls">' + x25519Toggle + mlkemToggle + '</div>',
    renderResilienceWires(),
    renderResilienceSecrets(),
    '<div class="resilience-verdict ' + verdict.level + '" role="status" aria-live="polite">',
    '<div class="resilience-verdict-head"><span class="resilience-verdict-icon" aria-hidden="true">' + verdictIcon + '</span><strong>' + verdict.headline + '</strong></div>',
    '<p>' + verdict.detail + '</p>',
    '</div>',
    '</div>',
  ].join('');
}

// Show the two HKDF inputs side by side. A wire toggled "broken" reveals its
// real 32-byte secret (labelled "known to attacker"); the surviving wire's bytes
// stay masked. This makes the central claim literal: with one wire broken the
// attacker still holds only half of the concatenated HKDF input.
//
// The bytes shown are the SAME live secrets the handshake derived — no fabricated
// values. Before the handshake finishes we fall back to a masked placeholder so
// the explorer is honest on the Threat tab even standalone.
function renderResilienceSecrets(): string {
  const maskHex = '•• •• •• •• •• •• •• •• … (32 bytes, unknown to attacker)';

  function secretCell(opts: {
    wireClass: 'blue' | 'purple';
    title: string;
    broken: boolean;
    secret?: Uint8Array;
  }): string {
    const revealed = opts.broken;
    const bytesLabel = revealed
      ? (opts.secret ? escapeHtml(toHexSpaced(opts.secret, 16)) + '…' : 'ff a2 3c … (example — run the handshake for live bytes)')
      : maskHex;
    const statusText = revealed ? 'known to attacker' : 'still unknown to attacker';
    const statusClass = revealed ? 'exposed' : 'masked';
    // Icon + text + colour (not colour alone) carries the state for a11y.
    const statusIcon = revealed ? '🔓' : '🔒';
    return [
      '<div class="secret-cell ' + opts.wireClass + ' ' + statusClass + '">',
      '<div class="secret-cell-head">',
      '<span class="secret-cell-title">' + opts.title + '</span>',
      '<span class="secret-status ' + statusClass + '"><span aria-hidden="true">' + statusIcon + '</span> ' + statusText + '</span>',
      '</div>',
      '<code class="secret-bytes">' + bytesLabel + '</code>',
      '</div>',
    ].join('');
  }

  const x25519Secret = state.timeline?.aliceX25519Secret;
  const mlkemSecret = state.timeline?.aliceMlkemSecret;
  const bothMasked = !state.breakX25519 && !state.breakMlkem;

  return [
    '<div class="secret-reveal" role="group" aria-label="HKDF input secrets and what the attacker knows">',
    secretCell({ wireClass: 'blue', title: 'X25519 secret (HKDF input A)', broken: state.breakX25519, secret: x25519Secret }),
    '<div class="secret-join" aria-hidden="true">‖</div>',
    secretCell({ wireClass: 'purple', title: 'ML-KEM secret (HKDF input B)', broken: state.breakMlkem, secret: mlkemSecret }),
    '<p class="secret-reveal-note">' + (bothMasked
      ? 'Both inputs are masked: the attacker knows neither half, so HKDF(A ‖ B) is fully out of reach.'
      : (state.breakX25519 && state.breakMlkem)
        ? 'Both inputs are exposed: only now can the attacker rebuild A ‖ B and re-derive the session key.'
        : 'One input is exposed, one is masked: the attacker holds half of A ‖ B and still cannot re-derive the HKDF output.') + '</p>',
    '</div>',
  ].join('');
}

function renderResilienceWires(): string {
  const blueBreak = state.breakX25519
    ? '<text class="diagram-break" x="410" y="48" font-size="22" text-anchor="middle" aria-hidden="true">✕</text>'
    : '';
  const purpleBreak = state.breakMlkem
    ? '<text class="diagram-break" x="410" y="138" font-size="22" text-anchor="middle" aria-hidden="true">✕</text>'
    : '';

  return renderWireSvg({
    ariaLabel: 'Two hybrid wires; a broken wire is marked with an X',
    blueClass: 'wire-path wire-blue' + (state.breakX25519 ? ' wire-broken' : ''),
    purpleClass: 'wire-path wire-purple' + (state.breakMlkem ? ' wire-broken' : ''),
    overlay: blueBreak + purpleBreak,
  });
}

function renderThreatTab(): string {
  return [
    '<section class="panel">',
    '<h2>Threat model</h2>',
    '<p>The whole point of hybrid is one claim: <strong>the session survives as long as either wire holds.</strong> Try to break it below.</p>',
    renderResilienceExplorer(),
    '<h3 id="threat-matrix-heading">Full threat matrix</h3>',
    '<div class="table-card" tabindex="0" role="region" aria-labelledby="threat-matrix-heading">',
    '<table><thead><tr><th>Attacker capability</th><th>Transcript access</th><th>Wire status</th><th>Session safety</th></tr></thead><tbody>',
    threatRows
      .map(function (row) {
        return '<tr><td>' + row[0] + '</td><td>' + row[1] + '</td><td>' + row[2] + '</td><td><strong>' + row[3] + '</strong></td></tr>';
      })
      .join(''),
    '</tbody></table>',
    '</div>',
    '<div class="quote">',
    '<strong>Harvest now, decrypt later:</strong> if an attacker records the handshake today and breaks X25519 years later with a quantum computer, the ML-KEM half still blocks recovery of the session key. They must break both wires at once.',
    '</div>',
    '</section>',
  ].join('');
}

function renderDeployedTab(): string {
  return [
    '<section class="panel">',
    '<h2>Deployed today</h2>',
    '<div class="deployment-grid">',
    deploymentCards
      .map(function (card) {
        return [
          '<article class="deployment-card">',
          '<div class="badge badge-good">' + card.status + '</div>',
          '<h3>' + card.title + '</h3>',
          '<p><strong>Scheme:</strong> ' + card.scheme + '</p>',
          '<p><strong>Coverage:</strong> ' + card.coverage + '</p>',
          '</article>',
        ].join('');
      })
      .join(''),
    '</div>',
    '<div class="quote"><strong>Cloudflare hybrid rationale:</strong> combine a classical key exchange with a post-quantum one so the session remains secure as long as at least one component stays secure.</div>',
    '</section>',
  ].join('');
}

// Names and refutes the natural wrong guess: hybrid does NOT double the security
// bits. It is two locks in series (an attacker must break BOTH) — a hedge against
// either primitive failing, not a multiplier of strength. Reuses the broken-wire
// ✕ marks from the resilience explorer so the visual vocabulary is consistent.
function renderTwiceAsStrong(): string {
  return [
    '<div class="misconception-card">',
    '<h3><span class="misconception-flag" aria-hidden="true">✕</span> "Twice as strong?" — No.</h3>',
    '<p>A first guess is that adding a second wire <em>doubles</em> the security (e.g. 128 + 128 = 256 bits). That is the wrong model. Hybrid is a <strong>hedge, not a multiplier</strong>: the two secrets sit in series, so an attacker must break <strong>both</strong> to win — and the combined strength is bounded by whichever wire is <em>stronger</em>, not their sum.</p>',
    '<div class="misconception-compare">',
    '<div class="misconception-col right">',
    '<h4><span aria-hidden="true">🔒</span> Right: two locks in series</h4>',
    '<div class="lock-row" aria-hidden="true"><span class="lock-chip blue">X25519</span><span class="lock-and">AND</span><span class="lock-chip purple">ML-KEM</span></div>',
    '<p>Break one wire (<span class="inline-break" aria-hidden="true">✕</span>) and the survivor still holds the key. The attacker must break <strong>both at once</strong>. Safety = "either one holding is enough."</p>',
    '</div>',
    '<div class="misconception-col wrong">',
    '<h4><span aria-hidden="true">⚠️</span> Wrong: two locks = double the bits</h4>',
    '<div class="lock-row" aria-hidden="true"><span class="lock-chip blue">128b</span><span class="lock-and">+</span><span class="lock-chip purple">128b</span><span class="lock-and">=</span><span class="lock-chip ghost">256b?</span></div>',
    '<p>Strengths do not add. If both wires were somehow broken by the same advance, the "sum" is zero — which is exactly why we combine <em>independent</em> primitives instead.</p>',
    '</div>',
    '</div>',
    '</div>',
  ].join('');
}

function renderWhyTab(): string {
  return [
    '<section class="panel">',
    '<h2>Why hybrid?</h2>',
    '<div class="cards-grid">',
    '<div class="connection-card"><h3>X25519 alone</h3><p>Compact and fast, but a future quantum computer could eventually threaten long-term confidentiality of recorded traffic.</p></div>',
    '<div class="connection-card"><h3>ML-KEM alone</h3><p>Post-quantum protection is strong, but deployments often prefer a transitional path that still includes a mature classical primitive.</p></div>',
    '<div class="connection-card"><h3>Hybrid together</h3><p>NIST SP 800-56C encourages robust combiners. HKDF lets both secrets contribute so the session survives if either primitive remains secure.</p></div>',
    '</div>',
    renderTwiceAsStrong(),
    '<h3>Portfolio connection</h3>',
    '<div class="cards-grid">',
    '<div class="connection-card"><strong>ratchet-wire → hybrid-wire</strong><p>The post-quantum upgrade path for X25519 session setup, similar to Signal PQXDH.</p></div>',
    '<div class="connection-card"><strong>kyber-vault → hybrid-wire</strong><p>ML-KEM alone becomes ML-KEM plus X25519 in the real-world deployed handshake.</p></div>',
    '<div class="connection-card"><strong>dilithium-seal + iron-serpent</strong><p>Hybrid-wire establishes the key. Signature and data-encryption demos complete the secure channel story.</p></div>',
    '</div>',
    '<p class="footer-note">References: IETF draft-ietf-tls-hybrid-design, NIST FIPS 203, and NIST SP 800-56C Rev. 2.</p>',
    '</section>',
  ].join('');
}

function renderPanelContent(): string {
  if (state.notice) {
    // Notice is rendered below the active tab panel to keep the main content stable.
  }

  if (state.activeTab === 'handshake') {
    return renderHandshakeTab();
  }
  if (state.activeTab === 'wires') {
    return renderWiresTab();
  }
  if (state.activeTab === 'threat') {
    return renderThreatTab();
  }
  if (state.activeTab === 'deployed') {
    return renderDeployedTab();
  }
  return renderWhyTab();
}

function renderNotice(): string {
  if (!state.notice) {
    return '';
  }

  return '<div class="notice-card"><strong>Status:</strong> ' + escapeHtml(state.notice) + '</div>';
}

function render(): void {
  appRoot!.innerHTML = [
    '<div class="app-shell">',
    renderHero(),
    '<nav class="tabs" role="tablist" aria-label="Demo sections">' + renderTabs() + '</nav>',
    '<div id="tab-panel-' + state.activeTab + '" role="tabpanel" aria-labelledby="tab-' + state.activeTab + '">' + renderPanelContent() + '</div>',
    '<div aria-live="polite" role="status">' + renderNotice() + '</div>',
    '<p class="footer-note">Offline runtime only: Vite + TypeScript + Web Crypto + verified noble packages.</p>',
    '</div>',
  ].join('');

  attachListeners();
  syncThemeToggleButton();
}

function attachListeners(): void {
  document.querySelectorAll<HTMLElement>('[data-tab]').forEach(function (element) {
    element.onclick = function () {
      const nextTab = element.dataset.tab as TabId | undefined;
      if (nextTab) {
        state.activeTab = nextTab;
        render();
        const newTab = document.querySelector<HTMLElement>('#tab-' + nextTab);
        if (newTab) {
          newTab.focus();
        }
      }
    };

    element.onkeydown = function (event: KeyboardEvent) {
      const tabButtons = Array.from(document.querySelectorAll<HTMLElement>('[role="tab"]'));
      const currentIndex = tabButtons.indexOf(element);
      let targetIndex = -1;

      if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
        targetIndex = (currentIndex + 1) % tabButtons.length;
      } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
        targetIndex = (currentIndex - 1 + tabButtons.length) % tabButtons.length;
      } else if (event.key === 'Home') {
        targetIndex = 0;
      } else if (event.key === 'End') {
        targetIndex = tabButtons.length - 1;
      }

      if (targetIndex >= 0) {
        event.preventDefault();
        tabButtons[targetIndex].click();
      }
    };
  });

  const prevButton = document.querySelector<HTMLButtonElement>('#prev-step');
  if (prevButton) {
    prevButton.onclick = function () {
      state.currentStep = Math.max(1, state.currentStep - 1);
      render();
    };
  }

  const nextButton = document.querySelector<HTMLButtonElement>('#next-step');
  if (nextButton) {
    nextButton.onclick = function () {
      state.currentStep = Math.min(6, state.currentStep + 1);
      render();
    };
  }

  const resetButton = document.querySelector<HTMLButtonElement>('#reset-handshake');
  if (resetButton) {
    resetButton.onclick = function () {
      void initializeHandshake();
    };
  }

  const sendButton = document.querySelector<HTMLButtonElement>('#send-button');
  if (sendButton) {
    sendButton.onclick = function () {
      void handleSendMessage();
    };
  }

  const tamperButton = document.querySelector<HTMLButtonElement>('#tamper-button');
  if (tamperButton) {
    tamperButton.onclick = function () {
      void handleTamperSession();
    };
  }

  const benchmarkButton = document.querySelector<HTMLButtonElement>('#run-benchmark');
  if (benchmarkButton) {
    benchmarkButton.onclick = function () {
      void handleBenchmark();
    };
  }

  const breakX25519Toggle = document.querySelector<HTMLButtonElement>('#break-x25519');
  if (breakX25519Toggle) {
    breakX25519Toggle.onclick = function () {
      state.breakX25519 = !state.breakX25519;
      render();
      document.querySelector<HTMLButtonElement>('#break-x25519')?.focus();
    };
  }

  const breakMlkemToggle = document.querySelector<HTMLButtonElement>('#break-mlkem');
  if (breakMlkemToggle) {
    breakMlkemToggle.onclick = function () {
      state.breakMlkem = !state.breakMlkem;
      render();
      document.querySelector<HTMLButtonElement>('#break-mlkem')?.focus();
    };
  }

  document.querySelectorAll<HTMLButtonElement>('.decrypt-button').forEach(function (button) {
    button.onclick = function () {
      const indexValue = button.dataset.index;
      if (typeof indexValue === 'string') {
        void handleDecrypt(Number(indexValue));
      }
    };
  });

  const themeToggle = document.querySelector<HTMLButtonElement>('#theme-toggle');
  if (themeToggle) {
    themeToggle.onclick = function () {
      const current = getThemeMode();
      applyTheme(current === 'dark' ? 'light' : 'dark');
    };
  }
}

async function initializeHandshake(): Promise<void> {
  state.loading = true;
  state.notice = '';
  state.messages = [];
  state.messageNumber = 1;
  state.tamperedSession = false;
  render();

  const stepTimes = [0, 0, 0, 0, 0, 0];

  const step1Start = nowMs();
  const bobKeys = await generateHybridKeyPair();
  stepTimes[0] = nowMs() - step1Start;

  const step2Start = nowMs();
  const aliceKeyPair = await generateX25519KeyPair();
  stepTimes[1] = nowMs() - step2Start;

  const step3Start = nowMs();
  const mlkemResult = await mlkemEncapsulate(bobKeys.mlkem.publicKey);
  stepTimes[2] = nowMs() - step3Start;

  const step4Start = nowMs();
  const x25519Secrets = await Promise.all([
    x25519SharedSecret(aliceKeyPair.privateKey, bobKeys.x25519.publicKeyRaw),
    x25519SharedSecret(bobKeys.x25519.privateKey, aliceKeyPair.publicKeyRaw),
  ]);
  stepTimes[3] = nowMs() - step4Start;

  const step5Start = nowMs();
  const bobMlkemSecret = await mlkemDecapsulate(mlkemResult.ciphertext, bobKeys.mlkem.privateKey);
  stepTimes[4] = nowMs() - step5Start;

  const step6Start = nowMs();
  const combinedKeys = await Promise.all([
    combineSecrets(x25519Secrets[0], mlkemResult.sharedSecret, 'hybrid-wire-v1'),
    combineSecrets(x25519Secrets[1], bobMlkemSecret, 'hybrid-wire-v1'),
  ]);
  stepTimes[5] = nowMs() - step6Start;

  state.timeline = {
    bobKeys,
    aliceKeyPair,
    aliceX25519Secret: x25519Secrets[0],
    bobX25519Secret: x25519Secrets[1],
    aliceMlkemSecret: mlkemResult.sharedSecret,
    bobMlkemSecret,
    aliceSessionKey: combinedKeys[0],
    bobSessionKey: combinedKeys[1],
    mlkemCiphertext: mlkemResult.ciphertext,
    stepTimes,
    totalTimeMs: stepTimes.reduce(function (sum, value) {
      return sum + value;
    }, 0),
  };

  state.sessions = {
    alice: {
      sessionKey: combinedKeys[0],
      myRole: 'alice',
      x25519PublicKey: aliceKeyPair.publicKeyRaw,
      mlkemCiphertext: mlkemResult.ciphertext,
    },
    bob: {
      sessionKey: combinedKeys[1],
      myRole: 'bob',
      x25519PublicKey: bobKeys.x25519.publicKeyRaw,
      mlkemPublicKey: bobKeys.mlkem.publicKey,
    },
  };

  state.currentStep = 1;
  state.loading = false;
  render();
}

async function handleSendMessage(): Promise<void> {
  if (!state.sessions) {
    return;
  }

  const senderSelect = document.querySelector<HTMLSelectElement>('#sender-select');
  const messageInput = document.querySelector<HTMLInputElement>('#message-input');
  if (!senderSelect || !messageInput) {
    return;
  }

  const plaintext = messageInput.value.trim();
  if (!plaintext) {
    state.notice = 'Enter a message before sending.';
    render();
    return;
  }

  const sender = senderSelect.value === 'bob' ? 'bob' : 'alice';
  const encrypted = await encryptMessage(state.sessions[sender], plaintext, state.messageNumber);

  state.messages.unshift({
    sender,
    plaintext,
    encrypted,
    verification: 'pending',
  });

  state.messageNumber += 1;
  state.notice = 'Message encrypted and ready for recipient decryption.';
  messageInput.value = '';
  render();
}

async function handleDecrypt(index: number): Promise<void> {
  if (!state.sessions || !state.messages[index]) {
    return;
  }

  const record = state.messages[index];
  const recipient = record.sender === 'alice' ? 'bob' : 'alice';

  try {
    const plaintext = await decryptMessage(state.sessions[recipient], record.encrypted);
    record.decryptedPlaintext = plaintext;
    record.recipientNote = 'Authenticated successfully on the ' + recipient + ' side.';
    record.verification = 'authenticated';
    state.notice = 'AES-GCM authentication succeeded.';
  } catch (error) {
    record.decryptedPlaintext = undefined;
    record.recipientNote = (error as Error).message;
    record.verification = 'tampered';
    state.notice = 'Decryption failed because the session keys no longer match.';
  }

  render();
}

async function handleTamperSession(): Promise<void> {
  if (!state.timeline || !state.sessions) {
    return;
  }

  const tamperedCiphertext = state.timeline.mlkemCiphertext.slice();
  tamperedCiphertext[0] ^= 0x01;

  const bobResult = await hybridDecapsulate(
    state.timeline.aliceKeyPair.publicKeyRaw,
    tamperedCiphertext,
    state.timeline.bobKeys.x25519,
    state.timeline.bobKeys.mlkem.privateKey,
  );

  state.timeline = {
    bobKeys: state.timeline.bobKeys,
    aliceKeyPair: state.timeline.aliceKeyPair,
    aliceX25519Secret: state.timeline.aliceX25519Secret,
    bobX25519Secret: state.timeline.bobX25519Secret,
    aliceMlkemSecret: state.timeline.aliceMlkemSecret,
    bobMlkemSecret: bobResult.mlkemSharedSecret,
    aliceSessionKey: state.timeline.aliceSessionKey,
    bobSessionKey: bobResult.combinedSessionKey,
    mlkemCiphertext: tamperedCiphertext,
    stepTimes: state.timeline.stepTimes,
    totalTimeMs: state.timeline.totalTimeMs,
  };

  state.sessions = {
    alice: state.sessions.alice,
    bob: {
      sessionKey: bobResult.combinedSessionKey,
      myRole: 'bob',
      x25519PublicKey: state.timeline.bobKeys.x25519.publicKeyRaw,
      mlkemPublicKey: state.timeline.bobKeys.mlkem.publicKey,
    },
  };

  state.tamperedSession = true;
  state.notice = 'The ML-KEM ciphertext was modified before Bob decapsulated it. Future decryptions should fail authentication.';
  render();
}

async function handleBenchmark(): Promise<void> {
  if (state.benchmarkStatus === 'running') {
    return;
  }

  state.benchmarkStatus = 'running';
  state.notice = 'Benchmark is running...';
  render();

  try {
    state.benchmark = await runBenchmark(50);
    state.notice = 'Benchmark complete.';
  } catch (error) {
    state.notice = 'Benchmark failed: ' + (error as Error).message;
  } finally {
    state.benchmarkStatus = 'idle';
    render();
  }
}

void initializeHandshake();
