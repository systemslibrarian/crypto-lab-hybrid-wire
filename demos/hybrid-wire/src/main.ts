import './styles.css';

import { runBenchmark, type BenchmarkResult } from './benchmark';
import { combineSecrets, generateHybridKeyPair, hybridDecapsulate, type HybridKeyPair } from './crypto/hybrid';
import { mlkemDecapsulate, mlkemEncapsulate } from './crypto/mlkem768';
import { decryptMessage, encryptMessage, type EncryptedMessage, type HybridSession } from './crypto/session';
import { bytesEqual, fingerprint, formatMs, nowMs, shortHex, toHex } from './crypto/utils';
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
  notice: '',
};

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
  return [
    '<section class="hero">',
    '<h1>X25519 + ML-KEM-768</h1>',
    '<p><strong>Hybrid post-quantum key exchange</strong> for the crypto-compare portfolio.</p>',
    '<p>This demo bridges ratchet-wire and kyber-vault by showing how classical and post-quantum secrets combine into the handshake protecting real traffic today.</p>',
    '<div class="hero-badges">',
    '<span class="badge badge-good">Safe if either wire holds</span>',
    '<span class="badge badge-info">HKDF-SHA-256 combiner</span>',
    '<span class="badge badge-info">AES-256-GCM secure chat</span>',
    '<span class="badge badge-info">No runtime CDN dependencies</span>',
    '</div>',
    '</section>',
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

function renderWireDiagram(): string {
  const animateClass = state.currentStep >= 3 ? ' wire-flow' : '';
  return [
    '<div class="wire-diagram">',
    '<svg viewBox="0 0 820 170" role="img" aria-label="Hybrid wire animation showing X25519 blue wire and ML-KEM purple wire between Bob and Alice">',
    '<text x="20" y="28" fill="#cbd5f5" font-size="14">Bob</text>',
    '<text x="760" y="28" fill="#cbd5f5" font-size="14">Alice</text>',
    '<path class="wire-path wire-blue' + animateClass + '" d="M 72 55 C 240 20, 580 20, 748 55"></path>',
    '<path class="wire-path wire-purple' + animateClass + '" d="M 72 115 C 240 150, 580 150, 748 115"></path>',
    '<circle class="node-dot" cx="72" cy="55" r="7"></circle>',
    '<circle class="node-dot" cx="748" cy="55" r="7"></circle>',
    '<circle class="node-dot" cx="72" cy="115" r="7"></circle>',
    '<circle class="node-dot" cx="748" cy="115" r="7"></circle>',
    '<text x="280" y="42" fill="#93c5fd" font-size="13">X25519 wire</text>',
    '<text x="280" y="150" fill="#d8b4fe" font-size="13">ML-KEM wire</text>',
    '</svg>',
    '</div>',
  ].join('');
}

function renderMatchCard(): string {
  if (!state.timeline || state.currentStep < 6) {
    return '';
  }

  const keysMatch = bytesEqual(state.timeline.aliceSessionKey, state.timeline.bobSessionKey);
  const status = keysMatch ? '✅ Session keys match' : '⚠️ Session keys diverged';
  const keyHex = shortHex(state.timeline.aliceSessionKey, 24);

  return [
    '<div class="match-card">',
    '<h3>' + status + '</h3>',
    '<p><strong>Combined key:</strong> <code>' + keyHex + '</code></p>',
    '<p>HKDF mixes the classical X25519 secret and the post-quantum ML-KEM secret into one 32-byte session key. This mirrors the combiner design described in the IETF hybrid draft.</p>',
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
    '<div class="metrics-row">',
    '<div class="metric-card"><div class="label">Total measured handshake time</div><div class="big-number">' + formatMs(state.timeline.totalTimeMs) + '</div></div>',
    '<div class="metric-card"><div class="label">Handshake overhead</div><div class="big-number">+2,272 bytes</div></div>',
    '<div class="metric-card"><div class="label">Session key length</div><div class="big-number">32 bytes</div></div>',
    '</div>',
    renderWireDiagram(),
    '<div class="live-grid">',
    '<div class="wire-card blue"><h3>Blue wire — X25519</h3><div class="key-list">',
    '<div><span class="label">Bob public key</span><span class="value">' + shortHex(state.timeline.bobKeys.x25519.publicKeyRaw, 16) + '</span></div>',
    '<div><span class="label">Alice ephemeral public key</span><span class="value">' + (state.currentStep >= 2 ? shortHex(state.timeline.aliceKeyPair.publicKeyRaw, 16) : 'pending') + '</span></div>',
    '<div><span class="label">Alice shared secret</span><span class="value">' + (state.currentStep >= 4 ? shortHex(state.timeline.aliceX25519Secret, 16) : 'pending') + '</span></div>',
    '<div><span class="label">Bob shared secret</span><span class="value">' + (state.currentStep >= 4 ? shortHex(state.timeline.bobX25519Secret, 16) : 'pending') + '</span></div>',
    '</div></div>',
    '<div class="wire-card purple"><h3>Purple wire — ML-KEM-768</h3><div class="key-list">',
    '<div><span class="label">Bob ML-KEM public key</span><span class="value">' + shortHex(state.timeline.bobKeys.mlkem.publicKey, 16) + '</span></div>',
    '<div><span class="label">Ciphertext from Alice</span><span class="value">' + (state.currentStep >= 3 ? shortHex(state.timeline.mlkemCiphertext, 16) : 'pending') + '</span></div>',
    '<div><span class="label">Alice shared secret</span><span class="value">' + (state.currentStep >= 3 ? shortHex(state.timeline.aliceMlkemSecret, 16) : 'pending') + '</span></div>',
    '<div><span class="label">Bob shared secret</span><span class="value">' + (state.currentStep >= 5 ? shortHex(state.timeline.bobMlkemSecret, 16) : 'pending') + '</span></div>',
    '</div></div>',
    '</div>',
    renderMatchCard(),
    renderChatSection(),
    '</section>',
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

function renderThreatTab(): string {
  return [
    '<section class="panel">',
    '<h2>Threat model</h2>',
    '<div class="table-card">',
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

function renderWhyTab(): string {
  return [
    '<section class="panel">',
    '<h2>Why hybrid?</h2>',
    '<div class="cards-grid">',
    '<div class="connection-card"><h3>X25519 alone</h3><p>Compact and fast, but a future quantum computer could eventually threaten long-term confidentiality of recorded traffic.</p></div>',
    '<div class="connection-card"><h3>ML-KEM alone</h3><p>Post-quantum protection is strong, but deployments often prefer a transitional path that still includes a mature classical primitive.</p></div>',
    '<div class="connection-card"><h3>Hybrid together</h3><p>NIST SP 800-56C encourages robust combiners. HKDF lets both secrets contribute so the session survives if either primitive remains secure.</p></div>',
    '</div>',
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

  document.querySelectorAll<HTMLButtonElement>('.decrypt-button').forEach(function (button) {
    button.onclick = function () {
      const indexValue = button.dataset.index;
      if (typeof indexValue === 'string') {
        void handleDecrypt(Number(indexValue));
      }
    };
  });
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
