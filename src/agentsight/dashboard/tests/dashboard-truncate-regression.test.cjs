const assert = require('node:assert/strict');
const { join } = require('node:path');
const test = require('node:test');

// Behavioral regression for the dashboard's code-point-safe text
// truncation (#6738): ExpandableText clipped long step messages and
// tool-result observations with String.prototype.slice, which counts
// UTF-16 code units — a cut landing inside a surrogate pair leaves a
// lone high surrogate that the browser renders as U+FFFD before the
// ellipsis. The causal panel's tag/detail clips and the subagent graph's
// label clip had the same shape; this is the dashboard twin of the
// retained-output byte-boundary fix #6539.
//
// Two layers:
//   1. direct fixtures against the shared truncateText utility
//      (transpiled with the dashboard's babel toolchain), pinning the
//      cut length, the surrogate-pair drop and astral-plane counting;
//   2. the REAL AtifViewerPage (transpiled, same hooks driver as the
//      round-model / atif-user-observation suites) loading a document
//      whose user message carries an astral-plane character exactly at
//      the 300-unit clip boundary — the collapsed ExpandableText must
//      display a well-formed string that never ends mid-pair.

const babel = require('@babel/core');

function transpile(relativePath) {
  const out = babel.transformFileSync(join(process.cwd(), relativePath), {
    presets: [
      ['@babel/preset-env', { targets: { node: 'current' } }],
      ['@babel/preset-typescript', { isTSX: true, allExtensions: true }],
      ['@babel/preset-react', { runtime: 'classic' }],
    ],
  });
  return out.code;
}

function loadModuleFromCode(code, moduleStubs) {
  const module = { exports: {} };
  const reactStub = {
    __esModule: true,
    default: {
      createElement: (type, props, ...children) => ({ type, props, children }),
      Fragment: Symbol.for('react.fragment'),
    },
    createElement: (type, props, ...children) => ({ type, props, children }),
  };
  const requireStub = (name) => {
    if (name === 'react') return reactStub;
    if (moduleStubs[name]) return moduleStubs[name];
    throw new Error(`unexpected require: ${name}`);
  };
  const fn = new Function('require', 'module', 'exports', code);
  fn(requireStub, module, module.exports);
  return module.exports;
}

function realModule(relativePath) {
  return loadModuleFromCode(transpile(relativePath), {});
}

// ─── 1. Direct fixtures on the shared utility ────────────────────────────────

const CAT = '\u{1f431}';   // U+1F431, one code point, two UTF-16 units
const ELLIPSIS = '\u2026';

// A lone (unpaired) high surrogate — what a mid-pair cut leaves behind.
const hasLoneSurrogate = (s) => /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(s);

function loadTruncateText() {
  const util = realModule('src/utils/truncate.ts');
  assert.equal(typeof util.truncateText, 'function', 'truncateText must be exported');
  return util.truncateText;
}

test('truncateText: short and exact-length text pass through unchanged', () => {
  const truncateText = loadTruncateText();
  assert.equal(truncateText('short', 300), 'short');
  assert.equal(truncateText('a'.repeat(300), 300), 'a'.repeat(300));
  // Astral characters count as one unit each, not two.
  assert.equal(truncateText(CAT.repeat(3), 3), CAT.repeat(3));
});

test('truncateText: a cut that would split a surrogate pair lands before it whole', () => {
  const truncateText = loadTruncateText();
  // 299 units of ASCII + one astral character: main's unit cut kept the
  // pair's high surrogate and dropped the low one; counting code points,
  // the emoji is the 300th character and survives the clip whole.
  const text = 'a'.repeat(299) + CAT + ' tail';
  const cut = truncateText(text, 300);
  assert.equal(cut, 'a'.repeat(299) + CAT + ELLIPSIS);
  assert.ok(!hasLoneSurrogate(cut), 'the cut must never end mid-pair');
});

test('truncateText: a cut between code points keeps whole characters', () => {
  const truncateText = loadTruncateText();
  // 298 units of ASCII + one astral character + a tail: the 300th code
  // point is the first tail character, so the emoji and one 'b' fit.
  const text = 'a'.repeat(298) + CAT + 'b'.repeat(10);
  const cut = truncateText(text, 300);
  assert.equal(cut, 'a'.repeat(298) + CAT + 'b' + ELLIPSIS);
  assert.ok(!hasLoneSurrogate(cut));
  // Astral-only content: three whole cats fit, the fourth is cut whole.
  assert.equal(truncateText(CAT.repeat(4), 3), CAT.repeat(3) + ELLIPSIS);
});

// ─── 2. Compiled production viewer integration ───────────────────────────────

function createHooksDriver() {
  const slots = [];
  const driver = {
    slots,
    render(Component, props = {}) {
      driver._cursor = 0;
      return Component(props);
    },
    useState(initial) {
      const slot = slots[driver._cursor] ?? {
        value: typeof initial === 'function' ? initial() : initial,
      };
      slots[driver._cursor] = slot;
      if (!slot.setter) {
        slot.setter = (update) => {
          slot.value = typeof update === 'function' ? update(slot.value) : update;
        };
      }
      driver._cursor += 1;
      return [slot.value, slot.setter];
    },
    useRef(initial) {
      const slot = slots[driver._cursor] ?? { value: { current: initial } };
      slots[driver._cursor] = slot;
      driver._cursor += 1;
      return slot.value;
    },
    useEffect(fn) { driver._pendingEffect = fn; },
    useCallback(fn) { return fn; },
    useMemo(factory) { return factory(); },
  };
  return driver;
}

function findElements(node, predicate, out = []) {
  if (Array.isArray(node)) {
    node.forEach((child) => findElements(child, predicate, out));
  } else if (node && typeof node === 'object' && node.type) {
    if (predicate(node)) out.push(node);
    findElements(node.children, predicate, out);
  }
  return out;
}

// Invoke the production component functions found in a createElement-stub
// tree (each on fresh hook slots) and collect every rendered string.
function renderTreeText(node, driver, out = [], depth = 0) {
  if (depth > 16) return out;
  if (node === null || node === undefined || typeof node === 'boolean') return out;
  if (typeof node === 'string' || typeof node === 'number') {
    out.push(String(node));
    return out;
  }
  if (Array.isArray(node)) {
    for (const child of node) renderTreeText(child, driver, out, depth);
    return out;
  }
  if (node && typeof node === 'object' && typeof node.type === 'function') {
    driver._cursor = driver.slots.length;
    // Real React hands JSX children to the component through props.children
    // (a lone child unwrapped from the array); mirror that so container
    // components actually receive their content.
    const props = { ...node.props };
    if (Array.isArray(node.children) && node.children.length > 0) {
      props.children = node.children.length === 1 ? node.children[0] : node.children;
    }
    const rendered = node.type(props);
    return renderTreeText(rendered, driver, out, depth + 1);
  }
  if (node && typeof node === 'object' && node.children) {
    return renderTreeText(node.children, driver, out, depth);
  }
  return out;
}

const viewerT = (key, params) => {
  if (key === 'atif.round') return `Round ${params.n}`;
  if (key === 'atif.preamble') return 'Preamble';
  return params ? `${key} ${JSON.stringify(params)}` : key;
};

function loadViewer(searchParamsInit, driver, apiStubs) {
  const roundModel = realModule('src/utils/roundModel.ts');
  const trajectoryTree = realModule('src/utils/trajectoryTree.ts');
  const trajectoryTextFilter = realModule('src/utils/trajectoryTextFilter.ts');
  const truncate = realModule('src/utils/truncate.ts');
  // Transport note (MA5p rebase): main's savings-rate wave added a
  // ../utils/savings import to AtifViewerPage; stub it from source like the
  // other real modules so the page still runs the real formula.
  const savings = realModule('src/utils/savings.ts');
  const spHolder = { params: new URLSearchParams(searchParamsInit) };
  const moduleStubs = {
    'react-router-dom': {
      useSearchParams: () => [spHolder.params, (next) => { spHolder.params = new URLSearchParams(next); }],
    },
    '../i18n': {
      useI18n: () => ({ t: viewerT }),
      useLocaleTag: () => 'en-US',
    },
    '../utils/apiClient': apiStubs,
    '../utils/roundModel': roundModel,
    '../utils/savings': savings,
    '../utils/trajectoryTree': trajectoryTree,
    '../utils/trajectoryTextFilter': trajectoryTextFilter,
    '../utils/truncate': truncate,
    '../components/SubagentGraph': { SubagentGraph: () => null },
    '../components/CausalAttributionPanel': { CausalAttributionPanel: () => null },
  };
  const hooks = {
    useState: driver.useState,
    useRef: driver.useRef,
    useEffect: driver.useEffect,
    useCallback: driver.useCallback,
    useMemo: driver.useMemo,
  };
  const reactWithHooks = {
    __esModule: true,
    default: {
      createElement: (type, props, ...children) => ({ type, props, children }),
      Fragment: Symbol.for('react.fragment'),
      ...hooks,
    },
    createElement: (type, props, ...children) => ({ type, props, children }),
    ...hooks,
  };
  const code = transpile('src/pages/AtifViewerPage.tsx');
  const module = { exports: {} };
  const requireStub = (name) => {
    if (name === 'react') return reactWithHooks;
    if (moduleStubs[name]) return moduleStubs[name];
    throw new Error(`unexpected require from AtifViewerPage: ${name}`);
  };
  new Function('require', 'module', 'exports', code)(requireStub, module, module.exports);
  return module.exports.AtifViewerPage;
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

async function renderLoadedViewer(doc) {
  const deferreds = [];
  const defer = () => {
    const d = {};
    d.promise = new Promise((resolve) => { d.resolve = resolve; });
    deferreds.push(d);
    return d.promise;
  };
  const apiStubs = {
    fetchAtifBySession: () => defer(),
    fetchAtifByConversation: () => Promise.reject(new Error('not used')),
    fetchTrajectoryAtif: () => Promise.reject(Object.assign(new Error('gone'), { status: 404 })),
    fetchSessionSavings: () => Promise.resolve({ items: [] }),
  };
  const driver = createHooksDriver();
  const Page = loadViewer('type=session&id=sess-fixture', driver, apiStubs);

  driver.render(Page);                    // mount render; records the auto-load effect
  const autoLoad = driver._pendingEffect; // eslint-disable-line no-underscore-dangle
  autoLoad();                             // mount auto-load fires handleLoad
  assert.equal(deferreds.length, 1, 'handleLoad must fetch the session document');
  deferreds[0].resolve(doc);
  await settle();
  await settle();

  const rendered = driver.render(Page);   // re-render with the loaded document
  return { driver, rendered };
}

test('the collapsed step message never ends inside a surrogate pair', async () => {
  // 299 ASCII units + an astral-plane character + a tail: the message is
  // longer than the 300-unit clip, and the clip boundary lands exactly
  // inside the emoji's surrogate pair.
  const doc = {
    schema_version: 'ATIF-v1.7',
    session_id: 'fixture-emoji-cut',
    agent: { name: 'qoder', version: 'fixture' },
    steps: [{
      step_id: 1, source: 'user',
      message: 'a'.repeat(299) + CAT + ' tail text',
    }],
  };
  const { rendered, driver } = await renderLoadedViewer(doc);

  // Render the production StepCard (inside the round detail's output).
  const detail = findElements(
    rendered,
    (el) => el.props && el.props.round && el.props.expandedSections instanceof Set && el.props.onToggleSection,
  )[0];
  assert.ok(detail, 'the round detail column renders');
  driver._cursor = driver.slots.length;
  const cards = findElements(detail.type(detail.props), (el) => el.props && el.props.step && el.props.onToggleSection);
  assert.equal(cards.length, 1, 'the round renders one step card');

  const strings = renderTreeText(cards[0], driver);
  // The collapsed display of the long message (isLong -> clipped + ellipsis).
  const clipped = strings.find((s) => s.endsWith(ELLIPSIS) && s.startsWith('a'.repeat(100)));
  assert.ok(clipped, 'the collapsed message renders with an ellipsis');
  assert.ok(!hasLoneSurrogate(clipped), 'the clip must not leave a lone surrogate half');
  assert.equal(clipped, 'a'.repeat(299) + CAT + ELLIPSIS,
    'the emoji is the 300th code point and survives the clip whole');
});

test('a message whose clip boundary sits between code points keeps whole characters', async () => {
  // 298 ASCII units + one astral character: the 300-unit clip ends exactly
  // after the complete pair, so the emoji survives the collapse.
  const doc = {
    schema_version: 'ATIF-v1.7',
    session_id: 'fixture-emoji-whole',
    agent: { name: 'qoder', version: 'fixture' },
    steps: [{
      step_id: 1, source: 'user',
      message: 'a'.repeat(298) + CAT + 'b'.repeat(10),
    }],
  };
  const { rendered, driver } = await renderLoadedViewer(doc);

  const detail = findElements(
    rendered,
    (el) => el.props && el.props.round && el.props.expandedSections instanceof Set && el.props.onToggleSection,
  )[0];
  driver._cursor = driver.slots.length;
  const cards = findElements(detail.type(detail.props), (el) => el.props && el.props.step && el.props.onToggleSection);
  const strings = renderTreeText(cards[0], driver);
  const clipped = strings.find((s) => s.endsWith(ELLIPSIS) && s.startsWith('a'.repeat(100)));
  assert.ok(clipped, 'the collapsed message renders with an ellipsis');
  assert.equal(clipped, 'a'.repeat(298) + CAT + 'b' + ELLIPSIS,
    'complete code points before the boundary must survive the clip');
});
