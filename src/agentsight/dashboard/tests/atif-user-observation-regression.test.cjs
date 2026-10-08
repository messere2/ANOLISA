const assert = require('node:assert/strict');
const { join } = require('node:path');
const test = require('node:test');

// Behavioral regression for the ATIF viewer user-step observation fix
// (#6593): the collector intentionally keeps a mixed text/tool-result
// event's observation on its user step when no preceding step exists
// (atif.rs, test_convert_mixed_tool_result_without_assistant_keeps_
// observation_and_text), but StepCard rendered the Observation section
// only inside `step.source === 'agent'`, so a document imported into the
// viewer matched the round through the content filter while the stored
// result stayed invisible inside the opened round.
//
// The REAL AtifViewerPage is transpiled with the dashboard's babel
// toolchain (same driver as the round-model and atif-import-deferred
// suites): the page loads a document through its own loader with
// highlight_call_id pointing at the user step's observation, then the
// production StepCard elements found in the rendered tree are invoked
// and their text collected, so the assertions exercise the real section
// gating — including the Collapsible/ExpandableText/ToolCallItem
// subtrees — rather than a hand-written stand-in.

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
  return loadModuleFromCode(transpile(relativePath), {
    // roundModel / trajectoryTree / trajectoryTextFilter only type-import
    // i18n and types (erased by the typescript preset).
  });
}

function createHooksDriver() {
  const slots = [];
  const driver = {
    slots,
    render(Component, props = {}) {
      driver._cursor = 0;
      const element = Component(props);
      return element;
    },
    useState(initial) {
      const slot = slots[driver._cursor] ?? {
        value: typeof initial === 'function' ? initial() : initial,
      };
      slots[driver._cursor] = slot;
      if (!slot.setter) {
        slot.setter = (update) => {
          slot.value = typeof update === 'function'
            ? update(slot.value)
            : update;
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

/** Every element in the tree matching predicate(element). */
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
// tree (each on fresh hook slots so page-render state is never clobbered)
// and collect every rendered string, so text produced inside nested
// components (Collapsible titles, ExpandableText bodies, ToolCallItem
// headers) is asserted as well.
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
    // components like Collapsible actually receive their content.
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

// Deterministic translator: round labels like the round-model fixtures,
// everything else renders as "<key> <json params>" so chips and section
// headers stay assertable.
const viewerT = (key, params) => {
  if (key === 'atif.round') return `Round ${params.n}`;
  if (key === 'atif.preamble') return 'Preamble';
  return params ? `${key} ${JSON.stringify(params)}` : key;
};

function loadViewer(searchParamsInit, driver, apiStubs) {
  const roundModel = realModule('src/utils/roundModel.ts');
  const trajectoryTree = realModule('src/utils/trajectoryTree.ts');
  const trajectoryTextFilter = realModule('src/utils/trajectoryTextFilter.ts');
  // Transport note (MA5o rebase): main added the savings-rate wave import to
  // AtifViewerPage (compoundedSavingsRate), so the viewer now requires it too.
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
    '../utils/trajectoryTree': trajectoryTree,
    '../utils/trajectoryTextFilter': trajectoryTextFilter,
    '../utils/savings': savings,
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

async function renderLoadedViewer(doc, { highlightCallId } = {}) {
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
  const search = highlightCallId
    ? `type=session&id=sess-fixture&highlight_call_id=${highlightCallId}`
    : 'type=session&id=sess-fixture';
  const Page = loadViewer(search, driver, apiStubs);

  driver.render(Page);                    // mount render; records the auto-load effect
  const autoLoad = driver._pendingEffect; // eslint-disable-line no-underscore-dangle
  const loadPromise = autoLoad();         // mount auto-load fires handleLoad
  assert.equal(deferreds.length, 1, 'handleLoad must fetch the session document');
  deferreds[0].resolve(doc);
  await loadPromise;
  await settle();
  await settle();

  const rendered = driver.render(Page);   // re-render with the loaded document
  return { driver, rendered, Page };
}

// StepCard elements: the only components receiving a `step` plus the
// shared section-collapse callbacks. They live inside the RoundDetail's
// render output, so the detail element is invoked first (on fresh hook
// slots so page-render state is never clobbered).
const isStepCard = (el) => el.props && el.props.step && el.props.onToggleSection;

function stepCards(rendered, driver) {
  const detail = findElements(
    rendered,
    (el) => el.props && el.props.round && el.props.expandedSections instanceof Set && el.props.onToggleSection,
  )[0];
  assert.ok(detail, 'the round detail column renders');
  driver._cursor = driver.slots.length;
  const detailTree = detail.type(detail.props);
  return findElements(detailTree, isStepCard);
}

// The exact reproduction document from the issue: a mixed text/tool-result
// event whose observation the collector kept on its user step because no
// preceding step exists.
function replayedContextDocument() {
  return {
    schema_version: 'ATIF-v1.7',
    session_id: 'fixture-replayed-context',
    agent: { name: 'qoder', version: 'fixture' },
    steps: [{
      step_id: 1, source: 'user', message: 'also update the docs',
      observation: { results: [{ source_call_id: 't1', content: 'fixture tool output' }] },
    }],
  };
}

test('a user step observation kept by the collector renders in its round', async () => {
  const { rendered, driver } = await renderLoadedViewer(replayedContextDocument(), { highlightCallId: 't1' });

  const cards = stepCards(rendered, driver);
  assert.equal(cards.length, 1, 'the document has a single step card');
  assert.equal(cards[0].props.step.source, 'user', 'the step card is the user turn');

  // The viewer itself considers the section openable: the highlight wiring
  // already expands the user step's observation section key.
  assert.ok(cards[0].props.expandedSections.has('1-observation'),
    'the highlight must expand the user step observation section');

  const text = renderTreeText(cards[0], driver).join(' ');
  // Control: the user message renders (the round is open and alive).
  assert.ok(text.includes('also update the docs'),
    'the user message renders');
  // The stored observation must be visible in the opened round.
  assert.ok(text.includes('atif.observation'),
    'the user step must render its observation section header');
  assert.ok(text.includes('fixture tool output'),
    'the stored observation result must be visible in the round');
  assert.ok(text.includes('atif.callLabel'),
    'the observation names its source call');
});

test('searching the observation content still matches the round', async () => {
  const { rendered, driver, Page } = await renderLoadedViewer(replayedContextDocument(), { highlightCallId: 't1' });

  // Drive the real round filter input: the issue reports that searching
  // `fixture tool output` matches the round without making the result
  // visible — the filter reads observation content, so the match must hold.
  const searchInput = findElements(rendered, (el) => el.props && el.props.type === 'search')[0];
  assert.ok(searchInput, 'the round filter input renders');
  searchInput.props.onChange({ target: { value: 'fixture tool output' } });
  const filtered = driver.render(Page);

  const liveChip = findElements(filtered, (el) => el.props && el.props['aria-live'] === 'polite')[0];
  assert.ok(liveChip, 'the matching-rounds chip renders');
  const chips = renderTreeText(liveChip, driver).join(' ');
  assert.ok(chips.includes('"matched":1'), 'the observation content keeps matching the round filter');
});

test('user steps do not grow agent-only sections', async () => {
  // A user step carrying reasoning, tool calls and metrics next to its
  // observation: only the observation may become visible.
  const doc = {
    schema_version: 'ATIF-v1.7',
    session_id: 'sess-mixed-turns',
    agent: { name: 'qoder', version: 'fixture' },
    steps: [
      {
        step_id: 1, source: 'user', message: 'run the checks',
        reasoning_content: 'user planning must not render',
        tool_calls: [{ tool_call_id: 'tc-u', function_name: 'user_side_tool', arguments: { path: '/tmp' } }],
        observation: { results: [{ source_call_id: 'tc-u', content: 'user-side tool output' }] },
        metrics: { prompt_tokens: 3, completion_tokens: 4 },
      },
      {
        step_id: 2, source: 'agent', message: 'done',
        reasoning_content: 'agent planning renders',
        tool_calls: [{ tool_call_id: 'tc-a', function_name: 'agent_side_tool', arguments: { path: '/etc' } }],
        observation: { results: [{ source_call_id: 'tc-a', content: 'agent-side tool output' }] },
        metrics: { prompt_tokens: 30, completion_tokens: 40 },
      },
    ],
  };
  const { rendered, driver, Page } = await renderLoadedViewer(doc, { highlightCallId: 'tc-u' });

  const cards = stepCards(rendered, driver);
  assert.equal(cards.length, 2, 'both step cards render in the round');
  const bySource = Object.fromEntries(cards.map((c) => [c.props.step.source, c]));

  const userText = renderTreeText(bySource.user, driver).join(' ');
  assert.ok(userText.includes('user-side tool output'),
    'the user step observation renders');
  assert.ok(!userText.includes('user planning must not render'),
    'reasoning stays agent-only');
  assert.ok(!userText.includes('user_side_tool'),
    'tool calls stay agent-only');
  assert.ok(!userText.includes('atif.inputLabel'),
    'metrics stay agent-only');

  // The agent card keeps every section: open its collapsibles through the
  // page's own toggle wiring (the same path a user click takes).
  bySource.agent.props.onToggleSection('2-observation');
  bySource.agent.props.onToggleSection('2-reasoning');
  bySource.agent.props.onToggleSection('2-toolcalls');
  const reopened = stepCards(driver.render(Page), driver);
  const agentText = renderTreeText(
    reopened.find((c) => c.props.step.source === 'agent'), driver,
  ).join(' ');
  assert.ok(agentText.includes('agent-side tool output'), 'the agent observation still renders');
  assert.ok(agentText.includes('agent planning renders'), 'agent reasoning still renders');
  assert.ok(agentText.includes('agent_side_tool'), 'agent tool calls still render');
  assert.ok(agentText.includes('atif.inputLabel'), 'agent metrics still render');
});
