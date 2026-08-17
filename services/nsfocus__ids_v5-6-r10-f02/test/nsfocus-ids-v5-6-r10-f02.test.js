import assert from 'node:assert/strict';
import test from 'node:test';

import { GrpcError, grpcStatus } from '@chaitin-ai/octobus-sdk';

import {
  QUERY_EVENT_LIST_PATH,
  METHOD_QUERY_EVENT_LIST_FULL,
  EVENT_LIST_URI,
  EVENT_REFERER_PATH,
  _test,
  handlers,
  rpcdef,
} from '../src/nsfocus-ids-v5-6-r10-f02.js';
import { service } from '../src/service.js';
import { createMockServer } from './mock_upstream.js';

const originalFetch = globalThis.fetch;
let seq = 0;
const nextId = () => `inst-${++seq}`;

const buildCtx = (mock, overrides = {}) => ({
  bindings: { host: mock?.host, cookie: mock?.cookie, ...(overrides.bindings || {}) },
  config: overrides.config || {},
  secret: overrides.secret || {},
  limits: { timeoutMs: 10_000, ...(overrides.limits || {}) },
  meta: { instance_id: nextId(), request_id: 'req', ...(overrides.meta || {}) },
  req: overrides.req || {},
});

const createHeaders = (entries = {}) => {
  const map = new Map();
  for (const [k, v] of Object.entries(entries)) map.set(String(k).toLowerCase(), Array.isArray(v) ? v.map(String) : [String(v)]);
  return { get(n) { const x = map.get(String(n).toLowerCase()); return x?.length ? x.join(', ') : null; } };
};
const fakeResponse = (status, body, ok = status >= 200 && status < 300) => ({ status, ok, headers: createHeaders(), text: async () => body });
const withFetch = (impl) => { globalThis.fetch = impl; };
const callHandler = (ctx, request = ctx.req ?? {}) => handlers[METHOD_QUERY_EVENT_LIST_FULL]({ ...ctx, request });

test.afterEach(() => { globalThis.fetch = originalFetch; });

// ---------- end-to-end against mock ----------

test('parses IDS event table into structured events', async () => {
  const mock = await createMockServer();
  try {
    const out = await rpcdef(buildCtx(mock))[QUERY_EVENT_LIST_PATH]({});
    assert.equal(out.http_status, 200);
    assert.equal(out.total, mock.rowCount);
    const e0 = out.entries[0];
    assert.deepEqual(e0, {
      severity: '低', action: '允许', time: '2026-06-25 16:11:27',
      event_id: '40432', event_name: 'HTTP服务基本登录认证',
      src_ip: '198.51.100.10', src_port: '54511', dst_ip: '203.0.113.5', dst_port: '80',
      auth_user: '', linked_account: '',
    });
    // proxy row: 代理IP img stripped, ip:port still parsed
    const e1 = out.entries[1];
    assert.equal(e1.severity, '中');
    assert.equal(e1.event_id, '60249');
    assert.equal(e1.src_ip, '192.0.2.9');
    assert.equal(e1.src_port, '30879');
    // request shape
    const r = mock.state.requests[0];
    assert.equal(r.method, 'GET');
    assert.equal(r.url, EVENT_LIST_URI);
    assert.equal(r.headers.cookie, mock.cookie);
    assert.equal(r.headers['x-requested-with'], 'XMLHttpRequest');
    assert.equal(r.headers.referer, `${mock.host}${EVENT_REFERER_PATH}`);
  } finally {
    await mock.close();
  }
});

test('limit caps the number of returned events', async () => {
  const mock = await createMockServer();
  try {
    const out = await callHandler(buildCtx(mock), { limit: 1 });
    assert.equal(out.total, 1);
  } finally {
    await mock.close();
  }
});

test('expired session (login page, no mytable) -> FAILED_PRECONDITION', async () => {
  const mock = await createMockServer();
  try {
    await assert.rejects(
      () => callHandler(buildCtx(mock, { bindings: { cookie: 'PHPSESSID=wrong' } })),
      (e) => e.legacyCode === 'FAILED_PRECONDITION',
    );
  } finally {
    await mock.close();
  }
});

// ---------- validation ----------

test('binding validation', async () => {
  await assert.rejects(() => callHandler(buildCtx({ host: '' })), (e) => e.legacyCode === 'INVALID_ARGUMENT');
  await assert.rejects(() => callHandler(buildCtx({ host: 'https://h', cookie: '' })), (e) => e.legacyCode === 'INVALID_ARGUMENT');
});

// ---------- error mapping ----------

test('error mapping: network / http', async () => {
  const ctx = buildCtx({ host: 'https://ids', cookie: 'c=1' });
  withFetch(async () => { throw new Error('ECONNREFUSED'); });
  await assert.rejects(() => callHandler(ctx), (e) => e.legacyCode === 'UNAVAILABLE');
  withFetch(async () => fakeResponse(401, 'no', false));
  await assert.rejects(() => callHandler(ctx), (e) => e.legacyCode === 'PERMISSION_DENIED');
  withFetch(async () => fakeResponse(404, 'no', false));
  await assert.rejects(() => callHandler(ctx), (e) => e.legacyCode === 'FAILED_PRECONDITION');
  withFetch(async () => fakeResponse(500, 'no', false));
  await assert.rejects(() => callHandler(ctx), (e) => e.legacyCode === 'UNAVAILABLE');
});

test('transport failures redact credential and upstream details', async () => {
  const ctx = buildCtx({ host: 'https://ids', cookie: 'c=1' });
  withFetch(async () => { throw {}; });
  await assert.rejects(() => callHandler(ctx), (e) => /upstream request failed/.test(e.message));
  withFetch(async () => { const e = new Error('m'); e.cause = { message: 'deep' }; throw e; });
  await assert.rejects(() => callHandler(ctx), (e) => !e.message.includes('deep') && !e.message.includes('c=1'));
});

test('valid event page with zero data rows returns empty entries', async () => {
  const ctx = buildCtx({ host: 'https://ids', cookie: 'c=1' });
  withFetch(async () => fakeResponse(200, '<table id="mytable"><tr class="first_title"><th>状态</th></tr></table>'));
  const out = await callHandler(ctx);
  assert.equal(out.total, 0);
  assert.deepEqual(out.entries, []);
});

// ---------- service surface + helpers ----------

test('service exposes the QueryEventList handler', () => {
  assert.equal(typeof service.handlers[METHOD_QUERY_EVENT_LIST_FULL], 'function');
});

test('helper coverage', () => {
  const h = _test;
  assert.equal(h.normalizeBaseUrl('https://h/'), 'https://h');
  assert.equal(h.normalizeBaseUrl('ftp://x'), '');
  assert.equal(h.normalizeBaseUrl('https://user:password@h'), '');
  assert.equal(h.resolveCookie({ session_cookie: 'c' }), 'c');
  assert.equal(h.resolveCookie({ sessionCookie: 'c2' }), 'c2');
  assert.equal(h.resolveHost({ host: 'missing-scheme', restBaseUrl: 'https://ids' }), 'https://ids');
  assert.equal(h.decodeEntities('a&amp;b&lt;c&gt;&quot;&#39;&nbsp;d'), 'a&b<c>"\' d');
  assert.equal(h.stripTags('<b> 1.2.3.4 </b>&nbsp;:80'), '1.2.3.4 :80');
  assert.deepEqual(h.attrTitles('<img title="低危险程度"><img title="允许">'), ['低危险程度', '允许']);
  assert.deepEqual(h.splitIpPort('<i></i>1.2.3.4:8080'), { ip: '1.2.3.4', port: '8080' });
  assert.deepEqual(h.splitIpPort('noport'), { ip: 'noport', port: '' });

  // parseEventList: skip header/non-data rows, require datetime
  const mkRow = (cls, time, withProxy, beforeClass = '') => `<tr ${beforeClass} class="${cls}">`
    + `<td><img title="高危险程度"><img title="阻断"><img title="反馈厂商"></td>`
    + `<td>${time}</td>`
    + `<td><a>[123]&nbsp;测试事件</a></td>`
    + `<td>${withProxy ? '<img title="代理IP">&nbsp;' : ''}1.1.1.1:11</td>`
    + '<td>2.2.2.2:22</td><td>u1</td><td>a1</td></tr>';
  const html = '<tr class="first_title"><th>x</th></tr>'
    + mkRow('even', '2026-01-02 03:04:05', false)
    + mkRow('odd', 'not-a-time', false)
    + mkRow('even', '2026-01-02 03:04:06', true, 'data-row="two"');
  const parsed = h.parseEventList(html);
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].severity, '高');
  assert.equal(parsed[0].action, '阻断');
  assert.equal(parsed[0].event_id, '123');
  assert.equal(parsed[0].event_name, '测试事件');
  assert.equal(parsed[0].auth_user, 'u1');
  assert.equal(parsed[1].src_ip, '1.1.1.1'); // proxy img stripped
  assert.equal(h.parseEventList(html, 1).length, 1);
  // anchor without [id] pattern falls back to raw text as name
  const noId = '<tr class="even"><td><img title="低危险程度"></td><td>2026-01-02 03:04:05</td><td><a>纯文本事件</a></td><td>1.1.1.1:1</td><td>2.2.2.2:2</td></tr>';
  assert.equal(h.parseEventList(noId)[0].event_name, '纯文本事件');

  assert.equal(h.pickInt({ a: '5' }, ['a'], 0), 5);
  assert.equal(h.pickInt({ a: '' }, ['a'], 9), 9);
  assert.equal(h.pickFirstString([null, '', 'y']), 'y');
  assert.equal(h.pickBoolean('off'), false);
  assert.equal(h.pickBoolean(true), true);
  assert.equal(h.pickBoolean(0), false);
  assert.equal(h.pickBoolean('maybe'), undefined);
  assert.equal(h.pickBoolean(Number.NaN), undefined);
  assert.equal(h.pickFirstBoolean(['x', 'true']), true);
  assert.equal(h.unwrapScalar({ value: { value: 2 } }), 2);
  assert.equal(h.hasOwn({}, 'missing'), false);
  assert.deepEqual(h.sanitizeHeaders({ A: 1, '': 2 }), { A: '1' });
  assert.deepEqual(h.sanitizeHeaders('x'), {});
  assert.ok(h.buildTlsOptions({ skipTlsVerify: true }, 'https://h').dispatcher);
  assert.deepEqual(h.buildTlsOptions({ skipTlsVerify: true }, 'http://h'), {});
  assert.deepEqual(h.buildTlsOptions({}), {});
  assert.equal(h.resolveTimeoutMs({ limits: { timeoutMs: 0 } }), 5000);
  assert.equal(h.resolveTimeoutMs({ limits: { timeoutMs: 321 } }), 321);
  assert.equal(h.grpcCodeFor('NOPE'), grpcStatus.UNKNOWN);
  assert.ok(h.errorWithCode('UNAVAILABLE', 'x') instanceof GrpcError);
  assert.throws(() => h.throwForHttpStatus(403), (e) => e.legacyCode === 'PERMISSION_DENIED');
  assert.throws(() => h.throwForHttpStatus(302), (e) => e.legacyCode === 'FAILED_PRECONDITION');
  assert.throws(() => h.throwForHttpStatus(500), (e) => e.legacyCode === 'UNAVAILABLE');
  const hdr = h.buildHeaders({ headers: { 'X-A': '1' } }, { instance_id: 'i', request_id: 'r' }, { cookie: 'c=1', refererUrl: 'https://h/ips/event' });
  assert.equal(hdr.cookie, 'c=1');
  assert.equal(hdr.referer, 'https://h/ips/event');
  assert.equal(hdr['x-requested-with'], 'XMLHttpRequest');
  assert.equal(hdr['X-A'], '1');
  assert.deepEqual(h.resolveCallContext({ request: { a: 1 } }).req, { a: 1 });
  assert.deepEqual(h.resolveCallContext({}).req, {});
  assert.deepEqual(h.requestFromContext({ req: { b: 2 } }), { b: 2 });
  assert.deepEqual(h.requestFromContext({}), {});
  assert.equal(h.resolveMaxResponseBytes({ limits: { maxResponseBytes: 99 } }), 99);
  assert.equal(h.resolveMaxResponseBytes({ limits: { maxResponseBytes: 999999999 } }), 10 * 1024 * 1024);
  assert.equal(h.resolveMaxResponseBytes({ limits: { maxResponseBytes: 0 } }), 4 * 1024 * 1024);
});

test('transport uses SDK-0.6 single context, timeout, manual redirects and bounded responses', async () => {
  const ctx = buildCtx({ host: 'https://ids', cookie: 'secret-cookie' });
  let init;
  withFetch(async (_url, options) => { init = options; return fakeResponse(200, '<table id="mytable"></table>'); });
  await callHandler(ctx);
  assert.equal(init.redirect, 'manual');
  assert.ok(init.signal instanceof AbortSignal);
  assert.equal(init.headers.cookie, 'secret-cookie');
  assert.equal(init.headers.referer, 'https://ids/ips/event');
  assert.equal(init.headers['x-requested-with'], 'XMLHttpRequest');

  withFetch(async () => fakeResponse(302, '<html>login</html>', false));
  await assert.rejects(() => callHandler(ctx), (e) => e.legacyCode === 'FAILED_PRECONDITION');
  withFetch(async () => ({ ...fakeResponse(200, '<table id="mytable"></table>'), headers: createHeaders({ 'content-length': '4097' }) }));
  await assert.rejects(() => callHandler(buildCtx({ host: 'https://ids', cookie: 'secret-cookie' }, { limits: { maxResponseBytes: 4096 } })), (e) => e.legacyCode === 'RESOURCE_EXHAUSTED');
  withFetch(async () => { const error = new Error('timeout'); error.name = 'TimeoutError'; throw error; });
  await assert.rejects(() => callHandler(ctx), (e) => e.legacyCode === 'DEADLINE_EXCEEDED');
});

test('streaming response bounds cancel oversized bodies and map read errors', async () => {
  let cancelled = false;
  const oversizedReader = {
    async read() { return { done: false, value: new Uint8Array(5) }; },
    async cancel() { cancelled = true; },
  };
  await assert.rejects(
    () => _test.readBoundedText({ headers: createHeaders(), body: { getReader: () => oversizedReader } }, 4),
    (e) => e.legacyCode === 'RESOURCE_EXHAUSTED',
  );
  assert.equal(cancelled, true);
  const failingReader = { async read() { throw new Error('stream fail'); } };
  await assert.rejects(
    () => _test.readBoundedText({ headers: createHeaders(), body: { getReader: () => failingReader } }, 4),
    (e) => e.legacyCode === 'UNAVAILABLE',
  );
  await assert.rejects(
    () => _test.readBoundedText({ headers: createHeaders(), text: async () => { throw new Error('read fail'); } }, 4),
    (e) => e.legacyCode === 'UNAVAILABLE',
  );
  await assert.rejects(
    () => _test.readBoundedText({ headers: createHeaders(), text: async () => '12345' }, 4),
    (e) => e.legacyCode === 'RESOURCE_EXHAUSTED',
  );
});

test('decodes device response using the declared GBK charset', () => {
  const response = { headers: createHeaders({ 'content-type': 'text/html; charset=gb2312' }) };
  assert.equal(_test.responseCharset(response), 'gb2312');
  assert.equal(_test.decodeResponseBytes(Uint8Array.from([0xb5, 0xcd]), response), '低');
  assert.throws(
    () => _test.decodeResponseBytes(Uint8Array.from([1]), { headers: createHeaders({ 'content-type': 'text/html; charset=x-invalid-charset' }) }),
    (e) => e.legacyCode === 'FAILED_PRECONDITION',
  );
});

test('rejects unrecognized event rows instead of reporting zero alerts', async () => {
  withFetch(async () => fakeResponse(200, '<table id="mytable"><tr class="event-row"><td>低</td><td>2026-01-02 03:04:05</td><td>event</td><td>192.0.2.1:1</td><td>192.0.2.2:2</td></tr></table>'));
  await assert.rejects(
    () => callHandler(buildCtx({ host: 'https://ids', cookie: 'secret-cookie' })),
    (e) => e.legacyCode === 'FAILED_PRECONDITION',
  );
});

test('maps HTTP status before reading an oversized error page', async () => {
  withFetch(async () => ({
    ...fakeResponse(403, '', false),
    headers: createHeaders({ 'content-length': '999999' }),
    text: async () => { throw new Error('must not read'); },
  }));
  await assert.rejects(
    () => callHandler(buildCtx({ host: 'https://ids', cookie: 'secret-cookie' }, { limits: { maxResponseBytes: 1 } })),
    (e) => e.legacyCode === 'PERMISSION_DENIED',
  );
});

test('rpcdef falls back to ctx.req when called without an argument', async () => {
  const mock = await createMockServer();
  try {
    const out = await rpcdef(buildCtx(mock, { req: { limit: 1 } }))[QUERY_EVENT_LIST_PATH]();
    assert.equal(out.total, 1);
  } finally {
    await mock.close();
  }
});
