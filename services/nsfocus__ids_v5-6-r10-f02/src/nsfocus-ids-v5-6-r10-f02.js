// NSFOCUS IDS/IPS V5.6R10F02 event-list adapter. The upstream is an HTML page
// authenticated with a short-lived browser session cookie.
import { GrpcError, grpcStatus } from '@chaitin-ai/octobus-sdk';
import { Agent } from 'undici';

const SVC = 'NSFOCUS_IDS_V5_6_R10_F02.NSFOCUS_IDS_V5_6_R10_F02';
export const QUERY_EVENT_LIST_PATH = `/${SVC}/QueryEventList`;
export const METHOD_QUERY_EVENT_LIST_FULL = `${SVC}/QueryEventList`;
export const EVENT_LIST_URI = '/ips/eventList/detail/false/dns/false';
export const EVENT_REFERER_PATH = '/ips/event';
export const DEFAULT_TIMEOUT_MS = 5000;
export const MAX_TIMEOUT_MS = 120000;
export const DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
export const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

const DATETIME_RE = /\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/;
const NON_ACTION_TITLES = new Set(['反馈厂商', '下载pcap文件', '代理IP']);
let insecureDispatcher;

const grpcCodeFor = (code) => ({
  DEADLINE_EXCEEDED: grpcStatus.DEADLINE_EXCEEDED,
  FAILED_PRECONDITION: grpcStatus.FAILED_PRECONDITION,
  INVALID_ARGUMENT: grpcStatus.INVALID_ARGUMENT,
  PERMISSION_DENIED: grpcStatus.PERMISSION_DENIED,
  RESOURCE_EXHAUSTED: grpcStatus.RESOURCE_EXHAUSTED,
  UNAVAILABLE: grpcStatus.UNAVAILABLE,
  UNKNOWN: grpcStatus.UNKNOWN,
})[code] ?? grpcStatus.UNKNOWN;

const errorWithCode = (code, message) => {
  const err = new GrpcError(grpcCodeFor(code), `${code}: ${message}`);
  err.legacyCode = code;
  return err;
};

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj ?? {}, key);
const firstDefined = (...values) => values.find((value) => value !== undefined && value !== null);
const unwrapScalar = (value) => (value && typeof value === 'object' && hasOwn(value, 'value') ? unwrapScalar(value.value) : value);
const pickFirstString = (values = []) => {
  for (const value of values) {
    const text = String(unwrapScalar(value) ?? '').trim();
    if (text) return text;
  }
  return '';
};
const pickStringFrom = (source = {}, keys = []) => pickFirstString(keys.map((key) => source[key]));
const pickInt = (source = {}, keys = [], fallback = 0) => {
  for (const key of keys) {
    const raw = unwrapScalar(source[key]);
    if (raw === undefined || raw === null || raw === '') continue;
    const value = Number(raw);
    if (Number.isFinite(value)) return Math.trunc(value);
  }
  return fallback;
};
const pickBoolean = (value) => {
  const raw = unwrapScalar(value);
  if (typeof raw === 'boolean') return raw;
  if (typeof raw === 'number') return Number.isFinite(raw) ? raw !== 0 : undefined;
  if (typeof raw === 'string') {
    const text = raw.trim().toLowerCase();
    if (['true', '1', 'yes', 'y', 'on'].includes(text)) return true;
    if (['false', '0', 'no', 'n', 'off', ''].includes(text)) return false;
  }
  return undefined;
};
const pickFirstBoolean = (values = []) => values.map(pickBoolean).find((value) => value !== undefined);

const normalizeBaseUrl = (value) => {
  try {
    const url = new URL(String(unwrapScalar(value) ?? '').trim());
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) return '';
    return url.toString().replace(/\/+$/, '');
  } catch { return ''; }
};
const mergedBindings = (ctx = {}) => ({ ...(ctx.config ?? {}), ...(ctx.secret ?? {}), ...(ctx.bindings ?? {}) });
const resolveCallContext = (ctx = {}) => ({ ...ctx, bindings: mergedBindings(ctx), limits: ctx.limits ?? {}, meta: ctx.meta ?? {}, req: ctx.request ?? ctx.req ?? {} });
const requestFromContext = (ctx = {}) => ctx.request ?? ctx.req ?? {};
const resolveHost = (bindings = {}) => [bindings.host, bindings.restBaseUrl, bindings.baseUrl]
  .map(normalizeBaseUrl).find(Boolean) ?? '';
const resolveCookie = (bindings = {}) => pickStringFrom(bindings, ['cookie', 'sessionCookie', 'session_cookie']);
const resolveTimeoutMs = (ctx = {}) => {
  const value = Number(firstDefined(ctx.limits?.timeoutMs, ctx.bindings?.timeoutMs, DEFAULT_TIMEOUT_MS));
  return Number.isFinite(value) && value > 0 ? Math.min(Math.floor(value), MAX_TIMEOUT_MS) : DEFAULT_TIMEOUT_MS;
};
const resolveMaxResponseBytes = (ctx = {}) => {
  const value = Number(firstDefined(ctx.limits?.maxResponseBytes, ctx.bindings?.maxResponseBytes, DEFAULT_MAX_RESPONSE_BYTES));
  return Number.isSafeInteger(value) && value > 0 ? Math.min(value, MAX_RESPONSE_BYTES) : DEFAULT_MAX_RESPONSE_BYTES;
};
const buildTlsOptions = (bindings = {}, url = '') => {
  const skip = pickFirstBoolean([bindings.skipTlsVerify, bindings.tlsInsecureSkipVerify, bindings.insecureSkipVerify]) === true;
  if (!skip || !String(url).startsWith('https:')) return {};
  insecureDispatcher ??= new Agent({ connect: { rejectUnauthorized: false } });
  return { dispatcher: insecureDispatcher };
};
const sanitizeHeaders = (headers) => {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return {};
  return Object.fromEntries(Object.entries(headers).filter(([key]) => key).map(([key, value]) => [key, String(unwrapScalar(value) ?? '')]));
};
const buildHeaders = (bindings = {}, meta = {}, { cookie, refererUrl } = {}) => ({
  ...sanitizeHeaders(bindings.headers),
  accept: 'text/javascript, text/html, application/xml, text/xml, */*',
  'x-requested-with': 'XMLHttpRequest',
  cookie,
  referer: refererUrl,
  'x-engine-instance': pickFirstString([meta.instance_id, meta.instanceId, 'unknown']),
  'x-request-id': pickFirstString([meta.request_id, meta.requestId, 'unknown']),
});
const logTarget = (url) => {
  try { const target = new URL(url); return { origin: target.origin, path: target.pathname }; } catch { return {}; }
};
const logFlow = (ctx, action, details = {}) => {
  const meta = ctx?.meta ?? {};
  const trace = [meta.instance_id ?? meta.instanceId, meta.request_id ?? meta.requestId].filter(Boolean).join(' ');
  try { console.info(`[NSFOCUS_IDS][${action}]${trace ? `[${trace}]` : ''}`, JSON.stringify(details)); } catch { console.info(`[NSFOCUS_IDS][${action}]`, details); }
};
const requireBindings = (ctx = {}) => {
  const callCtx = resolveCallContext(ctx);
  const host = resolveHost(callCtx.bindings);
  if (!host) throw errorWithCode('INVALID_ARGUMENT', 'bindings.host is required and must be an http(s) URL without credentials');
  const cookie = resolveCookie(callCtx.bindings);
  if (!cookie) throw errorWithCode('INVALID_ARGUMENT', 'bindings.cookie (web session cookie) is required');
  return { ...callCtx, host, cookie };
};

const decodeEntities = (value) => String(value).replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&nbsp;/g, ' ');
const stripTags = (value) => decodeEntities(String(value).replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim();
const attrTitles = (cell) => [...String(cell).matchAll(/\btitle\s*=\s*(["'])(.*?)\1/gi)].map((match) => decodeEntities(match[2]));
const splitIpPort = (cell) => {
  const text = stripTags(cell); const index = text.lastIndexOf(':');
  return index <= 0 ? { ip: text, port: '' } : { ip: text.slice(0, index).trim(), port: text.slice(index + 1).trim() };
};
const hasEventTable = (html) => /<table\b[^>]*\bid\s*=\s*(["'])mytable\1[^>]*>/i.test(String(html));
const hasEventDataRows = (html) => {
  const table = (String(html).match(/<table\b[^>]*\bid\s*=\s*(["'])mytable\1[^>]*>([\s\S]*?)<\/table>/i) ?? [])[2] ?? '';
  const eventRowRe = /<tr\b(?=[^>]*\bclass\s*=\s*(["'])(?:even|odd)\1)[^>]*>/i;
  for (const row of table.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)) {
    const cells = [...row[1].matchAll(/<td\b[^>]*>([\s\S]*?)<\/td>/gi)].map((cell) => cell[1]);
    if (eventRowRe.test(row[0])) {
      if (cells.length === 1 && /<td\b[^>]*\bcolspan\s*=/i.test(row[1])) continue;
      return true;
    }
    if (cells.length >= 5 && cells.some((cell) => DATETIME_RE.test(stripTags(cell)))) return true;
  }
  return false;
};
const parseEventList = (html, limit = 0) => {
  const entries = [];
  const rowRe = /<tr\b(?=[^>]*\bclass\s*=\s*(["'])(?:even|odd)\1)[^>]*>([\s\S]*?)<\/tr>/gi;
  for (const match of String(html).matchAll(rowRe)) {
    const cells = [...match[2].matchAll(/<td\b[^>]*>([\s\S]*?)<\/td>/gi)].map((cell) => cell[1]);
    if (cells.length < 5) continue;
    const time = stripTags(cells[1]);
    if (!DATETIME_RE.test(time)) continue;
    const titles = attrTitles(cells[0]);
    const anchor = (cells[2].match(/<a\b[^>]*>([\s\S]*?)<\/a>/i) ?? [])[1] ?? '';
    const eventText = stripTags(anchor); const event = eventText.match(/\[(\d+)\]\s*(.*)/);
    const src = splitIpPort(cells[3]); const dst = splitIpPort(cells[4]);
    entries.push({
      severity: (titles.find((title) => title.endsWith('危险程度')) ?? '').replace('危险程度', ''),
      action: titles.find((title) => !title.endsWith('危险程度') && !NON_ACTION_TITLES.has(title)) ?? '',
      time, event_id: event?.[1] ?? '', event_name: event ? event[2].trim() : eventText,
      src_ip: src.ip, src_port: src.port, dst_ip: dst.ip, dst_port: dst.port,
      auth_user: stripTags(cells[5] ?? ''), linked_account: stripTags(cells[6] ?? ''),
    });
    if (limit > 0 && entries.length >= limit) break;
  }
  return entries;
};
const responseCharset = (response) => {
  const contentType = response.headers?.get?.('content-type') ?? '';
  return (String(contentType).match(/\bcharset\s*=\s*["']?([^\s;"']+)/i) ?? [])[1] || 'utf-8';
};
const decodeResponseBytes = (bytes, response) => {
  try { return new TextDecoder(responseCharset(response)).decode(bytes); }
  catch { throw errorWithCode('FAILED_PRECONDITION', 'upstream response uses an unsupported character encoding'); }
};
const readBoundedText = async (response, maxBytes) => {
  const declaredLength = Number(response.headers?.get?.('content-length') ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) throw errorWithCode('RESOURCE_EXHAUSTED', 'upstream response is too large');
  if (!response.body?.getReader) {
    if (typeof response.arrayBuffer === 'function') {
      let bytes;
      try { bytes = new Uint8Array(await response.arrayBuffer()); } catch { throw errorWithCode('UNAVAILABLE', 'upstream response read failed'); }
      if (bytes.byteLength > maxBytes) throw errorWithCode('RESOURCE_EXHAUSTED', 'upstream response is too large');
      return decodeResponseBytes(bytes, response);
    }
    let text;
    try { text = await response.text(); } catch { throw errorWithCode('UNAVAILABLE', 'upstream response read failed'); }
    if (Buffer.byteLength(text) > maxBytes) throw errorWithCode('RESOURCE_EXHAUSTED', 'upstream response is too large');
    return text;
  }
  const reader = response.body.getReader(); const chunks = []; let bytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) { await reader.cancel(); throw errorWithCode('RESOURCE_EXHAUSTED', 'upstream response is too large'); }
      chunks.push(value);
    }
  } catch (err) {
    if (err?.legacyCode) throw err;
    throw errorWithCode('UNAVAILABLE', 'upstream response read failed');
  }
  return decodeResponseBytes(Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))), response);
};
const throwForHttpStatus = (status) => {
  if (status === 401 || status === 403) throw errorWithCode('PERMISSION_DENIED', `upstream HTTP ${status}`);
  if (status >= 300 && status < 400) throw errorWithCode('FAILED_PRECONDITION', `upstream redirected with HTTP ${status}`);
  if (status >= 400 && status < 500) throw errorWithCode('FAILED_PRECONDITION', `upstream HTTP ${status}`);
  throw errorWithCode('UNAVAILABLE', `upstream HTTP ${status}`);
};
const isTimeout = (err) => err?.name === 'AbortError' || err?.name === 'TimeoutError';
const runQueryEventList = async (req = {}, ctx = {}) => {
  const callCtx = requireBindings(ctx); const limit = Math.max(0, pickInt(req, ['limit'], 0));
  const url = `${callCtx.host}${EVENT_LIST_URI}`; const timeoutMs = resolveTimeoutMs(callCtx);
  let response;
  try {
    response = await fetch(url, {
      method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(timeoutMs), ...buildTlsOptions(callCtx.bindings, url),
      headers: buildHeaders(callCtx.bindings, callCtx.meta, { cookie: callCtx.cookie, refererUrl: `${callCtx.host}${EVENT_REFERER_PATH}` }),
    });
  } catch (err) {
    const code = isTimeout(err) ? 'DEADLINE_EXCEEDED' : 'UNAVAILABLE';
    logFlow(callCtx, 'QueryEventList:error', { ...logTarget(url), code });
    throw errorWithCode(code, code === 'DEADLINE_EXCEEDED' ? `upstream request timed out after ${timeoutMs}ms` : 'upstream request failed');
  }
  const status = Number(response.status) || 0;
  if (status < 200 || status >= 300) throwForHttpStatus(status);
  const text = await readBoundedText(response, resolveMaxResponseBytes(callCtx));
  if (!hasEventTable(text)) throw errorWithCode('FAILED_PRECONDITION', 'unexpected response (session may be expired or not the IDS event page)');
  const entries = parseEventList(text, limit);
  if (entries.length === 0 && hasEventDataRows(text)) throw errorWithCode('FAILED_PRECONDITION', 'event table rows do not match the expected V5.6R10F02 format');
  logFlow(callCtx, 'QueryEventList:done', { ...logTarget(url), http_status: status, entry_count: entries.length, body_bytes: Buffer.byteLength(text) });
  return { http_status: status, total: entries.length, entries };
};

export function rpcdef(ctx = {}) {
  const callCtx = resolveCallContext(ctx);
  return { [QUERY_EVENT_LIST_PATH]: async (req) => runQueryEventList(req ?? callCtx.req, callCtx) };
}
export const handlers = { [METHOD_QUERY_EVENT_LIST_FULL]: (ctx = {}) => runQueryEventList(requestFromContext(ctx), ctx) };
export const _test = { attrTitles, buildHeaders, buildTlsOptions, decodeEntities, decodeResponseBytes, errorWithCode, grpcCodeFor, hasEventDataRows, hasEventTable, hasOwn, normalizeBaseUrl, parseEventList, pickBoolean, pickFirstBoolean, pickFirstString, pickInt, pickStringFrom, readBoundedText, requestFromContext, requireBindings, resolveCallContext, resolveCookie, resolveHost, resolveMaxResponseBytes, resolveTimeoutMs, responseCharset, sanitizeHeaders, splitIpPort, stripTags, throwForHttpStatus, unwrapScalar };
