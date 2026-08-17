// 奇安信网神 SecGate3600 防火墙 V3.6.6.0 RESTful API 适配。
// 覆盖能力：登录、IP 地址黑名单封禁/解禁/查询、注销。
import { GrpcError, grpcStatus } from '@chaitin-ai/octobus-sdk';
import { Agent } from 'undici';

const SVC = 'QIANXIN_FW_SecGate3600_V3_6_6.QIANXIN_FW_SecGate3600_V3_6_6';
export const LOGIN_PATH = `/${SVC}/Login`;
export const BLOCK_PATH = `/${SVC}/BlockIP`;
export const UNBLOCK_PATH = `/${SVC}/UnblockIP`;
export const QUERY_PATH = `/${SVC}/QueryBlacklist`;
export const LOGOUT_PATH = `/${SVC}/Logout`;

export const METHOD_LOGIN_FULL = `${SVC}/Login`;
export const METHOD_BLOCK_FULL = `${SVC}/BlockIP`;
export const METHOD_UNBLOCK_FULL = `${SVC}/UnblockIP`;
export const METHOD_QUERY_FULL = `${SVC}/QueryBlacklist`;
export const METHOD_LOGOUT_FULL = `${SVC}/Logout`;

export const LOGIN_URI = '/v1.0/login';
export const REST_URI = '/v1.0/rest/';
export const LOGOUT_URI = '/v1.0/out';
export const BLACKLIST_MODULE = 'addr_blacklist';
export const ADD_FUNCTION = 'add_blacklist_ip';
export const DEL_FUNCTION = 'del_blacklist_by_id';
export const GET_FUNCTION = 'get_blacklist_config';
export const DEFAULT_TIMEOUT_MS = 5000;
export const MAX_TIMEOUT_MS = 120_000;
export const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
export const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
export const SESSION_TTL_MS = 30 * 60 * 1000;
export const MAX_SESSION_ENTRIES = 256;

const sessionCache = new Map();
let insecureTlsDispatcher;

const grpcCodeFor = (code) => ({
  FAILED_PRECONDITION: grpcStatus.FAILED_PRECONDITION,
  INVALID_ARGUMENT: grpcStatus.INVALID_ARGUMENT,
  PERMISSION_DENIED: grpcStatus.PERMISSION_DENIED,
  UNAVAILABLE: grpcStatus.UNAVAILABLE,
  UNKNOWN: grpcStatus.UNKNOWN,
})[code] ?? grpcStatus.UNKNOWN;

const errorWithCode = (code, message) => {
  const err = new GrpcError(grpcCodeFor(code), `${code}: ${message}`);
  err.legacyCode = code;
  return err;
};

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj ?? {}, key);
const firstDefined = (...vals) => vals.find((val) => val !== undefined && val !== null);

const unwrapScalar = (value) => {
  if (value === undefined || value === null) return undefined;
  if (typeof value === 'object' && hasOwn(value, 'value')) return unwrapScalar(value.value);
  return value;
};

const toTrimmedString = (value) => {
  const raw = unwrapScalar(value);
  if (raw === undefined || raw === null) return '';
  return String(raw).trim();
};

const sanitizeText = (value) => String(value ?? '')
  .replace(/(password|token|cookie|authorization)\s*[=:]\s*[^\s,;]+/gi, '$1=REDACTED');

const requireString = (value, fieldName) => {
  const text = toTrimmedString(value);
  if (!text) throw errorWithCode('INVALID_ARGUMENT', `${fieldName} is required`);
  return text;
};

const requireFirstString = (values, fieldName) => {
  for (const value of values) {
    const text = toTrimmedString(value);
    if (text) return text;
  }
  throw errorWithCode('INVALID_ARGUMENT', `${fieldName} is required`);
};

const mergedBindings = (ctx = {}) => ({
  ...(ctx?.config ?? {}),
  ...(ctx?.secret ?? {}),
  ...(ctx?.bindings ?? {}),
});

const requestFromContext = (ctx = {}) => ctx.request ?? ctx.req ?? {};

const resolveCallContext = (ctx = {}) => ({
  ...ctx,
  bindings: mergedBindings(ctx),
  limits: ctx.limits ?? {},
  meta: ctx.meta ?? {},
  req: requestFromContext(ctx),
});

const normalizeBaseUrl = (value) => {
  try {
    const url = new URL(toTrimmedString(value));
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.search || url.hash) return '';
    if (url.pathname !== '/' && url.pathname !== '') return '';
    return url.toString().replace(/\/+$/, '');
  } catch {
    return '';
  }
};

const requireHost = (req, ctx) => {
  const candidates = [
    req?.host,
    ctx?.bindings?.restBaseUrl,
    ctx?.bindings?.baseUrl,
    ctx?.bindings?.rest_base_url,
    ctx?.bindings?.base_url,
    ctx?.bindings?.host,
  ];
  for (const candidate of candidates) {
    const host = normalizeBaseUrl(candidate);
    if (host) return host;
  }
  throw errorWithCode('INVALID_ARGUMENT', 'host is required');
};

const resolveTimeoutMs = (ctx) => {
  const bindings = mergedBindings(ctx);
  const raw = Number(firstDefined(ctx?.limits?.timeoutMs, bindings.timeoutMs, bindings.timeout_ms, DEFAULT_TIMEOUT_MS));
  return Number.isFinite(raw) && raw > 0 ? Math.min(Math.trunc(raw), MAX_TIMEOUT_MS) : DEFAULT_TIMEOUT_MS;
};

const resolveMaxResponseBytes = (ctx) => {
  const raw = Number(firstDefined(mergedBindings(ctx).maxResponseBytes, mergedBindings(ctx).max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES));
  return Number.isFinite(raw) && raw > 0 ? Math.min(Math.trunc(raw), MAX_RESPONSE_BYTES) : DEFAULT_MAX_RESPONSE_BYTES;
};

const toBoolean = (value) => {
  const raw = unwrapScalar(value);
  if (typeof raw === 'boolean') return raw;
  if (typeof raw === 'number') return raw !== 0;
  if (typeof raw === 'string') {
    const normalized = raw.trim().toLowerCase();
    if (['true', '1', 'yes', 'y', 'on'].includes(normalized)) return true;
    if (['false', '0', 'no', 'n', 'off', ''].includes(normalized)) return false;
  }
  return false;
};

const buildTlsOptions = (bindings) => {
  if (!toBoolean(bindings?.skipTlsVerify) && !toBoolean(bindings?.tlsInsecureSkipVerify) && !toBoolean(bindings?.insecureSkipVerify)) return {};
  insecureTlsDispatcher ??= new Agent({ connect: { rejectUnauthorized: false } });
  return { dispatcher: insecureTlsDispatcher };
};

const buildHeaders = (ctx, extra = {}) => {
  const prohibited = new Set(['authorization', 'connection', 'content-length', 'content-type', 'cookie', 'host', 'proxy-authorization', 'transfer-encoding']);
  const headers = {};
  for (const [rawKey, rawValue] of Object.entries(ctx?.bindings?.headers || {})) {
    const key = String(rawKey).trim().toLowerCase();
    const value = String(unwrapScalar(rawValue) ?? '');
    if (/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(key) && !prohibited.has(key) && !/[\r\n]/.test(value)) headers[key] = value;
  }
  return { ...headers, ...extra };
};

const getInstanceKey = (ctx) => String(ctx?.meta?.instance_id || ctx?.meta?.instanceId || 'default');
// An OctoBus instance owns one configured device session. Keying by username made
// LoginRequest.username sessions unreachable from the other RPCs, whose request
// messages intentionally do not carry a username.
const getSessionKey = (ctx, host) => `${getInstanceKey(ctx)}:${host}`;
const pruneSessions = (now = Date.now()) => {
  for (const [key, session] of sessionCache) if (!session?.expiresAt || session.expiresAt <= now) sessionCache.delete(key);
  while (sessionCache.size > MAX_SESSION_ENTRIES) sessionCache.delete(sessionCache.keys().next().value);
};
const getSession = (ctx, host) => {
  pruneSessions();
  const key = getSessionKey(ctx, host);
  const session = sessionCache.get(key);
  if (session) { sessionCache.delete(key); sessionCache.set(key, session); }
  return session;
};
const setSession = (ctx, host, session) => {
  pruneSessions();
  const username = session.username || toTrimmedString(firstDefined(ctx?.bindings?.user, ctx?.bindings?.username));
  const key = getSessionKey(ctx, host);
  sessionCache.delete(key);
  sessionCache.set(key, { ...session, username, expiresAt: Date.now() + SESSION_TTL_MS });
  pruneSessions();
};
const clearSession = (ctx, host) => sessionCache.delete(getSessionKey(ctx, host));

const requireSession = (ctx, host) => {
  const session = getSession(ctx, host);
  if (!session?.cookie || !session?.token) throw errorWithCode('FAILED_PRECONDITION', 'call Login first');
  return session;
};

const toInt64 = (value, fallback = 0) => {
  const raw = unwrapScalar(value);
  if (raw === undefined || raw === null || raw === '') return fallback;
  const num = Number(raw);
  if (!Number.isFinite(num)) return fallback;
  return Math.trunc(num);
};

const deviceErrorCode = (value) => {
  const raw = unwrapScalar(value);
  if (raw === undefined || raw === null || raw === '') return -1;
  const num = Number(raw);
  return Number.isFinite(num) ? Math.trunc(num) : -1;
};

const deviceErrorString = (head = {}) => {
  const message = toTrimmedString(firstDefined(head.error_string, head.message));
  if (message) return message;
  const rawCode = unwrapScalar(head.error_code);
  return deviceErrorCode(rawCode) === -1 && rawCode !== undefined && rawCode !== null
    ? `device error_code: ${sanitizeText(rawCode)}`
    : '';
};

const toValue = (val) => {
  const raw = unwrapScalar(val);
  if (raw === undefined || raw === null) return null;
  if (typeof raw === 'string') return { stringValue: raw };
  if (typeof raw === 'number') return { numberValue: raw };
  if (typeof raw === 'boolean') return { boolValue: raw };
  if (Array.isArray(raw)) return { listValue: { values: raw.map((item) => toValue(item) ?? { nullValue: 'NULL_VALUE' }) } };
  if (typeof raw === 'object') {
    const fields = {};
    for (const [key, value] of Object.entries(raw)) fields[key] = toValue(value) ?? { nullValue: 'NULL_VALUE' };
    return { structValue: { fields } };
  }
  return { stringValue: String(raw) };
};

const redactValue = (value, key = '') => {
  if (/(password|token|cookie|authorization|secret)/i.test(key)) return 'REDACTED';
  if (Array.isArray(value)) return value.map((item) => redactValue(item));
  if (isPlainObject(value)) return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => [childKey, redactValue(childValue, childKey)]));
  return typeof value === 'string' ? sanitizeText(value) : value;
};

const isPlainObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

const readBoundedBody = async (response, maxBytes) => {
  const declared = Number(response?.headers?.get?.('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await response?.body?.cancel?.();
    throw errorWithCode('FAILED_PRECONDITION', `upstream response exceeds ${maxBytes} bytes`);
  }
  if (!response?.body?.getReader) return String(await response?.text?.() ?? '');
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw errorWithCode('FAILED_PRECONDITION', `upstream response exceeds ${maxBytes} bytes`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock?.();
  }
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { combined.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder().decode(combined);
};

const fetchUpstream = async (ctx, url, init = {}) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), resolveTimeoutMs(ctx));
  try {
    const response = await fetch(url, {
      ...buildTlsOptions(ctx?.bindings || {}),
      ...init,
      headers: buildHeaders(ctx, init.headers || {}),
      signal: controller.signal,
      redirect: 'error',
    });
    const text = await readBoundedBody(response, resolveMaxResponseBytes(ctx));
    return { status: Number(response.status), text: String(text ?? ''), res: response };
  } catch (err) {
    if (err instanceof GrpcError) throw err;
    const message = err?.name === 'AbortError' ? 'upstream request timed out' : sanitizeText(err?.cause?.message || err?.message || 'fetch failed');
    throw errorWithCode('UNAVAILABLE', message);
  } finally {
    clearTimeout(timer);
  }
};

const parseJsonOrThrow = (text) => {
  try {
    return JSON.parse(text);
  } catch {
    throw errorWithCode('UNKNOWN', 'response is not valid JSON');
  }
};

const requireJsonBody = (text) => {
  if (!String(text || '').trim()) throw errorWithCode('UNKNOWN', 'response body is empty');
  return parseJsonOrThrow(text);
};

// SecGate3600 业务报文统一为 [{head, data}] 或 {head, data}，取首个对象。
const firstEnvelope = (json) => {
  if (Array.isArray(json)) return isPlainObject(json[0]) ? json[0] : {};
  return isPlainObject(json) ? json : {};
};

const throwForAuthStatus = (ctx, host, status) => {
  if (status === 401 || status === 403) {
    clearSession(ctx, host);
    throw errorWithCode('PERMISSION_DENIED', `upstream http ${status}`);
  }
};

const throwForHttpStatus = (ctx, host, status) => {
  throwForAuthStatus(ctx, host, status);
  if (status >= 500) throw errorWithCode('UNAVAILABLE', `upstream http ${status}`);
  if (status < 200 || status >= 300) throw errorWithCode('FAILED_PRECONDITION', `upstream http ${status}`);
};

const getSetCookies = (res) => {
  const headers = res?.headers;
  if (headers && typeof headers.getSetCookie === 'function') {
    const values = headers.getSetCookie();
    return Array.isArray(values) ? values : [];
  }
  if (headers && typeof headers.get === 'function') {
    const combined = headers.get('set-cookie');
    return combined ? [String(combined)] : [];
  }
  return [];
};

const mergeCookieHeader = (setCookies, token) => {
  const pairs = new Map();
  for (const item of setCookies || []) {
    const raw = String(item || '').trim();
    if (!raw) continue;
    const pair = raw.split(';')[0]?.trim();
    if (!pair) continue;
    const eqIndex = pair.indexOf('=');
    if (eqIndex <= 0) continue;
    pairs.set(pair.slice(0, eqIndex).trim(), pair);
  }
  if (token) pairs.set('token', `token=${token}`);
  return Array.from(pairs.values()).join('; ');
};

const extractHeaders = (res) => {
  const map = new Map();
  const headers = res?.headers;
  if (headers && typeof headers.forEach === 'function') {
    headers.forEach((value, key) => {
      const lower = String(key || '').toLowerCase();
      if (!lower) return;
      const existing = map.get(lower) || [];
      existing.push(String(value ?? ''));
      map.set(lower, existing);
    });
  }
  const setCookies = getSetCookies(res);
  if (setCookies.length > 0) map.set('set-cookie', setCookies.map((value) => String(value ?? '')));
  return Array.from(map.entries())
    .filter(([key]) => !['set-cookie', 'cookie', 'authorization', 'proxy-authorization'].includes(key))
    .map(([key, values]) => ({ key, values }));
};

const sendRestEnvelope = async (ctx, host, session, fn, body) => {
  const upstream = await fetchUpstream(ctx, `${host}${REST_URI}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: session.cookie },
    body: JSON.stringify([{ head: { module: BLACKLIST_MODULE, function: fn }, body }]),
  });
  throwForHttpStatus(ctx, host, upstream.status);
  const json = requireJsonBody(upstream.text);
  return { upstream, json, head: isPlainObject(firstEnvelope(json).head) ? firstEnvelope(json).head : {} };
};

// ---- request normalization ----

const normalizeBlockItem = (item, index) => {
  const source = item || {};
  const ipStart = requireString(source.ip_start ?? source.ipStart, `items[${index}].ip_start`);
  const ipEnd = toTrimmedString(source.ip_end ?? source.ipEnd) || ipStart;
  const entry = { ip_start: ipStart, ip_end: ipEnd, enable: toTrimmedString(source.enable) || 'enable' };
  const desc = toTrimmedString(source.desc);
  if (desc) entry.desc = desc;
  const schedule = toTrimmedString(source.schedule);
  if (schedule) entry.schedule = schedule;
  return entry;
};

const normalizeBlockItems = (req) => {
  const items = Array.isArray(req?.items) ? req.items : [];
  if (items.length === 0) throw errorWithCode('INVALID_ARGUMENT', 'items must be a non-empty array');
  return items.map((item, index) => normalizeBlockItem(item, index));
};

const normalizeUnblockTarget = (target, index) => {
  const source = target || {};
  const ipStart = requireString(source.ip_start ?? source.ipStart, `targets[${index}].ip_start`);
  return { ip_start: ipStart, ip_end: toTrimmedString(source.ip_end ?? source.ipEnd) || ipStart };
};

const normalizeUnblockTargets = (req) => {
  const targets = Array.isArray(req?.targets) ? req.targets : [];
  if (targets.length === 0) throw errorWithCode('INVALID_ARGUMENT', 'targets must be a non-empty array');
  return targets.map((target, index) => normalizeUnblockTarget(target, index));
};

// ---- handlers ----

const handleLogin = async (req, ctx) => {
  const callCtx = resolveCallContext(ctx);
  const request = req ?? {};
  const host = requireHost(request, callCtx);
  const username = requireFirstString([request?.username, callCtx?.bindings?.user, callCtx?.bindings?.username], 'username');
  const password = requireFirstString([request?.password, callCtx?.bindings?.password], 'password');
  const upstream = await fetchUpstream(callCtx, `${host}${LOGIN_URI}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  throwForHttpStatus(callCtx, host, upstream.status);
  const json = requireJsonBody(upstream.text);
  const result = isPlainObject(json?.result) ? json.result : {};
  const token = toTrimmedString(result.token);
  const success = json?.success === true;
  if (success && token) {
    const cookie = mergeCookieHeader(getSetCookies(upstream.res), token);
    if (cookie) setSession(callCtx, host, { token, cookie, username, login_at_ms: Date.now() });
  }
  return {
    success,
    token: '',
    error_code: toTrimmedString(result.error_code),
    http_status: Number(upstream.status),
    raw_body: '',
    raw_json: toValue(redactValue(json)),
    headers: extractHeaders(upstream.res),
  };
};

const handleBlockIP = async (req, ctx) => {
  const callCtx = resolveCallContext(ctx);
  const request = req ?? {};
  const host = requireHost(request, callCtx);
  const items = normalizeBlockItems(request);
  const session = requireSession(callCtx, host);
  const results = [];
  // 设备不支持批量下发，逐条提交。
  for (const item of items) {
    try {
      const { upstream, json, head } = await sendRestEnvelope(callCtx, host, session, ADD_FUNCTION, {
        addr_blacklist_cp: { blacklist_cp: [item] },
      });
      results.push({
        ip_start: item.ip_start,
        ip_end: item.ip_end,
        error_code: deviceErrorCode(head.error_code),
        error_string: deviceErrorString(head),
        http_status: Number(upstream.status),
        raw_json: toValue(redactValue(json)),
      });
    } catch (err) {
      results.push({
        ip_start: item.ip_start,
        ip_end: item.ip_end,
        error_code: -1,
        error_string: sanitizeText(err?.message || 'upstream operation failed'),
        http_status: 0,
      });
    }
  }
  return { results };
};

const handleUnblockIP = async (req, ctx) => {
  const callCtx = resolveCallContext(ctx);
  const request = req ?? {};
  const host = requireHost(request, callCtx);
  const targets = normalizeUnblockTargets(request);
  const session = requireSession(callCtx, host);
  const results = [];
  for (const target of targets) {
    try {
      const { upstream, json, head } = await sendRestEnvelope(callCtx, host, session, DEL_FUNCTION, {
        addr_blacklist_cp: { blacklist_cp: [target] },
      });
      results.push({
        ip_start: target.ip_start,
        ip_end: target.ip_end,
        error_code: deviceErrorCode(head.error_code),
        error_string: deviceErrorString(head),
        http_status: Number(upstream.status),
        raw_json: toValue(redactValue(json)),
      });
    } catch (err) {
      results.push({
        ip_start: target.ip_start,
        ip_end: target.ip_end,
        error_code: -1,
        error_string: sanitizeText(err?.message || 'upstream operation failed'),
        http_status: 0,
      });
    }
  }
  return { results };
};

const handleQueryBlacklist = async (req, ctx) => {
  const callCtx = resolveCallContext(ctx);
  const request = req ?? {};
  const host = requireHost(request, callCtx);
  const session = requireSession(callCtx, host);
  const searchKey = toTrimmedString(request?.search_key ?? request?.searchKey);
  const body = { addr_blacklist_cp: searchKey ? { search_key: searchKey } : {} };
  const { upstream, json, head } = await sendRestEnvelope(callCtx, host, session, GET_FUNCTION, body);
  const envelope = firstEnvelope(json);
  return {
    error_code: deviceErrorCode(head.error_code),
    error_string: deviceErrorString(head),
    total: toInt64(head.total, 0),
    data: toValue(redactValue(envelope.data)),
    http_status: Number(upstream.status),
    raw_json: toValue(redactValue(json)),
    headers: extractHeaders(upstream.res),
  };
};

const handleLogout = async (req, ctx) => {
  const callCtx = resolveCallContext(ctx);
  const request = req ?? {};
  const host = requireHost(request, callCtx);
  const session = requireSession(callCtx, host);
  const username = requireFirstString([request?.username, session?.username, callCtx?.bindings?.user, callCtx?.bindings?.username], 'username');
  const upstream = await fetchUpstream(callCtx, `${host}${LOGOUT_URI}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: session.cookie },
    body: JSON.stringify({ username }),
  });
  clearSession(callCtx, host);
  throwForHttpStatus(callCtx, host, upstream.status);
  const base = {
    http_status: Number(upstream.status),
    raw_body: '',
    headers: extractHeaders(upstream.res),
  };
  if (!String(upstream.text || '').trim()) {
    return { ...base, raw_json: undefined };
  }
  return { ...base, raw_json: toValue(redactValue(parseJsonOrThrow(upstream.text))) };
};

export function rpcdef(ctx) {
  const callCtx = resolveCallContext(ctx);
  // 无显式 req 时回落到 ctx.req（rpcdef 主要作为测试/直调入口）。
  const pick = (req) => req ?? callCtx.req;
  return {
    [LOGIN_PATH]: async (req) => handleLogin(pick(req), callCtx),
    [BLOCK_PATH]: async (req) => handleBlockIP(pick(req), callCtx),
    [UNBLOCK_PATH]: async (req) => handleUnblockIP(pick(req), callCtx),
    [QUERY_PATH]: async (req) => handleQueryBlacklist(pick(req), callCtx),
    [LOGOUT_PATH]: async (req) => handleLogout(pick(req), callCtx),
  };
}

export const handlers = {
  [METHOD_LOGIN_FULL]: (ctx = {}) => handleLogin(requestFromContext(ctx), ctx),
  [METHOD_BLOCK_FULL]: (ctx = {}) => handleBlockIP(requestFromContext(ctx), ctx),
  [METHOD_UNBLOCK_FULL]: (ctx = {}) => handleUnblockIP(requestFromContext(ctx), ctx),
  [METHOD_QUERY_FULL]: (ctx = {}) => handleQueryBlacklist(requestFromContext(ctx), ctx),
  [METHOD_LOGOUT_FULL]: (ctx = {}) => handleLogout(requestFromContext(ctx), ctx),
};

export const _test = {
  buildHeaders,
  buildTlsOptions,
  clearSession,
  deviceErrorCode,
  deviceErrorString,
  errorWithCode,
  extractHeaders,
  fetchUpstream,
  firstEnvelope,
  getInstanceKey,
  getSessionKey,
  getSession,
  getSetCookies,
  mergeCookieHeader,
  normalizeBaseUrl,
  normalizeBlockItem,
  normalizeBlockItems,
  normalizeUnblockTargets,
  parseJsonOrThrow,
  readBoundedBody,
  redactValue,
  requireHost,
  requireFirstString,
  requireJsonBody,
  resolveCallContext,
  resolveMaxResponseBytes,
  resolveTimeoutMs,
  sanitizeText,
  sessionCache,
  setSession,
  throwForHttpStatus,
  toBoolean,
  toInt64,
  toTrimmedString,
  toValue,
};
