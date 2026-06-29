import { GrpcError, grpcStatus } from '@chaitin-ai/octobus-sdk';
import { Agent } from 'undici';

export const METHOD_GET_STATUS_FULL = 'Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetStatus';
export const METHOD_LIST_SPACES_FULL = 'Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/ListSpaces';
export const METHOD_GET_SPACE_FULL = 'Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetSpace';
export const METHOD_FIND_SAVED_OBJECTS_FULL = 'Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/FindSavedObjects';
export const METHOD_GET_SAVED_OBJECT_FULL = 'Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetSavedObject';
export const METHOD_BULK_GET_SAVED_OBJECTS_FULL = 'Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/BulkGetSavedObjects';
export const METHOD_EXPORT_SAVED_OBJECTS_FULL = 'Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/ExportSavedObjects';

export const DEFAULT_TIMEOUT_MS = 5000;
export const DEFAULT_PER_PAGE = 20;

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

const firstDefined = (...values) => values.find((value) => value !== undefined && value !== null);

const unwrapScalar = (value) => {
  if (value === undefined || value === null) return undefined;
  if (typeof value === 'object' && value !== null && Object.prototype.hasOwnProperty.call(value, 'value')) return unwrapScalar(value.value);
  return value;
};

const toTrimmedString = (value) => {
  const raw = unwrapScalar(value);
  if (raw === undefined || raw === null) return '';
  return String(raw).trim();
};

const toFiniteInt = (value, fallback = 0) => {
  const raw = unwrapScalar(value);
  if (raw === undefined || raw === null || raw === '') return fallback;
  const num = Number(raw);
  return Number.isFinite(num) ? Math.trunc(num) : fallback;
};

const toBool = (value, fallback = false) => {
  const raw = unwrapScalar(value);
  if (raw === undefined || raw === null) return fallback;
  if (typeof raw === 'boolean') return raw;
  if (typeof raw === 'number') return raw !== 0;
  if (typeof raw === 'string') {
    const normalized = raw.trim().toLowerCase();
    if (['true', '1', 'yes', 'on'].includes(normalized)) return true;
    if (['false', '0', 'no', 'off', ''].includes(normalized)) return false;
  }
  return fallback;
};

const toJsonString = (value) => {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string') return value;
  try { return JSON.stringify(value); } catch { return ''; }
};

const normalizeBaseUrl = (value) => {
  const raw = toTrimmedString(value);
  if (!/^https?:\/\//i.test(raw)) return '';
  return raw.replace(/\/+$/, '');
};

const mergedBindings = (ctx = {}) => ({
  ...(ctx.config ?? {}),
  ...(ctx.secret ?? {}),
  ...(ctx.bindings ?? {}),
});

const resolveCallContext = (ctx = {}) => ({
  ...ctx,
  bindings: mergedBindings(ctx),
  limits: ctx.limits ?? {},
  meta: ctx.meta ?? {},
  req: ctx.req ?? ctx.request ?? {},
});

const resolveBaseUrl = (bindings = {}) => normalizeBaseUrl(firstDefined(
  bindings.baseUrl,
  bindings.kibana_domain,
  bindings.domain,
  bindings.url,
));

const resolveUsername = (bindings = {}) => toTrimmedString(firstDefined(
  bindings.username,
  bindings.kibana_username,
  bindings.user,
));

const resolvePassword = (bindings = {}) => toTrimmedString(firstDefined(
  bindings.password,
  bindings.kibana_password,
  bindings.passwd,
));

const resolveTimeoutMs = (ctx = {}) => {
  const raw = Number(firstDefined(ctx.limits?.timeoutMs, ctx.bindings?.timeoutMs, DEFAULT_TIMEOUT_MS));
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_TIMEOUT_MS;
};

const buildTlsOptions = (bindings = {}) => {
  const enabled = Boolean(bindings.skipTlsVerify || bindings.tlsInsecureSkipVerify || bindings.insecureSkipVerify);
  if (!enabled) return {};
  return { skipTlsVerify: true, tlsInsecureSkipVerify: true, insecureSkipVerify: true };
};

const requireBaseUrl = (ctx = {}) => {
  const baseUrl = resolveBaseUrl(ctx.bindings || {});
  if (!baseUrl) throw errorWithCode('INVALID_ARGUMENT', 'baseUrl is required in bindings');
  return baseUrl;
};

const requireCredentials = (ctx = {}) => {
  const username = resolveUsername(ctx.bindings || {});
  const password = resolvePassword(ctx.bindings || {});
  if (!username || !password) throw errorWithCode('INVALID_ARGUMENT', 'username and password are required in secret bindings');
  return { username, password };
};

const buildBasicAuth = (username, password) => {
  const raw = `${String(username ?? '')}:${String(password ?? '')}`;
  return `Basic ${Buffer.from(raw, 'utf8').toString('base64')}`;
};

const encodeQueryPairs = (query = {}) => {
  const parts = [];
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') continue;
    parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
  }
  return parts.join('&');
};

const joinPath = (baseUrl, path) => {
  const base = String(baseUrl || '').replace(/\/+$/, '');
  const normalizedPath = String(path || '').replace(/^\/+/, '');
  return `${base}/${normalizedPath}`;
};

const buildUrl = (baseUrl, path, query = {}) => {
  const joined = joinPath(baseUrl, path);
  const qs = encodeQueryPairs(query);
  return qs ? `${joined}?${qs}` : joined;
};

const buildLogPrefix = (ctx = {}, action) => {
  const meta = ctx.meta || {};
  const trace = [];
  if (meta.instance_id || meta.instanceId) trace.push(`inst=${meta.instance_id || meta.instanceId}`);
  if (meta.request_id || meta.requestId) trace.push(`req=${meta.request_id || meta.requestId}`);
  return `[Elastic_Kibana_7_10_0][${action}]${trace.length ? `[${trace.join(' ')}]` : ''}`;
};

const logFlow = (ctx, action, details) => {
  const prefix = buildLogPrefix(ctx, action);
  try { console.log(prefix, JSON.stringify(details)); } catch { console.log(prefix, details); }
};

const attachResponse = (err, response) => { err.response = response; return err; };

const tryParseJson = (text) => {
  try { return { ok: true, value: JSON.parse(text) }; } catch { return { ok: false }; }
};

const mapHttpStatusToCode = (httpStatus) => {
  if (httpStatus === 401 || httpStatus === 403) return 'PERMISSION_DENIED';
  if (httpStatus >= 400 && httpStatus < 500) return 'FAILED_PRECONDITION';
  return 'UNAVAILABLE';
};

const executeRequest = async (url, ctx = {}, options = {}) => {
  const bindings = ctx.bindings || {};
  const timeoutMs = resolveTimeoutMs(ctx);
  const headers = { Accept: 'application/json', 'kbn-xsrf': 'octobus', ...(options.headers ?? {}) };
  const init = {
    method: options.method || 'GET',
    headers,
    timeoutMs,
    ...buildTlsOptions(bindings),
    ...(options.body !== undefined ? { body: options.body } : {}),
  };
  let res;
  try {
    res = await fetch(url, init);
  } catch (err) {
    const errMsg = err?.cause?.message || err?.message || 'fetch failed';
    logFlow(ctx, options.action || 'fetch:error', { url, error: errMsg });
    throw attachResponse(errorWithCode('UNAVAILABLE', `${options.action || 'fetch'} failed: ${errMsg}`), { http_status: 0, http_body: errMsg });
  }
  let rawBody;
  try { rawBody = await res.text(); }
  catch (err) {
    const errMsg = err?.message || 'response read failed';
    logFlow(ctx, 'fetch:read-error', { url, httpStatus: res.status, error: errMsg });
    throw attachResponse(errorWithCode('UNAVAILABLE', `response read failed: ${errMsg}`), { http_status: Number(res.status || 0), http_body: errMsg });
  }
  const httpStatus = Number(res.status || 0);
  logFlow(ctx, 'fetch:response', { url, httpStatus, bodyLength: rawBody?.length || 0 });
  return { httpStatus, httpBody: String(rawBody ?? '') };
};

const ensureSuccess = (result, action) => {
  const { httpStatus, httpBody } = result;
  if (httpStatus >= 200 && httpStatus < 300) return;
  const code = mapHttpStatusToCode(httpStatus);
  throw attachResponse(errorWithCode(code, `${action} upstream http ${httpStatus}: ${httpBody.substring(0, 500)}`), { http_status: httpStatus, http_body: httpBody });
};

const parseJsonOrThrowUnknown = (result, action) => {
  const trimmed = (result.httpBody || '').trim();
  if (!trimmed) {
    throw attachResponse(errorWithCode('UNKNOWN', `${action} returned empty response`), { http_status: result.httpStatus, http_body: result.httpBody });
  }
  const parsed = tryParseJson(trimmed);
  if (!parsed.ok) {
    throw attachResponse(errorWithCode('UNKNOWN', `${action} response is not valid JSON`), { http_status: result.httpStatus, http_body: result.httpBody });
  }
  return parsed.value;
};

const buildHeaders = (ctx) => {
  const { username, password } = requireCredentials(ctx);
  const headers = { Authorization: buildBasicAuth(username, password), 'kbn-xsrf': 'octobus' };
  const space = toTrimmedString(ctx.req?.space);
  if (space && space !== 'default') {
    headers['kbn-space'] = space;
  }
  return headers;
};

const handleGetStatus = async (req = {}, ctx = {}) => {
  const callCtx = resolveCallContext(ctx);
  const baseUrl = requireBaseUrl(callCtx);
  const { username, password } = requireCredentials(callCtx);
  const url = buildUrl(baseUrl, '/api/status');
  logFlow(callCtx, 'GetStatus', { url: joinPath(baseUrl, '/api/status') });
  const headers = { Authorization: buildBasicAuth(username, password), 'kbn-xsrf': 'octobus' };
  const result = await executeRequest(url, callCtx, { headers, action: 'GetStatus' });
  ensureSuccess(result, 'GetStatus');
  const json = parseJsonOrThrowUnknown(result, 'GetStatus');
  const statuses = (json?.status?.statuses || json?.statuses || []).map((s) => ({
    id: toTrimmedString(s?.id),
    state: toTrimmedString(s?.state),
    message: toTrimmedString(s?.message),
    level: toTrimmedString(s?.level),
  }));
  return {
    name: toTrimmedString(json?.name),
    uuid: toTrimmedString(json?.uuid),
    version: toTrimmedString(json?.version?.number || json?.version),
    raw_body: result.httpBody,
    statuses,
  };
};

const handleListSpaces = async (req = {}, ctx = {}) => {
  const callCtx = resolveCallContext(ctx);
  const baseUrl = requireBaseUrl(callCtx);
  const { username, password } = requireCredentials(callCtx);
  const url = buildUrl(baseUrl, '/api/spaces/space');
  logFlow(callCtx, 'ListSpaces', { url: joinPath(baseUrl, '/api/spaces/space') });
  const headers = { Authorization: buildBasicAuth(username, password), 'kbn-xsrf': 'octobus' };
  const result = await executeRequest(url, callCtx, { headers, action: 'ListSpaces' });
  ensureSuccess(result, 'ListSpaces');
  const json = parseJsonOrThrowUnknown(result, 'ListSpaces');
  const spaces = (Array.isArray(json) ? json : []).map((s) => ({
    id: toTrimmedString(s?.id),
    name: toTrimmedString(s?.name),
    description: toTrimmedString(s?.description),
    color: toTrimmedString(s?.color),
    disabled_features: Array.isArray(s?.disabledFeatures) ? s.disabledFeatures.map(String) : [],
    initials: toTrimmedString(s?.initials),
    raw_json: toJsonString(s),
  }));
  return { spaces, raw_body: result.httpBody };
};

const handleGetSpace = async (req = {}, ctx = {}) => {
  const callCtx = resolveCallContext(ctx);
  const baseUrl = requireBaseUrl(callCtx);
  const spaceId = toTrimmedString(req.id);
  if (!spaceId) throw errorWithCode('INVALID_ARGUMENT', 'id is required');
  const url = buildUrl(baseUrl, `/api/spaces/space/${encodeURIComponent(spaceId)}`);
  logFlow(callCtx, 'GetSpace', { url: joinPath(baseUrl, `/api/spaces/space/${spaceId}`) });
  const { username, password } = requireCredentials(callCtx);
  const headers = { Authorization: buildBasicAuth(username, password), 'kbn-xsrf': 'octobus' };
  const result = await executeRequest(url, callCtx, { headers, action: 'GetSpace' });
  ensureSuccess(result, 'GetSpace');
  const json = parseJsonOrThrowUnknown(result, 'GetSpace');
  return {
    id: toTrimmedString(json?.id),
    name: toTrimmedString(json?.name),
    description: toTrimmedString(json?.description),
    color: toTrimmedString(json?.color),
    disabled_features: Array.isArray(json?.disabledFeatures) ? json.disabledFeatures.map(String) : [],
    initials: toTrimmedString(json?.initials),
    raw_json: toJsonString(json),
  };
};

const handleFindSavedObjects = async (req = {}, ctx = {}) => {
  const callCtx = resolveCallContext({ ...ctx, req });
  const baseUrl = requireBaseUrl(callCtx);
  const type = toTrimmedString(req.type);
  if (!type) throw errorWithCode('INVALID_ARGUMENT', 'type is required');
  const perPage = toFiniteInt(req.per_page, DEFAULT_PER_PAGE);
  const page = toFiniteInt(req.page, 1);
  const params = {
    type,
    per_page: String(perPage),
    page: String(page),
    ...(req.search ? { search: toTrimmedString(req.search) } : {}),
    ...(req.search_fields ? { search_fields: toTrimmedString(req.search_fields) } : {}),
    ...(req.sort_field ? { sort_field: toTrimmedString(req.sort_field) } : {}),
    ...(req.sort_order ? { sort_order: toTrimmedString(req.sort_order) } : {}),
  };
  if (Array.isArray(req.fields) && req.fields.length > 0) {
    params.fields = req.fields.map(String).join(',');
  }
  const url = buildUrl(baseUrl, '/api/saved_objects/_find', params);
  logFlow(callCtx, 'FindSavedObjects', { url: joinPath(baseUrl, '/api/saved_objects/_find'), type });
  const headers = buildHeaders(callCtx);
  const result = await executeRequest(url, callCtx, { headers, action: 'FindSavedObjects' });
  ensureSuccess(result, 'FindSavedObjects');
  const json = parseJsonOrThrowUnknown(result, 'FindSavedObjects');
  const savedObjects = (json?.saved_objects || []).map((so) => ({
    id: toTrimmedString(so?.id),
    type: toTrimmedString(so?.type),
    updated_at: toTrimmedString(so?.updated_at),
    created_at: toTrimmedString(firstDefined(so?.created_at, so?.createdAt)),
    version: toFiniteInt(firstDefined(so?.version, so?._version)),
    raw_json: toJsonString(so),
    references: (Array.isArray(so?.references) ? so.references : []).map((r) => ({
      name: toTrimmedString(r?.name),
      type: toTrimmedString(r?.type),
      id: toTrimmedString(r?.id),
    })),
  }));
  return {
    saved_objects: savedObjects,
    total: toFiniteInt(json?.total),
    page: toFiniteInt(json?.page, 1),
    per_page: toFiniteInt(json?.per_page, perPage),
    raw_body: result.httpBody,
  };
};

const handleGetSavedObject = async (req = {}, ctx = {}) => {
  const callCtx = resolveCallContext({ ...ctx, req });
  const baseUrl = requireBaseUrl(callCtx);
  const type = toTrimmedString(req.type);
  const id = toTrimmedString(req.id);
  if (!type) throw errorWithCode('INVALID_ARGUMENT', 'type is required');
  if (!id) throw errorWithCode('INVALID_ARGUMENT', 'id is required');
  const url = buildUrl(baseUrl, `/api/saved_objects/${encodeURIComponent(type)}/${encodeURIComponent(id)}`);
  logFlow(callCtx, 'GetSavedObject', { url: joinPath(baseUrl, `/api/saved_objects/${type}/${id}`) });
  const headers = buildHeaders(callCtx);
  const result = await executeRequest(url, callCtx, { headers, action: 'GetSavedObject' });
  ensureSuccess(result, 'GetSavedObject');
  const json = parseJsonOrThrowUnknown(result, 'GetSavedObject');
  return {
    id: toTrimmedString(json?.id),
    type: toTrimmedString(json?.type),
    version: toFiniteInt(firstDefined(json?.version, json?._version)),
    updated_at: toTrimmedString(json?.updated_at),
    created_at: toTrimmedString(firstDefined(json?.created_at, json?.createdAt)),
    attributes_json: toJsonString(json?.attributes),
    references: (Array.isArray(json?.references) ? json.references : []).map((r) => ({
      name: toTrimmedString(r?.name),
      type: toTrimmedString(r?.type),
      id: toTrimmedString(r?.id),
    })),
    raw_body: result.httpBody,
    migration_version: toJsonString(json?.migrationVersion),
    core_migration_version: toTrimmedString(firstDefined(json?.coreMigrationVersion, json?._coreMigrationVersion)),
  };
};

const handleBulkGetSavedObjects = async (req = {}, ctx = {}) => {
  const callCtx = resolveCallContext({ ...ctx, req });
  const baseUrl = requireBaseUrl(callCtx);
  const objects = Array.isArray(req.objects) ? req.objects : [];
  if (objects.length === 0) throw errorWithCode('INVALID_ARGUMENT', 'at least one object is required');
  const body = objects.map((o) => ({ type: toTrimmedString(o?.type || o), id: toTrimmedString(o?.id || o) }));
  const url = buildUrl(baseUrl, '/api/saved_objects/_bulk_get');
  logFlow(callCtx, 'BulkGetSavedObjects', { url: joinPath(baseUrl, '/api/saved_objects/_bulk_get'), count: body.length });
  const headers = { ...buildHeaders(callCtx), 'Content-Type': 'application/json' };
  const result = await executeRequest(url, callCtx, { method: 'POST', headers, body: JSON.stringify(body), action: 'BulkGetSavedObjects' });
  ensureSuccess(result, 'BulkGetSavedObjects');
  const json = parseJsonOrThrowUnknown(result, 'BulkGetSavedObjects');
  const savedObjects = (json?.saved_objects || []).map((so) => ({
    id: toTrimmedString(so?.id),
    type: toTrimmedString(so?.type),
    version: toFiniteInt(firstDefined(so?.version, so?._version)),
    updated_at: toTrimmedString(so?.updated_at),
    created_at: toTrimmedString(firstDefined(so?.created_at, so?.createdAt)),
    attributes_json: toJsonString(so?.attributes),
    references: (Array.isArray(so?.references) ? so.references : []).map((r) => ({ name: toTrimmedString(r?.name), type: toTrimmedString(r?.type), id: toTrimmedString(r?.id) })),
    raw_body: '',
    migration_version: toJsonString(so?.migrationVersion),
    core_migration_version: toTrimmedString(firstDefined(so?.coreMigrationVersion, so?._coreMigrationVersion)),
  }));
  return { saved_objects: savedObjects, raw_body: result.httpBody };
};

const handleExportSavedObjects = async (req = {}, ctx = {}) => {
  const callCtx = resolveCallContext({ ...ctx, req });
  const baseUrl = requireBaseUrl(callCtx);
  const type = toTrimmedString(req.type);
  if (!type) throw errorWithCode('INVALID_ARGUMENT', 'type is required');
  const bodyObj = {
    type,
    ...(req.include_references_deep ? { includeReferencesDeep: true } : {}),
  };
  if (Array.isArray(req.objects) && req.objects.length > 0) {
    bodyObj.objects = req.objects.map((o) => {
      if (typeof o === 'object' && o !== null) return { type: toTrimmedString(o.type), id: toTrimmedString(o.id) };
      return { type, id: String(o) };
    });
  }
  const url = buildUrl(baseUrl, '/api/saved_objects/_export');
  logFlow(callCtx, 'ExportSavedObjects', { url: joinPath(baseUrl, '/api/saved_objects/_export'), type });
  const headers = {
    ...buildHeaders(callCtx),
    'Content-Type': 'application/json',
    Accept: 'application/ndjson',
  };
  const result = await executeRequest(url, callCtx, { method: 'POST', headers, body: JSON.stringify(bodyObj), action: 'ExportSavedObjects' });
  ensureSuccess(result, 'ExportSavedObjects');
  const body = result.httpBody || '';
  const lines = body.split('\n').filter((line) => line.trim());
  let exportedCount = 0;
  const missingRefs = [];
  for (const line of lines) {
    const parsed = tryParseJson(line);
    if (!parsed.ok) continue;
    if (parsed.value.exportedCount !== undefined) exportedCount = toFiniteInt(parsed.value.exportedCount);
    if (parsed.value.missingReferences) {
      for (const ref of parsed.value.missingReferences) {
        missingRefs.push(`${ref.type}:${ref.id}`);
      }
    }
    if (parsed.value.id) exportedCount++;
  }
  return {
    ndjson: body,
    total_count: lines.length,
    exported_count: exportedCount || lines.filter((l) => l.includes('"id"')).length,
    missing_refs: missingRefs,
  };
};

export const handlers = {
  [METHOD_GET_STATUS_FULL]: handleGetStatus,
  [METHOD_LIST_SPACES_FULL]: handleListSpaces,
  [METHOD_GET_SPACE_FULL]: handleGetSpace,
  [METHOD_FIND_SAVED_OBJECTS_FULL]: handleFindSavedObjects,
  [METHOD_GET_SAVED_OBJECT_FULL]: handleGetSavedObject,
  [METHOD_BULK_GET_SAVED_OBJECTS_FULL]: handleBulkGetSavedObjects,
  [METHOD_EXPORT_SAVED_OBJECTS_FULL]: handleExportSavedObjects,
};

export const rpcdef = (ctx) => ({
  '/Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetStatus': () => handleGetStatus({}, ctx),
  '/Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/ListSpaces': () => handleListSpaces({}, ctx),
  '/Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetSpace': (req) => handleGetSpace(req, ctx),
  '/Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/FindSavedObjects': (req) => handleFindSavedObjects(req, ctx),
  '/Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetSavedObject': (req) => handleGetSavedObject(req, ctx),
  '/Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/BulkGetSavedObjects': (req) => handleBulkGetSavedObjects(req, ctx),
  '/Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/ExportSavedObjects': (req) => handleExportSavedObjects(req, ctx),
});

export const _test = {
  resolveBaseUrl,
  resolveUsername,
  resolvePassword,
  buildBasicAuth,
  toTrimmedString,
  toFiniteInt,
  toBool,
  toJsonString,
  errorWithCode,
  buildHeaders,
  parseJsonOrThrowUnknown,
  ensureSuccess,
  tryParseJson,
};