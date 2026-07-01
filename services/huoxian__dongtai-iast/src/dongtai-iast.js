// Huoxian_IAST_DONGTAI DongTai IAST REST API proxy
// Bindings: endpoint/baseUrl (required), headers (optional), timeoutMs (optional)
// Auth: Token-based (Authorization: Token <token>)

import { GrpcError, grpcStatus } from '@chaitin-ai/octobus-sdk';
import { Agent } from 'undici';

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_TIMEOUT_MS = 120000;
const DEFAULT_PAGE = 1;
const DEFAULT_PAGE_SIZE = 20;
const MAX_PAGE_SIZE = 1000;
const MAX_RESPONSE_BYTES = 1024 * 1024;

let insecureTlsDispatcher;

const getInsecureTlsDispatcher = () => {
  insecureTlsDispatcher ??= new Agent({ connect: { rejectUnauthorized: false } });
  return insecureTlsDispatcher;
};

// gRPC method paths
const LIST_VULNS_PATH = '/Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/ListVulnerabilities';
const GET_VULN_PATH = '/Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/GetVulnerability';
const UPDATE_VULN_STATUS_PATH = '/Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/UpdateVulnStatus';
const GET_VULN_SUMMARY_PATH = '/Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/GetVulnSummary';
const LIST_PROJECTS_PATH = '/Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/ListProjects';
const GET_PROJECT_PATH = '/Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/GetProject';
const CREATE_PROJECT_PATH = '/Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/CreateProject';
const DELETE_PROJECT_PATH = '/Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/DeleteProject';
const LIST_AGENTS_PATH = '/Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/ListAgents';
const GET_SYSTEM_INFO_PATH = '/Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/GetSystemInfo';
const LIST_STRATEGIES_PATH = '/Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/ListStrategies';
const GET_SCA_DETAIL_PATH = '/Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/GetScaDetail';

// ============ Helpers ============

const grpcCodeFor = (code) => ({
  INVALID_ARGUMENT: grpcStatus.INVALID_ARGUMENT,
  FAILED_PRECONDITION: grpcStatus.FAILED_PRECONDITION,
  PERMISSION_DENIED: grpcStatus.PERMISSION_DENIED,
  UNAUTHENTICATED: grpcStatus.UNAUTHENTICATED,
  UNAVAILABLE: grpcStatus.UNAVAILABLE,
  DEADLINE_EXCEEDED: grpcStatus.DEADLINE_EXCEEDED,
  RESOURCE_EXHAUSTED: grpcStatus.RESOURCE_EXHAUSTED,
})[code] ?? grpcStatus.UNKNOWN;

const errorWithCode = (code, message) => {
  const err = new GrpcError(grpcCodeFor(code), `${code}: ${message}`);
  err.legacyCode = code;
  return err;
};

const toValue = (val) => {
  if (val === undefined || val === null) return undefined;
  if (typeof val === 'string') return { stringValue: val };
  if (typeof val === 'number') return { numberValue: val };
  if (typeof val === 'boolean') return { boolValue: val };
  if (Array.isArray(val)) {
    const values = val.map((item) => toValue(item)).filter((item) => item !== undefined);
    return { listValue: { values } };
  }
  if (typeof val === 'object') {
    const fields = {};
    for (const [k, v] of Object.entries(val)) {
      const normalized = toValue(v);
      fields[k] = normalized === undefined ? { nullValue: 'NULL_VALUE' } : normalized;
    }
    return { structValue: { fields } };
  }
  return { stringValue: String(val) };
};

const toStruct = (obj) => {
  if (obj === undefined || obj === null) return { fields: {} };
  const fields = {};
  for (const [k, v] of Object.entries(obj)) {
    const normalized = toValue(v);
    fields[k] = normalized === undefined ? { nullValue: 'NULL_VALUE' } : normalized;
  }
  return { fields };
};

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj ?? {}, key);

const firstDefined = (...vals) => vals.find((v) => v !== undefined && v !== null);

const toPositiveInt = (val) => {
  if (val === undefined || val === null) return null;
  if (typeof val === 'object' && 'value' in val) return toPositiveInt(val.value);
  const n = Number(val);
  if (!Number.isInteger(n) || Number.isNaN(n) || n < 0) return null;
  return n;
};

const toBoolean = (value) => value === true || value === 1 || value === '1'
  || (typeof value === 'string' && value.trim().toLowerCase() === 'true');

// Protobuf3 string fields default to "" — treat empty strings as absent
// so the handler falls through to secret bindings or defaults.
const unwrapString = (source) => {
  if (source === undefined || source === null) return '';
  if (typeof source === 'object' && source !== null && 'value' in source) {
    return String(source.value ?? '');
  }
  return String(source);
};

const unwrapNonEmpty = (source) => {
  const v = unwrapString(source);
  return v.trim() ? v : undefined;
};

const pickStringField = (req, keys) => {
  for (const key of keys) {
    if (hasOwn(req, key)) return unwrapNonEmpty(req[key]);
  }
  return undefined;
};

const mergedBindings = (ctx = {}) => ({
  ...(ctx?.config ?? {}),
  ...(ctx?.secret ?? {}),
  ...(ctx?.bindings ?? {}),
});

const parseHeaders = (value) => {
  if (value === undefined || value === null || value === '') return {};
  if (typeof value === 'object' && !Array.isArray(value)) return value;
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    } catch { return {}; }
  }
  return {};
};

const normalizeBaseUrl = (url) => {
  try {
    const parsed = new URL(String(url || '').trim());
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) {
      return null;
    }
    return parsed.toString().replace(/\/$/, '');
  } catch {
    return null;
  }
};

// ============ Core HTTP Client ============

export function rpcdef(ctx) {
  const bindings = mergedBindings(ctx);
  const baseUrl = normalizeBaseUrl(
    bindings.endpoint || bindings.baseUrl || bindings.base_url || bindings.restBaseUrl || ''
  );
  const rawTimeout = firstDefined(ctx?.limits?.timeoutMs, bindings.timeoutMs);
  const configuredTimeout = Number(rawTimeout);
  const timeoutMs = Number.isInteger(configuredTimeout) && configuredTimeout > 0
    ? Math.min(configuredTimeout, MAX_TIMEOUT_MS)
    : DEFAULT_TIMEOUT_MS;
  const baseHeaders = parseHeaders(bindings.headers);
  const meta = ctx.meta || {};
  const skipTlsVerify = [bindings.tlsInsecureSkipVerify, bindings.skipTlsVerify, bindings.skip_tls_verify]
    .some(toBoolean);

  const requestWithDefaults = (req = {}) => {
    // Protobuf3 string fields default to "" rather than undefined,
    // so we treat empty strings as absent and fall through to secret bindings.
    const reqToken = [req?.token, req?.api_token, req?.apiToken].find((v) => v && String(v).trim()) || undefined;
    const bindingToken = [bindings.api_token, bindings.apiToken].find((v) => v && String(v).trim()) || undefined;
    const token = reqToken || bindingToken;
    if (token === undefined || token === null) return req ?? {};
    // Spread req first so token override takes precedence over protobuf3 empty-string defaults
    return { ...(req ?? {}), token };
  };

  const logFlow = (action, details) => {
    const inst = meta.instance_id || meta.instanceId;
    const reqId = meta.request_id || meta.requestId;
    const trace = [];
    if (inst) trace.push(`inst=${inst}`);
    if (reqId) trace.push(`req=${reqId}`);
    const prefix = `[Huoxian_IAST_DONGTAI][${action}]${trace.length ? `[${trace.join(' ')}]` : ''}`;
    try { console.log(prefix, JSON.stringify(details)); } catch { console.log(prefix, details); }
  };

  const buildHeaders = (apiToken) => ({
    ...baseHeaders,
    'Authorization': `Token ${apiToken}`,
    'Content-Type': 'application/json',
    'x-engine-instance': meta.instance_id || meta.instanceId || 'unknown',
    'x-request-id': meta.request_id || meta.requestId || 'unknown',
  });

  const tlsOptions = () => (skipTlsVerify ? { dispatcher: getInsecureTlsDispatcher() } : {});

  const pageOrDefault = (value, field, fallback, maximum) => {
    if (value === undefined || value === null || value === '' || Number(value) === 0) return fallback;
    const parsed = toPositiveInt(value);
    if (parsed === null || parsed < 1 || parsed > maximum) {
      throw errorWithCode('INVALID_ARGUMENT', `${field} must be in [1, ${maximum}]`);
    }
    return parsed;
  };

  const readResponseText = async (res) => {
    const contentLength = Number(res.headers?.get?.('content-length'));
    if (Number.isFinite(contentLength) && contentLength > MAX_RESPONSE_BYTES) {
      throw errorWithCode('RESOURCE_EXHAUSTED', 'upstream response exceeds maximum size');
    }
    if (!res.body?.getReader) {
      const text = await res.text();
      if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) {
        throw errorWithCode('RESOURCE_EXHAUSTED', 'upstream response exceeds maximum size');
      }
      return text;
    }
    const reader = res.body.getReader();
    const chunks = [];
    let received = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > MAX_RESPONSE_BYTES) {
          await reader.cancel();
          throw errorWithCode('RESOURCE_EXHAUSTED', 'upstream response exceeds maximum size');
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const joined = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) {
      joined.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder().decode(joined);
  };

  const fetchDongtai = async (url, init) => {
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    try {
      return await fetch(url, { ...init, signal: controller.signal, redirect: 'error', ...tlsOptions() });
    } catch (e) {
      if (timedOut || e?.name === 'TimeoutError' || e?.name === 'AbortError') {
        throw errorWithCode('DEADLINE_EXCEEDED', `request timed out after ${timeoutMs}ms`);
      }
      throw errorWithCode('UNAVAILABLE', 'upstream request failed');
    } finally {
      clearTimeout(timer);
    }
  };

  const throwForHttpError = (status) => {
    // Never log upstream bodies: IAST errors can contain credentials, headers, or stack traces.
    try { console.error(`[Huoxian_IAST_DONGTAI] upstream request failed with HTTP ${status}`); } catch { /* ignore */ }
    if (status === 401) throw errorWithCode('UNAUTHENTICATED', `upstream returned ${status}`);
    if (status === 403) throw errorWithCode('PERMISSION_DENIED', `upstream returned ${status}`);
    if (status >= 400 && status < 500) throw errorWithCode('FAILED_PRECONDITION', `upstream returned ${status}`);
    throw errorWithCode('UNAVAILABLE', `upstream returned ${status}`);
  };

  const readJsonResponse = async (res, emptyValue) => {
    const text = await readResponseText(res);
    if (!res.ok) throwForHttpError(res.status);
    if (!text.trim()) return emptyValue;
    try { return JSON.parse(text); } catch {
      throw errorWithCode('UNKNOWN', 'response is not valid JSON');
    }
  };

  const requireToken = (req) => {
    // Treat empty strings (protobuf3 defaults) as absent
    const token = [req?.token, req?.api_token, req?.apiToken]
      .find((v) => v !== undefined && v !== null && String(v).trim()) || '';
    const normalized = String(token).trim();
    if (!normalized) throw errorWithCode('INVALID_ARGUMENT', 'token is required');
    if (/[\r\n]/.test(normalized)) throw errorWithCode('INVALID_ARGUMENT', 'token must not contain line breaks');
    return normalized.replace(/^Token\s+/i, '');
  };

  const requireBaseUrl = () => {
    if (!baseUrl) throw errorWithCode('INVALID_ARGUMENT', 'endpoint/baseUrl is required (http/https)');
    return baseUrl;
  };

  const requireRecordID = (rawId) => {
    const id = toPositiveInt(rawId);
    if (id === null || id < 1) throw errorWithCode('INVALID_ARGUMENT', 'id must be a positive integer');
    return id;
  };

  // ============ API Methods ============

  const callListVulnerabilities = async (req) => {
    const token = requireToken(req);
    const base = requireBaseUrl();

    const params = [];
    const projectId = toPositiveInt(firstDefined(req?.project_id, req?.projectId));
    if (projectId !== null) params.push(`project_id=${projectId}`);
    const levelId = toPositiveInt(firstDefined(req?.level_id, req?.levelId));
    if (levelId !== null) params.push(`level_id=${levelId}`);
    const vulType = pickStringField(req, ['vul_type', 'vulType']);
    if (vulType) params.push(`vul_type=${encodeURIComponent(vulType)}`);
    const state = pickStringField(req, ['state']);
    if (state) params.push(`state=${encodeURIComponent(state)}`);
    const page = pageOrDefault(firstDefined(req?.page), 'page', DEFAULT_PAGE, MAX_PAGE_SIZE);
    params.push(`page=${page}`);
    const pageSize = pageOrDefault(firstDefined(req?.page_size, req?.pageSize), 'page_size', DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE);
    params.push(`page_size=${pageSize}`);

    const url = `${base}/api/v1/vulns${params.length ? `?${params.join('&')}` : ''}`;
    const headers = buildHeaders(token);

    logFlow('ListVulnerabilities', { url: '/api/v1/vulns', project_id: projectId, level_id: levelId });
    const res = await fetchDongtai(url, { method: 'GET', headers });
    const json = await readJsonResponse(res, { status: 201, data: [], page: {} });

    const vulns = Array.isArray(json?.data) ? json.data.map(mapVulnRecord) : [];
    return {
      vulns,
      total: Number(json?.page?.alltotal ?? 0),
      num_pages: Number(json?.page?.num_pages ?? 1),
      page_size: Number(json?.page?.page_size ?? pageSize),
    };
  };

  const callGetVulnerability = async (req) => {
    const token = requireToken(req);
    const base = requireBaseUrl();
    const rawId = firstDefined(req?.id, req?.Id);
    if (rawId === undefined || rawId === null) throw errorWithCode('INVALID_ARGUMENT', 'id is required');
    const id = requireRecordID(rawId);

    const url = `${base}/api/v1/vuln/${id}`;
    const headers = buildHeaders(token);

    logFlow('GetVulnerability', { id });
    const res = await fetchDongtai(url, { method: 'GET', headers });
    const json = await readJsonResponse(res, {});

    const vuln = mapVulnRecord(json?.data ?? json);
    return { vuln, raw: toStruct(json) };
  };

  const callUpdateVulnStatus = async (req) => {
    const token = requireToken(req);
    const base = requireBaseUrl();
    const rawId = firstDefined(req?.id, req?.Id);
    if (rawId === undefined || rawId === null) throw errorWithCode('INVALID_ARGUMENT', 'id is required');
    const id = requireRecordID(rawId);

    const status = String(firstDefined(req?.status) || '').trim();
    if (!status) throw errorWithCode('INVALID_ARGUMENT', 'status is required');
    const validStatuses = ['confirmed', 'ignored', 'recheck', 'fake'];
    if (!validStatuses.includes(status)) {
      throw errorWithCode('INVALID_ARGUMENT', `status must be one of: ${validStatuses.join(', ')}`);
    }

    const url = `${base}/api/v1/vuln/status`;
    const headers = buildHeaders(token);
    const payload = { id, status };

    logFlow('UpdateVulnStatus', { id, status });
    const res = await fetchDongtai(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });
    const json = await readJsonResponse(res, {});
    return { raw: toStruct(json) };
  };

  const callGetVulnSummary = async (req) => {
    const token = requireToken(req);
    const base = requireBaseUrl();

    const params = [];
    const projectId = toPositiveInt(firstDefined(req?.project_id, req?.projectId));
    if (projectId !== null) params.push(`project_id=${projectId}`);

    const url = `${base}/api/v1/vuln/summary_type${params.length ? `?${params.join('&')}` : ''}`;
    const headers = buildHeaders(token);

    logFlow('GetVulnSummary', {});
    const res = await fetchDongtai(url, { method: 'GET', headers });
    const json = await readJsonResponse(res, {});

    const levels = Array.isArray(json?.data?.level)
      ? json.data.level.map((item) => ({
          level: String(item?.level ?? ''),
          level_id: Number(item?.level_id ?? 0),
          count: Number(item?.count ?? 0),
        }))
      : [];

    const types = Array.isArray(json?.data?.type)
      ? json.data.type.map((item) => ({
          vul_type: String(item?.vul_type ?? ''),
          count: Number(item?.count ?? 0),
        }))
      : [];

    return { levels, types };
  };

  const callListProjects = async (req) => {
    const token = requireToken(req);
    const base = requireBaseUrl();

    const params = [];
    const name = pickStringField(req, ['name', 'Name']);
    if (name) params.push(`name=${encodeURIComponent(name)}`);
    const page = pageOrDefault(firstDefined(req?.page), 'page', DEFAULT_PAGE, MAX_PAGE_SIZE);
    params.push(`page=${page}`);
    const pageSize = pageOrDefault(firstDefined(req?.page_size, req?.pageSize), 'page_size', DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE);
    params.push(`page_size=${pageSize}`);

    const url = `${base}/api/v1/projects${params.length ? `?${params.join('&')}` : ''}`;
    const headers = buildHeaders(token);

    logFlow('ListProjects', {});
    const res = await fetchDongtai(url, { method: 'GET', headers });
    const json = await readJsonResponse(res, { status: 201, data: [], page: {} });

    const projects = Array.isArray(json?.data) ? json.data.map(mapProjectRecord) : [];
    return {
      projects,
      total: Number(json?.page?.alltotal ?? 0),
      num_pages: Number(json?.page?.num_pages ?? 1),
      page_size: Number(json?.page?.page_size ?? pageSize),
    };
  };

  const callGetProject = async (req) => {
    const token = requireToken(req);
    const base = requireBaseUrl();
    const rawId = firstDefined(req?.id, req?.Id);
    if (rawId === undefined || rawId === null) throw errorWithCode('INVALID_ARGUMENT', 'id is required');
    const id = requireRecordID(rawId);

    const url = `${base}/api/v1/project/${id}`;
    const headers = buildHeaders(token);

    logFlow('GetProject', { id });
    const res = await fetchDongtai(url, { method: 'GET', headers });
    const json = await readJsonResponse(res, {});

    const project = mapProjectRecord(json?.data ?? json);
    return { project, raw: toStruct(json) };
  };

  const callCreateProject = async (req) => {
    const token = requireToken(req);
    const base = requireBaseUrl();
    const name = String(firstDefined(req?.name, req?.Name) || '').trim();
    if (!name) throw errorWithCode('INVALID_ARGUMENT', 'name is required');

    const payload = { name };
    const mode = pickStringField(req, ['mode', 'Mode']);
    if (mode) payload.mode = mode;
    const versionName = pickStringField(req, ['version_name', 'versionName']);
    if (versionName) payload.version_name = versionName;
    const description = pickStringField(req, ['description', 'Description']);
    if (description) payload.description = description;

    const url = `${base}/api/v1/project/add`;
    const headers = buildHeaders(token);

    logFlow('CreateProject', { name });
    const res = await fetchDongtai(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });
    const json = await readJsonResponse(res, {});

    return {
      id: Number(json?.data?.id ?? json?.id ?? 0),
      name: String(json?.data?.name ?? name),
    };
  };

  const callDeleteProject = async (req) => {
    const token = requireToken(req);
    const base = requireBaseUrl();
    const rawId = firstDefined(req?.id, req?.Id);
    if (rawId === undefined || rawId === null) throw errorWithCode('INVALID_ARGUMENT', 'id is required');
    const id = requireRecordID(rawId);

    const url = `${base}/api/v1/project/delete`;
    const headers = buildHeaders(token);
    const payload = { id };

    logFlow('DeleteProject', { id });
    const res = await fetchDongtai(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });
    const json = await readJsonResponse(res, {});
    return { raw: toStruct(json) };
  };

  const callListAgents = async (req) => {
    const token = requireToken(req);
    const base = requireBaseUrl();

    const params = [];
    const projectId = toPositiveInt(firstDefined(req?.project_id, req?.projectId));
    if (projectId !== null) params.push(`project_id=${projectId}`);
    const state = pickStringField(req, ['state', 'State']);
    if (state) params.push(`state=${encodeURIComponent(state)}`);
    const page = pageOrDefault(firstDefined(req?.page), 'page', DEFAULT_PAGE, MAX_PAGE_SIZE);
    params.push(`page=${page}`);
    const pageSize = pageOrDefault(firstDefined(req?.page_size, req?.pageSize), 'page_size', DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE);
    params.push(`page_size=${pageSize}`);

    const url = `${base}/api/v1/agents${params.length ? `?${params.join('&')}` : ''}`;
    const headers = buildHeaders(token);

    logFlow('ListAgents', {});
    const res = await fetchDongtai(url, { method: 'GET', headers });
    const json = await readJsonResponse(res, { status: 201, data: [], page: {} });

    const agents = Array.isArray(json?.data) ? json.data.map(mapAgentRecord) : [];
    return {
      agents,
      total: Number(json?.page?.alltotal ?? 0),
      num_pages: Number(json?.page?.num_pages ?? 1),
      page_size: Number(json?.page?.page_size ?? pageSize),
    };
  };

  const callGetSystemInfo = async (req) => {
    const token = requireToken(req);
    const base = requireBaseUrl();

    const url = `${base}/api/v1/system/info`;
    const headers = buildHeaders(token);

    logFlow('GetSystemInfo', {});
    const res = await fetchDongtai(url, { method: 'GET', headers });
    const json = await readJsonResponse(res, {});
    return { raw: toStruct(json) };
  };

  const callListStrategies = async (req) => {
    const token = requireToken(req);
    const base = requireBaseUrl();

    const url = `${base}/api/v1/strategys`;
    const headers = buildHeaders(token);

    logFlow('ListStrategies', {});
    const res = await fetchDongtai(url, { method: 'GET', headers });
    const json = await readJsonResponse(res, {});

    let strategies = Array.isArray(json?.data) ? json.data : [];
    const vulType = pickStringField(req, ['vul_type', 'vulType']);
    const levelId = toPositiveInt(firstDefined(req?.level_id, req?.levelId));
    const state = pickStringField(req, ['state', 'State']);

    if (vulType) strategies = strategies.filter((s) => s?.vul_type === vulType);
    if (levelId !== null) strategies = strategies.filter((s) => Number(s?.level_id) === levelId);
    if (state) strategies = strategies.filter((s) => s?.state === state);

    return {
      strategies: strategies.map(mapStrategyRecord),
    };
  };

  const callGetScaDetail = async (req) => {
    const token = requireToken(req);
    const base = requireBaseUrl();
    const rawId = firstDefined(req?.id, req?.Id);
    if (rawId === undefined || rawId === null) throw errorWithCode('INVALID_ARGUMENT', 'id is required');
    const id = requireRecordID(rawId);

    const url = `${base}/api/v1/sca/${id}`;
    const headers = buildHeaders(token);

    logFlow('GetScaDetail', { id });
    const res = await fetchDongtai(url, { method: 'GET', headers });
    const json = await readJsonResponse(res, {});
    return { raw: toStruct(json) };
  };

  // ============ Record Mappers ============

  const mapVulnRecord = (item) => ({
    id: Number(item?.id ?? 0),
    vul_name: String(item?.vul_name ?? ''),
    vul_type: String(item?.vul_type ?? ''),
    level_id: Number(item?.level_id ?? 0),
    level_name: String(item?.level_name ?? ''),
    state: String(item?.state ?? ''),
    url: String(item?.url ?? ''),
    req_header: String(item?.req_header ?? ''),
    req_data: String(item?.req_data ?? ''),
    res_header: String(item?.res_header ?? ''),
    res_data: String(item?.res_data ?? ''),
    full_stack: String(item?.full_stack ?? ''),
    top_stack: String(item?.top_stack ?? ''),
    bottom_stack: String(item?.bottom_stack ?? ''),
    project_id: Number(item?.project_id ?? 0),
    project_name: String(item?.project_name ?? ''),
    agent_id: Number(item?.agent_id ?? 0),
    language: String(item?.language ?? ''),
    first_time: String(item?.first_time ?? ''),
    latest_time: String(item?.latest_time ?? ''),
    count: Number(item?.count ?? 0),
  });

  const mapProjectRecord = (item) => ({
    id: Number(item?.id ?? 0),
    name: String(item?.name ?? ''),
    mode: String(item?.mode ?? ''),
    agent_count: Number(item?.agent_count ?? 0),
    owner: String(item?.owner ?? ''),
    latest_time: String(item?.latest_time ?? ''),
    agent_language: Array.isArray(item?.agent_language) ? item.agent_language : [],
    vul_count: Number(item?.vul_count ?? 0),
    status: Number(item?.status ?? 0),
    version_name: String(item?.versionData?.version_name ?? item?.version_name ?? ''),
  });

  const mapAgentRecord = (item) => ({
    id: Number(item?.id ?? 0),
    token_value: String(item?.token ?? item?.token_value ?? ''),
    alias: String(item?.alias ?? ''),
    language: String(item?.language ?? ''),
    state: String(item?.state ?? ''),
    project_id: Number(item?.project_id ?? item?.bind_project_id ?? 0),
    project_name: String(item?.project_name ?? ''),
    server: String(item?.server ?? item?.server_ip ?? ''),
    runtime: String(item?.runtime ?? ''),
    latest_time: String(item?.latest_time ?? ''),
  });

  const mapStrategyRecord = (item) => ({
    id: Number(item?.id ?? 0),
    vul_type: String(item?.vul_type ?? ''),
    vul_name: String(item?.vul_name ?? ''),
    vul_desc: String(item?.vul_desc ?? ''),
    level_id: Number(item?.level_id ?? 0),
    state: String(item?.state ?? ''),
  });

  // ============ Return RPC Definitions ============

  const request = ctx?.request ?? ctx?.req ?? {};
  return {
    [LIST_VULNS_PATH]: async () => callListVulnerabilities(requestWithDefaults(request)),
    [GET_VULN_PATH]: async () => callGetVulnerability(requestWithDefaults(request)),
    [UPDATE_VULN_STATUS_PATH]: async () => callUpdateVulnStatus(requestWithDefaults(request)),
    [GET_VULN_SUMMARY_PATH]: async () => callGetVulnSummary(requestWithDefaults(request)),
    [LIST_PROJECTS_PATH]: async () => callListProjects(requestWithDefaults(request)),
    [GET_PROJECT_PATH]: async () => callGetProject(requestWithDefaults(request)),
    [CREATE_PROJECT_PATH]: async () => callCreateProject(requestWithDefaults(request)),
    [DELETE_PROJECT_PATH]: async () => callDeleteProject(requestWithDefaults(request)),
    [LIST_AGENTS_PATH]: async () => callListAgents(requestWithDefaults(request)),
    [GET_SYSTEM_INFO_PATH]: async () => callGetSystemInfo(requestWithDefaults(request)),
    [LIST_STRATEGIES_PATH]: async () => callListStrategies(requestWithDefaults(request)),
    [GET_SCA_DETAIL_PATH]: async () => callGetScaDetail(requestWithDefaults(request)),
  };
}

// ============ SDK Handler Registration ============

const wrapHandler = (methodPath) => async (ctx) => rpcdef(ctx)[methodPath]();

export const METHOD_LIST_VULNS_FULL = 'Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/ListVulnerabilities';
export const METHOD_GET_VULN_FULL = 'Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/GetVulnerability';
export const METHOD_UPDATE_VULN_STATUS_FULL = 'Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/UpdateVulnStatus';
export const METHOD_GET_VULN_SUMMARY_FULL = 'Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/GetVulnSummary';
export const METHOD_LIST_PROJECTS_FULL = 'Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/ListProjects';
export const METHOD_GET_PROJECT_FULL = 'Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/GetProject';
export const METHOD_CREATE_PROJECT_FULL = 'Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/CreateProject';
export const METHOD_DELETE_PROJECT_FULL = 'Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/DeleteProject';
export const METHOD_LIST_AGENTS_FULL = 'Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/ListAgents';
export const METHOD_GET_SYSTEM_INFO_FULL = 'Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/GetSystemInfo';
export const METHOD_LIST_STRATEGIES_FULL = 'Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/ListStrategies';
export const METHOD_GET_SCA_DETAIL_FULL = 'Huoxian_IAST_DONGTAI.Huoxian_IAST_DONGTAI/GetScaDetail';

export const handlers = {
  [METHOD_LIST_VULNS_FULL]: wrapHandler(LIST_VULNS_PATH),
  [METHOD_GET_VULN_FULL]: wrapHandler(GET_VULN_PATH),
  [METHOD_UPDATE_VULN_STATUS_FULL]: wrapHandler(UPDATE_VULN_STATUS_PATH),
  [METHOD_GET_VULN_SUMMARY_FULL]: wrapHandler(GET_VULN_SUMMARY_PATH),
  [METHOD_LIST_PROJECTS_FULL]: wrapHandler(LIST_PROJECTS_PATH),
  [METHOD_GET_PROJECT_FULL]: wrapHandler(GET_PROJECT_PATH),
  [METHOD_CREATE_PROJECT_FULL]: wrapHandler(CREATE_PROJECT_PATH),
  [METHOD_DELETE_PROJECT_FULL]: wrapHandler(DELETE_PROJECT_PATH),
  [METHOD_LIST_AGENTS_FULL]: wrapHandler(LIST_AGENTS_PATH),
  [METHOD_GET_SYSTEM_INFO_FULL]: wrapHandler(GET_SYSTEM_INFO_PATH),
  [METHOD_LIST_STRATEGIES_FULL]: wrapHandler(LIST_STRATEGIES_PATH),
  [METHOD_GET_SCA_DETAIL_FULL]: wrapHandler(GET_SCA_DETAIL_PATH),
};

export const _test = {
  errorWithCode,
  firstDefined,
  mergedBindings,
  normalizeBaseUrl,
  parseHeaders,
  toPositiveInt,
  toStruct,
  toValue,
  unwrapString,
};
