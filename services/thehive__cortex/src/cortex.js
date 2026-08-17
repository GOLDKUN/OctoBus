// TheHive_CORTEX Cortex REST proxy implementation
// Bindings: endpoint/restBaseUrl/baseUrl (required), headers (optional), timeoutMs (optional)
// Auth: Cortex API key passed as a Bearer token.

import { GrpcError, grpcStatus } from '@chaitin-ai/octobus-sdk';
import { Agent as UndiciAgent } from 'undici';

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const SECURE_DISPATCHER = new UndiciAgent({ connect: { rejectUnauthorized: true } });

const METHOD_LIST_ANALYZERS = '/TheHive_CORTEX.TheHive_CORTEX/ListAnalyzers';
const METHOD_ANALYZE_OBSERVABLE = '/TheHive_CORTEX.TheHive_CORTEX/AnalyzeObservable';
const METHOD_GET_JOB_REPORT = '/TheHive_CORTEX.TheHive_CORTEX/GetJobReport';
const METHOD_LIST_JOBS = '/TheHive_CORTEX.TheHive_CORTEX/ListJobs';
const METHOD_GET_JOB_STATUS = '/TheHive_CORTEX.TheHive_CORTEX/GetJobStatus';

const grpcCodeFor = (code) => ({
  INVALID_ARGUMENT: grpcStatus.INVALID_ARGUMENT,
  FAILED_PRECONDITION: grpcStatus.FAILED_PRECONDITION,
  UNAUTHENTICATED: grpcStatus.UNAUTHENTICATED,
  PERMISSION_DENIED: grpcStatus.PERMISSION_DENIED,
  RESOURCE_EXHAUSTED: grpcStatus.RESOURCE_EXHAUSTED,
  UNAVAILABLE: grpcStatus.UNAVAILABLE,
  DEADLINE_EXCEEDED: grpcStatus.DEADLINE_EXCEEDED,
})[code] ?? grpcStatus.UNKNOWN;

const errorWithCode = (code, message) => {
  const err = new GrpcError(grpcCodeFor(code), `${code}: ${message}`);
  err.legacyCode = code;
  return err;
};

const firstDefined = (...vals) => vals.find((v) => v !== undefined && v !== null && v !== '');

const BLOCKED_HEADER_NAMES = new Set([
  'authorization', 'connection', 'content-length', 'content-type', 'host',
  'proxy-authorization', 'transfer-encoding',
]);

const mergedBindings = (ctx = {}) => ({
  ...(ctx?.config ?? {}),
  ...(ctx?.secret ?? {}),
  ...(ctx?.bindings ?? {}),
});

const parseHeaders = (value) => {
  if (value === undefined || value === null || value === '') return {};
  if (typeof value === 'object' && !Array.isArray(value)) return sanitizeHeaders(value);
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return sanitizeHeaders(parsed);
    } catch {
      return {};
    }
  }
  return {};
};

const sanitizeHeaders = (headers) => {
  const safe = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (!BLOCKED_HEADER_NAMES.has(name.toLowerCase()) && typeof value === 'string') safe[name] = value;
  }
  return safe;
};

const normalizeBaseUrl = (url) => {
  try {
    const parsed = new URL(String(url || '').trim());
    const loopback = ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
    if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) return null;
    if (parsed.username || parsed.password || parsed.search || parsed.hash) return null;
    parsed.pathname = parsed.pathname === '/' ? '' : parsed.pathname.replace(/\/+$/, '');
    return parsed.toString().replace(/\/$/, '');
  } catch {
    return null;
  }
};

const resolveTimeoutMs = (value) => {
  if (value === undefined || value === null || value === '') return DEFAULT_TIMEOUT_MS;
  const timeout = Number(value);
  if (!Number.isSafeInteger(timeout) || timeout < 1) {
    throw errorWithCode('INVALID_ARGUMENT', 'timeoutMs must be a positive integer');
  }
  return timeout;
};

const readResponseText = async (response) => {
  const declared = Number(response.headers?.get?.('content-length'));
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw errorWithCode('RESOURCE_EXHAUSTED', 'upstream response exceeds the 4 MiB limit');
  }
  if (!response.body?.getReader) {
    const text = String(await response.text());
    if (Buffer.byteLength(text) > MAX_RESPONSE_BYTES) {
      throw errorWithCode('RESOURCE_EXHAUSTED', 'upstream response exceeds the 4 MiB limit');
    }
    return text;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw errorWithCode('RESOURCE_EXHAUSTED', 'upstream response exceeds the 4 MiB limit');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return new TextDecoder().decode(Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))));
};

const toPositiveInt = (val) => {
  if (val === undefined || val === null) return null;
  if (typeof val === 'object') {
    if ('value' in val) return toPositiveInt(val.value);
    return null;
  }
  const n = Number(val);
  if (!Number.isInteger(n) || Number.isNaN(n)) return null;
  return n;
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

const PROTO_VALUE_KEYS = new Set([
  'stringValue', 'numberValue', 'boolValue', 'nullValue', 'listValue', 'structValue',
]);

const isProtoValue = (value) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  if (keys.length !== 1 || !PROTO_VALUE_KEYS.has(keys[0])) return false;
  if (keys[0] === 'listValue') {
    return Array.isArray(value.listValue?.values) && value.listValue.values.every(isProtoValue);
  }
  if (keys[0] === 'structValue') {
    const fields = value.structValue?.fields;
    return fields && typeof fields === 'object' && !Array.isArray(fields) &&
      Object.values(fields).every(isProtoValue);
  }
  return true;
};

const decodeProtoValue = (value) => {
  if ('stringValue' in value) return String(value.stringValue ?? '');
  if ('numberValue' in value) return Number(value.numberValue);
  if ('boolValue' in value) return Boolean(value.boolValue);
  if ('nullValue' in value) return null;
  if ('listValue' in value) return value.listValue.values.map(decodeProtoValue);
  return Object.fromEntries(Object.entries(value.structValue.fields)
    .map(([key, child]) => [key, decodeProtoValue(child)]));
};

const normalizeParameters = (value) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
  const keys = Object.keys(value);
  const fields = value.fields;
  if (keys.length !== 1 || !fields || typeof fields !== 'object' || Array.isArray(fields) ||
      !Object.values(fields).every(isProtoValue)) {
    return value;
  }
  return Object.fromEntries(Object.entries(fields)
    .map(([key, child]) => [key, decodeProtoValue(child)]));
};

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj ?? {}, key);

const unwrapString = (source) => {
  if (source === undefined || source === null) return '';
  if (typeof source === 'object' && source !== null && 'value' in source) {
    return String(source.value ?? '');
  }
  return String(source);
};

const pickStringField = (req, keys) => {
  for (const key of keys) {
    if (hasOwn(req, key)) {
      return unwrapString(req[key]);
    }
  }
  return undefined;
};

export function rpcdef(ctx) {
  const bindings = mergedBindings(ctx);
  const restBaseUrl = bindings.restBaseUrl || bindings.rest_base_url || bindings.baseUrl || bindings.base_url || bindings.endpoint || '';
  const timeoutMs = resolveTimeoutMs(bindings.timeoutMs ?? ctx.limits?.timeoutMs);
  const baseHeaders = parseHeaders(bindings.headers);
  const meta = ctx.meta || {};

  const requestWithDefaults = (req = {}) => {
    const apiKey = firstDefined(req?.api_key, req?.apiKey, bindings.api_key, bindings.apiKey);
    return {
      ...(req ?? {}),
      ...(apiKey !== undefined ? { api_key: apiKey } : {}),
    };
  };

  const logFlow = (action, details) => {
    const inst = meta.instance_id || meta.instanceId;
    const reqId = meta.request_id || meta.requestId;
    const trace = [];
    if (inst) trace.push(`inst=${inst}`);
    if (reqId) trace.push(`req=${reqId}`);
    const prefix = `[TheHive_CORTEX][${action}]${trace.length ? `[${trace.join(' ')}]` : ''}`;
    console.log(prefix, details);
  };

  const buildHeaders = (authInfo, withContentType = true) => {
    const headers = {
      ...baseHeaders,
      'Accept': 'application/json',
      'x-engine-instance': meta.instance_id || meta.instanceId || 'unknown',
      'x-request-id': meta.request_id || meta.requestId || 'unknown',
    };

    if (withContentType) {
      headers['Content-Type'] = 'application/json';
    }

    const apiKey = firstDefined(authInfo?.api_key, authInfo?.apiKey);
    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }
    return headers;
  };

  const fetchCortex = async (url, init) => {
    try {
      return await fetch(url, {
        ...init,
        signal: init?.signal ?? AbortSignal.timeout(timeoutMs),
        dispatcher: SECURE_DISPATCHER,
        redirect: 'error',
      });
    } catch (e) {
      if (e instanceof GrpcError) throw e;
      if (e?.name === 'TimeoutError' || e?.cause?.name === 'TimeoutError') {
        throw errorWithCode('DEADLINE_EXCEEDED', `request timed out after ${timeoutMs}ms`);
      }
      throw errorWithCode('UNAVAILABLE', 'upstream request failed');
    }
  };

  const throwForHttpError = (status) => {
    // Do not log response bodies: they can contain credentials or observables.
    console.log(`[TheHive_CORTEX][http-error] upstream status=${status}`);
    if (status === 401) {
      throw errorWithCode('UNAUTHENTICATED', `upstream http ${status}`);
    }
    if (status === 403) {
      throw errorWithCode('PERMISSION_DENIED', `upstream http ${status}`);
    }
    if (status >= 400 && status < 500) {
      throw errorWithCode('FAILED_PRECONDITION', `upstream http ${status}`);
    }
    throw errorWithCode('UNAVAILABLE', `upstream http ${status}`);
  };

  const readJsonResponse = async (res, emptyValue) => {
    let text;
    try {
      text = await readResponseText(res);
    } catch (e) {
      if (e instanceof GrpcError) throw e;
      if (e?.name === 'TimeoutError' || e?.name === 'AbortError' ||
          e?.cause?.name === 'TimeoutError' || e?.cause?.name === 'AbortError') {
        throw errorWithCode('DEADLINE_EXCEEDED', `request timed out after ${timeoutMs}ms`);
      }
      throw errorWithCode('UNAVAILABLE', 'upstream response could not be read');
    }
    if (!res.ok) {
      throwForHttpError(res.status);
    }
    if (!text.trim()) {
      return emptyValue;
    }
    try {
      return JSON.parse(text);
    } catch {
      throw errorWithCode('UNKNOWN', 'response is not valid JSON');
    }
  };

  const mapAnalyzerData = (item) => ({
    id: String(item?.id ?? item?._id ?? ''),
    name: String(item?.name ?? ''),
    analyzer_definition_id: String(item?.analyzerDefinitionId ?? item?.analyzer_definition_id ?? item?.workerDefinitionId ?? ''),
    description: String(item?.description ?? ''),
    data_type_list: Array.isArray(item?.dataTypeList ?? item?.data_type_list) ? item.dataTypeList ?? item.data_type_list : [],
    version: String(item?.version ?? ''),
    tlp: Number(item?.tlp ?? 2),
    state: String(item?.state ?? ''),
    raw: item ?? {},
  });

  const mapJobData = (item) => ({
    id: String(item?.id ?? item?._id ?? ''),
    analyzer_id: String(item?.analyzerId ?? item?.analyzer_id ?? item?.workerId ?? ''),
    analyzer_name: String(item?.analyzerName ?? item?.analyzer_name ?? item?.workerName ?? ''),
    analyzer_definition_id: String(item?.analyzerDefinitionId ?? item?.analyzer_definition_id ?? item?.workerDefinitionId ?? ''),
    status: String(item?.status ?? ''),
    data_type: String(item?.dataType ?? item?.data_type ?? ''),
    data: String(item?.data ?? ''),
    message: String(item?.message ?? ''),
    tlp: Number(item?.tlp ?? 2),
    date: String(item?.date ?? item?.createdAt ?? ''),
    start_date: String(item?.startDate ?? item?.start_date ?? ''),
    end_date: String(item?.endDate ?? item?.end_date ?? ''),
    raw: item ?? {},
  });

  // ListAnalyzers - GET /api/analyzer or GET /api/analyzer/type/:dataType
  const callListAnalyzers = async (req) => {
    const baseUrl = normalizeBaseUrl(restBaseUrl);
    if (!baseUrl) {
      throw errorWithCode('INVALID_ARGUMENT', 'endpoint/restBaseUrl/baseUrl is required (http/https)');
    }

    const dataType = pickStringField(req, ['data_type', 'dataType', 'DataType']) || '';
    const headers = buildHeaders(req, false);

    const url = dataType
      ? `${baseUrl}/api/analyzer/type/${encodeURIComponent(dataType)}`
      : `${baseUrl}/api/analyzer`;

    logFlow('ListAnalyzers:start', { baseUrl, dataType: dataType || 'all' });
    const res = await fetchCortex(url, { method: 'GET', headers });
    const json = await readJsonResponse(res, []);

    const analyzerList = Array.isArray(json) ? json :
                         Array.isArray(json?.data) ? json.data :
                         json && typeof json === 'object' ? [json] : [];

    logFlow('ListAnalyzers:done', { count: analyzerList.length });
    return {
      data: {
        analyzers: analyzerList.map(mapAnalyzerData),
      },
    };
  };

  // AnalyzeObservable - POST /api/analyzer/:analyzerId/run
  const callAnalyzeObservable = async (req) => {
    const analyzerId = pickStringField(req, ['analyzer_id', 'analyzerId', 'AnalyzerId']) || '';
    if (!analyzerId) {
      throw errorWithCode('INVALID_ARGUMENT', 'analyzer_id is required');
    }

    const data = pickStringField(req, ['data', 'Data']) || '';
    if (!data) {
      throw errorWithCode('INVALID_ARGUMENT', 'data (observable value) is required');
    }

    const dataType = pickStringField(req, ['data_type', 'dataType', 'DataType']) || '';
    if (!dataType) {
      throw errorWithCode('INVALID_ARGUMENT', 'data_type (observable type) is required');
    }

    const baseUrl = normalizeBaseUrl(restBaseUrl);
    if (!baseUrl) {
      throw errorWithCode('INVALID_ARGUMENT', 'endpoint/restBaseUrl/baseUrl is required (http/https)');
    }

    const rawTlp = firstDefined(req?.tlp, req?.Tlp);
    const tlp = toPositiveInt(rawTlp);
    const message = pickStringField(req, ['message', 'Message']) || '';
    const parameters = normalizeParameters(req?.parameters ?? req?.Parameters ?? {});

    const payload = {
      data,
      dataType,
    };
    if (tlp !== null) payload.tlp = tlp;
    if (message) payload.message = message;
    if (typeof parameters === 'object' && Object.keys(parameters).length > 0) payload.parameters = parameters;

    const url = `${baseUrl}/api/analyzer/${encodeURIComponent(analyzerId)}/run`;
    const headers = buildHeaders(req);

    logFlow('AnalyzeObservable:start', { analyzerId, dataType });
    const res = await fetchCortex(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });
    const json = await readJsonResponse(res, {});

    logFlow('AnalyzeObservable:done', { jobId: json?.id ?? json?._id });
    return {
      data: mapJobData(json),
    };
  };

  // GetJobReport - GET /api/job/:jobId/report
  const callGetJobReport = async (req) => {
    const jobId = pickStringField(req, ['job_id', 'jobId', 'JobId']) || '';
    if (!jobId) {
      throw errorWithCode('INVALID_ARGUMENT', 'job_id is required');
    }

    const baseUrl = normalizeBaseUrl(restBaseUrl);
    if (!baseUrl) {
      throw errorWithCode('INVALID_ARGUMENT', 'endpoint/restBaseUrl/baseUrl is required (http/https)');
    }

    const url = `${baseUrl}/api/job/${encodeURIComponent(jobId)}/report`;
    const headers = buildHeaders(req, false);

    logFlow('GetJobReport:start', { jobId });
    const res = await fetchCortex(url, { method: 'GET', headers });
    const json = await readJsonResponse(res, {});

    logFlow('GetJobReport:done', { jobId, success: json?.success ?? json?.report?.success ?? false });
    return {
      data: mapJobReport(json),
    };
  };

  const mapJobReport = (json) => {
    const report = json?.report ?? json;
    const job = json;

    if (typeof report === 'string') {
      // Job still running: report is a status string like "Running" or "Waiting".
      // Use the actual job status from the top-level response (e.g. "InProgress"),
      // not the report string itself, to stay within the proto-defined enum.
      // Wrap the report string in summary so callers can see the upstream message.
      return {
        id: String(job?.id ?? job?._id ?? ''),
        status: String(job?.status ?? 'InProgress'),
        success: false,
        summary: { message: report },
        full: {},
        operations: toValue(null),
        artifacts: [],
        error_message: '',
        input: '',
        raw: job ?? {},
      };
    }

    if (typeof report === 'object' && report !== null) {
      const success = Boolean(report?.success ?? false);
      const summary = success ? (report?.summary ?? {}) : {};
      const full = success ? (report?.full ?? {}) : {};
      const operations = report?.operations ?? null;
      const artifacts = Array.isArray(report?.artifacts) ? report.artifacts.map(mapArtifact) : [];
      const errorMessage = report?.errorMessage ?? '';

      return {
        id: String(job?.id ?? job?._id ?? ''),
        status: success ? 'Success' : (errorMessage ? 'Failure' : String(job?.status ?? '')),
        success,
        summary: typeof summary === 'object' ? summary : {},
        full: typeof full === 'object' ? full : {},
        operations: toValue(operations),
        artifacts,
        error_message: String(errorMessage),
        input: String(report?.input ?? job?.input ?? ''),
        raw: job ?? {},
      };
    }

    return {
      id: String(job?.id ?? job?._id ?? ''),
      status: String(job?.status ?? 'Unknown'),
      success: false,
      summary: {},
      full: {},
      operations: toValue(null),
      artifacts: [],
      error_message: '',
      input: '',
      raw: job ?? {},
    };
  };

  const mapArtifact = (item) => ({
    data: String(item?.data ?? ''),
    data_type: String(item?.dataType ?? item?.data_type ?? ''),
    message: String(item?.message ?? ''),
    tags: Array.isArray(item?.tags) ? item.tags.map(String) : [],
    tlp: Number(item?.tlp ?? 2),
    raw: item ?? {},
  });

  // ListJobs - GET /api/job with query params
  const callListJobs = async (req) => {
    const baseUrl = normalizeBaseUrl(restBaseUrl);
    if (!baseUrl) {
      throw errorWithCode('INVALID_ARGUMENT', 'endpoint/restBaseUrl/baseUrl is required (http/https)');
    }

    const dataType = pickStringField(req, ['data_type', 'dataType', 'DataType']) || '';
    const data = pickStringField(req, ['data', 'Data']) || '';
    const analyzer = pickStringField(req, ['analyzer', 'Analyzer']) || '';
    const range = pickStringField(req, ['range', 'Range']) || 'all';

    const queryParts = [];
    if (dataType) queryParts.push(`dataTypeFilter=${encodeURIComponent(dataType)}`);
    if (data) queryParts.push(`dataFilter=${encodeURIComponent(data)}`);
    if (analyzer) queryParts.push(`analyzerFilter=${encodeURIComponent(analyzer)}`);
    queryParts.push(`range=${encodeURIComponent(range)}`);

    const url = `${baseUrl}/api/job${queryParts.length ? `?${queryParts.join('&')}` : ''}`;
    const headers = buildHeaders(req, false);

    // Observable values can be sensitive; never write the data filter to logs.
    logFlow('ListJobs:start', { dataType, analyzer, range, hasDataFilter: Boolean(data) });
    const res = await fetchCortex(url, { method: 'GET', headers });
    const json = await readJsonResponse(res, []);

    const jobList = Array.isArray(json) ? json :
                    Array.isArray(json?.data) ? json.data :
                    json && typeof json === 'object' ? [json] : [];

    logFlow('ListJobs:done', { count: jobList.length });
    return {
      data: {
        jobs: jobList.map(mapJobData),
      },
    };
  };

  // GetJobStatus - GET /api/job/:jobId (single) or POST /api/job/status (batch)
  const callGetJobStatus = async (req) => {
    const baseUrl = normalizeBaseUrl(restBaseUrl);
    if (!baseUrl) {
      throw errorWithCode('INVALID_ARGUMENT', 'endpoint/restBaseUrl/baseUrl is required (http/https)');
    }

    const singleJobId = pickStringField(req, ['job_id', 'jobId', 'JobId']) || '';
    const batchJobIds = Array.isArray(req?.job_ids ?? req?.jobIds ?? req?.JobIds) ? req.job_ids ?? req.jobIds ?? req.JobIds : [];

    if (singleJobId && batchJobIds.length === 0) {
      // Single job status - GET, no Content-Type
      const headers = buildHeaders(req, false);
      const url = `${baseUrl}/api/job/${encodeURIComponent(singleJobId)}`;
      logFlow('GetJobStatus:start', { jobId: singleJobId });
      const res = await fetchCortex(url, { method: 'GET', headers });
      const json = await readJsonResponse(res, {});
      logFlow('GetJobStatus:done', { jobId: singleJobId, status: json?.status });

      return {
        data: {
          statuses: [{
            job_id: String(json?.id ?? json?._id ?? singleJobId),
            status: String(json?.status ?? 'Unknown'),
          }],
        },
      };
    }

    if (batchJobIds.length > 0) {
      // Cortex exposes single-job lookup; aggregate it for a portable batch RPC.
      const headers = buildHeaders(req, false);
      logFlow('GetJobStatus:start', { jobIds: batchJobIds });
      const statuses = [];
      for (const jobId of batchJobIds) {
        const normalizedId = String(jobId);
        const url = `${baseUrl}/api/job/${encodeURIComponent(normalizedId)}`;
        const res = await fetchCortex(url, { method: 'GET', headers });
        if (res.status === 404) {
          statuses.push({ job_id: normalizedId, status: 'NotFound' });
          continue;
        }
        const json = await readJsonResponse(res, {});
        statuses.push({
          job_id: String(json?.id ?? json?._id ?? normalizedId),
          status: String(json?.status ?? 'Unknown'),
        });
      }

      logFlow('GetJobStatus:done', { count: statuses.length });
      return {
        data: { statuses },
      };
    }

    throw errorWithCode('INVALID_ARGUMENT', 'job_id or job_ids is required');
  };

  return {
    [METHOD_LIST_ANALYZERS]: async () => callListAnalyzers(requestWithDefaults(ctx.req)),
    [METHOD_ANALYZE_OBSERVABLE]: async () => callAnalyzeObservable(requestWithDefaults(ctx.req)),
    [METHOD_GET_JOB_REPORT]: async () => callGetJobReport(requestWithDefaults(ctx.req)),
    [METHOD_LIST_JOBS]: async () => callListJobs(requestWithDefaults(ctx.req)),
    [METHOD_GET_JOB_STATUS]: async () => callGetJobStatus(requestWithDefaults(ctx.req)),
  };
}

export const METHOD_LIST_ANALYZERS_FULL = 'TheHive_CORTEX.TheHive_CORTEX/ListAnalyzers';
export const METHOD_ANALYZE_OBSERVABLE_FULL = 'TheHive_CORTEX.TheHive_CORTEX/AnalyzeObservable';
export const METHOD_GET_JOB_REPORT_FULL = 'TheHive_CORTEX.TheHive_CORTEX/GetJobReport';
export const METHOD_LIST_JOBS_FULL = 'TheHive_CORTEX.TheHive_CORTEX/ListJobs';
export const METHOD_GET_JOB_STATUS_FULL = 'TheHive_CORTEX.TheHive_CORTEX/GetJobStatus';

const handle = (methodPath) => async (ctx = {}) => rpcdef({
  ...ctx,
  req: ctx.request ?? ctx.req ?? {},
})[methodPath]();

export const handlers = {
  [METHOD_LIST_ANALYZERS_FULL]: handle(METHOD_LIST_ANALYZERS),
  [METHOD_ANALYZE_OBSERVABLE_FULL]: handle(METHOD_ANALYZE_OBSERVABLE),
  [METHOD_GET_JOB_REPORT_FULL]: handle(METHOD_GET_JOB_REPORT),
  [METHOD_LIST_JOBS_FULL]: handle(METHOD_LIST_JOBS),
  [METHOD_GET_JOB_STATUS_FULL]: handle(METHOD_GET_JOB_STATUS),
};

export const _test = {
  errorWithCode,
  mergedBindings,
  normalizeBaseUrl,
  parseHeaders,
  toPositiveInt,
  toValue,
  normalizeParameters,
  readResponseText,
  resolveTimeoutMs,
  sanitizeHeaders,
  unwrapString,
};
