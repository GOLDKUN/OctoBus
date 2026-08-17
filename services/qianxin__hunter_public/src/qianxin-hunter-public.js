import {
  GrpcError,
  createTlsDispatcher,
  fetchWithTimeout,
  grpcStatus,
  readResponseText,
  redactSensitive,
} from "@chaitin-ai/octobus-sdk";

export const SERVICE_NAME = "hunter.v1.HunterService";
export const GET_USER_INFO_PATH = `/${SERVICE_NAME}/GetUserInfo`;
export const SEARCH_PATH = `/${SERVICE_NAME}/Search`;
export const BATCH_SEARCH_PATH = `/${SERVICE_NAME}/BatchSearch`;
export const DEFAULT_API_BASE = "https://hunter.qianxin.com/openApi";
export const DEFAULT_TIMEOUT_MS = 15_000;
export const MAX_RETRIES = 2;
export const MIN_REQUEST_INTERVAL_MS = 2_000;

let rateLimitQueue = Promise.resolve();
let nextRequestAt = 0;

const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value ?? {}, key);

const unwrap = (value) => {
  if (value !== null && typeof value === "object" && hasOwn(value, "value")) return unwrap(value.value);
  return value;
};

const stringValue = (value) => {
  const unwrapped = unwrap(value);
  return unwrapped === undefined || unwrapped === null ? "" : String(unwrapped);
};

const numberValue = (value, fallback = 0) => {
  const number = Number(unwrap(value));
  return Number.isFinite(number) ? Math.trunc(number) : fallback;
};

const booleanValue = (value) => {
  const unwrapped = unwrap(value);
  if (typeof unwrapped === "boolean") return unwrapped;
  if (typeof unwrapped === "number") return unwrapped !== 0;
  return ["true", "1", "yes", "on"].includes(String(unwrapped ?? "").trim().toLowerCase());
};

const firstValue = (...values) => values.find((value) => {
  const unwrapped = unwrap(value);
  return unwrapped !== undefined && unwrapped !== null && String(unwrapped).trim() !== "";
});

const errorWithCode = (code, message) => {
  const status = grpcStatus[code] ?? grpcStatus.UNKNOWN;
  const error = new GrpcError(status, message, { legacyCode: code });
  error.legacyCode = code;
  return error;
};

const normalizeBaseUrl = (value) => {
  const raw = stringValue(value).trim().replace(/\/+$/, "");
  try {
    const parsed = new URL(raw || DEFAULT_API_BASE);
    return ["http:", "https:"].includes(parsed.protocol) ? parsed.toString().replace(/\/$/, "") : "";
  } catch {
    return "";
  }
};

const base64urlEncode = (value) => Buffer.from(String(value), "utf8").toString("base64url");

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function waitForRateLimit() {
  const previous = rateLimitQueue;
  let release;
  rateLimitQueue = new Promise((resolve) => { release = resolve; });
  await previous;
  try {
    const remaining = nextRequestAt - Date.now();
    if (remaining > 0) await sleep(remaining);
    nextRequestAt = Date.now() + MIN_REQUEST_INTERVAL_MS;
  } finally {
    release();
  }
}

const retryDelay = (response) => {
  const retryAfter = Number(response?.headers?.get?.("retry-after"));
  return Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter * 1_000, 10_000) : MIN_REQUEST_INTERVAL_MS;
};

const callContext = (ctx = {}) => ({
  request: ctx.request ?? ctx.req ?? {},
  config: ctx.config ?? {},
  secret: ctx.secret ?? {},
  bindings: ctx.bindings ?? {},
  limits: ctx.limits ?? {},
});

const resolveSettings = (ctx) => {
  const { config, secret, bindings, limits } = callContext(ctx);
  const apiBase = normalizeBaseUrl(firstValue(config.api_base, config.apiBase, config.baseUrl, bindings.api_base, bindings.apiBase, bindings.baseUrl, DEFAULT_API_BASE));
  if (!apiBase) throw errorWithCode("INVALID_ARGUMENT", "config.api_base must be an http or https URL");

  // API credentials deliberately come only from the instance secret, never RPC input or config.
  const apiKey = stringValue(firstValue(secret.api_key, secret.apiKey)).trim();
  if (!apiKey) throw errorWithCode("UNAUTHENTICATED", "secret.api_key is required");

  const timeoutMs = numberValue(firstValue(limits.timeoutMs, config.timeout_ms, config.timeoutMs, bindings.timeout_ms, bindings.timeoutMs), DEFAULT_TIMEOUT_MS);
  const skipTlsVerify = booleanValue(firstValue(config.skip_tls_verify, config.skipTlsVerify, bindings.skip_tls_verify, bindings.skipTlsVerify));
  return {
    apiBase,
    apiKey,
    timeoutMs: timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS,
    dispatcher: createTlsDispatcher(skipTlsVerify),
  };
};

const requireSearch = (request) => {
  const search = stringValue(request.search).trim();
  if (!search) throw errorWithCode("INVALID_ARGUMENT", "request.search is required");
  return search;
};

const optionalParam = (params, key, value) => {
  const text = stringValue(value).trim();
  if (text) params.set(key, text);
};

const parseJSON = (text) => {
  try {
    return JSON.parse(text);
  } catch {
    throw errorWithCode("UNKNOWN", "upstream response is not valid JSON");
  }
};

const validateUpstreamResult = (payload) => {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw errorWithCode("UNKNOWN", "upstream response has an invalid shape");
  }
  const code = Number(payload.code);
  if (Number.isFinite(code) && ![0, 200].includes(code)) {
    throw errorWithCode("FAILED_PRECONDITION", "upstream rejected the request");
  }
  return redactSensitive(payload);
};

async function callHunterAPI({ endpoint, params = new URLSearchParams(), method = "GET", fileContent, settings }) {
  const url = new URL(`${settings.apiBase}${endpoint}`);
  const headers = { accept: "application/json" };
  // Hunter's public API accepts the credential only as the documented
  // `api-key` query parameter. Never log or expose this URL in an error.
  url.searchParams.set("api-key", settings.apiKey);
  let body;

  if (fileContent !== undefined) {
    const form = new FormData();
    form.append("file", new Blob([fileContent], { type: "text/csv" }), "batch.csv");
    for (const [key, value] of params) form.append(key, value);
    body = form;
  } else if (method === "GET") {
    for (const [key, value] of params) url.searchParams.set(key, value);
  } else {
    headers["content-type"] = "application/x-www-form-urlencoded";
    body = params.toString();
  }

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt += 1) {
    await waitForRateLimit();
    const response = await fetchWithTimeout(url, { method, headers, body }, {
      timeoutMs: settings.timeoutMs,
      ...(settings.dispatcher ? { dispatcher: settings.dispatcher } : {}),
    });
    if (response.status === 429 && attempt < MAX_RETRIES) {
      await sleep(retryDelay(response));
      continue;
    }
    if (response.status === 401) throw errorWithCode("UNAUTHENTICATED", "upstream authentication failed");
    if (response.status === 403) throw errorWithCode("PERMISSION_DENIED", "upstream permission denied");
    if (response.status === 429) throw errorWithCode("UNAVAILABLE", "upstream rate limit exceeded");
    if (!response.ok) {
      throw errorWithCode(response.status >= 500 ? "UNAVAILABLE" : "FAILED_PRECONDITION", `upstream http ${response.status}`);
    }
    return validateUpstreamResult(parseJSON(await readResponseText(response)));
  }
  throw errorWithCode("UNAVAILABLE", "upstream rate limit exceeded");
}

const responseFor = (payload) => ({
  code: numberValue(payload.code, 200),
  message: stringValue(payload.message || "success"),
  data: payload.data ?? {},
});

const getUserInfo = async (ctx) => responseFor(await callHunterAPI({
  endpoint: "/userInfo",
  settings: resolveSettings(ctx),
}));

const search = async (ctx) => {
  const request = callContext(ctx).request;
  const params = new URLSearchParams({
    search: base64urlEncode(requireSearch(request)),
    page: String(Math.max(1, numberValue(request.page, 1))),
    page_size: String(Math.max(1, numberValue(request.page_size ?? request.pageSize, 10))),
  });
  optionalParam(params, "start_time", request.start_time ?? request.startTime);
  optionalParam(params, "end_time", request.end_time ?? request.endTime);
  optionalParam(params, "is_web", request.is_web ?? request.isWeb);
  optionalParam(params, "status_code", request.status_code ?? request.statusCode);
  optionalParam(params, "fields", request.fields);
  return responseFor(await callHunterAPI({ endpoint: "/search", params, settings: resolveSettings(ctx) }));
};

const batchSearch = async (ctx) => {
  const request = callContext(ctx).request;
  const fileContent = stringValue(request.file_content ?? request.fileContent);
  const params = new URLSearchParams();
  if (fileContent) {
    optionalParam(params, "start_time", request.start_time ?? request.startTime);
  } else {
    params.set("search", base64urlEncode(requireSearch(request)));
  }
  for (const [key, value] of Object.entries({
    end_time: request.end_time ?? request.endTime,
    is_web: request.is_web ?? request.isWeb,
    status_code: request.status_code ?? request.statusCode,
    fields: request.fields,
    search_type: request.search_type ?? request.searchType,
    assets_limit: request.assets_limit ?? request.assetsLimit,
  })) optionalParam(params, key, value);
  if (!fileContent && !params.get("search")) throw errorWithCode("INVALID_ARGUMENT", "request.search or request.file_content is required");
  return responseFor(await callHunterAPI({
    endpoint: "/search/batch",
    params,
    method: "POST",
    ...(fileContent ? { fileContent } : {}),
    settings: resolveSettings(ctx),
  }));
};

export const handlers = {
  "hunter.v1.HunterService/GetUserInfo": getUserInfo,
  "hunter.v1.HunterService/Search": search,
  "hunter.v1.HunterService/BatchSearch": batchSearch,
};

export const _test = {
  base64urlEncode,
  booleanValue,
  callContext,
  normalizeBaseUrl,
  numberValue,
  resolveSettings,
  responseFor,
  retryDelay,
  resetRateLimit: () => {
    rateLimitQueue = Promise.resolve();
    nextRequestAt = 0;
  },
  stringValue,
  validateUpstreamResult,
};
