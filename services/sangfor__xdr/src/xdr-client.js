/**
 * 深信服 XDR API 客户端工厂
 */

import { canonicalizeQuery, createSign } from "./sangfor-sign.js";
import { GrpcError, grpcStatus } from "@chaitin-ai/octobus-sdk";

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj ?? {}, key);

const firstDefined = (...values) => values.find((v) => v !== undefined && v !== null);
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 300_000;
const RESERVED_HEADERS = new Set([
  "authorization",
  "sdk-content-type",
  "sdk-host",
  "sign-date",
]);

const unwrapString = (value) => {
  if (value === undefined || value === null) return "";
  if (typeof value === "object" && value !== null && hasOwn(value, "value")) return unwrapString(value.value);
  return String(value);
};

export const resolveBaseUrl = (config = {}) => {
  const raw = unwrapString(firstDefined(
    config.xdrBaseUrl,
    config.endpoint,
    config.restBaseUrl,
    config.baseUrl,
  )).trim().replace(/\/+$/, "");
  if (!raw) throw new Error("xdrBaseUrl/endpoint is required in config");
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("xdrBaseUrl/endpoint must be an absolute HTTP(S) URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("xdrBaseUrl/endpoint must use HTTP or HTTPS");
  }
  return url.toString().replace(/\/+$/, "");
};

export const resolveTimeoutMs = (config = {}) => {
  const raw = firstDefined(config.timeoutMs, DEFAULT_TIMEOUT_MS);
  const timeoutMs = Number(unwrapString(raw));
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new Error(`timeoutMs must be an integer from 1 to ${MAX_TIMEOUT_MS}`);
  }
  return timeoutMs;
};

const resolveHeaders = (config = {}) => {
  if (config.headers === undefined || config.headers === null) return {};
  if (typeof config.headers !== "object" || Array.isArray(config.headers)) {
    throw new Error("headers must be an object of string values");
  }
  return Object.fromEntries(Object.entries(config.headers).map(([key, value]) => {
    if (typeof value !== "string") throw new Error(`header ${key} must be a string`);
    const normalizedKey = key.toLowerCase();
    if (RESERVED_HEADERS.has(normalizedKey)) {
      throw new Error(`header ${key} is reserved for XDR request signing`);
    }
    return [normalizedKey, value];
  }));
};

export const resolveAccessKey = (secret = {}) => {
  const ak = unwrapString(firstDefined(secret.accessKey, secret.ak)).trim();
  if (!ak) throw new Error("accessKey is required in secret");
  return ak;
};

export const resolveSecretKey = (secret = {}) => {
  const sk = unwrapString(firstDefined(secret.secretKey, secret.sk)).trim();
  if (!sk) throw new Error("secretKey is required in secret");
  return sk;
};

const upstreamError = (code, message, details = {}) => {
  const payload = {
    code,
    message,
    http_status: Number.isFinite(Number(details.httpStatus)) ? Number(details.httpStatus) : 0,
    raw_body: typeof details.rawBody === "string" ? details.rawBody : "",
    reason: String(details.reason || "").trim(),
  };
  const err = new GrpcError(
    code === "PERMISSION_DENIED" ? grpcStatus.PERMISSION_DENIED :
    code === "INVALID_ARGUMENT" ? grpcStatus.INVALID_ARGUMENT :
    code === "UNAVAILABLE" ? grpcStatus.UNAVAILABLE :
    grpcStatus.UNKNOWN,
    JSON.stringify(payload),
  );
  err.httpStatus = payload.http_status;
  err.rawBody = payload.raw_body;
  err.reason = payload.reason;
  return err;
};

const mapHttpStatusToCode = (status) => {
  if (status === 401 || status === 403) return "PERMISSION_DENIED";
  if (status >= 400 && status < 500) return "INVALID_ARGUMENT";
  return "UNAVAILABLE";
};

export async function signedRequest({ config, secret, method, path, body }) {
  const baseUrl = resolveBaseUrl(config);
  const ak = resolveAccessKey(secret);
  const sk = resolveSecretKey(secret);
  const timeoutMs = resolveTimeoutMs(config);
  const configuredHeaders = resolveHeaders(config);

  const url = new URL(path, baseUrl);
  const uri = url.pathname;
  const queryString = canonicalizeQuery(url.search ? url.search.slice(1) : "");
  url.search = queryString;
  const host = url.host;
  const payload = body ? JSON.stringify(body) : "";

  const headers = {
    ...configuredHeaders,
    "content-type": "application/json",
    accept: "application/json",
  };
  const signHeaders = createSign({ ak, sk, method: method.toUpperCase(), uri, queryString, host, payload, headers });
  Object.assign(headers, signHeaders);

  const fetchOptions = {
    method: method.toUpperCase(),
    headers,
    signal: AbortSignal.timeout(timeoutMs),
  };
  if (body && method.toUpperCase() !== "GET") {
    fetchOptions.body = payload;
  }

  let res;
  try {
    res = await fetch(url.toString(), fetchOptions);
  } catch (err) {
    throw upstreamError("UNAVAILABLE", "XDR upstream request failed", {
      httpStatus: 0,
      rawBody: "",
      reason: err?.cause?.message || err?.message || "fetch failed",
    });
  }

  let text;
  try {
    text = await res.text();
  } catch (err) {
    throw upstreamError("UNAVAILABLE", "XDR upstream response body read failed", {
      httpStatus: res.status,
      rawBody: "",
      reason: err?.message || "response body read failed",
    });
  }

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { _raw: text };
  }

  if (!res.ok) {
    throw upstreamError(mapHttpStatusToCode(res.status), `XDR API error: ${res.status}`, {
      httpStatus: res.status,
      rawBody: text,
      reason: JSON.stringify(data),
    });
  }

  return { data, httpStatus: res.status };
}
