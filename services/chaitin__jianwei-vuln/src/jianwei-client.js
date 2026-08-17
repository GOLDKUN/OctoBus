/** Jianwei's JSON-RPC 2.0 transport. */
import { Agent } from "undici";
import { mapHttpStatusToCode, serviceError } from "@chaitin-ai/octobus-sdk";

export const JSON_RPC_ERROR_CODES = {
    PARSE_ERROR: -32700,
    INVALID_REQUEST: -32600,
    METHOD_NOT_FOUND: -32601,
    INVALID_PARAMS: -32602,
    INTERNAL_ERROR: -32603,
};

const DEFAULT_RETRY_OPTIONS = {
    maxRetries: 2,
    retryDelayMs: 100,
    retryableStatusCodes: [429, 500, 502, 503, 504],
};
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

let insecureAgent;

function getInsecureAgent() {
    insecureAgent ??= new Agent({ connect: { rejectUnauthorized: false } });
    return insecureAgent;
}

function normalizeBaseUrl(baseUrl) {
    let parsed;
    try {
        parsed = new URL(String(baseUrl ?? "").trim());
    }
    catch {
        throw serviceError("INVALID_ARGUMENT", "baseUrl must be an absolute URL");
    }
    const loopback = ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname);
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
        throw serviceError("INVALID_ARGUMENT", "baseUrl must use HTTPS (HTTP is allowed only for loopback testing)");
    }
    if (parsed.username || parsed.password || parsed.search || parsed.hash) {
        throw serviceError("INVALID_ARGUMENT", "baseUrl must not contain credentials, query parameters, or fragments");
    }
    parsed.pathname = parsed.pathname.replace(/\/+$/, "").replace(/\/insight$/, "");
    return parsed.toString().replace(/\/$/, "");
}

function timeoutMs(value) {
    if (value === undefined || value === null) {
        return DEFAULT_TIMEOUT_MS;
    }
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed <= 0) {
        throw serviceError("INVALID_ARGUMENT", "timeoutMs must be a positive integer");
    }
    return parsed;
}

function rpcErrorCode(error) {
    switch (Number(error?.code)) {
        case JSON_RPC_ERROR_CODES.INVALID_REQUEST:
        case JSON_RPC_ERROR_CODES.INVALID_PARAMS:
            return "INVALID_ARGUMENT";
        case JSON_RPC_ERROR_CODES.METHOD_NOT_FOUND:
            return "UNIMPLEMENTED";
        case JSON_RPC_ERROR_CODES.PARSE_ERROR:
            return "INTERNAL";
        default:
            return "INTERNAL";
    }
}

function isTimeout(error) {
    return error?.name === "AbortError" || error?.name === "TimeoutError";
}

async function readJson(response) {
    const contentLength = Number(response.headers?.get?.("content-length"));
    if (Number.isFinite(contentLength) && contentLength > MAX_RESPONSE_BYTES) {
        throw serviceError("RESOURCE_EXHAUSTED", "upstream response exceeds 4 MiB");
    }
    const text = await response.text();
    if (Buffer.byteLength(text) > MAX_RESPONSE_BYTES) {
        throw serviceError("RESOURCE_EXHAUSTED", "upstream response exceeds 4 MiB");
    }
    try {
        return JSON.parse(text);
    }
    catch {
        throw serviceError("INTERNAL", "upstream returned invalid JSON");
    }
}

export class JianweiClient {
    constructor(baseUrl, token, options = {}) {
        this.baseUrl = normalizeBaseUrl(baseUrl);
        this.token = String(token ?? "").trim();
        if (!this.token) {
            throw serviceError("UNAUTHENTICATED", "secret.token is required");
        }
        this.skipTlsVerify = options.skipTlsVerify === true;
        this.timeoutMs = timeoutMs(options.timeoutMs);
        this.retryOptions = { ...DEFAULT_RETRY_OPTIONS, ...options.retryOptions };
        this.nextId = 1;
    }

    async call(method, params = {}) {
        const deadline = Date.now() + this.timeoutMs;
        let lastError;
        for (let attempt = 0; attempt <= this.retryOptions.maxRetries; attempt += 1) {
            const remaining = deadline - Date.now();
            if (remaining <= 0) {
                throw serviceError("DEADLINE_EXCEEDED", `upstream request timed out after ${this.timeoutMs}ms`);
            }
            try {
                const requestId = this.nextId++;
                const response = await fetch(`${this.baseUrl}/pedestal/rpc`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        Authorization: `Bearer ${this.token}`,
                    },
                    body: JSON.stringify({ jsonrpc: "2.0", method, params, id: requestId }),
                    signal: AbortSignal.timeout(remaining),
                    dispatcher: this.skipTlsVerify ? getInsecureAgent() : undefined,
                    redirect: "error",
                });
                if (!response.ok) {
                    const error = serviceError(mapHttpStatusToCode(response.status), `upstream returned HTTP ${response.status}`);
                    if (this.isRetryable(response.status, attempt)) {
                        lastError = error;
                        await this.backoff(attempt, deadline);
                        continue;
                    }
                    throw error;
                }
                const payload = await readJson(response);
                // Jianwei's deployments sometimes return a legacy envelope without
                // JSON-RPC metadata; when present, metadata must still be correct.
                if ((payload?.jsonrpc !== undefined && payload.jsonrpc !== "2.0")
                    || (payload?.id !== undefined && payload.id !== requestId)) {
                    throw serviceError("INTERNAL", "upstream returned a mismatched JSON-RPC response");
                }
                if (payload?.error) {
                    throw serviceError(rpcErrorCode(payload.error), `upstream JSON-RPC error ${String(payload.error.code ?? "unknown")}`);
                }
                if (!("result" in (payload ?? {}))) {
                    throw serviceError("INTERNAL", "upstream JSON-RPC response is missing result");
                }
                return payload.result;
            }
            catch (error) {
                if (isTimeout(error)) {
                    throw serviceError("DEADLINE_EXCEEDED", `upstream request timed out after ${this.timeoutMs}ms`);
                }
                if (error?.legacyCode) {
                    throw error;
                }
                if (attempt < this.retryOptions.maxRetries) {
                    lastError = error;
                    await this.backoff(attempt, deadline);
                    continue;
                }
                throw serviceError("UNAVAILABLE", "upstream request failed");
            }
        }
        throw lastError ?? serviceError("UNAVAILABLE", "upstream request failed");
    }

    isRetryable(status, attempt) {
        return attempt < this.retryOptions.maxRetries && this.retryOptions.retryableStatusCodes.includes(status);
    }

    async backoff(attempt, deadline) {
        const delay = Math.min(this.retryOptions.retryDelayMs * (2 ** attempt), Math.max(deadline - Date.now(), 0));
        if (delay > 0) {
            await new Promise((resolve) => setTimeout(resolve, delay));
        }
    }
}

export const _test = { normalizeBaseUrl, rpcErrorCode, timeoutMs };
