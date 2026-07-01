/**
 * Jianwei Vulnerability Management Platform API Client
 *
 * Handles JSON-RPC 2.0 requests over HTTP POST to the Jianwei platform.
 * Uses Bearer token authentication and includes retry logic for transient failures.
 */
/** Standard JSON-RPC 2.0 error codes. */
export const JSON_RPC_ERROR_CODES = {
    PARSE_ERROR: -32700,
    INVALID_REQUEST: -32600,
    METHOD_NOT_FOUND: -32601,
    INVALID_PARAMS: -32602,
    INTERNAL_ERROR: -32603,
};
const DEFAULT_RETRY_OPTIONS = {
    maxRetries: 3,
    retryDelayMs: 1000,
    retryableStatusCodes: [429, 500, 502, 503, 504],
};
/**
 * Error thrown when a JSON-RPC response contains an error object.
 */
export class JianweiRpcError extends Error {
    code;
    data;
    constructor(error) {
        super(`JSON-RPC error ${error.code}: ${error.message}`);
        this.name = "JianweiRpcError";
        this.code = error.code;
        this.data = error.data;
    }
}
/**
 * Error thrown when the HTTP request itself fails (non-2xx status, network error, etc.).
 */
export class JianweiHttpError extends Error {
    statusCode;
    constructor(statusCode, message) {
        super(`HTTP ${statusCode}: ${message}`);
        this.name = "JianweiHttpError";
        this.statusCode = statusCode;
    }
}
let _insecureAgent;
function getInsecureAgent() {
    if (!_insecureAgent) {
        const { Agent } = require("undici");
        _insecureAgent = new Agent({ connect: { rejectUnauthorized: false } });
    }
    return _insecureAgent;
}
/**
 * Client for the Jianwei Vulnerability Management Platform's JSON-RPC 2.0 API.
 *
 * When `skipTlsVerify` is true, an undici Agent with `rejectUnauthorized: false`
 * is used as the fetch dispatcher, allowing connections to servers with
 * self-signed certificates.
 */
export class JianweiClient {
    baseUrl;
    token;
    skipTlsVerify;
    retryOptions;
    nextId = 1;
    constructor(baseUrl, token, options) {
        this.baseUrl = baseUrl.replace(/\/+$/, "").replace(/\/insight\/?$/, "");
        this.token = token;
        this.skipTlsVerify = options?.skipTlsVerify ?? false;
        this.retryOptions = { ...DEFAULT_RETRY_OPTIONS, ...options?.retryOptions };
    }
    async call(method, params = {}) {
        const request = {
            jsonrpc: "2.0",
            method,
            params,
            id: this.nextId++,
        };
        const url = `${this.baseUrl}/pedestal/rpc`;
        const fetchOptions = {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${this.token}`,
            },
            body: JSON.stringify(request),
        };
        if (this.skipTlsVerify) {
            fetchOptions.dispatcher = getInsecureAgent();
        }
        let lastError = null;
        for (let attempt = 0; attempt <= this.retryOptions.maxRetries; attempt++) {
            try {
                const response = await fetch(url, fetchOptions);
                if (!response.ok) {
                    const isRetryable = this.retryOptions.retryableStatusCodes.includes(response.status);
                    if (isRetryable && attempt < this.retryOptions.maxRetries) {
                        lastError = new JianweiHttpError(response.status, `Request failed, retrying (attempt ${attempt + 1}/${this.retryOptions.maxRetries})`);
                        await this.delay(this.retryOptions.retryDelayMs * Math.pow(2, attempt));
                        continue;
                    }
                    const body = await response.text().catch(() => "");
                    throw new JianweiHttpError(response.status, body || response.statusText);
                }
                const json = await response.json();
                if ("error" in json && json.error) {
                    throw new JianweiRpcError(json.error);
                }
                return json.result;
            }
            catch (error) {
                if (error instanceof JianweiRpcError) {
                    throw error;
                }
                if (error instanceof JianweiHttpError) {
                    if (attempt < this.retryOptions.maxRetries && this.retryOptions.retryableStatusCodes.includes(error.statusCode)) {
                        lastError = error;
                        await this.delay(this.retryOptions.retryDelayMs * Math.pow(2, attempt));
                        continue;
                    }
                    throw error;
                }
                if (attempt < this.retryOptions.maxRetries) {
                    lastError = error instanceof Error ? error : new Error(String(error));
                    await this.delay(this.retryOptions.retryDelayMs * Math.pow(2, attempt));
                    continue;
                }
                throw error instanceof Error ? error : new Error(String(error));
            }
        }
        throw lastError ?? new Error("Max retries exceeded");
    }
    delay(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }
}
