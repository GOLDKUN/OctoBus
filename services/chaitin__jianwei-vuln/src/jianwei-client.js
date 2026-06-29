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
/**
 * Client for the Jianwei Vulnerability Management Platform's JSON-RPC 2.0 API.
 *
 * Sends real HTTP POST requests using the native fetch API, with Bearer token
 * authentication in the Authorization header.
 *
 * Usage:
 *   const client = new JianweiClient("https://your-jianwei-host", "<your-api-token>");
 *   const result = await client.call("AssetMgrService.ListAssets", { page: 1, page_size: 10 });
 *
 * Note: baseUrl should be the platform root URL (e.g. "https://your-jianwei-host"),
 *       NOT the web UI path ("/insight"). The API endpoint is at /pedestal/rpc
 *       which is separate from the web frontend. The /insight suffix is stripped
 *       automatically if present.
 */
export class JianweiClient {
    baseUrl;
    token;
    retryOptions;
    nextId = 1;
    constructor(baseUrl, token, retryOptions) {
        // Strip /insight suffix if present — the API endpoint is at /pedestal/rpc,
        // not under the /insight web UI path
        this.baseUrl = baseUrl.replace(/\/+$/, "").replace(/\/insight\/?$/, "");
        this.token = token;
        this.retryOptions = { ...DEFAULT_RETRY_OPTIONS, ...retryOptions };
    }
    /**
     * Invoke a JSON-RPC 2.0 method on the Jianwei platform.
     *
     * Sends a JSON-RPC request to the single `/pedestal/rpc` endpoint with
     * Bearer token auth, and returns the `result` field from the success response.
     *
     * The method name is carried in the JSON-RPC body (not the URL path).
     *
     * Throws JianweiRpcError on JSON-RPC-level errors (method not found, invalid
     * params, etc.) and JianweiHttpError on HTTP-level failures (auth failures,
     * server errors, network issues).
     *
     * Transient HTTP failures (429, 5xx) are retried automatically up to
     * maxRetries times with exponential backoff.
     */
    async call(method, params = {}) {
        const request = {
            jsonrpc: "2.0",
            method,
            params,
            id: this.nextId++,
        };
        const url = `${this.baseUrl}/pedestal/rpc`;
        let lastError = null;
        for (let attempt = 0; attempt <= this.retryOptions.maxRetries; attempt++) {
            try {
                const response = await fetch(url, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        Authorization: `Bearer ${this.token}`,
                    },
                    body: JSON.stringify(request),
                });
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
                // Network errors (fetch itself threw) — retryable
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
