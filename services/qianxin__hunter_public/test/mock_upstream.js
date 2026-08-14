import http from "node:http";

export async function createMockServer() {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString("utf8");
    const url = new URL(request.url, "http://127.0.0.1");
    requests.push({ method: request.method, path: url.pathname, query: Object.fromEntries(url.searchParams), headers: request.headers, body });

    const json = (status, payload, headers = {}) => {
      response.writeHead(status, { "content-type": "application/json", ...headers });
      response.end(JSON.stringify(payload));
    };
    if (request.headers["x-api-key"] !== "test-key") return json(401, { code: 401, message: "bad key" });
    if (url.pathname === "/openApi/userInfo") return json(200, { code: 200, message: "ok", data: { type: "professional", rest_equity_point: 9 } });
    if (url.pathname === "/openApi/search") {
      if (!url.searchParams.get("search")) return json(400, { code: 400, message: "search required" });
      return json(200, { code: 200, message: "ok", data: { total: 1, arr: [{ ip: "203.0.113.9", port: 443, component: [{ name: "nginx", version: "1.26" }] }] } });
    }
    if (url.pathname === "/openApi/search/batch") return json(200, { code: 200, message: "ok", data: { task_id: 7, filename: "batch.csv" } });
    return json(404, { code: 404, message: "not found" });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  return {
    host: `http://127.0.0.1:${address.port}/openApi`,
    requests,
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}
