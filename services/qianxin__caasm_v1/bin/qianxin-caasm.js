#!/usr/bin/env node

import { defineService, runServiceMain } from "@chaitin-ai/octobus-sdk";

import { createClient } from "../src/client.js";
import { buildRequestBody, buildPageResponse, API_PATHS, MAX_LIMITS } from "../src/mappers.js";

// ---- helpers ----

/**
 * Create a unary handler for a given CAASM API path.
 * @param {string} path - API path (e.g. "/api/entity/dev")
 * @param {"default"|"largeTable"|"noPagination"} limitProfile
 *   - default:     normal endpoint, forwards offset/limit to CAASM
 *   - largeTable:  service/component/software tables (millions of rows), tiny limit
 *   - noPagination: user/list, org/list — CAASM ignores pagination; we
 *                    send an empty body and slice client-side
 */
function makeHandler(path, limitProfile = "default") {
  const maxLimit = MAX_LIMITS[limitProfile] ?? MAX_LIMITS.default;
  const skipPagination = limitProfile === "noPagination";

  return async (ctx) => {
    const client = createClient(ctx.config, ctx.secret);
    let body, pageParams;

    if (skipPagination) {
      // user/list and org/list ignore offset/limit — send minimal body
      body = {};
      pageParams = {
        offset: Number(ctx.request.offset) || 0,
        limit: Math.min(Number(ctx.request.limit) || 10, maxLimit),
      };
    } else {
      body = buildRequestBody(ctx.request, { maxLimit });
      pageParams = { offset: body.offset, limit: body.limit };
    }

    const raw = await client(path, body);
    return buildPageResponse(raw, pageParams);
  };
}

const service = defineService({
  handlers: {
    // ---- Asset ----
    "AssetService/GetDevices":    makeHandler(API_PATHS.dev),
    "AssetService/GetSoftware":   makeHandler(API_PATHS.software, "largeTable"),
    "AssetService/GetServices":   makeHandler(API_PATHS.service, "largeTable"),
    "AssetService/GetComponents": makeHandler(API_PATHS.component, "largeTable"),
    "AssetService/GetWebsites":   makeHandler(API_PATHS.website),

    // ---- Vulnerability ----
    "VulnerabilityService/GetSysVulnerabilities": makeHandler(API_PATHS.vulnSys),
    "VulnerabilityService/GetSysWeakPasswords":   makeHandler(API_PATHS.weakpwdSys),
    "VulnerabilityService/GetWebVulnerabilities": makeHandler(API_PATHS.vulnWeb),
    "VulnerabilityService/GetWebWeakPasswords":   makeHandler(API_PATHS.weakpwdWeb),

    // ---- Admin ----
    "AdminService/GetUsers":         makeHandler(API_PATHS.user, "noPagination"),
    "AdminService/GetOrganizations": makeHandler(API_PATHS.org, "noPagination"),
    "AdminService/GetRoles":         makeHandler(API_PATHS.role),
  },
});

runServiceMain(service);
