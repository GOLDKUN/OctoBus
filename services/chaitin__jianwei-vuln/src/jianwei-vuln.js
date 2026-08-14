import { JianweiClient } from "./jianwei-client.js";
function getClient(ctx) {
    const config = ctx.config ?? {};
    const secret = ctx.secret ?? {};
    return new JianweiClient(config.baseUrl, secret.token, {
        skipTlsVerify: config.skipTlsVerify,
        timeoutMs: ctx.limits?.timeoutMs,
    });
}
function transformFilter(filter) {
    if (!filter)
        return {};
    const result = {};
    for (const [key, value] of Object.entries(filter)) {
        if (value !== null && value !== undefined) {
            result[key] = value;
        }
    }
    return result;
}
function buildListParams(request) {
    const params = {};
    if (request.count !== undefined && request.count !== null) {
        params.page_size = Number(request.count);
    }
    if (request.offset !== undefined && request.offset !== null) {
        params.page = Math.floor(Number(request.offset) / Math.max(Number(request.count) || 10, 1)) + 1;
    }
    const orderBy = request.orderBy || request.order_by;
    if (orderBy) {
        params.orderBy = orderBy;
    }
    if (request.filter) {
        Object.assign(params, transformFilter(request.filter));
    }
    return params;
}
// ============================================================
// AssetService handlers
// ============================================================
const listAssets = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = buildListParams(request);
    const result = await client.call("AssetMgrService.IpAssetList", params);
    return { total: result.total ?? 0, data: result.data ?? [] };
};
const getAsset = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.id !== undefined && request.id !== null)
        params.id = Number(request.id);
    if (request.workflow_id !== undefined && request.workflow_id !== null)
        params.workflow_id = Number(request.workflow_id);
    const result = await client.call("AssetMgrService.IpAssetGet", params);
    return { data: result.data ?? {} };
};
const updateAsset = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.id !== undefined && request.id !== null)
        params.id = Number(request.id);
    if (request.data)
        params.data = request.data;
    if (request.update_empty_col !== undefined)
        params.update_empty_col = request.update_empty_col;
    const result = await client.call("AssetMgrService.IpAssetSave", params);
    return { data: result.data ?? {} };
};
const batchUpdateAssets = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.asset_ids)
        params.asset_ids = request.asset_ids.map(Number);
    if (request.data)
        params.data = request.data;
    if (request.cascade_vuln !== undefined)
        params.cascade_vuln = request.cascade_vuln;
    if (request.conflict_strategy !== undefined)
        params.conflict_strategy = Number(request.conflict_strategy);
    if (request.update_empty_col !== undefined)
        params.update_empty_col = request.update_empty_col;
    const result = await client.call("AssetMgrService.IpAssetBatchUpdate", params);
    return { duplicated: result.duplicated?.map(Number) ?? [] };
};
// ============================================================
// VulnerabilityService handlers
// ============================================================
const listIpVulnerabilities = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = buildListParams(request);
    const result = await client.call("ScanVulnIpService.SearchScanVulnIpList", params);
    return { total: result.total ?? 0, data: result.data ?? [] };
};
const listWebVulnerabilities = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = buildListParams(request);
    const result = await client.call("ScanVulnIpService.SearchScanVulnWebList", params);
    return { total: result.total ?? 0, data: result.data ?? [] };
};
const getVulnerabilityDetails = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.vuln_id !== undefined && request.vuln_id !== null)
        params.id = Number(request.vuln_id);
    if (request.workflow_id)
        params.workflow_id = request.workflow_id;
    const result = await client.call("ScanVulnIpService.SearchScanVulnIpDetail", params);
    return { data: result.data ?? {} };
};
const updateVulnerabilityStatus = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.vuln_ids)
        params.vuln_ids = request.vuln_ids.map(Number);
    if (request.vuln_status !== undefined)
        params.vuln_status = Number(request.vuln_status);
    if (request.vuln_type)
        params.vuln_type = request.vuln_type;
    if (request.fix_remarks)
        params.fix_remarks = request.fix_remarks;
    if (request.remark)
        params.remark = request.remark;
    if (request.workflow_id)
        params.workflow_id = request.workflow_id;
    if (request.skip_end_status !== undefined)
        params.skip_end_status = request.skip_end_status;
    if (request.exposure_exec_id !== undefined)
        params.exposure_exec_id = Number(request.exposure_exec_id);
    if (request.exposure_result_id)
        params.exposure_result_id = request.exposure_result_id.map(Number);
    await client.call("ScanVulnIpService.UpsertScanVulnIp", params);
    return {};
};
// ============================================================
// DisposalService handlers
// ============================================================
const directVulnDispose = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.vuln_ids)
        params.vuln_ids = request.vuln_ids.map(Number);
    if (request.vuln_status !== undefined)
        params.vuln_status = Number(request.vuln_status);
    if (request.vuln_type)
        params.vuln_type = request.vuln_type;
    if (request.fix_remarks)
        params.fix_remarks = request.fix_remarks;
    if (request.remark)
        params.remark = request.remark;
    if (request.workflow_id)
        params.workflow_id = request.workflow_id;
    if (request.skip_end_status !== undefined)
        params.skip_end_status = request.skip_end_status;
    if (request.exposure_exec_id !== undefined)
        params.exposure_exec_id = Number(request.exposure_exec_id);
    if (request.exposure_result_id)
        params.exposure_result_id = request.exposure_result_id.map(Number);
    await client.call("ScanVulnIpService.UpsertScanVulnIp", params);
    return {};
};
const vulnDisposeHistory = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.vuln_id !== undefined && request.vuln_id !== null)
        params.id = Number(request.vuln_id);
    if (request.vuln_type)
        params.vuln_type = request.vuln_type;
    const result = await client.call("ScanVulnIpService.SearchScanVulnIpDetail", params);
    return { vuln_dispose_record: result.vuln_dispose_record ?? [] };
};
const saveVulnWorkflowStatus = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.vuln_type)
        params.vuln_type = request.vuln_type;
    if (request.status_map) {
        const statusMap = {};
        for (const [key, value] of Object.entries(request.status_map)) {
            statusMap[key] = { ids: value.ids?.map(Number) ?? [] };
        }
        params.status_map = statusMap;
    }
    await client.call("ScanVulnIpService.UpsertScanVulnIp", params);
    return {};
};
// ============================================================
// IntelligenceService handlers
// ============================================================
const getIPIntelligenceList = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = buildListParams(request);
    const result = await client.call("IntelligenceService.GetIPIntelligenceList", params);
    return { total: result.total ?? 0, data: result.data ?? [] };
};
const getIPIntelligenceDetail = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.id !== undefined && request.id !== null)
        params.id = Number(request.id);
    const result = await client.call("IntelligenceService.GetIPIntelligenceDetail", params);
    return { data: result.data ?? {} };
};
const getDomainIntelligenceList = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = buildListParams(request);
    const result = await client.call("IntelligenceService.GetDomainIntelligenceList", params);
    return { total: result.total ?? 0, data: result.data ?? [] };
};
const getDomainIntelligenceDetail = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.id !== undefined && request.id !== null)
        params.id = Number(request.id);
    const result = await client.call("IntelligenceService.GetDomainIntelligenceDetail", params);
    return { data: result.data ?? {} };
};
// ============================================================
// KnowledgeBaseService handlers
// ============================================================
const searchStandardVulnList = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = buildListParams(request);
    const result = await client.call("KBService.SearchStandardVulnList", params);
    return { total: result.total ?? 0, data: result.data ?? [] };
};
const getStandardVulnDetailByCTID = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.ct_id)
        params.ct_id = request.ct_id;
    const result = await client.call("KBService.GetStandardVulnDetailByCTID", params);
    return { detail: result.detail ?? {} };
};
const getStandardVulnDetailByID = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.id !== undefined && request.id !== null)
        params.id = Number(request.id);
    const result = await client.call("KBService.GetStandardVulnDetailByID", params);
    return { detail: result.detail ?? {} };
};
const searchCustomizeTags = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.keyword)
        params.keyword = request.keyword;
    const result = await client.call("KBService.SearchCustomizeTags", params);
    return { data: result.data ?? [] };
};
const createCustomizeTag = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.name)
        params.name = request.name;
    if (request.category)
        params.category = request.category;
    const result = await client.call("KBService.CreateCustomizeTag", params);
    return { data: result.data ?? {} };
};
const deleteCustomizeTag = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.id !== undefined && request.id !== null)
        params.id = Number(request.id);
    await client.call("KBService.DeleteCustomizeTag", params);
    return {};
};
const appendCustomizeTags = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.vuln_id !== undefined && request.vuln_id !== null)
        params.vuln_id = Number(request.vuln_id);
    if (request.tag_names)
        params.tag_names = request.tag_names;
    await client.call("KBService.AppendCustomizeTags", params);
    return {};
};
const replaceCustomizeTags = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.vuln_id !== undefined && request.vuln_id !== null)
        params.vuln_id = Number(request.vuln_id);
    if (request.tag_names)
        params.tag_names = request.tag_names;
    await client.call("KBService.ReplaceCustomizeTags", params);
    return {};
};
// ============================================================
// DeviceService handlers
// ============================================================
const checkScanDeviceAuth = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.device_id !== undefined && request.device_id !== null)
        params.device_id = Number(request.device_id);
    if (request.env_map)
        params.env_map = request.env_map;
    await client.call("ScanDeviceService.CheckScanDeviceAuth", params);
    return {};
};
const createDevice = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = { ...request };
    if (params.organization_id !== undefined)
        params.organization_id = Number(params.organization_id);
    if (params.owner_id !== undefined)
        params.owner_id = Number(params.owner_id);
    if (params.security_scope_id !== undefined)
        params.security_scope_id = Number(params.security_scope_id);
    if (params.logo_file_id !== undefined)
        params.logo_file_id = Number(params.logo_file_id);
    const result = await client.call("ScanDeviceService.CreateDevice", params);
    return { result: result.result ?? {} };
};
const removeScanDevice = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.device_id !== undefined && request.device_id !== null)
        params.device_id = Number(request.device_id);
    await client.call("ScanDeviceService.RemoveScanDevice", params);
    return {};
};
const getDataAccessMapping = async (ctx) => {
    const client = getClient(ctx);
    const result = await client.call("ScanDeviceService.GetDataAccessMapping", {});
    return { data: result.data ?? [] };
};
const getDeviceProductNameList = async (ctx) => {
    const client = getClient(ctx);
    const result = await client.call("ScanDeviceService.GetDeviceProductNameList", {});
    return { data: result.data ?? [] };
};
// ============================================================
// VptService handlers
// ============================================================
const getVulnVptScore = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.vuln_ids)
        params.vuln_ids = request.vuln_ids.map(Number);
    if (request.vuln_type)
        params.vuln_type = request.vuln_type;
    const result = await client.call("ScanVulnIpService.GetVulnVptScore", params);
    return { list: result.list ?? [] };
};
const getVulnVptScoreSetting = async (ctx) => {
    const client = getClient(ctx);
    const result = await client.call("ScanVulnIpService.GetVulnVptScoreSetting", {});
    return { is_default: result.is_default ?? false, setting: result.setting ?? {} };
};
const saveVulnVptScoreSetting = async (ctx) => {
    const client = getClient(ctx);
    const request = ctx.request;
    const params = {};
    if (request.setting)
        params.setting = request.setting;
    await client.call("ScanVulnIpService.SaveVulnVptScoreSetting", params);
    return {};
};
const resetVulnVptScoreSetting = async (ctx) => {
    const client = getClient(ctx);
    await client.call("ScanVulnIpService.ResetVulnVptScoreSetting", {});
    return {};
};
const getVulnVptScoreState = async (ctx) => {
    const client = getClient(ctx);
    const result = await client.call("ScanVulnIpService.GetVulnVptScoreState", {});
    return { state: result.state ?? "", progress: Number(result.progress ?? 0) };
};
// ============================================================
// Service definition
// ============================================================
const PKG = "jianwei.vuln.service";
export const handlers = {
        // AssetService
        [`${PKG}.AssetService/ListAssets`]: listAssets,
        [`${PKG}.AssetService/GetAsset`]: getAsset,
        [`${PKG}.AssetService/UpdateAsset`]: updateAsset,
        [`${PKG}.AssetService/BatchUpdateAssets`]: batchUpdateAssets,
        // VulnerabilityService
        [`${PKG}.VulnerabilityService/ListIpVulnerabilities`]: listIpVulnerabilities,
        [`${PKG}.VulnerabilityService/ListWebVulnerabilities`]: listWebVulnerabilities,
        [`${PKG}.VulnerabilityService/GetVulnerabilityDetails`]: getVulnerabilityDetails,
        [`${PKG}.VulnerabilityService/UpdateVulnerabilityStatus`]: updateVulnerabilityStatus,
        // DisposalService
        [`${PKG}.DisposalService/DirectVulnDispose`]: directVulnDispose,
        [`${PKG}.DisposalService/VulnDisposeHistory`]: vulnDisposeHistory,
        [`${PKG}.DisposalService/SaveVulnWorkflowStatus`]: saveVulnWorkflowStatus,
        // IntelligenceService
        [`${PKG}.IntelligenceService/GetIPIntelligenceList`]: getIPIntelligenceList,
        [`${PKG}.IntelligenceService/GetIPIntelligenceDetail`]: getIPIntelligenceDetail,
        [`${PKG}.IntelligenceService/GetDomainIntelligenceList`]: getDomainIntelligenceList,
        [`${PKG}.IntelligenceService/GetDomainIntelligenceDetail`]: getDomainIntelligenceDetail,
        // KnowledgeBaseService
        [`${PKG}.KnowledgeBaseService/SearchStandardVulnList`]: searchStandardVulnList,
        [`${PKG}.KnowledgeBaseService/GetStandardVulnDetailByCTID`]: getStandardVulnDetailByCTID,
        [`${PKG}.KnowledgeBaseService/GetStandardVulnDetailByID`]: getStandardVulnDetailByID,
        [`${PKG}.KnowledgeBaseService/SearchCustomizeTags`]: searchCustomizeTags,
        [`${PKG}.KnowledgeBaseService/CreateCustomizeTag`]: createCustomizeTag,
        [`${PKG}.KnowledgeBaseService/DeleteCustomizeTag`]: deleteCustomizeTag,
        [`${PKG}.KnowledgeBaseService/AppendCustomizeTags`]: appendCustomizeTags,
        [`${PKG}.KnowledgeBaseService/ReplaceCustomizeTags`]: replaceCustomizeTags,
        // DeviceService
        [`${PKG}.DeviceService/CheckScanDeviceAuth`]: checkScanDeviceAuth,
        [`${PKG}.DeviceService/CreateDevice`]: createDevice,
        [`${PKG}.DeviceService/RemoveScanDevice`]: removeScanDevice,
        [`${PKG}.DeviceService/GetDataAccessMapping`]: getDataAccessMapping,
        [`${PKG}.DeviceService/GetDeviceProductNameList`]: getDeviceProductNameList,
        // VptService
        [`${PKG}.VptService/GetVulnVptScore`]: getVulnVptScore,
        [`${PKG}.VptService/GetVulnVptScoreSetting`]: getVulnVptScoreSetting,
        [`${PKG}.VptService/SaveVulnVptScoreSetting`]: saveVulnVptScoreSetting,
        [`${PKG}.VptService/ResetVulnVptScoreSetting`]: resetVulnVptScoreSetting,
        [`${PKG}.VptService/GetVulnVptScoreState`]: getVulnVptScoreState,
    };
