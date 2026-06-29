# Jianwei (鉴微) Vulnerability Management Platform - OctoBus Service

OctoBus service package for integrating with Jianwei (鉴微) Vulnerability Management Platform.

## Features

- **Asset Management**: List, get, update, and batch update IP/Web assets
- **Vulnerability Management**: List and manage IP/Web vulnerabilities
- **Disposal Service**: Vulnerability disposal and workflow management
- **Intelligence Center**: Access IP/domain threat intelligence data
- **Knowledge Base**: Search vulnerability knowledge base, manage custom tags
- **Device Management**: Manage connected security scan devices
- **VPT Scoring**: Vulnerability Priority Threat scoring system

## Installation

```bash
npm install
```

## Configuration

### config
```json
{
  "baseUrl": "https://your-jianwei-host"
}
```

> `baseUrl` should be the platform root URL (e.g. `https://your-jianwei-host`).
> The `/insight` suffix, if present, is automatically stripped.
> The API endpoint is at `/pedestal/rpc`, which is separate from the web UI.

### secret
```json
{
  "token": "<your-api-token>"
}
```

> The token is a JWT with `aim: "api"` claim, obtained from the Jianwei platform's
> API token management page.

## Usage

### Run as OctoBus service
```bash
OCTOBUS_SERVICE_CONTEXT='{"config":{"baseUrl":"https://your-host"},"secret":{"token":"your-token"}}' \
  node bin/jianwei-vuln.js --runtime dev --port 50051
```

## API Reference

### AssetService
- `ListAssets` - List IP assets with pagination
- `GetAsset` - Get detailed asset information
- `UpdateAsset` - Update asset properties
- `BatchUpdateAssets` - Batch update multiple assets

### VulnerabilityService
- `ListIpVulnerabilities` - List IP-based vulnerabilities
- `ListWebVulnerabilities` - List Web-based vulnerabilities
- `GetVulnerabilityDetails` - Get vulnerability details
- `UpdateVulnerabilityStatus` - Update vulnerability status

### DisposalService
- `DirectVulnDispose` - Direct vulnerability disposal
- `VulnDisposeHistory` - Query disposal history
- `SaveVulnWorkflowStatus` - Save workflow status

### IntelligenceService
- `GetIPIntelligenceList` - List IP threat intelligence
- `GetIPIntelligenceDetail` - Get IP intelligence detail
- `GetDomainIntelligenceList` - List domain threat intelligence
- `GetDomainIntelligenceDetail` - Get domain intelligence detail

### KnowledgeBaseService
- `SearchStandardVulnList` - Search vulnerability knowledge base
- `GetStandardVulnDetailByCTID` - Get vuln detail by CTID
- `GetStandardVulnDetailByID` - Get vuln detail by ID
- `SearchCustomizeTags` - Search custom tags
- `CreateCustomizeTag` / `DeleteCustomizeTag` - Manage custom tags
- `AppendCustomizeTags` / `ReplaceCustomizeTags` - Manage vuln tags

### DeviceService
- `CheckScanDeviceAuth` - Verify device authentication
- `CreateDevice` - Register new device
- `RemoveScanDevice` - Remove a device
- `GetDataAccessMapping` - Get data access mapping
- `GetDeviceProductNameList` - List device product names

### VptService
- `GetVulnVptScore` - Calculate VPT score for vulnerabilities
- `GetVulnVptScoreSetting` - Get VPT score configuration
- `SaveVulnVptScoreSetting` - Save VPT score configuration
- `ResetVulnVptScoreSetting` - Reset VPT score configuration
- `GetVulnVptScoreState` - Get VPT score calculation state

## Protocol

This service uses JSON-RPC 2.0 protocol to communicate with Jianwei platform:
- All requests are HTTP POST to `/pedestal/rpc` (single endpoint)
- Authentication via Bearer token (JWT with `aim: "api"` claim)
- Method name is in the JSON-RPC request body, not the URL path
- Request format: `{"jsonrpc": "2.0", "method": "ServiceName.MethodName", "params": {...}, "id": 1}`
- Response format: `{"jsonrpc": "2.0", "result": {...}, "id": 1}`

## License

LGPL-3.0-only
