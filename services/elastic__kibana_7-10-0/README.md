# Elastic Kibana 7.10.0

OctoBus service package for Kibana 7.10.0 read-only operations via the Kibana REST API.

## Methods

| Method | Description |
|--------|-------------|
| `GetStatus` | Get Kibana server status and plugin health |
| `ListSpaces` | List all Kibana spaces |
| `GetSpace` | Get a single Kibana space by ID |
| `FindSavedObjects` | Find saved objects by type with search and pagination |
| `GetSavedObject` | Get a single saved object by type and id |
| `BulkGetSavedObjects` | Bulk get multiple saved objects by type and id |
| `ExportSavedObjects` | Export saved objects as NDJSON |

## Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `baseUrl` | string | Yes | Kibana base URL (e.g. `https://kibana.example.com:5601`) |
| `timeoutMs` | integer | No | HTTP timeout in milliseconds (default: 5000) |
| `skipTlsVerify` | boolean | No | Skip TLS certificate verification |

## Secrets

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | Yes | Kibana username |
| `password` | string | Yes | Kibana password |

## API Reference

- [Kibana 7.10 Spaces API](https://www.elastic.co/guide/en/kibana/7.10/spaces-api.html)
- [Kibana 7.10 Saved Objects API](https://www.elastic.co/guide/en/kibana/7.10/saved-objects-api.html)
- [Kibana 7.10 Status API](https://www.elastic.co/guide/en/kibana/7.10/access.html)