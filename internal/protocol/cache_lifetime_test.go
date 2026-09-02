package protocol

import (
	"net/http"
	"testing"
	"time"
)

func TestGatewayCacheEntriesExpireAndInvalidateTogether(t *testing.T) {
	gateway := &Gateway{
		mcpToolsCache:  map[string][]map[string]any{"expired": {{"name": "tool"}}},
		connectCache:   map[string]http.Handler{"expired": http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})},
		mcpCacheAt:     map[string]time.Time{"expired": time.Now().Add(-gatewayCacheTTL)},
		connectCacheAt: map[string]time.Time{"expired": time.Now().Add(-gatewayCacheTTL)},
	}
	gateway.mu.Lock()
	gateway.evictExpiredCachesLocked(time.Now())
	gateway.mu.Unlock()
	if len(gateway.mcpToolsCache) != 0 || len(gateway.connectCache) != 0 {
		t.Fatalf("expired gateway cache entries remain: mcp=%d connect=%d", len(gateway.mcpToolsCache), len(gateway.connectCache))
	}
}

func TestGatewayInstanceInvalidationClearsSchemaCaches(t *testing.T) {
	gateway := &Gateway{
		mcpToolsCache:  map[string][]map[string]any{"cached": {{"name": "tool"}}},
		connectCache:   map[string]http.Handler{"cached": http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})},
		mcpCacheAt:     map[string]time.Time{"cached": time.Now()},
		connectCacheAt: map[string]time.Time{"cached": time.Now()},
	}
	gateway.InvalidateInstance("missing-instance")
	if len(gateway.mcpToolsCache) != 0 || len(gateway.connectCache) != 0 {
		t.Fatal("instance invalidation left stale schema caches")
	}
}
