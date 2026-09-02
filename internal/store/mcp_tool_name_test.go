package store

import (
	"context"
	"errors"
	"testing"

	"octobus/internal/domain"
)

func TestAddCapsetMethodEnforcesToolNameUniquenessWithinCapset(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	if err := st.UpsertService(ctx, domain.Service{ID: "echo", Name: "Echo"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertInstance(ctx, domain.Instance{ID: "echo-instance", ServiceID: "echo", Name: "Echo", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for _, capsetID := range []string{"dev", "qa"} {
		if err := st.CreateCapset(ctx, domain.Capset{ID: capsetID, Name: capsetID, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if err := st.AddCapsetInstance(ctx, domain.CapsetInstance{ID: capsetID + ":echo-instance", CapsetID: capsetID, ServiceID: "echo", InstanceID: "echo-instance", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}

	first := domain.CapsetMethod{CapsetInstanceID: "dev:echo-instance", MethodFullName: "echo.Echo/Call", MCPToolName: "shared_tool", Enabled: true}
	if err := st.AddCapsetMethod(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := st.AddCapsetMethod(ctx, domain.CapsetMethod{CapsetInstanceID: "dev:echo-instance", MethodFullName: "echo.Echo/Other", MCPToolName: "shared_tool", Enabled: true}); !errors.Is(err, ErrMCPToolNameConflict) {
		t.Fatalf("duplicate tool error = %v", err)
	}
	if err := st.AddCapsetMethod(ctx, domain.CapsetMethod{CapsetInstanceID: "qa:echo-instance", MethodFullName: "echo.Echo/Call", MCPToolName: "shared_tool", Enabled: true}); err != nil {
		t.Fatalf("same tool in another capset error = %v", err)
	}
}
