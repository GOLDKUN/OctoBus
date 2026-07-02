#!/usr/bin/env bash
set -euo pipefail

coverpkg="$(
  go list ./cmd/... ./internal/... |
    grep -v '^octobus/internal/integration$' |
    paste -sd, -
)"
unit_pkgs=()
while IFS= read -r pkg; do
  unit_pkgs+=("$pkg")
done < <(
  go list ./cmd/... ./internal/... |
    grep -v '^octobus/internal/integration$'
)

go test -v -coverprofile=coverage/unit.out "${unit_pkgs[@]}"
printf 'unit coverage: '
go tool cover -func=coverage/unit.out | tail -n 1

go test -v -coverpkg="$coverpkg" -coverprofile=coverage/integration.out ./internal/integration
printf 'integration coverage: '
go tool cover -func=coverage/integration.out | tail -n 1

OCTOBUS_E2E_COVERAGE_DIR="$PWD/coverage/e2e" OCTOBUS_E2E_COVERPKG="$coverpkg" go test -v ./tests/e2e
go tool covdata textfmt -i=coverage/e2e -o=coverage/e2e.out
printf 'e2e coverage: '
go tool cover -func=coverage/e2e.out | tail -n 1

go run ./scripts/merge-coverprofiles.go coverage/coverage.out coverage/unit.out coverage/integration.out coverage/e2e.out
printf 'total coverage: '
go tool cover -func=coverage/coverage.out | tail -n 1
