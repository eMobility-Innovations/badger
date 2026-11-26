#!/usr/bin/env bash
# The suite entry point the merge gate runs: vet, then every Go test with the race detector.
# The plugin is loaded by Traefik's interpreter in production; these run it compiled.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v go >/dev/null || { echo "REFUSING: no go toolchain on PATH; a gate that runs nothing must not report success" >&2; exit 2; }
test -z "$(gofmt -l .)" || { echo "gofmt: these files need formatting:" >&2; gofmt -l . >&2; exit 1; }
go vet ./...
go test -race ./...
