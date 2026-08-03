#!/usr/bin/env bash
#
# Build SeedForge desktop binaries for every major OS from one machine.
# Requires only the Go toolchain (https://go.dev/dl/). No other dependencies.
#
set -euo pipefail
cd "$(dirname "$0")"

OUT="${OUT:-./out}"
mkdir -p "$OUT"
export CGO_ENABLED=0
LD="-s -w"   # strip symbols/debug for smaller, cleaner binaries

build() {
  echo "-> $1/$2"
  GOOS="$1" GOARCH="$2" go build -trimpath -ldflags "$LD" -o "$3" .
}

build windows amd64 "$OUT/SeedForge-windows-amd64.exe"
build windows arm64 "$OUT/SeedForge-windows-arm64.exe"
build darwin  amd64 "$OUT/SeedForge-macos-amd64"
build darwin  arm64 "$OUT/SeedForge-macos-arm64"
build linux   amd64 "$OUT/SeedForge-linux-amd64"
build linux   arm64 "$OUT/SeedForge-linux-arm64"

echo
echo "Built binaries in $OUT:"
ls -la "$OUT"
echo
echo "Verify none of them link networking code:"
go list -deps . | grep -E '(^net$|net/http)' && echo "NETWORK FOUND" || echo "  clean: no net / no net/http"
