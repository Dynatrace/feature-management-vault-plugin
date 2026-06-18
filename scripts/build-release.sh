#!/usr/bin/env bash
#
# build-release.sh — cross-compile the plugin into release archives plus a
# SHA256SUMS file under dist/. Used by CI (sanity build) and the release
# workflow (artifacts uploaded to the GitHub release).
#
# Usage: scripts/build-release.sh <version>   (version may be "v0.1.0" or "0.1.0")
set -euo pipefail

VERSION="${1:?usage: build-release.sh <version>}"
VER="${VERSION#v}" # strip a leading v for archive filenames
NAME="vault-plugin-secrets-feature-management"
DIST="${DIST:-dist}"
PLATFORMS=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

rm -rf "$DIST"
mkdir -p "$DIST"

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

for platform in "${PLATFORMS[@]}"; do
  os="${platform%/*}"
  arch="${platform#*/}"
  echo "building ${os}/${arch} ..."
  # CGO disabled => static, portable plugin binaries.
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags "-s -w" -o "${DIST}/${NAME}" "./cmd/${NAME}"
  (cd "$DIST" && zip -q "${NAME}_${VER}_${os}_${arch}.zip" "$NAME" && rm -f "$NAME")
done

(cd "$DIST" && sha256 ./*.zip >"${NAME}_${VER}_SHA256SUMS")

echo "=== artifacts ==="
ls -la "$DIST"
