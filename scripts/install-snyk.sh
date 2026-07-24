#!/usr/bin/env bash
# Install the Snyk CLI and verifying the published sha256.
#
# Env: SNYK_VERSION ("latest"/"stable" for the stable channel, or a version
# such as "1.1305.1" / "v1.1305.1" to pin).
set -euo pipefail

: "${SNYK_VERSION:=latest}"

# RUNNER_OS / RUNNER_ARCH are set by the Actions runner on every platform.
case "${RUNNER_OS:-Linux}-${RUNNER_ARCH:-X64}" in
  Linux-X64)    asset="snyk-linux" ;;
  Linux-ARM64)  asset="snyk-linux-arm64" ;;
  macOS-X64)    asset="snyk-macos" ;;
  macOS-ARM64)  asset="snyk-macos-arm64" ;;
  *)            asset="" ;;
esac

if [ -z "$asset" ]; then
  echo "::notice::No Snyk standalone binary for ${RUNNER_OS:-?}/${RUNNER_ARCH:-?}; installing via npm."
  npm install -g "snyk@${SNYK_VERSION}"
  snyk --version
  exit 0
fi

case "$SNYK_VERSION" in
  latest|stable|"") channel="stable" ;;
  v*)               channel="$SNYK_VERSION" ;;
  *)                channel="v${SNYK_VERSION}" ;;
esac

dest="${RUNNER_TEMP:-/tmp}/snyk-cli"
mkdir -p "$dest"
cd "$dest"

base="https://downloads.snyk.io/cli/${channel}"
curl -fsSL --retry 3 --retry-delay 2 --compressed "${base}/${asset}" -o "$asset"
curl -fsSL --retry 3 --retry-delay 2 "${base}/${asset}.sha256" -o "${asset}.sha256"


if command -v sha256sum > /dev/null 2>&1; then
  sha256sum -c "${asset}.sha256"
else
  shasum -a 256 -c "${asset}.sha256"
fi
rm -f "${asset}.sha256"

mv "$asset" snyk
chmod +x snyk

echo "$dest" >> "$GITHUB_PATH"
"./snyk" --version
