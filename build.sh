#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$ROOT/bin"
BINARY_NAME="stackscanner"
OUTPUT="$OUT_DIR/$BINARY_NAME"
GOFLAGS="${GOFLAGS:-}"

LD_FLAGS=""
VERBOSE=0

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -o <path>        Output binary path (default: ./bin/stackscanner)
  -l <ldflags>     Pass string to go build -ldflags
  -v               Verbose output
  -h               Show this help

Examples:
  ./build.sh
  ./build.sh -o ./release/stackscanner
  LD_FLAGS="-s -w" ./build.sh -o ./release/stackscanner
EOF
  exit 1
}

while getopts ":o:l:vh" opt; do
  case "$opt" in
    o) OUTPUT="$OPTARG" ;;
    l) LD_FLAGS="$OPTARG" ;;
    v) VERBOSE=1 ;;
    h) usage ;;
    *) usage ;;
  esac
done

mkdir -p "$(dirname "$OUTPUT")"

echo "Building for: $(go version 2>/dev/null || echo 'go not found')"
if [ "$VERBOSE" -eq 1 ]; then
  set -x
fi

if [ -n "${LD_FLAGS}" ]; then
  echo "go build -ldflags '${LD_FLAGS}' -o '$OUTPUT' ."
  go build $GOFLAGS -ldflags "${LD_FLAGS}" -o "$OUTPUT" .
else
  echo "go build -o '$OUTPUT' ."
  go build $GOFLAGS -o "$OUTPUT" .
fi

if command -v strip >/dev/null 2>&1; then
  # try to strip binary (best-effort)
  if [ "$(uname -s)" = "Linux" ] || [ "$(uname -s)" = "Darwin" ]; then
    strip "$OUTPUT" 2>/dev/null || true
  fi
fi

echo "Built: $OUTPUT"
if command -v sha256sum >/dev/null 2>&1; then
  echo "SHA256: $(sha256sum "$OUTPUT" | awk '{print $1}')"
fi

cat <<EOF
Next steps:
  - Make the helper script executable (if not already):
      chmod +x build.sh
  - Run the built binary:
      $OUTPUT --help
  - To create a minimal static linux binary (best-effort):
      CGO_ENABLED=0 GOOS=linux GOARCH=amd64 LD_FLAGS='-s -w' ./build.sh -o ./bin/stackscanner-linux
EOF
