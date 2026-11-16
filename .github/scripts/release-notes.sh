#!/usr/bin/env bash
# Print the CHANGELOG.md notes for a release tag (for example v0.1.0 or v0.1.0-rc.1).
#
# - Stable tag: the [X.Y.Z] section is required, otherwise exit 1.
# - Pre-release tag: the exact [X.Y.Z-rc.N] section, else the [X.Y.Z] section of the
#   base version; prints nothing if neither exists (the caller then generates notes).
set -euo pipefail

tag="${1:?usage: release-notes.sh <tag>}"
changelog="${2:-CHANGELOG.md}"
version="${tag#v}"

extract() {
  awk -v header="## [$1]" '
    index($0, header) == 1 { found = 1; next }
    found && /^## \[/ { exit }
    found && /^\[[^]]+\]: / { exit }
    found { print }
  ' "$changelog"
}

blank() { [ -z "$(printf '%s' "$1" | tr -d '[:space:]')" ]; }

notes="$(extract "$version")"
if blank "$notes" && [[ "$version" == *-* ]]; then
  notes="$(extract "${version%%-*}")"
fi
if blank "$notes"; then
  if [[ "$version" == *-* ]]; then
    exit 0
  fi
  echo "::error::CHANGELOG.md has no notes for ${version}" >&2
  exit 1
fi
printf '%s\n' "$notes"
