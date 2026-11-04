#!/usr/bin/env bash
# AI-hint: Bootstrap alias of the canonical install entry; checkout and piped invocations preserve arguments and failures.
# AI-related: install.sh, field/lib/field.sh, installation/mios-install.sh
set -euo pipefail

source_path="${BASH_SOURCE[0]:-}"
if [[ -n "$source_path" && -f "$source_path" ]]; then
    repo_root="$(cd -P -- "$(dirname -- "$source_path")" && pwd -P)"
    entry="$repo_root/install.sh"
    if [[ ! -f "$entry" || "$(readlink -f -- "$entry")" != "$entry" ]]; then
        echo "Canonical install entry is absent or escapes its checkout: $entry" >&2
        exit 1
    fi
    exec bash "$entry" "$@"
fi

repo="${MIOS_BOOTSTRAP_REPO:-}"
if [[ -d "$repo" ]]; then
    repo_root="$(cd -P -- "$repo" && pwd -P)"
    entry="$repo_root/install.sh"
    if [[ ! -f "$entry" || "$(readlink -f -- "$entry")" != "$entry" ]]; then
        echo "Explicit bootstrap repository has no canonical install entry: $entry" >&2
        exit 1
    fi
    exec bash "$entry" "$@"
elif [[ "$repo" == /* || "$repo" == ./* || "$repo" == ../* ]]; then
    echo "Explicit bootstrap repository is absent: $repo" >&2
    exit 1
fi

# Fetch the complete install resolver, which obtains the selected full checkout;
# fetching only MiOS-Field.sh loses its required library and installer.
curl -fsSL "https://raw.githubusercontent.com/mios-dev/mios-bootstrap/main/install.sh" | bash -s -- "$@"
