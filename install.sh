#!/usr/bin/env bash
# AI-hint: Resolve the invoked bootstrap checkout, then reach the canonical installer.
# AI-related: bootstrap.sh, field/lib/field.sh, installation/mios-install.sh
set -euo pipefail

source_path="${BASH_SOURCE[0]:-}"
if [[ -n "$source_path" && -f "$source_path" ]]; then
    repo_root="$(cd -P -- "$(dirname -- "$source_path")" && pwd -P)"
else
    # A piped script has no checkout-relative path. Never search the caller's
    # working directory or its siblings for executable bootstrap files.
    repo="${MIOS_BOOTSTRAP_REPO:-${MIOS_BOOTSTRAP_REPO_URL:-https://github.com/mios-dev/mios-bootstrap.git}}"
    if [[ -d "$repo" ]]; then
        repo_root="$(cd -P -- "$repo" && pwd -P)"
    elif [[ "$repo" == /* || "$repo" == ./* || "$repo" == ../* ]]; then
        echo "Explicit bootstrap repository is absent: $repo" >&2
        exit 1
    else
        repo_root="${MIOS_BOOTSTRAP_ROOT:-${HOME:?}/mios-bootstrap}"
        if [[ ! -e "$repo_root" ]]; then
            git clone --depth 1 -- "$repo" "$repo_root"
        elif [[ "$(git -C "$repo_root" config --get remote.origin.url)" != "$repo" ]]; then
            echo "Existing bootstrap checkout does not match the selected repository: $repo_root" >&2
            exit 1
        fi
        repo_root="$(cd -P -- "$repo_root" && pwd -P)"
    fi
fi

for entry in field/MiOS-Field.sh field/lib/field.sh installation/mios-common.sh installation/mios-install.sh; do
    path="$repo_root/$entry"
    if [[ ! -f "$path" || "$(readlink -f -- "$path")" != "$path" ]]; then
        echo "Canonical bootstrap file is absent or escapes its checkout: $path" >&2
        exit 1
    fi
done
exec bash "$repo_root/field/MiOS-Field.sh" install "$@"
