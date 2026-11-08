<!-- AI-hint: Native bootstrap mirror parity receipt with exact bases, non-destructive scope and repeatable verification. -->
# Bootstrap port parity handoff

Bootstrap base: `ca1e7d392f801b50f32acc6a9de1a247aba47cc8`, verified against
remote `origin/main` before creating the isolated `mios-bootstrap-port-parity`
worktree. The original `/workspace/mios-bootstrap` checkout remains clean at
that revision. The authority used is `/workspace/mios-handoff-continuation`;
its observed revision after synchronization was
`238f9a9b4a48a65ca9239b2f9ea916fc2dd694ad`.

## Source changes

The source-matched native `mios-gen bootstrap-sync` applied exactly two
drifting surfaces from MiOS's `[bootstrap.sync]` declaration:

- `build-mios.ps1` now matches the authority byte for byte. The recovered
  endpoint corrections resolve SearXNG from `[ports].searxng`, remove stale
  listener/drop-in and direct LAN-forwarding behavior, and omit unresolved
  service shortcuts rather than substituting a retired literal.
- Root `mios.toml` scalar `[ports]` drops `searxng_internal` and changes
  `unbound` to `["field_live_chat"]`. The bootstrap-owned nested
  `[ports.lan_firewall]` table is unchanged.

Other declared mirror files, scalar colors and seven individual keys already
matched. The only additional tracked changes are this receipt and its narrow
ignore whitelist.

## Actual verification

All native synchronization commands ran through the prepared builder's
existing `mios-build-exec` helper as its unprivileged user; no additional
compiler or parallel build was launched:

```sh
MIOS_BUILD_WORKDIR=/workspace/mios-bootstrap-port-parity \
  /workspace/mios-native-builder-state/mios-build-exec \
  /workspace/mios-native-builder-state/target/x86_64-unknown-linux-musl/debug/mios-gen \
  bootstrap-sync --root /workspace/mios-handoff-continuation \
  --bootstrap /workspace/mios-bootstrap-port-parity --check
```

The initial check exited 1 and named exactly `build-mios.ps1` and `mios.toml`.
The first `--apply` exited 0 and applied two surfaces. The next `--check`
exited 0: `13 mirrored file(s), 2 table(s), 7 key(s) match`.
The second `--apply` exited 0 with zero applied surfaces. Both file hashes
were identical before and after that second apply:

| File | SHA-256 |
| --- | --- |
| build-mios.ps1 | fa4cf714a834649c953b0db0e80fc053c91f725f6951c98ed7632ad2d79c3122 |
| mios.toml | 7cf4cc4e9f6339b9a15339f5e795d0c54177deba4fa01241e82d15451b3be6d8 |

Independent Python TOML parsing confirmed all scalar mirror tables and keys,
the retired endpoint's absence, exact PowerShell bytes, and equality of the
nested LAN firewall table with the original bootstrap base. That table's
sorted JSON SHA-256 remains
`800f4cfbc31472a9fc660f68021c879924e41ffe0f6caaaeac921140af8a08f8`.

No live installer, Windows firewall, port proxy, deployed node, or Codespace
was changed or certified. PowerShell execution and live endpoint acceptance
remain separate checks on an authorized target.

## Publication and recovery

The operator requires publication through main only. This worker creates a
local reviewable commit and sends its SHA to the integration owner; it does
not push a worker branch. After the integration owner verifies the remote
head and publishes the fast-forward to bootstrap main, a remote agent can
fetch `origin/main`, read this receipt, and rerun native `bootstrap-sync
--check` against matching authority and bootstrap worktrees. Use Git history
for the publication commit identity; this receipt does not invent its own SHA.
