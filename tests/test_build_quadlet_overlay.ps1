# Quadlet-overlay root checkout fixtures. The mios-root-checkout bash block and the three /etc/wsl.conf writers are
# extracted from build-mios.ps1 and run against scratch fixture roots: a scratch "mios.git" source, a scratch root with
# machine-os-shaped files, Git for Windows' bash (never WSL's) and a pass-through sudo shim. Nothing outside the scratch
# tree is read or written, and no distro, wsl.exe or network is touched.
# Default runs the fixtures; -PlantDefect plants each guarded defect into a copy of the product and requires a red result.
[CmdletBinding()]
param([switch]$PlantDefect, [string]$BuildPath)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $BuildPath) { $BuildPath = Join-Path $repoRoot 'build-mios.ps1' }
$gitExe = (Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $gitExe) { $c = Join-Path $env:LOCALAPPDATA 'Programs\Git\cmd\git.exe'; if (Test-Path -LiteralPath $c) { $gitExe = $c } else { throw 'git is required' } }
$gitHome = Split-Path (Split-Path $gitExe -Parent) -Parent
$bash = Join-Path $gitHome 'bin\bash.exe'
if (-not (Test-Path -LiteralPath $bash)) { throw "Git for Windows bash not found at $bash (WSL's bash is never used)" }
# A real interpreter, never the WindowsApps "python3" store alias stub.
$python = $null
foreach ($cand in @(Get-Command python3, python, py -CommandType Application -All -ErrorAction SilentlyContinue)) {
    if ($cand.Source -match '\\WindowsApps\\') { continue }
    $ErrorActionPreference = 'Continue'; $null = & $cand.Source -c 'import sys' 2>$null; $ok = $LASTEXITCODE -eq 0; $ErrorActionPreference = 'Stop'
    if ($ok) { $python = $cand.Source; break }
}
if (-not $python) { throw 'python is required for the wsl.conf sanitizer fixture' }
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-quadlet-overlay-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -ErrorAction Stop | Out-Null
$lf = New-Object Text.UTF8Encoding($false)

$script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
function Check([bool]$Ok, [string]$What) {
    $script:checks++
    if ($Ok) { Write-Host "  PASS $What" } else { Write-Host "  FAIL $What"; $script:fail++; $script:failedChecks.Add($What) }
}
function Fwd([string]$Path) { return $Path -replace '\\', '/' }
function Write-Lf([string]$Path, [string]$Text) { New-Item -ItemType Directory -Force -Path (Split-Path $Path -Parent) | Out-Null; [IO.File]::WriteAllText($Path, $Text, $lf) }
function Get-Sha([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function G([string]$Dir) { $ErrorActionPreference = 'Continue'; $o = & $gitExe -C $Dir @args 2>&1; if ($LASTEXITCODE -ne 0) { throw "git $($args -join ' ') in ${Dir}: $o" }; return (($o | Out-String).Trim()) }
function Get-Head([string]$Dir) { $ErrorActionPreference = 'Continue'; $o = & $gitExe -C $Dir rev-parse --verify -q HEAD 2>$null; if ($LASTEXITCODE -ne 0) { return '' }; return (($o | Out-String).Trim()) }
function Get-Block([string]$Text, [string]$Start, [string]$End) {
    $i = $Text.IndexOf($Start); if ($i -lt 0) { throw "block start not found: $Start" }
    $j = $Text.IndexOf($End, $i); if ($j -lt 0) { throw "block end not found: $End" }
    return $Text.Substring($i, $j + $End.Length - $i)
}

# mios.git's etc/wsl.conf and usr/lib/wsl.conf at e0351285 (both blob cad13fa99a8dd7d6a1a023ea3202857b82d29243).
$miosWslConf = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('IyBBSS1oaW50OiBEZWZpbmVzIHRoZSBjb3JlIFdTTDIgZW52aXJvbm1lbnQgY29uZmlndXJhdGlvbiBmb3IgTWlPUywgZW5hYmxpbmcgc3lzdGVtZCwgc2V0dGluZyB0aGUgZGVmYXVsdCAnbWlvcycgdXNlciwgYW5kIGNvbmZpZ3VyaW5nIG1vdW50IG9wdGlvbnMgYW5kIG5ldHdvcmsgYmVoYXZpb3IgZm9yIHRoZSBXU0wgc3Vic3lzdGVtLgojIEFJLWRvYzogdXNyL3NoYXJlL2RvYy9taW9zL21hbnVhbC9saWIubWQKW2Jvb3RdCnN5c3RlbWQ9dHJ1ZQpbdXNlcl0KZGVmYXVsdD1taW9zCltpbnRlcm9wXQplbmFibGVkPXRydWUKYXBwZW5kV2luZG93c1BhdGg9ZmFsc2UKW2F1dG9tb3VudF0KZW5hYmxlZD10cnVlCm9wdGlvbnM9bWV0YWRhdGEsdW1hc2s9MjIsZm1hc2s9MTEKW25ldHdvcmtdCmdlbmVyYXRlSG9zdHM9dHJ1ZQpnZW5lcmF0ZVJlc29sdkNvbmY9dHJ1ZQo='))
$overlap = @('etc/chrony.conf', 'etc/wsl.conf', 'usr/lib/os-release', 'usr/lib/systemd/system/var-lib-nfs-rpc_pipefs.mount', 'usr/share/containers/storage.conf')

# --- Scratch "mios.git": the 5 overlap paths plus MiOS-only files ------------------------------------------------------
$src = Join-Path $scratch 'mios-src'
New-Item -ItemType Directory -Path $src | Out-Null
$null = G $src init -q -b main; $null = G $src config core.autocrlf false
$null = G $src config user.email fixture@example.invalid; $null = G $src config user.name Fixture
$srcFiles = [ordered]@{ 'etc/chrony.conf' = "server 0.pool.ntp.org iburst`nconfdir /etc/chrony.d`n"; 'etc/wsl.conf' = $miosWslConf
    'usr/lib/os-release' = "NAME=`"MiOS`"`nID=mios`n"; 'usr/lib/systemd/system/var-lib-nfs-rpc_pipefs.mount' = "# AI-hint: rpc_pipefs`n[Unit]`nDescription=RPC Pipe File System`n"
    'usr/share/containers/storage.conf' = "[storage]`ndriver = `"overlay`"`n[storage.options.overlay]`nmountopt = `"nodev,metacopy=on,userxattr`"`n"
    'usr/lib/mios/mios_toml.py' = "# mios_toml fixture`n"; 'usr/share/mios/mios.toml' = "[identity]`nusername = `"user`"`n"; 'etc/mios-extra.conf' = "extra = true`n" }
foreach ($k in $srcFiles.Keys) { Write-Lf (Join-Path $src $k) $srcFiles[$k] }
$null = G $src add -A; $null = G $src commit -q -m one
$commit1 = G $src rev-parse HEAD

function New-Root([string]$Name, [switch]$Unknown, [switch]$StoreContent, [switch]$DirConflict) {
    $root = Join-Path $scratch $Name
    foreach ($p in $overlap) { Write-Lf (Join-Path $root $p) "machine-os $p`n" }
    Write-Lf (Join-Path $root 'bin/sh') "machine-os sh`n"; Write-Lf (Join-Path $root 'usr/bin/podman') "machine-os podman`n"
    # An empty store as podman leaves it: the `l` link dir and the .has-mount-program marker, which are not layers.
    New-Item -ItemType Directory -Force -Path (Join-Path $root 'var/lib/containers/storage/overlay/l') | Out-Null
    Write-Lf (Join-Path $root 'var/lib/containers/storage/overlay/.has-mount-program') "true`n"
    Write-Lf (Join-Path $root 'home/user/.local/share/containers/storage/overlay/.has-mount-program') "true`n"
    if ($StoreContent) { New-Item -ItemType Directory -Force -Path (Join-Path $root ('var/lib/containers/storage/overlay/' + ('0a1b2c3d' * 8))) | Out-Null }
    if ($Unknown) { Write-Lf (Join-Path $root 'etc/mios-extra.conf') "machine-os extra`n" }
    if ($DirConflict) { Write-Lf (Join-Path $root 'usr/lib/mios') "machine-os file where mios.git has a directory`n" }
    $null = G $root init -q -b main; $null = G $root config core.autocrlf false; $null = G $root config core.filemode false
    $null = G $root remote add origin (Fwd $src); $null = G $root fetch -q origin main
    return $root
}
function Get-Backups([string]$Root) { $d = Join-Path $Root 'var/lib/mios/overlay-backup'; if (Test-Path -LiteralPath $d) { return @(Get-ChildItem -LiteralPath $d -Directory) } else { return @() } }
function Read-OrNull([string]$Path) { if (Test-Path -LiteralPath $Path -PathType Leaf) { return [IO.File]::ReadAllText($Path) } else { return $null } }
function Test-MachineOsIntact([string]$Root) { foreach ($p in $overlap) { if ((Read-OrNull (Join-Path $Root $p)) -cne "machine-os $p`n") { return $false } }; return $true }
function Test-NoHead([string]$Root) { return ((Get-Head $Root) -eq '') }

# --- sudo shim and bash drivers ---------------------------------------------------------------------------------------
$shim = Join-Path $scratch 'shim'
# Pass-through sudo. NTFS cannot take a POSIX mode, so on this fixture host only `install -m <mode>` drops the mode;
# the product's private 0700 backup directory is asserted in the source contract below.
Write-Lf (Join-Path $shim 'sudo') ("#!/bin/bash`nif [[ `"`$1`" == install ]]; then shift; a=(); while ((`$#)); do if [[ `"`$1`" == -m ]]; then shift 2; continue; fi; a+=(`"`$1`"); shift; done; exec install `"`${a[@]}`"; fi`nexec `"`$@`"`n")
$driver = Join-Path $scratch 'drive-checkout.sh'
Write-Lf $driver "set -uo pipefail`nexport PATH=`"`$(cygpath -u `"`$1`"):/usr/bin:/mingw64/bin:`$PATH`"`n[[ `"`$(command -v sudo)`" == `"`$(cygpath -u `"`$1`")/sudo`" ]] || { echo 'sudo shim not first on PATH'; echo RC=99; exit 99; }`nsource `"`$2`"`nmios_root_checkout `"`$3`" FETCH_HEAD`necho `"RC=`$?`"`n"
function Invoke-Checkout([string]$Block, [string]$Root) {
    $ErrorActionPreference = 'Continue'
    $out = @(& $bash --noprofile --norc $driver (Fwd $shim) (Fwd $Block) (Fwd $Root) 2>&1 | ForEach-Object { "$_" })
    $rcLine = @($out | Where-Object { $_ -match '^RC=\d+$' }) | Select-Object -Last 1
    if ($env:MIOS_TEST_VERBOSE) { Write-Host ($out -join "`n") }
    return [pscustomobject]@{ Rc = if ($rcLine) { [int]($rcLine -replace '^RC=', '') } else { -1 }; Text = ($out -join "`n") }
}
function Invoke-BashBlock([string]$Body) {
    $ErrorActionPreference = 'Continue'
    $f = Join-Path $scratch ('block-' + [guid]::NewGuid().ToString('N') + '.sh'); Write-Lf $f ("set -uo pipefail`nexport PATH=`"/usr/bin:/mingw64/bin:`$PATH`"`n" + $Body + "`n")
    $o = @(& $bash --noprofile --norc $f 2>&1 | ForEach-Object { "$_" }); return ($o -join "`n")
}

function Invoke-Checks([string]$Build) {
    $script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
    $text = ([IO.File]::ReadAllText($Build)) -replace "`r`n", "`n"
    $blockFile = Join-Path $scratch ('checkout-' + [guid]::NewGuid().ToString('N') + '.sh')
    Write-Lf $blockFile (Get-Block $text '# >>> mios-root-checkout' '# <<< mios-root-checkout')

    # --- Happy path: the 5 known paths are backed up, moved aside and checked out; / ends clean ------------------------
    $root = New-Root ('happy-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $r = Invoke-Checkout $blockFile $root
    $headOk = (Get-Head $root) -eq $commit1
    $contentOk = @($overlap | Where-Object { (Read-OrNull (Join-Path $root $_)) -cne $srcFiles[$_] }).Count -eq 0
    $clean = (G $root status --porcelain --untracked-files=no) -eq ''
    Check ($r.Rc -eq 0 -and $headOk -and $contentOk -and $clean -and (Read-OrNull (Join-Path $root 'bin/sh')) -ceq "machine-os sh`n" -and
           (Read-OrNull (Join-Path $root 'usr/bin/podman')) -ceq "machine-os podman`n") 'the known machine-os overlaps are replaced by a clean checkout; other machine-os files stay'
    $backups = @(Get-Backups $root); $backupOk = $false
    if ($backups.Count -eq 1) {
        $b = $backups[0].FullName; $manifest = @(if (Test-Path -LiteralPath (Join-Path $b 'MANIFEST')) { Get-Content -LiteralPath (Join-Path $b 'MANIFEST') })
        $backupOk = $manifest.Count -eq 5
        foreach ($p in $overlap) {
            $orig = "machine-os $p`n"; $saved = Join-Path $b ('files/' + $p)
            $want = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($lf.GetBytes($orig))).Replace('-', '').ToLowerInvariant()
            if (-not (Test-Path -LiteralPath $saved) -or (Read-OrNull $saved) -cne $orig -or
                -not @($manifest | Where-Object { $_ -match (' ' + $want + ' ' + [regex]::Escape($p) + '$') -and $_ -match '^\S+:\S+ \d+ \d+ ' }).Count) { $backupOk = $false }
        }
    }
    Check $backupOk 'every moved path is in one timestamped private backup with owner:group, mode, size and sha256'
    # The same root fast-forwards when mios.git moves on.
    Write-Lf (Join-Path $src 'etc/chrony.conf') "server 1.pool.ntp.org iburst`nconfdir /etc/chrony.d`n"
    $null = G $src commit -q -am two; $commit2 = G $src rev-parse HEAD; $null = G $root fetch -q origin main
    $r2 = Invoke-Checkout $blockFile $root
    Check ($r2.Rc -eq 0 -and (Get-Head $root) -eq $commit2) 'an existing clean checkout fast-forwards'
    $null = G $src reset -q --hard $commit1

    # --- Refusals: nothing is moved ------------------------------------------------------------------------------------
    $root = New-Root ('unknown-' + [guid]::NewGuid().ToString('N').Substring(0, 8)) -Unknown
    $r = Invoke-Checkout $blockFile $root
    Check ($r.Rc -eq 4 -and $r.Text -match 'etc/mios-extra.conf' -and $r.Text -match 'REMEDY: .* re-provision it \(podman machine rm \S+, then re-run the installer\)' -and (Test-MachineOsIntact $root) -and (Get-Backups $root).Count -eq 0 -and (Test-NoHead $root) -and
           (Read-OrNull (Join-Path $root 'etc/mios-extra.conf')) -ceq "machine-os extra`n") 'a path git would overwrite that is not on the known list refuses with nothing moved'
    $root = New-Root ('store-' + [guid]::NewGuid().ToString('N').Substring(0, 8)) -StoreContent
    $r = Invoke-Checkout $blockFile $root
    Check ($r.Rc -eq 5 -and $r.Text -match 'already holds images or layers' -and (Test-MachineOsIntact $root) -and (Get-Backups $root).Count -eq 0 -and (Test-NoHead $root)) 'a container store with layers refuses the storage.conf switch with nothing moved'
    # Re-run from "git init done, no HEAD" (that refusal's state) resumes once the store is empty.
    Remove-Item -LiteralPath (Join-Path $root ('var/lib/containers/storage/overlay/' + ('0a1b2c3d' * 8))) -Recurse -Force
    $r = Invoke-Checkout $blockFile $root
    Check ($r.Rc -eq 0 -and (Get-Head $root) -eq $commit1 -and (G $root status --porcelain --untracked-files=no) -eq '') 'a root left at git init with no HEAD resumes the checkout on the next run'
    # A checkout git itself refuses restores everything that was moved.
    $root = New-Root ('dirconf-' + [guid]::NewGuid().ToString('N').Substring(0, 8)) -DirConflict
    $r = Invoke-Checkout $blockFile $root
    Check ($r.Rc -ne 0 -and $r.Rc -ne -1 -and (Test-MachineOsIntact $root) -and (Test-NoHead $root) -and $r.Text -match 'restored') 'a failed checkout restores every moved file'

    # --- The three /etc/wsl.conf writers are no-ops on mios.git's bytes, so / stays clean ------------------------------
    $body = $lf.GetBytes($miosWslConf); $hdr = [Text.Encoding]::ASCII.GetBytes("blob $($body.Length)`0")
    $blobOk = ([BitConverter]::ToString([Security.Cryptography.SHA1]::Create().ComputeHash([byte[]]($hdr + $body))).Replace('-', '').ToLowerInvariant()) -eq 'cad13fa99a8dd7d6a1a023ea3202857b82d29243'
    $wsl = Join-Path $scratch ('wsl-' + [guid]::NewGuid().ToString('N') + '.conf')
    $seedBlock = Get-Block $text 'echo "[quadlet-overlay] setting wsl.conf' "skipping wsl.conf default-user write`"`nfi"
    $seedRun = $seedBlock.Replace('/etc/wsl.conf', (Fwd $wsl)).Replace('sudo ', '').Replace('id mios >/dev/null 2>&1', 'true')
    Write-Lf $wsl $miosWslConf; $before = Get-Sha $wsl; $null = Invoke-BashBlock $seedRun
    $seedSame = (Get-Sha $wsl) -eq $before
    Write-Lf $wsl "[interop]`nenabled=true`n"; $null = Invoke-BashBlock $seedRun; $seedActs = ([IO.File]::ReadAllText($wsl)) -match '\[boot\]'
    Check ($blobOk -and $seedSame -and $seedActs) 'the quadlet-overlay wsl.conf enforcement leaves mios.git''s bytes unchanged (and still repairs a file that lacks them)'
    $miosSeed = Get-Block $text 'if [ ! -f /etc/wsl.conf ]; then' "default=mios already set`"`n    fi`nfi"
    $miosSeedRun = $miosSeed.Replace('/etc/wsl.conf', (Fwd $wsl)).Replace('id mios >/dev/null 2>&1', 'true')
    Write-Lf $wsl $miosWslConf; $null = Invoke-BashBlock $miosSeedRun
    Check ((Get-Sha $wsl) -eq $before) 'the mios-seed wsl.conf enforcement leaves mios.git''s bytes unchanged'
    $py = Get-Block $text 'import os, re, shutil' 'sanitize_conf("/etc/wsl.conf", has_mios)'
    $usrLib = Join-Path $scratch ('usrlib-' + [guid]::NewGuid().ToString('N') + '.conf')
    # On Linux text-mode writes use "\n"; this Windows fixture host would translate to "\r\n", so the copy pins newline="\n".
    $pyRun = $py.Replace('"/usr/lib/wsl.conf"', ('"' + (Fwd $usrLib) + '"')).Replace('"/etc/wsl.conf"', ('"' + (Fwd $wsl) + '"')).Replace('has_mios = os.system("id mios >/dev/null 2>&1") == 0', 'has_mios = True').Replace('open(filepath, "w", encoding="utf-8")', 'open(filepath, "w", encoding="utf-8", newline="\n")')
    $pyFile = Join-Path $scratch ('sanitize-' + [guid]::NewGuid().ToString('N') + '.py'); Write-Lf $pyFile $pyRun
    Write-Lf $wsl $miosWslConf; Write-Lf $usrLib $miosWslConf
    $ErrorActionPreference = 'Continue'; $null = & $python -I $pyFile 2>&1; $pyExit = $LASTEXITCODE; $ErrorActionPreference = 'Stop'
    Check ($pyExit -eq 0 -and (Get-Sha $wsl) -eq $before -and (Get-Sha $usrLib) -eq $before) 'the wsl.conf sanitizer leaves mios.git''s etc/ and usr/lib/ copies unchanged'

    # --- Source contract ------------------------------------------------------------------------------------------------
    $overlapLine = [regex]::Match($text, 'MIOS_ROOT_OVERLAP=\(([^)]*)\)').Groups[1].Value -split '\s+' | Where-Object { $_ }
    Check (@(Compare-Object @($overlapLine) $overlap).Count -eq 0 -and $text.Contains('mios_root_checkout / FETCH_HEAD || exit $?') -and
           $text.Contains('if ! sudo install -d -m 0700 "$backup/files"; then') -and
           -not $text.Contains('checkout --detach FETCH_HEAD || exit 1')) 'the seed checks out only through mios_root_checkout with exactly the 5 known overlaps'
    $tk = $null; $er = $null; $psAst = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tk, [ref]$er)
    $fnAst = @($psAst.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-MiosQuadletOverlay' }, $true))
    $fn = if ($fnAst.Count -eq 1) { $fnAst[0].Extent.Text } else { '' }
    $rcAt = $fn.IndexOf('if ($overlayRc -ne 0) {'); $throwAt = $fn.IndexOf('throw "Quadlet overlay failed (rc=$overlayRc)"', [Math]::Max(0, $rcAt))
    Check ($rcAt -ge 0 -and $throwAt -gt $rcAt -and -not $fn.Contains('rerun safe')) 'any non-zero overlay exit is fatal, never "partial overlay possible ... rerun safe"'
    Check ($fn.Contains('if ($overlayRc -eq 4) {') -and $fn.Contains('Unknown paths: $($unknownPaths -join '', '')') -and
           $fn.Contains('re-provision it (podman machine rm $DevDistro, then re-run the installer).') -and $fn.Contains("MIOS_DEV_MACHINE='`$DevDistro'")) 'an unknown-path refusal tells the operator the paths and the remedy on screen'
    Write-Host "QUADLET_OVERLAY_ASSERTIONS $($script:checks)"
    return $script:fail
}

try {
    if (-not $PlantDefect) {
        $failures = Invoke-Checks $BuildPath
        if ($failures) { Write-Host "RESULT: FAIL ($failures checks)"; exit 1 }
        Write-Host 'RESULT: PASS (quadlet-overlay root checkout fixtures; scratch roots, Git bash and a sudo shim only)'; exit 0
    }
    $baseline = Invoke-Checks $BuildPath
    if ($baseline) { Write-Host 'QUADLET_OVERLAY_BASELINE_FAILED'; exit 1 }
    $plants = @(
        @{ Name = 'the backup removed'; Expected = 'every moved path is in one timestamped private backup with owner:group, mode, size and sha256'
           From = 'sudo mv "$base/$p" "$backup/files/$p"'; To = 'sudo rm -f "$base/$p"' },
        @{ Name = 'the storage guard removed'; Expected = 'a container store with layers refuses the storage.conf switch with nothing moved'
           From = 'if [[ "$p" == usr/share/containers/storage.conf ]] && mios_store_has_content "$root"; then'; To = 'if false; then' },
        @{ Name = 'an unknown path forced'; Expected = 'a path git would overwrite that is not on the known list refuses with nothing moved'
           From = '(( known )) || unknown+=("$p")'; To = 'true' },
        @{ Name = 'non-zero overlay rc downgraded to a warning'; Expected = 'any non-zero overlay exit is fatal, never "partial overlay possible ... rerun safe"'
           From = 'throw "Quadlet overlay failed (rc=$overlayRc)"'; To = 'Log-Warn "Quadlet overlay rc=$overlayRc -- partial overlay possible (rerun safe)"' },
        @{ Name = 'the on-screen remedy dropped'; Expected = 'an unknown-path refusal tells the operator the paths and the remedy on screen'
           From = ' re-provision it (podman machine rm $DevDistro, then re-run the installer)."'; To = '"' },
        @{ Name = "the seed's wsl.conf rewrite making / dirty"; Expected = "the quadlet-overlay wsl.conf enforcement leaves mios.git's bytes unchanged (and still repairs a file that lacks them)"
           From = 'echo "[quadlet-overlay] /etc/wsl.conf: [boot] systemd=true already set"'; To = 'printf ''systemd=true\n'' | sudo tee -a /etc/wsl.conf >/dev/null' }
    )
    $caught = 0; $index = 0
    foreach ($plant in $plants) {
        $index++
        $text = [IO.File]::ReadAllText($BuildPath)
        $count = ([regex]::Matches($text, [regex]::Escape($plant.From))).Count
        if ($count -ne 1) { throw "Missing or ambiguous defect anchor: $($plant.Name) (found $count)" }
        $copy = Join-Path $scratch ('planted-' + $index + '-build-mios.ps1')
        [IO.File]::WriteAllText($copy, $text.Replace($plant.From, $plant.To), (New-Object Text.UTF8Encoding($true)))
        $null = Invoke-Checks $copy
        $detected = $script:failedChecks.Contains($plant.Expected)
        Write-Host ('  {0} planted defect caught: {1}' -f $(if ($detected) { 'PASS' } else { 'FAIL' }), $plant.Name)
        if ($detected) { $caught++ }
    }
    if ($caught -eq $plants.Count) { Write-Host "RESULT: PASS (every planted defect was caught: $caught/$($plants.Count))"; exit 0 }
    Write-Host "RESULT: FAIL (planted defects caught: $caught/$($plants.Count))"; exit 1
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
