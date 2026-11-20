# Quadlet overlay stages. The seed runs twice: checkout (mios.git at /, nothing reloaded, linked, rendered or started)
# right after the builder is found, and realize after mios-seed and the native catalog build (which installs the
# renderer), before anything restarts the guest. The source-order and source-contract checks read build-mios.ps1; the
# gate, the ERR trap, the unit stop/restart cycle and the dev-overlay preflight run as extracted blocks against
# scratch files, Git for Windows' bash (never WSL's) and a systemctl shim. No distro, wsl.exe or network is touched.
# Default runs the checks; -PlantDefect plants each guarded defect into a copy of the product and requires a red result.
[CmdletBinding()]
param([switch]$PlantDefect, [string]$BuildPath)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $BuildPath) { $BuildPath = Join-Path $repoRoot 'build-mios.ps1' }
$gitExe = (Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $gitExe) { $c = Join-Path $env:LOCALAPPDATA 'Programs\Git\cmd\git.exe'; if (Test-Path -LiteralPath $c) { $gitExe = $c } else { throw 'git is required' } }
$bash = Join-Path (Split-Path (Split-Path $gitExe -Parent) -Parent) 'bin\bash.exe'
if (-not (Test-Path -LiteralPath $bash)) { throw "Git for Windows bash not found at $bash (WSL's bash is never used)" }
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-overlay-stages-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -ErrorAction Stop | Out-Null
$lf = New-Object Text.UTF8Encoding($false)

$script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
function Check([bool]$Ok, [string]$What) {
    $script:checks++
    if ($Ok) { Write-Host "  PASS $What" } else { Write-Host "  FAIL $What"; $script:fail++; $script:failedChecks.Add($What) }
}
function Fwd([string]$Path) { return $Path -replace '\\', '/' }
function Write-Lf([string]$Path, [string]$Text) { New-Item -ItemType Directory -Force -Path (Split-Path $Path -Parent) | Out-Null; [IO.File]::WriteAllText($Path, $Text, $lf) }
function Get-Block([string]$Text, [string]$Start, [string]$End) {
    $i = $Text.IndexOf($Start); if ($i -lt 0) { return '' }
    $j = $Text.IndexOf($End, $i); if ($j -lt 0) { return '' }
    return $Text.Substring($i, $j + $End.Length - $i)
}
function Get-Count([string]$Text, [string]$Needle) { return ([regex]::Matches($Text, [regex]::Escape($Needle))).Count }
# Code lines only: comment lines would let a plant hide behind prose (and prose trip a check).
function Get-Code([string]$Text) { return ((($Text -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n") }
function Invoke-Bash([string]$Body, [string[]]$Arguments = @(), [hashtable]$Env = @{}) {
    $ErrorActionPreference = 'Continue'
    $f = Join-Path $scratch ('run-' + [guid]::NewGuid().ToString('N') + '.sh'); Write-Lf $f ("export PATH=`"/usr/bin:/mingw64/bin:`$PATH`"`n" + $Body + "`n")
    $saved = @{}; foreach ($k in $Env.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, [string]$Env[$k]) }
    try { $o = @(& $bash --noprofile --norc $f @Arguments 2>&1 | ForEach-Object { "$_" }); $rc = $LASTEXITCODE }
    finally { foreach ($k in $Env.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) } }
    if ($env:MIOS_TEST_VERBOSE) { Write-Host ($o -join "`n") }
    return [pscustomobject]@{ Rc = $rc; Text = ($o -join "`n") }
}

# systemctl shim for the unit cycle: listing and SourcePath come from fixture files; stop/start/daemon-reload are logged.
$shim = Join-Path $scratch 'shim'
Write-Lf (Join-Path $shim 'systemctl') @'
#!/bin/bash
case "$1" in
    list-units) [[ -n "${FIXTURE_FAIL_LIST:-}" ]] && exit 1; cat "$FIXTURE_UNITS" ;;
    show) u="${@: -1}"; while read -r name src; do [[ "$name" == "$u" ]] && echo "$src"; done < "$FIXTURE_SOURCES"; exit 0 ;;
    stop) echo "stop $2" >> "$FIXTURE_LOG" ;;
    start) echo "start ${@: -1}" >> "$FIXTURE_LOG" ;;
    daemon-reload) echo "daemon-reload" >> "$FIXTURE_LOG" ;;
    *) echo "unexpected systemctl $*" >> "$FIXTURE_LOG"; exit 9 ;;
esac
'@

function Invoke-Checks([string]$Build) {
    $script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
    $text = ([IO.File]::ReadAllText($Build)) -replace "`r`n", "`n"
    $tk = $null; $er = $null; $psAst = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tk, [ref]$er)
    $fnText = { param($name) $f = @($psAst.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }.GetNewClosure(), $true)); if ($f.Count -eq 1) { $f[0].Extent.Text -replace "`r`n", "`n" } else { '' } }

    # --- Main flow: checkout < mios-seed < native catalog < realize < first guest shutdown ----------------------------
    $iCheckout = $text.IndexOf('Invoke-MiosQuadletOverlay -Stage checkout')
    $iOverlayPkgs = $text.IndexOf('Layering $($_allOverlayPkgs.Count) packages from [packages.dev_overlay].sections')
    $iSeed = $text.IndexOf('bash $seedTmpWsl')
    $catalogCall = '    $null = Install-MiosNativeCatalog -Root $MiosRepoDir -Machine $DevDistro'
    $iCatalog = if ($iSeed -ge 0) { $text.IndexOf("`n" + $catalogCall + "`n", $iSeed) } else { -1 }
    $iRealize = $text.IndexOf('Invoke-MiosQuadletOverlay -Stage realize')
    $iShutdown = if ($iCheckout -ge 0) { $text.IndexOf('& wsl.exe --shutdown', $iCheckout) } else { -1 }
    $between = if ($iCheckout -ge 0 -and $iRealize -gt $iCheckout) { Get-Code $text.Substring($iCheckout, $iRealize - $iCheckout) } else { '' }
    $restartRx = 'wsl(\.exe)?\s+--(shutdown|terminate)|Set-MiosWslConfig|Start-MiosDevMachine|Restart-PodmanPrefix|Rename-PodmanDevDistro|machine\s+(stop|start|rm)\b'
    Check ((Get-Count $text 'Invoke-MiosQuadletOverlay -Stage checkout') -eq 1 -and (Get-Count $text 'Invoke-MiosQuadletOverlay -Stage realize') -eq 1 -and
           @([regex]::Matches((Get-Code $text), '(?m)^\s*Invoke-MiosQuadletOverlay\b')).Count -eq 2 -and $iCheckout -ge 0 -and $iCheckout -lt $iOverlayPkgs -and $iOverlayPkgs -lt $iSeed -and
           $iSeed -lt $iCatalog -and $iCatalog -lt $iRealize -and $iRealize -lt $iShutdown -and $between -and $between -notmatch $restartRx) 'checkout, then the dev overlay and mios-seed, then the native catalog, then realize, all before the first guest shutdown and with no guest restart between checkout and realize'

    # --- The catalog runs once per process ------------------------------------------------------------------------------
    $afterCatalog = if ($iCatalog -ge 0) { ($text.Substring($iCatalog + $catalogCall.Length + 2) -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1).Trim() } else { '' }
    $launcher = & $fnText 'Install-MiosLauncher'
    Check ($afterCatalog -eq '$script:MiosNativeCatalogInstalled = $true' -and (Get-Count $text '$script:MiosNativeCatalogInstalled = $true') -eq 1 -and
           (Get-Count $launcher 'Install-MiosNativeCatalog') -eq 1 -and
           $launcher.Contains('if (-not $script:MiosNativeCatalogInstalled) { $null = Install-MiosNativeCatalog -Root $MiosRepoDir -Machine $DevDistro }')) 'the catalog flag is set only after a successful Phase 3 build, and the launcher builds only without it'

    # --- Preflight: dev_overlay_full=false refuses before the machine is touched ---------------------------------------
    $iPre = $text.IndexOf('if (Test-MiosDevOverlayFullDisabled $devVmTomlCands) {')
    $preBlock = if ($iPre -ge 0) { $text.Substring($iPre, [Math]::Min(500, $text.Length - $iPre)) } else { '' }
    $iEnsure = $text.IndexOf('Ensure-MiosBuilder -Machine $BuilderDistro')
    $iWslCfg = $text.IndexOf('try { Set-MiosWslConfig -RamGB $HW.RamGB -Cpus $HW.Cpus -Force } catch { Log-Warn "Set-MiosWslConfig (pre-Phase-3)')
    $preOk = $iPre -ge 0 -and $iPre -lt $iWslCfg -and $iPre -lt $iEnsure -and $iPre -lt $iCheckout -and $preBlock -match '(?s)^[^}]*\bthrow "[^"]*Rust toolchain'
    $fnDef = & $fnText 'Test-MiosDevOverlayFullDisabled'
    $behaviourOk = $false
    if ($fnDef) {
        $tomlOff = Join-Path $scratch 'off.toml'; $tomlOn = Join-Path $scratch 'on.toml'; $tomlNone = Join-Path $scratch 'none.toml'
        Write-Lf $tomlOff "[identity]`nusername = `"user`"`n[bootstrap]`ndev_distro = `"MiOS-DEV`"`ndev_overlay_full = false`n"
        Write-Lf $tomlOn "[bootstrap]`ndev_overlay_full = true`n"; Write-Lf $tomlNone "[bootstrap]`ndev_distro = `"MiOS-DEV`"`n"
        $probe = [scriptblock]::Create("param(`$c)`n" + $fnDef + "`nTest-MiosDevOverlayFullDisabled `$c")
        $missing = Join-Path $scratch 'missing.toml'
        $behaviourOk = ((& $probe @($missing, $tomlOff)) -eq $true) -and ((& $probe @($tomlOn, $tomlOff)) -eq $false) -and
                       ((& $probe @($tomlNone)) -eq $false) -and ((& $probe @($missing)) -eq $false)
    }
    Check ($preOk -and $behaviourOk) 'dev_overlay_full=false (first existing mios.toml wins) refuses before the builder is touched, naming the Rust toolchain'

    # --- Seed blocks ----------------------------------------------------------------------------------------------------
    $gate = Get-Block $text '# >>> overlay-stage-gate' '# <<< overlay-stage-gate'
    $c1 = Get-Block $text '# >>> overlay-stage-checkout' '# <<< overlay-stage-checkout'
    $rz = Get-Block $text '# >>> overlay-stage-realize' '# <<< overlay-stage-realize'
    $cycle = Get-Block $rz '# >>> quadlet-unit-cycle' '# <<< quadlet-unit-cycle'
    $c1Code = Get-Code $c1; $rzCode = Get-Code $rz

    # Stage 1 reloads, links, renders, starts and seals nothing; a modified root skips only the checkout itself.
    $c1Lines = @(($c1Code -split "`n") | Where-Object { $_.Trim() })
    $c1Tail = if ($c1Lines.Count -ge 3) { ($c1Lines[($c1Lines.Count - 3)..($c1Lines.Count - 1)] | ForEach-Object { $_.Trim() }) -join '|' } else { '' }
    Check ($c1 -and $c1Code.Contains('mios_root_checkout / FETCH_HEAD || exit $?') -and $c1Code.Contains('sudo touch "$STAGE1_MARKER"') -and
           $c1Code -notmatch 'systemctl|\.wants|render-quadlets|SENTINEL|chpasswd|enable-linger' -and $c1Tail -match '^echo [^|]*\|exit 0\|fi$' -and
           (Get-Count $c1Code 'exit 0') -eq 1) 'the checkout stage reloads, links, renders, starts and seals nothing, and ends by writing its marker'
    Check ($c1Code -match 'preserving modified root overlay; full image build remains required"\n\s*ROOT_PRESERVED=1\n' -and
           $c1Code -match '(?s)if \(\( ! ROOT_PRESERVED \)\); then\n.*mios_root_checkout / FETCH_HEAD \|\| exit \$\?\nfi\n') 'a modified root skips only the checkout; the rest of the checkout stage still runs'

    # The sentinel is the only gate, for both stages (behaviour).
    $gateOk = $false
    if ($gate) {
        $srcDir = Join-Path $scratch ('src-' + [guid]::NewGuid().ToString('N').Substring(0, 8)); Write-Lf (Join-Path $srcDir 'Containerfile') "FROM scratch`n"
        $sent = Join-Path $scratch 'sentinel'; $mark = Join-Path $scratch 'stage1-marker'
        $gateRun = "set -uo pipefail`n" + $gate.Replace('/var/lib/mios/.quadlet-overlay-seeded', (Fwd $sent)).Replace('/run/mios/quadlet-stage1', (Fwd $mark)) + "`necho PROCEEDED`n"
        Write-Lf $mark "marker`n"; Remove-Item -LiteralPath $sent -Force -ErrorAction SilentlyContinue
        $a = Invoke-Bash $gateRun @((Fwd $srcDir)) @{ MIOS_OVERLAY_STAGE = 'realize' }
        Write-Lf $sent "old`n"; (Get-Item -LiteralPath $sent).LastWriteTime = (Get-Date).AddDays(-2)
        $b = Invoke-Bash $gateRun @((Fwd $srcDir)) @{ MIOS_OVERLAY_STAGE = 'realize' }
        $c = Invoke-Bash $gateRun @((Fwd $srcDir)) @{ MIOS_OVERLAY_STAGE = 'checkout' }
        (Get-Item -LiteralPath $sent).LastWriteTime = (Get-Date).AddDays(2)
        $d = Invoke-Bash $gateRun @((Fwd $srcDir)) @{ MIOS_OVERLAY_STAGE = 'realize' }
        $e = Invoke-Bash $gateRun @((Fwd $srcDir)) @{ MIOS_OVERLAY_STAGE = 'checkout' }
        $f = Invoke-Bash $gateRun @((Fwd $srcDir)) @{ MIOS_OVERLAY_STAGE = 'bogus' }
        $gateOk = $a.Rc -eq 0 -and $a.Text -match 'PROCEEDED' -and $b.Text -match 'PROCEEDED' -and $c.Text -match 'PROCEEDED' -and
                  $d.Rc -eq 0 -and $d.Text -notmatch 'PROCEEDED' -and $e.Rc -eq 0 -and $e.Text -notmatch 'PROCEEDED' -and $f.Rc -eq 2 -and $f.Text -notmatch 'PROCEEDED'
    }
    $markerUse = @(($rzCode -split "`n") | Where-Object { $_ -match 'STAGE1_MARKER' })
    Check ($gateOk -and $rz -and $rzCode -notmatch '\bexit 0\b' -and $markerUse.Count -eq 2 -and $markerUse[0].Trim() -eq 'if [[ -e "$STAGE1_MARKER" ]]; then') 'realize runs after checkout in the same boot and is skipped only by a fresh sentinel; the stage-1 marker only warns'

    # Realize: set -eE + ERR trap first; renderer check, stop, render, reload, restart, then enable/link/start.
    $rzLines = @(($rzCode -split "`n") | Where-Object { $_.Trim() })
    $prologueOk = $rzLines.Count -ge 2 -and $rzLines[0].Trim() -eq 'set -eE' -and $rzLines[1] -match "^trap '.*exit 7; fi' ERR$"
    $pReadlink = $rzCode.IndexOf('RENDERER_TARGET=$(readlink -f "$RENDERER" 2>/dev/null)')
    $pStop = $rzCode.IndexOf("`nmios_stop_unrendered system required`n")
    $pUsers = $rzCode.IndexOf("`n    mios_stop_unrendered `"`$_uid`" optional`n")
    $pRender = $rzCode.IndexOf("`nsudo /automation/34-render-quadlets.sh 2>&1 | sed 's/^/[quadlet-overlay]   /' || \`n    { echo `"[quadlet-overlay] ERROR: 34-render-quadlets.sh failed; no unit was started`"; exit 3; }`n")
    $pReload = $rzCode.IndexOf("`n`$NS systemctl daemon-reload 2>&1 | tail -3`n")
    $pRestart = $rzCode.IndexOf("`nmios_restart_stopped`n")
    $cycleCode = Get-Code $cycle
    $beforeRender = if ($pRender -gt 0) { (Get-Code $rz.Substring(0, $rz.IndexOf('sudo /automation/34-render-quadlets.sh'))).Replace($cycleCode, '') } else { 'missing' }
    $afterRestart = if ($pRestart -gt 0) { $rzCode.Substring($pRestart) } else { '' }
    $firstAct = [regex]::Match($rzCode, 'systemctl enable|\.wants|start --no-block "\$svc"|systemctl preset|systemctl mask')
    $refuseOk = $rzCode -match 'if \[\[ "\$RENDERER_TARGET" != /usr/bin/mios-render-quadlets \|\| ! -x "\$RENDERER_TARGET" \]\]; then\n[^\n]*\n\s*exit 3\n'
    Check ($prologueOk -and $refuseOk -and $pReadlink -gt 0 -and $pReadlink -lt $pStop -and $pStop -lt $pUsers -and $pUsers -lt $pRender -and
           $pRender -lt $pReload -and $pReload -lt $pRestart -and $firstAct.Success -and $firstAct.Index -gt $pRestart -and
           $beforeRender -notmatch 'systemctl (enable|start|restart|preset)|\.wants|--no-block|daemon-reload' -and $afterRestart) 'realize checks the native renderer, stops running Quadlet units, renders (fatal), reloads and restarts them before it enables, links or starts anything'

    # The sentinel is written once, last.
    $touch = 'sudo touch "$SENTINEL"'
    $tail = if ($rzCode.IndexOf($touch) -ge 0) { @(($rzCode.Substring($rzCode.IndexOf($touch) + $touch.Length) -split "`n") | Where-Object { $_.Trim() }) } else { @('missing') }
    $seedCode = Get-Code (Get-Block $text '# >>> overlay-stage-gate' '# <<< overlay-stage-realize')
    Check ((Get-Count $seedCode $touch) -eq 1 -and $rzCode.Contains($touch) -and @($tail | Where-Object { $_ -notmatch '^\s*echo ' }).Count -eq 0 -and
           $rzCode.IndexOf($touch) -gt $rzCode.IndexOf('for _hostile in audit-rules.service')) 'the sentinel is written once, by realize, after every other step'

    # The ERR trap stops realize at the failed step (pipelines included) before the sentinel; $(...) noise does not.
    $trapOk = $false
    if ($prologueOk) {
        $prologue = "set -uo pipefail`n" + $rzLines[0] + "`n" + $rzLines[1] + "`n"
        $s1 = Join-Path $scratch 'trap-sentinel-1'; $s2 = Join-Path $scratch 'trap-sentinel-2'; $s3 = Join-Path $scratch 'trap-sentinel-3'
        $t1 = Invoke-Bash ($prologue + "late_step() { return 5; }`necho before`nlate_step`ntouch `"`$1`"`necho after`n") @((Fwd $s1))
        $t2 = Invoke-Bash ($prologue + "false | cat`ntouch `"`$1`"`n") @((Fwd $s2))
        $t3 = Invoke-Bash ($prologue + "echo `"listing `$(false)`"`nfalse | cat >/dev/null || echo tolerated`ntouch `"`$1`"`n") @((Fwd $s3))
        # The line is the call site (line 7 of the run file); bash reports the function's last command (return 5).
        $trapOk = $t1.Rc -eq 7 -and $t1.Text -match 'ERROR: realize stopped at line 7 \(exit 5\): return 5;' -and $t1.Text -notmatch 'after' -and -not (Test-Path -LiteralPath $s1) -and
                  $t2.Rc -eq 7 -and -not (Test-Path -LiteralPath $s2) -and
                  $t3.Rc -eq 0 -and $t3.Text -notmatch 'ERROR' -and $t3.Text -match 'tolerated' -and (Test-Path -LiteralPath $s3)
    }
    Check $trapOk 'a failed realize step (a pipeline too) stops the stage with rc 7 and its line and command, before the sentinel'

    # Unit cycle (behaviour): Quadlet-generated units and mios-ai-firstboot are stopped before the render and started after.
    $cycleOk = $false
    if ($cycle) {
        $units = Join-Path $scratch 'units'; $sources = Join-Path $scratch 'sources'; $log = Join-Path $scratch 'cycle.log'
        Write-Lf $units ("mios-forge.service loaded active running Forge`nchronyd.service loaded active running NTP`n" +
                         "mios-ai-firstboot.service loaded activating start First boot`nmios-searxng.service loaded failed failed SearXNG`n")
        Write-Lf $sources ("mios-forge.service /usr/share/containers/systemd/mios-forge.container`nchronyd.service`nmios-ai-firstboot.service /usr/lib/systemd/system/mios-ai-firstboot.service`n" +
                           "mios-searxng.service /etc/containers/systemd/mios-searxng.container`n")
        $envs = @{ FIXTURE_UNITS = (Fwd $units); FIXTURE_SOURCES = (Fwd $sources); FIXTURE_LOG = (Fwd $log) }
        $head = "set -uo pipefail`nexport PATH=`"`$(cygpath -u '$(Fwd $shim)'):`$PATH`"`n[[ `"`$(command -v systemctl)`" == */shim/systemctl ]] || echo 'systemctl shim not first on PATH'`nNS=`"`"`n" + $cycle + "`n"
        Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue
        $r = Invoke-Bash ($head + "mios_stop_unrendered system required`necho RENDER >> `"`$FIXTURE_LOG`"`nmios_restart_stopped`necho `"RC=`$?`"`n") @() $envs
        $got = if (Test-Path -LiteralPath $log) { @(Get-Content -LiteralPath $log) -join '|' } else { '' }
        $want = 'stop mios-forge.service|stop mios-ai-firstboot.service|stop mios-searxng.service|RENDER|start mios-forge.service|start mios-ai-firstboot.service|start mios-searxng.service'
        $envs.FIXTURE_FAIL_LIST = '1'
        $req = Invoke-Bash ($head + "mios_stop_unrendered system required`necho `"RC=`$?`"`n") @() $envs
        $opt = Invoke-Bash ($head + "mios_stop_unrendered 1000 optional`necho `"RC=`$?`"`n") @() $envs
        $cycleOk = $r.Text -match 'RC=0' -and $got -eq $want -and $req.Text -match 'RC=1' -and $req.Text -match 'ERROR: cannot list' -and $opt.Text -match 'RC=0' -and $opt.Text -match 'WARN: cannot list'
        if (-not $cycleOk -and $env:MIOS_TEST_VERBOSE) { Write-Host "cycle log: $got"; Write-Host $r.Text; Write-Host $req.Text; Write-Host $opt.Text }
    }
    Check $cycleOk 'units generated from Quadlet sources (and mios-ai-firstboot) are stopped before the render and started after it; other units are left alone'

    # The PowerShell side: the stage is exported, the realize copy alone carries the credential, and no copy is kept.
    $fn = & $fnText 'Invoke-MiosQuadletOverlay'
    $iIf = $fn.IndexOf("if (`$Stage -eq 'realize') {"); $iResolve = $fn.IndexOf('Resolve-MiosLoginCredential')
    Check ($fn.Contains("param([Parameter(Mandatory = `$true)][ValidateSet('checkout', 'realize')][string]`$Stage)") -and $fn.Contains("MIOS_OVERLAY_STAGE='`$Stage'") -and
           (Get-Count $fn 'Resolve-MiosLoginCredential') -eq 1 -and $iIf -ge 0 -and $iIf -lt $iResolve -and
           $fn -match '(?s)\} finally \{\n[^}]*Remove-Item -LiteralPath \$stagedPath -Force') 'each stage is passed to the seed, only realize resolves the credential, and the staged copy is removed after every run'

    # The function itself, run for each stage against a wsl.exe mock. Only the 8 s probe line is replaced: it would start
    # a real wsl.exe. Source checks alone missed run 8's failure (a local $stage is the ValidateSet-bound $Stage).
    $probeLine = 'if (_ProbeWslAlive -Distro $candidate -TimeoutMs 8000) {'
    $fnNode = @($psAst.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-MiosQuadletOverlay' }, $true))
    $stageAssign = if ($fnNode.Count -eq 1) { @($fnNode[0].Body.FindAll({ param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left -is [Management.Automation.Language.VariableExpressionAst] -and $n.Left.VariablePath.UserPath -ieq 'Stage' }, $true)) } else { @('no function') }
    $runOk = $false
    if ($fn -and (Get-Count $fn $probeLine) -eq 1) {
        $fnRun = $fn.Replace($probeLine, 'if ($true) {')
        $harness = [scriptblock]::Create(@'
param($FnSrc, $RepoDir, $ShadowDir, $Stage, $Rc)
$ErrorActionPreference = 'Stop'
$calls = New-Object System.Collections.Generic.List[object]; $logs = New-Object System.Collections.Generic.List[string]
function Write-Log { param($M) $logs.Add([string]$M) }
function Set-Step { param($T) }
function Log-Ok { param($T) $logs.Add("OK $T") }
function Log-Warn { param($T) $logs.Add("WARN $T") }
function Log-Fail { param($T) $logs.Add("FAIL $T") }
function Get-MiosTomlValue { param($Section, $Key, $Default) $Default }
function Get-MiosSsotPort { param($Key) 8888 }
function Resolve-MiosLoginCredential { @{ Plain = 'fixture-credential'; Hash = '' } }
function wsl.exe {
    $cmd = [string]$args[-1]
    $m = [regex]::Match($cmd, "bash '/mnt/([a-z])(/[^']+)'")
    $win = if ($m.Success) { $m.Groups[1].Value.ToUpper() + ':' + ($m.Groups[2].Value -replace '/', '\') } else { '' }
    $text = if ($win -and (Test-Path -LiteralPath $win)) { [IO.File]::ReadAllText($win) } else { '' }
    $calls.Add([pscustomobject]@{ Command = $cmd; Staged = [bool]$text; Credential = $text.Contains("_mios_pw='fixture-credential'") })
    'seed line'
    $global:LASTEXITCODE = $Rc
}
. ([scriptblock]::Create($FnSrc))
$DevDistro = 'MiOS-DEV'; $MiosRepoDir = $RepoDir; $MiosBootstrapShadow = $ShadowDir
$err = ''
try { Invoke-MiosQuadletOverlay -Stage $Stage } catch { $err = $_.Exception.Message }
[pscustomobject]@{ Error = $err; Calls = $calls.ToArray(); Logs = ($logs -join "`n"); Left = (Test-Path -LiteralPath (Join-Path $ShadowDir '.tmp\quadlet-overlay-seed.sh')) }
'@)
        $runRoot = Join-Path $scratch ('fnrun-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $repoDir = Join-Path $runRoot 'repo'; Write-Lf (Join-Path $repoDir 'Containerfile') "FROM scratch`n"
        $shadowDir = Join-Path $runRoot 'shadow'; New-Item -ItemType Directory -Force -Path $shadowDir | Out-Null
        $savedSkip = $env:MIOS_SKIP_DEV_QUADLETS; $env:MIOS_SKIP_DEV_QUADLETS = $null
        try {
            $run = { param($s, $rc) & $harness -FnSrc $fnRun -RepoDir $repoDir -ShadowDir $shadowDir -Stage $s -Rc $rc }
            $co = & $run 'checkout' 0; $rz = & $run 'realize' 0; $r7 = & $run 'realize' 7; $r3 = & $run 'realize' 3; $c4 = & $run 'checkout' 4; $bad = & $run 'bogus' 0
        } finally { $env:MIOS_SKIP_DEV_QUADLETS = $savedSkip }
        $one = { param($r, $stage) $r.Calls.Count -eq 1 -and $r.Calls[0].Staged -and $r.Calls[0].Command.Contains("MIOS_OVERLAY_STAGE='$stage'") -and $r.Calls[0].Command.Contains("MIOS_BUILDER_DISTRO='MiOS-DEV'") -and -not $r.Left }
        $runOk = $co.Error -eq '' -and (& $one $co 'checkout') -and -not $co.Calls[0].Credential -and $co.Logs.Contains('OK mios.git checked out at / in MiOS-DEV') -and
                 $rz.Error -eq '' -and (& $one $rz 'realize') -and $rz.Calls[0].Credential -and $rz.Logs.Contains('OK MiOS Quadlet overlay applied to MiOS-DEV') -and
                 $r7.Error -eq 'Quadlet overlay failed (rc=7)' -and (& $one $r7 'realize') -and $r7.Logs.Contains('FAIL Quadlet overlay realize failed (rc=7)') -and $r7.Logs -notmatch 're-provision' -and
                 $r3.Error -eq 'Quadlet overlay failed: 34-render-quadlets.sh' -and (& $one $r3 'realize') -and
                 $c4.Error -eq 'Quadlet overlay failed (rc=4)' -and (& $one $c4 'checkout') -and $c4.Logs -match 'FAIL Quadlet overlay failed \(rc=4\): .*re-provision it' -and
                 $bad.Error -and $bad.Calls.Count -eq 0
        if (-not $runOk -and $env:MIOS_TEST_VERBOSE) { foreach ($x in @($co, $rz, $r7, $r3, $c4, $bad)) { Write-Host ("error=[{0}] calls={1} left={2}`n{3}" -f $x.Error, $x.Calls.Count, $x.Left, $x.Logs) } }
    }
    Check ($runOk -and $stageAssign.Count -eq 0) 'Invoke-MiosQuadletOverlay runs both stages against a wsl.exe mock: the stage reaches the seed, only realize stages the credential, no staged copy survives, rc 3/4/7 fail with their own messages'

    Write-Host "OVERLAY_STAGES_ASSERTIONS $($script:checks)"
    return $script:fail
}

try {
    if (-not $PlantDefect) {
        $failures = Invoke-Checks $BuildPath
        if ($failures) { Write-Host "RESULT: FAIL ($failures checks)"; exit 1 }
        Write-Host 'RESULT: PASS (quadlet overlay stages; source order, scratch files, Git bash and a systemctl shim only)'; exit 0
    }
    $baseline = Invoke-Checks $BuildPath
    if ($baseline) { Write-Host 'OVERLAY_STAGES_BASELINE_FAILED'; exit 1 }
    $catalogBlock = "    `$null = Install-MiosNativeCatalog -Root `$MiosRepoDir -Machine `$DevDistro`n    `$script:MiosNativeCatalogInstalled = `$true`n    Log-Ok `"MiOS native catalog installed in `$_wslDistroForTerm`"`n    Invoke-MiosQuadletOverlay -Stage realize`n"
    $plants = @(
        @{ Name = '1 render before the native build'; Expected = 'checkout, then the dev overlay and mios-seed, then the native catalog, then realize, all before the first guest shutdown and with no guest restart between checkout and realize'
           Edits = @(, @($catalogBlock, "    Invoke-MiosQuadletOverlay -Stage realize`n    `$null = Install-MiosNativeCatalog -Root `$MiosRepoDir -Machine `$DevDistro`n    `$script:MiosNativeCatalogInstalled = `$true`n    Log-Ok `"MiOS native catalog installed in `$_wslDistroForTerm`"`n")) },
        @{ Name = '2 render failure downgraded'; Expected = 'realize checks the native renderer, stops running Quadlet units, renders (fatal), reloads and restarts them before it enables, links or starts anything'
           Edits = @(, @('{ echo "[quadlet-overlay] ERROR: 34-render-quadlets.sh failed; no unit was started"; exit 3; }', '{ echo "[quadlet-overlay] WARN: 34-render-quadlets.sh failed"; }')) },
        @{ Name = '3 a unit started before the render'; Expected = 'realize checks the native renderer, stops running Quadlet units, renders (fatal), reloads and restarts them before it enables, links or starts anything'
           Edits = @(, @("`nmios_stop_unrendered system required`n", "`n`$NS systemctl enable --now mios-forge.service`nmios_stop_unrendered system required`n")) },
        @{ Name = '3b a .wants link made by the checkout stage'; Expected = 'the checkout stage reloads, links, renders, starts and seals nothing, and ends by writing its marker'
           Edits = @(, @("mios_sync_env`n`nmios_resolve_ns`necho `"[quadlet-overlay] realizing sysusers / tmpfiles (the realize stage", "sudo ln -sf ../mios-ai-firstboot.service /usr/lib/systemd/system/multi-user.target.wants/mios-ai-firstboot.service`nmios_sync_env`n`nmios_resolve_ns`necho `"[quadlet-overlay] realizing sysusers / tmpfiles (the realize stage")) },
        @{ Name = '4 the sentinel written by the checkout stage'; Expected = 'the checkout stage reloads, links, renders, starts and seals nothing, and ends by writing its marker'
           Edits = @(, @('sudo mkdir -p "$(dirname "$STAGE1_MARKER")" && sudo touch "$STAGE1_MARKER"', 'sudo mkdir -p "$(dirname "$STAGE1_MARKER")" && sudo touch "$STAGE1_MARKER" && sudo touch "$SENTINEL"')) },
        @{ Name = '5 realize skipped on a rerun after checkout'; Expected = 'realize runs after checkout in the same boot and is skipped only by a fresh sentinel; the stage-1 marker only warns'
           Edits = @(, @('if [[ -f "$SENTINEL" && "$SENTINEL" -nt "$SRC/Containerfile" ]]; then', 'if [[ -f "$SENTINEL" && "$SENTINEL" -nt "$SRC/Containerfile" ]] || [[ "$OVERLAY_STAGE" == realize && -e "$STAGE1_MARKER" ]]; then')) },
        @{ Name = '5b realize returns early once the checkout ran'; Expected = 'realize runs after checkout in the same boot and is skipped only by a fresh sentinel; the stage-1 marker only warns'
           Edits = @(, @('    echo "[quadlet-overlay] realize: the checkout stage ran in this guest boot"', '    echo "[quadlet-overlay] realize: the checkout stage ran in this guest boot"; exit 0')) },
        @{ Name = '6 a guest shutdown before the catalog'; Expected = 'checkout, then the dev overlay and mios-seed, then the native catalog, then realize, all before the first guest shutdown and with no guest restart between checkout and realize'
           Edits = @(, @($catalogBlock, "    & wsl.exe --shutdown 2>`$null | Out-Null`n" + $catalogBlock)) },
        @{ Name = '7 the stop loop removed'; Expected = 'realize checks the native renderer, stops running Quadlet units, renders (fatal), reloads and restarts them before it enables, links or starts anything'
           Edits = @(, @("`nmios_stop_unrendered system required`n", "`n")) },
        @{ Name = '7b the stop keeps a unit running'; Expected = 'units generated from Quadlet sources (and mios-ai-firstboot) are stopped before the render and started after it; other units are left alone'
           Edits = @(, @('/usr/share/containers/systemd/*|/etc/containers/systemd/*) echo "$u $src" ;;', '/etc/containers/systemd/*) echo "$u $src" ;;')) },
        @{ Name = '8 the sentinel moved before the masks'; Expected = 'the sentinel is written once, by realize, after every other step'
           Edits = @(@("sudo install -d -m 0755 /var/lib/mios`nsudo touch `"`$SENTINEL`"`necho `"[quadlet-overlay] sealed", "echo `"[quadlet-overlay] sealed"),
                     @('for _hostile in audit-rules.service', "sudo touch `"`$SENTINEL`"`nfor _hostile in audit-rules.service")) },
        @{ Name = '8b set -e removed from realize'; Expected = 'a failed realize step (a pipeline too) stops the stage with rc 7 and its line and command, before the sentinel'
           Edits = @(, @("# failed line and command, and the sentinel, written last, is never reached.`nset -eE`n", "# failed line and command, and the sentinel, written last, is never reached.`nset -E`n")) },
        @{ Name = '9 the dev-overlay preflight removed'; Expected = 'dev_overlay_full=false (first existing mios.toml wins) refuses before the builder is touched, naming the Rust toolchain'
           Edits = @(, @('if (Test-MiosDevOverlayFullDisabled $devVmTomlCands) {', 'if ($false) {')) },
        @{ Name = '10 the launcher builds the catalog again'; Expected = 'the catalog flag is set only after a successful Phase 3 build, and the launcher builds only without it'
           Edits = @(, @('if (-not $script:MiosNativeCatalogInstalled) { $null = Install-MiosNativeCatalog -Root $MiosRepoDir -Machine $DevDistro }', '$null = Install-MiosNativeCatalog -Root $MiosRepoDir -Machine $DevDistro')) },
        @{ Name = '11 the staged credential copy kept'; Expected = 'each stage is passed to the seed, only realize resolves the credential, and the staged copy is removed after every run'
           Edits = @(, @('Remove-Item -LiteralPath $stagedPath -Force -ErrorAction SilentlyContinue', '$null = $stagedPath')) },
        @{ Name = '12 a modified root ends the checkout stage'; Expected = 'a modified root skips only the checkout; the rest of the checkout stage still runs'
           Edits = @(, @("        ROOT_PRESERVED=1`n", "        exit 0`n")) },
        @{ Name = '13 the seed command held in $stage (run 8)'; Expected = 'Invoke-MiosQuadletOverlay runs both stages against a wsl.exe mock: the stage reaches the seed, only realize stages the credential, no staged copy survives, rc 3/4/7 fail with their own messages'
           Edits = @(@('    $seedCommand = "set -e; export MIOS_DEV_ENABLE_AI=', '    $stage = "set -e; export MIOS_DEV_ENABLE_AI='), @('--exec bash -c $seedCommand 2>&1', '--exec bash -c $stage 2>&1')) }
    )
    $caught = 0; $index = 0
    foreach ($plant in $plants) {
        $index++
        $text = ([IO.File]::ReadAllText($BuildPath)) -replace "`r`n", "`n"
        foreach ($edit in $plant.Edits) {
            $count = ([regex]::Matches($text, [regex]::Escape($edit[0]))).Count
            if ($count -ne 1) { throw "Missing or ambiguous defect anchor: $($plant.Name) (found $count)" }
            $text = $text.Replace($edit[0], $edit[1])
        }
        $copy = Join-Path $scratch ('planted-' + $index + '-build-mios.ps1')
        [IO.File]::WriteAllText($copy, $text, (New-Object Text.UTF8Encoding($true)))
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
