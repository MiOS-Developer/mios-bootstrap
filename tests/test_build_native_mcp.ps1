# Native MiOS-MCP step (C8). Before the launcher's client setup, build-mios.ps1 runs MiOS's own offline payload installer
# (mios-mcp-server --install-native, the call MiOS's Containerfile makes) in the builder as root on every install, then
# re-probes as the uid-1000 user exactly what mios-native-client-setup.ps1 probes. The source-order checks read
# build-mios.ps1; the behaviour checks run Install-MiosNativeMcp itself against a wsl.exe mock. No distro or wsl.exe is
# touched. Default runs the checks; -PlantDefect plants each guarded defect into a copy and requires a red result.
[CmdletBinding()]
param([switch]$PlantDefect, [string]$BuildPath)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $BuildPath) { $BuildPath = Join-Path $repoRoot 'build-mios.ps1' }

$script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
function Check([bool]$Ok, [string]$What) {
    $script:checks++
    if ($Ok) { Write-Host "  PASS $What" } else { Write-Host "  FAIL $What"; $script:fail++; $script:failedChecks.Add($What) }
}
function Get-Count([string]$Text, [string]$Needle) { return ([regex]::Matches($Text, [regex]::Escape($Needle))).Count }
function Get-Code([string]$Text) { return ((($Text -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n") }

$harness = [scriptblock]::Create(@'
param($FnSrc, $InstallRc, $ProbeOk, $Uid1000)
$ErrorActionPreference = 'Stop'
$calls = New-Object System.Collections.Generic.List[string]; $logs = New-Object System.Collections.Generic.List[string]
function Write-Log { param($M) $logs.Add([string]$M) }
function Log-Ok { param($T) $logs.Add("OK $T") }
function Log-Warn { param($T) $logs.Add("WARN $T") }
function Resolve-MiosBuilderDistribution { param($Machine) "podman-$Machine" }
function wsl.exe {
    $line = ($args | ForEach-Object { [string]$_ }) -join ' '
    $calls.Add($line)
    if ($line -match '--install-native') { 'mios-mcp-server: installed'; $global:LASTEXITCODE = $InstallRc; return }
    if ($line -match 'getpwuid\(1000\)') { $Uid1000; $global:LASTEXITCODE = 0; return }
    if ($line -match "load_merged\(\)\['mcp'\]\['python'\]") { '/usr/lib/mios/mcp/.venv/bin/python3'; $global:LASTEXITCODE = 0; return }
    if ($line -match 'native-ready') { if ($ProbeOk) { 'native-ready'; $global:LASTEXITCODE = 0 } else { 'AssertionError'; $global:LASTEXITCODE = 1 }; return }
    'unexpected'; $global:LASTEXITCODE = 99
}
. ([scriptblock]::Create($FnSrc))
$err = ''
try { Install-MiosNativeMcp -Machine 'MiOS-DEV' } catch { $err = $_.Exception.Message }
[pscustomobject]@{ Error = $err; Calls = $calls.ToArray(); Logs = ($logs -join "`n") }
'@)

function Invoke-Checks([string]$Build) {
    $script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
    $text = ([IO.File]::ReadAllText($Build)) -replace "`r`n", "`n"
    $tk = $null; $er = $null; $ast = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tk, [ref]$er)
    $fnText = { param($name) $f = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }.GetNewClosure(), $true)); if ($f.Count -eq 1) { $f[0].Extent.Text -replace "`r`n", "`n" } else { '' } }

    # --- Placement: every run, right after the catalog line and right before the client setup ---------------------
    $launcher = Get-Code (& $fnText 'Install-MiosLauncher')
    $lines = @(($launcher -split "`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $iCatalog = [array]::IndexOf($lines, 'if (-not $script:MiosNativeCatalogInstalled) { $null = Install-MiosNativeCatalog -Root $MiosRepoDir -Machine $DevDistro }')
    $iMcp = [array]::IndexOf($lines, 'Install-MiosNativeMcp -Machine $DevDistro')
    $iSetup = [array]::IndexOf($lines, '& $_nativeSetup -Distro $DevDistro -BinDirectory $MiosBinDir -SourceRoot $MiosRepoDir')
    $calls = @([regex]::Matches((Get-Code $text), '(?m)^\s*Install-MiosNativeMcp\b')).Count
    Check ($iCatalog -ge 0 -and $iMcp -eq $iCatalog + 1 -and $iSetup -eq $iMcp + 1 -and $calls -eq 1) 'the native MiOS-MCP step runs unconditionally, right after the catalog and right before the client setup'

    # --- Behaviour: Install-MiosNativeMcp against a wsl.exe mock ------------------------------------------------------
    $fn = & $fnText 'Install-MiosNativeMcp'
    $ok = $false; $failInstall = $false; $failProbe = $false; $rootUid = $false
    if ($fn) {
        $a = & $harness -FnSrc $fn -InstallRc 0 -ProbeOk $true -Uid1000 'user'
        $install = @($a.Calls | Where-Object { $_ -match '--install-native' })
        $probe = @($a.Calls | Where-Object { $_ -match 'native-ready' })
        $iInstall = [array]::IndexOf($a.Calls, $install[0]); $iProbe = [array]::IndexOf($a.Calls, $probe[0])
        $ok = $a.Error -eq '' -and $install.Count -eq 1 -and $probe.Count -eq 1 -and $iInstall -lt $iProbe -and
              $install[0] -eq '-d podman-MiOS-DEV -u root --exec python3.13 /usr/libexec/mios/mios-mcp-server --install-native --source-root / --root /' -and
              $probe[0].StartsWith('-d podman-MiOS-DEV -u user --exec /usr/lib/mios/mcp/.venv/bin/python3 -c ') -and
              $probe[0].Contains("from mcp import Client; assert os.getuid()!=0; assert os.access('/usr/libexec/mios/tmux-mcp',os.X_OK); print('native-ready')") -and
              $a.Logs.Contains('mios-mcp-install: mios-mcp-server: installed') -and $a.Logs.Contains('mios-mcp-probe: native-ready') -and $a.Logs.Contains('OK Native MiOS-MCP installed and probed as user')
        $b = & $harness -FnSrc $fn -InstallRc 1 -ProbeOk $true -Uid1000 'user'
        $failInstall = $b.Error -match '^Native MiOS-MCP install failed \(exit 1\)' -and @($b.Calls | Where-Object { $_ -match 'native-ready' }).Count -eq 0
        $c = & $harness -FnSrc $fn -InstallRc 0 -ProbeOk $false -Uid1000 'user'
        $failProbe = $c.Error -match '^Native MiOS-MCP probe failed as user \(exit 1\)' -and $c.Logs.Contains('mios-mcp-probe: AssertionError')
        $d = & $harness -FnSrc $fn -InstallRc 0 -ProbeOk $true -Uid1000 'root'
        $rootUid = $d.Error -match 'No unprivileged uid-1000 user' -and @($d.Calls | Where-Object { $_ -match 'native-ready' }).Count -eq 0
    }
    Check $ok 'MiOS''s installer runs as root (python3.13 mios-mcp-server --install-native --source-root / --root /), then the client setup''s probe runs as the uid-1000 user'
    Check ($failInstall -and $failProbe -and $rootUid) 'an installer failure, a failed probe and a root uid 1000 are each fatal with their own message'
    # Native arguments carry no double quote (Windows PowerShell would drop it) and no 2>$null (it would throw on stderr).
    $fnCode = Get-Code $fn
    Check ($fnCode -and @([regex]::Matches($fnCode, "--exec [^\n]*-c '")).Count -eq 3 -and -not ([regex]::Matches($fnCode, "--exec [^\n]*-c '[^'\n]*`"")).Count -and $fnCode -notmatch '2>\$null') 'the probes pass single-quoted Python with no 2>$null, safe on Windows PowerShell 5.1 and pwsh 7'

    Write-Host "NATIVE_MCP_ASSERTIONS $($script:checks)"
    return $script:fail
}

try {
    if (-not $PlantDefect) {
        $failures = Invoke-Checks $BuildPath
        if ($failures) { Write-Host "RESULT: FAIL ($failures checks)"; exit 1 }
        Write-Host 'RESULT: PASS (native MiOS-MCP step; source order and a wsl.exe mock only)'; exit 0
    }
    $baseline = Invoke-Checks $BuildPath
    if ($baseline) { Write-Host 'NATIVE_MCP_BASELINE_FAILED'; exit 1 }
    $call = "    Install-MiosNativeMcp -Machine `$DevDistro`n"
    $setup = "    & `$_nativeSetup -Distro `$DevDistro -BinDirectory `$MiosBinDir -SourceRoot `$MiosRepoDir`n"
    $plants = @(
        @{ Name = 'the step removed'; Expected = 'the native MiOS-MCP step runs unconditionally, right after the catalog and right before the client setup'
           Edits = @(, @($call, '')) },
        @{ Name = 'the installer failure downgraded to a warning'; Expected = 'an installer failure, a failed probe and a root uid 1000 are each fatal with their own message'
           Edits = @(, @('{ throw "Native MiOS-MCP install failed', '{ Log-Warn "Native MiOS-MCP install failed')) },
        @{ Name = 'the step placed after the client setup'; Expected = 'the native MiOS-MCP step runs unconditionally, right after the catalog and right before the client setup'
           Edits = @(, @(($call + $setup), ($setup + $call))) },
        @{ Name = 'the probe run as root'; Expected = 'MiOS''s installer runs as root (python3.13 mios-mcp-server --install-native --source-root / --root /), then the client setup''s probe runs as the uid-1000 user'
           Edits = @(, @("& wsl.exe -d `$distribution -u `$user --exec `$python -c", "& wsl.exe -d `$distribution -u root --exec `$python -c")) },
        @{ Name = 'a skip when the payload is present'; Expected = 'the native MiOS-MCP step runs unconditionally, right after the catalog and right before the client setup'
           Edits = @(, @($call, "    if (-not (Test-Path -LiteralPath `$MiosBinDir)) { Install-MiosNativeMcp -Machine `$DevDistro }`n")) }
    )
    $caught = 0
    foreach ($plant in $plants) {
        $text = ([IO.File]::ReadAllText($BuildPath)) -replace "`r`n", "`n"
        foreach ($edit in $plant.Edits) {
            $count = ([regex]::Matches($text, [regex]::Escape($edit[0]))).Count
            if ($count -ne 1) { throw "Missing or ambiguous defect anchor: $($plant.Name) (found $count)" }
            $text = $text.Replace($edit[0], $edit[1])
        }
        $copy = Join-Path ([IO.Path]::GetTempPath()) ('planted-mcp-' + [guid]::NewGuid().ToString('N') + '.ps1')
        try {
            [IO.File]::WriteAllText($copy, $text, (New-Object Text.UTF8Encoding($true)))
            $null = Invoke-Checks $copy
        } finally { Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue }
        $detected = $script:failedChecks.Contains($plant.Expected)
        Write-Host ('  {0} planted defect caught: {1}' -f $(if ($detected) { 'PASS' } else { 'FAIL' }), $plant.Name)
        if ($detected) { $caught++ }
    }
    if ($caught -eq $plants.Count) { Write-Host "RESULT: PASS (every planted defect was caught: $caught/$($plants.Count))"; exit 0 }
    Write-Host "RESULT: FAIL (planted defects caught: $caught/$($plants.Count))"; exit 1
} catch { Write-Host "RESULT: ERROR $($_.Exception.Message)"; exit 1 }
