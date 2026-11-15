# The MiOS login is the SSOT identity: the vendor/host [identity].username through MiOS's identity guard, the exact text
# mios.git's usr/share/mios/windows/*.ps1 carries (pinned below by sha256). No installer path resolves the login as
# uid 1000 or writes a literal default user into wsl.conf. Source checks only: no distro or wsl.exe is touched.
# Default runs the checks; -PlantDefect plants each guarded defect into a copy and requires a red result.
[CmdletBinding()]
param([switch]$PlantDefect, [string]$BuildPath, [string]$GetPath)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $BuildPath) { $BuildPath = Join-Path $repoRoot 'build-mios.ps1' }
if (-not $GetPath) { $GetPath = Join-Path $repoRoot 'Get-MiOS.ps1' }
# sha256 of the guard's Python text as mios.git ships it (mios-native-client-setup.ps1 $identityProbe, mios.git 7a3a0dba).
$GuardSha256 = '82169695caa49524cf90ac4b60da1e2cfbf2edec0237f6d011110977b03f4ad4'

$script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
function Check([bool]$Ok, [string]$What) {
    $script:checks++
    if ($Ok) { Write-Host "  PASS $What" } else { Write-Host "  FAIL $What"; $script:fail++; $script:failedChecks.Add($What) }
}
function Get-Count([string]$Text, [string]$Needle) { return ([regex]::Matches($Text, [regex]::Escape($Needle))).Count }
function Get-Sha256([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Invoke-Checks([string]$Build, [string]$Get) {
    $script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
    $build = ([IO.File]::ReadAllText($Build)) -replace "`r`n", "`n"
    $getText = ([IO.File]::ReadAllText($Get)) -replace "`r`n", "`n"

    $uidLookups = 0; $literalDefaults = 0
    foreach ($text in @($build, $getText)) {
        $uidLookups += (Get-Count $text 'getpwuid(1000)') + (Get-Count $text 'getent passwd 1000')
        $literalDefaults += Get-Count $text 'default=mios'
    }
    Check ($uidLookups -eq 0) 'no installer path resolves the login as uid 1000'
    Check ($literalDefaults -eq 0) 'no installer path writes a literal default=mios'

    # The PowerShell copies are single-quoted literals ('' escapes a quote); every other copy is the plain text.
    $psCopies = @([regex]::Matches($build, "(?m)^\s*\`$identityProbe = '((?:[^']|'')*)'\s*$") | ForEach-Object { $_.Groups[1].Value.Replace("''", "'") })
    $guard = if ($psCopies.Count) { $psCopies[0] } else { '' }
    $psSame = $psCopies.Count -eq 2 -and @($psCopies | Where-Object { (Get-Sha256 $_) -eq $GuardSha256 }).Count -eq 2
    Check $psSame 'both PowerShell callers (C8''s probe and the configurator) carry the MiOS identity guard byte for byte'
    $plain = if ($guard) { Get-Count $build $guard } else { 0 }
    $starts = Get-Count $build "import sys,pwd; sys.path.insert(0,'/usr/lib/mios'); import mios_toml as m;"
    Check ($plain -eq 4 -and $starts -eq 4) 'the realize, sudoers, wsl --import and seed paths carry the same guard text (4 plain copies, no drifted copy)'

    $realizeWrites = (Get-Count $build "printf '\n[user]\ndefault=%s\n' `"`$MIOS_LOGIN`" | sudo tee -a /etc/wsl.conf") -eq 1
    $seedWrites = (Get-Count $build "printf '\n[user]\ndefault=%s\n' `"`$MIOS_LOGIN`" >> /etc/wsl.conf") -eq 1
    $sudoersUser = $build.Contains('DEV_USER=$(python3 -c "import sys,pwd;') -and $build.Contains('no usable MiOS login for [identity].username; sudoers drop-in not written')
    $pyLogin = (Get-Count $build 'login = probe.stdout.strip() if probe.returncode == 0 else ""') -eq 1 -and $build.Contains('probe = subprocess.run([sys.executable, "-c", GUARD], capture_output=True, text=True)')
    Check ($realizeWrites -and $seedWrites -and $sudoersUser -and $pyLogin) 'each writer takes the login from the guard: realize and seed write default=$MIOS_LOGIN, sudoers grants $DEV_USER, the wsl --import sanitizer uses the guard''s output'

    Write-Host "IDENTITY_LOGIN_ASSERTIONS $($script:checks)"
    return $script:fail
}

try {
    if (-not $PlantDefect) {
        $failures = Invoke-Checks $BuildPath $GetPath
        if ($failures) { Write-Host "RESULT: FAIL ($failures checks)"; exit 1 }
        Write-Host 'RESULT: PASS (the MiOS login comes from [identity].username through MiOS''s guard; source checks only)'; exit 0
    }
    $baseline = Invoke-Checks $BuildPath $GetPath
    if ($baseline) { Write-Host 'IDENTITY_LOGIN_BASELINE_FAILED'; exit 1 }
    $plants = @(
        @{ Name = 'C8 resolves the login as uid 1000 again'; Expected = 'no installer path resolves the login as uid 1000'
           Edits = @(, @("`$user = ((& wsl.exe -d `$distribution -u root --exec python3 -c `$identityProbe) -join '').Trim()",
                         "`$user = ((& wsl.exe -d `$distribution -u root --exec python3 -c 'import pwd; print(pwd.getpwuid(1000).pw_name)') -join '').Trim()")) },
        @{ Name = 'the realize writes a literal default=mios again'; Expected = 'no installer path writes a literal default=mios'
           Edits = @(, @("printf '\n[user]\ndefault=%s\n' `"`$MIOS_LOGIN`" | sudo tee -a /etc/wsl.conf", "printf '\n[user]\ndefault=mios\n' | sudo tee -a /etc/wsl.conf")) },
        @{ Name = 'the seed''s guard copy drifted'; Expected = 'the realize, sudoers, wsl --import and seed paths carry the same guard text (4 plain copies, no drifted copy)'
           Edits = @(, @("or no login shell)' % n)`" 2>/dev/null) || MIOS_LOGIN=`"`"", "or no login shell!)' % n)`" 2>/dev/null) || MIOS_LOGIN=`"`"")) },
        @{ Name = 'the configurator''s guard copy drifted'; Expected = 'both PowerShell callers (C8''s probe and the configurator) carry the MiOS identity guard byte for byte'
           Edits = @(, @("or no login shell)'' % n)'`n    `$devUser = ((& wsl.exe", "or no login shell!)'' % n)'`n    `$devUser = ((& wsl.exe")) },
        @{ Name = 'the wsl --import sanitizer takes id mios again'; Expected = 'each writer takes the login from the guard: realize and seed write default=$MIOS_LOGIN, sudoers grants $DEV_USER, the wsl --import sanitizer uses the guard''s output'
           Edits = @(, @('login = probe.stdout.strip() if probe.returncode == 0 else ""', 'login = "mios" if os.system("id mios >/dev/null 2>&1") == 0 else ""')) }
    )
    $caught = 0
    foreach ($plant in $plants) {
        $text = ([IO.File]::ReadAllText($BuildPath)) -replace "`r`n", "`n"
        foreach ($edit in $plant.Edits) {
            $count = ([regex]::Matches($text, [regex]::Escape($edit[0]))).Count
            if ($count -ne 1) { throw "Missing or ambiguous defect anchor: $($plant.Name) (found $count)" }
            $text = $text.Replace($edit[0], $edit[1])
        }
        $copy = Join-Path ([IO.Path]::GetTempPath()) ('planted-identity-' + [guid]::NewGuid().ToString('N') + '.ps1')
        try {
            [IO.File]::WriteAllText($copy, $text, (New-Object Text.UTF8Encoding($true)))
            $null = Invoke-Checks $copy $GetPath
        } finally { Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue }
        $detected = $script:failedChecks.Contains($plant.Expected)
        Write-Host ('  {0} planted defect caught: {1}' -f $(if ($detected) { 'PASS' } else { 'FAIL' }), $plant.Name)
        if ($detected) { $caught++ }
    }
    if ($caught -eq $plants.Count) { Write-Host "RESULT: PASS (every planted defect was caught: $caught/$($plants.Count))"; exit 0 }
    Write-Host "RESULT: FAIL (planted defects caught: $caught/$($plants.Count))"; exit 1
} catch { Write-Host "RESULT: ERROR $($_.Exception.Message)"; exit 1 }
