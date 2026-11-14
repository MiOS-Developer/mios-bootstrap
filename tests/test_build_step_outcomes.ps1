# Distro step outcome fixtures: Get-MiosDistroStepVerdict AST-extracted from build-mios.ps1, plus the source contract that
# the NVIDIA userland and AI CLI steps report success only on exit 0. Nothing is run in a distro.
# Default runs the fixtures; -PlantDefect plants each guarded defect into a copy of the product and requires a red result.
[CmdletBinding()]
param([switch]$PlantDefect, [string]$BuildPath)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $BuildPath) { $BuildPath = Join-Path $repoRoot 'build-mios.ps1' }
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-step-outcomes-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -ErrorAction Stop | Out-Null

$script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
function Check([bool]$Ok, [string]$What) {
    $script:checks++
    if ($Ok) { Write-Host "  PASS $What" } else { Write-Host "  FAIL $What"; $script:fail++; $script:failedChecks.Add($What) }
}

function Invoke-Checks([string]$Build) {
    $script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Build, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Product source does not parse: $($errors[0].Message)" }
    $fn = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-MiosDistroStepVerdict' }, $true))
    if ($fn.Count -ne 1) { throw 'Missing or duplicate Get-MiosDistroStepVerdict' }
    . ([scriptblock]::Create(($fn[0].Extent.Text -replace '^function\s+', 'function global:')))

    $ok = Get-MiosDistroStepVerdict -Exit 0 -Script '/usr/libexec/mios/x.sh'
    Check ($ok.Ok -and $ok.Detail -eq '') 'exit 0 is a success'
    $missing = Get-MiosDistroStepVerdict -Exit 127 -Script '/usr/libexec/mios/install-ai-clis.sh'
    Check (-not $missing.Ok -and $missing.Detail -match 'exit 127' -and $missing.Detail.Contains('/usr/libexec/mios/install-ai-clis.sh') -and $missing.Detail -match 'missing') 'exit 127 is a failure that names the missing script'
    $other = Get-MiosDistroStepVerdict -Exit 3 -Script '/usr/libexec/mios/install-nvidia-wsl-userland.sh'
    Check (-not $other.Ok -and $other.Detail -match 'exit 3') 'any other non-zero exit is a failure that names the exit code'

    $text = ([IO.File]::ReadAllText($Build)) -replace "`r`n", "`n"
    $aiOk = 'Log-Ok "MiOS AI CLIs installed (claude + gemini available on PATH)"'
    $aiAt = $text.IndexOf($aiOk)
    Check ($aiAt -ge 0 -and $text.Substring([Math]::Max(0, $aiAt - 40), [Math]::Min(40, $aiAt)).Contains('if ($_aiVerdict.Ok) {') -and
           ([regex]::Matches($text, [regex]::Escape($aiOk))).Count -eq 1 -and $text.Contains('$_aiVerdict = Get-MiosDistroStepVerdict -Exit $LASTEXITCODE -Script $_aiScript')) 'the AI CLI step reports success only on exit 0'
    Check ($text.Contains('$_nvVerdict = Get-MiosDistroStepVerdict -Exit $LASTEXITCODE -Script $_nvScript') -and $text.Contains('if ($_nvVerdict.Ok) {') -and
           $text.Contains('$_nvOut | ForEach-Object { Write-Log "nvidia-wsl: $_" }')) 'the NVIDIA userland step reports success only on exit 0 and logs its output'
    $seedAt = $text.IndexOf('$seedRc = $LASTEXITCODE'); $seedThrow = $text.IndexOf('throw "MiOS package overlay failed (rc=$seedRc)"', [Math]::Max(0, $seedAt))
    Check ($seedAt -ge 0 -and $seedThrow -gt $seedAt -and -not $text.Contains('rerun safe') -and -not $text.Contains('partial install possible')) 'a non-zero package overlay exit is a failure with its rc, never "rerun safe"'
    Write-Host "STEP_OUTCOME_ASSERTIONS $($script:checks)"
    return $script:fail
}

try {
    if (-not $PlantDefect) {
        $failures = Invoke-Checks $BuildPath
        if ($failures) { Write-Host "RESULT: FAIL ($failures checks)"; exit 1 }
        Write-Host 'RESULT: PASS (distro step outcome fixtures; source only, nothing run in a distro)'; exit 0
    }
    $baseline = Invoke-Checks $BuildPath
    if ($baseline) { Write-Host 'STEP_OUTCOME_BASELINE_FAILED'; exit 1 }
    $plants = @(
        @{ Name = 'exit 127 treated as success'; Expected = 'exit 127 is a failure that names the missing script'
           From = 'if ($Exit -eq 0) { return [pscustomobject]@{ Ok = $true'; To = 'if ($Exit -in @(0, 127)) { return [pscustomobject]@{ Ok = $true' },
        @{ Name = 'AI CLI success logged unconditionally'; Expected = 'the AI CLI step reports success only on exit 0'
           From = 'if ($_aiVerdict.Ok) { Log-Ok "MiOS AI CLIs installed'; To = '$null = $_aiVerdict; { Log-Ok "MiOS AI CLIs installed' },
        @{ Name = 'NVIDIA verdict ignored'; Expected = 'the NVIDIA userland step reports success only on exit 0 and logs its output'
           From = 'if ($_nvVerdict.Ok) {'; To = 'if ($true) {' },
        @{ Name = 'package overlay rc downgraded to "rerun safe"'; Expected = 'a non-zero package overlay exit is a failure with its rc, never "rerun safe"'
           From = 'throw "MiOS package overlay failed (rc=$seedRc)"'; To = 'Log-Warn "overlay seed exited rc=$seedRc -- partial install possible (packages may still be present; rerun safe)"' }
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
