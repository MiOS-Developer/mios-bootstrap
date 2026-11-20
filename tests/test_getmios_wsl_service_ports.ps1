# Runs tests/GetMiOS.WslServicePorts.Tests.ps1 (Pester 5, mocked cmdlets, pwsh on Linux or Windows).
# Default: the suite must pass. -PlantDefect: additionally plant each defect into the extracted product source and
# require the named test to FAIL; a plant that leaves its test green fails this runner.
[CmdletBinding()]
param([switch]$PlantDefect)
$ErrorActionPreference = 'Stop'
Import-Module Pester -MinimumVersion 5.0.0 -ErrorAction Stop
$suite = Join-Path $PSScriptRoot 'GetMiOS.WslServicePorts.Tests.ps1'

function Invoke-Suite([string]$Plant) {
    $env:MIOS_WSL_PORTS_PLANT = $Plant
    try {
        $cfg = New-PesterConfiguration
        $cfg.Run.Path = $suite
        $cfg.Run.PassThru = $true
        $cfg.Output.Verbosity = if ($Plant) { 'None' } else { 'Detailed' }
        return Invoke-Pester -Configuration $cfg
    } finally { Remove-Item Env:MIOS_WSL_PORTS_PLANT -ErrorAction SilentlyContinue }
}

$clean = Invoke-Suite ''
if ($clean.Result -ne 'Passed' -or $clean.FailedCount -gt 0 -or $clean.PassedCount -eq 0) {
    throw "WSL service-port suite did not pass ($($clean.FailedCount) failed, $($clean.PassedCount) passed)."
}
Write-Host "PASS clean suite ($($clean.PassedCount) passed, $($clean.SkippedCount) skipped)"
if (-not $PlantDefect) { return }

$plants = [ordered]@{
    'unscoped'      = 'every service rule is scoped to the SSOT remote addresses'
    'default-allow' = 'never sets the WSL default inbound action to anything but Block'
    'non-ssot-port' = 'rule ports equal exactly the SSOT [firewall].open_ports ports'
}
$bad = 0
foreach ($plant in $plants.Keys) {
    $r = Invoke-Suite $plant
    $failed = @($r.Failed | ForEach-Object { $_.Name })
    if ($failed -contains $plants[$plant]) { Write-Host "PASS plant '$plant' fails '$($plants[$plant])'" }
    else { Write-Host "FAIL plant '$plant' left '$($plants[$plant])' green (failed: $($failed -join '; '))"; $bad++ }
}
if ($bad) { throw "$bad planted defect(s) were not caught." }
