# Source-only storage refusals and the actual worker request catch, with all disk APIs replaced by tripwires.
# Never execute installer top-level, worker pipe setup, UAC, registry, partition or volume commands.
[CmdletBinding()]
param([string]$SourcePath)
$ErrorActionPreference = 'Stop'
if (-not $SourcePath) { $SourcePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-MiOS.ps1' }
$text = [IO.File]::ReadAllText($SourcePath)
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ('Invalid product source: ' + $errors[0].Message) }
function Get-SourceFunction([string]$Name) {
    $defs = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true))
    if ($defs.Count -ne 1) { throw ('Missing/duplicate product function: ' + $Name) }
    return $defs[0]
}
$script:checks = 0; $script:failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$Ok, [string]$Name) {
    $script:checks++
    if ($Ok) { Write-Host ('  PASS ' + $Name) } else { $script:failures.Add($Name); Write-Host ('  FAIL ' + $Name) }
}
$storageFns = @((Get-SourceFunction 'Initialize-DataDisk'), (Get-SourceFunction 'Initialize-MiosMachineStorage'))
$exits = @($storageFns | ForEach-Object { $_.FindAll({ param($n) $n -is [Management.Automation.Language.ExitStatementAst] }, $true) })
$reaps = @($storageFns | ForEach-Object { $_.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-MiOSFullReap' }, $true) })
Check ($exits.Count -eq 0) 'storage refusals cannot terminate the elevated worker before its error reply'
Check ($reaps.Count -eq 0) 'storage failures cannot invoke persistent-state cleanup'
if ($exits.Count -or $reaps.Count) { throw 'Unsafe storage source refused before executing the isolated fixture.' }
foreach ($name in @('Initialize-DataDisk', 'Initialize-MiosMachineStorage', 'Get-MiosMachineWorkerScript')) {
    . ([scriptblock]::Create(((Get-SourceFunction $name).Extent.Text -replace '^function\s+', 'function global:')))
}
$worker = Get-MiosMachineWorkerScript -Source $text
Check ($worker -notmatch '(?m)^function Invoke-MiOSFullReap \{' -and $worker -match '(?m)^function Initialize-MiosMachineStorage \{') 'the worker carries storage preparation and excludes the reap helper'
if ($script:failures.Count) { throw 'Unsafe worker helper closure.' }
$workerFn = Get-SourceFunction 'Invoke-MiosMachineWorker'
$requestTries = @($workerFn.FindAll({ param($n)
    $n -is [Management.Automation.Language.TryStatementAst] -and $n.CatchClauses.Count -eq 1 -and
    @($n.Body.FindAll({ param($c) $c -is [Management.Automation.Language.CommandAst] -and $c.GetCommandName() -eq 'Invoke-MiosMachinePreparationRequest' }, $true)).Count -eq 1
}, $true))
if ($requestTries.Count -ne 1) { throw 'The worker request try/catch fixture anchor is not unique.' }
# Execute this exact source try/catch/finally with in-memory reader/writer objects.
# The real pipe client, elevation/peer setup and machine request validation do not execute here.
$script:requestTry = $requestTries[0].Extent.Text

function global:Get-MiosTomlValue {
    param($Section, $Key, $Default)
    if ($Section -ne 'bootstrap.host_storage') { throw 'Unexpected fixture configuration section.' }
    switch ($Key) {
        'drive_letter' { return $script:selection }
        'shrink_mb' { return 64 }
        default { return $Default }
    }
}
function global:Get-CimInstance {
    [CmdletBinding()]param([string]$ClassName)
    switch ($ClassName) {
        'Win32_Processor' { return [pscustomobject]@{ VirtualizationFirmwareEnabled = ($script:scenario -ne 'virtualization') } }
        'Win32_ComputerSystem' { return [pscustomobject]@{ HypervisorPresent = $false } }
        default { throw 'Unexpected fixture CIM query.' }
    }
}
function global:Get-Volume {
    [CmdletBinding()]param($DriveLetter)
    $script:volumeReads.Add([string]$DriveLetter)
    switch ($script:scenario) {
        'label' { return [pscustomobject]@{ FileSystemLabel = 'OTHER-VOLUME'; Size = 1GB; FileSystem = 'NTFS' } }
        'style' { return $null }
        'missing' { return $null }
        'query' { return $null }
        'ready' { return [pscustomobject]@{ FileSystemLabel = 'MIOS-DEV'; Size = 1GB; FileSystem = 'NTFS' } }
        default { throw 'A virtualization refusal reached storage discovery.' }
    }
}
function global:Get-Partition {
    param($DriveLetter)
    if ($script:scenario -eq 'query') { throw 'FIXTURE-STORAGE-QUERY-REFUSAL' }
    return [pscustomobject]@{ Size = 1GB; DiskNumber = 7 }
}
function global:Get-PartitionSupportedSize { param($DriveLetter) return [pscustomobject]@{ SizeMin = 256MB } }
function global:Get-Disk { param($Number) return [pscustomobject]@{ Number = 7; PartitionStyle = 'RAW' } }
function global:Resize-Partition { $script:mutations++; throw 'Forbidden actual partition resize.' }
function global:New-Partition { $script:mutations++; throw 'Forbidden actual partition creation.' }
function global:Format-Volume { $script:mutations++; throw 'Forbidden actual volume format.' }
function global:Invoke-MiOSFullReap { $script:mutations++; throw 'Forbidden cleanup.' }
function global:Write-Info { param($Message) }
function global:Write-Good { param($Message) }
function global:Write-Err { param($Message) }
function global:Read-MiosPipeLine { param($Reader) return '{}' }
function global:Invoke-MiosMachinePreparationRequest {
    param($Request, $OriginProcessId)
    Initialize-MiosMachineStorage -Context ([pscustomobject]@{ Sid = 'S-1-5-21-1-2-3-1001' })
    return [pscustomobject]@{ Status = 'ready' }
}
function Invoke-WorkerCase {
    $reader = [pscustomobject]@{ Disposed = 0 }
    $reader | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $this.Disposed++ }
    $writer = [pscustomobject]@{ Disposed = 0; Lines = (New-Object System.Collections.Generic.List[string]) }
    $writer | Add-Member -MemberType ScriptMethod -Name WriteLine -Value { param($Line) $this.Lines.Add([string]$Line) }
    $writer | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $this.Disposed++ }
    $OriginProcessId = 4242
    $caught = ''
    try { . ([scriptblock]::Create($script:requestTry)) } catch { $caught = $_.Exception.Message }
    $reply = if ($writer.Lines.Count -eq 1) { $writer.Lines[0] | ConvertFrom-Json } else { $null }
    return [pscustomobject]@{ Reply = $reply; Thrown = $caught; Lines = $writer.Lines.Count; ReaderDisposed = $reader.Disposed; WriterDisposed = $writer.Disposed }
}
$originalSystemDrive = $env:SystemDrive
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-storage-failure-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$sentinels = @{}
foreach ($name in @('source-checkout', 'persistent-distribution', 'cached-model')) {
    $path = Join-Path $scratch $name
    [IO.File]::WriteAllText($path, ('EXISTING-' + $name))
    $sentinels[$path] = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
}
$cases = @(
    @{ Name = 'label'; Drive = 'D'; Reason = 'Initialize-DataDisk: drive D: already exists with another label; no disk changes were made.' },
    @{ Name = 'style'; Drive = 'D'; Reason = 'Initialize-DataDisk: disk 7 has an unsupported partition style; no disk changes were made.' },
    @{ Name = 'virtualization'; Drive = 'C'; Reason = 'Hardware virtualization is disabled: enable Intel VT-x / AMD-V (SVM) in BIOS/UEFI, then re-run. No storage changes were made.' },
    @{ Name = 'missing'; Drive = 'C'; Reason = 'configured volume C: was not returned by storage discovery' },
    @{ Name = 'query'; Drive = 'D'; Reason = 'FIXTURE-STORAGE-QUERY-REFUSAL' },
    @{ Name = 'ready'; Drive = 'C'; Reason = '' }
)
try {
    $env:SystemDrive = 'C:'
    foreach ($case in $cases) {
        $script:scenario = $case.Name; $script:selection = $case.Drive
        $script:mutations = 0; $script:volumeReads = New-Object System.Collections.Generic.List[string]
        $result = Invoke-WorkerCase
        Check ($result.Lines -eq 1 -and $null -ne $result.Reply) ($case.Name + ' produces one actual worker reply instead of missing readiness')
        Check ($result.ReaderDisposed -eq 1 -and $result.WriterDisposed -eq 1) ($case.Name + ' closes the actual request reader/writer in finally')
        Check ($script:mutations -eq 0) ($case.Name + ' performs no partition, format or cleanup action')
        $unchanged = @($sentinels.Keys | Where-Object { [Convert]::ToBase64String([IO.File]::ReadAllBytes($_)) -cne $sentinels[$_] }).Count -eq 0
        Check $unchanged ($case.Name + ' leaves scratch source, distribution and model sentinels unchanged')
        if ($case.Name -eq 'ready') {
            Check ($result.Reply.Status -ceq 'ready' -and -not $result.Thrown) 'converged storage success retains actual ready delivery'
        } else {
            Check ($result.Reply.Status -ceq 'error') ($case.Name + ' reaches the actual worker error catch')
            Check ($result.Reply.Detail.Contains($case.Reason)) ($case.Name + ' delivers its precise public reason through the actual catch')
            Check ($result.Thrown -ceq $result.Reply.Detail) ($case.Name + ' rethrows the same public reason after writing the reply')
            if ($case.Name -ne 'virtualization') {
                Check ($result.Reply.Detail.Contains('existing distributions, persistent state and source checkouts are preserved.')) ($case.Name + ' retains the lossless preservation notice')
            }
        }
        if ($case.Name -eq 'virtualization') { Check ($script:volumeReads.Count -eq 0) 'disabled virtualization refuses before storage discovery' }
    }
    Write-Host ('STORAGE_FAILURE_ASSERTIONS ' + $script:checks)
    if ($script:failures.Count) { throw ('Storage failure fixture failures: ' + ($script:failures -join '; ')) }
    Write-Host 'RESULT: PASS (source storage refusals and actual worker catch; no disk, UAC, pipe or installer execution)'
    exit 0
} finally {
    $env:SystemDrive = $originalSystemDrive
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
