# Source-only fixture: execute the real publication and machine orchestration functions extracted by AST.
# Windows drive paths are mapped into a unique scratch tree; never run installer top-level, elevation, disk, registry or ACL APIs.
[CmdletBinding()]
param([switch]$PlantDefect, [string]$SourcePath)
$ErrorActionPreference = 'Stop'
if (-not $SourcePath) { $SourcePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-MiOS.ps1' }
$source = ([IO.File]::ReadAllText($SourcePath)).Replace("`r`n", "`n").Replace("`r", "`n")
$scratch = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('mios-publication-scope-' + [guid]::NewGuid().ToString('N')))
[IO.Directory]::CreateDirectory($scratch) | Out-Null
$originalSystemDrive = $env:SystemDrive
$script:checks = 0; $script:failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$Ok, [string]$What) {
    $script:checks++
    if ($Ok) { Write-Host "  PASS $What" } else { $script:failures.Add($What); Write-Host "  FAIL $What" }
}
function Import-Product([string]$Text) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw ('Invalid product source: ' + $errors[0].Message) }
    foreach ($name in @('Get-MiosTomlValue', 'Get-MiosMachineTomlRoots', 'Publish-MiosMachineToml',
        'Invoke-MiosMachinePreparationCore', 'Get-MiosMachineWorkerScript')) {
        $defs = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true))
        if ($defs.Count -ne 1) { throw "Missing/duplicate source function: $name" }
        . ([scriptblock]::Create(($defs[0].Extent.Text -replace '^function\s+', 'function global:')))
    }
}
function global:ConvertTo-FixturePath([string]$Path) {
    if ($Path -match '^([A-Za-z]):(?:[\\/](.*))?$') {
        $letter = $Matches[1].ToUpperInvariant(); $tail = [string]$Matches[2]
        if (-not $script:driveMap.ContainsKey($letter)) { throw 'Unexpected fixture drive.' }
        $Path = [IO.Path]::Combine($script:driveMap[$letter], $tail.Replace('\', [string][IO.Path]::DirectorySeparatorChar))
    }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -ine $script:runRoot -and -not $full.StartsWith(($script:runRoot + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'A source fixture attempted a path outside its own scratch tree.'
    }
    return $full
}
function global:Join-Path {
    [CmdletBinding()]param([string]$Path, [string]$ChildPath)
    return [IO.Path]::Combine((ConvertTo-FixturePath $Path), $ChildPath.Replace('\', [string][IO.Path]::DirectorySeparatorChar))
}
function global:Test-Path {
    [CmdletBinding()]param([string]$Path, [string]$LiteralPath, [string]$PathType)
    $requested = if ($PSBoundParameters.ContainsKey('LiteralPath')) { $LiteralPath } else { $Path }
    $actual = ConvertTo-FixturePath $requested
    if ($PathType) { return Microsoft.PowerShell.Management\Test-Path -LiteralPath $actual -PathType $PathType }
    return Microsoft.PowerShell.Management\Test-Path -LiteralPath $actual
}
function global:Resolve-MiosVendorTomlText { return $script:vendor }
function global:Resolve-MiosTomlText { return $script:operator }
function global:Repair-MiosHostTierCredentials {
    param([string[]]$Paths)
    foreach ($path in $Paths) {
        $actual = ConvertTo-FixturePath $path
        $script:repairs.Add($actual); $script:events.Add('repair|' + $actual)
        # A leaked M repair really damages its sentinel, so a spy-only assertion cannot conceal a regression.
        if ([IO.File]::Exists($actual)) { [IO.File]::WriteAllText($actual, 'FIXTURE-REPAIRED') }
    }
}
function global:Write-FixtureToml([string]$Path, [string]$Text, [string]$Kind) {
    $actual = ConvertTo-FixturePath $Path
    $script:writes.Add($Kind + '|' + $actual); $script:events.Add($Kind + '|' + $actual)
    if ($Kind -eq 'vendor' -and $script:dropSystemVendor -and $actual -eq $script:cVendor) { return }
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($actual)) | Out-Null
    [IO.File]::WriteAllText($actual, $Text, (New-Object Text.UTF8Encoding($false)))
}
function global:Write-MiosVendorToml { param($Path, $Text) Write-FixtureToml $Path $Text 'vendor' }
function global:Write-MiosHostToml { param($Path, $Text) Write-FixtureToml $Path $Text 'host' }
function global:Test-MiosElevated { return $script:elevated }
function global:Assert-MiosOriginContext {
    param($Context)
    if ($Context.Sid -cne $script:origin.Sid) { throw 'Fixture origin mismatch.' }
    $script:validated = $true; $script:events.Add('origin')
}
function global:Invoke-MiosMachineBoundaryRecovery {
    param($OriginSid, $Root, $BackupDirectory)
    if (-not $script:validated -or $OriginSid -cne $script:origin.Sid) { throw 'Recovery ran without the validated origin.' }
    $script:recovered.Add([string]$Root); $script:events.Add('recover|' + $Root)
}
function global:Initialize-MiosMachineStorage { param($Context) $script:events.Add('storage') }
function global:Add-MiosDefenderExclusions {}
function global:Invoke-MiosPlatformGate { [pscustomobject]@{ Status = 'ready' } }
function global:Unregister-ScheduledTask { [CmdletBinding()]param($TaskName, [switch]$Confirm) }
function global:Set-ItemProperty { [CmdletBinding()]param($Path, $Name, $Value, $Type, [switch]$Force) }
function Reset-Calls {
    $script:repairs = New-Object System.Collections.Generic.List[string]
    $script:writes = New-Object System.Collections.Generic.List[string]
    $script:events = New-Object System.Collections.Generic.List[string]
    $script:recovered = New-Object System.Collections.Generic.List[string]
    $script:dropSystemVendor = $false; $script:validated = $false; $script:elevated = $true
}
function Set-Selection([string]$Drive) {
    $script:operator = "[bootstrap.host_storage]`ndrive_letter = '$Drive'`n[identity]`nusername = 'fixture'`n"
}
function M-SentinelsIntact {
    return [IO.File]::ReadAllText($script:mVendor) -ceq 'M-VENDOR-SENTINEL' -and
           [IO.File]::ReadAllText($script:mHost) -ceq 'M-HOST-SENTINEL'
}
function Invoke-Checks([string]$Text) {
    $script:checks = 0; $script:failures = New-Object System.Collections.Generic.List[string]
    Import-Product $Text
    $script:runRoot = [IO.Path]::Combine($scratch, [guid]::NewGuid().ToString('N'))
    $script:driveMap = @{}
    foreach ($letter in @('C', 'D', 'M')) {
        $script:driveMap[$letter] = [IO.Path]::Combine($script:runRoot, $letter)
        [IO.Directory]::CreateDirectory($script:driveMap[$letter]) | Out-Null
    }
    $script:cVendor = Join-Path 'C:' 'usr\share\mios\mios.toml'
    $script:mVendor = Join-Path 'M:' 'usr\share\mios\mios.toml'
    $script:mHost = Join-Path 'M:' 'etc\mios\mios.toml'
    foreach ($path in @($script:mVendor, $script:mHost)) { [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) | Out-Null }
    [IO.File]::WriteAllText($script:mVendor, 'M-VENDOR-SENTINEL')
    [IO.File]::WriteAllText($script:mHost, 'M-HOST-SENTINEL')
    $script:vendor = "[meta]`nname = 'scope-fixture'`n[identity]`nusername = 'vendor'`n[packages.windows]`npkgs = []`n"
    $script:origin = [pscustomobject]@{ Sid = 'S-1-5-21-1-2-3-1001' }
    $env:SystemDrive = 'C:'
    Set-Selection 'C'; Reset-Calls
    Check ((@(Get-MiosMachineTomlRoots) -join ',') -ceq 'C:') 'C selection admits only C despite an existing M volume'
    $null = Publish-MiosMachineToml -Context $script:origin
    Check (M-SentinelsIntact) 'real C publication preserves both existing M TOML sentinels'
    Check (($script:repairs -join ',') -ceq (Join-Path 'C:' 'etc\mios\mios.toml')) 'real C publication repairs only the C host tier'
    Check ($script:writes.Count -eq 2 -and @($script:writes | Where-Object { $_ -like ('*|' + $script:driveMap['M'] + '*') }).Count -eq 0) 'real C publication performs exactly its two C writes'
    Check ([IO.File]::ReadAllText($script:cVendor) -ceq $script:vendor) 'real publication verifies the fetched vendor bytes on C'

    Reset-Calls
    $null = Invoke-MiosMachinePreparationCore -Context $script:origin
    Check (($script:recovered -join ',') -ceq 'C:') 'real C core dispatch recovers exactly C'
    Check ($script:events[0] -ceq 'origin' -and $script:events.IndexOf('recover|C:') -lt $script:events.IndexOf('repair|' + (Join-Path 'C:' 'etc\mios\mios.toml'))) 'real C core validates origin and recovers before the first repair'
    Check (M-SentinelsIntact) 'real C core dispatch leaves the existing M sentinels unchanged'

    Set-Selection 'd'; Reset-Calls
    Check ((@(Get-MiosMachineTomlRoots) -join ',') -ceq 'C:,D:') 'explicit existing secondary drive is normalized and admitted with the system root'
    $null = Invoke-MiosMachinePreparationCore -Context $script:origin
    Check (($script:recovered -join ',') -ceq 'C:,D:') 'real secondary-drive core dispatch recovers both publication roots'
    $firstRepair = $script:events.IndexOf('repair|' + (Join-Path 'C:' 'etc\mios\mios.toml'))
    Check ($firstRepair -ge 0 -and $script:events.IndexOf('recover|C:') -ge 0 -and $script:events.IndexOf('recover|D:') -ge 0 -and $script:events.IndexOf('recover|C:') -lt $firstRepair -and $script:events.IndexOf('recover|D:') -lt $firstRepair) 'all admitted roots recover before either host repair or publication'
    Check ($script:repairs.Count -eq 2 -and $script:writes.Count -eq 4 -and [IO.File]::ReadAllText((Join-Path 'D:' 'usr\share\mios\mios.toml')) -ceq $script:vendor) 'real secondary-drive publication writes and verifies exactly C and D'
    Check (M-SentinelsIntact) 'an unselected existing M stays untouched when D is selected'

    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $script:driveMap['D'] -Recurse -Force
    Reset-Calls
    $null = Invoke-MiosMachinePreparationCore -Context $script:origin
    Check (($script:recovered -join ',') -ceq 'C:' -and $script:repairs.Count -eq 1 -and $script:writes.Count -eq 2) 'an absent selected secondary drive waits for storage provisioning'
    Check ($script:events.Contains('storage')) 'an absent secondary drive still reaches the existing storage stage'

    Set-Selection 'M:\..\C'; Reset-Calls
    $caught = $false
    try { $null = Publish-MiosMachineToml -Context $script:origin } catch { $caught = $true }
    Check ($caught -and $script:repairs.Count -eq 0 -and $script:writes.Count -eq 0) 'an invalid configured drive is refused before every repair and writer'

    Set-Selection 'C'; Reset-Calls; $script:elevated = $false
    $caught = $false
    try { $null = Invoke-MiosMachinePreparationCore -Context $script:origin } catch { $caught = $true }
    Check ($caught -and $script:events.Count -eq 0 -and $script:repairs.Count -eq 0 -and $script:writes.Count -eq 0) 'unelevated real core dispatch performs zero recovery or publication actions'

    # A readable exact M copy must never hide a missing required C publication.
    [IO.File]::WriteAllText($script:mVendor, $script:vendor)
    [IO.File]::Delete($script:cVendor)
    Reset-Calls; $script:dropSystemVendor = $true; $caught = $false
    try { $null = Publish-MiosMachineToml -Context $script:origin } catch { $caught = $true }
    Check $caught 'missing C vendor cannot pass with a readable M copy'
    Check ([IO.File]::ReadAllText($script:mVendor) -ceq $script:vendor -and [IO.File]::ReadAllText($script:mHost) -ceq 'M-HOST-SENTINEL') 'failed C verification does not rewrite unselected M copies'
    $worker = Get-MiosMachineWorkerScript -Source $Text
    Check ($worker -match '(?m)^function Get-MiosMachineTomlRoots \{') 'the elevated worker carries the shared root admission helper'
    return $script:failures.Count
}

try {
    $baseline = Invoke-Checks $source
    Write-Host "PUBLICATION_SCOPE_ASSERTIONS $($script:checks)"
    if ($baseline) { throw "Publication scope baseline failed: $baseline" }
    if (-not $PlantDefect) { Write-Host 'RESULT: PASS (real publication and core dispatch, selected-root sentinels)'; exit 0 }
    $plants = @(
        @{ Name = 'presence-based M root'; Expected = 'real C publication preserves both existing M TOML sentinels';
           From = "    `$_systemDrive`n    `$_dataRoot ="; To = "    `$_systemDrive`n    'M:'`n    `$_dataRoot =" },
        @{ Name = 'M verification fallback'; Expected = 'missing C vendor cannot pass with a readable M copy';
           From = "        `$_checkDst = Join-Path `$_root 'usr\share\mios\mios.toml'";
           To = "        `$_checkDst = Join-Path `$_root 'usr\share\mios\mios.toml'; if (-not (Test-Path -LiteralPath `$_checkDst)) { `$_checkDst = Join-Path 'M:' 'usr\share\mios\mios.toml' }" },
        @{ Name = 'secondary recovery omitted'; Expected = 'real secondary-drive core dispatch recovers both publication roots';
           From = 'foreach ($_tomlRoot in @(Get-MiosMachineTomlRoots)) {';
           To = 'foreach ($_tomlRoot in @(Get-MiosMachineTomlRoots | Select-Object -First 1)) {' },
        @{ Name = 'worker helper omitted'; Expected = 'the elevated worker carries the shared root admission helper';
           From = "'Get-MiosTomlValue', 'Get-MiosMachineTomlRoots',"; To = "'Get-MiosTomlValue'," }
    )
    $caught = 0
    foreach ($plant in $plants) {
        $at = $source.IndexOf($plant.From, [StringComparison]::Ordinal)
        if ($at -lt 0 -or $source.IndexOf($plant.From, $at + 1, [StringComparison]::Ordinal) -ge 0) { throw ('Missing/ambiguous mutation anchor: ' + $plant.Name) }
        $null = Invoke-Checks ($source.Replace($plant.From, $plant.To))
        if ($script:failures.Contains($plant.Expected)) { $caught++; Write-Host ('  PASS planted defect caught: ' + $plant.Name) }
        else { Write-Host ('  FAIL planted defect missed: ' + $plant.Name) }
    }
    if ($caught -ne $plants.Count) { throw "Publication scope plants caught $caught/$($plants.Count)." }
    Write-Host "RESULT: PASS (every planted scope defect caught: $caught/$($plants.Count))"
} finally {
    $env:SystemDrive = $originalSystemDrive
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
