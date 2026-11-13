# Source-only cross-entrypoint fixtures. Never execute either installer top-level.
# Windows APIs are mocked; this script also runs in Native MiOS-DEV PowerShell.
[CmdletBinding()]
param([switch]$PlantDefect)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$canonicalText = [IO.File]::ReadAllText((Join-Path $root 'Get-MiOS.ps1')).Replace("`r`n", "`n")
$backendText = [IO.File]::ReadAllText((Join-Path $root 'field/lib/Get-MiOS-Backend.ps1')).Replace("`r`n", "`n")
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-field-platform-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $scratch
$script:checks = 0

function Check([bool]$Condition, [string]$Name) {
    $script:checks++
    if (-not $Condition) { throw ('ASSERT: ' + $Name) }
}
function Parse-Source([string]$Text) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw ('Source parser rejected a fixture: ' + $errors[0].Message) }
    return $ast
}
function Definition($Ast, [string]$Name) {
    $found = @($Ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name }, $true))
    if ($found.Count -ne 1) { throw ('Missing or duplicate fixture function: ' + $Name) }
    return $found[0]
}
function Import-FieldFunctions([string]$Text) {
    $ast = Parse-Source $Text
    foreach ($name in @('Get-MiosFieldCanonicalPath', 'Get-MiosFieldCanonicalFunctions', 'Invoke-MiosFieldPlatformGate',
        'Get-MiosFieldWslConfigText', 'Complete-MiosFieldPlatformGate', 'Invoke-MiOSFullReap')) {
        $definition = Definition $ast $name
        $body = $definition.Extent.Text
        if ($name -eq 'Complete-MiosFieldPlatformGate') {
            # Replace only its real exit statement for observation in this fixture process.
            $exits = @($definition.FindAll({ param($node) $node -is [Management.Automation.Language.ExitStatementAst] }, $true))
            foreach ($exit in ($exits | Sort-Object { $_.Extent.StartOffset } -Descending)) {
                $offset = $exit.Extent.StartOffset - $definition.Extent.StartOffset
                $body = $body.Remove($offset, $exit.Extent.Text.Length).Insert($offset, "throw 'FIELD_PENDING_EXIT'")
            }
        }
        . ([scriptblock]::Create(($body -replace '^function\s+', 'function global:')))
    }
    return $ast
}
function Write-MockedCanonical([string]$Text) {
    $ast = Parse-Source $Text
    $elevated = Definition $ast 'Test-MiosElevated'
    $replacement = 'function Test-MiosElevated { return $global:FieldFixture.Elevated }'
    $mocked = $Text.Remove($elevated.Extent.StartOffset, $elevated.Extent.Text.Length).Insert($elevated.Extent.StartOffset, $replacement)
    # Fail before any entrypoint effect if Field accidentally executes the whole file.
    $mocked = $mocked.Insert($ast.ParamBlock.Extent.EndOffset, "`n`$global:FieldTopLevelExecuted = `$true; throw 'CANONICAL_TOP_LEVEL_EXECUTED'`n")
    $path = Join-Path $scratch ('canonical-' + [guid]::NewGuid().ToString('N') + '.ps1')
    [IO.File]::WriteAllText($path, $mocked, (New-Object Text.UTF8Encoding($false)))
    return $path
}

$global:FieldFixtureText = @'
[bootstrap.prereqs.features]
wsl = 'Microsoft-Windows-Subsystem-Linux'
vmp = 'VirtualMachinePlatform'
hyperv = 'Microsoft-Hyper-V'
require_reboot_to_continue = false
[[wsl2.inbound]]
name = 'fixture-narrow'
protocol = 'TCP'
local_port = '7447'
remote_address = '100.64.0.1/32'
reason = 'An explicit narrow fixture service'
'@
function global:Resolve-MiosTomlText { return $global:FieldFixtureText }
function Reset-Fixture {
    $global:FieldFixture = @{
        Elevated = $true; States = @{ 'Microsoft-Windows-Subsystem-Linux' = 'Enabled'; 'VirtualMachinePlatform' = 'Enabled'; 'Microsoft-Hyper-V' = 'Enabled' }
        EnableExit = @{}; Creator = $true; RegisterExit = 0; RegisterCalls = 0; MissingProvider = ''
        SetCalls = 0; Inbound = 'Allow'; ActiveInbound = ''; ActiveEnabled = 'True'; Rules = @(); Removed = @()
        ProviderThrows = ''; StoreWslExit = 0; CreatorVisibleAfterRegister = $true; OldRules = $false
        VmStarts = 0; DestructiveCalls = 0; ElevationReads = 0; Sleeps = 0
    }
    $global:FieldTopLevelExecuted = $false
}
function global:Get-Command {
    param([string]$Name, $ErrorAction)
    if ($Name -eq $global:FieldFixture.MissingProvider) { return $null }
    return [pscustomobject]@{ Name = $Name; Source = $Name }
}
function global:dism.exe {
    $name = [string](@($args | Where-Object { [string]$_ -like '/featurename:*' })[0])
    $name = $name.Substring('/featurename:'.Length)
    if ($args -contains '/get-featureinfo') {
        $global:LASTEXITCODE = 0
        if ($args -notcontains '/English') { return 'Zustand : Aktiviert' }
        return ('State : ' + $global:FieldFixture.States[$name])
    }
    if ($args -notcontains '/enable-feature') { throw 'Unexpected DISM fixture operation.' }
    $global:LASTEXITCODE = if ($global:FieldFixture.EnableExit.ContainsKey($name)) { $global:FieldFixture.EnableExit[$name] } else { 0 }
    if ($global:LASTEXITCODE -eq 0) { $global:FieldFixture.States[$name] = 'Enabled' }
}
function global:wsl.exe {
    if ($args -contains '--unregister' -or $args -contains '--import' -or $args -contains '-d') {
        $global:FieldFixture.DestructiveCalls++
        throw 'A distribution operation reached the platform fixture.'
    }
    $global:LASTEXITCODE = 0
    if ($args -contains '--version') { $global:LASTEXITCODE = $global:FieldFixture.StoreWslExit; return 'WSL fixture' }
}
function global:Get-NetFirewallHyperVVMCreator {
    param($ErrorAction)
    if ($global:FieldFixture.ProviderThrows -eq 'Get-NetFirewallHyperVVMCreator') { throw 'Fixture provider query failed.' }
    if ($global:FieldFixture.Creator) { return [pscustomobject]@{ VMCreatorId = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' } }
}
function global:Invoke-CimMethod {
    param($Namespace, $ClassName, $MethodName, $Arguments, $ErrorAction)
    if ($ClassName -ne 'MSFT_NetFirewallHyperVVMCreator' -or $MethodName -ne 'RegisterHyperVVMCreator') { throw 'Unexpected CIM fixture operation.' }
    if ($global:FieldFixture.ProviderThrows -eq 'Invoke-CimMethod') { throw 'Fixture creator registration failed.' }
    $global:FieldFixture.RegisterCalls++
    if ($global:FieldFixture.RegisterExit -eq 0 -and $global:FieldFixture.CreatorVisibleAfterRegister) { $global:FieldFixture.Creator = $true }
    return [pscustomobject]@{ ReturnValue = $global:FieldFixture.RegisterExit }
}
function global:Set-NetFirewallHyperVVMSetting {
    param($Name, $Enabled, $DefaultInboundAction, $DefaultOutboundAction, $LoopbackEnabled, $AllowHostPolicyMerge, $ErrorAction)
    if ($global:FieldFixture.ProviderThrows -eq 'Set-NetFirewallHyperVVMSetting') { throw 'Fixture policy update failed.' }
    $global:FieldFixture.SetCalls++
    $global:FieldFixture.Inbound = [string]$DefaultInboundAction
}
function global:Get-NetFirewallHyperVVMSetting {
    param($Name, $PolicyStore, $ErrorAction)
    if ($global:FieldFixture.ProviderThrows -eq 'Get-NetFirewallHyperVVMSetting') { throw 'Fixture effective policy query failed.' }
    if ($PolicyStore -ne 'ActiveStore') { throw 'Effective firewall readback is required.' }
    $inbound = if ($global:FieldFixture.ActiveInbound) { $global:FieldFixture.ActiveInbound } else { $global:FieldFixture.Inbound }
    return [pscustomobject]@{ Enabled = $global:FieldFixture.ActiveEnabled; DefaultInboundAction = $inbound }
}
function global:Get-NetFirewallHyperVRule {
    param($ErrorAction)
    if ($global:FieldFixture.ProviderThrows -eq 'Get-NetFirewallHyperVRule') { throw 'Fixture rule query failed.' }
    if ($global:FieldFixture.OldRules) { return [pscustomobject]@{ Name = 'MiOS-WSL-obsolete'; VMCreatorId = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' } }
}
function global:Remove-NetFirewallHyperVRule {
    param($Name, $ErrorAction)
    if ($global:FieldFixture.ProviderThrows -eq 'Remove-NetFirewallHyperVRule') { throw 'Fixture rule removal failed.' }
    $global:FieldFixture.Removed += $Name
}
function global:New-NetFirewallHyperVRule {
    param($Name, $DisplayName, $VMCreatorId, $Direction, $Action, $Protocol, $LocalPorts, $RemoteAddresses, $ErrorAction)
    if ($global:FieldFixture.ProviderThrows -eq 'New-NetFirewallHyperVRule') { throw 'Fixture rule creation failed.' }
    $global:FieldFixture.Rules += @{ Name = $Name; Direction = $Direction; Action = $Action; Protocol = $Protocol; Port = $LocalPorts; Remote = $RemoteAddresses }
}
function global:Start-Sleep { param($Seconds) $global:FieldFixture.Sleeps++ }
function global:podman { $global:FieldFixture.DestructiveCalls++; throw 'Podman is outside platform admission.' }
function global:Remove-VM { $global:FieldFixture.DestructiveCalls++; throw 'VM removal is outside platform admission.' }
function global:Remove-Partition { $global:FieldFixture.DestructiveCalls++; throw 'Partition removal is outside platform admission.' }

function Invoke-CanonicalGate([string]$Path) {
    $definitions = Get-MiosFieldCanonicalFunctions -Path $Path
    return & {
        param($Definitions, $Text)
        . $Definitions
        function Resolve-MiosTomlText { return '' }
        function Resolve-MiosVendorTomlText { return $Text }
        Invoke-MiosPlatformGate
    } $definitions $global:FieldFixtureText
}
function Invoke-FieldCase([string]$Path) {
    $message = ''
    try {
        $result = Invoke-MiosFieldPlatformGate -CanonicalPath $Path
        Complete-MiosFieldPlatformGate -Result $result
        $global:FieldFixture.VmStarts++
    } catch { $message = $_.Exception.Message }
    return $message
}
function Test-Suite([string]$FieldSource, [string]$CanonicalSource) {
    $fieldAst = Import-FieldFunctions $FieldSource
    $canonical = Write-MockedCanonical $CanonicalSource
    Reset-Fixture
    Check ((Invoke-CanonicalGate $canonical).Status -eq 'ready') 'canonical ready gate succeeds'
    Check ($global:FieldFixture.Inbound -eq 'Block') 'canonical gate establishes default Block'
    Check ((Invoke-FieldCase $canonical) -eq '') 'Field ready gate reaches downstream admission'
    Check ($global:FieldFixture.Inbound -eq 'Block') 'Field preserves canonical default Block'
    Check ($global:FieldFixture.SetCalls -eq 2) 'both entrypoints use the canonical policy'
    Check ($global:FieldFixture.VmStarts -eq 1) 'only ready Field reaches the VM marker'
    Check ($global:FieldFixture.Rules.Count -eq 2 -and $global:FieldFixture.Rules[1].Remote -eq '100.64.0.1/32') 'Field consumes the selected scoped inbound table'
    Check (-not $global:FieldTopLevelExecuted) 'canonical entrypoint top-level was never executed'

    foreach ($pending in @('Enable Pending', 'Disabled')) {
        Reset-Fixture
        $global:FieldFixture.States.VirtualMachinePlatform = $pending
        $global:FieldFixture.EnableExit.VirtualMachinePlatform = 3010
        Check ((Invoke-FieldCase $canonical) -eq 'FIELD_PENDING_EXIT') 'pending Field dispatch halts before the VM marker'
        Check ($global:FieldFixture.SetCalls -eq 0) 'pending features never change firewall policy'
        Check ($global:FieldFixture.VmStarts -eq 0) 'pending features never start the VM'
    }
    foreach ($mode in @('required-feature', 'required-wsl-feature', 'deferred', 'inbound-allow', 'disabled-policy', 'creator-error', 'creator-invisible')) {
        Reset-Fixture
        switch ($mode) {
            'required-feature' { $global:FieldFixture.States.VirtualMachinePlatform = 'Disabled'; $global:FieldFixture.EnableExit.VirtualMachinePlatform = 5 }
            'required-wsl-feature' { $global:FieldFixture.States.'Microsoft-Windows-Subsystem-Linux' = 'Disabled'; $global:FieldFixture.EnableExit.'Microsoft-Windows-Subsystem-Linux' = 5; $global:FieldFixture.StoreWslExit = 1 }
            'deferred' { $global:FieldFixture.Elevated = $false }
            'inbound-allow' { $global:FieldFixture.ActiveInbound = 'Allow' }
            'disabled-policy' { $global:FieldFixture.ActiveEnabled = 'False' }
            'creator-error' { $global:FieldFixture.Creator = $false; $global:FieldFixture.RegisterExit = 5 }
            'creator-invisible' { $global:FieldFixture.Creator = $false; $global:FieldFixture.CreatorVisibleAfterRegister = $false }
        }
        Check ((Invoke-FieldCase $canonical) -ne '') ('unsafe Field case throws: ' + $mode)
        Check ($global:FieldFixture.VmStarts -eq 0) ('unsafe Field case stops before VM: ' + $mode)
    }
    foreach ($provider in @('Get-NetFirewallHyperVVMCreator', 'Get-NetFirewallHyperVVMSetting', 'Set-NetFirewallHyperVVMSetting',
        'Get-NetFirewallHyperVRule', 'New-NetFirewallHyperVRule', 'Remove-NetFirewallHyperVRule', 'Invoke-CimMethod')) {
        Reset-Fixture
        $global:FieldFixture.MissingProvider = $provider
        Check ((Invoke-FieldCase $canonical) -ne '') ('missing provider fails closed: ' + $provider)
        Check ($global:FieldFixture.VmStarts -eq 0) ('missing provider stops before VM: ' + $provider)
    }
    foreach ($provider in @('Get-NetFirewallHyperVVMCreator', 'Get-NetFirewallHyperVVMSetting', 'Set-NetFirewallHyperVVMSetting',
        'Get-NetFirewallHyperVRule', 'New-NetFirewallHyperVRule', 'Remove-NetFirewallHyperVRule', 'Invoke-CimMethod')) {
        Reset-Fixture
        $global:FieldFixture.ProviderThrows = $provider
        if ($provider -eq 'Invoke-CimMethod') { $global:FieldFixture.Creator = $false }
        if ($provider -eq 'Remove-NetFirewallHyperVRule') { $global:FieldFixture.OldRules = $true }
        Check ((Invoke-FieldCase $canonical) -ne '') ('provider operation failure stops admission: ' + $provider)
        Check ($global:FieldFixture.VmStarts -eq 0) ('provider operation failure stops before VM: ' + $provider)
    }
    Reset-Fixture
    $global:FieldFixture.Creator = $false
    Check ((Invoke-FieldCase $canonical) -eq '') 'first-use creator registration succeeds'
    Check ($global:FieldFixture.RegisterCalls -eq 1 -and $global:FieldFixture.Inbound -eq 'Block') 'first-use creator still receives Block'
    Invoke-MiOSFullReap -CanonicalPath $canonical
    Check ($global:FieldFixture.DestructiveCalls -eq 0) 'Field recovery preserves distributions and machines'
    Check (-not $global:FieldTopLevelExecuted) 'Field recovery never executes canonical top-level'

    foreach ($mode in @('NAT', 'mirrored')) {
        $text = Get-MiosFieldWslConfigText -CanonicalPath $canonical -Existing "[wsl2]`nfirewall=false`nswap=8GB" -ManagedLines @("networkingMode=$mode") -Firewall $true
        Check ($text -match '(?m)^firewall=true\r?$') ('Field enables mandatory WSL firewall in ' + $mode)
        Check ($text -notmatch 'firewall=false' -and $text -match 'swap=8GB') 'Field replaces unsafe managed state and preserves other settings'
    }
    $errorText = ''
    try { $null = Get-MiosFieldWslConfigText -CanonicalPath $canonical -Existing '' -ManagedLines @('networkingMode=NAT') -Firewall $false } catch { $errorText = $_.Exception.Message }
    Check ($errorText -ne '') 'Field cannot disable the filtering policy in wslconfig'
    $errorText = ''
    try { $null = Get-MiosFieldWslConfigText -CanonicalPath $canonical -Existing "[wsl2]`nfirewall=true`n[wsl2]`nfirewall=false" -ManagedLines @('networkingMode=NAT') -Firewall $true } catch { $errorText = $_.Exception.Message }
    Check ($errorText -ne '') 'Field rejects ambiguous WSL2 firewall sections'
    $errorText = ''
    try { Complete-MiosFieldPlatformGate -Result ([pscustomobject]@{ Status = 'error' }) } catch { $errorText = $_.Exception.Message }
    Check ($errorText -ne '') 'unknown or failed readiness never reaches the VM marker'

    # The real gate and completion calls must both be unguarded top-level before user setup / MiOS-DEV handoff.
    $calls = @($fieldAst.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Invoke-MiosFieldPlatformGate' }, $true))
    $top = @($calls | Where-Object {
        $parent = $_.Parent
        while ($parent) { if ($parent -is [Management.Automation.Language.FunctionDefinitionAst] -or $parent -is [Management.Automation.Language.TryStatementAst]) { return $false }; $parent = $parent.Parent }
        return $true
    })
    Check ($top.Count -eq 1) 'Field calls the platform gate once without a warning-only catch'
    $done = @($fieldAst.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Complete-MiosFieldPlatformGate' }, $true))
    Check ($done.Count -eq 1 -and $done[0].Extent.StartOffset -gt $top[0].Extent.EndOffset) 'Field completes readiness immediately after the gate'
    $parent = $done[0].Parent
    while ($parent) {
        if ($parent -is [Management.Automation.Language.FunctionDefinitionAst] -or $parent -is [Management.Automation.Language.TryStatementAst]) { throw 'Field completion must not be conditional or caught.' }
        $parent = $parent.Parent
    }
    Check ($FieldSource -notmatch '(?m)^function Enable-MiOSWindowsFeatures\s*\{') 'Field carries no duplicate feature implementation'
    Check ($FieldSource -notmatch 'DefaultInboundAction\s+Allow') 'Field has no second broad inbound policy writer'
}

try {
    Test-Suite $backendText $canonicalText
    Write-Host "FIELD_PLATFORM_SOURCE_ASSERTIONS $script:checks"
    if ($PlantDefect) {
        $plants = @(
            @{ Name = 'Field gate bypass'; Field = $true; From = '$_featResult = Invoke-MiosFieldPlatformGate'; To = '$_featResult = [pscustomobject]@{Status="ready"}'; Expected = 'Field calls the platform gate once without a warning-only catch' },
            @{ Name = 'pending completion falls through'; Field = $true; From = '            exit 0'; To = '            return'; Expected = 'pending Field dispatch halts before the VM marker' },
            @{ Name = 'Field recovery unregisters'; Field = $true; From = 'Invoke-MiOSFullReap -Quiet:$QuietFlag'; To = 'Invoke-MiOSFullReap -Quiet:$QuietFlag; wsl.exe --unregister MiOS'; Expected = 'distribution operation reached the platform fixture' },
            @{ Name = 'inbound default Allow'; Field = $false; From = "DefaultInboundAction = 'Block'"; To = "DefaultInboundAction = 'Allow'"; Expected = 'did not read back enabled with inbound Block' },
            @{ Name = 'firewall before pending restart'; Field = $false; From = "'pending' { return `$result }"; To = "'pending' { `$null = Set-MiosWslFirewallPolicy; return `$result }"; Expected = 'pending features never change firewall policy' }
        )
        $caught = 0
        foreach ($plant in $plants) {
            $field = $backendText; $canonical = $canonicalText
            $source = if ($plant.Field) { $field } else { $canonical }
            if (-not $source.Contains($plant.From)) { throw ('Missing plant anchor: ' + $plant.Name) }
            if ($plant.Field) { $field = $field.Replace($plant.From, $plant.To) } else { $canonical = $canonical.Replace($plant.From, $plant.To) }
            $message = ''
            try { Test-Suite $field $canonical } catch { $message = $_.Exception.Message }
            if (-not $message -or $message -notmatch [regex]::Escape($plant.Expected)) { throw ('Plant did not reach its intended control: ' + $plant.Name) }
            $caught++
        }
        Write-Host "FIELD_PLATFORM_PLANTS PASS ($caught/$($plants.Count))"
    } else { Write-Host 'RESULT: PASS (Field platform source fixtures; Windows APIs mocked)' }
} finally { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue }
