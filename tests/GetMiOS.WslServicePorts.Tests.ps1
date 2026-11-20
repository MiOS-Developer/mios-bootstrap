# Pester 5 fixture for MiOS-DEV's SSOT service-port rules on the WSL Hyper-V firewall (Get-MiOS.ps1).
# Source-only: functions are extracted with the PowerShell AST; Get-MiOS.ps1 top-level never runs. Every Windows
# firewall and address cmdlet is a stub over an in-memory rule store, so this runs under pwsh on Linux.
# MIOS_WSL_PORTS_PLANT names one planted defect (see tests/test_getmios_wsl_service_ports.ps1); each must fail its test.

BeforeAll {
    $global:WslCreator = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'
    $global:WslRepoRoot = Split-Path $PSScriptRoot -Parent
    $source = Join-Path $global:WslRepoRoot 'Get-MiOS.ps1'
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Get-MiOS.ps1 does not parse: $($errors[0].Message)" }
    $names = @('Split-MiosTomlKeyLine', 'Get-MiosTomlValue', 'Get-MiosTomlTableArray', 'Get-MiosTomlStringArray',
        'Get-MiosWslServicePortPlan', 'ConvertTo-MiosNetworkPrefix', 'Resolve-MiosWslRemoteScope', 'Sync-MiosWslServicePortRules',
        'Test-MiosWslVmCreator', 'Register-MiosWslVmCreator', 'Set-MiosWslFirewallPolicy')
    $defs = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $names }, $true))
    foreach ($n in $names) { if (@($defs | Where-Object Name -eq $n).Count -ne 1) { throw "Missing or duplicate function $n" } }
    $text = ($defs | ForEach-Object { $_.Extent.Text -replace '^function\s+', 'function global:' }) -join "`n"

    $plants = @{
        'unscoped'      = @{ From = '-Protocol TCP -LocalPorts $want.Port -RemoteAddresses $scope.Addresses -ErrorAction Stop | Out-Null'
                             To   = '-Protocol TCP -LocalPorts $want.Port -ErrorAction Stop | Out-Null' }
        'default-allow' = @{ From = "DefaultInboundAction = 'Block'; DefaultOutboundAction"
                             To   = "DefaultInboundAction = 'Allow'; DefaultOutboundAction" }
        'non-ssot-port' = @{ From = '$ports = [ordered]@{}'
                             To   = '$ports = [ordered]@{ debug = 8080 }' }
    }
    $plant = [string]$env:MIOS_WSL_PORTS_PLANT
    if ($plant) {
        if (-not $plants.ContainsKey($plant)) { throw "Unknown plant '$plant'." }
        $from = $plants[$plant].From
        $count = ([regex]::Matches($text, [regex]::Escape($from))).Count
        if ($count -ne 1) { throw "Plant '$plant' must match the product source exactly once (matched $count)." }
        $text = $text.Replace($from, $plants[$plant].To)
    }
    . ([scriptblock]::Create($text))

    $global:WslVendorBase = @'
[firewall]
open_ports = [
  "forge_http",   # Forgejo web [the bracket in this comment must not end the array]
  "ssh",
]

[ports]
stack_id   = 0
ssh        = 8100     # operator SSH
forge_http = 8400
searxng    = 8800

[ports.categories.edge]
base = 8050

[ssh.windows]
remote_addresses = ["LocalSubnet", "100.64.0.0/10"]

[wsl2]
networking_mode = "NAT"
'@
    $global:WslExpectedScope = @('100.101.102.103/32', '100.64.0.0/10', '172.24.160.0/20', '192.168.1.0/24', '2001:db8:1::/64')

    function global:Resolve-MiosTomlText { return $global:FwFixture.Operator }
    function global:Resolve-MiosVendorTomlText { return $global:FwFixture.Vendor }
    function global:Get-NetIPAddress {
        [CmdletBinding()]param([string]$AddressState)
        return @(
            @{ IPAddress = '192.168.1.37'; PrefixLength = 24 }, @{ IPAddress = '127.0.0.1'; PrefixLength = 8 },
            @{ IPAddress = '169.254.3.4'; PrefixLength = 16 }, @{ IPAddress = 'fe80::1%12'; PrefixLength = 64 },
            @{ IPAddress = '172.24.170.9'; PrefixLength = 20 }, @{ IPAddress = '100.101.102.103'; PrefixLength = 32 },
            @{ IPAddress = '::1'; PrefixLength = 128 }, @{ IPAddress = '2001:db8:1::5'; PrefixLength = 64 }
        ) | ForEach-Object { [pscustomobject]$_ }
    }
    function global:Get-NetFirewallHyperVVMCreator { [CmdletBinding()]param() [pscustomobject]@{ VMCreatorId = $global:WslCreator; FriendlyName = 'WSL' } }
    function global:Invoke-CimMethod { [CmdletBinding()]param($Namespace, $ClassName, $MethodName, $Arguments) [pscustomobject]@{ ReturnValue = 0 } }
    function global:Set-NetFirewallHyperVVMSetting {
        [CmdletBinding()]param($Name, $Enabled, $DefaultInboundAction, $DefaultOutboundAction, $LoopbackEnabled, $AllowHostPolicyMerge)
        $global:FwFixture.PolicySets.Add([string]$DefaultInboundAction)
        $global:FwFixture.Policy = [pscustomobject]@{ Name = $Name; Enabled = $Enabled; DefaultInboundAction = $DefaultInboundAction }
    }
    function global:Get-NetFirewallHyperVVMSetting { [CmdletBinding()]param($PolicyStore, $Name) $global:FwFixture.Policy }
    function global:Get-NetFirewallHyperVRule { [CmdletBinding()]param() @($global:FwFixture.Rules.Values) }
    function global:New-NetFirewallHyperVRule {
        [CmdletBinding()]param($Name, $DisplayName, $VMCreatorId, $Direction = 'Inbound', $Action = 'Allow', $Protocol = 'Any',
            $LocalPorts = 'Any', $RemoteAddresses = 'Any')
        if ($global:FwFixture.Rules.ContainsKey($Name)) { throw "Rule $Name already exists." }
        $global:FwFixture.Calls.Add("New $Name")
        $global:FwFixture.Rules[$Name] = [pscustomobject]@{ Name = $Name; DisplayName = $DisplayName; VMCreatorId = $VMCreatorId
            Direction = [string]$Direction; Action = [string]$Action; Enabled = 'True'; Protocol = [string]$Protocol
            LocalPorts = @($LocalPorts | ForEach-Object { [string]$_ }); RemoteAddresses = @($RemoteAddresses | ForEach-Object { [string]$_ }) }
    }
    function global:Set-NetFirewallHyperVRule {
        [CmdletBinding()]param($Name, $NewDisplayName, $Protocol, $LocalPorts, $RemoteAddresses)
        $global:FwFixture.Calls.Add("Set $Name")
        $r = $global:FwFixture.Rules[$Name]
        if ($NewDisplayName) { $r.DisplayName = $NewDisplayName }
        if ($Protocol) { $r.Protocol = [string]$Protocol }
        if ($LocalPorts) { $r.LocalPorts = @($LocalPorts | ForEach-Object { [string]$_ }) }
        if ($RemoteAddresses) { $r.RemoteAddresses = @($RemoteAddresses | ForEach-Object { [string]$_ }) }
    }
    function global:Remove-NetFirewallHyperVRule {
        [CmdletBinding()]param($Name)
        $global:FwFixture.Calls.Add("Remove $Name")
        $global:FwFixture.Rules.Remove($Name)
    }

    function global:Reset-FwFixture([string]$Vendor = $global:WslVendorBase, [string]$Operator = '') {
        $global:FwFixture = @{ Vendor = $Vendor; Operator = $Operator; Rules = @{}; Policy = $null
            PolicySets = New-Object System.Collections.Generic.List[string]; Calls = New-Object System.Collections.Generic.List[string] }
    }
    function global:Add-ForeignRule([string]$Name, [string]$Creator = $global:WslCreator) {
        $global:FwFixture.Rules[$Name] = [pscustomobject]@{ Name = $Name; DisplayName = $Name; VMCreatorId = $Creator; Direction = 'Inbound'
            Action = 'Allow'; Enabled = 'True'; Protocol = 'TCP'; LocalPorts = @('9999'); RemoteAddresses = @('Any') }
    }
    function global:Get-ServiceRules { @($global:FwFixture.Rules.Values | Where-Object { $_.Name -like 'MiOS-DEV-Port-*' } | Sort-Object Name) }
    function global:Invoke-Sync { Sync-MiosWslServicePortRules -Creator $global:WslCreator 6>$null }
}

Describe 'MiOS-DEV service ports on the WSL Hyper-V firewall' {
    BeforeEach { Reset-FwFixture }

    It 'rule ports equal exactly the SSOT [firewall].open_ports ports' {
        $null = Invoke-Sync
        $got = @(Get-ServiceRules | ForEach-Object { "$($_.Name)=$($_.LocalPorts -join ',')" })
        $got | Should -Be @('MiOS-DEV-Port-forge-http=8400', 'MiOS-DEV-Port-ssh=8100')
    }

    It 'every service rule is scoped to the SSOT remote addresses' {
        $null = Invoke-Sync
        $rules = Get-ServiceRules
        $rules.Count | Should -Be 2
        foreach ($r in $rules) {
            @($r.RemoteAddresses | Sort-Object) | Should -Be $global:WslExpectedScope
            $r.RemoteAddresses | Should -Not -Contain 'Any'
        }
    }

    It 'every service rule is an enabled inbound TCP allow for the WSL VM creator' {
        $null = Invoke-Sync
        foreach ($r in Get-ServiceRules) {
            [guid]$r.VMCreatorId | Should -Be ([guid]$global:WslCreator)
            $r.Direction | Should -Be 'Inbound'
            $r.Action | Should -Be 'Allow'
            $r.Protocol | Should -Be 'TCP'
            $r.Enabled | Should -Be 'True'
        }
    }

    It 'never sets the WSL default inbound action to anything but Block' {
        try { Set-MiosWslFirewallPolicy 6>$null } catch { }
        $global:FwFixture.PolicySets.Count | Should -BeGreaterThan 0
        $global:FwFixture.PolicySets | Should -Not -Contain 'Allow'
        @($global:FwFixture.PolicySets | Where-Object { $_ -ne 'Block' }).Count | Should -Be 0
        $global:FwFixture.Policy.DefaultInboundAction | Should -Be 'Block'
        # The policy path reaches the service-port reconcile only after the Block read-back.
        (Get-ServiceRules).Count | Should -Be 2
    }

    It 'is idempotent: a second run changes nothing' {
        $null = Invoke-Sync
        $global:FwFixture.Calls.Clear()
        $null = Invoke-Sync
        $global:FwFixture.Calls.Count | Should -Be 0
    }

    It 'removes the rule of a port that left SSOT and keeps the rest untouched' {
        $null = Invoke-Sync
        $global:FwFixture.Calls.Clear()
        $global:FwFixture.Vendor = $global:WslVendorBase.Replace("  `"ssh`",`n", '').Replace("  `"ssh`",`r`n", '')
        $result = Invoke-Sync
        Get-ServiceRules | ForEach-Object Name | Should -Be 'MiOS-DEV-Port-forge-http'
        $global:FwFixture.Calls | Should -Be 'Remove MiOS-DEV-Port-ssh'
        $result.Removed | Should -Be 'MiOS-DEV-Port-ssh'
    }

    It 'corrects a rule whose scope or port drifted, in place' {
        $null = Invoke-Sync
        $r = $global:FwFixture.Rules['MiOS-DEV-Port-ssh']
        $r.RemoteAddresses = @('Any'); $r.LocalPorts = @('22')
        $global:FwFixture.Calls.Clear()
        $null = Invoke-Sync
        $global:FwFixture.Calls | Should -Be 'Set MiOS-DEV-Port-ssh'
        $r.LocalPorts | Should -Be '8100'
        @($r.RemoteAddresses | Sort-Object) | Should -Be $global:WslExpectedScope
    }

    It 'recreates a rule whose action, direction or creator cannot be corrected in place' {
        $null = Invoke-Sync
        $global:FwFixture.Rules['MiOS-DEV-Port-ssh'].Action = 'Block'
        $global:FwFixture.Rules['MiOS-DEV-Port-forge-http'].VMCreatorId = '{11111111-1111-1111-1111-111111111111}'
        $global:FwFixture.Calls.Clear()
        $null = Invoke-Sync
        $global:FwFixture.Calls | Should -Contain 'Remove MiOS-DEV-Port-ssh'
        $global:FwFixture.Calls | Should -Contain 'New MiOS-DEV-Port-ssh'
        $global:FwFixture.Calls | Should -Contain 'New MiOS-DEV-Port-forge-http'
        foreach ($r in Get-ServiceRules) { $r.Action | Should -Be 'Allow'; [guid]$r.VMCreatorId | Should -Be ([guid]$global:WslCreator) }
    }

    It 'shifts every port by [ports].stack_id * 10000' {
        Reset-FwFixture -Vendor $global:WslVendorBase.Replace('stack_id   = 0', 'stack_id   = 1')
        $null = Invoke-Sync
        @(Get-ServiceRules | ForEach-Object { $_.LocalPorts[0] }) | Should -Be @('18400', '18100')
    }

    It 'opens nothing for an open_ports key without a [ports] value' {
        Reset-FwFixture -Vendor $global:WslVendorBase.Replace('"ssh",', '"ssh", "ghost_service",')
        $result = Invoke-Sync
        (Get-ServiceRules).Count | Should -Be 2
        ($result.Refused -join ';') | Should -Match 'ghost_service'
    }

    It 'refuses unscoped remote addresses, opens nothing and closes what was open' {
        $null = Invoke-Sync
        $global:FwFixture.Vendor = $global:WslVendorBase.Replace('["LocalSubnet", "100.64.0.0/10"]', '["0.0.0.0/0", "::/0", "Any", "0.0.0.0"]')
        $result = Invoke-Sync
        $result.Status | Should -Be 'unscoped'
        (Get-ServiceRules).Count | Should -Be 0
    }

    It 'the operator layer replaces the vendor open_ports list' {
        Reset-FwFixture -Operator "[firewall]`nopen_ports = [`"ssh`"]`n"
        $null = Invoke-Sync
        Get-ServiceRules | ForEach-Object Name | Should -Be 'MiOS-DEV-Port-ssh'
    }

    It 'leaves [wsl2.inbound] rules and foreign rules alone' {
        Add-ForeignRule 'MiOS-WSL-operator'
        Add-ForeignRule 'ThirdParty'
        $null = Invoke-Sync
        $global:FwFixture.Rules.ContainsKey('MiOS-WSL-operator') | Should -BeTrue
        $global:FwFixture.Rules.ContainsKey('ThirdParty') | Should -BeTrue
        $global:FwFixture.Calls | Should -Not -Contain 'Remove MiOS-WSL-operator'
    }

    It 'degrades with WSL-SERVICE-PORTS-UNSUPPORTED where the rule cmdlets are missing' {
        $saved = ${function:global:Set-NetFirewallHyperVRule}
        Remove-Item Function:\Set-NetFirewallHyperVRule
        Get-Command Set-NetFirewallHyperVRule -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        try {
            $out = @(Sync-MiosWslServicePortRules -Creator $global:WslCreator 6>&1)
        } finally { Set-Item function:global:Set-NetFirewallHyperVRule $saved }
        ($out | Where-Object { $_ -is [Management.Automation.InformationRecord] } | ForEach-Object { [string]$_ }) -join "`n" |
            Should -Match 'WSL-SERVICE-PORTS-UNSUPPORTED'
        ($out | Where-Object { $_ -isnot [Management.Automation.InformationRecord] }).Status | Should -Be 'unsupported'
        $global:FwFixture.Calls.Count | Should -Be 0
    }
}

Describe 'SSOT readers for the service-port rules' {
    BeforeEach { Reset-FwFixture }

    It 'reads a multi-line string array with comments' {
        $got = Get-MiosTomlStringArray -Section 'firewall' -Key 'open_ports'
        $got | Should -Be @('forge_http', 'ssh')
    }

    It 'refuses a non-string array element' {
        Reset-FwFixture -Vendor "[firewall]`nopen_ports = [`"ssh`", 22]`n"
        { Get-MiosTomlStringArray -Section 'firewall' -Key 'open_ports' } | Should -Throw
    }

    It 'returns null when no layer declares the key' {
        Get-MiosTomlStringArray -Section 'firewall' -Key 'absent' | Should -BeNullOrEmpty
    }

    It 'computes network prefixes for IPv4 and IPv6' {
        ConvertTo-MiosNetworkPrefix -Address ([Net.IPAddress]::Parse('192.168.1.37')) -PrefixLength 24 | Should -Be '192.168.1.0/24'
        ConvertTo-MiosNetworkPrefix -Address ([Net.IPAddress]::Parse('100.101.102.103')) -PrefixLength 10 | Should -Be '100.64.0.0/10'
        ConvertTo-MiosNetworkPrefix -Address ([Net.IPAddress]::Parse('2001:db8:1::5')) -PrefixLength 64 | Should -Be '2001:db8:1::/64'
    }

    It 'resolves LocalSubnet to host subnets without loopback or link-local' {
        (Resolve-MiosWslRemoteScope -Entries @('LocalSubnet', '100.64.0.0/10')).Addresses | Should -Be $global:WslExpectedScope
    }

    It 'resolves the system SSOT: every [firewall].open_ports key has a [ports] value' {
        $sys = if ($env:MIOS_SYSTEM_TOML) { $env:MIOS_SYSTEM_TOML } else { Join-Path (Split-Path $global:WslRepoRoot -Parent) 'mios/usr/share/mios/mios.toml' }
        if (-not (Test-Path -LiteralPath $sys)) { Set-ItResult -Skipped -Because "no system mios.toml at $sys (set MIOS_SYSTEM_TOML)"; return }
        $text = [IO.File]::ReadAllText($sys)
        Reset-FwFixture -Vendor $text
        # Independent read of the same SSOT: the open_ports block, then each key's line in [ports].
        $block = [regex]::Match($text, '(?ms)^\[firewall\][ \t]*\r?\n.*?^[ \t]*open_ports[ \t]*=[ \t]*\[(?<b>.*?)\]').Groups['b'].Value
        $keys = @([regex]::Matches(($block -replace '#[^\n]*', ''), '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
        $ports = [regex]::Match($text, '(?ms)^\[ports\][ \t]*\r?\n(?<b>.*?)(?=^\[)').Groups['b'].Value
        $expected = [ordered]@{}
        foreach ($k in $keys) { $expected[$k] = [int]([regex]::Match($ports, '(?m)^[ \t]*' + [regex]::Escape($k) + '[ \t]*=[ \t]*([0-9]+)').Groups[1].Value) }
        $plan = Get-MiosWslServicePortPlan
        $plan.Refused | Should -BeNullOrEmpty
        $keys.Count | Should -BeGreaterThan 0
        @($plan.Ports.Keys) | Should -Be @($expected.Keys)
        @($plan.Ports.Values) | Should -Be @($expected.Values)
        $remote = Get-MiosTomlStringArray -Section 'ssh.windows' -Key 'remote_addresses'
        $remote | Should -Be @('LocalSubnet', '100.64.0.0/10')
    }
}
