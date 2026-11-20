# AI-hint: Pester fixture (run under pwsh on Linux or Windows) for MiOS-DEV's Windows-host networking: the WSL Hyper-V service-port rules in Get-MiOS.ps1, the .wslconfig networkingMode/firewall/hostAddressLoopback rendered by every writer, and the Windows Defender rules and portproxy in build-mios.ps1, all from mios.toml [firewall.windows] and [wsl2]. -PlantDefect plants each named defect into the extracted source and requires its named test to fail.
# AI-related: Get-MiOS.ps1, build-mios.ps1, /usr/share/mios/mios.toml, [firewall.windows], [wsl2], [ports]
# AI-functions: Invoke-Suite

[CmdletBinding()]
param([switch]$PlantDefect)
$ErrorActionPreference = 'Stop'
Import-Module Pester -MinimumVersion 5.0.0 -ErrorAction Stop
$repoRoot = Split-Path $PSScriptRoot -Parent

# Source-only: functions are extracted with the PowerShell AST; neither installer's top level ever runs. Every Windows
# firewall, address, netsh and wsl.exe call is a stub over an in-memory store.
$suite = {
    param([string]$RepoRoot, [string]$Plant)

    BeforeAll {
        $global:WslCreator = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'
        $global:WslRepoRoot = $RepoRoot

        $global:WslPlants = $plants = @{
            'unscoped'          = @{ File = 'Get-MiOS.ps1'
                                     From = '-Protocol TCP -LocalPorts $want.Port -RemoteAddresses $scope.Addresses -Profiles $profileText -ErrorAction Stop | Out-Null'
                                     To   = '-Protocol TCP -LocalPorts $want.Port -Profiles $profileText -ErrorAction Stop | Out-Null' }
            'profile-any'       = @{ File = 'Get-MiOS.ps1'
                                     From = '-Protocol TCP -LocalPorts $want.Port -RemoteAddresses $scope.Addresses -Profiles $profileText -ErrorAction Stop | Out-Null'
                                     To   = '-Protocol TCP -LocalPorts $want.Port -RemoteAddresses $scope.Addresses -ErrorAction Stop | Out-Null' }
            'default-allow'     = @{ File = 'Get-MiOS.ps1'
                                     From = "DefaultInboundAction = 'Block'; DefaultOutboundAction"
                                     To   = "DefaultInboundAction = 'Allow'; DefaultOutboundAction" }
            'non-ssot-port'     = @{ File = 'Get-MiOS.ps1'
                                     From = '$ports = [ordered]@{}'
                                     To   = '$ports = [ordered]@{ debug = 8080 }' }
            'guest-port-list'   = @{ File = 'Get-MiOS.ps1'
                                     From = "Get-MiosVendorBoundedList -Section 'firewall.windows' -Key 'expose'"
                                     To   = "Get-MiosVendorBoundedList -Section 'firewall' -Key 'open_ports'" }
            'operator-widening' = @{ File = 'Get-MiOS.ps1'
                                     From = 'if (@($bound.Addresses | Where-Object { Test-MiosPrefixWithin -Inner $cidr -Outer $_ }).Count) { $kept += $cidr }'
                                     To   = 'if ($true) { $kept += $cidr }' }
            'mask-drift'        = @{ File = 'Get-MiOS.ps1'
                                     From = 'ForEach-Object { ConvertTo-MiosCanonicalPrefix ([string]$_) }'
                                     To   = 'ForEach-Object { [string]$_ }' }
            'loopback-in-nat'   = @{ File = 'Get-MiOS.ps1'
                                     From = "`$mirrored = (`$NetworkingMode -ieq 'mirrored')"
                                     To   = '$mirrored = $true' }
            'mode-upgrade'      = @{ File = 'build-mios.ps1'
                                     From = "if (`$raw -ieq 'NAT') { return 'NAT' }"
                                     To   = "if (`$raw -ieq 'NAT') { if (`$WindowsBuild -ge 22621) { return 'mirrored' }; return 'NAT' }" }
            'firewall-stripped' = @{ File = 'build-mios.ps1'
                                     From = "`$defaultKeys['firewall'] = `$fwall.ToString().ToLowerInvariant()"
                                     To   = '$null = $fwall' }
            'defender-unscoped' = @{ File = 'build-mios.ps1'
                                     From = '-Profile $profileText -RemoteAddress $plan.RemoteAddresses -ErrorAction Stop | Out-Null'
                                     To   = '-Profile $profileText -ErrorAction Stop | Out-Null' }
        }
        if ($Plant -and -not $plants.ContainsKey($Plant)) { throw "Unknown plant '$Plant'." }

        function global:Get-FixtureSource([string]$File, [string[]]$Names, [string]$Plant, [hashtable]$Plants, [string]$Root, [switch]$Probe) {
            $tokens = $null; $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $File), [ref]$tokens, [ref]$errors)
            if ($errors.Count) { throw "$File does not parse: $($errors[0].Message)" }
            $defs = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $Names }, $true))
            foreach ($n in $Names) { if (@($defs | Where-Object Name -eq $n).Count -ne 1) { throw "$File`: missing or duplicate function $n" } }
            $text = ($defs | ForEach-Object { $_.Extent.Text }) -join "`n"
            if ($Plant -and $Plants[$Plant].File -eq $File -and (-not $Probe -or $text.Contains($Plants[$Plant].From))) {
                $from = $Plants[$Plant].From
                $count = ([regex]::Matches($text, [regex]::Escape($from))).Count
                if ($count -ne 1) { throw "Plant '$Plant' must match $File exactly once (matched $count)." }
                $text = $text.Replace($from, $Plants[$Plant].To)
            }
            return $text
        }

        $getNames = @('Split-MiosTomlKeyLine', 'Get-MiosTomlValue', 'Get-MiosTomlTableArray', 'Get-MiosTomlStringArray',
            'Get-MiosVendorBoundedList', 'Get-MiosWslServicePortPlan', 'ConvertTo-MiosNetworkPrefix', 'ConvertTo-MiosCanonicalPrefix',
            'Test-MiosPrefixWithin', 'Resolve-MiosWslRemoteScope', 'Resolve-MiosWslServiceScope', 'Sync-MiosWslServicePortRules',
            'Test-MiosWslVmCreator', 'Register-MiosWslVmCreator', 'Set-MiosWslFirewallPolicy', 'Resolve-MiosWslNetworkingMode',
            'Get-MiosWslExperimentalLines', 'Get-MiosWslConfigText')
        $getText = Get-FixtureSource -File 'Get-MiOS.ps1' -Names $getNames -Plant $Plant -Plants $plants -Root $RepoRoot
        . ([scriptblock]::Create(($getText -replace '(?m)^function\s+', 'function global:')))
        $global:GetMiosTomlValue = ${function:global:Get-MiosTomlValue}

        # build-mios.ps1 carries its own Get-MiosTomlValue and copies of the shared WSL helpers: load its functions into
        # a module so the two scripts' definitions never shadow each other. Its TOML reads go through Get-MiOS.ps1's
        # layered reader over the same fixture text; host-sizing and logging helpers are stubs.
        $buildNames = @('Get-MiosSsotPort', 'Resolve-MiosWslNetworkingMode', 'Get-MiosWslExperimentalLines', 'Repair-WslConfig',
            'Set-MiosWslConfig', 'Get-MiosLanExposurePlan', 'Set-MiosLanFirewallRules', 'Set-MiosLanPortProxy')
        $buildText = Get-FixtureSource -File 'build-mios.ps1' -Names $buildNames -Plant $Plant -Plants $plants -Root $RepoRoot
        $global:BuildMios = New-Module -Name 'MiosBuildFixture' -ScriptBlock ([scriptblock]::Create(@'
function Get-MiosTomlValue { param($Section, $Key, $Default, [switch]$VendorOnly, $SourcePath) & $global:GetMiosTomlValue -Section $Section -Key $Key -Default $Default }
function Get-MiosCpuMinimum { 4 }
function Resolve-MiosCpuAllocation { param($AvailableCpus, $RequestedCpus) $RequestedCpus }
function Write-Log { param($T, $L) $global:FwFixture.Log.Add([string]$T) }
function Log-Ok { param($T) Write-Log $T }
function Log-Info { param($T) Write-Log $T }
function Log-Warn { param($T) Write-Log ('WARN ' + $T) }
$DevDistro = 'MiOS-DEV'
'@ + "`n" + $buildText + "`nExport-ModuleMember -Function @()`n"))

        $global:WslVendorBase = @'
[firewall]
open_ports = [
  "forge_http",   # the guest firewalld list [it carries pgvector and must never drive Windows exposure]
  "pgvector",
  "llm_light",
]

[firewall.windows]
expose           = ["forge_http", "llm_light"]
profiles         = ["Private", "Domain"]
remote_addresses = ["LocalSubnet", "100.64.0.0/10", "fd7a:115c:a1e0::/48"]

[ports]
stack_id   = 0
ssh        = 8100
forge_http = 8400     # Forgejo web
llm_light  = 8500
pgvector   = 8600
searxng    = 8800

[ports.categories.edge]
base = 8050

[wsl2]
networking_mode       = "NAT"
localhost_forwarding  = true
firewall              = true
gui_applications      = true
dns_tunneling         = true
auto_proxy            = true
host_address_loopback = true

[bootstrap.dev_vm]
minimum_cpus = 4
'@
        $global:WslExpectedScope = @('100.101.102.103/32', '100.64.0.0/10', '172.24.160.0/20', '192.168.1.0/24', '2001:db8:1::/64', 'fd7a:115c:a1e0::/48')

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
                $LocalPorts = 'Any', $RemoteAddresses = 'Any', $Profiles = 'Any')
            if ($global:FwFixture.Rules.ContainsKey($Name)) { throw "Rule $Name already exists." }
            $global:FwFixture.Calls.Add("New $Name")
            $global:FwFixture.Rules[$Name] = [pscustomobject]@{ Name = $Name; DisplayName = $DisplayName; VMCreatorId = $VMCreatorId
                Direction = [string]$Direction; Action = [string]$Action; Enabled = 'True'; Protocol = [string]$Protocol; Profiles = [string]$Profiles
                LocalPorts = @($LocalPorts | ForEach-Object { [string]$_ }); RemoteAddresses = @($RemoteAddresses | ForEach-Object { [string]$_ }) }
        }
        function global:Set-NetFirewallHyperVRule {
            [CmdletBinding()]param($Name, $NewDisplayName, $Protocol, $LocalPorts, $RemoteAddresses, $Profiles)
            $global:FwFixture.Calls.Add("Set $Name")
            $r = $global:FwFixture.Rules[$Name]
            if ($NewDisplayName) { $r.DisplayName = $NewDisplayName }
            if ($Protocol) { $r.Protocol = [string]$Protocol }
            if ($LocalPorts) { $r.LocalPorts = @($LocalPorts | ForEach-Object { [string]$_ }) }
            if ($RemoteAddresses) { $r.RemoteAddresses = @($RemoteAddresses | ForEach-Object { [string]$_ }) }
            if ($Profiles) { $r.Profiles = [string]$Profiles }
        }
        function global:Remove-NetFirewallHyperVRule {
            [CmdletBinding()]param($Name)
            $global:FwFixture.Calls.Add("Remove $Name")
            $global:FwFixture.Rules.Remove($Name)
        }
        # Windows Defender (host) rules and the portproxy, used by build-mios.ps1.
        function global:New-NetFirewallRule {
            [CmdletBinding()]param($DisplayName, $Description, $Direction, $Action, $Protocol, $LocalPort, $Profile = 'Any', $RemoteAddress = 'Any')
            $global:FwFixture.HostRules[$DisplayName] = [pscustomobject]@{ DisplayName = $DisplayName; Port = [string]$LocalPort
                Profile = [string]$Profile; RemoteAddress = @($RemoteAddress | ForEach-Object { [string]$_ }); Action = [string]$Action }
        }
        function global:Get-NetFirewallRule {
            [CmdletBinding()]param($DisplayName)
            @($global:FwFixture.HostRules.Values | Where-Object { $_.DisplayName -like $DisplayName })
        }
        function global:Set-NetFirewallRule {
            [CmdletBinding()]param($DisplayName, $Enabled, $Action, $Direction, $Profile, $RemoteAddress)
            $r = $global:FwFixture.HostRules[$DisplayName]
            $r.Profile = [string]$Profile; $r.RemoteAddress = @($RemoteAddress | ForEach-Object { [string]$_ })
        }
        function global:Remove-NetFirewallRule { [CmdletBinding()]param($DisplayName) [void]$global:FwFixture.HostRules.Remove($DisplayName) }
        function global:Get-NetFirewallPortFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject) process { } }
        function global:Set-NetFirewallPortFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject, $Protocol, $LocalPort) process { } }
        function global:netsh { $global:FwFixture.Netsh.Add(($args -join ' ')); $global:LASTEXITCODE = 0 }
        function global:wsl.exe { $global:LASTEXITCODE = 0; '2: eth0    inet 172.24.170.9/20 brd 172.24.175.255 scope global eth0' }
        function global:Get-Service { [CmdletBinding()]param($Name, $ErrorAction) [pscustomobject]@{ Status = 'Running' } }

        function global:Reset-FwFixture([string]$Vendor = $global:WslVendorBase, [string]$Operator = '') {
            $global:FwFixture = @{ Vendor = $Vendor; Operator = $Operator; Rules = @{}; Policy = $null; HostRules = @{}
                PolicySets = New-Object System.Collections.Generic.List[string]; Calls = New-Object System.Collections.Generic.List[string]
                Netsh = New-Object System.Collections.Generic.List[string]; Log = New-Object System.Collections.Generic.List[string] }
        }
        function global:Add-ForeignRule([string]$Name, [string]$Creator = $global:WslCreator) {
            $global:FwFixture.Rules[$Name] = [pscustomobject]@{ Name = $Name; DisplayName = $Name; VMCreatorId = $Creator; Direction = 'Inbound'
                Action = 'Allow'; Enabled = 'True'; Protocol = 'TCP'; LocalPorts = @('9999'); RemoteAddresses = @('Any'); Profiles = 'Any' }
        }
        function global:Get-ServiceRules { @($global:FwFixture.Rules.Values | Where-Object { $_.Name -like 'MiOS-DEV-Port-*' } | Sort-Object Name) }
        function global:Invoke-Sync { Sync-MiosWslServicePortRules -Creator $global:WslCreator 6>$null }
        function global:Invoke-Build([string]$Command, [hashtable]$Arguments = @{}) { & $global:BuildMios { param($c, $a) & $c @a 6>$null } $Command $Arguments }
        function global:New-WslHome([string]$Text) {
            $dir = Join-Path ([IO.Path]::GetTempPath()) ('mios-wsl-' + [guid]::NewGuid().ToString('N'))
            $null = New-Item -ItemType Directory -Path $dir
            if ($null -ne $Text) { [IO.File]::WriteAllText((Join-Path $dir '.wslconfig'), $Text) }
            $global:WslHome = $dir; $env:USERPROFILE = $dir
            return (Join-Path $dir '.wslconfig')
        }
        $global:SavedUserProfile = $env:USERPROFILE
    }

    AfterAll { $env:USERPROFILE = $global:SavedUserProfile; Remove-Module MiosBuildFixture -ErrorAction SilentlyContinue }

    Describe 'MiOS-DEV service ports on the WSL Hyper-V firewall' {
        BeforeEach { Reset-FwFixture }

        It 'rule ports equal exactly the SSOT [firewall].open_ports ports' {
            # Name kept from the first suite; the selector is now [firewall.windows].expose.
            $null = Invoke-Sync
            $got = @(Get-ServiceRules | ForEach-Object { "$($_.Name)=$($_.LocalPorts -join ',')" })
            $got | Should -Be @('MiOS-DEV-Port-forge-http=8400', 'MiOS-DEV-Port-llm-light=8500')
        }

        It 'opens [firewall.windows].expose and never the guest list, so pgvector stays closed' {
            $null = Invoke-Sync
            @(Get-ServiceRules | ForEach-Object { $_.LocalPorts[0] }) | Should -Not -Contain '8600'
            @(Get-ServiceRules).Count | Should -Be 2
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

        It 'every service rule is restricted to the SSOT profiles, never Any' {
            $null = Invoke-Sync
            foreach ($r in Get-ServiceRules) { $r.Profiles | Should -Be 'Domain,Private' }
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
            (Get-ServiceRules).Count | Should -Be 2
        }

        It 'is idempotent: a second run changes nothing' {
            $null = Invoke-Sync
            $global:FwFixture.Calls.Clear()
            $null = Invoke-Sync
            $global:FwFixture.Calls.Count | Should -Be 0
        }

        It 'is idempotent when Windows reads addresses back in mask form' {
            $null = Invoke-Sync
            foreach ($r in Get-ServiceRules) {
                $r.RemoteAddresses = @('100.101.102.103', '100.64.0.0/255.192.0.0', '172.24.160.0/255.255.240.0', '192.168.1.0/255.255.255.0',
                    '2001:db8:1::/64', 'fd7a:115c:a1e0::/48')
                $r.Profiles = 'Private, Domain'
            }
            $global:FwFixture.Calls.Clear()
            $null = Invoke-Sync
            $global:FwFixture.Calls.Count | Should -Be 0
        }

        It 'removes the rule of a port that left SSOT and keeps the rest untouched' {
            $null = Invoke-Sync
            $global:FwFixture.Calls.Clear()
            $global:FwFixture.Vendor = $global:WslVendorBase.Replace('expose           = ["forge_http", "llm_light"]', 'expose           = ["forge_http"]')
            $result = Invoke-Sync
            Get-ServiceRules | ForEach-Object Name | Should -Be 'MiOS-DEV-Port-forge-http'
            $global:FwFixture.Calls | Should -Be 'Remove MiOS-DEV-Port-llm-light'
            $result.Removed | Should -Be 'MiOS-DEV-Port-llm-light'
        }

        It 'corrects a rule whose scope, port or profile drifted, in place' {
            $null = Invoke-Sync
            $r = $global:FwFixture.Rules['MiOS-DEV-Port-forge-http']
            $r.RemoteAddresses = @('Any'); $r.LocalPorts = @('22'); $r.Profiles = 'Any'
            $global:FwFixture.Calls.Clear()
            $null = Invoke-Sync
            $global:FwFixture.Calls | Should -Be 'Set MiOS-DEV-Port-forge-http'
            $r.LocalPorts | Should -Be '8400'
            $r.Profiles | Should -Be 'Domain,Private'
            @($r.RemoteAddresses | Sort-Object) | Should -Be $global:WslExpectedScope
        }

        It 'recreates a rule whose action, direction or creator cannot be corrected in place' {
            $null = Invoke-Sync
            $global:FwFixture.Rules['MiOS-DEV-Port-forge-http'].Action = 'Block'
            $global:FwFixture.Rules['MiOS-DEV-Port-llm-light'].VMCreatorId = '{11111111-1111-1111-1111-111111111111}'
            $global:FwFixture.Calls.Clear()
            $null = Invoke-Sync
            $global:FwFixture.Calls | Should -Contain 'Remove MiOS-DEV-Port-forge-http'
            $global:FwFixture.Calls | Should -Contain 'New MiOS-DEV-Port-forge-http'
            $global:FwFixture.Calls | Should -Contain 'New MiOS-DEV-Port-llm-light'
            foreach ($r in Get-ServiceRules) { $r.Action | Should -Be 'Allow'; [guid]$r.VMCreatorId | Should -Be ([guid]$global:WslCreator) }
        }

        It 'shifts every port by [ports].stack_id * 10000' {
            Reset-FwFixture -Vendor $global:WslVendorBase.Replace('stack_id   = 0', 'stack_id   = 1')
            $null = Invoke-Sync
            @(Get-ServiceRules | ForEach-Object { $_.LocalPorts[0] }) | Should -Be @('18400', '18500')
        }

        It 'opens nothing for an expose key without a [ports] value' {
            Reset-FwFixture -Vendor $global:WslVendorBase.Replace('["forge_http", "llm_light"]', '["forge_http", "llm_light", "ghost_service"]')
            $result = Invoke-Sync
            (Get-ServiceRules).Count | Should -Be 2
            ($result.Refused -join ';') | Should -Match 'ghost_service'
        }

        It 'refuses unscoped remote addresses, opens nothing and closes what was open' {
            $null = Invoke-Sync
            $global:FwFixture.Vendor = $global:WslVendorBase.Replace('["LocalSubnet", "100.64.0.0/10", "fd7a:115c:a1e0::/48"]', '["0.0.0.0/0", "::/0", "Any", "0.0.0.0"]')
            $result = Invoke-Sync
            $result.Status | Should -Be 'unscoped'
            (Get-ServiceRules).Count | Should -Be 0
        }

        It 'the operator layer can narrow the scope, the ports and the profiles but never widen them' {
            Reset-FwFixture -Operator "[firewall.windows]`nexpose = [`"forge_http`", `"pgvector`"]`nprofiles = [`"Private`", `"Public`"]`nremote_addresses = [`"192.168.1.0/25`", `"10.0.0.0/8`"]`n"
            $result = Invoke-Sync
            Get-ServiceRules | ForEach-Object Name | Should -Be 'MiOS-DEV-Port-forge-http'
            foreach ($r in Get-ServiceRules) {
                $r.RemoteAddresses | Should -Be '192.168.1.0/25'
                $r.Profiles | Should -Be 'Private'
            }
            $text = $result.Refused -join ';'
            $text | Should -Match 'pgvector'
            $text | Should -Match 'Public'
            $text | Should -Match '10.0.0.0/8'
        }

        It 'leaves [wsl2.inbound] rules and foreign rules alone' {
            Add-ForeignRule 'MiOS-WSL-operator'
            Add-ForeignRule 'ThirdParty'
            $null = Invoke-Sync
            $global:FwFixture.Rules.ContainsKey('MiOS-WSL-operator') | Should -BeTrue
            $global:FwFixture.Rules.ContainsKey('ThirdParty') | Should -BeTrue
        }

        It 'degrades with WSL-SERVICE-PORTS-UNSUPPORTED where the rule cmdlets are missing' {
            $saved = ${function:global:Set-NetFirewallHyperVRule}
            Remove-Item Function:\Set-NetFirewallHyperVRule
            Get-Command Set-NetFirewallHyperVRule -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
            try { $out = @(Sync-MiosWslServicePortRules -Creator $global:WslCreator 6>&1) }
            finally { Set-Item function:global:Set-NetFirewallHyperVRule $saved }
            ($out | Where-Object { $_ -is [Management.Automation.InformationRecord] } | ForEach-Object { [string]$_ }) -join "`n" |
                Should -Match 'WSL-SERVICE-PORTS-UNSUPPORTED'
            ($out | Where-Object { $_ -isnot [Management.Automation.InformationRecord] }).Status | Should -Be 'unsupported'
            $global:FwFixture.Calls.Count | Should -Be 0
        }
    }

    Describe 'One SSOT networking mode across every .wslconfig writer' {
        BeforeEach { Reset-FwFixture }

        It 'the Get-MiOS.ps1 and build-mios.ps1 copies of the shared WSL helpers are identical' {
            foreach ($n in 'Resolve-MiosWslNetworkingMode', 'Get-MiosWslExperimentalLines') {
                $texts = foreach ($f in 'Get-MiOS.ps1', 'build-mios.ps1') {
                    Get-FixtureSource -File $f -Names @($n) -Plant $Plant -Plants $global:WslPlants -Root $global:WslRepoRoot -Probe
                }
                $texts[1].Replace("`r`n", "`n") | Should -BeExactly $texts[0].Replace("`r`n", "`n") -Because "$n must be one answer in both installers"
            }
        }

        It 'Get-MiOS.ps1 keeps SSOT NAT as NAT on Windows 11 and downgrades mirrored only below 22621' {
            Resolve-MiosWslNetworkingMode -WindowsBuild 26100 6>$null | Should -Be 'NAT'
            $global:FwFixture.Vendor = $global:WslVendorBase.Replace('networking_mode       = "NAT"', 'networking_mode       = "mirrored"')
            Resolve-MiosWslNetworkingMode -WindowsBuild 26100 6>$null | Should -Be 'mirrored'
            Resolve-MiosWslNetworkingMode -WindowsBuild 19045 6>$null | Should -Be 'NAT'
            $global:FwFixture.Vendor = $global:WslVendorBase.Replace('networking_mode       = "NAT"', 'networking_mode       = "bridged"')
            Resolve-MiosWslNetworkingMode -WindowsBuild 26100 6>$null | Should -Be 'NAT'
        }

        It 'build-mios.ps1 keeps SSOT NAT as NAT on Windows 11' {
            Invoke-Build 'Resolve-MiosWslNetworkingMode' @{ WindowsBuild = 26100 } | Should -Be 'NAT'
            $global:FwFixture.Vendor = $global:WslVendorBase.Replace('networking_mode       = "NAT"', 'networking_mode       = "mirrored"')
            Invoke-Build 'Resolve-MiosWslNetworkingMode' @{ WindowsBuild = 26100 } | Should -Be 'mirrored'
            Invoke-Build 'Resolve-MiosWslNetworkingMode' @{ WindowsBuild = 19045 } | Should -Be 'NAT'
        }

        It 'Get-MiosWslConfigText writes hostAddressLoopback only under mirrored networking' {
            $nat = Get-MiosWslConfigText -Existing "[experimental]`nhostAddressLoopback=true`nsparseVhd=true" -ManagedLines @('networkingMode=NAT') -Firewall $true -HostAddressLoopback $true
            $nat | Should -Not -Match 'hostAddressLoopback'
            $nat | Should -Match 'sparseVhd=true'
            $nat | Should -Match '(?m)^firewall=true'
            $mir = Get-MiosWslConfigText -Existing '' -ManagedLines @('networkingMode=mirrored') -Firewall $true -HostAddressLoopback $true
            $mir | Should -Match '(?ms)^\[experimental\]\r?\nhostAddressLoopback=true'
        }

        It 'Repair-WslConfig renders the SSOT mode, keeps firewall=true and manages hostAddressLoopback' {
            $cfg = New-WslHome "[wsl2]`nnetworkingMode=mirrored`nmemory=8GB`n[experimental]`nhostAddressLoopback=true`n"
            Invoke-Build 'Repair-WslConfig'
            $text = [IO.File]::ReadAllText($cfg)
            $text | Should -Match '(?m)^networkingMode=NAT\r?$'
            $text | Should -Match '(?m)^firewall=true\r?$'
            $text | Should -Match '(?m)^memory=8GB\r?$'
            $text | Should -Not -Match 'hostAddressLoopback'
        }

        It 'Set-MiosWslConfig writes the SSOT mode and firewall and never strips firewall' {
            $cfg = New-WslHome "[wsl2]`nnetworkingMode=mirrored`nfirewall=true`nmemory=8GB`n"
            Invoke-Build 'Set-MiosWslConfig' @{ RamGB = 8; Cpus = 4; NoShutdown = $true }
            $text = [IO.File]::ReadAllText($cfg)
            $text | Should -Match '(?m)^networkingMode=NAT\r?$'
            $text | Should -Match '(?m)^firewall=true\r?$'
            $text | Should -Match '(?m)^localhostForwarding=true\r?$'
            $text | Should -Not -Match 'hostAddressLoopback'
            $fresh = New-WslHome "[wsl2]`nmemory=8GB`n"
            Invoke-Build 'Set-MiosWslConfig' @{ RamGB = 8; Cpus = 4; NoShutdown = $true }
            [IO.File]::ReadAllText($fresh) | Should -Match '(?m)^firewall=true\r?$'
        }

        It 'Set-MiosWslConfig under SSOT mirrored writes hostAddressLoopback and drops localhostForwarding' {
            $global:FwFixture.Vendor = $global:WslVendorBase.Replace('networking_mode       = "NAT"', 'networking_mode       = "mirrored"')
            $cfg = New-WslHome "[wsl2]`nnetworkingMode=NAT`nlocalhostForwarding=true`n"
            # The resolver reads the real Windows build: only assert mirrored output where this host could run it.
            $saved = & $global:BuildMios { ${function:script:Resolve-MiosWslNetworkingMode} }
            if ([Environment]::OSVersion.Version.Build -lt 22621) {
                & $global:BuildMios { Set-Item function:script:Resolve-MiosWslNetworkingMode { param([int]$WindowsBuild) 'mirrored' } }
            }
            try { Invoke-Build 'Set-MiosWslConfig' @{ RamGB = 8; Cpus = 4; NoShutdown = $true } }
            finally { & $global:BuildMios { param($f) Set-Item function:script:Resolve-MiosWslNetworkingMode $f } $saved }
            $text = [IO.File]::ReadAllText($cfg)
            $text | Should -Match '(?m)^networkingMode=mirrored\r?$'
            $text | Should -Match '(?ms)^\[experimental\]\r?\nhostAddressLoopback=true'
            $text | Should -Not -Match 'localhostForwarding'
        }
    }

    Describe 'Windows Defender rules and portproxy from [firewall.windows]' {
        BeforeEach { Reset-FwFixture }

        It 'creates a Defender rule only for each expose port, scoped to the SSOT remote addresses and profiles' {
            Invoke-Build 'Set-MiosLanFirewallRules'
            $rules = @($global:FwFixture.HostRules.Values | Sort-Object DisplayName)
            @($rules | ForEach-Object Port) | Should -Be @('8400', '8500')
            foreach ($r in $rules) {
                $r.RemoteAddress | Should -Be @('LocalSubnet', '100.64.0.0/10', 'fd7a:115c:a1e0::/48')
                $r.Profile | Should -Be 'Private,Domain'
            }
        }

        It 'refuses an unscoped remote list with LAN-FIREWALL-UNSCOPED and removes the MiOS rules' {
            Invoke-Build 'Set-MiosLanFirewallRules'
            $global:FwFixture.Vendor = $global:WslVendorBase.Replace('["LocalSubnet", "100.64.0.0/10", "fd7a:115c:a1e0::/48"]', '["Any", "0.0.0.0/0"]')
            Invoke-Build 'Set-MiosLanFirewallRules'
            $global:FwFixture.HostRules.Count | Should -Be 0
            ($global:FwFixture.Log -join "`n") | Should -Match 'LAN-FIREWALL-UNSCOPED'
        }

        It 'removes the Defender rule of a service that left expose' {
            Invoke-Build 'Set-MiosLanFirewallRules'
            $global:FwFixture.Vendor = $global:WslVendorBase.Replace('expose           = ["forge_http", "llm_light"]', 'expose           = ["forge_http"]')
            Invoke-Build 'Set-MiosLanFirewallRules'
            @($global:FwFixture.HostRules.Keys) | Should -Be @('MiOS - forge_http (8400/tcp)')
        }

        It 'forwards only expose ports through the portproxy under NAT' {
            Invoke-Build 'Set-MiosLanPortProxy'
            $adds = @($global:FwFixture.Netsh | Where-Object { $_ -match ' add v4tov4 ' })
            @($adds | ForEach-Object { [regex]::Match($_, 'listenport=([0-9]+)').Groups[1].Value }) | Should -Be @('8400', '8500')
            ($adds -join "`n") | Should -Not -Match 'listenport=8600'
        }
    }

    Describe 'SSOT readers' {
        BeforeEach { Reset-FwFixture }

        It 'reads a multi-line string array with comments' {
            $got = Get-MiosTomlStringArray -Section 'firewall' -Key 'open_ports'
            $got | Should -Be @('forge_http', 'pgvector', 'llm_light')
        }

        It 'refuses a non-string array element' {
            Reset-FwFixture -Vendor "[firewall.windows]`nexpose = [`"ssh`", 22]`n"
            { Get-MiosTomlStringArray -Section 'firewall.windows' -Key 'expose' } | Should -Throw
        }

        It 'returns null when no layer declares the key' {
            Get-MiosTomlStringArray -Section 'firewall' -Key 'absent' | Should -BeNullOrEmpty
        }

        It 'computes and canonicalises network prefixes' {
            ConvertTo-MiosNetworkPrefix -Address ([Net.IPAddress]::Parse('192.168.1.37')) -PrefixLength 24 | Should -Be '192.168.1.0/24'
            ConvertTo-MiosNetworkPrefix -Address ([Net.IPAddress]::Parse('2001:db8:1::5')) -PrefixLength 64 | Should -Be '2001:db8:1::/64'
            ConvertTo-MiosCanonicalPrefix '100.64.0.0/255.192.0.0' | Should -Be '100.64.0.0/10'
            ConvertTo-MiosCanonicalPrefix '100.101.102.103' | Should -Be '100.101.102.103/32'
            Test-MiosPrefixWithin -Inner '192.168.1.0/25' -Outer '192.168.1.0/24' | Should -BeTrue
            Test-MiosPrefixWithin -Inner '10.0.0.0/8' -Outer '192.168.1.0/24' | Should -BeFalse
        }

        It 'resolves LocalSubnet to host subnets without loopback or link-local' {
            (Resolve-MiosWslRemoteScope -Entries @('LocalSubnet', '100.64.0.0/10', 'fd7a:115c:a1e0::/48')).Addresses | Should -Be $global:WslExpectedScope
        }

        It 'resolves the system SSOT: every [firewall.windows].expose key has a [ports] value and pgvector is not exposed' {
            $sys = if ($env:MIOS_SYSTEM_TOML) { $env:MIOS_SYSTEM_TOML } else { Join-Path (Split-Path $global:WslRepoRoot -Parent) 'mios/usr/share/mios/mios.toml' }
            if (-not (Test-Path -LiteralPath $sys)) { Set-ItResult -Skipped -Because "no system mios.toml at $sys (set MIOS_SYSTEM_TOML)"; return }
            $text = [IO.File]::ReadAllText($sys)
            if ($text -notmatch '(?m)^\[firewall\.windows\]') { Set-ItResult -Skipped -Because "$sys predates [firewall.windows]"; return }
            Reset-FwFixture -Vendor $text
            $plan = Get-MiosWslServicePortPlan
            $plan.Refused | Should -BeNullOrEmpty
            $plan.Ports.Count | Should -BeGreaterThan 0
            @($plan.Ports.Keys) | Should -Not -Contain 'pgvector'
            $remote = Get-MiosTomlStringArray -Section 'firewall.windows' -Key 'remote_addresses'
            $remote | Should -Contain '100.64.0.0/10'
            $profiles = Get-MiosTomlStringArray -Section 'firewall.windows' -Key 'profiles'
            $profiles | Should -Not -Contain 'Public'
        }
    }
}

function Invoke-Suite([string]$Plant) {
    $cfg = New-PesterConfiguration
    $cfg.Run.Container = New-PesterContainer -ScriptBlock $suite -Data @{ RepoRoot = $repoRoot; Plant = $Plant }
    $cfg.Run.PassThru = $true
    $cfg.Output.Verbosity = if ($Plant) { 'None' } else { 'Detailed' }
    return Invoke-Pester -Configuration $cfg
}

$clean = Invoke-Suite ''
if ($clean.Result -ne 'Passed' -or $clean.FailedCount -gt 0 -or $clean.PassedCount -eq 0) {
    throw "WSL host-network suite did not pass ($($clean.FailedCount) failed, $($clean.PassedCount) passed)."
}
Write-Host "PASS clean suite ($($clean.PassedCount) passed, $($clean.SkippedCount) skipped)"
if (-not $PlantDefect) { return }

$plants = [ordered]@{
    'unscoped'          = 'every service rule is scoped to the SSOT remote addresses'
    'profile-any'       = 'every service rule is restricted to the SSOT profiles, never Any'
    'default-allow'     = 'never sets the WSL default inbound action to anything but Block'
    'non-ssot-port'     = 'rule ports equal exactly the SSOT [firewall].open_ports ports'
    'guest-port-list'   = 'opens [firewall.windows].expose and never the guest list, so pgvector stays closed'
    'operator-widening' = 'the operator layer can narrow the scope, the ports and the profiles but never widen them'
    'mask-drift'        = 'is idempotent when Windows reads addresses back in mask form'
    'loopback-in-nat'   = 'Get-MiosWslConfigText writes hostAddressLoopback only under mirrored networking'
    'mode-upgrade'      = 'build-mios.ps1 keeps SSOT NAT as NAT on Windows 11'
    'firewall-stripped' = 'Set-MiosWslConfig writes the SSOT mode and firewall and never strips firewall'
    'defender-unscoped' = 'creates a Defender rule only for each expose port, scoped to the SSOT remote addresses and profiles'
}
$bad = 0
foreach ($plant in $plants.Keys) {
    $r = Invoke-Suite $plant
    $failed = @($r.Failed | ForEach-Object { $_.Name })
    if ($failed -contains $plants[$plant]) { Write-Host "PASS plant '$plant' fails '$($plants[$plant])'" }
    else { Write-Host "FAIL plant '$plant' left '$($plants[$plant])' green (failed: $($failed -join '; '))"; $bad++ }
}
if ($bad) { throw "$bad planted defect(s) were not caught." }
