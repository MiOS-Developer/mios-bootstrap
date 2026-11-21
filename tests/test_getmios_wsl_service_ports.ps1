# AI-hint: Pester fixture (run under pwsh on Linux or Windows) for MiOS-DEV's Windows-host networking: the WSL Hyper-V service-port rules in Get-MiOS.ps1, the .wslconfig networkingMode/firewall/hostAddressLoopback rendered by every writer, the Windows Defender rules, portproxy and portproxy refresh task in build-mios.ps1, all from mios.toml [firewall.windows] and [wsl2], and the dev VM's own firewalld ports and host-network drop-ins in build-mios.ps1's overlay. -PlantDefect plants each named defect into the extracted source and requires its named test to fail.
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
        # On Windows the NetSecurity commands are functions, so a mid-suite auto-load (any Get-Command of one of them)
        # imports them into the global scope over the firewall stubs below. Load it first; the stubs then stay in front.
        if (Get-Module -ListAvailable -Name NetSecurity) { Import-Module NetSecurity -ErrorAction Stop }
        # ScheduledTasks is the same kind of module, for the portproxy refresh task stubs.
        if (Get-Module -ListAvailable -Name ScheduledTasks) { Import-Module ScheduledTasks -ErrorAction Stop }
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
            'profiles-empty-open' = @{ File = 'Get-MiOS.ps1'
                                     From = 'if (-not $scope.Addresses.Count -or -not $profiles.Count) {'
                                     To   = 'if (-not $scope.Addresses.Count) {' }
            'operator-port-redirect' = @{ File = 'Get-MiOS.ps1'
                                     From = "`$base = Get-MiosTomlValue -Section 'ports' -Key `$key -Default 0 -VendorOnly"
                                     To   = "`$base = Get-MiosTomlValue -Section 'ports' -Key `$key -Default 0" }
            'defender-refresh-unscoped' = @{ File = 'build-mios.ps1'
                                     From = "-Profile `$profileText -RemoteAddress `$plan.RemoteAddresses -ErrorAction Stop`n                `$existing"
                                     To   = "-Profile `$profileText -ErrorAction Stop`n                `$existing" }
            'defender-operator-widening' = @{ File = 'build-mios.ps1'
                                     From = 'if (@($vendor | Where-Object { $_ -ieq $item }).Count) { if (-not @($kept'
                                     To   = 'if ($true) { if (-not @($kept' }
            'portproxy-stale'   = @{ File = 'build-mios.ps1'
                                     From = 'if ($owned.ContainsKey($listen) -and $wanted -notcontains $listen) {'
                                     To   = 'if ($false) {' }
            'defender-unscoped' = @{ File = 'build-mios.ps1'
                                     From = '-Profile $profileText -RemoteAddress $plan.RemoteAddresses -ErrorAction Stop | Out-Null'
                                     To   = '-Profile $profileText -ErrorAction Stop | Out-Null' }
            'portproxy-distro'  = @{ File = 'build-mios.ps1'
                                     From = '& wsl.exe -d $distro --user root'
                                     To   = '& wsl.exe -d $DevDistro --user root' }
            # Statement-level plants in build-mios.ps1's overlay (outside the lifted functions).
            'devvm-fw-literal'  = @{ File = 'build-mios.ps1#overlay'
                                     From = '$_p = Get-MiosSsotPort -Key $_k'
                                     To   = '$_p = if ($_k -eq ''cockpit'') { 8090 } else { Get-MiosSsotPort -Key $_k }' }
            'owui-port-override' = @{ File = 'build-mios.ps1#overlay'
                                     From = '"mios-open-webui:" \'
                                     To   = '"mios-open-webui:Environment=PORT=3030" \' }
            'elevate-unconditionally' = @{ File = 'build-mios.ps1'
                                     From = 'if (-not $drift.Count -and -not $Force) {'
                                     To   = 'if ($false) {' }
            'drift-mask'        = @{ File = 'build-mios.ps1'
                                     From = 'if ($t -ieq ''LocalSubnet'') { ''LocalSubnet'' } else { ConvertTo-MiosCanonicalPrefix $t }'
                                     To   = 'if ($t -ieq ''LocalSubnet'') { ''LocalSubnet'' } else { $t }' }
            'projection-all-sections' = @{ File = 'build-mios.ps1'
                                     From = '$on = ($Matches[1] -cmatch ''^(firewall\.windows|wsl2|ports)$'')'
                                     To   = '$on = $true' }
            'request-any-layer' = @{ File = 'build-mios.ps1'
                                     From = 'if (-not (Test-MiosLanExposureLayerText $text)) {'
                                     To   = 'if ($false) {' }
            'request-any-address' = @{ File = 'build-mios.ps1'
                                     From = 'if ($address -and -not (Test-MiosWslNatAddress $address)) {'
                                     To   = 'if ($false) {' }
            'reply-list'        = @{ File = 'build-mios.ps1'
                                     From = 'Lines = @(if ($null -ne $Lines) { $Lines.ToArray() })'
                                     To   = 'Lines = @($Lines)' }
            'refresh-any-port'  = @{ File = 'build-mios.ps1'
                                     From = 'if (-not $wanted.ContainsKey($listen) -or $connect -ne $listen'
                                     To   = 'if ($connect -ne $listen' }
            'refresh-adds'      = @{ File = 'build-mios.ps1'
                                     From = '$changed = @(); $failed = @()'
                                     To   = '$changed = @(); $failed = @(); foreach ($k in @($wanted.Keys)) { $null = & $Netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=$k connectaddress=$ip connectport=$k }' }
            'refresh-loopback'  = @{ File = 'build-mios.ps1'
                                     From = " -or `$target -like '127.*') { continue }"
                                     To   = ') { continue }' }
            'refresh-unbounded' = @{ File = 'build-mios.ps1'
                                     From = 'if (-not (Test-MiosWslNatAddress $ip)) {'
                                     To   = 'if ($false) {' }
            'refresh-principal' = @{ File = 'build-mios.ps1'
                                     From = "New-ScheduledTaskPrincipal -UserId 'S-1-5-18'"
                                     To   = 'New-ScheduledTaskPrincipal -UserId $OperatorSid' }
            'refresh-no-read-grant' = @{ File = 'build-mios.ps1'
                                     From = '(A;;FR;;;$OperatorSid)'
                                     To   = '' }
            'refresh-bound-missing' = @{ File = 'build-mios.ps1'
                                     From = "@('ConvertTo-MiosNetworkPrefix', 'Test-MiosPrefixWithin', 'Test-MiosWslNatAddress', 'Update-MiosLanPortProxyTarget')"
                                     To   = "@('Update-MiosLanPortProxyTarget')" }
            'refresh-drift-register' = @{ File = 'build-mios.ps1'
                                     From = "`$drift.Add('register the portproxy refresh task')"
                                     To   = "`$null = 'register the portproxy refresh task'" }
            'refresh-drift-remove' = @{ File = 'build-mios.ps1'
                                     From = "} elseif (`$task) { `$drift.Add('remove the portproxy refresh task') }"
                                     To   = '}' }
            'refresh-worker-skips' = @{ File = 'build-mios.ps1'
                                     From = 'try { Register-MiosLanPortProxyRefresh -OperatorSid $OperatorSid } catch'
                                     To   = 'try { } catch' }
        }
        if ($Plant -and -not $plants.ContainsKey($Plant)) { throw "Unknown plant '$Plant'." }

        function global:Get-FixtureSource([string]$File, [string[]]$Names, [string]$Plant, [hashtable]$Plants, [string]$Root, [switch]$Probe) {
            $tokens = $null; $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $Root $File), [ref]$tokens, [ref]$errors)
            if ($errors.Count) { throw "$File does not parse: $($errors[0].Message)" }
            $defs = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $Names }, $true))
            foreach ($n in $Names) { if (@($defs | Where-Object Name -eq $n).Count -ne 1) { throw "$File`: missing or duplicate function $n" } }
            $text = (($defs | ForEach-Object { $_.Extent.Text }) -join "`n").Replace("`r`n", "`n")
            if ($Plant -and $Plants[$Plant].File -eq $File -and (-not $Probe -or $text.Contains($Plants[$Plant].From))) {
                $from = $Plants[$Plant].From
                $count = ([regex]::Matches($text, [regex]::Escape($from))).Count
                if ($count -ne 1) { throw "Plant '$Plant' must match $File exactly once (matched $count)." }
                $text = $text.Replace($from, $Plants[$Plant].To)
            }
            return $text
        }

        # build-mios.ps1 with a '#overlay' plant applied: the overlay steps are statements inside a large function, so
        # these tests lift them from the whole file rather than from a function definition.
        function global:Get-OverlaySource {
            $text = [IO.File]::ReadAllText((Join-Path $global:WslRepoRoot 'build-mios.ps1')).Replace("`r`n", "`n")
            $p = $global:WslPlant
            if ($p -and $global:WslPlants[$p].File -eq 'build-mios.ps1#overlay') {
                $count = ([regex]::Matches($text, [regex]::Escape($global:WslPlants[$p].From))).Count
                if ($count -ne 1) { throw "Plant '$p' must match build-mios.ps1 exactly once (matched $count)." }
                $text = $text.Replace($global:WslPlants[$p].From, $global:WslPlants[$p].To)
            }
            return $text
        }
        # The statements from the $_fwServicePorts assignment through $_fwPortsStr, run in the build fixture's scope;
        # returns the dev VM firewalld port list it renders.
        function global:Invoke-DevVmFirewallRun {
            $ast = [Management.Automation.Language.Parser]::ParseInput((Get-OverlaySource), [ref]$null, [ref]$null)
            $a = $ast.Find({ param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$_fwServicePorts' }, $true)
            if (-not $a) { throw 'build-mios.ps1 has no $_fwServicePorts assignment' }
            $st = @($a.Parent.Statements); $i = [array]::IndexOf($st, $a); $j = $i
            while ($j -lt $st.Count -and $st[$j].Extent.Text -notmatch '^\$_fwPortsStr\s*=') { $j++ }
            if ($j -ge $st.Count) { throw 'no $_fwPortsStr after $_fwServicePorts' }
            $code = ($st[$i..$j] | ForEach-Object { $_.Extent.Text }) -join "`n"
            & $global:BuildMios { param($c) . ([scriptblock]::Create($c)); $_fwPortsStr } $code
        }
        $global:WslPlant = $Plant

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
        $buildNames = @('Get-MiosSsotPort', 'ConvertTo-MiosNetworkPrefix', 'Test-MiosPrefixWithin', 'Get-MiosVendorTomlValue', 'Resolve-MiosBuilderDistribution',
            'Resolve-MiosWslNetworkingMode', 'Get-MiosWslExperimentalLines', 'Repair-WslConfig',
            'Set-MiosWslConfig', 'Get-MiosLanExposurePlan', 'Set-MiosLanFirewallRules', 'Set-MiosLanPortProxy',
            'Resolve-MiosWslVmAddress', 'Get-MiosVendorPortSet', 'ConvertTo-MiosCanonicalPrefix', 'Get-MiosLanExposureDrift',
            'Get-MiosLanExposureLayers', 'Test-MiosLanExposureLayerText', 'Test-MiosWslNatAddress', 'Invoke-MiosLanExposureRequest',
            'Get-MiosLanExposureWorkerScript', 'Invoke-MiosLanExposure', 'ConvertTo-MiosLanExposureReply',
            'Update-MiosLanPortProxyTarget', 'Get-MiosLanPortProxyRefreshTask', 'Register-MiosLanPortProxyRefresh')
        $buildText = Get-FixtureSource -File 'build-mios.ps1' -Names $buildNames -Plant $Plant -Plants $plants -Root $RepoRoot
        # Invoke-MiosElevatedLanExposure is never lifted: it starts a UAC worker. Its stub records each hand-off instead.
        # Get-MiosTokenSid is the fixture account, so the refresh task resolves alike on Windows and Linux.
        $global:FixtureSid = 'S-1-5-21-1000-2000-3000-1001'
        $global:BuildMios = New-Module -Name 'MiosBuildFixture' -ScriptBlock ([scriptblock]::Create(@'
function Get-MiosTokenSid { $global:FixtureSid }
function Get-MiosTomlValue { param($Section, $Key, $Default, [switch]$VendorOnly, $SourcePath)
    if ($SourcePath) { return (& $global:GetMiosTomlValue -Section $Section -Key $Key -Default $Default -VendorOnly) }
    & $global:GetMiosTomlValue -Section $Section -Key $Key -Default $Default }
function Resolve-MiosTomlLayers {
    @(if ($global:FwFixture.Operator) { [pscustomobject]@{ Path = 'C:\Users\op\.config\mios\mios.toml'; Text = $global:FwFixture.Operator } }) +
        @([pscustomobject]@{ Path = 'C:\usr\share\mios\mios.toml'; Text = $global:FwFixture.Vendor }) }
function Invoke-MiosElevatedLanExposure { param([string]$WslAddress = '') $global:FwFixture.Elevations.Add($WslAddress) }
$script:IsAdmin = $false
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
        # The host's WSL virtual adapter is 172.24.160.1/20; the MiOS-DEV guest (wsl.exe below) is 172.24.170.9 inside it.
        function global:Get-NetIPAddress {
            [CmdletBinding()]param([string]$AddressState, [string]$AddressFamily)
            return @(
                @{ IPAddress = '192.168.1.37'; PrefixLength = 24; InterfaceAlias = 'Ethernet' }, @{ IPAddress = '127.0.0.1'; PrefixLength = 8; InterfaceAlias = 'Loopback Pseudo-Interface 1' },
                @{ IPAddress = '169.254.3.4'; PrefixLength = 16; InterfaceAlias = 'Ethernet 2' }, @{ IPAddress = 'fe80::1%12'; PrefixLength = 64; InterfaceAlias = 'Ethernet' },
                @{ IPAddress = '172.24.160.1'; PrefixLength = 20; InterfaceAlias = 'vEthernet (WSL (Hyper-V firewall))' }, @{ IPAddress = '100.101.102.103'; PrefixLength = 32; InterfaceAlias = 'Tailscale' },
                @{ IPAddress = '::1'; PrefixLength = 128; InterfaceAlias = 'Loopback Pseudo-Interface 1' }, @{ IPAddress = '2001:db8:1::5'; PrefixLength = 64; InterfaceAlias = 'Ethernet' }
            ) | ForEach-Object { [pscustomobject]$_ } | Where-Object { $AddressFamily -ne 'IPv4' -or $_.IPAddress -notmatch ':' }
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
                Profile = [string]$Profile; RemoteAddress = @($RemoteAddress | ForEach-Object { [string]$_ }); Action = [string]$Action
                Enabled = 'True'; Direction = [string]$Direction; Protocol = [string]$Protocol }
        }
        function global:Get-NetFirewallRule {
            [CmdletBinding()]param($DisplayName)
            @($global:FwFixture.HostRules.Values | Where-Object { $_.DisplayName -like $DisplayName })
        }
        function global:Set-NetFirewallRule {
            [CmdletBinding()]param($DisplayName, $Enabled, $Action, $Direction, $Profile, $RemoteAddress)
            $r = $global:FwFixture.HostRules[$DisplayName]
            # Like the real cmdlet, a parameter left unbound keeps the rule's current value.
            if ($PSBoundParameters.ContainsKey('Profile')) { $r.Profile = [string]$Profile }
            if ($PSBoundParameters.ContainsKey('RemoteAddress')) { $r.RemoteAddress = @($RemoteAddress | ForEach-Object { [string]$_ }) }
            foreach ($p in 'Enabled', 'Action', 'Direction') {
                if ($PSBoundParameters.ContainsKey($p)) { $r | Add-Member -NotePropertyName $p -NotePropertyValue ([string]$PSBoundParameters[$p]) -Force }
            }
        }
        function global:Remove-NetFirewallRule { [CmdletBinding()]param($DisplayName) [void]$global:FwFixture.HostRules.Remove($DisplayName) }
        # A rule's filters read back from (and, for the port filter, write back to) the rule itself.
        function global:Get-NetFirewallPortFilter {
            [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject)
            process { if ($InputObject) { [pscustomobject]@{ Rule = $InputObject; Protocol = $InputObject.Protocol; LocalPort = $InputObject.Port } } }
        }
        function global:Get-NetFirewallAddressFilter {
            [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject)
            process { if ($InputObject) { [pscustomobject]@{ RemoteAddress = $InputObject.RemoteAddress } } }
        }
        function global:Set-NetFirewallPortFilter {
            [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject, $Protocol, $LocalPort)
            process {
                if ($InputObject -and $InputObject.Rule) {
                    $InputObject.Rule | Add-Member -NotePropertyName Protocol -NotePropertyValue ([string]$Protocol) -Force
                    $InputObject.Rule.Port = [string]$LocalPort
                }
            }
        }
        function global:netsh {
            $line = $args -join ' '; $global:FwFixture.Netsh.Add($line); $global:LASTEXITCODE = 0
            if ($line -match 'portproxy show v4tov4') { return @($global:FwFixture.Proxy.Keys | ForEach-Object { "0.0.0.0         $_         $($global:FwFixture.Proxy[$_])  $_" }) }
            if ($line -match 'portproxy delete v4tov4 listenaddress=0\.0\.0\.0 listenport=([0-9]+)') { $global:FwFixture.Proxy.Remove($Matches[1]) }
            if ($line -match 'portproxy (add|set) v4tov4 listenaddress=0\.0\.0\.0 listenport=([0-9]+) connectaddress=(\S+)') { $global:FwFixture.Proxy[$Matches[2]] = $Matches[3] }
        }
        # The scheduled task store. Like Windows, Get-ScheduledTask shows a standard account only a task whose security
        # descriptor grants it read access, and reads the SYSTEM principal back by name.
        function global:New-ScheduledTaskAction { [CmdletBinding()]param($Execute, $Argument) [pscustomobject]@{ Execute = [string]$Execute; Arguments = [string]$Argument } }
        function global:New-ScheduledTaskTrigger { [CmdletBinding()]param([switch]$Once, $At, $RepetitionInterval) [pscustomobject]@{ Interval = $RepetitionInterval } }
        function global:New-ScheduledTaskPrincipal { [CmdletBinding()]param($UserId, $LogonType, $RunLevel) [pscustomobject]@{ UserId = [string]$UserId; LogonType = [string]$LogonType; RunLevel = [string]$RunLevel } }
        function global:New-ScheduledTaskSettingsSet {
            [CmdletBinding()]param([switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries, [switch]$StartWhenAvailable, $MultipleInstances, $ExecutionTimeLimit)
            [pscustomobject]@{ ExecutionTimeLimit = $ExecutionTimeLimit }
        }
        function global:New-ScheduledTask {
            [CmdletBinding()]param($Action, $Trigger, $Principal, $Settings, $Description)
            [pscustomobject]@{ Actions = @($Action); Triggers = @($Trigger); Principal = $Principal; Settings = $Settings; Description = [string]$Description; SecurityDescriptor = '' }
        }
        function global:Register-ScheduledTask {
            [CmdletBinding()]param($TaskPath, $TaskName, $InputObject, [switch]$Force)
            $user = [string]$InputObject.Principal.UserId
            if ($user -eq 'S-1-5-18') { $user = 'SYSTEM' }
            $global:FwFixture.TaskCalls.Add("Register $TaskPath$TaskName")
            $global:FwFixture.Tasks["$TaskPath$TaskName"] = [pscustomobject]@{ TaskPath = $TaskPath; TaskName = $TaskName; Actions = @($InputObject.Actions)
                Triggers = @($InputObject.Triggers); Principal = [pscustomobject]@{ UserId = $user; RunLevel = $InputObject.Principal.RunLevel }
                SecurityDescriptor = [string]$InputObject.SecurityDescriptor; Description = $InputObject.Description }
        }
        function global:Get-ScheduledTask {
            [CmdletBinding()]param($TaskPath, $TaskName)
            $t = $global:FwFixture.Tasks["$TaskPath$TaskName"]
            if ($t -and $t.SecurityDescriptor -match ('\(A;;F[AR];;;' + [regex]::Escape($global:FixtureSid) + '\)')) { $t }
        }
        function global:Unregister-ScheduledTask {
            [CmdletBinding()]param($TaskPath, $TaskName, [switch]$Confirm)
            $global:FwFixture.TaskCalls.Add("Unregister $TaskPath$TaskName")
            [void]$global:FwFixture.Tasks.Remove("$TaskPath$TaskName")
        }
        # The registry value WSL writes for the fixture account; Update-MiosLanPortProxyTarget reads it through -Read.
        $global:RefreshRead = { param($Key, $Name) if ($Name -eq 'NatIpAddress' -and $Key -like "Registry::HKEY_USERS\$global:FixtureSid\*") { $global:FwFixture.NatIp } }
        function global:Invoke-Refresh([int[]]$Ports = @(8400, 8500)) {
            Invoke-Build 'Update-MiosLanPortProxyTarget' @{ Ports = $Ports; OperatorSid = $global:FixtureSid; Netsh = 'netsh'; Read = $global:RefreshRead }
        }
        function global:Get-RefreshTask { $global:FwFixture.Tasks['\MiOS\MiOS-DEV-PortProxy-Refresh'] }
        # The registered distributions are the fixture's: --list answers them, and -d of any other name fails like WSL.
        function global:wsl.exe {
            $a = @($args | ForEach-Object { [string]$_ })
            $global:LASTEXITCODE = 0
            if ($a -contains '--list') { return @($global:FwFixture.Distros) }
            $i = [array]::IndexOf($a, '-d')
            if ($i -ge 0) {
                $global:FwFixture.Probes.Add($a[$i + 1])
                if ($global:FwFixture.Distros -notcontains $a[$i + 1]) { $global:LASTEXITCODE = 1; return 'There is no distribution with the supplied name.' }
            }
            '2: eth0    inet 172.24.170.9/20 brd 172.24.175.255 scope global eth0'
        }
        function global:Get-Service { [CmdletBinding()]param($Name, $ErrorAction) [pscustomobject]@{ Status = 'Running' } }

        function global:Reset-FwFixture([string]$Vendor = $global:WslVendorBase, [string]$Operator = '') {
            $global:FwFixture = @{ Vendor = $Vendor; Operator = $Operator; Rules = @{}; Policy = $null; HostRules = @{}
                PolicySets = New-Object System.Collections.Generic.List[string]; Calls = New-Object System.Collections.Generic.List[string]
                Netsh = New-Object System.Collections.Generic.List[string]; Log = New-Object System.Collections.Generic.List[string]; Proxy = @{}
                Distros = @('podman-MiOS-DEV'); Probes = New-Object System.Collections.Generic.List[string]
                Elevations = New-Object System.Collections.Generic.List[string]
                Tasks = @{}; TaskCalls = New-Object System.Collections.Generic.List[string]; NatIp = '172.24.170.9' }
        }
        function global:New-HostRule([string]$Name, [string]$Port) {
            [pscustomobject]@{ DisplayName = $Name; Port = $Port; Profile = 'Private,Domain'; Action = 'Allow'; Enabled = 'True'
                Direction = 'Inbound'; Protocol = 'TCP'; RemoteAddress = @('LocalSubnet', '100.64.0.0/10', 'fd7a:115c:a1e0::/48') }
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

        It 'opens no Hyper-V rule and closes open ones when the SSOT profiles resolve empty or to Any' {
            $null = Invoke-Sync
            (Get-ServiceRules).Count | Should -Be 2
            foreach ($bad in '[]', '["Any"]') {
                $global:FwFixture.Vendor = $global:WslVendorBase.Replace('profiles         = ["Private", "Domain"]', "profiles         = $bad")
                $result = Invoke-Sync
                $result.Status | Should -Be 'unscoped'
                (Get-ServiceRules).Count | Should -Be 0
            }
        }

        It 'an operator [ports] override cannot redirect an exposed key to another listener' {
            Reset-FwFixture -Operator "[ports]`nforge_http = 8600`nstack_id = 1`n"
            $null = Invoke-Sync
            @(Get-ServiceRules | ForEach-Object { $_.LocalPorts[0] }) | Should -Be @('8400', '8500')
        }

        It 'reads Hyper-V profiles back as flag values without drift' {
            $null = Invoke-Sync
            foreach ($r in Get-ServiceRules) { $r.Profiles = '3' }
            $global:FwFixture.Calls.Clear()
            $null = Invoke-Sync
            $global:FwFixture.Calls.Count | Should -Be 0
        }

        It 'leaves [wsl2.inbound] rules and foreign rules alone' {
            Add-ForeignRule 'MiOS-WSL-operator'
            Add-ForeignRule 'ThirdParty'
            $null = Invoke-Sync
            $global:FwFixture.Rules.ContainsKey('MiOS-WSL-operator') | Should -BeTrue
            $global:FwFixture.Rules.ContainsKey('ThirdParty') | Should -BeTrue
        }

        It 'degrades with WSL-SERVICE-PORTS-UNSUPPORTED where the rule cmdlets are missing' {
            # Removing the stub is not enough on Windows, where NetSecurity's own command stays resolvable: hide the name
            # from the presence probe itself. Every other name still resolves through the real cmdlet, invoked by its
            # CmdletInfo because Pester 6 has no implicit fall-through and also aliases the module-qualified name.
            $global:WslRealGetCommand = $ExecutionContext.InvokeCommand.GetCmdlet('Get-Command')
            Mock Get-Command { & $global:WslRealGetCommand @PesterBoundParameters }
            Mock Get-Command { } -ParameterFilter { $Name -contains 'Set-NetFirewallHyperVRule' }
            Get-Command Set-NetFirewallHyperVRule -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
            $out = @(Sync-MiosWslServicePortRules -Creator $global:WslCreator 6>&1)
            ($out | Where-Object { $_ -is [Management.Automation.InformationRecord] } | ForEach-Object { [string]$_ }) -join "`n" |
                Should -Match 'WSL-SERVICE-PORTS-UNSUPPORTED'
            ($out | Where-Object { $_ -isnot [Management.Automation.InformationRecord] }).Status | Should -Be 'unsupported'
            $global:FwFixture.Calls.Count | Should -Be 0
        }
    }

    Describe 'One SSOT networking mode across every .wslconfig writer' {
        BeforeEach { Reset-FwFixture }

        It 'the Get-MiOS.ps1 and build-mios.ps1 copies of the shared WSL helpers are identical' {
            foreach ($n in 'Resolve-MiosWslNetworkingMode', 'Get-MiosWslExperimentalLines', 'ConvertTo-MiosNetworkPrefix', 'Test-MiosPrefixWithin',
                    'ConvertTo-MiosCanonicalPrefix', 'Assert-MiosNoReparsePath', 'Set-MiosPrivateUserTomlAcl', 'Initialize-MiosPipePeerApi',
                    'Read-MiosPipeLine') {
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

        It 'refreshes an existing open Defender rule to the SSOT scope and profiles' {
            $global:FwFixture.HostRules['MiOS - forge_http (8400/tcp)'] = [pscustomobject]@{ DisplayName = 'MiOS - forge_http (8400/tcp)'; Port = '8400'
                Profile = 'Any'; RemoteAddress = @('Any'); Action = 'Allow' }
            Invoke-Build 'Set-MiosLanFirewallRules'
            $r = $global:FwFixture.HostRules['MiOS - forge_http (8400/tcp)']
            $r.RemoteAddress | Should -Be @('LocalSubnet', '100.64.0.0/10', 'fd7a:115c:a1e0::/48')
            $r.Profile | Should -Be 'Private,Domain'
        }

        It 'opens no Defender rule when the SSOT profiles resolve empty' {
            Reset-FwFixture -Vendor $global:WslVendorBase.Replace('profiles         = ["Private", "Domain"]', 'profiles         = []')
            Invoke-Build 'Set-MiosLanFirewallRules'
            $global:FwFixture.HostRules.Count | Should -Be 0
            ($global:FwFixture.Log -join "`n") | Should -Match 'LAN-FIREWALL-UNSCOPED'
        }

        It 'the operator layer cannot widen the Defender exposure, ports, profiles or scope' {
            Reset-FwFixture -Operator ("[firewall.windows]`nexpose = [`"forge_http`", `"pgvector`"]`nprofiles = [`"Private`", `"Public`"]`n" +
                "remote_addresses = [`"100.100.0.0/16`", `"0.0.0.0/1`", `"Internet`", `"10.0.0.1-10.0.0.9`", `"192.168.1.0/25`"]`n[ports]`nforge_http = 8600`n")
            Invoke-Build 'Set-MiosLanFirewallRules'
            @($global:FwFixture.HostRules.Keys) | Should -Be @('MiOS - forge_http (8400/tcp)')
            $r = $global:FwFixture.HostRules['MiOS - forge_http (8400/tcp)']
            $r.RemoteAddress | Should -Be @('100.100.0.0/16')
            $r.Profile | Should -Be 'Private'
            $log = $global:FwFixture.Log -join "`n"
            foreach ($refused in 'pgvector', 'Public', '0.0.0.0/1', 'Internet', '10.0.0.1-10.0.0.9', '192.168.1.0/25') { $log | Should -Match ([regex]::Escape($refused)) }
        }

        It 'removes stale portproxy forwards of MiOS ports no longer exposed and keeps foreign ones' {
            $global:FwFixture.Proxy['8800'] = '172.24.170.9'; $global:FwFixture.Proxy['8600'] = '172.24.170.9'; $global:FwFixture.Proxy['9999'] = '172.24.170.9'
            Invoke-Build 'Set-MiosLanPortProxy'
            @($global:FwFixture.Proxy.Keys | Sort-Object) | Should -Be @('8400', '8500', '9999')
        }

        It 'forwards only expose ports through the portproxy under NAT' {
            Invoke-Build 'Set-MiosLanPortProxy'
            $adds = @($global:FwFixture.Netsh | Where-Object { $_ -match ' add v4tov4 ' })
            @($adds | ForEach-Object { [regex]::Match($_, 'listenport=([0-9]+)').Groups[1].Value }) | Should -Be @('8400', '8500')
            ($adds -join "`n") | Should -Not -Match 'listenport=8600'
        }

        It 'asks the registered builder distribution for the portproxy VM address' {
            # [bootstrap].dev_distro names the podman machine (MiOS-DEV); WSL registers it as podman-MiOS-DEV, or under the
            # machine name itself for an imported builder.
            foreach ($registered in @('podman-MiOS-DEV', 'MiOS-DEV')) {
                Reset-FwFixture
                $global:FwFixture.Distros = @('Ubuntu', $registered)
                Invoke-Build 'Set-MiosLanPortProxy'
                @($global:FwFixture.Probes) | Should -Be @($registered)
                @($global:FwFixture.Proxy.Keys | Sort-Object) | Should -Be @('8400', '8500')
                ($global:FwFixture.Log -join "`n") | Should -Not -Match 'could not resolve'
            }
        }
    }

    Describe 'MiOS-DEV guest surface in build-mios.ps1' {
        BeforeEach { Reset-FwFixture }

        It 'opens the dev VM firewalld ports from [ports] alone, leaving out a key with no port by name' {
            # The fixture's [ports] defines ssh, forge_http, llm_light, pgvector and searxng; the other dev VM keys
            # (cockpit among them) have no port and must stay closed by name, with no vendor literal in their place.
            $ports = Invoke-DevVmFirewallRun
            $ports | Should -Be '22 8100 8400 8500 8800'
            ($global:FwFixture.Log -join "`n") | Should -Match 'WARN dev VM firewalld: mios\.toml \[ports\]\.cockpit does not resolve'
        }

        It 'leaves every service on its SSOT port in the dev host-network drop-ins' {
            # The vendor Quadlets render PORT= from [ports]; a drop-in that sets it again moves the listener off the port
            # the Windows exposure opens (Open WebUI was pinned to 3030 against [ports].open_webui).
            $src = Get-OverlaySource
            $m = [regex]::Match($src, '(?ms)for svc_pair in \\\n(?<list>.*?)^; do')
            $m.Success | Should -BeTrue
            $pairs = @([regex]::Matches($m.Groups['list'].Value, '"(?<svc>mios-[a-z0-9-]+):(?<extra>[^"]*)"') | ForEach-Object { $_ })
            @($pairs | ForEach-Object { $_.Groups['svc'].Value }) | Should -Contain 'mios-open-webui'
            @($pairs | Where-Object { $_.Groups['extra'].Value -match '(^|\|)Environment=PORT=' } | ForEach-Object { $_.Groups['svc'].Value }) | Should -BeNullOrEmpty
        }
    }

    Describe 'Phase 4 hands the Windows-host exposure to an elevated worker' {
        BeforeEach { Reset-FwFixture }

        It 'measures no drift once the host matches the plan, and one line per difference' {
            Invoke-Build 'Set-MiosLanFirewallRules'
            Invoke-Build 'Set-MiosLanPortProxy'
            Invoke-Build 'Register-MiosLanPortProxyRefresh' @{ OperatorSid = $global:FixtureSid }
            @(Invoke-Build 'Get-MiosLanExposureDrift' @{ WslAddress = '172.24.170.9' }) | Should -BeNullOrEmpty
            [void]$global:FwFixture.HostRules.Remove('MiOS - llm_light (8500/tcp)')
            $global:FwFixture.HostRules['MiOS - stale (8999/tcp)'] = New-HostRule 'MiOS - stale (8999/tcp)' '8999'
            $global:FwFixture.HostRules['MiOS - forge_http (8400/tcp)'].RemoteAddress = @('Any')
            $global:FwFixture.Proxy['8400'] = '172.24.170.99'
            $global:FwFixture.Proxy['8600'] = '172.24.170.9'
            $drift = @(Invoke-Build 'Get-MiosLanExposureDrift' @{ WslAddress = '172.24.170.9' })
            $drift | Should -Contain "create Defender rule 'MiOS - llm_light (8500/tcp)'"
            $drift | Should -Contain "remove Defender rule 'MiOS - stale (8999/tcp)'"
            $drift | Should -Contain "refresh Defender rule 'MiOS - forge_http (8400/tcp)'"
            $drift | Should -Contain 'forward 0.0.0.0:8400 to 172.24.170.9:8400'
            $drift | Should -Contain 'remove forward 0.0.0.0:8600'
            $drift.Count | Should -Be 5
        }

        It 'reads mask-form scopes and reordered profiles back without drift' {
            Invoke-Build 'Set-MiosLanFirewallRules'
            Invoke-Build 'Set-MiosLanPortProxy'
            Invoke-Build 'Register-MiosLanPortProxyRefresh' @{ OperatorSid = $global:FixtureSid }
            foreach ($r in @($global:FwFixture.HostRules.Values)) {
                $r.RemoteAddress = @('fd7a:115c:a1e0::/48', 'LocalSubnet', '100.64.0.0/255.192.0.0')
                $r.Profile = 'Domain, Private'
            }
            @(Invoke-Build 'Get-MiosLanExposureDrift' @{ WslAddress = '172.24.170.9' }) | Should -BeNullOrEmpty
        }

        It 'elevates only when the host differs from the plan, with the VM address the operator resolved' {
            Invoke-Build 'Invoke-MiosLanExposure'
            @($global:FwFixture.Elevations) | Should -Be @('172.24.170.9')
            $global:FwFixture.HostRules.Count | Should -Be 0
            @($global:FwFixture.Netsh | Where-Object { $_ -match ' (add|delete) ' }).Count | Should -Be 0
            $global:FwFixture.Tasks.Count | Should -Be 0
            Invoke-Build 'Set-MiosLanFirewallRules'
            Invoke-Build 'Set-MiosLanPortProxy'
            Invoke-Build 'Register-MiosLanPortProxyRefresh' @{ OperatorSid = $global:FixtureSid }
            $global:FwFixture.Elevations.Clear()
            Invoke-Build 'Invoke-MiosLanExposure'
            $global:FwFixture.Elevations.Count | Should -Be 0
            ($global:FwFixture.Log -join "`n") | Should -Match 'no elevation needed'
            Invoke-Build 'Invoke-MiosLanExposure' @{ Force = $true }
            @($global:FwFixture.Elevations) | Should -Be @('172.24.170.9')
        }

        It 'applies in place, without the worker, when the build is already elevated' {
            & $global:BuildMios { $script:IsAdmin = $true }
            try { Invoke-Build 'Invoke-MiosLanExposure' } finally { & $global:BuildMios { $script:IsAdmin = $false } }
            $global:FwFixture.Elevations.Count | Should -Be 0
            @($global:FwFixture.HostRules.Keys | Sort-Object) | Should -Be @('MiOS - forge_http (8400/tcp)', 'MiOS - llm_light (8500/tcp)')
            @($global:FwFixture.Proxy.Keys | Sort-Object) | Should -Be @('8400', '8500')
            $global:FwFixture.Proxy['8400'] | Should -Be '172.24.170.9'
        }

        It 'sends only [firewall.windows], [wsl2] and [ports] across the privilege boundary' {
            Reset-FwFixture -Operator @'
[identity]
username = "op"
password_hash = "$6$fixture-secret-hash"

[firewall.windows]
expose = ["forge_http"]

[[wsl2.inbound]]
name = "fixture-inbound"

[auth]
token = "fixture-secret-token"

  [identity.extra]
recovery = "fixture-secret-recovery"

[wsl2]
networking_mode = "NAT"
'@
            $layers = @(Invoke-Build 'Get-MiosLanExposureLayers')
            @($layers | ForEach-Object { $_.Path }) | Should -Be @('C:\Users\op\.config\mios\mios.toml', 'C:\usr\share\mios\mios.toml')
            $all = ($layers | ForEach-Object { $_.Text }) -join "`n"
            $all | Should -Not -Match 'secret|username|fixture-inbound|\[identity|\[auth\]|\[\['
            $layers[0].Text | Should -Match '(?m)^expose = \["forge_http"\]$'
            $layers[0].Text | Should -Match '(?m)^networking_mode = "NAT"$'
            $layers[1].Text | Should -Match '(?m)^\[ports\]$'
            $layers[1].Text | Should -Not -Match '(?m)^\[(firewall|bootstrap\.dev_vm|ports\.categories\.edge)\]$'
            foreach ($l in $layers) { Invoke-Build 'Test-MiosLanExposureLayerText' @{ Text = $l.Text } | Should -BeTrue }
        }

        It 'the elevated request refuses other sections, other fields and addresses outside the WSL network' {
            $layer = { param($t) [pscustomobject]@{ Path = 'C:\usr\share\mios\mios.toml'; Text = $t } }
            $ok = "[firewall.windows]`nexpose = [""forge_http""]"
            $bad = @(
                [pscustomobject]@{ Layers = @(& $layer "[identity]`npassword_hash = ""x"""); WslAddress = '172.24.170.9' },
                [pscustomobject]@{ Layers = @(& $layer "[[wsl2.inbound]]`nname = ""x"""); WslAddress = '172.24.170.9' },
                [pscustomobject]@{ Layers = @(& $layer $ok); WslAddress = '8.8.8.8' },
                [pscustomobject]@{ Layers = @(& $layer $ok); WslAddress = '172.24.160.1' },
                [pscustomobject]@{ Layers = @(& $layer $ok); WslAddress = '172.24.170.9'; Extra = 1 },
                [pscustomobject]@{ Layers = @([pscustomobject]@{ Path = 'C:\usr\share\mios\mios.toml'; Text = $ok; Extra = 1 }); WslAddress = '' }
            )
            foreach ($r in $bad) { { Invoke-Build 'Invoke-MiosLanExposureRequest' @{ Request = $r } } | Should -Throw }
            $global:FwFixture.HostRules.Count | Should -Be 0
            @($global:FwFixture.Netsh | Where-Object { $_ -match ' (add|delete) ' }).Count | Should -Be 0
            Invoke-Build 'Invoke-MiosLanExposureRequest' @{ Request = [pscustomobject]@{ Layers = @(& $layer $ok); WslAddress = '172.24.170.9' } }
            @($global:FwFixture.HostRules.Keys | Sort-Object) | Should -Be @('MiOS - forge_http (8400/tcp)', 'MiOS - llm_light (8500/tcp)')
            $global:FwFixture.Proxy['8400'] | Should -Be '172.24.170.9'
            # The worker forwards to the address it was handed and never asks WSL itself.
            $global:FwFixture.Probes.Count | Should -Be 0
        }

        It 'serializes the worker reply with and without log lines' {
            $lines = New-Object System.Collections.Generic.List[object]
            $empty = Invoke-Build 'ConvertTo-MiosLanExposureReply' @{ Status = 'applied'; Lines = $lines } | ConvertFrom-Json
            $empty.Status | Should -Be 'applied'
            @($empty.Lines).Count | Should -Be 0
            $lines.Add([pscustomobject]@{ L = 'OK'; M = 'created' })
            $lines.Add([pscustomobject]@{ L = 'WARN'; M = 'a "quoted" warning' })
            $err = Invoke-Build 'ConvertTo-MiosLanExposureReply' @{ Status = 'error'; Detail = 'stopped'; Lines = $lines } | ConvertFrom-Json
            $err.Status | Should -Be 'error'
            $err.Detail | Should -Be 'stopped'
            @($err.Lines | ForEach-Object { "$($_.L) $($_.M)" }) | Should -Be @('OK created', 'WARN a "quoted" warning')
        }

        It 'compiles the elevated worker from the fixed functions alone' {
            $source = [IO.File]::ReadAllText((Join-Path $global:WslRepoRoot 'build-mios.ps1'))
            $worker = Invoke-Build 'Get-MiosLanExposureWorkerScript' @{ Source = $source }
            $tokens = $null; $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseInput($worker, [ref]$tokens, [ref]$errors)
            $errors.Count | Should -Be 0
            $top = @($ast.EndBlock.Statements)
            $other = @($top | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] -and $_ -isnot [Management.Automation.Language.AssignmentStatementAst] })
            @($other | ForEach-Object { $_.Extent.Text }) | Should -Be @('Invoke-MiosLanExposureWorker -PipeName $PipeName -OriginProcessId $OriginProcessId')
            $defined = @($top | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object { $_.Name })
            foreach ($n in 'Set-MiosLanFirewallRules', 'Set-MiosLanPortProxy', 'Invoke-MiosLanExposureRequest', 'Invoke-MiosLanExposureWorker', 'Test-MiosWslNatAddress',
                'Update-MiosLanPortProxyTarget', 'Get-MiosLanPortProxyRefreshTask', 'Register-MiosLanPortProxyRefresh') { $defined | Should -Contain $n }
            foreach ($n in 'Invoke-MiosLanExposure', 'Invoke-MiosElevatedLanExposure', 'Get-MiosLanExposureLayers', 'Start-Phase', 'Ensure-MiosBuilder', 'Get-MiosTokenSid') { $defined | Should -Not -Contain $n }
            { Invoke-Build 'Get-MiosLanExposureWorkerScript' @{ Source = $source.Replace('function Test-MiosWslNatAddress {', 'function Test-MiosWslNatAddressGone {') } } | Should -Throw
        }
    }

    Describe 'The portproxy refresh task keeps the forwards on the VM address between builds' {
        BeforeAll {
            # Mirrored networking needs Windows 11; the resolver is pinned so these cases run on any host.
            function global:Invoke-Mirrored([scriptblock]$Body) {
                $saved = & $global:BuildMios { ${function:script:Resolve-MiosWslNetworkingMode} }
                & $global:BuildMios { Set-Item function:script:Resolve-MiosWslNetworkingMode { param([int]$WindowsBuild) 'mirrored' } }
                try { & $Body } finally { & $global:BuildMios { param($f) Set-Item function:script:Resolve-MiosWslNetworkingMode $f } $saved }
            }
        }
        BeforeEach { Reset-FwFixture }

        It 're-points the forwarded ports to the VM address WSL records and leaves every other forward alone' {
            foreach ($p in '8400', '8500', '8600', '9999') { $global:FwFixture.Proxy[$p] = '172.24.170.9' }
            $global:FwFixture.NatIp = '172.24.171.20'
            $r = Invoke-Refresh
            $r.Status | Should -Be 'retargeted'
            $global:FwFixture.Proxy['8400'] | Should -Be '172.24.171.20'
            $global:FwFixture.Proxy['8500'] | Should -Be '172.24.171.20'
            $global:FwFixture.Proxy['8600'] | Should -Be '172.24.170.9'
            $global:FwFixture.Proxy['9999'] | Should -Be '172.24.170.9'
            @($global:FwFixture.Netsh | Where-Object { $_ -match ' (add|delete) ' }).Count | Should -Be 0
            (Invoke-Refresh).Status | Should -Be 'current'
        }

        It 'never adds a forward and leaves loopback targets to the localhost relays' {
            $global:FwFixture.Proxy['8400'] = '127.0.0.1'
            $global:FwFixture.NatIp = '172.24.171.20'
            (Invoke-Refresh).Status | Should -Be 'current'
            @($global:FwFixture.Proxy.Keys) | Should -Be @('8400')
            $global:FwFixture.Proxy['8400'] | Should -Be '127.0.0.1'
            @($global:FwFixture.Netsh | Where-Object { $_ -match ' (add|set|delete) ' }).Count | Should -Be 0
        }

        It 'takes only a guest address on the host WSL network from the registry' {
            $global:FwFixture.Proxy['8400'] = '172.24.170.9'
            foreach ($bad in '192.168.1.50', '172.24.160.1', '8.8.8.8', '999.1.1.1', '172.24.171.20 connectport=22') {
                $global:FwFixture.NatIp = $bad
                (Invoke-Refresh).Status | Should -Be 'refused' -Because "'$bad' is not a guest address on the WSL network"
            }
            $global:FwFixture.NatIp = ''
            (Invoke-Refresh).Status | Should -Be 'no-address'
            $global:FwFixture.Proxy['8400'] | Should -Be '172.24.170.9'
            @($global:FwFixture.Netsh | Where-Object { $_ -match ' set ' }).Count | Should -Be 0
        }

        It 'registers a SYSTEM task carrying the address bound, the plan ports and the account, readable by that account' {
            Invoke-Build 'Register-MiosLanPortProxyRefresh' @{ OperatorSid = $global:FixtureSid }
            $t = Get-RefreshTask
            $t | Should -Not -BeNullOrEmpty
            $t.Principal.UserId | Should -Be 'SYSTEM'
            $t.Triggers[0].Interval | Should -Be (New-TimeSpan -Minutes 5)
            @($t.Actions).Count | Should -Be 1
            $t.Actions[0].Execute | Should -Match 'WindowsPowerShell\\v1\.0\\powershell\.exe$'
            $t.SecurityDescriptor | Should -Be "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;$global:FixtureSid)"
            $encoded = [regex]::Match($t.Actions[0].Arguments, '-EncodedCommand (\S+)$').Groups[1].Value
            $script = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
            $tokens = $null; $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseInput($script, [ref]$tokens, [ref]$errors)
            $errors.Count | Should -Be 0
            $defs = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] })
            @($defs | ForEach-Object Name) | Should -Be @('ConvertTo-MiosNetworkPrefix', 'Test-MiosPrefixWithin', 'Test-MiosWslNatAddress', 'Update-MiosLanPortProxyTarget')
            $script | Should -Match ([regex]::Escape("Update-MiosLanPortProxyTarget -Ports @(8400,8500) -OperatorSid '$global:FixtureSid'"))
            # The embedded body works with nothing but the task's own functions.
            $global:FwFixture.Proxy['8400'] = '172.24.170.9'; $global:FwFixture.NatIp = '172.24.171.20'
            $code = ($defs | ForEach-Object { $_.Extent.Text }) -join "`n"
            $r = & { param($c, $read)
                . ([scriptblock]::Create($c))
                Update-MiosLanPortProxyTarget -Ports 8400 -OperatorSid $global:FixtureSid -Netsh 'netsh' -Read $read } $code $global:RefreshRead
            $r.Status | Should -Be 'retargeted'
            $global:FwFixture.Proxy['8400'] | Should -Be '172.24.171.20'
        }

        It 'removes the task when nothing is forwarded and refuses a value that is not an account SID' {
            Invoke-Build 'Register-MiosLanPortProxyRefresh' @{ OperatorSid = $global:FixtureSid }
            Invoke-Mirrored { Invoke-Build 'Register-MiosLanPortProxyRefresh' @{ OperatorSid = $global:FixtureSid } }
            $global:FwFixture.Tasks.Count | Should -Be 0
            Invoke-Build 'Register-MiosLanPortProxyRefresh' @{ OperatorSid = $global:FixtureSid }
            $global:FwFixture.Vendor = $global:WslVendorBase.Replace('expose           = ["forge_http", "llm_light"]', 'expose           = []')
            Invoke-Build 'Register-MiosLanPortProxyRefresh' @{ OperatorSid = $global:FixtureSid }
            $global:FwFixture.Tasks.Count | Should -Be 0
            $global:FwFixture.Vendor = $global:WslVendorBase
            foreach ($bad in 'S-1-5-18', 'S-1-5-32-544', "S-1-5-21-1-2-3-4')(A;;FA;;;WD") {
                { Invoke-Build 'Register-MiosLanPortProxyRefresh' @{ OperatorSid = $bad } } | Should -Throw
            }
            $global:FwFixture.Tasks.Count | Should -Be 0
        }

        It 'asks for the refresh task when it is missing or differs, and for its removal under mirrored networking' {
            Invoke-Build 'Set-MiosLanFirewallRules'
            Invoke-Build 'Set-MiosLanPortProxy'
            $drift = { @(Invoke-Build 'Get-MiosLanExposureDrift' @{ WslAddress = '172.24.170.9' }) }
            @(& $drift) | Should -Be @('register the portproxy refresh task') -Because 'no task is registered'
            Invoke-Build 'Register-MiosLanPortProxyRefresh' @{ OperatorSid = $global:FixtureSid }
            @(& $drift) | Should -BeNullOrEmpty
            # Different ports: the task a build with a narrower expose list writes.
            $global:FwFixture.Vendor = $global:WslVendorBase.Replace('expose           = ["forge_http", "llm_light"]', 'expose           = ["forge_http"]')
            $narrow = Invoke-Build 'Get-MiosLanPortProxyRefreshTask' @{ OperatorSid = $global:FixtureSid }
            $global:FwFixture.Vendor = $global:WslVendorBase
            (Get-RefreshTask).Actions[0].Arguments = $narrow.Argument
            @(& $drift) | Should -Be @('register the portproxy refresh task') -Because 'the task forwards other ports'
            # Another account's task cannot be read here, so it is registered for this account.
            Invoke-Build 'Register-MiosLanPortProxyRefresh' @{ OperatorSid = 'S-1-5-21-1000-2000-3000-1002' }
            @(& $drift) | Should -Be @('register the portproxy refresh task') -Because 'the task serves another account'
            Invoke-Build 'Register-MiosLanPortProxyRefresh' @{ OperatorSid = $global:FixtureSid }
            (Get-RefreshTask).Principal.UserId = 'MIOS\user'
            @(& $drift) | Should -Be @('register the portproxy refresh task') -Because 'the task does not run as SYSTEM'
            Invoke-Build 'Register-MiosLanPortProxyRefresh' @{ OperatorSid = $global:FixtureSid }
            Invoke-Mirrored { @(& $drift) | Should -Be @('remove the portproxy refresh task') -Because 'nothing is forwarded under mirrored networking' }
            # Under mirrored networking, no task and a task this token cannot read are both no drift.
            $global:FwFixture.Tasks.Clear()
            Invoke-Mirrored { @(& $drift) | Should -BeNullOrEmpty }
            Invoke-Build 'Register-MiosLanPortProxyRefresh' @{ OperatorSid = 'S-1-5-21-1000-2000-3000-1002' }
            Invoke-Mirrored { @(& $drift) | Should -BeNullOrEmpty }
        }

        It 'the elevated request registers the task for the origin account it is handed, and the in-place path for this token' {
            $request = [pscustomobject]@{ Layers = @(Invoke-Build 'Get-MiosLanExposureLayers'); WslAddress = '172.24.170.9' }
            Invoke-Build 'Invoke-MiosLanExposureRequest' @{ Request = $request }
            $global:FwFixture.Tasks.Count | Should -Be 0
            ($global:FwFixture.Log -join "`n") | Should -Match 'originating account is unknown'
            Invoke-Build 'Invoke-MiosLanExposureRequest' @{ Request = $request; OperatorSid = 'S-1-5-21-1000-2000-3000-1002' }
            (Get-RefreshTask).SecurityDescriptor | Should -Match ([regex]::Escape('(A;;FR;;;S-1-5-21-1000-2000-3000-1002)'))
            $global:FwFixture.Tasks.Clear()
            & $global:BuildMios { $script:IsAdmin = $true }
            try { Invoke-Build 'Invoke-MiosLanExposure' } finally { & $global:BuildMios { $script:IsAdmin = $false } }
            $global:FwFixture.Elevations.Count | Should -Be 0
            (Get-RefreshTask).SecurityDescriptor | Should -Match ([regex]::Escape("(A;;FR;;;$global:FixtureSid)"))
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
    'profiles-empty-open' = 'opens no Hyper-V rule and closes open ones when the SSOT profiles resolve empty or to Any'
    'operator-port-redirect' = 'an operator [ports] override cannot redirect an exposed key to another listener'
    'defender-refresh-unscoped' = 'refreshes an existing open Defender rule to the SSOT scope and profiles'
    'defender-operator-widening' = 'the operator layer cannot widen the Defender exposure, ports, profiles or scope'
    'portproxy-stale' = 'removes stale portproxy forwards of MiOS ports no longer exposed and keeps foreign ones'
    'portproxy-distro' = 'asks the registered builder distribution for the portproxy VM address'
    'devvm-fw-literal' = 'opens the dev VM firewalld ports from [ports] alone, leaving out a key with no port by name'
    'owui-port-override' = 'leaves every service on its SSOT port in the dev host-network drop-ins'
    'elevate-unconditionally' = 'elevates only when the host differs from the plan, with the VM address the operator resolved'
    'drift-mask' = 'reads mask-form scopes and reordered profiles back without drift'
    'projection-all-sections' = 'sends only [firewall.windows], [wsl2] and [ports] across the privilege boundary'
    'request-any-layer' = 'the elevated request refuses other sections, other fields and addresses outside the WSL network'
    'request-any-address' = 'the elevated request refuses other sections, other fields and addresses outside the WSL network'
    'reply-list' = 'serializes the worker reply with and without log lines'
    'refresh-any-port' = 're-points the forwarded ports to the VM address WSL records and leaves every other forward alone'
    'refresh-adds' = 'never adds a forward and leaves loopback targets to the localhost relays'
    'refresh-loopback' = 'never adds a forward and leaves loopback targets to the localhost relays'
    'refresh-unbounded' = 'takes only a guest address on the host WSL network from the registry'
    'refresh-principal' = 'registers a SYSTEM task carrying the address bound, the plan ports and the account, readable by that account'
    'refresh-no-read-grant' = 'registers a SYSTEM task carrying the address bound, the plan ports and the account, readable by that account'
    'refresh-bound-missing' = 'registers a SYSTEM task carrying the address bound, the plan ports and the account, readable by that account'
    'refresh-drift-register' = 'asks for the refresh task when it is missing or differs, and for its removal under mirrored networking'
    'refresh-drift-remove' = 'asks for the refresh task when it is missing or differs, and for its removal under mirrored networking'
    'refresh-worker-skips' = 'the elevated request registers the task for the origin account it is handed, and the in-place path for this token'
}
$bad = 0
foreach ($plant in $plants.Keys) {
    $r = Invoke-Suite $plant
    $failed = @($r.Failed | ForEach-Object { $_.Name })
    if ($failed -contains $plants[$plant]) { Write-Host "PASS plant '$plant' fails '$($plants[$plant])'" }
    else { Write-Host "FAIL plant '$plant' left '$($plants[$plant])' green (failed: $($failed -join '; '))"; $bad++ }
}
if ($bad) { throw "$bad planted defect(s) were not caught." }
