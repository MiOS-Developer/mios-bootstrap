# Source-only fixtures: extract functions with the PowerShell AST; NEVER execute Get-MiOS.ps1 top-level.
# Default/PlantDefect use scratch files and mocked Windows APIs only, including on Native MiOS-DEV.
# -WindowsAcl additionally exercises real ACLs on an isolated Windows scratch tree (never C:\etc or M:).
[CmdletBinding()]
param([switch]$PlantDefect, [switch]$WindowsAcl, [switch]$VerifyReceiverBaselineGuard, [string]$CanonicalVendorPath)
$ErrorActionPreference = 'Stop'
if ($VerifyReceiverBaselineGuard -and ($PlantDefect -or $WindowsAcl)) { throw '-VerifyReceiverBaselineGuard is a standalone source fixture control.' }
$PlantReceiverFailure = $false
$repoRoot = Split-Path $PSScriptRoot -Parent
$realScript = Join-Path $repoRoot 'Get-MiOS.ps1'
if (-not $CanonicalVendorPath) {
    $CanonicalVendorPath = Join-Path $repoRoot 'usr/share/mios/mios.toml'
    if (-not (Test-Path -LiteralPath $CanonicalVendorPath)) { $CanonicalVendorPath = Join-Path $repoRoot 'mios.toml' }
}
if (-not (Test-Path -LiteralPath $CanonicalVendorPath -PathType Leaf)) { throw 'A tracked canonical vendor TOML is required for the grammar fixture.' }
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-getmios-security-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -ErrorAction Stop | Out-Null
$script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
function Check([bool]$Ok, [string]$What) {
    $script:checks++
    if ($Ok) { Write-Host "  PASS $What" } else { Write-Host "  FAIL $What"; $script:fail++; $script:failedChecks.Add($What) }
}
function Expect-Throw([scriptblock]$Action, [string]$What) {
    $caught = $false
    try { $null = & $Action } catch { $caught = $true }
    Check $caught $What
}
function Expect-ThrowMatch([scriptblock]$Action, [string]$Pattern, [string]$What) {
    $message = $null
    try { $null = & $Action } catch { $message = $_.Exception.Message }
    Check ($null -ne $message -and $message -match $Pattern) $What
}
$wslCreator = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'
function Reset-FirewallState([string[]]$Creators, [string]$Mode) {
    $script:fwCreators = New-Object System.Collections.Generic.List[string]
    foreach ($c in $Creators) { $script:fwCreators.Add($c) }
    $script:fwRegisterMode = $Mode
    $script:fwRegisterCalls = New-Object System.Collections.Generic.List[string]
    $script:fwPersistent = @{}; $script:fwActiveOverride = $null; $script:fwReadStore = ''
    $script:fwSetCalls = 0; $script:firewallDefault = ''; $script:firewallSetError = ''; $script:sleeps = 0
}
function Reset-FeatureState([hashtable]$State = @{}, [hashtable]$Exit = @{}, [bool]$StoreWsl = $true) {
    $script:dismState = @{ 'Microsoft-Windows-Subsystem-Linux' = 'Enabled'; 'VirtualMachinePlatform' = 'Enabled'; 'Microsoft-Hyper-V' = 'Enabled' }
    foreach ($k in $State.Keys) { $script:dismState[$k] = $State[$k] }
    $script:dismEnableExit = @{ 'Microsoft-Windows-Subsystem-Linux' = 0; 'VirtualMachinePlatform' = 0; 'Microsoft-Hyper-V' = 0 }
    foreach ($k in $Exit.Keys) { $script:dismEnableExit[$k] = $Exit[$k] }
    $script:dismCalls = New-Object System.Collections.Generic.List[string]
    $script:storeWsl = $StoreWsl
}
function Invoke-GateCase([hashtable]$State = @{}, [hashtable]$Exit = @{}, [bool]$StoreWsl = $true) {
    Reset-FeatureState -State $State -Exit $Exit -StoreWsl $StoreWsl
    Reset-FirewallState -Creators @($wslCreator) -Mode 'ok'
    $out = [pscustomobject]@{ Status = ''; Error = '' }
    try { $out.Status = [string](Invoke-MiosPlatformGate).Status } catch { $out.Error = $_.Exception.Message }
    return $out
}
function Import-MiosFunctions([string]$Path) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Product source does not parse: $($errors[0].Message)" }
    $want = @('Get-MiosTomlAssignments', 'Split-MiosTomlKeyLine', 'Get-MiosTomlCredentialKeys', 'ConvertTo-MiosCredentialFreeToml',
        'Assert-MiosNoReparsePath', 'Set-MiosHostTierAcl', 'Initialize-MiosHostTierDirectory', 'Write-MiosHostToml',
        'Repair-MiosHostTierCredentials', 'Get-MiosTomlTableArray', 'ConvertTo-MiosWindowsPath', 'Test-MiosDefenderExclusionRefused',
        'Get-MiosDefenderExclusionPlan', 'Add-MiosDefenderExclusions', 'Set-MiosWslFirewallPolicy', 'Set-MiosPrivateUserTomlAcl',
        'Import-MiosUserToml', 'ConvertTo-MiosNativeArgument', 'Sync-MiosUserTomlToBuilder', 'Get-MiosUserTomlReceiverScript', 'Get-MiosWslConfigText',
        'Get-MiosFeatureState', 'Get-MiosDismEnableOutcome', 'Enable-MiOSWindowsFeatures', 'Test-MiosWslVmCreator', 'Register-MiosWslVmCreator',
        'Invoke-MiosPlatformGate')
    $defs = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        Where-Object { $want -contains $_.Name })
    foreach ($name in $want) { if (@($defs | Where-Object Name -eq $name).Count -ne 1) { throw "Missing/duplicate canonical function $name" } }
    foreach ($a in $ast.FindAll({ param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq '$Script:MiosCredentialKeyRe' }, $true)) { . ([scriptblock]::Create($a.Extent.Text)) }
    foreach ($d in $defs) { . ([scriptblock]::Create(($d.Extent.Text -replace '^function\s+', 'function global:'))) }
    return $ast
}
$fixture = @'
[identity]
username = "mios"
default_password = "FIXTURE-SECRET-A"
[ttyd]
auth_pass = "FIXTURE-SECRET-B"
[pgvector]
pass = "FIXTURE-SECRET-C"
[auth]
github_pat = "FIXTURE-SECRET-D"
password_hash = '$6$fixture$hash'
[adguard]
admin_password_bcrypt = "FIXTURE-SECRET-E"
[ai]
max_tokens = 4096
password_hint = "nonsecret"
[field.sysrescue]
wipe_passphrase = """FIXTURE-SECRET-F
second secret line
"""
password = ''
'@
$grammar = @(
    'identity."default_password" = "FIXTURE-SECRET-G"',
    'identity.default_password.value = "FIXTURE-SECRET-G"',
    'identity = { default_password.value = "FIXTURE-SECRET-G" }',
    '"identity" . ''default_password'' = "FIXTURE-SECRET-G"',
    'identity = { "default_password" = "FIXTURE-SECRET-G", username = "fixture" }',
    @'
[autounattend]
accounts = [
  { name = "fixture", "password" = "FIXTURE-SECRET-G" },
]
'@,
    @'
[[autounattend.accounts]]
name = "fixture"
password = '''FIXTURE-SECRET-G
not a TOML assignment: key = value
'''
'@,
    @'
[fixture]
description = """A non-secret string containing syntax:
password = "keep this text"
[not.a.table]
"""
keep = [
 "FIXTURE-PUBLIC", # quoted strings and trailing array commas from the configurator
 { name = "public", enabled = true },
]
'@
)
$ruleVendor = @'
[[security.defender_exclusions.path]]
path = "C:\\MiOS\\bin"
reason = "Fixture # native launcher"
[[security.defender_exclusions.path]]
path = '%TEMP%/child'
reason = 'Must be refused'
[[security.defender_exclusions.path]]
path = 'M:/directory/..'
reason = 'Must be refused'
[[security.defender_exclusions.path]]
path = 'C:\MiOS\cache'
[[security.defender_exclusions.process]]
path = 'C:\MiOS\bin\mios-launch.exe'
reason = 'Fixture launcher'
'@
function Install-ApiMocks {
    $script:aclCalls = New-Object System.Collections.Generic.List[string]
    $script:failAcl = $false
    function global:Set-MiosHostTierAcl {
        param([string]$Path, [switch]$Private)
        $script:aclCalls.Add("$Path|$Private")
        if ($script:failAcl) { throw 'Fixture ACL failure' }
        if ($Path -like '*.tmp' -and $Private -and (Test-Path -LiteralPath $Path)) {
            if ((Get-Item -LiteralPath $Path -Force).Length -ne 0) { throw 'Fixture: private ACL was set after bytes were written' }
        }
    }
    function global:Resolve-MiosTomlText { return $script:fixtureUser }
    function global:Resolve-MiosVendorTomlText { return $script:fixtureVendor }
    $script:removedExclusions = New-Object System.Collections.Generic.List[string]
    $script:removedProcesses = New-Object System.Collections.Generic.List[string]
    $script:addedExclusions = New-Object System.Collections.Generic.List[string]
    $script:mockDefenderPaths = @('M:/', 'M:', ($env:TEMP + '/'), 'C:\usr', 'C:\MiOS\bin', ($env:LOCALAPPDATA + '\Microsoft\WinGet'), 'D:\Admin\owned')
    $script:mockDefenderProcesses = @('C:\MiOS\bin\mios-launch.exe', 'M:\MiOS\bin\mios-launch.exe', 'D:\Admin\owned.exe')
    function global:Get-MpPreference { [CmdletBinding()]param() return [pscustomobject]@{ ExclusionPath = $script:mockDefenderPaths; ExclusionProcess = $script:mockDefenderProcesses } }
    function global:Remove-MpPreference {
        [CmdletBinding()]param($ExclusionPath, $ExclusionProcess)
        if ($ExclusionPath) {
            $script:removedExclusions.Add($ExclusionPath)
            $script:mockDefenderPaths = @($script:mockDefenderPaths | Where-Object { $_ -cne $ExclusionPath })
        }
        if ($ExclusionProcess) {
            $script:removedProcesses.Add($ExclusionProcess)
            $script:mockDefenderProcesses = @($script:mockDefenderProcesses | Where-Object { $_ -cne $ExclusionProcess })
        }
    }
    function global:Add-MpPreference {
        [CmdletBinding()]param($ExclusionPath, $ExclusionProcess)
        $script:addedExclusions.Add([string]$ExclusionPath + [string]$ExclusionProcess)
        if ($ExclusionPath) { $script:mockDefenderPaths += $ExclusionPath }
        if ($ExclusionProcess) { $script:mockDefenderProcesses += $ExclusionProcess }
    }
    $script:firewallRemoved = New-Object System.Collections.Generic.List[string]
    $script:firewallAdded = New-Object System.Collections.Generic.List[object]
    # Stateful Hyper-V firewall: registered creators, persistent settings, and an ActiveStore that Group Policy may override.
    Reset-FirewallState -Creators @($wslCreator) -Mode 'ok'
    function global:Get-NetFirewallHyperVVMCreator {
        [CmdletBinding()]param()
        foreach ($id in $script:fwCreators) { [pscustomobject]@{ VMCreatorId = $id; FriendlyName = 'WSL' } }
    }
    function global:Invoke-CimMethod {
        [CmdletBinding()]param($Namespace, $ClassName, $MethodName, $Arguments)
        $script:fwRegisterCalls.Add("$Namespace|$ClassName|$MethodName|$($Arguments.VMCreatorId)|$($Arguments.FriendlyName)")
        $exists = [InvalidOperationException]::new('Fixture: the creator already exists.')
        $exists | Add-Member -NotePropertyName NativeErrorCode -NotePropertyValue 'AlreadyExists'
        switch ($script:fwRegisterMode) {
            'denied'        { throw [UnauthorizedAccessException]::new('Fixture: access denied.') }
            'exists-race'   { $script:fwCreators.Add([string]$Arguments.VMCreatorId); throw $exists }
            'exists-absent' { throw $exists }
            'rv-fail'       { return [pscustomobject]@{ ReturnValue = [uint32]5 } }
            'ok-absent'     { return [pscustomobject]@{ ReturnValue = [uint32]0 } }
            default         { $script:fwCreators.Add([string]$Arguments.VMCreatorId); return [pscustomobject]@{ ReturnValue = [uint32]0 } }
        }
    }
    function global:Set-NetFirewallHyperVVMSetting {
        [CmdletBinding()]param($Name, $Enabled, $DefaultInboundAction, $DefaultOutboundAction, $LoopbackEnabled, $AllowHostPolicyMerge)
        if ($script:firewallSetError) {
            $PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([InvalidOperationException]::new($script:firewallSetError),
                'Fixture', [Management.Automation.ErrorCategory]::PermissionDenied, $Name))
        }
        if (-not ($script:fwCreators -contains $Name)) {
            $PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([InvalidOperationException]::new(
                "No MSFT_NetFirewallHyperVVMSetting objects found with property 'Name' equal to '$Name'."),
                'CmdletizationQuery_NotFound_Name', [Management.Automation.ErrorCategory]::ObjectNotFound, $Name))
        }
        $script:fwSetCalls++
        $script:firewallDefault = $DefaultInboundAction
        $script:fwPersistent[$Name] = @{ Enabled = $Enabled; DefaultInboundAction = $DefaultInboundAction }
    }
    function global:Get-NetFirewallHyperVVMSetting {
        [CmdletBinding()]param($Name, $PolicyStore)
        $script:fwReadStore = [string]$PolicyStore
        if (-not $script:fwPersistent.ContainsKey($Name)) {
            $PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('Fixture: no setting.'),
                'Fixture', [Management.Automation.ErrorCategory]::ObjectNotFound, $Name))
        }
        $s = $script:fwPersistent[$Name].Clone()
        if ($script:fwActiveOverride -and $script:fwReadStore -eq 'ActiveStore') { foreach ($k in $script:fwActiveOverride.Keys) { $s[$k] = $script:fwActiveOverride[$k] } }
        [pscustomobject]@{ Name = $Name; Enabled = $s.Enabled; DefaultInboundAction = $s.DefaultInboundAction }
    }
    function global:Start-Sleep { [CmdletBinding()]param($Seconds, $Milliseconds) $script:sleeps++ }
    # Windows features: dism state per feature, the exit code an enable returns, Store wsl.exe, elevation, SSOT overrides.
    $script:elevated = $true
    $script:toml = @{}
    function global:Test-MiosElevated { return $script:elevated }
    function global:Get-MiosTomlValue {
        param([string]$Section, [string]$Key, $Default)
        if ($script:toml.ContainsKey("$Section.$Key")) { return $script:toml["$Section.$Key"] }
        return $Default
    }
    Reset-FeatureState
    function global:dism.exe {
        $argText = $args -join ' '
        $script:dismCalls.Add($argText)
        $name = if ($argText -match '/featurename:(\S+)') { $Matches[1] } else { '' }
        if ($argText -match '/get-featureinfo') { $global:LASTEXITCODE = 0; return @("Feature Name : $name", "State : $($script:dismState[$name])") }
        if ($argText -match '/enable-feature') {
            $global:LASTEXITCODE = [int]$script:dismEnableExit[$name]
            if ($global:LASTEXITCODE -eq 0) { $script:dismState[$name] = 'Enabled' }
            elseif ($global:LASTEXITCODE -eq 3010) { $script:dismState[$name] = 'Enable Pending' }
            return @('Fixture dism output.')
        }
        $global:LASTEXITCODE = 87
    }
    function global:wsl.exe {
        $argText = $args -join ' '
        if ($argText -match '(^|\s)(-d|--distribution|--import|--unregister)(\s|$)') { $global:MiosFixtureTripwires.Add("wsl.exe $argText") }
        $global:LASTEXITCODE = if ($script:storeWsl) { 0 } else { 1 }
    }
    # Tripwires: no disk/partition verb, no dummy firewall object, and nothing that starts MiOS-DEV.
    $global:MiosFixtureTripwires = New-Object System.Collections.Generic.List[string]
    foreach ($verb in @('New-Partition', 'Resize-Partition', 'Remove-Partition', 'Set-Partition', 'Format-Volume', 'Initialize-Disk', 'Clear-Disk',
                        'diskpart.exe', 'bcdedit.exe', 'New-NetFirewallHyperVVMSetting', 'Remove-NetFirewallHyperVVMSetting', 'podman', 'podman.exe')) {
        $null = New-Item -Path "function:global:$verb" -Value ([scriptblock]::Create("`$global:MiosFixtureTripwires.Add('$verb')")) -Force
    }
    function global:Get-NetFirewallHyperVRule {
        [CmdletBinding()]param()
        return @([pscustomobject]@{ Name = 'MiOS-WSL-deleted'; VMCreatorId = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' },
            [pscustomobject]@{ Name = 'ThirdParty'; VMCreatorId = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' },
            [pscustomobject]@{ Name = 'MiOS-WSL-other-creator'; VMCreatorId = '{11111111-1111-1111-1111-111111111111}' })
    }
    function global:Remove-NetFirewallHyperVRule { [CmdletBinding()]param($Name) $script:firewallRemoved.Add([string]$Name) }
    function global:New-NetFirewallHyperVRule {
        [CmdletBinding()]param($Name, $DisplayName, $VMCreatorId, $Direction, $Action, $Protocol, $LocalPorts, $RemoteAddresses)
        $script:firewallAdded.Add(@{ Name = $Name; Remote = $RemoteAddresses; Ports = $LocalPorts })
    }
}
function Invoke-Checks([string]$Path, [switch]$SkipReceiverProtocol) {
    $script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
    $ast = Import-MiosFunctions $Path
    Install-ApiMocks
    $script:fixtureUser = ''; $script:fixtureVendor = $ruleVendor
    $keys = @(Get-MiosTomlCredentialKeys $fixture)
    foreach ($key in @('identity.default_password', 'ttyd.auth_pass', 'pgvector.pass', 'auth.github_pat', 'auth.password_hash',
                      'adguard.admin_password_bcrypt', 'field.sysrescue.wipe_passphrase')) {
        Check ($keys -contains $key) "canonical alias $key is recognized"
    }
    Check (-not ($keys -contains 'ai.max_tokens')) 'max_tokens is not a credential'
    Check (-not ($keys -contains 'field.sysrescue.password')) 'an empty credential is not reported as exposed'
    Check (($keys -join ',') -notmatch 'FIXTURE-SECRET') 'key reports contain no credential values'
    $proj = ConvertTo-MiosCredentialFreeToml $fixture
    Check ($proj -notmatch 'FIXTURE-SECRET|second secret line') 'all aliases and entire multiline values are removed'
    Check ($proj.Contains('username = "mios"') -and $proj.Contains('max_tokens = 4096')) 'non-secret settings remain'
    foreach ($case in $grammar) {
        $clean = ConvertTo-MiosCredentialFreeToml $case
        Check ($clean -notmatch 'FIXTURE-SECRET') 'quoted/dotted/inline/multiline grammar cannot retain credentials'
        Check (@(Get-MiosTomlCredentialKeys $clean).Count -eq 0) 'projected grammar rescans without credential fields'
        if ($case.Contains('FIXTURE-PUBLIC')) { Check ($clean -ceq $case) 'syntax inside a non-secret multiline string remains byte-exact' }
    }
    $canonical = [IO.File]::ReadAllText($CanonicalVendorPath)
    $canonicalClean = ConvertTo-MiosCredentialFreeToml $canonical
    Check (@(Get-MiosTomlCredentialKeys $canonicalClean).Count -eq 0) 'actual tracked vendor grammar projects without credential fields'
    Check ($canonicalClean.Length -gt (0.8 * $canonical.Length) -and $canonicalClean.Contains('[identity]')) 'ordinary canonical vendor settings are retained'
    $registered = [regex]::Match($canonical, '(?ms)^\[security\.secret_keys\]\s*\r?\n(?<body>.*?)(?=^\[|\z)')
    if ($registered.Success) {
        $paths = [regex]::Match($registered.Groups['body'].Value, '(?ms)^paths\s*=\s*\[(?<items>.*?)^\]')
        foreach ($entry in [regex]::Matches($paths.Groups['items'].Value, '"([^"]+)"')) {
            $probe = $entry.Groups[1].Value + ' = "FIXTURE-SECRET-REGISTER"'
            Check ((ConvertTo-MiosCredentialFreeToml $probe) -notmatch 'FIXTURE-SECRET-REGISTER') ('canonical secret path is covered: ' + $entry.Groups[1].Value)
        }
    }
    $unsupported = '[identity]' + "`n" + '"default\u005fpassword" = "FIXTURE-SECRET-ESCAPED"'
    Expect-Throw { ConvertTo-MiosCredentialFreeToml $unsupported } 'unsupported escaped keys fail closed'
    Expect-Throw { ConvertTo-MiosCredentialFreeToml ('[identity.default_password]' + "`n" + 'value = "FIXTURE-SECRET-TABLE"') } 'credential namespaces represented as tables fail closed'
    Expect-Throw { ConvertTo-MiosCredentialFreeToml ('[identity]' + "`n" + 'default_password = "unterminated') } 'unterminated strings fail closed'
    $hostTier = Join-Path (Join-Path (Join-Path $scratch 'etc') 'mios') 'mios.toml'
    Write-MiosHostToml -Path $hostTier -Text $fixture
    Check ([IO.File]::ReadAllText($hostTier) -notmatch 'FIXTURE-SECRET') 'host writer publishes only the projection'
    [IO.File]::WriteAllText($hostTier, $unsupported)
    $script:aclCalls.Clear()
    Expect-Throw { Repair-MiosHostTierCredentials -Paths @($hostTier) } 'an unsupported legacy raw host file aborts repair'
    Check (@($script:aclCalls | Where-Object { $_ -eq ($hostTier + '|True') }).Count -gt 0) 'legacy raw host file is restricted before parse failure'
    $script:failAcl = $true
    Expect-Throw { Write-MiosHostToml -Path $hostTier -Text $fixture } 'ACL failure stops the writer'
    Check ([IO.File]::ReadAllText($hostTier) -ceq $unsupported) 'ACL failure does not overwrite the old file'
    $script:failAcl = $false
    [IO.File]::WriteAllText($hostTier, $fixture)
    $null = Repair-MiosHostTierCredentials -Paths @($hostTier)
    Check ([IO.File]::ReadAllText($hostTier) -notmatch 'FIXTURE-SECRET') 'legacy raw host aliases are repaired'
    foreach ($bad in @('C:/', 'C:\folder\..\', '%TEMP%/child', '%TEMP%\..\Temp\child',
                       '%USERPROFILE%/Downloads', '\\server\share', 'relative.exe', '%MISSING_FIXTURE_VARIABLE%\bin')) {
        Check (-not [string]::IsNullOrWhiteSpace((Test-MiosDefenderExclusionRefused $bad))) "Defender refuses $bad"
    }
    $plan = Get-MiosDefenderExclusionPlan
    Check (@($plan.paths).Count -eq 1 -and $plan.paths[0] -ceq 'C:\MiOS\bin') 'basic TOML path escapes decode into one narrow canonical path'
    Check (@($plan.processes).Count -eq 1) 'an explicit narrow process is planned'
    Check (@($plan.refused).Count -eq 3) 'temp/root/missing-reason exclusions are refused'
    Add-MiosDefenderExclusions
    Check ($script:removedExclusions.Count -eq 6 -and $script:removedExclusions.Contains('C:\usr') -and $script:removedExclusions.Contains($env:LOCALAPPDATA + '\Microsoft\WinGet')) 'exact known legacy roots/temp/usr/WinGet/path signatures are removed'
    Check ($script:removedProcesses.Count -eq 2) 'exact known legacy process signatures are removed'
    Check ($script:mockDefenderPaths -contains 'D:\Admin\owned' -and $script:mockDefenderProcesses -contains 'D:\Admin\owned.exe') 'unrelated administrator path and process exclusions remain'
    Check ($script:addedExclusions.Count -eq 2 -and $script:mockDefenderPaths -contains 'C:\MiOS\bin' -and $script:mockDefenderProcesses -contains 'C:\MiOS\bin\mios-launch.exe') 'validated current SSOT path/process exclusions are re-added'
    # A WSL creator that already exists: no registration, Set in place, effective ActiveStore readback.
    $script:fixtureVendor = ''; $ok = $false
    try { Set-MiosWslFirewallPolicy; $ok = $true } catch {}
    Check ($ok -and $script:firewallDefault -eq 'Block') 'WSL inbound remains Block by default'
    Check ($script:firewallRemoved.Count -eq 1 -and $script:firewallRemoved[0] -eq 'MiOS-WSL-deleted') 'deleted owned allow rules are removed and other rules preserved'
    Check ($script:fwRegisterCalls.Count -eq 0 -and $script:fwSetCalls -eq 1) 'an existing WSL creator is set in place, never re-registered'
    Check ($script:fwReadStore -ceq 'ActiveStore') 'the WSL policy is read back from the effective ActiveStore'
    # Active platform, WSL never ran: register the creator exactly as WSL does (no VM), then Set.
    Reset-FirewallState -Creators @() -Mode 'ok'
    $ok = $false; try { Set-MiosWslFirewallPolicy; $ok = $true } catch {}
    Check ($ok -and $script:fwRegisterCalls.Count -eq 1 -and
           $script:fwRegisterCalls[0] -ceq "root/standardcimv2|MSFT_NetFirewallHyperVVMCreator|RegisterHyperVVMCreator|$wslCreator|WSL" -and
           $script:firewallDefault -eq 'Block') 'an absent WSL creator is registered by the WSL provider call, then set to inbound Block'
    Reset-FirewallState -Creators @() -Mode 'exists-race'
    $ok = $false; try { Set-MiosWslFirewallPolicy; $ok = $true } catch {}
    Check ($ok -and $script:firewallDefault -eq 'Block') 'an already-exists race is accepted once the creator record appears'
    Reset-FirewallState -Creators @() -Mode 'exists-absent'
    Expect-ThrowMatch { Set-MiosWslFirewallPolicy } 'did not appear' 'already-exists without a creator record stops after the re-query'
    Check ($script:sleeps -ge 1 -and $script:sleeps -le 5 -and $script:fwSetCalls -eq 0) 'the creator re-query is bounded and sets no policy'
    Reset-FirewallState -Creators @() -Mode 'ok-absent'
    Expect-ThrowMatch { Set-MiosWslFirewallPolicy } 'did not appear' 'a zero return without a creator record stops the installer'
    Reset-FirewallState -Creators @() -Mode 'rv-fail'
    Expect-ThrowMatch { Set-MiosWslFirewallPolicy } 'returned 5' 'a failing RegisterHyperVVMCreator return value stops the installer'
    Reset-FirewallState -Creators @() -Mode 'denied'
    Expect-ThrowMatch { Set-MiosWslFirewallPolicy } 'Registering the WSL firewall creator failed' 'a registration error stops the installer'
    Check ($script:fwSetCalls -eq 0) 'no policy is set after a failed registration'
    # Set succeeds but the effective policy is unsafe (Group Policy, for one): stop before MiOS-DEV.
    Reset-FirewallState -Creators @($wslCreator) -Mode 'ok'
    $script:fwActiveOverride = @{ DefaultInboundAction = 'Allow' }
    Expect-ThrowMatch { Set-MiosWslFirewallPolicy } 'did not read back' 'Set success with an effective inbound Allow stops the installer'
    $script:fwActiveOverride = @{ Enabled = 'False' }
    Expect-ThrowMatch { Set-MiosWslFirewallPolicy } 'did not read back' 'Set success with an effective disabled firewall stops the installer'
    Reset-FirewallState -Creators @($wslCreator) -Mode 'ok'
    $script:firewallSetError = 'Access is denied.'
    Expect-Throw { Set-MiosWslFirewallPolicy } 'a firewall Set failure stops the installer'
    Reset-FirewallState -Creators @($wslCreator) -Mode 'ok'
    $script:hiddenCommand = 'Invoke-CimMethod'
    function global:Get-Command {
        [CmdletBinding()]param([Parameter(Position = 0)][string[]]$Name)
        if ($Name -contains $script:hiddenCommand) { return }
        Microsoft.PowerShell.Core\Get-Command -Name $Name
    }
    try { Expect-ThrowMatch { Set-MiosWslFirewallPolicy } 'provider is unavailable' 'an unavailable Hyper-V firewall provider stops the installer' }
    finally { Remove-Item -Path 'Function:\Get-Command' }
    if (Test-Path -Path 'Function:\Get-Command') { throw 'Fixture: the Get-Command wrapper was not removed.' }
    Check ($script:fwSetCalls -eq 0) 'no policy is set without the provider'
    # dism: 3010 and 'Enable Pending' mean enabled-but-inactive -> the run must halt for the restart, never skip it
    Check ((Get-MiosDismEnableOutcome 0) -eq 'enabled' -and (Get-MiosDismEnableOutcome 3010) -eq 'restart' -and
           (Get-MiosDismEnableOutcome 50) -eq 'unavailable') 'dism exit 3010 is enabled-with-restart, not unavailable'
    Check ((Get-MiosFeatureState @('Feature Name : VirtualMachinePlatform', 'State : Enabled')) -eq 'enabled' -and
           (Get-MiosFeatureState @('State : Enable Pending')) -eq 'pending' -and
           (Get-MiosFeatureState @('State : Disabled')) -eq 'disabled') 'feature state separates Enabled from Enable Pending'
    # Readiness gate: only 'ready' reaches the WSL firewall policy; pending halts, error and deferred stop.
    $g = Invoke-GateCase
    Check ($g.Status -eq 'ready' -and $script:fwSetCalls -eq 1) 'active features reach the WSL firewall policy'
    $g = Invoke-GateCase -State @{ VirtualMachinePlatform = 'Disabled' } -Exit @{ VirtualMachinePlatform = 3010 }
    Check ($g.Status -eq 'pending' -and $script:fwSetCalls -eq 0) 'a 3010 VMP enable halts for the restart even with Store wsl.exe present'
    $g = Invoke-GateCase -State @{ VirtualMachinePlatform = 'Enable Pending' }
    Check ($g.Status -eq 'pending' -and $script:fwSetCalls -eq 0) 'an Enable Pending feature halts before the WSL firewall policy'
    $script:toml['bootstrap.prereqs.features.require_reboot_to_continue'] = 'false'
    $g = Invoke-GateCase -State @{ VirtualMachinePlatform = 'Enable Pending' }
    $script:toml.Clear()
    Check ($g.Status -eq 'pending' -and $script:fwSetCalls -eq 0) 'require_reboot_to_continue=false cannot skip the restart'
    $g = Invoke-GateCase -State @{ VirtualMachinePlatform = 'Disabled' } -Exit @{ VirtualMachinePlatform = 50 }
    Check ($g.Error -match 'not ready \(error: Virtual Machine Platform' -and $script:fwSetCalls -eq 0) 'a required VMP failure stops before the WSL firewall policy'
    $g = Invoke-GateCase -State @{ 'Microsoft-Windows-Subsystem-Linux' = 'Disabled' } -Exit @{ 'Microsoft-Windows-Subsystem-Linux' = 50 } -StoreWsl $false
    Check ($g.Error -match 'not ready \(error: Windows Subsystem for Linux' -and $script:fwSetCalls -eq 0) 'a required WSL failure without Store wsl.exe stops before the policy'
    $g = Invoke-GateCase -State @{ 'Microsoft-Windows-Subsystem-Linux' = 'Disabled' }
    Check ($g.Status -eq 'ready' -and @($script:dismCalls | Where-Object { $_ -match '/enable-feature' }).Count -eq 0) 'Store wsl.exe satisfies the WSL optional feature'
    $g = Invoke-GateCase -State @{ 'Microsoft-Hyper-V' = 'Disabled' } -Exit @{ 'Microsoft-Hyper-V' = 50 }
    Check ($g.Status -eq 'ready' -and $script:fwSetCalls -eq 1) 'an unavailable optional Hyper-V feature does not block'
    $g = Invoke-GateCase -State @{ VirtualMachinePlatform = 'Disabled'; 'Microsoft-Windows-Subsystem-Linux' = 'Disabled' } `
        -Exit @{ VirtualMachinePlatform = 3010; 'Microsoft-Windows-Subsystem-Linux' = 50 } -StoreWsl $false
    Check ($g.Error -match 'not ready \(error:' -and $script:fwSetCalls -eq 0) 'a required failure with a pending restart still stops'
    $script:elevated = $false
    $g = Invoke-GateCase
    $script:elevated = $true
    Check ($g.Error -match 'not ready \(deferred:' -and $script:dismCalls.Count -eq 0 -and $script:fwSetCalls -eq 0) 'an unelevated run is deferred and stops'
    Reset-FeatureState; Reset-FirewallState -Creators @($wslCreator) -Mode 'ok'
    $script:fwActiveOverride = @{ DefaultInboundAction = 'Allow' }
    Expect-ThrowMatch { Invoke-MiosPlatformGate } 'did not read back' 'an unsafe readback stops the readiness gate'
    Reset-FirewallState -Creators @($wslCreator) -Mode 'ok'
    # Source order: the gate runs unguarded at top level before the MiOS-DEV hand-off, and only the gate applies the policy.
    $commands = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] }, $true))
    $unguarded = { param($node) for ($p = $node.Parent; $p; $p = $p.Parent) {
        if ($p -is [Management.Automation.Language.FunctionDefinitionAst] -or $p -is [Management.Automation.Language.TryStatementAst]) { return $false } }
        return $true }
    $gateCalls = @($commands | Where-Object { $_.GetCommandName() -eq 'Invoke-MiosPlatformGate' })
    $handoff = @($commands | Where-Object { $_.CommandElements[0].Extent.Text -eq '$entry' })
    Check ($gateCalls.Count -eq 1 -and (& $unguarded $gateCalls[0]) -and $handoff.Count -eq 1 -and
           $gateCalls[0].Extent.StartOffset -lt $handoff[0].Extent.StartOffset) 'the readiness gate runs unguarded at top level before the MiOS-DEV hand-off'
    $inGate = { param($node) for ($p = $node.Parent; $p; $p = $p.Parent) {
        if ($p -is [Management.Automation.Language.FunctionDefinitionAst]) { return $p.Name -eq 'Invoke-MiosPlatformGate' } }
        return $false }
    Check (@($commands | Where-Object { $_.GetCommandName() -in @('Set-MiosWslFirewallPolicy', 'Enable-MiOSWindowsFeatures') -and -not (& $inGate $_) }).Count -eq 0) 'only the readiness gate enables features or applies the WSL firewall policy'
    $ifs = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.IfStatementAst] }, $true))
    $guard = @($ifs | Where-Object { $_.Clauses[0].Item1.Extent.Text -ceq '-not $_isAdmin -and $env:MIOS_GETMIOS_RELAUNCHED' })
    $elevate = @($ifs | Where-Object { $_.Clauses[0].Item1.Extent.Text -ceq '-not $_isAdmin -and -not $env:MIOS_GETMIOS_RELAUNCHED' })
    Check ($guard.Count -eq 1 -and $elevate.Count -eq 1 -and $guard[0].Extent.StartOffset -lt $elevate[0].Extent.StartOffset -and
           @($guard[0].Clauses[0].Item2.FindAll({ param($n) $n -is [Management.Automation.Language.ThrowStatementAst] }, $true)).Count -eq 1) 'a stale relaunch marker in an unelevated session stops before any admin step'
    $script:fixtureVendor = @'
[[wsl2.inbound]]
name = 'fixture'
protocol = 'TCP'
local_port = '12345'
remote_address = '192.0.2.0/24'
reason = 'Fixture only'
'@
    try { Set-MiosWslFirewallPolicy } catch {}
    Check ($script:firewallAdded.Count -eq 1 -and $script:firewallAdded[0].Remote -eq '192.0.2.0/24') 'a scoped explicit inbound rule is applied'
    foreach ($bad in @('Any', '0.0.0.0/0', '::/0', '0.0.0.0-255.255.255.255')) {
        $script:fixtureVendor = $script:fixtureVendor.Replace('192.0.2.0/24', $bad)
        Expect-Throw { Set-MiosWslFirewallPolicy } "unscoped remote $bad is refused"
        $script:fixtureVendor = $script:fixtureVendor.Replace($bad, '192.0.2.0/24')
    }
    $managed = @('memory=8GB', 'networkingMode=NAT', 'localhostForwarding=true')
    $existing = "[wsl2]`n" + ($managed -join "`n") + "`nfirewall=false`ncustom=value`n[experimental]`ncustomExperimental=keep`n"
    $updated = Get-MiosWslConfigText -Existing $existing -ManagedLines $managed -Firewall $true
    Check ($updated -match '(?m)^firewall=true\r?$' -and $updated -notmatch '(?m)^firewall=false') 'SSOT true replaces stale false when all other managed keys already match'
    Check ($updated.Contains('custom=value') -and $updated.Contains('[experimental]') -and $updated.Contains('customExperimental=keep')) 'unmanaged WSL keys and sections remain'
    Check ((Get-MiosWslConfigText -Existing $updated -ManagedLines $managed -Firewall $true) -ceq $updated) 'WSL firewall reconciliation is stable on retry'
    Expect-Throw { Get-MiosWslConfigText -Existing $existing -ManagedLines $managed -Firewall $false } 'an explicit insecure SSOT firewall=false fails closed'
    Check ($global:MiosFixtureTripwires.Count -eq 0) 'no disk/partition verb, dummy firewall object, or MiOS-DEV start was invoked'
    if (-not $SkipReceiverProtocol) { Invoke-ReceiverProtocolChecks }
    Write-Host "SOURCE_FIXTURE_ASSERTIONS $($script:checks)"
    return $script:fail
}
function Invoke-ReceiverProtocolChecks {
    $protocolStartFailures = $script:fail
    $shell = Get-Command sh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $shell) {
        if ($PlantReceiverFailure) { throw 'A POSIX shell is required to exercise the receiver baseline control.' }
        Write-Host 'SOURCE_RECEIVER_PROTOCOL_UNRUN (sh unavailable)'; return
    }
    $receiverHome = Join-Path $scratch 'receiver-home'
    $receiverDirectory = Join-Path (Join-Path $receiverHome '.config') 'mios'
    New-Item -ItemType Directory -Path $receiverDirectory -Force -ErrorAction Stop | Out-Null
    $target = Join-Path $receiverDirectory 'mios.toml'
    $content = (New-Object Text.UTF8Encoding($false)).GetBytes('fixture-' + [char]0x03bb + '-without-final-newline')
    $old = (New-Object Text.UTF8Encoding($false)).GetBytes('fixture-old-canonical')
    foreach ($mode in @('complete', 'short', 'interrupted')) {
        Get-ChildItem -LiteralPath $receiverDirectory -Filter '.mios.*' -Force | Remove-Item -Force -ErrorAction Stop
        [IO.File]::WriteAllBytes($target, $old)
        $expected = $content.LongLength
        if ($PlantReceiverFailure -and $mode -eq 'complete') { $expected++ }
        $program = Get-MiosUserTomlReceiverScript -ExpectedBytes $expected
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = $shell.Source
        $psi.Arguments = (@('-c', $program) | ForEach-Object { ConvertTo-MiosNativeArgument $_ }) -join ' '
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
        $psi.EnvironmentVariables['HOME'] = $receiverHome
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $psi
        $callerEncoding = [Console]::InputEncoding
        $callerSignature = $callerEncoding.CodePage.ToString() + ':' + [Convert]::ToBase64String($callerEncoding.GetPreamble())
        $savedInputEncoding = $null; $changedInputEncoding = $false
        try {
            # Deliberately hostile caller state reproduces the Desktop StreamWriter BOM regression.
            if ($PSVersionTable.PSEdition -eq 'Desktop') {
                [Console]::InputEncoding = New-Object Text.UTF8Encoding($true)
                $savedInputEncoding = [Console]::InputEncoding; $changedInputEncoding = $true
                [Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
            } elseif ($psi.PSObject.Properties['StandardInputEncoding']) {
                $psi.StandardInputEncoding = New-Object Text.UTF8Encoding($false)
            }
            if (-not $process.Start()) { throw 'Fixture receiver could not start.' }
            $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
            $count = if ($mode -eq 'complete') { $content.Length } else { [int][math]::Floor($content.Length / 2) }
            $process.StandardInput.BaseStream.Write($content, 0, $count)
            $process.StandardInput.BaseStream.Flush()
            if ($mode -eq 'interrupted') {
                $pendingSeen = $false
                for ($attempt = 0; $attempt -lt 200; $attempt++) {
                    if (@(Get-ChildItem -LiteralPath $receiverDirectory -Filter '.mios.*' -Force).Count) { $pendingSeen = $true; break }
                    [Threading.Thread]::Sleep(10)
                }
                Check $pendingSeen 'interrupted receiver started its private pending write'
                if (-not $process.HasExited) { $process.Kill() }
            }
            $process.StandardInput.Close()
            if (-not $process.WaitForExit(10000)) { $process.Kill(); throw 'Fixture receiver did not exit.' }
            $null = $stdout.GetAwaiter().GetResult(); $null = $stderr.GetAwaiter().GetResult()
            $actual = [Convert]::ToBase64String([IO.File]::ReadAllBytes($target))
            if ($mode -eq 'complete') {
                Check ($process.ExitCode -eq 0 -and $actual -ceq [Convert]::ToBase64String($content)) 'complete receiver publishes exact UTF8 bytes without an added newline'
                if ($env:OS -ne 'Windows_NT') {
                    $modeText = (& stat -c '%a' $target) -join ''
                    Check ($LASTEXITCODE -eq 0 -and $modeText.Trim() -eq '600') 'complete receiver publishes mode 0600'
                }
            } else {
                Check ($process.ExitCode -ne 0 -and $actual -ceq [Convert]::ToBase64String($old)) "$mode receiver input retains the old canonical TOML"
            }
        } finally {
            try { if (-not $process.HasExited) { $process.Kill() } } catch {}
            try { $process.Dispose() }
            finally {
                try { if ($changedInputEncoding) { [Console]::InputEncoding = $savedInputEncoding } }
                finally { [Console]::InputEncoding = $callerEncoding }
            }
        }
        $restoredEncoding = [Console]::InputEncoding
        $restoredSignature = $restoredEncoding.CodePage.ToString() + ':' + [Convert]::ToBase64String($restoredEncoding.GetPreamble())
        Check ($restoredSignature -ceq $callerSignature) 'receiver harness restores caller console input encoding'
    }
    if ($script:fail -eq $protocolStartFailures) { Write-Host 'SOURCE_RECEIVER_PROTOCOL PASS' }
    else { Write-Host 'SOURCE_RECEIVER_PROTOCOL FAIL' }
}

function Assert-SourceDefectBaseline {
    $baselineFailures = Invoke-Checks $realScript
    if ($baselineFailures) { throw 'SOURCE_DEFECT_BASELINE_FAILED' }
}
function Invoke-WindowsAclChecks([string]$ProductPath = $realScript) {
    if ($env:OS -ne 'Windows_NT') { throw '-WindowsAcl requires a Windows host; no Windows API acceptance is claimed.' }
    $script:fail = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
    $null = Import-MiosFunctions $ProductPath
    $runRoot = Join-Path $scratch ('windows-acl-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop | Out-Null
    $source = Join-Path $runRoot 'download.toml'
    $userPath = Join-Path (Join-Path $runRoot 'user') 'mios.toml'
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $allowed = @('S-1-5-18', 'S-1-5-32-544', [string]$owner)
    foreach ($generation in 1..3) {
        $text = $fixture + "`r`n# fixture generation $generation " + [char]0x03bb
        [IO.File]::WriteAllText($source, $text, (New-Object Text.UTF8Encoding($false)))
        $null = Import-MiosUserToml -SourcePath $source -DestinationPath $userPath
        Check ([Convert]::ToBase64String([IO.File]::ReadAllBytes($source)) -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($userPath))) 'Windows private first/repeated replacement preserves exact bytes'
        $acl = Get-Acl -LiteralPath $userPath
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        Check ($acl.AreAccessRulesProtected -and @($rules | Where-Object { $_.IdentityReference.Value -notin $allowed }).Count -eq 0 -and
               $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $owner.Value) 'Windows user TOML grants no other principals access'
    }
    if ($script:fail -eq 0) { Write-Host 'WINDOWS_PRIVATE_ACL_FIXTURE PASS' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'WINDOWS_HOST_ACL_FIXTURE UNRUN (elevation required for Administrators ownership)'
        throw 'Private ACL checks completed; full Windows ACL acceptance requires an elevated scratch-only host-tier run.'
    }
    $hostRoot = Join-Path $runRoot 'host-tier'
    New-Item -ItemType Directory -Path $hostRoot -ErrorAction Stop | Out-Null
    $hostPath = Join-Path (Join-Path $hostRoot 'etc') 'mios/mios.toml'
    foreach ($generation in 1..3) {
        $text = $fixture + "`r`n[fixture_generation]`r`nvalue = $generation`r`n"
        Write-MiosHostToml -Path $hostPath -Text $text
        Check ([IO.File]::ReadAllText($hostPath) -ceq (ConvertTo-MiosCredentialFreeToml $text)) 'Windows host first/repeated replacement publishes only the expected projection'
        foreach ($path in @($hostPath, (Split-Path -Parent $hostPath), (Split-Path -Parent (Split-Path -Parent $hostPath)))) {
            $acl = Get-Acl -LiteralPath $path
            $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
            $users = @($rules | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-32-545' })
            $write = [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
            Check ($acl.AreAccessRulesProtected -and $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544' -and
                   @($rules | Where-Object { $_.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544','S-1-5-32-545') }).Count -eq 0 -and
                   @($users | Where-Object { ($_.FileSystemRights -band $write) -ne 0 }).Count -eq 0) 'Windows host file and parent directories grant Users no write/delete rights'
        }
    }
    if ($script:fail -eq 0) { Write-Host 'WINDOWS_HOST_ACL_FIXTURE PASS' }
    return $script:fail
}

$savedEnvironment = @{}
foreach ($name in @('TEMP','TMP','USERPROFILE','LOCALAPPDATA','APPDATA','SystemRoot')) { $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name) }
try {
    $env:TEMP = 'C:\Users\Fixture\AppData\Local\Temp'; $env:TMP = $env:TEMP
    $env:USERPROFILE = 'C:\Users\Fixture'; $env:LOCALAPPDATA = 'C:\Users\Fixture\AppData\Local'; $env:APPDATA = 'C:\Users\Fixture\AppData\Roaming'; $env:SystemRoot = 'C:\Windows'
    if ($VerifyReceiverBaselineGuard) {
        $PlantReceiverFailure = $true
        $rejected = $false
        try { Assert-SourceDefectBaseline }
        catch {
            if ($_.Exception.Message -ceq 'SOURCE_DEFECT_BASELINE_FAILED' -and
                $script:failedChecks.Contains('complete receiver publishes exact UTF8 bytes without an added newline')) { $rejected = $true }
            else { throw }
        }
        if (-not $rejected) { throw 'A broken receiver baseline was accepted by the defect tally guard.' }
        Write-Host 'SOURCE_DEFECT_BASELINE_GUARD PASS'
        exit 0
    }
    if ($WindowsAcl) {
        $baselineFailures = Invoke-WindowsAclChecks $realScript
        if ($baselineFailures) { Write-Host 'WINDOWS_ACL_BASELINE_FAILED'; exit 1 }
        if (-not $PlantDefect) { Write-Host 'WINDOWS_ACL_FIXTURE_ONLY PASS'; exit 0 }
        $source = [IO.File]::ReadAllText($realScript)
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
        $aclCaught = 0
        foreach ($name in @('Set-MiosPrivateUserTomlAcl', 'Set-MiosHostTierAcl')) {
            $definition = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true))[0].Extent.Text
            $anchor = '$acl.SetAccessRuleProtection($true, $false)'
            if (-not $definition.Contains($anchor)) { throw 'Missing ACL mutation anchor.' }
            $broken = $definition.Replace($anchor, '$acl.SetAccessRuleProtection($false, $true)')
            $copy = Join-Path $scratch ($name + '-planted.ps1')
            [IO.File]::WriteAllText($copy, $source.Replace($definition, $broken), (New-Object Text.UTF8Encoding($false)))
            $null = Invoke-WindowsAclChecks $copy
            $expected = if ($name -eq 'Set-MiosPrivateUserTomlAcl') { 'Windows user TOML grants no other principals access' } else { 'Windows host file and parent directories grant Users no write/delete rights' }
            if ($script:failedChecks.Contains($expected)) { $aclCaught++ } else { throw 'The Windows ACL mutation was not detected by its intended policy assertion.' }
        }
        if ($aclCaught -eq 2) { Write-Host 'WINDOWS_ACL_PLANTS PASS (2/2)'; exit 0 }
        exit 1
    }
    if (-not $PlantDefect) {
        $failures = Invoke-Checks $realScript
        if ($failures) { Write-Host "RESULT: FAIL ($failures checks)"; exit 1 }
        Write-Host 'RESULT: PASS (source fixtures; Windows APIs mocked)'; exit 0
    }
    # A planted defect is meaningful only after the complete, unmodified baseline (including receiver) passes.
    Assert-SourceDefectBaseline
    $plants = @(
        @{ Name = 'raw host projection'; ExpectedException = 'The host projection still contains credential fields; refusing to write.'; From = '$proj = ConvertTo-MiosCredentialFreeToml $Text'; To = '$proj = $Text' },
        @{ Name = 'canonical alias pass omitted'; Expected = 'canonical alias pgvector.pass is recognized'; From = 'password|passwd|pass|passphrase'; To = 'password|passwd|passphrase' },
        @{ Name = 'inbound Allow'; Expected = 'WSL inbound remains Block by default'; From = "DefaultInboundAction = 'Block'"; To = "DefaultInboundAction = 'Allow'" },
        @{ Name = 'path canonicalization omitted'; Expected = 'Defender refuses C:/'; From = 'try { $p = ConvertTo-MiosWindowsPath $Path }'; To = 'try { $p = $Path }' },
        @{ Name = 'stale inbound removal omitted'; Expected = 'deleted owned allow rules are removed and other rules preserved'; From = 'Remove-NetFirewallHyperVRule -Name $old.Name -ErrorAction Stop'; To = '$null = $old.Name' },
        @{ Name = 'dism 3010 read as unavailable'; Expected = 'dism exit 3010 is enabled-with-restart, not unavailable'; From = "3010 { return 'restart' }"; To = "3010 { return 'unavailable' }" },
        @{ Name = 'restart outcome does not halt'; Expected = 'a 3010 VMP enable halts for the restart even with Store wsl.exe present'; From = "elseif (`$outcome -eq 'restart') {"; To = "elseif (`$outcome -eq 'restart-never') {" },
        @{ Name = 'existing creator re-registered'; Expected = 'an existing WSL creator is set in place, never re-registered'; From = 'if (-not (Test-MiosWslVmCreator $creator)) { Register-MiosWslVmCreator $creator }'; To = 'Register-MiosWslVmCreator $creator' },
        @{ Name = 'absent creator not registered'; Expected = 'an absent WSL creator is registered by the WSL provider call, then set to inbound Block'; From = 'if (-not (Test-MiosWslVmCreator $creator)) { Register-MiosWslVmCreator $creator }'; To = '$null = $creator' },
        @{ Name = 'already-exists trusted without the record'; Expected = 'already-exists without a creator record stops after the re-query'; From = 'if (Test-MiosWslVmCreator $Creator) { return }'; To = 'return' },
        @{ Name = 'register return value ignored'; Expected = 'a failing RegisterHyperVVMCreator return value stops the installer'; From = 'if ($rv -ne 0 -and $rv -ne $alreadyExists) {'; To = 'if ($false) {' },
        @{ Name = 'unsafe inbound readback accepted'; Expected = 'Set success with an effective inbound Allow stops the installer'; From = "[string]`$active[0].DefaultInboundAction -ne 'Block'"; To = '$false' },
        @{ Name = 'readback from the persistent store'; Expected = 'Set success with an effective inbound Allow stops the installer'; From = '-PolicyStore ActiveStore -Name $creator'; To = '-PolicyStore PersistentStore -Name $creator' },
        @{ Name = 'provider check removed'; Expected = 'an unavailable Hyper-V firewall provider stops the installer'; From = 'if ($missing.Count) { throw'; To = 'if ($false) { throw' },
        @{ Name = 'pending reaches the policy'; Expected = 'an Enable Pending feature halts before the WSL firewall policy'; From = "'pending' { return `$result }"; To = "'pending' { `$null = Set-MiosWslFirewallPolicy; return `$result }" },
        @{ Name = 'required VMP failure skipped'; Expected = 'a required VMP failure stops before the WSL firewall policy'; From = '} elseif ($feature.Required) {'; To = '} elseif ($false) {' },
        @{ Name = 'deferred treated as ready'; Expected = 'an unelevated run is deferred and stops'; From = "return [pscustomobject]@{ Status = 'deferred'"; To = "return [pscustomobject]@{ Status = 'ready'" },
        @{ Name = 'error status continues'; Expected = 'a required VMP failure stops before the WSL firewall policy'; From = 'default   { throw "Windows features are not ready'; To = 'default   { return $result; throw "Windows features are not ready' },
        @{ Name = 'warning-only catch around the gate'; Expected = 'the readiness gate runs unguarded at top level before the MiOS-DEV hand-off'; From = '$_platform = Invoke-MiosPlatformGate'; To = 'try { $_platform = Invoke-MiosPlatformGate } catch { Write-Host $_ }' },
        @{ Name = 'stale relaunch guard removed'; Expected = 'a stale relaunch marker in an unelevated session stops before any admin step'; From = 'if (-not $_isAdmin -and $env:MIOS_GETMIOS_RELAUNCHED) {'; To = 'if ($false) {' },
        @{ Name = 'partition verb in the gate'; Expected = 'no disk/partition verb, dummy firewall object, or MiOS-DEV start was invoked'; From = "'ready'   { `$null = Set-MiosWslFirewallPolicy;"; To = "'ready'   { New-Partition -DiskNumber 0 -UseMaximumSize; `$null = Set-MiosWslFirewallPolicy;" },
        @{ Name = 'dummy firewall object'; Expected = 'no disk/partition verb, dummy firewall object, or MiOS-DEV start was invoked'; From = 'Set-NetFirewallHyperVVMSetting -Name $creator @policy -ErrorAction Stop'; To = 'New-NetFirewallHyperVVMSetting -Name $creator @policy -ErrorAction Stop' },
        @{ Name = 'MiOS-DEV started while pending'; Expected = 'no disk/partition verb, dummy firewall object, or MiOS-DEV start was invoked'; From = "'pending' { return `$result }"; To = "'pending' { & wsl.exe -d MiOS-DEV -- true; return `$result }" }
    )
    $caught = 0
    foreach ($plant in $plants) {
        $text = [IO.File]::ReadAllText($realScript)
        if (-not $text.Contains($plant.From)) { throw "Missing defect anchor: $($plant.Name)" }
        $copy = Join-Path $scratch ('planted-' + $caught + '.ps1')
        [IO.File]::WriteAllText($copy, $text.Replace($plant.From, $plant.To), (New-Object Text.UTF8Encoding($false)))
        $detected = $false
        try {
            $null = Invoke-Checks $copy -SkipReceiverProtocol
            $detected = $plant.Expected -and $script:failedChecks.Contains($plant.Expected)
        } catch {
            if ($plant.ExpectedException -and $_.Exception.Message -ceq $plant.ExpectedException) { $detected = $true }
            else { throw }
        }
        Check $detected ("planted defect caught: " + $plant.Name)
        if ($detected) { $caught++ }
    }
    if ($caught -eq $plants.Count) { Write-Host "RESULT: PASS (every planted defect was caught: $caught/$($plants.Count))"; exit 0 }
    Write-Host "RESULT: FAIL (planted defects caught: $caught/$($plants.Count))"; exit 1
} finally {
    foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name]) }
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction Stop
}
