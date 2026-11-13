# Source-only fixtures: extract functions with the PowerShell AST; NEVER execute Get-MiOS.ps1 top-level.
# Default/PlantDefect use scratch files and mocked Windows APIs only, including on Native MiOS-DEV.
# -WindowsAcl additionally exercises real ACLs on an isolated Windows scratch tree (never C:\etc or M:).
[CmdletBinding()]
param([switch]$PlantDefect, [switch]$WindowsAcl, [string]$CanonicalVendorPath)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$realScript = Join-Path $repoRoot 'Get-MiOS.ps1'
if (-not $CanonicalVendorPath) {
    $CanonicalVendorPath = Join-Path $repoRoot 'usr/share/mios/mios.toml'
    if (-not (Test-Path -LiteralPath $CanonicalVendorPath)) { $CanonicalVendorPath = Join-Path $repoRoot 'mios.toml' }
}
if (-not (Test-Path -LiteralPath $CanonicalVendorPath -PathType Leaf)) { throw 'A tracked canonical vendor TOML is required for the grammar fixture.' }
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-getmios-security-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -ErrorAction Stop | Out-Null
$script:fail = 0; $script:checks = 0
function Check([bool]$Ok, [string]$What) {
    $script:checks++
    if ($Ok) { Write-Host "  PASS $What" } else { Write-Host "  FAIL $What"; $script:fail++ }
}
function Expect-Throw([scriptblock]$Action, [string]$What) {
    $caught = $false
    try { $null = & $Action } catch { $caught = $true }
    Check $caught $What
}
function Import-MiosFunctions([string]$Path) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Product source does not parse: $($errors[0].Message)" }
    $want = @('Get-MiosTomlAssignments', 'Split-MiosTomlKeyLine', 'Get-MiosTomlCredentialKeys', 'ConvertTo-MiosCredentialFreeToml',
        'Assert-MiosNoReparsePath', 'Set-MiosHostTierAcl', 'Initialize-MiosHostTierDirectory', 'Write-MiosHostToml',
        'Repair-MiosHostTierCredentials', 'Get-MiosTomlTableArray', 'ConvertTo-MiosWindowsPath', 'Test-MiosDefenderExclusionRefused',
        'Get-MiosDefenderExclusionPlan', 'Add-MiosDefenderExclusions', 'Set-MiosWslFirewallPolicy', 'Set-MiosPrivateUserTomlAcl',
        'Import-MiosUserToml', 'ConvertTo-MiosNativeArgument', 'Sync-MiosUserTomlToBuilder')
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
            if ((Get-Item -LiteralPath $Path).Length -ne 0) { throw 'Fixture: private ACL was set after bytes were written' }
        }
    }
    function global:Resolve-MiosTomlText { return $script:fixtureUser }
    function global:Resolve-MiosVendorTomlText { return $script:fixtureVendor }
    $script:removedExclusions = New-Object System.Collections.Generic.List[string]
    $script:addedExclusions = New-Object System.Collections.Generic.List[string]
    function global:Get-MpPreference { [CmdletBinding()]param() return [pscustomobject]@{ ExclusionPath = @('M:/', 'M:', ($env:TEMP + '/'), 'C:\MiOS\other') } }
    function global:Remove-MpPreference { [CmdletBinding()]param($ExclusionPath) $script:removedExclusions.Add($ExclusionPath) }
    function global:Add-MpPreference { [CmdletBinding()]param($ExclusionPath, $ExclusionProcess) $script:addedExclusions.Add([string]$ExclusionPath + [string]$ExclusionProcess) }
    $script:firewallRemoved = New-Object System.Collections.Generic.List[string]
    $script:firewallAdded = New-Object System.Collections.Generic.List[object]
    $script:firewallDefault = ''
    function global:Set-NetFirewallHyperVVMSetting {
        [CmdletBinding()]param($Name, $Enabled, $DefaultInboundAction, $DefaultOutboundAction, $LoopbackEnabled, $AllowHostPolicyMerge)
        $script:firewallDefault = $DefaultInboundAction
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
function Invoke-Checks([string]$Path) {
    $script:fail = 0; $script:checks = 0
    $null = Import-MiosFunctions $Path
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
    Check ($script:removedExclusions.Count -eq 3) 'legacy root/temp aliases are removed using their original stored spelling'
    Check ($script:addedExclusions.Count -eq 2) 'only explicit canonical narrow exclusions are added'
    $script:fixtureVendor = ''; Set-MiosWslFirewallPolicy
    Check ($script:firewallDefault -eq 'Block') 'WSL inbound remains Block by default'
    Check ($script:firewallRemoved.Count -eq 1 -and $script:firewallRemoved[0] -eq 'MiOS-WSL-deleted') 'deleted owned allow rules are removed and other rules preserved'
    $script:fixtureVendor = @'
[[wsl2.inbound]]
name = 'fixture'
protocol = 'TCP'
local_port = '12345'
remote_address = '192.0.2.0/24'
reason = 'Fixture only'
'@
    Set-MiosWslFirewallPolicy
    Check ($script:firewallAdded.Count -eq 1 -and $script:firewallAdded[0].Remote -eq '192.0.2.0/24') 'a scoped explicit inbound rule is applied'
    foreach ($bad in @('Any', '0.0.0.0/0', '::/0', '0.0.0.0-255.255.255.255')) {
        $script:fixtureVendor = $script:fixtureVendor.Replace('192.0.2.0/24', $bad)
        Expect-Throw { Set-MiosWslFirewallPolicy } "unscoped remote $bad is refused"
        $script:fixtureVendor = $script:fixtureVendor.Replace($bad, '192.0.2.0/24')
    }
    Write-Host "SOURCE_FIXTURE_ASSERTIONS $($script:checks)"
    return $script:fail
}
function Invoke-WindowsAclChecks {
    if ($env:OS -ne 'Windows_NT') { throw '-WindowsAcl requires a Windows host; no Windows API acceptance is claimed.' }
    $null = Import-MiosFunctions $realScript
    $source = Join-Path $scratch 'download.toml'
    $userPath = Join-Path (Join-Path $scratch 'user') 'mios.toml'
    [IO.File]::WriteAllText($source, $fixture, (New-Object Text.UTF8Encoding($false)))
    $null = Import-MiosUserToml -SourcePath $source -DestinationPath $userPath
    # Exercise existing-file replacement as well as first publication (the PS 5.1 genuine-null backup case).
    $null = Import-MiosUserToml -SourcePath $source -DestinationPath $userPath
    Check ([Convert]::ToBase64String([IO.File]::ReadAllBytes($source)) -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($userPath))) 'Windows private import preserves exact bytes on replacement'
    $acl = Get-Acl -LiteralPath $userPath
    $allowed = @('S-1-5-18', 'S-1-5-32-544', [string][Security.Principal.WindowsIdentity]::GetCurrent().User)
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    Check ($acl.AreAccessRulesProtected -and @($rules | Where-Object { $_.IdentityReference.Value -notin $allowed }).Count -eq 0) 'Windows user TOML grants no other principals access'
    $hostRoot = Join-Path $scratch 'acl-etc'
    New-Item -ItemType Directory -Path $hostRoot -ErrorAction Stop | Out-Null
    $hostPath = Join-Path (Join-Path $hostRoot 'etc') 'mios/mios.toml'
    Write-MiosHostToml -Path $hostPath -Text $fixture
    foreach ($path in @($hostPath, (Split-Path -Parent $hostPath), (Split-Path -Parent (Split-Path -Parent $hostPath)))) {
        $acl = Get-Acl -LiteralPath $path
        $users = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-32-545' })
        $write = [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
        Check ($acl.AreAccessRulesProtected -and @($users | Where-Object { ($_.FileSystemRights -band $write) -ne 0 }).Count -eq 0) 'Windows host file and parent directories grant Users no write/delete rights'
    }
    Write-Host 'WINDOWS_ACL_FIXTURE_ONLY PASS'
}
$savedEnvironment = @{}
foreach ($name in @('TEMP','TMP','USERPROFILE','LOCALAPPDATA','APPDATA','SystemRoot')) { $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name) }
try {
    $env:TEMP = 'C:\Users\Fixture\AppData\Local\Temp'; $env:TMP = $env:TEMP
    $env:USERPROFILE = 'C:\Users\Fixture'; $env:LOCALAPPDATA = 'C:\Users\Fixture\AppData\Local'; $env:APPDATA = 'C:\Users\Fixture\AppData\Roaming'; $env:SystemRoot = 'C:\Windows'
    if ($WindowsAcl) { Invoke-WindowsAclChecks; if ($script:fail) { exit 1 }; exit 0 }
    if (-not $PlantDefect) {
        $failures = Invoke-Checks $realScript
        if ($failures) { Write-Host "RESULT: FAIL ($failures checks)"; exit 1 }
        Write-Host 'RESULT: PASS (source fixtures; Windows APIs mocked)'; exit 0
    }
    $plants = @(
        @{ Name = 'raw host projection'; From = '$proj = ConvertTo-MiosCredentialFreeToml $Text'; To = '$proj = $Text' },
        @{ Name = 'canonical alias pass omitted'; From = 'password|passwd|pass|passphrase'; To = 'password|passwd|passphrase' },
        @{ Name = 'inbound Allow'; From = '-DefaultInboundAction Block'; To = '-DefaultInboundAction Allow' },
        @{ Name = 'path canonicalization omitted'; From = 'try { $p = ConvertTo-MiosWindowsPath $Path }'; To = 'try { $p = $Path }' },
        @{ Name = 'stale inbound removal omitted'; From = 'Remove-NetFirewallHyperVRule -Name $old.Name -ErrorAction Stop'; To = '$null = $old.Name' }
    )
    $caught = 0
    foreach ($plant in $plants) {
        $text = [IO.File]::ReadAllText($realScript)
        if (-not $text.Contains($plant.From)) { throw "Missing defect anchor: $($plant.Name)" }
        $copy = Join-Path $scratch ('planted-' + $caught + '.ps1')
        [IO.File]::WriteAllText($copy, $text.Replace($plant.From, $plant.To), (New-Object Text.UTF8Encoding($false)))
        $detected = $false
        try { $detected = (Invoke-Checks $copy) -gt 0 } catch { $detected = $true }
        Check $detected ("planted defect caught: " + $plant.Name)
        if ($detected) { $caught++ }
    }
    if ($caught -eq $plants.Count) { Write-Host "RESULT: PASS (every planted defect was caught: $caught/$($plants.Count))"; exit 0 }
    Write-Host "RESULT: FAIL (planted defects caught: $caught/$($plants.Count))"; exit 1
} finally {
    foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name]) }
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction Stop
}
