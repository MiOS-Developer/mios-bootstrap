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
function Import-MiosFunctions([string]$Path) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Product source does not parse: $($errors[0].Message)" }
    $want = @('Get-MiosTomlAssignments', 'Split-MiosTomlKeyLine', 'Get-MiosTomlCredentialKeys', 'ConvertTo-MiosCredentialFreeToml',
        'Assert-MiosNoReparsePath', 'Set-MiosHostTierAcl', 'Initialize-MiosHostTierDirectory', 'Write-MiosHostToml',
        'Repair-MiosHostTierCredentials', 'Get-MiosTomlTableArray', 'ConvertTo-MiosWindowsPath', 'Test-MiosDefenderExclusionRefused',
        'Get-MiosDefenderExclusionPlan', 'Add-MiosDefenderExclusions', 'Set-MiosWslFirewallPolicy', 'Set-MiosPrivateUserTomlAcl',
        'Import-MiosUserToml', 'ConvertTo-MiosNativeArgument', 'Sync-MiosUserTomlToBuilder', 'Get-MiosUserTomlReceiverScript', 'Get-MiosWslConfigText')
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
function Invoke-Checks([string]$Path, [switch]$SkipReceiverProtocol) {
    $script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
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
    $managed = @('memory=8GB', 'networkingMode=NAT', 'localhostForwarding=true')
    $existing = "[wsl2]`n" + ($managed -join "`n") + "`nfirewall=false`ncustom=value`n[experimental]`ncustomExperimental=keep`n"
    $updated = Get-MiosWslConfigText -Existing $existing -ManagedLines $managed -Firewall $true
    Check ($updated -match '(?m)^firewall=true\r?$' -and $updated -notmatch '(?m)^firewall=false') 'SSOT true replaces stale false when all other managed keys already match'
    Check ($updated.Contains('custom=value') -and $updated.Contains('[experimental]') -and $updated.Contains('customExperimental=keep')) 'unmanaged WSL keys and sections remain'
    Check ((Get-MiosWslConfigText -Existing $updated -ManagedLines $managed -Firewall $true) -ceq $updated) 'WSL firewall reconciliation is stable on retry'
    Expect-Throw { Get-MiosWslConfigText -Existing $existing -ManagedLines $managed -Firewall $false } 'an explicit insecure SSOT firewall=false fails closed'
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
        @{ Name = 'inbound Allow'; Expected = 'WSL inbound remains Block by default'; From = '-DefaultInboundAction Block'; To = '-DefaultInboundAction Allow' },
        @{ Name = 'path canonicalization omitted'; Expected = 'Defender refuses C:/'; From = 'try { $p = ConvertTo-MiosWindowsPath $Path }'; To = 'try { $p = $Path }' },
        @{ Name = 'stale inbound removal omitted'; Expected = 'deleted owned allow rules are removed and other rules preserved'; From = 'Remove-NetFirewallHyperVRule -Name $old.Name -ErrorAction Stop'; To = '$null = $old.Name' }
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
