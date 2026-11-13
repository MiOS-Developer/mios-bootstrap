# Source fixtures only. Never invoke Get-MiOS.ps1 top-level, UAC, pipes, WSL, disk or registry APIs.
[CmdletBinding()]
param([switch]$PlantDefect, [switch]$WindowsAcl)
if ($PlantDefect -and $WindowsAcl) { throw 'Run source plants and Windows ACL fixtures separately.' }
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-MiOS.ps1'
function ConvertTo-MiosFixtureSource {
    param([Parameter(Mandatory)][string]$Text)
    return $Text.Replace("`r`n", "`n").Replace("`r", "`n")
}
# Git blobs use LF; Windows checkouts may use CRLF. Mutation anchors use the same canonical LF form.
$source = ConvertTo-MiosFixtureSource ([IO.File]::ReadAllText($sourcePath))
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-context-fixture-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$script:checks = 0
$script:failures = New-Object 'System.Collections.Generic.List[string]'
function Check([bool]$Ok, [string]$What) {
    $script:checks++
    if (-not $Ok) { $script:failures.Add($What); Write-Host "FAIL $What" }
}
function Must-Throw([scriptblock]$Body, [string]$What) {
    $caught = $false
    try { & $Body | Out-Null } catch { $caught = $true }
    Check $caught $What
}
function Parse-Source([string]$Text) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Invalid source AST: $($errors[0].Message)" }
    return $ast
}
function Import-Functions($Ast, [string[]]$Names) {
    foreach ($name in $Names) {
        $defs = @($Ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true))
        if ($defs.Count -ne 1) { throw "Missing or duplicate function $name" }
        . ([scriptblock]::Create(($defs[0].Extent.Text -replace '^function\s+', 'function global:')))
    }
    $policy = @($Ast.FindAll({ param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$Script:MiosCredentialKeyRe' }, $true))
    if ($policy.Count -eq 1) { . ([scriptblock]::Create($policy[0].Extent.Text)) }
}
function Run-Checks([string]$Text) {
    $ast = Parse-Source $Text
    Import-Functions $ast @('Assert-MiosNoReparsePath', 'Assert-MiosOriginContext', 'Get-MiosTomlAssignments', 'Get-MiosTomlCredentialKeys',
        'ConvertTo-MiosCredentialFreeToml', 'Resolve-MiosTomlText', 'Resolve-MiosVendorTomlText', 'Initialize-MiosHostTierDirectory',
        'Write-MiosHostToml', 'Invoke-MiosMachinePreparationRequest', 'Read-MiosPipeLine', 'Get-MiosMachineWorkerScript', 'Get-MiosWslConfigText',
        'New-MiosGetChildArguments', 'Get-MiosWindowsInstallRoot', 'Get-MiosWindowsBootstrapRoot', 'Get-MiosTerminalProfileCommand')
    $operator = Join-Path $scratch 'operator'
    $admin = Join-Path $scratch 'different-admin'
    foreach ($profile in @($operator, $admin)) { New-Item -ItemType Directory -Path (Join-Path $profile '.config/mios') -Force | Out-Null; New-Item -ItemType Directory -Path (Join-Path $profile 'local') -Force | Out-Null }
    $opToml = "[identity]`nusername = 'OPERATOR-SENTINEL'`ndefault_password = 'OPERATOR-PRIVATE-SENTINEL'`n"
    $adminToml = "[identity]`nusername = 'ADMIN-SENTINEL'`ndefault_password = 'ADMIN-PRIVATE-SENTINEL'`n"
    $opPath = Join-Path $operator '.config/mios/mios.toml'
    $adminPath = Join-Path $admin '.config/mios/mios.toml'
    [IO.File]::WriteAllText($opPath, $opToml)
    [IO.File]::WriteAllText($adminPath, $adminToml)
    $script:opSid = 'S-1-5-21-1-2-3-1001'; $script:adminSid = 'S-1-5-21-1-2-3-1002'
    $script:registeredProfile = $operator; $script:registeredLocal = Join-Path $operator 'local'
    $script:rawRegisteredLocal = '%USERPROFILE%' + [IO.Path]::DirectorySeparatorChar + 'local'
    $script:rawReadOption = ''
    $script:processSid = $script:opSid; $script:processSession = 17
    function global:Get-CimInstance { param($ClassName, $Filter, $ErrorAction) [pscustomobject]@{ ProcessId = 4242; SessionId = $script:processSession } }
    function global:Invoke-CimMethod { param($InputObject, $MethodName, $ErrorAction) [pscustomobject]@{ ReturnValue = 0; Sid = $script:processSid } }
    function global:Get-Process { param($Id) [pscustomobject]@{ SessionId = 17 } }
    function global:Get-ItemProperty {
        param($LiteralPath, $ErrorAction)
        if ($LiteralPath -like '*ProfileList*') { return [pscustomobject]@{ ProfileImagePath = $script:registeredProfile } }
        if ($LiteralPath -like '*User Shell Folders') { return [pscustomobject]@{ 'Local AppData' = [Environment]::ExpandEnvironmentVariables($script:rawRegisteredLocal) } }
        throw 'Unexpected registry fixture read.'
    }
    function global:Get-Item {
        [CmdletBinding()]param([string]$LiteralPath, [switch]$Force)
        if ($LiteralPath -like 'Registry::*User Shell Folders') {
            $key = [pscustomobject]@{}
            $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
                param($Name, $Default, $Options)
                $script:rawReadOption = [string]$Options
                if ($Options -eq [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) { return $script:rawRegisteredLocal }
                return [Environment]::ExpandEnvironmentVariables($script:rawRegisteredLocal)
            }
            $key | Add-Member -MemberType ScriptMethod -Name Close -Value {}
            return $key
        }
        Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
    }
    function global:Set-MiosHostTierAcl { param($Path, [switch]$Private) }
    $origin = [pscustomobject]@{ Sid = $script:opSid; Profile = $operator; LocalAppData = $script:registeredLocal
        ConfigPath = $opPath; ProcessId = 4242; SessionId = 17 }
    $vendor = "[meta]`nname = 'fixture'`n[identity]`nusername = 'vendor'`n[packages.windows]`npkgs = []`n"
    $script:coreCalls = 0
    $script:hostPath = Join-Path $scratch 'host/etc/mios/mios.toml'
    function global:Invoke-MiosMachinePreparationCore {
        param($Context)
        $script:coreCalls++
        $script:coreOrigin = $Context
        $script:observedMachineProfile = $env:USERPROFILE
        Write-MiosHostToml -Path $script:hostPath -Text (Resolve-MiosTomlText)
        [pscustomobject]@{ Status = 'ready' }
    }
    foreach ($machineProfile in @($operator, $admin)) {
        # Model the actual two processes' different environments; product code never substitutes USERPROFILE.
        $env:USERPROFILE = $operator; $script:_MiosTomlCache = @{}
        $private = Resolve-MiosTomlText
        $projection = ConvertTo-MiosCredentialFreeToml $private
        $request = [pscustomobject]@{ Origin = $origin; OperatorToml = $projection; VendorToml = $vendor }
        $env:USERPROFILE = $machineProfile; $script:_MiosTomlCache = @{}
        $result = Invoke-MiosMachinePreparationRequest -Request $request -OriginProcessId 4242
        Check ($result.Status -eq 'ready' -and $script:coreOrigin.Sid -eq $script:opSid) 'same-user and different-admin dispatch retain the real operator SID'
        Check ($script:observedMachineProfile -eq $machineProfile) 'the machine phase keeps its actual token profile'
        $hostText = [IO.File]::ReadAllText($script:hostPath)
        Check ($hostText.Contains('OPERATOR-SENTINEL') -and -not $hostText.Contains('PRIVATE-SENTINEL') -and -not $hostText.Contains('ADMIN-SENTINEL')) 'host projection comes only from the operator and contains no credentials'
        Check ($script:_MiosTomlCache['_source'] -eq $origin.ConfigPath) 'machine configuration provenance names the validated operator file'
        Check ([IO.File]::ReadAllText($opPath) -ceq $opToml -and [IO.File]::ReadAllText($adminPath) -ceq $adminToml) 'both private TOML sentinels remain untouched'
    }
    Check ($script:rawReadOption -eq 'DoNotExpandEnvironmentNames') 'raw known-folder values expand only against the validated operator profile'
    $before = $script:coreCalls
    foreach ($change in @(@('Sid', $script:adminSid), @('Profile', $admin), @('LocalAppData', (Join-Path $admin 'local')),
        @('ConfigPath', $adminPath), @('ProcessId', 9999), @('SessionId', 23))) {
        $badOrigin = $origin | ConvertTo-Json | ConvertFrom-Json
        $badOrigin.($change[0]) = $change[1]
        if ($change[0] -eq 'Profile') { $badOrigin.ConfigPath = $adminPath; $badOrigin.LocalAppData = Join-Path $admin 'local' }
        Must-Throw { Invoke-MiosMachinePreparationRequest -Request ([pscustomobject]@{ Origin = $badOrigin; OperatorToml = $projection; VendorToml = $vendor }) -OriginProcessId 4242 } ('reject mismatched origin ' + $change[0])
    }
    $badOrigin = $origin | ConvertTo-Json | ConvertFrom-Json
    $badOrigin | Add-Member Extra 'unexpected'
    Must-Throw { Assert-MiosOriginContext $badOrigin } 'reject extra origin fields'
    Must-Throw { Invoke-MiosMachinePreparationRequest -Request ([pscustomobject]@{ Origin = $origin; OperatorToml = $private; VendorToml = $vendor }) -OriginProcessId 4242 } 'reject credentials before machine dispatch'
    Must-Throw { Invoke-MiosMachinePreparationRequest -Request ([pscustomobject]@{ Origin = $origin; OperatorToml = $projection; VendorToml = $vendor; Code = 'forbidden' }) -OriginProcessId 4242 } 'reject extra executable request fields'
    Check ($script:coreCalls -eq $before) 'invalid requests perform zero machine actions'
    Check ((Read-MiosPipeLine -Reader ([IO.StringReader]::new("ok`n")) -Limit 2) -eq 'ok') 'bounded pipe accepts a complete message'
    Must-Throw { Read-MiosPipeLine -Reader ([IO.StringReader]::new("long`n")) -Limit 2 } 'bounded pipe rejects oversized messages'
    Must-Throw { Read-MiosPipeLine -Reader ([IO.StringReader]::new('partial')) } 'bounded pipe rejects truncated messages'
    $workerText = Get-MiosMachineWorkerScript $Text
    $workerAst = Parse-Source $workerText
    $workerFunctions = @($workerAst.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $true))
    Check (@($workerFunctions | Where-Object { $_.Name -in @('Install-MiOSTerminalProfile', 'Install-MiOSPowerShellProfile', 'Complete-MiosMachinePreparation', 'Invoke-MiosMachinePreparation', 'Set-PodmanMachineStorageOnM', 'Set-WingetStorageOnM') }).Count -eq 0) 'the elevated worker excludes operator setup and generic dispatch'
    Check (-not $workerText.Contains('OPERATOR-PRIVATE-SENTINEL') -and -not $workerText.Contains('ADMIN-PRIVATE-SENTINEL')) 'generated worker source contains no profile credentials'
    Check ($Text.Contains('GetNamedPipeServerProcessId') -and $Text.Contains('GetNamedPipeClientProcessId') -and $Text.Contains('$peer -ne $worker.Id')) 'both pipe peer processes are checked'
    Check ($Text.Contains('if (`$actual -cne ''$digest'') { throw') -and $Text.Contains('[scriptblock]::Create(`$source)') -and $Text.Contains('$workerSha.ComputeHash($workerBytes)') -and -not $Text.Contains('Get-FileHash -LiteralPath $workerPath')) 'UAC verifies the exact worker bytes before parsing them'
    $commands = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] }, $true))
    $completionCalls = @($commands | Where-Object { $_.GetCommandName() -eq 'Complete-MiosMachinePreparation' })
    $handoff = @($commands | Where-Object { $_.CommandElements[0].Extent.Text -eq '$entry' })
    Check ($completionCalls.Count -eq 1 -and $handoff.Count -eq 1 -and $completionCalls[0].Extent.StartOffset -lt $handoff[0].Extent.StartOffset) 'the actual completion dispatch precedes the build handoff'
    $completion = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Complete-MiosMachinePreparation' }, $true))[0]
    $exits = @($completion.FindAll({ param($n) $n -is [Management.Automation.Language.ExitStatementAst] }, $true))
    Check ($exits.Count -eq 1) 'pending completion has one explicit process exit'
    # Replace only ExitStatementAst for an isolated source fixture; the actual completion body still decides whether it is reached.
    $safeCompletion = $completion.Extent.Text
    foreach ($exitNode in $exits) { $safeCompletion = $safeCompletion.Replace($exitNode.Extent.Text, "throw 'MIOS_FIXTURE_EXIT_0'") }
    . ([scriptblock]::Create(($safeCompletion -replace '^function\s+', 'function global:')))
    $after = $false; $stopped = ''
    try { Complete-MiosMachinePreparation ([pscustomobject]@{ Status = 'pending' }); $after = $true } catch { $stopped = $_.Exception.Message }
    Check (-not $after -and $stopped -eq 'MIOS_FIXTURE_EXIT_0') 'actual pending dispatch halts before downstream bootstrap'
    $after = $false
    Complete-MiosMachinePreparation ([pscustomobject]@{ Status = 'ready' }); $after = $true
    Check $after 'ready completion reaches downstream bootstrap'
    Must-Throw { Complete-MiosMachinePreparation ([pscustomobject]@{ Status = 'error' }) } 'error completion halts downstream bootstrap'
    function global:New-ScheduledTaskTrigger { param([switch]$AtLogOn, $User) $script:resumeUser = $User }
    function global:New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) $script:resumePrincipal = "$UserId|$LogonType|$RunLevel" }
    $Context = $origin
    $resume = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -in @('$_trg', '$_prin') }, $true))
    foreach ($assignment in $resume) { . ([scriptblock]::Create($assignment.Extent.Text)) }
    Check ($script:resumeUser -eq $origin.Sid -and $script:resumePrincipal -eq ($origin.Sid + '|Interactive|Limited')) 'actual resume registration targets the operator with a limited interactive token'
    # Execute the actual machine orchestration under ready/pending/error. Redirector calls are tripwires.
    Import-Functions $ast @('Invoke-MiosMachinePreparationCore')
    function global:Test-MiosElevated { return $true }
    function global:Publish-MiosMachineToml { param($Context) }
    function global:Initialize-MiosMachineStorage { param($Context) }
    function global:Add-MiosDefenderExclusions {}
    function global:Register-MiosBootstrapResume { param($Context) $script:pendingSid = $Context.Sid }
    function global:Unregister-ScheduledTask { param($TaskName, $Confirm, $ErrorAction) }
    function global:Set-ItemProperty { param($Path, $Name, $Value, $Type, [switch]$Force, $ErrorAction) }
    function global:Set-Acl { throw 'Unexpected ACL mutation in source-only machine orchestration.' }
    $script:legacyRedirectCalls = 0
    function global:Set-PodmanMachineStorageOnM { $script:legacyRedirectCalls++; throw 'Legacy profile redirector invoked.' }
    function global:Set-WingetStorageOnM { $script:legacyRedirectCalls++; throw 'Legacy shared package redirector invoked.' }
    function global:Invoke-MiosPlatformGate {
        if ($script:platformMode -eq 'error') { throw 'Fixture feature failure.' }
        [pscustomobject]@{ Status = $script:platformMode }
    }
    foreach ($mode in @('ready', 'pending', 'error')) {
        $script:platformMode = $mode
        $result = $null; $failed = $false
        try { $result = Invoke-MiosMachinePreparationCore -Context $origin } catch { $failed = $true }
        Check ($script:legacyRedirectCalls -eq 0) ('actual ' + $mode + ' machine dispatch performs zero profile or shared package redirects')
        Check (($mode -eq 'error' -and $failed) -or ($mode -ne 'error' -and -not $failed -and $result.Status -eq $mode)) ('actual machine orchestration preserves ' + $mode + ' readiness')
    }
    $defaultResolution = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
        $n.Clauses[0].Item1.Extent.Text -eq '[string]::IsNullOrWhiteSpace($RepoDir)' }, $true))
    foreach ($elevated in @($false, $true)) {
        $args = @(New-MiosGetChildArguments -EntryPath 'entry.ps1' -Action Default -RepoUrl 'fixture' -Branch main -RepoDir '' -FullBuild)
        Check ($args -notcontains '-RepoDir' -and $args -notcontains '-ExecutionPolicy' -and $args -contains '-FullBuild') 'actual child arguments retain an absent checkout and inherit execution policy'
        $_isAdmin = $elevated; $RepoDir = ''; $Script:MiosOriginContext = $origin
        $env:SystemDrive = Join-Path $scratch 'system'
        foreach ($resolution in $defaultResolution) { . ([scriptblock]::Create($resolution.Extent.Text)) }
        $expectedRoot = if ($elevated) { Join-Path $env:SystemDrive 'mios-bootstrap' } else { Join-Path $origin.LocalAppData 'MiOS/repo/mios-bootstrap' }
        Check ($RepoDir -eq $expectedRoot) 'actual default checkout resolution matches the token scope'
        $runtime = Get-MiosWindowsInstallRoot -Elevated $elevated -LocalAppData $origin.LocalAppData
        $expectedRuntime = if ($elevated) { Join-Path $env:SystemDrive 'MiOS' } else { Join-Path $origin.LocalAppData 'MiOS' }
        Check ($runtime -eq $expectedRuntime) 'runtime root matches the existing CurrentUser or AllUsers build layout'
        $RepoDir = Join-Path $scratch 'explicit-checkout'
        foreach ($resolution in $defaultResolution) { . ([scriptblock]::Create($resolution.Extent.Text)) }
        $args = @(New-MiosGetChildArguments -EntryPath 'entry.ps1' -Action Default -RepoUrl 'fixture' -Branch main -RepoDir $RepoDir)
        $index = [Array]::IndexOf($args, '-RepoDir')
        Check ($index -ge 0 -and $args[$index + 1] -eq (Join-Path $scratch 'explicit-checkout')) 'actual child arguments and resolution preserve an explicit checkout'
    }
    $apostropheProfile = Join-Path $scratch "O'Brien/powershell/profile.ps1"
    New-Item -ItemType Directory -Path (Split-Path -Parent $apostropheProfile) -Force | Out-Null
    [IO.File]::WriteAllText($apostropheProfile, '$global:MiosApostropheFixtureLoaded = $true')
    $command = Get-MiosTerminalProfileCommand -ShellPath 'powershell.exe' -ProfilePath $apostropheProfile
    $prefix = '-Command "'; $offset = $command.IndexOf($prefix) + $prefix.Length
    $body = $command.Substring($offset, $command.Length - $offset - 1)
    $null = Parse-Source $body
    $oldAppContext = $env:MIOS_APP_CONTEXT
    try { & ([scriptblock]::Create($body)); Check ($global:MiosApostropheFixtureLoaded -eq $true) 'actual generated terminal command loads an apostrophe profile path' }
    finally { $env:MIOS_APP_CONTEXT = $oldAppContext; Remove-Variable MiosApostropheFixtureLoaded -Scope Global -ErrorAction SilentlyContinue }
    # No mutation below can execute an actual Windows action.
}
function Invoke-WindowsBoundaryFixture {
    if ($env:OS -ne 'Windows_NT') { throw '-WindowsAcl requires Windows.' }
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw '-WindowsAcl requires an elevated scratch-only fixture process.' }
    $ast = Parse-Source $source
    Import-Functions $ast @('Assert-MiosNoReparsePath', 'Set-MiosHostTierAcl', 'Assert-MiosMachineWriteBoundary', 'Initialize-MiosVendorTierDirectory', 'Write-MiosVendorToml',
        'New-MiosMachineCreationAcl', 'New-MiosProtectedMachineDirectory', 'Write-MiosPrivateMachineFile')
    $machine = Join-Path $scratch 'windows-machine'
    $vendorPath = Join-Path $machine 'usr/share/mios/mios.toml'
    New-Item -ItemType Directory -Path $machine -Force | Out-Null
    $vendorText = "[meta]`nname = 'FULL-VENDOR-SENTINEL'`n[identity]`ndefault_password = ''`n"
    Write-MiosVendorToml -Path $vendorPath -Text $vendorText
    Check ([IO.File]::ReadAllText($vendorPath) -ceq $vendorText) 'Windows vendor staging retains full source bytes'
    $vendorDirectory = Split-Path -Parent $vendorPath
    $savedAcl = Get-Acl -LiteralPath $vendorDirectory
    $unsafeAcl = Get-Acl -LiteralPath $vendorDirectory
    $untrusted = New-Object Security.Principal.SecurityIdentifier 'S-1-5-21-1-2-3-1999'
    $unsafeAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($untrusted, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    Microsoft.PowerShell.Security\Set-Acl -LiteralPath $vendorDirectory -AclObject $unsafeAcl
    Must-Throw { Write-MiosVendorToml -Path $vendorPath -Text 'REJECTED' } 'Windows vendor staging rejects a writable child boundary'
    Check ([IO.File]::ReadAllText($vendorPath) -ceq $vendorText) 'Windows rejected vendor write preserves existing bytes'
    Microsoft.PowerShell.Security\Set-Acl -LiteralPath $vendorDirectory -AclObject $savedAcl
    $inheritAcl = Get-Acl -LiteralPath $vendorDirectory
    $inheritAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($untrusted, 'Modify', 'ContainerInherit,ObjectInherit', 'InheritOnly', 'Allow')))
    Microsoft.PowerShell.Security\Set-Acl -LiteralPath $vendorDirectory -AclObject $inheritAcl
    $probe = Join-Path $vendorDirectory '.atomic-acl-probe'
    Write-MiosPrivateMachineFile -Path $probe -Bytes ([Text.Encoding]::UTF8.GetBytes('ATOMIC-SENTINEL'))
    $probeAcl = Get-Acl -LiteralPath $probe
    $probeRules = @($probeAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    Check ($probeAcl.AreAccessRulesProtected -and @($probeRules | Where-Object { $_.IdentityReference.Value -eq $untrusted.Value }).Count -eq 0) 'Windows atomic file creation excludes InheritOnly write grants from its first handle'
    Write-MiosVendorToml -Path $vendorPath -Text $vendorText
    Check ([IO.File]::ReadAllText($vendorPath) -ceq $vendorText -and (Get-Acl -LiteralPath $vendorPath).AreAccessRulesProtected) 'Windows vendor staging handles InheritOnly parent grants without an inherited child DACL'
    Microsoft.PowerShell.Security\Set-Acl -LiteralPath $vendorDirectory -AclObject $savedAcl
    $packages = Join-Path $machine 'winget/MachinePackages'
    New-Item -ItemType Directory -Path $packages -Force | Out-Null
    Set-MiosHostTierAcl $packages
    $before = (Get-Acl -LiteralPath $packages).Sddl
    $script:platformMode = 'ready'
    $null = Invoke-MiosMachinePreparationCore -Context $Script:MiosOriginContext
    Check ((Get-Acl -LiteralPath $packages).Sddl -ceq $before) 'actual machine dispatch preserves protected MachinePackages child ACLs'
    $unrelated = Join-Path $scratch 'windows-unrelated'
    $attackRoot = Join-Path $scratch 'windows-junction-attack'
    New-Item -ItemType Directory -Path $unrelated -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $attackRoot 'usr/share') -Force | Out-Null
    $sentinel = Join-Path $unrelated 'mios.toml'
    [IO.File]::WriteAllText($sentinel, 'UNRELATED-SENTINEL')
    New-Item -ItemType Junction -Path (Join-Path $attackRoot 'usr/share/mios') -Target $unrelated | Out-Null
    Must-Throw { Write-MiosVendorToml -Path (Join-Path $attackRoot 'usr/share/mios/mios.toml') -Text 'REJECTED' } 'Windows vendor staging rejects a junction before any write'
    Check ([IO.File]::ReadAllText($sentinel) -ceq 'UNRELATED-SENTINEL') 'Windows junction target sentinel remains untouched'
    if ($script:failures.Count) { throw ('Windows boundary fixture failed: ' + ($script:failures -join '; ')) }
    Write-Host 'WINDOWS_OPERATOR_BOUNDARY_FIXTURE PASS'
}

$oldProfile = $env:USERPROFILE
$oldSystemDrive = $env:SystemDrive
try {
    Run-Checks $source
    if ($script:failures.Count) { throw ('Baseline failed: ' + ($script:failures -join '; ')) }
    if (-not $PlantDefect) {
        if ($WindowsAcl) { Invoke-WindowsBoundaryFixture }
        Write-Host "OPERATOR_CONTEXT_SOURCE_ASSERTIONS $script:checks"
        Write-Host 'RESULT: PASS (operator context source fixtures; Windows APIs mocked)'
    } else {
        $plants = @(
            @{ Name = 'shared package redirect reintroduced'; From = '$script:MiosMachineOrigin = $Context'; To = '$script:MiosMachineOrigin = $Context; Set-WingetStorageOnM'; Expected = 'actual ready machine dispatch performs zero profile or shared package redirects' },
            @{ Name = 'pending exit removed'; From = "            exit 0`n        }`n        default { throw 'Machine preparation did not report ready"; To = "            # exit removed`n        }`n        default { throw 'Machine preparation did not report ready"; Expected = 'actual pending dispatch halts before downstream bootstrap' },
            @{ Name = 'origin profile comparison removed'; From = 'if (-not $registered -or '; To = 'if ($false -and '; Expected = 'reject mismatched origin Profile' },
            @{ Name = 'origin config comparison removed'; From = 'if ([string]$Context.ConfigPath -ine '; To = 'if ($false -and '; Expected = 'reject mismatched origin ConfigPath' },
            @{ Name = 'credential guard removed'; From = 'if ((ConvertTo-MiosCredentialFreeToml ([string]$request.OperatorToml)) -cne [string]$request.OperatorToml)'; To = 'if ($false)'; Expected = 'reject credentials before machine dispatch' },
            @{ Name = 'resume uses admin'; From = '-UserId $Context.Sid -LogonType Interactive -RunLevel Limited'; To = '-UserId $env:USERNAME -LogonType Interactive -RunLevel Highest'; Expected = 'actual resume registration targets the operator with a limited interactive token' }
        )
        # Exercise the actual canonicalizer against both transport/check-out forms before any mutation.
        foreach ($variant in @($source, $source.Replace("`n", "`r`n"))) {
            $canonical = ConvertTo-MiosFixtureSource $variant
            foreach ($plant in $plants) {
                if ($plant.From.Contains("`r") -or $plant.To.Contains("`r") -or -not $canonical.Contains($plant.From)) {
                    throw ('Line-ending portability guard failed for defect anchor: ' + $plant.Name)
                }
            }
        }
        Write-Host 'OPERATOR_CONTEXT_SOURCE_NEWLINE_GUARD PASS'
        $caught = 0
        foreach ($plant in $plants) {
            if (-not $source.Contains($plant.From)) { throw ('Missing defect anchor: ' + $plant.Name) }
            $script:failures.Clear()
            Run-Checks ($source.Replace($plant.From, $plant.To))
            if (-not $script:failures.Contains($plant.Expected)) { throw ('Defect was not detected: ' + $plant.Name) }
            $caught++
        }
        Write-Host "RESULT: PASS (operator context planted defects caught: $caught/$($plants.Count))"
    }
} finally {
    $env:USERPROFILE = $oldProfile
    $env:SystemDrive = $oldSystemDrive
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
