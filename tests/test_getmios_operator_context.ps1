# Source fixtures only. Never invoke Get-MiOS.ps1 top-level, UAC, pipes, WSL, disk or registry APIs.
[CmdletBinding()]
param([switch]$PlantDefect)
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-MiOS.ps1'
$source = [IO.File]::ReadAllText($sourcePath)
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
        'Write-MiosHostToml', 'Invoke-MiosMachinePreparationRequest', 'Read-MiosPipeLine', 'Get-MiosMachineWorkerScript', 'Get-MiosWslConfigText')
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
    $script:processSid = $script:opSid; $script:processSession = 17
    function global:Get-CimInstance { param($ClassName, $Filter, $ErrorAction) [pscustomobject]@{ ProcessId = 4242; SessionId = $script:processSession } }
    function global:Invoke-CimMethod { param($InputObject, $MethodName, $ErrorAction) [pscustomobject]@{ ReturnValue = 0; Sid = $script:processSid } }
    function global:Get-Process { param($Id) [pscustomobject]@{ SessionId = 17 } }
    function global:Get-ItemProperty {
        param($LiteralPath, $ErrorAction)
        if ($LiteralPath -like '*ProfileList*') { return [pscustomobject]@{ ProfileImagePath = $script:registeredProfile } }
        if ($LiteralPath -like '*User Shell Folders') { return [pscustomobject]@{ 'Local AppData' = $script:registeredLocal } }
        throw 'Unexpected registry fixture read.'
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
    $before = $script:coreCalls
    foreach ($change in @(@('Sid', $script:adminSid), @('Profile', $admin), @('LocalAppData', (Join-Path $admin 'local')),
        @('ConfigPath', $adminPath), @('ProcessId', 9999), @('SessionId', 23))) {
        $badOrigin = $origin | ConvertTo-Json | ConvertFrom-Json
        $badOrigin.($change[0]) = $change[1]
        if ($change[0] -eq 'Profile') { $badOrigin.ConfigPath = $adminPath }
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
    Check (@($workerFunctions | Where-Object { $_.Name -in @('Install-MiOSTerminalProfile', 'Install-MiOSPowerShellProfile', 'Complete-MiosMachinePreparation', 'Invoke-MiosMachinePreparation') }).Count -eq 0) 'the elevated worker excludes operator setup and generic dispatch'
    Check (-not $workerText.Contains('OPERATOR-PRIVATE-SENTINEL') -and -not $workerText.Contains('ADMIN-PRIVATE-SENTINEL')) 'generated worker source contains no profile credentials'
    Check ($Text.Contains('GetNamedPipeServerProcessId') -and $Text.Contains('GetNamedPipeClientProcessId') -and $Text.Contains('$peer -ne $worker.Id')) 'both pipe peer processes are checked'
    Check ($Text.Contains('if (`$actual -cne ''$digest'') { throw') -and $Text.Contains('[scriptblock]::Create(`$source)')) 'UAC verifies the exact worker bytes before parsing them'
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
    # No mutation below can execute an actual Windows action.
}
$oldProfile = $env:USERPROFILE
try {
    Run-Checks $source
    if ($script:failures.Count) { throw ('Baseline failed: ' + ($script:failures -join '; ')) }
    if (-not $PlantDefect) {
        Write-Host "OPERATOR_CONTEXT_SOURCE_ASSERTIONS $script:checks"
        Write-Host 'RESULT: PASS (operator context source fixtures; Windows APIs mocked)'
    } else {
        $plants = @(
            @{ Name = 'pending exit removed'; From = "            exit 0`r`n        }`r`n        default { throw 'Machine preparation did not report ready"; To = "            # exit removed`r`n        }`r`n        default { throw 'Machine preparation did not report ready"; Expected = 'actual pending dispatch halts before downstream bootstrap' },
            @{ Name = 'origin profile comparison removed'; From = 'if (-not $registered -or '; To = 'if ($false -and '; Expected = 'reject mismatched origin Profile' },
            @{ Name = 'origin config comparison removed'; From = 'if ([string]$Context.ConfigPath -ine '; To = 'if ($false -and '; Expected = 'reject mismatched origin ConfigPath' },
            @{ Name = 'credential guard removed'; From = 'if ((ConvertTo-MiosCredentialFreeToml ([string]$request.OperatorToml)) -cne [string]$request.OperatorToml)'; To = 'if ($false)'; Expected = 'reject credentials before machine dispatch' },
            @{ Name = 'resume uses admin'; From = '-UserId $Context.Sid -LogonType Interactive -RunLevel Limited'; To = '-UserId $env:USERNAME -LogonType Interactive -RunLevel Highest'; Expected = 'actual resume registration targets the operator with a limited interactive token' }
        )
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
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
