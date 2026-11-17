# Installed Windows layout (C6a). Get-MiOS.ps1 and build-mios.ps1 each carry Get-MiosInstalledLayout; both profile
# redirectors, every native-bin default and the client setup's arguments resolve through it. The hub mios.ps1 must reach
# a verb in one hop and never dispatch to itself. Functions run extracted from the product; the hub and the profile
# startup block run in child processes of both engines against a scratch install root. Nothing outside the scratch tree
# is read or written. Default runs the checks; -PlantDefect plants each guarded defect into copies and requires red.
[CmdletBinding()]
param([switch]$PlantDefect, [string]$GetPath, [string]$BuildPath)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $GetPath) { $GetPath = Join-Path $repoRoot 'Get-MiOS.ps1' }
if (-not $BuildPath) { $BuildPath = Join-Path $repoRoot 'build-mios.ps1' }
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-native-layout-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -ErrorAction Stop | Out-Null
$lf = New-Object Text.UTF8Encoding($false)
$engines = @(, @('ps51', (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')))
$pwsh = (Get-Command pwsh.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $pwsh -and $PSVersionTable.PSEdition -eq 'Core') { $pwsh = (Get-Process -Id $PID).Path }
if ($pwsh) { $engines += , @('ps7', $pwsh) }

$script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
function Check([bool]$Ok, [string]$What) {
    $script:checks++
    if ($Ok) { Write-Host "  PASS $What" } else { Write-Host "  FAIL $What"; $script:fail++; $script:failedChecks.Add($What) }
}
function Write-Lf([string]$Path, [string]$Text) { New-Item -ItemType Directory -Force -Path (Split-Path $Path -Parent) | Out-Null; [IO.File]::WriteAllText($Path, $Text, $lf) }
function Get-Count([string]$Text, [string]$Pattern) { return ([regex]::Matches($Text, $Pattern)).Count }
function Get-Ast([string]$Text) { $t = $null; $e = $null; return [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$t, [ref]$e) }
function Get-FunctionText($Ast, [string]$Name) {
    $f = @($Ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }.GetNewClosure(), $true))
    if ($f.Count -eq 1) { return ($f[0].Extent.Text -replace "`r`n", "`n") } else { return '' }
}
# The value of the here-string assigned to $Name inside function $Function.
function Get-HereString($Ast, [string]$Function, [string]$Name) {
    $fn = @($Ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Function }.GetNewClosure(), $true))
    if ($fn.Count -ne 1) { return '' }
    $a = @($fn[0].Body.FindAll({ param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq "`$$Name" -and $n.Right.Extent.Text.StartsWith("@'") }.GetNewClosure(), $true))
    if ($a.Count -lt 1) { return '' }
    $right = $a[0].Right
    $value = if ($right -is [Management.Automation.Language.CommandExpressionAst]) { $right.Expression.Value } else { $right.PipelineElements[0].Expression.Value }
    return ([string]$value -replace "`r`n", "`n")
}
# Runs a child engine with a deadline; a hub that recursed would never return on its own.
function Invoke-Child([string]$Engine, [string[]]$Arguments, [hashtable]$Env = @{}, [int]$TimeoutMs = 60000) {
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $Engine
    $psi.Arguments = (($Arguments | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' ')
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    foreach ($k in $Env.Keys) { $psi.EnvironmentVariables[$k] = [string]$Env[$k] }
    foreach ($k in @('MIOS_HUB_ACTIVE', 'MIOS_SKIP_MOTD', 'MIOS_NATIVE_BIN')) { if (-not $Env.ContainsKey($k) -and $psi.EnvironmentVariables.ContainsKey($k)) { $psi.EnvironmentVariables.Remove($k) } }
    $p = [Diagnostics.Process]::Start($psi)
    $outTask = $p.StandardOutput.ReadToEndAsync(); $errTask = $p.StandardError.ReadToEndAsync()
    $done = $p.WaitForExit($TimeoutMs)
    if (-not $done) { try { & taskkill.exe /PID $p.Id /T /F 2>&1 | Out-Null } catch {}; $p.WaitForExit(5000) | Out-Null }
    return [pscustomobject]@{ TimedOut = -not $done; Rc = $(if ($done) { $p.ExitCode } else { -1 }); Text = ($outTask.Result + $errTask.Result) }
}
function Read-Log([string]$Path) { if (Test-Path -LiteralPath $Path) { return (@(Get-Content -LiteralPath $Path) -join '|') } else { return '' } }

# Only extracted staging code runs. Files and processes are in-memory fixtures;
# a legacy direct invocation targets a nonexistent file beneath the scratch root.
function Invoke-MiosTerminalProjectionProbe {
    param([string]$Body, [string]$FixtureBin, [int]$NativeCode, [int]$StaleCode,
          [bool]$FunctionMode = $true, [bool]$Present = $true)
    $calls = New-Object System.Collections.Generic.List[object]
    function Get-MiosInstalledLayout { [pscustomobject]@{ NativeBin = $FixtureBin } }
    function Test-Path {
        param([string]$LiteralPath, [string]$PathType)
        return $Present -and ($LiteralPath -in @((Join-Path $FixtureBin 'mios-launch.exe'), (Join-Path $FixtureBin 'native-binding.json')))
    }
    function Start-Process {
        param([string]$FilePath, [string[]]$ArgumentList, [switch]$NoNewWindow, [switch]$Wait, [switch]$PassThru)
        $calls.Add([pscustomobject]@{ FilePath=$FilePath; Arguments=@($ArgumentList); Wait=[bool]$Wait; PassThru=[bool]$PassThru; NoNewWindow=[bool]$NoNewWindow })
        if ($PassThru) { [pscustomobject]@{ ExitCode = $NativeCode } }
    }
    $savedBin = $env:MIOS_NATIVE_BIN
    $savedExit = Get-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
    $hadExit = $null -ne $savedExit; $savedExitValue = if ($hadExit) { $savedExit.Value } else { $null }
    $env:MIOS_NATIVE_BIN = $FixtureBin; $global:LASTEXITCODE = $StaleCode
    $BinDirectory = $FixtureBin; $accepted = $false; $message = $null; $value = $null
    try {
        if ($FunctionMode) { . ([scriptblock]::Create($Body)); $value = Install-MiOSTmuxProfile -Required }
        else { $value = . ([scriptblock]::Create($Body)) }
        $accepted = $true
    } catch { $message = $_.Exception.Message }
    finally {
        $env:MIOS_NATIVE_BIN = $savedBin
        if ($hadExit) { $global:LASTEXITCODE = $savedExitValue } else { Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue }
    }
    [pscustomobject]@{ Accepted=$accepted; Message=$message; Calls=@($calls.ToArray()); Value=$value }
}
function Invoke-Checks([string]$Get, [string]$Build) {
    $script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
    $getText = ([IO.File]::ReadAllText($Get)) -replace "`r`n", "`n"; $buildText = ([IO.File]::ReadAllText($Build)) -replace "`r`n", "`n"
    $getAst = Get-Ast $getText; $buildAst = Get-Ast $buildText

    # --- One layout: both scripts answer the same, unelevated and elevated, with and without MIOS_NATIVE_BIN ---------
    $agree = $false
    $getFns = (@('Test-MiosElevated', 'Get-MiosWindowsInstallRoot', 'Get-MiosInstalledLayout') | ForEach-Object { Get-FunctionText $getAst $_ }) -join "`n"
    $buildFn = Get-FunctionText $buildAst 'Get-MiosInstalledLayout'
    if ($buildFn -and (Get-FunctionText $getAst 'Get-MiosInstalledLayout')) {
        $probe = [scriptblock]::Create(@'
param($GetFns, $BuildFn, $Elevated, $NativeBin)
$saved = $env:MIOS_NATIVE_BIN; $env:MIOS_NATIVE_BIN = $NativeBin
try {
    $g = & { . ([scriptblock]::Create($GetFns)); Get-MiosInstalledLayout -Elevated $Elevated }
    $b = & { $script:IsAdmin = $Elevated; $script:MiosInstallDir = $null; $script:MiosBinDir = $null; . ([scriptblock]::Create($BuildFn)); Get-MiosInstalledLayout }
} finally { $env:MIOS_NATIVE_BIN = $saved }
foreach ($x in @($g, $b)) { '{0}|{1}|{2}|{3}|{4}' -f $x.Root, $x.Bin, $x.NativeBin, $x.ProfileBody, $x.Scope }
'@)
        $rows = @()
        foreach ($case in @(@($false, ''), @($true, ''), @($false, 'D:\override\bin'))) { $rows += , @(& $probe $getFns $buildFn $case[0] $case[1]) }
        $local = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'MiOS'
        $agree = $rows.Count -eq 3 -and @($rows | Where-Object { $_.Count -ne 2 -or $_[0] -ne $_[1] }).Count -eq 0 -and
                 $rows[0][0] -eq ('{0}|{0}\bin|{0}\bin|{0}\powershell\profile.ps1|User' -f $local) -and
                 $rows[1][0] -eq ('{0}|{0}\bin|{0}\bin|{0}\powershell\profile.ps1|Machine' -f (Join-Path $env:SystemDrive 'MiOS')) -and
                 $rows[2][0] -eq ('{0}|{0}\bin|D:\override\bin|{0}\powershell\profile.ps1|User' -f $local)
        if (-not $agree -and $env:MIOS_TEST_VERBOSE) { $rows | ForEach-Object { Write-Host ($_ -join ' <> ') } }
    }
    Check $agree 'Get-MiOS.ps1 and build-mios.ps1 resolve one installed layout (root, bin, native bin, profile body, scope)'

    # --- Both redirectors load that body; no ProgramData native bin or M:\ guess is left -------------------------------
    $branding = Get-FunctionText $buildAst 'Install-WindowsBranding'
    $psProfile = Get-FunctionText $getAst 'Install-MiOSPowerShellProfile'
    Check ($branding.Contains('$miosProfilePath = (Get-MiosInstalledLayout).ProfileBody') -and $psProfile.Contains('$_layout = Get-MiosInstalledLayout') -and
           $psProfile.Contains('$miosProfileScript = $_layout.ProfileBody') -and
           (Get-Count ($getText + $buildText) "MiOS-bootstrap\\powershell|'M:\\MiOS\\powershell\\profile\.ps1'") -eq 0) 'both profile redirectors load the installed layout''s body, with no M:\ or MiOS-bootstrap guess'
    Check ((Get-Count ($getText + $buildText) 'ProgramData.{0,12}MiOS.{0,3}bin') -eq 0) 'no native-bin default or search order points at %ProgramData%\MiOS\bin'

    # --- The body's startup block: a missing native shell is a message, not a throw ----------------------------------
    $startup = Get-HereString $getAst 'Install-MiOSPowerShellProfile' 'nativeStartup'
    $startupOk = $false
    if ($startup -and $psProfile.Contains("`$nativeStartup = `$nativeStartup.Replace('__MIOS_NATIVE_BIN__', `$safeNativeBin)") -and $psProfile.Contains('$safeNativeBin = $_layout.Bin.Replace(')) {
        $bin = Join-Path $scratch ('startup-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '\bin')
        New-Item -ItemType Directory -Force -Path $bin | Out-Null
        $file = Join-Path (Split-Path $bin -Parent) 'startup.ps1'
        Write-Lf $file ($startup.Replace('__MIOS_NATIVE_BIN__', $bin.Replace("'", "''")) + "`n'after-startup'`n")
        $marker = Join-Path $bin 'shell-loaded.txt'
        $startupOk = $true
        foreach ($e in $engines) {
            Remove-Item -LiteralPath (Join-Path $bin 'mios-native-shell.ps1') -Force -ErrorAction SilentlyContinue
            $a = Invoke-Child $e[1] @('-NoProfile', '-NonInteractive', '-File', $file)
            Write-Lf (Join-Path $bin 'mios-native-shell.ps1') "param([string]`$BinDirectory)`n[IO.File]::WriteAllText('$($marker.Replace("'", "''"))', `$BinDirectory)`n"
            Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
            $b = Invoke-Child $e[1] @('-NoProfile', '-NonInteractive', '-File', $file) @{ MIOS_SKIP_MOTD = '1' }
            $ok = $a.Rc -eq 0 -and $a.Text -match 'MiOS native shell missing at' -and $a.Text -match 'after-startup' -and
                  $b.Rc -eq 0 -and (Test-Path -LiteralPath $marker) -and ([IO.File]::ReadAllText($marker) -eq $bin) -and $b.Text -match 'after-startup'
            if (-not $ok -and $env:MIOS_TEST_VERBOSE) { Write-Host "$($e[0]) startup: $($a.Text) || $($b.Text)" }
            $startupOk = $startupOk -and $ok
        }
    }
    Check $startupOk 'the profile body names a missing native shell and keeps loading; an installed one loads from the layout bin'

    # --- The hub: one hop to a verb, never itself, one refusal for a verb the native entry hands back ----------------
    $hub = Get-HereString $buildAst 'Install-MiosLauncher' 'hubScript'
    $hubOk = $false; $loopOk = $false; $motdOk = $false
    if ($hub) {
        $hubOk = $true; $loopOk = $true; $motdOk = $true
        foreach ($e in $engines) {
            $root = Join-Path $scratch ('hub-' + $e[0] + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            $bin = Join-Path $root 'bin'; $body = Join-Path $root 'powershell\profile.ps1'; $log = Join-Path $root 'calls.log'
            Write-Lf (Join-Path $bin 'mios.ps1') $hub
            Write-Lf (Join-Path $bin 'mios-help.ps1') "Add-Content -LiteralPath `$env:MIOS_TEST_LOG -Value 'help'`n"
            $envs = @{ MIOS_TEST_LOG = $log }
            $run = { param($argsList, $extraEnv) Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue; $all = $envs.Clone(); foreach ($k in $extraEnv.Keys) { $all[$k] = $extraEnv[$k] }; $r = Invoke-Child $e[1] $argsList $all; [pscustomobject]@{ R = $r; Log = (Read-Log $log) } }
            $file = @('-NoProfile', '-NonInteractive', '-File', (Join-Path $bin 'mios.ps1'), 'help')
            # (a) no profile body; (b) a body that throws; (c) a body with the mios function; (d) through PATH.
            $a = & $run $file @{}
            Write-Lf $body "throw 'broken body'`n"; $b = & $run $file @{}
            Write-Lf $body "function mios { param([string]`$Verb) Add-Content -LiteralPath `$env:MIOS_TEST_LOG -Value ('fn:' + `$Verb) }`nif (-not `$env:MIOS_SKIP_MOTD) { Add-Content -LiteralPath `$env:MIOS_TEST_LOG -Value 'motd' }`n"
            $c = & $run $file @{}
            Remove-Item -LiteralPath $body -Force
            $d = & $run @('-NoProfile', '-NonInteractive', '-Command', 'mios help') @{ PATH = "$bin;$env:PATH" }
            $ok = -not $a.R.TimedOut -and $a.Log -eq 'help' -and -not $b.R.TimedOut -and $b.Log -eq 'help' -and $b.R.Text -match 'broken body' -and
                  -not $d.R.TimedOut -and $d.Log -eq 'help' -and -not $c.R.TimedOut -and ($c.Log -split '\|' | Where-Object { $_ -like 'fn:*' }) -join ',' -eq 'fn:help'
            $hubOk = $hubOk -and $ok
            $motdOk = $motdOk -and -not $c.R.TimedOut -and $c.Log -eq 'fn:help'
            # (e) an unowned verb: the native entry hands it back to the hub, as mios-native-entry.ps1's default branch does.
            Write-Lf (Join-Path $bin 'mios-native-entry.ps1') "Add-Content -LiteralPath `$env:MIOS_TEST_LOG -Value 'entry'`n& (Join-Path `$PSScriptRoot 'mios.ps1') @args`n"
            $f = & $run @('-NoProfile', '-NonInteractive', '-File', (Join-Path $bin 'mios.ps1'), 'zzz-unknown') @{}
            $loopOk = $loopOk -and -not $f.R.TimedOut -and $f.Log -eq 'entry' -and $f.R.Text -match 'has no handler'
            if ($env:MIOS_TEST_VERBOSE) { Write-Host ("{0}: a=[{1}] b=[{2}] c=[{3}] d=[{4}] f=[{5}] timeouts={6}{7}{8}{9}{10}" -f $e[0], $a.Log, $b.Log, $c.Log, $d.Log, $f.Log, $a.R.TimedOut, $b.R.TimedOut, $c.R.TimedOut, $d.R.TimedOut, $f.R.TimedOut) }
        }
    }
    Check $hubOk 'mios.ps1 runs a verb in one hop (no body, a broken body, a body''s mios function, or through PATH) and never dispatches to itself'
    Check $loopOk 'a verb the native entry hands back to mios.ps1 ends in one refusal, not a loop'
    Check $motdOk 'loading the profile body to dispatch a verb does not start the interactive host terminal'

    # --- The client setup gets -Scope User with the layout's bin and body ---------------------------------------------
    $argsFn = Get-FunctionText $buildAst 'Get-MiosClientSetupArguments'
    $launcher = Get-FunctionText $buildAst 'Install-MiosLauncher'
    $scopeOk = $false
    if ($argsFn -and $buildFn) {
        $withScope = Join-Path $scratch 'setup-with-scope.ps1'; $without = Join-Path $scratch 'setup-without-scope.ps1'
        Write-Lf $withScope "[CmdletBinding()]`nparam([string]`$Distro, [string]`$BinDirectory, [string]`$SourceRoot, [ValidateSet('User','Machine')][string]`$Scope = 'Machine', [string]`$ProfilePath)`n"
        Write-Lf $without "[CmdletBinding()]`nparam([string]`$Distro, [string]`$BinDirectory, [string]`$SourceRoot)`n"
        $probe = [scriptblock]::Create(@'
param($Fns, $Setup, $Elevated)
$script:IsAdmin = $Elevated; $script:MiosInstallDir = 'C:\Fixture\MiOS'; $script:MiosBinDir = 'C:\Fixture\MiOS\bin'
. ([scriptblock]::Create($Fns))
try { $a = Get-MiosClientSetupArguments -Setup $Setup -Distro 'MiOS-DEV' -SourceRoot 'C:\Fixture\MiOS\repo'; ($a.Keys | Sort-Object | ForEach-Object { "$_=$($a[$_])" }) -join ';' } catch { 'THROW ' + $_.Exception.Message }
'@)
        $user = & $probe ($buildFn + "`n" + $argsFn) $withScope $false
        $machine = & $probe ($buildFn + "`n" + $argsFn) $withScope $true
        $old = & $probe ($buildFn + "`n" + $argsFn) $without $false
        $scopeOk = $user -eq 'BinDirectory=C:\Fixture\MiOS\bin;Distro=MiOS-DEV;ProfilePath=C:\Fixture\MiOS\powershell\profile.ps1;Scope=User;SourceRoot=C:\Fixture\MiOS\repo' -and
                   $machine -eq 'BinDirectory=C:\Fixture\MiOS\bin;Distro=MiOS-DEV;SourceRoot=C:\Fixture\MiOS\repo' -and
                   $old -match '^THROW .*has no -Scope User' -and
                   $launcher.Contains('$_setupArgs = Get-MiosClientSetupArguments -Setup $_nativeSetup -Distro $DevDistro -SourceRoot $MiosRepoDir') -and $launcher.Contains('& $_nativeSetup @_setupArgs') -and
                   $getText.Contains("if (`$_layout.Scope -eq 'User') { `$_projectionArgs['Scope'] = 'User'; `$_projectionArgs['ProfilePath'] = `$_layout.ProfileBody }")
        if (-not $scopeOk -and $env:MIOS_TEST_VERBOSE) { Write-Host "user=[$user] machine=[$machine] old=[$old]" }
    }
    Check $scopeOk 'a per-user install calls the client setup with -Scope User, its bin and its body, and refuses a setup without -Scope'

    # --- The pull and build verbs use the installed checkout, not a guessed C:\, C:\MiOS or M:\ root -----------------
    $verbOk = $false
    $literalLine = '    $miosRepoLiteral = "''" + $MiosRepoDir.Replace("''", "''''") + "''"'
    $trimLine = "    `$_repoTrim = `$MiosRepoDir.TrimEnd('\')"
    $wslLine = "    `$miosRepoWsl = '/mnt/' + `$_repoTrim.Substring(0, 1).ToLower() + (`$_repoTrim.Substring(2) -replace '\\', '/')"
    if ($launcher.Contains($literalLine) -and $launcher.Contains($trimLine) -and $launcher.Contains($wslLine)) {
        $convert = [scriptblock]::Create("param(`$MiosRepoDir)`n$literalLine`n$trimLine`n$wslLine`n`"`$miosRepoLiteral|`$miosRepoWsl`"")
        $verbOk = (& $convert "C:\Users\o'p\AppData\Local\MiOS\repo") -eq "'C:\Users\o''p\AppData\Local\MiOS\repo'|/mnt/c/Users/o'p/AppData/Local/MiOS/repo" -and
                  (& $convert 'M:\') -eq "'M:\'|/mnt/m" -and
                  (Get-Count $launcher ([regex]::Escape('`$miosRoot = $miosRepoLiteral'))) -eq 2 -and
                  $launcher.Contains("```$driverSrc = '`$miosRepoWsl/usr/libexec/mios/mios-build-driver'") -and
                  $launcher.Contains("```$_smoke = '`$miosRepoWsl/tests/post-bootstrap-smoke.sh'") -and
                  $launcher -match "is not readable inside ``\`$distro'; exit 1; fi`"\nif \(``\`$LASTEXITCODE -ne 0\) \{" -and
                  (Get-Count $launcher "M:\\\.git|/mnt/m/usr/libexec|falling back to curl|/mnt/c/MiOS/tests|'/mnt/c/usr/libexec/mios/mios-build-driver'") -eq 0
    }
    Check $verbOk 'the mios pull and mios build verbs use the installed MiOS checkout: its root, its driver (never a download) and its smoke script'

    # A GUI native launcher must be waited, and its status must not come from an earlier native command.
    foreach ($site in @(@('Get-MiOS.ps1', $getAst), @('build-mios.ps1', $buildAst))) {
        $body = Get-FunctionText $site[1] 'Install-MiOSTmuxProfile'
        $ok = $false
        if ($body) {
            $bin = Join-Path $scratch 'projection-bin'
            $a = Invoke-MiosTerminalProjectionProbe -Body $body -FixtureBin $bin -NativeCode 0 -StaleCode -1978335189
            $b = Invoke-MiosTerminalProjectionProbe -Body $body -FixtureBin $bin -NativeCode 7 -StaleCode 0
            $c = Invoke-MiosTerminalProjectionProbe -Body $body -FixtureBin $bin -NativeCode 0 -StaleCode 0 -Present $false
            $ok = $a.Accepted -and $a.Calls.Count -eq 1 -and $a.Calls[0].Wait -and $a.Calls[0].PassThru -and $a.Calls[0].NoNewWindow -and
                  $a.Calls[0].FilePath -eq (Join-Path $bin 'mios-launch.exe') -and ($a.Calls[0].Arguments -join '|') -eq '--stage-host-terminal' -and
                  -not $b.Accepted -and $b.Message -match '\(exit 7\)' -and $b.Calls.Count -eq 1 -and $b.Calls[0].Wait -and
                  -not $c.Accepted -and $c.Calls.Count -eq 0 -and $c.Message -match 'missing.*incomplete'
            if (-not $ok -and $env:MIOS_TEST_VERBOSE) { Write-Host ($a, $b, $c | ConvertTo-Json -Depth 5 -Compress) }
        }
        Check $ok ($site[0] + ' native tmux staging waits for its GUI process and checks that process''s exit code')
    }    Write-Host "NATIVE_LAYOUT_ASSERTIONS $($script:checks)"
    return $script:fail
}

try {
    if (-not $PlantDefect) {
        $failures = Invoke-Checks $GetPath $BuildPath
        if ($failures) { Write-Host "RESULT: FAIL ($failures checks)"; exit 1 }
        Write-Host 'RESULT: PASS (installed layout, redirectors, profile startup and hub; scratch roots and child engines only)'; exit 0
    }
    $baseline = Invoke-Checks $GetPath $BuildPath
    if ($baseline) { Write-Host 'NATIVE_LAYOUT_BASELINE_FAILED'; exit 1 }
    $plants = @(
        @{ Name = 'the entrypoint invokes the GUI renderer asynchronously again'; Expected = 'Get-MiOS.ps1 native tmux staging waits for its GUI process and checks that process''s exit code'
           File = 'Get'; Edits = @(, @('$projectionProcess = Start-Process -FilePath $launcher -ArgumentList ''--stage-host-terminal'' -NoNewWindow -Wait -PassThru', '& $launcher --stage-host-terminal')) },
        @{ Name = 'the build reads an unrelated native exit status again'; Expected = 'build-mios.ps1 native tmux staging waits for its GUI process and checks that process''s exit code'
           File = 'Build'; Edits = @(, @('if ($projectionProcess.ExitCode -ne 0) { throw "Native layered SSOT tmux projection failed (exit $($projectionProcess.ExitCode))" }', 'if ($LASTEXITCODE -ne 0) { throw "Native layered SSOT tmux projection failed (exit $LASTEXITCODE)" }')) },
        @{ Name = 'the entrypoint no longer waits for staging'; Expected = 'Get-MiOS.ps1 native tmux staging waits for its GUI process and checks that process''s exit code'
           File = 'Get'; Edits = @(, @('$projectionProcess = Start-Process -FilePath $launcher -ArgumentList ''--stage-host-terminal'' -NoNewWindow -Wait -PassThru', '$projectionProcess = Start-Process -FilePath $launcher -ArgumentList ''--stage-host-terminal'' -NoNewWindow -PassThru')) },
        @{ Name = 'the build loses the staging process status object'; Expected = 'build-mios.ps1 native tmux staging waits for its GUI process and checks that process''s exit code'
           File = 'Build'; Edits = @(, @('$projectionProcess = Start-Process -FilePath $launcher -ArgumentList ''--stage-host-terminal'' -NoNewWindow -Wait -PassThru', '$projectionProcess = Start-Process -FilePath $launcher -ArgumentList ''--stage-host-terminal'' -NoNewWindow -Wait')) },
        @{ Name = 'the two layout functions disagree on the body'; Expected = 'Get-MiOS.ps1 and build-mios.ps1 resolve one installed layout (root, bin, native bin, profile body, scope)'
           File = 'Get'; Edits = @(, @("        ProfileBody = Join-Path `$root 'powershell\profile.ps1'`n        Scope       = if (`$Elevated)", "        ProfileBody = Join-Path `$root 'powershell\profile-main.ps1'`n        Scope       = if (`$Elevated)")) },
        @{ Name = 'the M:\ / MiOS-bootstrap redirector guess restored'; Expected = 'both profile redirectors load the installed layout''s body, with no M:\ or MiOS-bootstrap guess'
           File = 'Build'; Edits = @(, @('$miosProfilePath = (Get-MiosInstalledLayout).ProfileBody.Replace("''", "''''")', "`$miosProfilePath = if (Test-Path 'M:\') { 'M:\MiOS\powershell\profile.ps1' } else { Join-Path `$env:USERPROFILE 'MiOS-bootstrap\powershell\profile.ps1' }")) },
        @{ Name = 'the ProgramData native-bin default restored in the body'; Expected = 'no native-bin default or search order points at %ProgramData%\MiOS\bin'
           File = 'Get'; Edits = @(, @("else { '__MIOS_NATIVE_BIN__' }", "else { Join-Path `$env:ProgramData 'MiOS\bin' }")) },
        @{ Name = 'a missing native shell throws again'; Expected = 'the profile body names a missing native shell and keeps loading; an installed one loads from the layout bin'
           File = 'Get'; Edits = @(, @("if (-not (Test-Path -LiteralPath `$_miosNativeShell)) {`n    Write-Host", "if (-not (Test-Path -LiteralPath `$_miosNativeShell)) {`n    throw 'missing'`n    Write-Host")) },
        @{ Name = 'the hub resolves mios to itself'; Expected = 'mios.ps1 runs a verb in one hop (no body, a broken body, a body''s mios function, or through PATH) and never dispatches to itself'
           File = 'Build'; Edits = @(, @('$dispatcher = Get-Command mios -CommandType Function -ErrorAction SilentlyContinue', '$dispatcher = Get-Command mios -ErrorAction SilentlyContinue')) },
        @{ Name = 'the hub re-entry guard removed'; Expected = 'a verb the native entry hands back to mios.ps1 ends in one refusal, not a loop'
           File = 'Build'; Edits = @(, @('if ($env:MIOS_HUB_ACTIVE) {', 'if ($false) {')) },
        @{ Name = 'the hub opens the host terminal while dispatching'; Expected = 'loading the profile body to dispatch a verb does not start the interactive host terminal'
           File = 'Build'; Edits = @(, @("    `$env:MIOS_SKIP_MOTD = '1'`n    try { . `$_miosProfile }", "    try { . `$_miosProfile }")) },
        @{ Name = 'the client setup called without -Scope User'; Expected = 'a per-user install calls the client setup with -Scope User, its bin and its body, and refuses a setup without -Scope'
           File = 'Build'; Edits = @(, @("        `$arguments['Scope'] = 'User'`n", '')) },
        @{ Name = 'a verb guesses M:\ for the checkout again'; Expected = 'the mios pull and mios build verbs use the installed MiOS checkout: its root, its driver (never a download) and its smoke script'
           File = 'Build'; Edits = @(, @("# END WINDOWS CHECKOUT REFRESH`n`n# The contained native companion", "# END WINDOWS CHECKOUT REFRESH`nif (Test-Path 'M:\.git') { ```$miosRoot = 'M:\' }`n`n# The contained native companion")) },
        @{ Name = 'the build driver downloaded when the checkout lacks it'; Expected = 'the mios pull and mios build verbs use the installed MiOS checkout: its root, its driver (never a download) and its smoke script'
           File = 'Build'; Edits = @(, @("is not readable inside ```$distro'; exit 1; fi`"", "is not readable inside ```$distro -- falling back to curl'; curl -fsSL -o /usr/libexec/mios/mios-build-driver '`$MiosRawBase/usr/libexec/mios/mios-build-driver'; fi`"")) }
    )
    $caught = 0; $index = 0
    foreach ($plant in $plants) {
        $index++
        $source = if ($plant.File -eq 'Get') { $GetPath } else { $BuildPath }
        $text = ([IO.File]::ReadAllText($source)) -replace "`r`n", "`n"
        foreach ($edit in $plant.Edits) {
            $count = ([regex]::Matches($text, [regex]::Escape($edit[0]))).Count
            if ($count -ne 1) { throw "Missing or ambiguous defect anchor: $($plant.Name) (found $count)" }
            $text = $text.Replace($edit[0], $edit[1])
        }
        $copy = Join-Path $scratch ('planted-' + $index + '-' + (Split-Path $source -Leaf))
        [IO.File]::WriteAllText($copy, $text, (New-Object Text.UTF8Encoding($true)))
        if ($plant.File -eq 'Get') { $null = Invoke-Checks $copy $BuildPath } else { $null = Invoke-Checks $GetPath $copy }
        $detected = $script:failedChecks.Contains($plant.Expected)
        Write-Host ('  {0} planted defect caught: {1}' -f $(if ($detected) { 'PASS' } else { 'FAIL' }), $plant.Name)
        if ($detected) { $caught++ }
    }
    if ($caught -eq $plants.Count) { Write-Host "RESULT: PASS (every planted defect was caught: $caught/$($plants.Count))"; exit 0 }
    Write-Host "RESULT: FAIL (planted defects caught: $caught/$($plants.Count))"; exit 1
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
