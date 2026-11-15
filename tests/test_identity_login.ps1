# The MiOS login is the SSOT identity: the vendor/host [identity].username through MiOS's identity guard, the exact text
# mios.git's usr/share/mios/windows/*.ps1 carries (pinned below by sha256). No installer path resolves the login as
# uid 1000, writes a literal default user into wsl.conf, or logs in, hands off or defaults to a literal account name:
# build-mios.ps1's launcher resolves the login once (Get-MiosLinuxLogin) and bakes it into what it generates, and
# Get-MiOS.ps1's profile verbs resolve it at run time through their own pinned copy of the same guard.
# Source checks, plus both resolvers executed against a wsl.exe mock: no distro or wsl.exe is touched.
# Default runs the checks; -PlantDefect plants each guarded defect into a copy and requires a red result.
[CmdletBinding()]
param([switch]$PlantDefect, [string]$BuildPath, [string]$GetPath, [string]$FieldPath)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $BuildPath) { $BuildPath = Join-Path $repoRoot 'build-mios.ps1' }
if (-not $GetPath) { $GetPath = Join-Path $repoRoot 'Get-MiOS.ps1' }
if (-not $FieldPath) { $FieldPath = Join-Path $repoRoot 'field\lib\Get-MiOS-Backend.ps1' }
# sha256 of the guard's Python text as mios.git ships it (mios-native-client-setup.ps1 $identityProbe, mios.git 7a3a0dba).
$GuardSha256 = '82169695caa49524cf90ac4b60da1e2cfbf2edec0237f6d011110977b03f4ad4'

$script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
function Check([bool]$Ok, [string]$What) {
    $script:checks++
    if ($Ok) { Write-Host "  PASS $What" } else { Write-Host "  FAIL $What"; $script:fail++; $script:failedChecks.Add($What) }
}
function Get-Count([string]$Text, [string]$Needle) { return ([regex]::Matches($Text, [regex]::Escape($Needle))).Count }
function Get-Sha256([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
# The PowerShell copies are single-quoted literals ('' escapes a quote).
function Get-PsGuardCopies([string]$Text) {
    return @([regex]::Matches($Text, "(?m)^\s*\`$identityProbe = '((?:[^']|'')*)'\s*$") | ForEach-Object { $_.Groups[1].Value.Replace("''", "'") })
}
function Get-FunctionText([string]$Text, [string]$Name) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    $f = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }.GetNewClosure(), $true))
    if ($f.Count -eq 1) { return $f[0].Extent.Text } else { return '' }
}

function Invoke-Checks([string]$Build, [string]$Get, [string]$Field) {
    $script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
    $build = ([IO.File]::ReadAllText($Build)) -replace "`r`n", "`n"
    $getText = ([IO.File]::ReadAllText($Get)) -replace "`r`n", "`n"
    $field = ([IO.File]::ReadAllText($Field)) -replace "`r`n", "`n"

    $uidLookups = 0; $literalDefaults = 0
    foreach ($text in @($build, $getText)) {
        $uidLookups += (Get-Count $text 'getpwuid(1000)') + (Get-Count $text 'getent passwd 1000')
        $literalDefaults += Get-Count $text 'default=mios'
    }
    Check ($uidLookups -eq 0) 'no installer path resolves the login as uid 1000'
    Check ($literalDefaults -eq 0) 'no installer path writes a literal default=mios'

    # Exactly one PowerShell copy of the guard per entry script, so a third copy shows red.
    $buildCopies = @(Get-PsGuardCopies $build); $getCopies = @(Get-PsGuardCopies $getText); $fieldCopies = @(Get-PsGuardCopies $field)
    $psSame = $buildCopies.Count -eq 1 -and $getCopies.Count -eq 1 -and $fieldCopies.Count -eq 0 -and
              @(@($buildCopies) + @($getCopies) | Where-Object { (Get-Sha256 $_) -eq $GuardSha256 }).Count -eq 2
    Check $psSame 'one PowerShell copy of the MiOS identity guard in build-mios.ps1 and one in Get-MiOS.ps1, both byte for byte (the field backend takes Get-MiOS.ps1''s)'
    $guard = if ($buildCopies.Count) { $buildCopies[0] } else { '' }
    $plain = if ($guard) { Get-Count $build $guard } else { 0 }
    $starts = Get-Count $build "import sys,pwd; sys.path.insert(0,'/usr/lib/mios'); import mios_toml as m;"
    Check ($plain -eq 4 -and $starts -eq 4) 'the realize, sudoers, wsl --import and seed paths carry the same guard text (4 plain copies, no drifted copy)'

    $realizeWrites = (Get-Count $build "printf '\n[user]\ndefault=%s\n' `"`$MIOS_LOGIN`" | sudo tee -a /etc/wsl.conf") -eq 1
    $seedWrites = (Get-Count $build "printf '\n[user]\ndefault=%s\n' `"`$MIOS_LOGIN`" >> /etc/wsl.conf") -eq 1
    $sudoersUser = $build.Contains('DEV_USER=$(python3 -c "import sys,pwd;') -and $build.Contains('no usable MiOS login for [identity].username; sudoers drop-in not written')
    $pyLogin = (Get-Count $build 'login = probe.stdout.strip() if probe.returncode == 0 else ""') -eq 1 -and $build.Contains('probe = subprocess.run([sys.executable, "-c", GUARD], capture_output=True, text=True)')
    Check ($realizeWrites -and $seedWrites -and $sudoersUser -and $pyLogin) 'each writer takes the login from the guard: realize and seed write default=$MIOS_LOGIN, sudoers grants $DEV_USER, the wsl --import sanitizer uses the guard''s output'

    # No login, handoff or default names an account literally. systemctl's --user subcommands and root are not logins.
    $literalLogins = New-Object System.Collections.Generic.List[string]
    foreach ($pair in @(@('build-mios.ps1', $build), @('Get-MiOS.ps1', $getText), @('Get-MiOS-Backend.ps1', $field))) {
        foreach ($m in [regex]::Matches($pair[1], "(?:--user|-User)\s+'?([a-z_][a-z0-9_-]*)'?(?=[\s)])")) {
            if ($m.Groups[1].Value -notin @('root', 'is-active', 'list-units')) { $literalLogins.Add("$($pair[0]): $($m.Value)") }
        }
        foreach ($needle in @("[string]`$User = 'mios'", "-Key 'username' -Default 'mios'", "`$resolvedUser = 'mios'")) {
            if ($pair[1].Contains($needle)) { $literalLogins.Add("$($pair[0]): $needle") }
        }
    }
    if ($literalLogins.Count) { $literalLogins | ForEach-Object { Write-Host "    literal login: $_" } }
    Check ($literalLogins.Count -eq 0) 'no installer, generated verb, shortcut, profile or handoff logs in as, hands off to or defaults to a literal account name'

    # The one credential is the operator's: chpasswd never takes a literal user:password pair.
    $literalPasswords = 0
    foreach ($text in @($build, $getText, $field)) {
        $literalPasswords += ([regex]::Matches($text, "(echo|printf)\s+(['`"])[^'`"$]*:[^'`"$]*\2\s*\|\s*(sudo\s+)?chpasswd")).Count
    }
    Check ($literalPasswords -eq 0) 'no installer path sets a literal password: chpasswd only ever takes the operator''s credential'
    $locked = (Get-Count $build 'sudo usermod -L mios 2>&1') -eq 1 -and (Get-Count $build 'usermod -L mios 2>/dev/null || true') -eq 1 -and
              (Get-Count $build '"$DEV_USER" "$_mios_pw_hash" | sudo chpasswd -e') -eq 1 -and (Get-Count $build '"$DEV_USER" "$_mios_pw" | sudo chpasswd') -eq 1 -and
              -not $build.Contains('for account in "$DEV_USER" mios')
    Check $locked 'the operator''s credential goes to the MiOS login only, and the mios account''s password is locked at creation and on every realize'

    # The launcher resolves the login once, then bakes it into every script and shortcut it writes.
    $launcher = (Get-FunctionText $build 'Install-MiosLauncher') -replace "`r`n", "`n"
    $baked = (Get-Count $launcher '$miosLogin = Get-MiosLinuxLogin (Resolve-MiosBuilderDistribution $DevDistro)') -eq 1 -and
             (Get-Count $launcher '--user $miosLogin ') -eq 5 -and (Get-Count $launcher "-User '`$miosLogin'") -eq 1 -and
             (Get-Count $launcher '--user {2}') -eq 4 -and (Get-Count $launcher ', $miosLogin)') -eq 4 -and
             (Get-Count $launcher 'Install-MiOSTerminalProfile -LinuxLogin $miosLogin') -eq 1
    Check $baked 'the launcher resolves the login once (Get-MiosLinuxLogin) and bakes it into mios-pull, mios-build, the verbs, btop, the shortcuts and the terminal profile'
    $resolver = (Get-FunctionText $build 'Get-MiosLinuxLogin') -replace "`r`n", "`n"
    $users = $resolver.Contains('--exec python3 -c $identityProbe') -and $resolver.Contains('re-run the installer') -and
             (Get-Count $build '$user = Get-MiosLinuxLogin $distribution') -eq 1 -and (Get-Count $build 'try { $devUser = Get-MiosLinuxLogin $wslDistro }') -eq 1 -and
             (Get-Count $build 'try { $resolvedUser = Get-MiosLinuxLogin $devDistro }') -eq 1
    Check $users 'the native MiOS-MCP probe, the configurator and the auto-chain take the login from Get-MiosLinuxLogin, which refuses rather than falls back'

    # The profile verbs, written before the guest may exist, resolve at run time through Get-MiOS.ps1's resolver.
    $getResolver = (Get-FunctionText $getText 'Get-MiosLinuxLogin') -replace "`r`n", "`n"
    $runtime = $getResolver.Contains('--exec python3 -c $identityProbe') -and $getResolver.Contains('$Global:MiosLinuxLogins[$Distribution] = $login') -and
               $getResolver.Contains('re-run the installer') -and
               (Get-Count $getText '--user (Get-MiosLinuxLogin `$') -eq 4 -and
               (Get-Count $getText "'ConvertTo-MiosNativeArgument', 'Get-MiosLinuxLogin', 'Sync-MiosUserTomlToBuilder'") -eq 1
    Check $runtime 'the profile verbs (mios dev, mios mini, mios dash, btop) log in through the profile''s embedded Get-MiosLinuxLogin, cached per distro, never a fallback'
    $fieldRuntime = (Get-Count $field '--user (Get-MiosLinuxLogin `$') -eq 2 -and
                    (Get-Count $field "-Names @('Get-MiosLinuxLogin')") -eq 1 -and
                    @([regex]::Matches($field, '(?m)^\$loginHelperBlock$')).Count -eq 1
    Check $fieldRuntime 'the field backend''s profile verbs embed and use Get-MiOS.ps1''s Get-MiosLinuxLogin'

    # The operator's private mios.toml handoff lands in the MiOS login's home: every call takes the resolved login.
    $syncCalls = @([regex]::Matches(($build + "`n" + $getText), '(?m)^.*Sync-MiosUserTomlToBuilder -Path .*$') | ForEach-Object { $_.Value })
    $syncResolved = $syncCalls.Count -eq 3 -and
                    @($syncCalls | Where-Object { $_ -match "-User \(Get-MiosLinuxLogin ``\`$_devDistro\)\s*$" -or $_ -match "-User '\`$miosLogin'\s*$" }).Count -eq 3 -and
                    (Get-Count $getText '[Parameter(Mandatory)][string]$Distro, [Parameter(Mandatory)][string]$User)') -eq 1
    Check $syncResolved 'Sync-MiosUserTomlToBuilder''s -User is mandatory and always the resolved MiOS login'

    $terminal = (Get-Count $getText "param([string]`$LinuxLogin = '')") -eq 1 -and (Get-Count $getText "-Key 'username' -Default '' -VendorOnly") -eq 1 -and
                (Get-Count $field "param([string]`$LinuxLogin = '')") -eq 1
    Check $terminal 'the terminal profile takes the launcher''s resolved login; its first render only has the vendor value as a placeholder'

    # Behaviour: both resolvers, executed against a wsl.exe mock. A usable login comes back (the profile's copy once per
    # distro per session); a failed guard, root or a name that is not a plain login refuses with the fix, never a name.
    $resolverOk = $false
    if ($resolver -and $getResolver) {
        $runs = @{}
        foreach ($case in @(@('ok', 'user', 0), @('fail', '', 1), @('root', 'root', 0), @('odd', 'Bad Name', 0))) {
            foreach ($copy in @(@('build', $resolver), @('get', $getResolver))) {
                $runs["$($copy[0])-$($case[0])"] = & $script:resolverHarness -FnSrc $copy[1] -Reply $case[1] -Rc $case[2]
            }
        }
        $refused = { param($r) @($r.Results | Where-Object { $_ -like 'ERR *re-run the installer' }).Count -eq 2 }
        $resolverOk = ($runs['build-ok'].Results -join ',') -eq 'user,user' -and ($runs['get-ok'].Results -join ',') -eq 'user,user' -and
                      $runs['get-ok'].Calls -eq 1 -and
                      (& $refused $runs['build-fail']) -and (& $refused $runs['get-fail']) -and (& $refused $runs['build-root']) -and
                      (& $refused $runs['get-root']) -and (& $refused $runs['build-odd']) -and (& $refused $runs['get-odd'])
    }
    Check $resolverOk 'executed against a wsl.exe mock, both resolvers return a usable login (the profile''s once per distro) and refuse a failed guard, root or a non-plain name with the fix'

    Write-Host "IDENTITY_LOGIN_ASSERTIONS $($script:checks)"
    return $script:fail
}
$script:resolverHarness = [scriptblock]::Create(@'
param($FnSrc, $Reply, $Rc)
$ErrorActionPreference = 'Stop'
$script:wslCalls = 0
function wsl.exe { $script:wslCalls++; if ($Reply) { $Reply }; $global:LASTEXITCODE = $Rc }
Remove-Variable -Name MiosLinuxLogins -Scope Global -ErrorAction SilentlyContinue
. ([scriptblock]::Create($FnSrc))
$results = @()
foreach ($i in 1..2) { try { $results += [string](Get-MiosLinuxLogin 'fixture-DEV') } catch { $results += ('ERR ' + $_.Exception.Message) } }
Remove-Variable -Name MiosLinuxLogins -Scope Global -ErrorAction SilentlyContinue
[pscustomobject]@{ Results = $results; Calls = $script:wslCalls }
'@)

try {
    if (-not $PlantDefect) {
        $failures = Invoke-Checks $BuildPath $GetPath $FieldPath
        if ($failures) { Write-Host "RESULT: FAIL ($failures checks)"; exit 1 }
        Write-Host 'RESULT: PASS (the MiOS login comes from [identity].username through MiOS''s guard; source checks and a wsl.exe mock)'; exit 0
    }
    $baseline = Invoke-Checks $BuildPath $GetPath $FieldPath
    if ($baseline) { Write-Host 'IDENTITY_LOGIN_BASELINE_FAILED'; exit 1 }
    $buildSource = ([IO.File]::ReadAllText($BuildPath)) -replace "`r`n", "`n"
    $probeLine = [regex]::Match($buildSource, "(?m)^\s*\`$identityProbe = '(?:[^']|'')*'\s*$").Value.Trim()
    $literal = 'no installer, generated verb, shortcut, profile or handoff logs in as, hands off to or defaults to a literal account name'
    $plants = @(
        @{ Name = 'the resolver looks up uid 1000 again'; Target = 'build'; Expected = 'no installer path resolves the login as uid 1000'
           Edits = @(, @("`$login = ((& wsl.exe -d `$Distribution -u root --exec python3 -c `$identityProbe) -join '').Trim()",
                         "`$login = ((& wsl.exe -d `$Distribution -u root --exec python3 -c 'import pwd; print(pwd.getpwuid(1000).pw_name)') -join '').Trim()")) },
        @{ Name = 'the realize writes a literal default=mios again'; Target = 'build'; Expected = 'no installer path writes a literal default=mios'
           Edits = @(, @("printf '\n[user]\ndefault=%s\n' `"`$MIOS_LOGIN`" | sudo tee -a /etc/wsl.conf", "printf '\n[user]\ndefault=mios\n' | sudo tee -a /etc/wsl.conf")) },
        @{ Name = 'the seed''s guard copy drifted'; Target = 'build'; Expected = 'the realize, sudoers, wsl --import and seed paths carry the same guard text (4 plain copies, no drifted copy)'
           Edits = @(, @("or no login shell)' % n)`" 2>/dev/null) || MIOS_LOGIN=`"`"", "or no login shell!)' % n)`" 2>/dev/null) || MIOS_LOGIN=`"`"")) },
        @{ Name = 'build-mios.ps1''s PowerShell guard copy drifted'; Target = 'build'; Expected = 'one PowerShell copy of the MiOS identity guard in build-mios.ps1 and one in Get-MiOS.ps1, both byte for byte (the field backend takes Get-MiOS.ps1''s)'
           Edits = @(, @("or no login shell)'' % n)'`n    `$login = ((& wsl.exe", "or no login shell!)'' % n)'`n    `$login = ((& wsl.exe")) },
        @{ Name = 'a third PowerShell copy of the guard'; Target = 'build'; Expected = 'one PowerShell copy of the MiOS identity guard in build-mios.ps1 and one in Get-MiOS.ps1, both byte for byte (the field backend takes Get-MiOS.ps1''s)'
           Edits = @(, @("    `$user = Get-MiosLinuxLogin `$distribution", "    $probeLine`n    `$user = Get-MiosLinuxLogin `$distribution")) },
        @{ Name = 'the wsl --import sanitizer takes id mios again'; Target = 'build'; Expected = 'each writer takes the login from the guard: realize and seed write default=$MIOS_LOGIN, sudoers grants $DEV_USER, the wsl --import sanitizer uses the guard''s output'
           Edits = @(, @('login = probe.stdout.strip() if probe.returncode == 0 else ""', 'login = "mios" if os.system("id mios >/dev/null 2>&1") == 0 else ""')) },
        @{ Name = 'a generated verb logs in as mios again'; Target = 'build'; Expected = $literal
           Edits = @(, @("--user `$miosLogin -- mios `$v @Args", "--user mios -- mios `$v @Args")) },
        @{ Name = 'the launcher stops resolving the login'; Target = 'build'; Expected = 'the launcher resolves the login once (Get-MiosLinuxLogin) and bakes it into mios-pull, mios-build, the verbs, btop, the shortcuts and the terminal profile'
           Edits = @(, @("`$miosLogin = Get-MiosLinuxLogin (Resolve-MiosBuilderDistribution `$DevDistro)", "`$miosLogin = 'mios'")) },
        @{ Name = 'the auto-chain parses /etc/passwd for mios again'; Target = 'build'; Expected = $literal
           Edits = @(, @("try { `$resolvedUser = Get-MiosLinuxLogin `$devDistro } catch {", "try { `$resolvedUser = 'mios' } catch {")) },
        @{ Name = 'Phase 6 defaults the image account to mios again'; Target = 'build'; Expected = $literal
           Edits = @(, @("-Key 'username' -Default '')).Trim()", "-Key 'username' -Default 'mios')).Trim()")) },
        @{ Name = 'the profile handoff targets mios again'; Target = 'get'; Expected = 'Sync-MiosUserTomlToBuilder''s -User is mandatory and always the resolved MiOS login'
           Edits = @(, @('-Path `$tomlDst -Distro `$_devDistro -User (Get-MiosLinuxLogin `$_devDistro)', '-Path `$tomlDst -Distro `$_devDistro -User mios')) },
        @{ Name = 'Sync-MiosUserTomlToBuilder takes a default user again'; Target = 'get'; Expected = $literal
           Edits = @(, @("[Parameter(Mandatory)][string]`$Distro, [Parameter(Mandatory)][string]`$User)", "[Parameter(Mandatory)][string]`$Distro, [string]`$User = 'mios')")) },
        @{ Name = 'Get-MiOS.ps1''s guard copy drifted'; Target = 'get'; Expected = 'one PowerShell copy of the MiOS identity guard in build-mios.ps1 and one in Get-MiOS.ps1, both byte for byte (the field backend takes Get-MiOS.ps1''s)'
           Edits = @(, @("or no login shell)'' % n)'`n    `$login = ((& wsl.exe", "or no login shell!)'' % n)'`n    `$login = ((& wsl.exe")) },
        @{ Name = 'the profile body no longer carries the resolver'; Target = 'get'; Expected = 'the profile verbs (mios dev, mios mini, mios dash, btop) log in through the profile''s embedded Get-MiosLinuxLogin, cached per distro, never a fallback'
           Edits = @(, @("'ConvertTo-MiosNativeArgument', 'Get-MiosLinuxLogin', 'Sync-MiosUserTomlToBuilder'", "'ConvertTo-MiosNativeArgument', 'Sync-MiosUserTomlToBuilder'")) },
        @{ Name = 'the profile''s resolver falls back to a name'; Target = 'get'; Expected = 'executed against a wsl.exe mock, both resolvers return a usable login (the profile''s once per distro) and refuse a failed guard, root or a non-plain name with the fix'
           Edits = @(, @("    if (`$LASTEXITCODE -ne 0 -or -not `$login -or `$login -eq 'root') { throw", "    if (`$LASTEXITCODE -ne 0 -or -not `$login -or `$login -eq 'root') { `$login = 'user' } elseif (`$false) { throw")) },
        @{ Name = 'the seed sets mios:mios again'; Target = 'build'; Expected = 'no installer path sets a literal password: chpasswd only ever takes the operator''s credential'
           Edits = @(, @("        usermod -L mios 2>/dev/null || true", "        echo 'mios:mios' | chpasswd 2>/dev/null || true")) },
        @{ Name = 'the realize stops locking mios'; Target = 'build'; Expected = 'the operator''s credential goes to the MiOS login only, and the mios account''s password is locked at creation and on every realize'
           Edits = @(, @('sudo usermod -L mios 2>&1', 'sudo true 2>&1')) },
        @{ Name = 'the operator''s credential goes to mios again'; Target = 'build'; Expected = 'the operator''s credential goes to the MiOS login only, and the mios account''s password is locked at creation and on every realize'
           Edits = @(, @('"$DEV_USER" "$_mios_pw_hash" | sudo chpasswd -e', '"mios" "$_mios_pw_hash" | sudo chpasswd -e')) },
        @{ Name = 'the realize sets a literal password with printf'; Target = 'build'; Expected = 'no installer path sets a literal password: chpasswd only ever takes the operator''s credential'
           Edits = @(, @("_mios_pw='__MIOS_LOGIN_PASSWORD__'", "printf 'user:changeme\n' | sudo chpasswd`n_mios_pw='__MIOS_LOGIN_PASSWORD__'")) },
        @{ Name = 'the field profile body no longer carries the resolver'; Target = 'field'; Expected = 'the field backend''s profile verbs embed and use Get-MiOS.ps1''s Get-MiosLinuxLogin'
           Edits = @(, @("`n`$loginHelperBlock`n`nfunction mios-dev {", "`n`nfunction mios-dev {")) }
    )
    $caught = 0
    foreach ($plant in $plants) {
        $source = switch ($plant.Target) { 'build' { $BuildPath } 'get' { $GetPath } 'field' { $FieldPath } }
        $text = ([IO.File]::ReadAllText($source)) -replace "`r`n", "`n"
        foreach ($edit in $plant.Edits) {
            $count = ([regex]::Matches($text, [regex]::Escape($edit[0]))).Count
            if ($count -ne 1) { throw "Missing or ambiguous defect anchor: $($plant.Name) (found $count)" }
            $text = $text.Replace($edit[0], $edit[1])
        }
        $copy = Join-Path ([IO.Path]::GetTempPath()) ('planted-identity-' + [guid]::NewGuid().ToString('N') + '.ps1')
        try {
            [IO.File]::WriteAllText($copy, $text, (New-Object Text.UTF8Encoding($true)))
            $paths = @{ build = $BuildPath; get = $GetPath; field = $FieldPath }
            $paths[$plant.Target] = $copy
            $null = Invoke-Checks $paths['build'] $paths['get'] $paths['field']
        } finally { Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue }
        $detected = $script:failedChecks.Contains($plant.Expected)
        Write-Host ('  {0} planted defect caught: {1}' -f $(if ($detected) { 'PASS' } else { 'FAIL' }), $plant.Name)
        if ($detected) { $caught++ }
    }
    if ($caught -eq $plants.Count) { Write-Host "RESULT: PASS (every planted defect was caught: $caught/$($plants.Count))"; exit 0 }
    Write-Host "RESULT: FAIL (planted defects caught: $caught/$($plants.Count))"; exit 1
} catch { Write-Host "RESULT: ERROR $($_.Exception.Message)"; exit 1 }
