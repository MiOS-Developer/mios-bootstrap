# Tests only generated saved-config promotion code, extracted through the parser.
# No installer top-level, real WSL/Podman/build, or existing checkout is invoked.
# Git refresh checks use only throwaway local repositories inside the fixture directory.
# Run both modes on the Native Windows host with PowerShell 5.1 or pwsh:
#   powershell -NoProfile -File tests\test_build_savedconfig_security.ps1
#   powershell -NoProfile -File tests\test_build_savedconfig_security.ps1 -PlantDefect
[CmdletBinding()]
param([switch]$PlantDefect)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-build-user-config-' + [guid]::NewGuid().ToString('N'))
$originalProfile = $env:USERPROFILE
$originalSystemDrive = $env:SystemDrive
$script:failed = 0
$helperNames = @('Assert-MiosNoReparsePath', 'Set-MiosPrivateUserTomlAcl', 'Import-MiosUserToml',
                 'ConvertTo-MiosNativeArgument', 'Sync-MiosUserTomlToBuilder')

function Check([bool]$Ok, [string]$Description) {
    if ($Ok) { Write-Host "  PASS $Description" }
    else { Write-Host "  FAIL $Description"; $script:failed++ }
}

function Read-SourceAst([string]$Path) {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Source does not parse: $Path" }
    return $ast
}

function Read-GeneratedAst([string]$Text) {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Generated script does not parse: $($errors[0].Message)" }
    return $ast
}

function Get-HereString([object]$Ast, [string]$VariableName) {
    $assignments = @($Ast.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq ('$' + $VariableName)
    }, $true))
    $strings = @($assignments | ForEach-Object {
        $_.Right.FindAll({ param($node)
            $node -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and
            $node.Extent.Text.StartsWith('@"')
        }, $true)
    })
    if ($strings.Count -ne 1) { throw "Expected exactly one generated $VariableName template." }
    return $strings[0].Extent.Text
}

function Test-UnsafeGeneratedGitCommand([object]$Command) {
    if ($Command.GetCommandName() -ne 'git') { return $false }
    $arguments = @($Command.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.Extent.Text.Trim("'", '"') })
    return [bool](@($arguments | Where-Object { $_ -eq '--depth' -or $_.StartsWith('--depth=') }).Count -or
        ($arguments -contains 'reset' -and $arguments -contains '--hard') -or
        $arguments -contains 'clean' -or $arguments -contains 'stash')
}

function Test-GitCommandControls {
    foreach ($control in @(
        @{ Code = 'git merge --ff-only --no-autostash --no-overwrite-ignore FETCH_HEAD'; Unsafe = $false },
        @{ Code = 'git fetch origin main'; Unsafe = $false },
        @{ Code = 'git fetch --depth=1 origin main'; Unsafe = $true },
        @{ Code = 'git reset --hard FETCH_HEAD'; Unsafe = $true },
        @{ Code = 'git clean -fd'; Unsafe = $true },
        @{ Code = 'git stash push'; Unsafe = $true }
    )) {
        $ast = Read-GeneratedAst $control.Code
        $command = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)
        Check ((Test-UnsafeGeneratedGitCommand $command) -eq $control.Unsafe) "git argument control: $($control.Code)"
    }
}

function Get-GeneratedEntrypoints {
    $buildAst = Read-SourceAst (Join-Path $repoRoot 'build-mios.ps1')
    $getPath = Join-Path $repoRoot 'Get-MiOS.ps1'
    $getAst = Read-SourceAst $getPath
    $export = @($buildAst.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-MiosUserTomlHelperSource'
    }, $true))
    if ($export.Count -ne 1) { throw 'The standalone builder must obtain its helpers from the canonical entrypoint.' }
    . ([scriptblock]::Create($export[0].Extent.Text))
    $userTomlHelperBlock = Get-MiosUserTomlHelperSource -Path $getPath
    $helperAst = Read-GeneratedAst $userTomlHelperBlock
    foreach ($name in $helperNames) {
        $canonical = @($getAst.FindAll({ param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true))
        $emitted = @($helperAst.FindAll({ param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true))
        Check ($canonical.Count -eq 1 -and $emitted.Count -eq 1 -and
            $canonical[0].Extent.Text -ceq $emitted[0].Extent.Text) "canonical helper $name is embedded verbatim"
    }
    $refresh = @($getAst.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Update-MiosWindowsBuildCheckout'
    }, $true))
    if ($refresh.Count -ne 1) { throw 'The clean-only Windows refresh helper is missing.' }
    $script:windowsRefreshSource = $refresh[0].Extent.Text
    . ([scriptblock]::Create($script:windowsRefreshSource))
    $windowsRefreshBlock = Get-MiosUserTomlHelperSource -Path $getPath -Names @('Update-MiosWindowsBuildCheckout')
    $losslessShellHelper = Get-MiosUserTomlHelperSource -Path $getPath -Names @('Get-MiosLosslessPullShell')
    $losslessPullShell = & ([scriptblock]::Create($losslessShellHelper + "`nGet-MiosLosslessPullShell"))
    $script:nativePullShell = [string]$losslessPullShell
    $script:nativeArgumentSource = Get-MiosUserTomlHelperSource -Path $getPath -Names @('ConvertTo-MiosNativeArgument')
    $miosBuildRefLiteral = "'main'"; $miosBootstrapRefLiteral = "'main'"
    $MiosBootstrapShadow = Join-Path $scratch 'bootstrap-source'
    $bootstrapBuild = Join-Path $MiosBootstrapShadow 'build-mios.ps1'
    $bootstrapFallback = Join-Path $scratch 'build-mios.ps1'
    # Only generator strings are expanded. Installer/profile statements are never invoked.
    $DevDistro = 'fixture-DEV'; $LegacyDevName = 'fixture-LEGACY'
    $devResolveBlock = & ([scriptblock]::Create((Get-HereString $buildAst 'devResolveBlock')))
    $miosDevDistroLiteral = "'fixture-DEV'"
    $miosBuilderUserLiteral = "'mios'"
    $_miosCols = 80; $_miosRows = 20; $_miosScroll = 9000
    $ompBlobBase64 = ''; $Script:MiosBootstrapRaw = 'https://fixture.invalid/bootstrap'
    $standalone = [string](& ([scriptblock]::Create((Get-HereString $buildAst 'buildScript'))))
    $profile = [string](& ([scriptblock]::Create((Get-HereString $getAst 'miosScriptBody'))))
    $standaloneAst = Read-GeneratedAst $standalone
    $profileAst = Read-GeneratedAst $profile
    $pull = [string](& ([scriptblock]::Create((Get-HereString $buildAst 'pullScript'))))
    $update = [string](& ([scriptblock]::Create((Get-HereString $buildAst 'updateScript'))))
    $pullAst = Read-GeneratedAst $pull
    $updateAst = Read-GeneratedAst $update
    foreach ($surface in @(@{ Name = 'standalone'; Ast = $standaloneAst },
                            @{ Name = 'profile'; Ast = $profileAst },
                            @{ Name = 'pull companion'; Ast = $pullAst },
                            @{ Name = 'update companion'; Ast = $updateAst })) {
        $embedded = @($surface.Ast.FindAll({ param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Update-MiosWindowsBuildCheckout'
        }, $true))
        Check ($embedded.Count -eq 1 -and $embedded[0].Extent.Text -ceq $script:windowsRefreshSource) "$($surface.Name) embeds the canonical lossless refresh helper"
        $calls = @($surface.Ast.FindAll({ param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        }, $true))
        Check (@($calls | Where-Object { $_.GetCommandName() -eq 'Update-MiosWindowsBuildCheckout' }).Count -gt 0) "$($surface.Name) invokes the canonical refresh"
        Check (-not @($calls | Where-Object {
            Test-UnsafeGeneratedGitCommand $_
        }).Count) "$($surface.Name) contains no shallow fetch, force reset, clean, or stash"
    }
    $inline = @($pullAst.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$inlinePull'
    }, $true))
    if ($inline.Count -ne 1) { throw 'Expected one contained native pull implementation.' }
    $inlineValue = $inline[0].Right.Find({ param($node)
        $node -is [System.Management.Automation.Language.StringConstantExpressionAst]
    }, $true)
    Check ($inlineValue -and $inlineValue.Value.Replace("`r`n", "`n") -ceq $script:nativePullShell.Replace("`r`n", "`n")) 'pull companion embeds the canonical native shell verbatim'
    Check ($script:nativePullShell -notmatch '--depth|reset\s+--hard|git\s+clean|git\s+stash' -and
        $script:nativePullShell.Contains('--ff-only') -and $script:nativePullShell.Contains('--no-autostash') -and
        $script:nativePullShell.Contains('--no-overwrite-ignore')) 'native pull uses a complete safe fast-forward policy'
    Check (-not $pull.Contains('/usr/bin/mios-pull')) 'pull companion does not bypass preservation through an external backend'
    Check (-not @($updateAst.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'robocopy'
    }, $true)).Count) 'update companion does not overwrite the source through a blind overlay'
    foreach ($entry in @(@{ Name = 'standalone'; Ast = $standaloneAst; Text = $standalone },
                          @{ Name = 'profile'; Ast = $profileAst; Text = $profile })) {
        foreach ($name in $helperNames) {
            $emitted = @($entry.Ast.FindAll({ param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
            }, $true))
            Check ($emitted.Count -eq 1 -and $userTomlHelperBlock.Contains($emitted[0].Extent.Text)) "$($entry.Name) includes the canonical $name helper"
        }
        $body = $entry.Ast
        if ($entry.Name -eq 'profile') {
            $fn = @($body.FindAll({ param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'mios-build'
            }, $true))
            if ($fn.Count -ne 1) { throw 'Expected exactly one generated profile mios-build function.' }
            $body = $fn[0].Body
        }
        $bodyText = $body.Extent.Text
        $marker = '# END PRIVATE USER CONFIGURATION HANDOFF'
        $end = $bodyText.IndexOf($marker, [StringComparison]::Ordinal)
        if ($end -lt 0) { throw "$($entry.Name) has no private handoff boundary." }
        $prefix = $bodyText.Substring(0, $end)
        if ($entry.Name -eq 'profile') { $prefix += "`n}" }
        $prefixAst = Read-GeneratedAst $prefix
        # Strip embedded definitions so the fixture can spy on private I/O safely.
        # Profile param() is not an EndBlock statement and does not enter this program.
        $program = @($prefixAst.EndBlock.Statements | Where-Object {
            $_ -isnot [System.Management.Automation.Language.FunctionDefinitionAst]
        } | ForEach-Object { $_.Extent.Text }) -join "`n"
        if ($entry.Name -eq 'profile') {
            # The parsed prefix is a bare { ... } scriptblock expression.
            $scriptBlock = $prefixAst.Find({ param($node)
                $node -is [System.Management.Automation.Language.ScriptBlockExpressionAst]
            }, $true)
            if (-not $scriptBlock) { throw 'Profile private phase was not isolated.' }
            $program = @($scriptBlock.ScriptBlock.EndBlock.Statements | Where-Object {
                $_ -isnot [System.Management.Automation.Language.FunctionDefinitionAst]
            } | ForEach-Object { $_.Extent.Text }) -join "`n"
        }
        $programAst = Read-GeneratedAst $program
        $commands = @($programAst.FindAll({ param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | ForEach-Object { $_.GetCommandName() })
        Check ($commands -contains 'Import-MiosUserToml' -and $commands -contains 'Sync-MiosUserTomlToBuilder') "$($entry.Name) invokes both private helpers before the boundary"
        Check (-not @($commands | Where-Object { $_ -in @('git','podman','wsl.exe','pwsh.exe','Invoke-Expression') }).Count) "$($entry.Name) private phase contains no refresh or build command"
        [pscustomobject]@{ Name = $entry.Name; Program = $program }
    }
}

function Invoke-PromotionFixture([string]$Name, [string]$Program, [string]$Failure = '') {
    $script:caseRoot = Join-Path $scratch ([guid]::NewGuid().ToString('N'))
    $env:USERPROFILE = $script:caseRoot
    # Generated Windows paths stay inside this fixture on every Native platform.
    $env:SystemDrive = $script:caseRoot
    $downloads = Join-Path $script:caseRoot 'Downloads'
    $private = Join-Path $script:caseRoot '.config\mios\mios.toml'
    $null = New-Item -ItemType Directory -Path $downloads -Force
    $old = Join-Path $downloads 'mios-old.toml'
    $new = Join-Path $downloads 'mios (2).toml'
    $archived = Join-Path $downloads 'mios.imported-20000101.toml'
    $secret = 'FIXTURE-ONLY-SAVED-PASSWORD'
    $content = "[identity]`nusername = 'mios'`ndefault_password = '$secret'`n# UTF8: $([char]0x00e9)$([char]0x4e2d)`n"
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($old, "[identity]`nusername = 'old'`n", $utf8)
    [IO.File]::WriteAllText($new, $content, $utf8)
    [IO.File]::WriteAllText($archived, 'already imported', $utf8)
    [IO.File]::SetLastWriteTimeUtc($old, [datetime]::UtcNow.AddMinutes(-2))
    [IO.File]::SetLastWriteTimeUtc($new, [datetime]::UtcNow.AddMinutes(-1))
    [IO.File]::SetLastWriteTimeUtc($archived, [datetime]::UtcNow)
    $script:events = New-Object System.Collections.Generic.List[string]
    $script:failure = $Failure; $script:reached = $false; $script:synced = ''
    $script:unexpected = $false; $script:rejectedStage = ''
    function Test-Path {
        param([string]$LiteralPath, [string]$Path, [string]$PathType)
        $candidate = if ($LiteralPath) { $LiteralPath } else { $Path }
        if (-not $candidate -or -not $candidate.StartsWith($script:caseRoot, [StringComparison]::OrdinalIgnoreCase)) { return $false }
        return Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
    }
    function Resolve-MiosDevDistro {
        $script:events.Add('resolve')
        if ($script:failure -eq 'resolve') { $script:rejectedStage = 'resolve'; throw 'fixture resolver refused' }
        return 'fixture-DEV'
    }
    function Import-MiosUserToml {
        param([string]$SourcePath, [string]$DestinationPath)
        $script:events.Add('import')
        if ($script:failure -eq 'import') { $script:rejectedStage = 'import'; throw 'fixture private import refused' }
        if (-not $DestinationPath) { $DestinationPath = Join-Path $env:USERPROFILE '.config\mios\mios.toml' }
        if ($DestinationPath -ne $private) { throw 'fixture refused a public destination' }
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $DestinationPath) -Force
        [IO.File]::WriteAllBytes($DestinationPath, [IO.File]::ReadAllBytes($SourcePath))
        return $DestinationPath
    }
    function Sync-MiosUserTomlToBuilder {
        param([string]$Path, [string]$Distro, [string]$User)
        $script:events.Add('sync')
        if ($script:failure -eq 'sync') { $script:rejectedStage = 'sync'; throw 'fixture private handoff refused' }
        if ($Path -ne $private -or $Distro -ne 'fixture-DEV' -or $User -ne 'mios') { throw 'fixture refused an unexpected handoff' }
        $script:synced = [IO.File]::ReadAllText($Path, (New-Object System.Text.UTF8Encoding($false)))
    }
    function Move-Item {
        param([string]$LiteralPath, [string]$Destination, [switch]$Force, [string]$ErrorAction)
        if (-not $LiteralPath.StartsWith($downloads, [StringComparison]::OrdinalIgnoreCase) -or
            -not $Destination.StartsWith($downloads, [StringComparison]::OrdinalIgnoreCase)) { throw 'fixture archive escaped its sandbox' }
        $script:events.Add('archive')
        Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination -Force:$Force -ErrorAction Stop
    }
    function Start-Process { $script:unexpected = $true; throw 'fixture refused browser launch' }
    function Read-Host { throw 'fixture refused interactive prompt' }
    function git { $script:unexpected = $true; throw 'fixture refused git' }
    function wsl.exe { $script:unexpected = $true; throw 'fixture refused WSL' }
    function podman { $script:unexpected = $true; throw 'fixture refused Podman' }
    $threw = $false; $output = ''; $fixtureError = ''
    try { $output = (& ([scriptblock]::Create($Program + "`n`$script:reached = `$true")) 6>&1 | Out-String) }
    catch {
        $threw = $true; $output += $_.Exception.Message
        $fixtureError = $_.Exception.GetType().FullName + ': ' + $_.Exception.Message.Replace($secret, '[fixture secret redacted]')
    }
    $label = "$Name $Failure".Trim()
    Check (-not $script:unexpected) "$label invokes no host command"
    Check (-not $output.Contains($secret)) "$label never logs a credential value"
    Check ([IO.File]::Exists($old) -and [IO.File]::Exists($archived)) "$label leaves older and previously imported downloads intact"
    if ($threw -and -not $Failure) { Write-Host ('  FIXTURE_ERROR ' + $label + ': ' + $fixtureError) }
    if ($Failure) {
        Check ($script:rejectedStage -eq $Failure) "$label reaches the intended failure control"
        Check ($threw -and -not $script:reached) "$label stops before overlay/build work"
        Check ([IO.File]::Exists($new)) "$label retains the last saved download"
        Check (-not $script:events.Contains('archive')) "$label never archives after a failed private write"
    } else {
        Check (-not $threw -and $script:reached) "$label completes the private phase"
        Check ($script:events.Contains('import') -and $script:events.Contains('sync') -and
            $script:events.IndexOf('import') -lt $script:events.IndexOf('sync') -and
            $script:events.IndexOf('sync') -lt $script:events.IndexOf('archive')) "$label imports and syncs before archiving"
        Check ($script:synced -ceq $content -and [IO.File]::ReadAllText($private, $utf8) -ceq $content) "$label preserves the entire newest TOML including UTF8 and credentials privately"
        Check (-not [IO.File]::Exists($new)) "$label archives only the newest pending download"
    }
}


function Invoke-LosslessRefreshFixture([string]$Source, [switch]$NativeShell) {
    $gitCommand = Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $fixtureGit = $gitCommand.Source
    $fixtureRoot = Join-Path $scratch ('git-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $fixtureRoot -Force
    $origin = Join-Path $fixtureRoot 'origin.git'
    $seed = Join-Path $fixtureRoot 'seed'
    $clean = Join-Path $fixtureRoot 'clean'
    $diverged = Join-Path $fixtureRoot 'diverged'
    $noHooks = Join-Path $fixtureRoot 'no-hooks'
    $null = New-Item -ItemType Directory -Path $noHooks -Force
    function git {
        # Disable user hooks, signing, and automatic stashing for isolated local fixtures.
        $ErrorActionPreference = 'Continue'
        & $fixtureGit -c "core.hooksPath=$noHooks" -c commit.gpgsign=false -c merge.autoStash=false `
            -c user.name=Fixture -c user.email=fixture@example.invalid @args
    }
    function Run-Git {
        $result = @(& git @args 2>&1)
        if ($LASTEXITCODE -ne 0) { throw "Local git fixture setup failed: $($args[0])" }
        return $result
    }
    if ($NativeShell) {
        $shellCommand = Get-Command sh -CommandType Application -ErrorAction Stop | Select-Object -First 1
        if ($shellCommand.Name -notmatch '^sh(?:\.exe)?$') { throw 'A local POSIX sh executable is required; no WSL launcher may substitute.' }
        . ([scriptblock]::Create($script:nativeArgumentSource))
        function Update-MiosWindowsBuildCheckout {
            param([string]$Path, [string]$Ref)
            $psi = New-Object Diagnostics.ProcessStartInfo
            $psi.FileName = $shellCommand.Source
            $psi.Arguments = (@('-s', '--', $Path, $Ref) | ForEach-Object { ConvertTo-MiosNativeArgument $_ }) -join ' '
            $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
            $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
            $psi.EnvironmentVariables['GIT_CONFIG_COUNT'] = '3'
            $psi.EnvironmentVariables['GIT_CONFIG_KEY_0'] = 'core.hooksPath'; $psi.EnvironmentVariables['GIT_CONFIG_VALUE_0'] = $noHooks
            $psi.EnvironmentVariables['GIT_CONFIG_KEY_1'] = 'merge.autoStash'; $psi.EnvironmentVariables['GIT_CONFIG_VALUE_1'] = 'false'
            $psi.EnvironmentVariables['GIT_CONFIG_KEY_2'] = 'protocol.file.allow'; $psi.EnvironmentVariables['GIT_CONFIG_VALUE_2'] = 'always'
            $process = New-Object Diagnostics.Process; $process.StartInfo = $psi
            try {
                if (-not $process.Start()) { throw 'Local shell fixture could not start.' }
                $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
                $process.StandardInput.Write($Source.Replace("`r`n", "`n")); $process.StandardInput.Close()
                if (-not $process.WaitForExit(60000)) { $process.Kill(); throw 'Local shell fixture timed out.' }
                $null = $stdout.GetAwaiter().GetResult(); $null = $stderr.GetAwaiter().GetResult()
                if ($process.ExitCode -ne 0) { throw 'Local native companion refused an unsafe refresh.' }
            } finally { $process.Dispose() }
        }
    } else { . ([scriptblock]::Create($Source)) }
    $kind = if ($NativeShell) { 'native companion' } else { 'Windows companion' }
    $null = Run-Git init --bare $origin
    $null = Run-Git init $seed
    $null = Run-Git -C $seed symbolic-ref HEAD refs/heads/main
    $seedFile = Join-Path $seed 'source.txt'
    [IO.File]::WriteAllText($seedFile, 'vendor-one')
    $null = Run-Git -C $seed add source.txt
    $null = Run-Git -C $seed commit -m 'Initial fixture source'
    $null = Run-Git -C $seed remote add origin $origin
    $null = Run-Git -C $seed push origin main
    $null = Run-Git clone --branch main $origin $clean
    [IO.File]::WriteAllText($seedFile, 'vendor-two')
    $null = Run-Git -C $seed commit -am 'Advance fixture source'
    $null = Run-Git -C $seed push origin main
    $remoteHead = (Run-Git -C $seed rev-parse HEAD) -join ''
    Update-MiosWindowsBuildCheckout -Path $clean -Ref main 6>$null
    Check (((Run-Git -C $clean rev-parse HEAD) -join '') -eq $remoteHead -and
        [IO.File]::ReadAllText((Join-Path $clean 'source.txt')) -eq 'vendor-two') "a clean $kind checkout fast-forwards"

    $localFile = Join-Path $clean 'source.txt'
    $untracked = Join-Path $clean 'operator-untracked.txt'
    $staged = Join-Path $clean 'operator-staged.txt'
    [IO.File]::WriteAllText($localFile, 'operator edit')
    [IO.File]::WriteAllText($untracked, 'operator untracked')
    [IO.File]::WriteAllText($staged, 'operator staged')
    $null = Run-Git -C $clean add operator-staged.txt
    $dirtyHead = (Run-Git -C $clean rev-parse HEAD) -join ''
    $dirtyStatus = (Run-Git -C $clean status --porcelain=v1) -join "`n"
    [IO.File]::WriteAllText($seedFile, 'vendor-three')
    $null = Run-Git -C $seed commit -am 'Advance past dirty fixture'
    $null = Run-Git -C $seed push origin main
    Update-MiosWindowsBuildCheckout -Path $clean -Ref main 6>$null
    Check (((Run-Git -C $clean rev-parse HEAD) -join '') -eq $dirtyHead -and
        ((Run-Git -C $clean status --porcelain=v1) -join "`n") -ceq $dirtyStatus -and
        [IO.File]::ReadAllText($localFile) -eq 'operator edit' -and
        [IO.File]::ReadAllText($untracked) -eq 'operator untracked' -and
        [IO.File]::ReadAllText($staged) -eq 'operator staged') "dirty $kind source preserves HEAD, staged edits, unstaged edits, and untracked files"

    $null = Run-Git clone --branch main $origin $diverged
    [IO.File]::WriteAllText((Join-Path $diverged 'source.txt'), 'local commit')
    $null = Run-Git -C $diverged commit -am 'Keep local fixture commit'
    $localHead = (Run-Git -C $diverged rev-parse HEAD) -join ''
    [IO.File]::WriteAllText($seedFile, 'remote divergent commit')
    $null = Run-Git -C $seed commit -am 'Diverge remote fixture source'
    $null = Run-Git -C $seed push origin main
    Update-MiosWindowsBuildCheckout -Path $diverged -Ref main 6>$null
    Check (((Run-Git -C $diverged rev-parse HEAD) -join '') -eq $localHead -and
        [IO.File]::ReadAllText((Join-Path $diverged 'source.txt')) -eq 'local commit' -and
        -not @((Run-Git -C $diverged status --porcelain=v1) | Where-Object { $_ }).Count) "diverged $kind source preserves its local commit and current tree"
    $ignoredCheckout = Join-Path $fixtureRoot 'ignored'
    $null = Run-Git clone --branch main $origin $ignoredCheckout
    $ignoredFile = Join-Path $ignoredCheckout 'ignored-operator.txt'
    [IO.File]::WriteAllText((Join-Path $ignoredCheckout '.git/info/exclude'), "ignored-operator.txt`n")
    [IO.File]::WriteAllText($ignoredFile, 'ignored local operator content')
    $ignoredHead = (Run-Git -C $ignoredCheckout rev-parse HEAD) -join ''
    [IO.File]::WriteAllText((Join-Path $seed 'ignored-operator.txt'), 'remote newly tracked content')
    $null = Run-Git -C $seed add ignored-operator.txt
    $null = Run-Git -C $seed commit -m 'Add remote collision fixture'
    $null = Run-Git -C $seed push origin main
    $refused = $false
    try { Update-MiosWindowsBuildCheckout -Path $ignoredCheckout -Ref main 6>$null } catch { $refused = $true }
    Check ($refused -and ((Run-Git -C $ignoredCheckout rev-parse HEAD) -join '') -eq $ignoredHead -and
        [IO.File]::ReadAllText($ignoredFile) -eq 'ignored local operator content') "$kind preserves ignored files when the remote starts tracking their paths"
    Check (-not @((Run-Git -C $clean stash list) | Where-Object { $_ }).Count -and
        -not @((Run-Git -C $diverged stash list) | Where-Object { $_ }).Count) 'source refresh never creates an automatic stash'
}

try {
    $null = New-Item -ItemType Directory -Path $scratch -Force
    Test-GitCommandControls
    $entries = @(Get-GeneratedEntrypoints)
    if ($entries.Count -ne 2) { throw 'Expected both generated entrypoints.' }
    foreach ($entry in $entries) {
        if (-not $PlantDefect) {
            foreach ($failure in @('', 'resolve', 'import', 'sync')) { Invoke-PromotionFixture $entry.Name $entry.Program $failure }
            continue
        }
        $programAst = Read-GeneratedAst $entry.Program
        $sync = @($programAst.FindAll({ param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Sync-MiosUserTomlToBuilder'
        }, $true))
        if ($sync.Count -lt 1) { throw 'No handoff command to mutate.' }
        $syncText = $sync[0].Extent.Text
        $publicProgram = $entry.Program.Replace("'.config\mios\mios.toml'", "'etc\mios\mios.toml'")
        if ($entry.Name -eq 'profile') {
            $import = $programAst.Find({ param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Import-MiosUserToml'
            }, $true)
            $publicProgram = $entry.Program.Replace($import.Extent.Text,
                ($import.Extent.Text + " -DestinationPath (Join-Path `$env:USERPROFILE 'etc\mios\mios.toml')"))
        }
        $plants = @(
            @{ Name = 'public user destination'; Program = $publicProgram },
            @{ Name = 'missing private builder handoff'; Program = $entry.Program.Replace($syncText, "Write-Host 'fixture handoff skipped'") },
            @{ Name = 'archive before failed handoff'; Program = $entry.Program.Replace($syncText,
                "Move-Item -LiteralPath `$tomlSrc.FullName -Destination (Join-Path `$tomlSrc.DirectoryName 'defect.imported.toml') -ErrorAction Stop`n$syncText") }
        )
        foreach ($plant in $plants) {
            if ($plant.Program -ceq $entry.Program) { throw "Mutation anchor missing: $($plant.Name)" }
            $before = $script:failed
            foreach ($failure in @('', 'sync')) { Invoke-PromotionFixture ($entry.Name + ' planted ' + $plant.Name) $plant.Program $failure }
            $caught = $script:failed -gt $before
            $script:failed = $before
            Check $caught "$($entry.Name) catches planted $($plant.Name)"
        }
    }
    if ($PlantDefect) {
        $before = $script:failed
        $unsafeRefresh = @'
function Update-MiosWindowsBuildCheckout {
    param([string]$Path, [string]$Ref)
    & git -C $Path fetch origin $Ref *> $null
    & git -C $Path reset --hard FETCH_HEAD *> $null
}
'@
        Invoke-LosslessRefreshFixture $unsafeRefresh
        $caught = $script:failed -gt $before
        $script:failed = $before
        Check $caught 'local repository fixtures catch the former destructive Windows refresh'
        $before = $script:failed
        $unsafeShell = 'set -eu; git -C "$1" fetch --depth=1 origin "$2" >/dev/null 2>&1; git -C "$1" reset --hard FETCH_HEAD >/dev/null 2>&1'
        Invoke-LosslessRefreshFixture $unsafeShell -NativeShell
        $caught = $script:failed -gt $before
        $script:failed = $before
        Check $caught 'local repository fixtures catch the former destructive native companion'
    } else {
        Invoke-LosslessRefreshFixture $script:windowsRefreshSource
        Invoke-LosslessRefreshFixture $script:nativePullShell -NativeShell
    }
    if ($script:failed) { Write-Host "RESULT: FAIL ($($script:failed) checks)"; exit 1 }
    Write-Host 'RESULT: PASS (both generated entrypoints)'
    exit 0
} finally {
    $env:USERPROFILE = $originalProfile
    $env:SystemDrive = $originalSystemDrive
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
