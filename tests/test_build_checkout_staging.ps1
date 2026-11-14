# Checkout update and entry-script staging fixtures: Update-MiosCheckout and Publish-MiosEntryScripts AST-extracted from
# build-mios.ps1 and run against real scratch git repositories and scratch directories. Nothing outside the scratch tree
# is read or written; the only network-free git remote is a scratch origin.
# Default runs the fixtures; -PlantDefect plants each guarded defect into a copy of the product and requires a red result.
[CmdletBinding()]
param([switch]$PlantDefect, [string]$BuildPath)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $BuildPath) { $BuildPath = Join-Path $repoRoot 'build-mios.ps1' }
if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) {
    $gitCmd = Join-Path $env:LOCALAPPDATA 'Programs\Git\cmd'
    if (Test-Path -LiteralPath (Join-Path $gitCmd 'git.exe')) { $env:PATH = "$gitCmd;$env:PATH" } else { throw 'git is required for the checkout fixtures.' }
}
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-checkout-staging-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -ErrorAction Stop | Out-Null

$script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
function Check([bool]$Ok, [string]$What) {
    $script:checks++
    if ($Ok) { Write-Host "  PASS $What" } else { Write-Host "  FAIL $What"; $script:fail++; $script:failedChecks.Add($What) }
}
function Get-Ast([string]$Path) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Product source does not parse: $Path $($errors[0].Message)" }
    return $ast
}
function Get-Function($Ast, [string]$Name) {
    $found = @($Ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true))
    if ($found.Count -ne 1) { throw "Missing or duplicate function $Name" }
    return $found[0]
}
function Invoke-Git([string]$Dir) { $out = & git -C $Dir @args 2>&1; if ($LASTEXITCODE -ne 0) { throw "git $($args -join ' ') failed in ${Dir}: $out" }; return $out }
function Get-Sha([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }

# --- Scratch origin with two commits; the clone starts at the first --------------------------------------------------
$origin = Join-Path $scratch 'origin'; New-Item -ItemType Directory -Path $origin | Out-Null
$null = Invoke-Git $origin init -q -b main
$null = Invoke-Git $origin config user.email fixture@example.invalid; $null = Invoke-Git $origin config user.name Fixture
$null = Invoke-Git $origin config core.autocrlf false
[IO.File]::WriteAllText((Join-Path $origin 'a.txt'), "one`n")
$null = Invoke-Git $origin add a.txt; $null = Invoke-Git $origin commit -q -m one
$first = (Invoke-Git $origin rev-parse HEAD).Trim()
$clone = Join-Path $scratch 'repo'
$null = & git clone -q $origin $clone 2>&1; if ($LASTEXITCODE -ne 0) { throw 'scratch clone failed' }
$null = Invoke-Git $clone config core.autocrlf false
[IO.File]::WriteAllText((Join-Path $origin 'b.txt'), "two`n")
$null = Invoke-Git $origin add b.txt; $null = Invoke-Git $origin commit -q -m two
$second = (Invoke-Git $origin rev-parse HEAD).Trim()

function Invoke-Checks([string]$Build) {
    $script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
    $ast = Get-Ast $Build
    foreach ($name in 'Update-MiosCheckout', 'Publish-MiosEntryScripts') {
        . ([scriptblock]::Create(((Get-Function $ast $name).Extent.Text -replace '^function\s+', 'function global:')))
    }
    function global:Log-Warn { param($m) $script:warnings.Add([string]$m) }
    function global:Write-Log { param($m) }
    function global:Invoke-GitFetchWithRetry { param([string]$RepoPath, [string]$Ref) $null = & git -C $RepoPath fetch -q origin $Ref 2>&1; return $LASTEXITCODE }

    function Reset-Clone {
        $null = Invoke-Git $clone reset -q --hard $first
        $null = Invoke-Git $clone clean -q -fdx
        $script:warnings = New-Object System.Collections.Generic.List[string]
        $script:updateError = ''
    }
    function Invoke-Update { try { Update-MiosCheckout -RepoPath $clone -Ref main } catch { $script:updateError = $_.Exception.Message } }

    # --- Update-MiosCheckout: only tracked changes defer --------------------------------------------------------------
    Reset-Clone
    [IO.File]::WriteAllText((Join-Path $clone 'install.ps1'), 'overlay copy')
    New-Item -ItemType Directory -Force -Path (Join-Path $clone 'tests') | Out-Null
    [IO.File]::WriteAllText((Join-Path $clone 'tests\test_overlay.ps1'), 'overlay copy')
    Invoke-Update
    Check ($script:updateError -eq '' -and (Invoke-Git $clone rev-parse HEAD).Trim() -eq $second -and @($script:warnings).Count -eq 0 -and
           (Test-Path -LiteralPath (Join-Path $clone 'install.ps1')) -and (Test-Path -LiteralPath (Join-Path $clone 'tests\test_overlay.ps1'))) 'untracked overlay copies do not defer the update; it fast-forwards and keeps them'
    Reset-Clone
    [IO.File]::WriteAllText((Join-Path $clone 'a.txt'), "local edit`n")
    Invoke-Update
    Check ((Invoke-Git $clone rev-parse HEAD).Trim() -eq $first -and @($script:warnings | Where-Object { $_ -match 'Preserving local contributions' }).Count -eq 1 -and
           [IO.File]::ReadAllText((Join-Path $clone 'a.txt')) -eq "local edit`n") 'a tracked local change still defers the update and is preserved'
    Reset-Clone
    [IO.File]::WriteAllText((Join-Path $clone 'b.txt'), 'untracked local b')
    Invoke-Update
    Check ($script:updateError -match 'Cannot fast-forward .* untracked files are preserved' -and (Invoke-Git $clone rev-parse HEAD).Trim() -eq $first -and
           [IO.File]::ReadAllText((Join-Path $clone 'b.txt')) -eq 'untracked local b') 'an untracked file the update would overwrite refuses the fast-forward and is preserved'

    # --- Publish-MiosEntryScripts: the shadow's bytes, never the mios.git work tree's stale root copies ----------------
    $shadow = Join-Path $scratch 'shadow'; $repoDir = Join-Path $scratch 'mios-worktree'; $bin = Join-Path $scratch 'bin'
    foreach ($d in $shadow, $repoDir, $bin) { if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }; New-Item -ItemType Directory -Path $d | Out-Null }
    [IO.File]::WriteAllText((Join-Path $shadow 'Get-MiOS.ps1'), 'published get')
    [IO.File]::WriteAllText((Join-Path $shadow 'build-mios.ps1'), 'published build')
    [IO.File]::WriteAllText((Join-Path $shadow 'bootstrap.ps1'), 'published bootstrap')
    [IO.File]::WriteAllText((Join-Path $repoDir 'Get-MiOS.ps1'), 'stale get from mios.git')
    [IO.File]::WriteAllText((Join-Path $repoDir 'build-mios.ps1'), 'stale build from mios.git')
    [IO.File]::WriteAllText((Join-Path $repoDir 'build-mios.sh'), 'stale sh from mios.git')
    [IO.File]::WriteAllText((Join-Path $bin 'build-mios.ps1'), 'previous stage')
    $global:MiosRepoDir = $repoDir
    $publishError = ''; try { Publish-MiosEntryScripts -ShadowDir $shadow -BinDir $bin } catch { $publishError = $_.Exception.Message }
    Check ($publishError -eq '' -and (Get-Sha (Join-Path $bin 'Get-MiOS.ps1')) -eq (Get-Sha (Join-Path $shadow 'Get-MiOS.ps1')) -and
           (Get-Sha (Join-Path $bin 'build-mios.ps1')) -eq (Get-Sha (Join-Path $shadow 'build-mios.ps1')) -and
           (Get-Sha (Join-Path $bin 'bootstrap.ps1')) -eq (Get-Sha (Join-Path $shadow 'bootstrap.ps1'))) 'entry scripts are staged with the shadow''s published bytes'
    Check (-not (Test-Path -LiteralPath (Join-Path $bin 'build-mios.sh'))) 'a script only the mios.git work tree has is never staged from it'
    # A copy that does not land byte-identical refuses.
    function global:Copy-Item { [CmdletBinding()] param([string]$LiteralPath, [string]$Destination, [switch]$Force) [IO.File]::WriteAllText($Destination, 'tampered') }
    $publishError = ''; try { Publish-MiosEntryScripts -ShadowDir $shadow -BinDir $bin } catch { $publishError = $_.Exception.Message }
    Remove-Item function:global:Copy-Item
    Check ($publishError -match 'does not match the mios-bootstrap shadow') 'a staged copy that differs from the shadow refuses'

    # --- Source: the overlay run stages from the shadow -------------------------------------------------------------
    $text = [IO.File]::ReadAllText($Build)
    Check ($text.Contains('Publish-MiosEntryScripts -ShadowDir $MiosBootstrapShadow -BinDir $MiosBinDir') -and
           -not $text.Contains('$srcFile = Join-Path $MiosRepoDir $script')) 'build-mios stages entry scripts from the mios-bootstrap shadow only'
    Write-Host "CHECKOUT_STAGING_ASSERTIONS $($script:checks)"
    return $script:fail
}

try {
    if (-not $PlantDefect) {
        $failures = Invoke-Checks $BuildPath
        if ($failures) { Write-Host "RESULT: FAIL ($failures checks)"; exit 1 }
        Write-Host 'RESULT: PASS (checkout update and entry staging fixtures; scratch git and directories only)'; exit 0
    }
    $baseline = Invoke-Checks $BuildPath
    if ($baseline) { Write-Host 'CHECKOUT_STAGING_BASELINE_FAILED'; exit 1 }
    $plants = @(
        @{ Name = 'untracked files counted again'; Expected = 'untracked overlay copies do not defer the update; it fast-forwards and keeps them'
           From = '$changes = @(& git -C $RepoPath status --porcelain --untracked-files=no)'; To = '$changes = @(& git -C $RepoPath status --porcelain --untracked-files=all)' },
        @{ Name = "the mios.git work tree's root copy staged"; Expected = "entry scripts are staged with the shadow's published bytes"
           From = '$srcFile = Join-Path $ShadowDir $script'; To = '$srcFile = Join-Path $MiosRepoDir $script' },
        @{ Name = 'staged hash check removed'; Expected = 'a staged copy that differs from the shadow refuses'
           From = 'if ($have -ne $want) { throw'; To = 'if ($false) { throw' },
        @{ Name = 'staging call pointed at the mios.git work tree'; Expected = 'build-mios stages entry scripts from the mios-bootstrap shadow only'
           From = 'Publish-MiosEntryScripts -ShadowDir $MiosBootstrapShadow -BinDir $MiosBinDir'; To = 'Publish-MiosEntryScripts -ShadowDir $MiosRepoDir -BinDir $MiosBinDir' }
    )
    $caught = 0; $index = 0
    foreach ($plant in $plants) {
        $index++
        $text = [IO.File]::ReadAllText($BuildPath)
        $count = ([regex]::Matches($text, [regex]::Escape($plant.From))).Count
        if ($count -ne 1) { throw "Missing or ambiguous defect anchor: $($plant.Name) (found $count)" }
        $copy = Join-Path $scratch ('planted-' + $index + '-build-mios.ps1')
        [IO.File]::WriteAllText($copy, $text.Replace($plant.From, $plant.To), (New-Object Text.UTF8Encoding($true)))
        $null = Invoke-Checks $copy
        $detected = $script:failedChecks.Contains($plant.Expected)
        Write-Host ('  {0} planted defect caught: {1}' -f $(if ($detected) { 'PASS' } else { 'FAIL' }), $plant.Name)
        if ($detected) { $caught++ }
    }
    if ($caught -eq $plants.Count) { Write-Host "RESULT: PASS (every planted defect was caught: $caught/$($plants.Count))"; exit 0 }
    Write-Host "RESULT: FAIL (planted defects caught: $caught/$($plants.Count))"; exit 1
} finally {
    Remove-Variable -Name MiosRepoDir -Scope Global -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
