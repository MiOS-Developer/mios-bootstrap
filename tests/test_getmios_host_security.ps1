# tests/test_getmios_host_security.ps1
# Two-sided regression test for Get-MiOS.ps1 host security (mios-boot-win-03, mios-boot-win-04).
#
# mios-boot-win-03: the operator's user layer (mios.html -> ~\.config\mios\mios.toml) carries the D0 credential and
# must never reach the HOST tier (C:\etc\mios, M:\etc\mios). Positive: the real functions, extracted from Get-MiOS.ps1
# by the PowerShell parser (no top-level code runs), report credential KEY NAMES only, write a credential-free
# projection, and repair a raw copy an earlier bootstrap left; the script has no other writer of the operator layer
# into the host tier, and `mios build` promotes the saved file into the user tier only.
# mios-boot-win-04: Defender exclusions come only from SSOT [[security.defender_exclusions.path|process]] entries with
# a reason; %TEMP%, drive roots and profile roots are refused; the WSL VM firewall keeps DefaultInboundAction Block.
#
# Negative mode (-PlantDefect) plants each old behaviour into a scratch copy of Get-MiOS.ps1 and EXPECTS every check
# to catch it: a raw WriteAllText of the operator layer into etc\mios (and the raw copy's credential keys are named),
# DefaultInboundAction Allow, and a refusal rule that admits %TEMP%.
#
# Fixture credentials only (never a real value). Runs on Windows PowerShell 5.1 and pwsh:
#   powershell -NoProfile -File tests\test_getmios_host_security.ps1
#   powershell -NoProfile -File tests\test_getmios_host_security.ps1 -PlantDefect
[CmdletBinding()]
param([switch]$PlantDefect)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$realScript = Join-Path $repoRoot 'Get-MiOS.ps1'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-getmios-sec-' + $PID)
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
$script:fail = 0
function Check([bool]$Ok, [string]$What) {
    if ($Ok) { Write-Host "  PASS $What" } else { Write-Host "  FAIL $What"; $script:fail++ }
}

$secretMarks = @('PLANTED-SECRET-1', 'PLANTED-SECRET-2', 'PLANTED-SECRET-3', 'PLANTED-SECRET-4')
$userLayer = @"
[identity]
username = "mios"
default_password = "PLANTED-SECRET-1"
fullname = "Fixture Operator"

[ai]
max_tokens = 4096

[field.sysrescue]
wipe_passphrase = """PLANTED-SECRET-4
second line"""
password = ''

[[autounattend.accounts]]
name = "fixture"
password = "PLANTED-SECRET-2"

[auth]
password_hash = "`$6`$fixturesalt`$fixturehash"

[fixture.inline]
accounts = [{ name = "b", password = "PLANTED-SECRET-3" }]
keep = "yes"
"@
$vendorLayer = @"
[security.defender_exclusions]

[[security.defender_exclusions.path]]
path = 'C:\MiOS\bin'
reason = 'fixture: the native launcher directory'

[[security.defender_exclusions.path]]
path = '%TEMP%'
reason = 'fixture: must be refused'

[[security.defender_exclusions.path]]
path = 'M:\'
reason = 'fixture: must be refused'

[[security.defender_exclusions.path]]
path = 'C:\MiOS\cache'

[[security.defender_exclusions.process]]
path = 'C:\MiOS\bin\mios-launch.exe'
reason = 'fixture: launcher'
"@

function Import-MiosFunctions([string]$ScriptPath) {
    # Define the named functions from the script in this scope; nothing else in the script runs.
    $tok = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tok, [ref]$errs)
    if ($errs.Count) { throw "$ScriptPath does not parse: $($errs[0].Message)" }
    $want = 'Split-MiosTomlKeyLine', 'Get-MiosTomlCredentialKeys', 'ConvertTo-MiosCredentialFreeToml', 'Set-MiosHostTierAcl',
            'Write-MiosHostToml', 'Repair-MiosHostTierCredentials', 'Get-MiosTomlTableArray', 'Test-MiosDefenderExclusionRefused',
            'Get-MiosDefenderExclusionPlan'
    $defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        Where-Object { $want -contains $_.Name }
    $missing = @($want | Where-Object { $_ -notin @($defs | ForEach-Object { $_.Name }) })
    if ($missing.Count) { throw "Get-MiOS.ps1 lacks $($missing -join ', ')" }
    $assigns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -match '^\$Script:MiosCredential(Key|Inline)Re$' }, $true)
    foreach ($a in $assigns) { . ([scriptblock]::Create($a.Extent.Text)) }
    foreach ($d in $defs) { . ([scriptblock]::Create(($d.Extent.Text -replace '^function\s+', 'function global:'))) }
    return $ast
}

function Invoke-Checks([string]$ScriptPath) {
    $script:fail = 0
    $text = [IO.File]::ReadAllText($ScriptPath)
    $null = Import-MiosFunctions $ScriptPath
    function global:Resolve-MiosTomlText { return $script:fixtureUser }
    function global:Resolve-MiosVendorTomlText { return $script:fixtureVendor }
    $script:fixtureUser = ''; $script:fixtureVendor = $vendorLayer

    Write-Host '== mios-boot-win-03: credential keys by name, never by value'
    $keys = @(Get-MiosTomlCredentialKeys $userLayer)
    $joined = $keys -join ', '
    foreach ($k in 'identity.default_password', 'field.sysrescue.wipe_passphrase', 'autounattend.accounts.password', 'auth.password_hash') {
        Check ($keys -contains $k) "credential key $k is named"
    }
    Check (@($keys | Where-Object { $_ -like 'fixture.inline.accounts*' }).Count -eq 1) 'an inline table holding a password is named'
    Check (-not ($keys -contains 'ai.max_tokens')) 'ai.max_tokens is not a credential'
    Check (-not ($keys -contains 'field.sysrescue.password')) 'an empty password is not reported'
    Check (-not @($secretMarks | Where-Object { $joined.Contains($_) }).Count) 'no credential value appears in the key report'

    Write-Host '== mios-boot-win-03: projection and host-tier writer'
    $proj = ConvertTo-MiosCredentialFreeToml $userLayer
    Check (-not @($secretMarks | Where-Object { $proj.Contains($_) }).Count) 'projection carries no credential value'
    Check (-not $proj.Contains('second line')) 'a multi-line credential value is dropped whole'
    Check ($proj -match '(?m)^username = "mios"' -and $proj -match '(?m)^max_tokens = 4096' -and $proj -match '(?m)^keep = "yes"') 'non-credential keys are kept'
    Check (-not @(Get-MiosTomlCredentialKeys $proj).Count) 'projection has no credential key'
    $hostTier = Join-Path $scratch 'etc\mios\mios.toml'
    Write-MiosHostToml -Path $hostTier -Text $userLayer 6>$null | Out-Null
    $written = [IO.File]::ReadAllText($hostTier)
    Check (-not @($secretMarks | Where-Object { $written.Contains($_) }).Count) 'Write-MiosHostToml writes no credential value'
    $raw = Join-Path $scratch 'M\etc\mios\mios.toml'
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $raw) | Out-Null
    [IO.File]::WriteAllText($raw, $userLayer)   # the planted raw copy an earlier bootstrap left
    $out = (Repair-MiosHostTierCredentials -Paths @($raw) 6>&1 | Out-String)
    Check (@(Get-MiosTomlCredentialKeys ([IO.File]::ReadAllText($raw))).Count -eq 0) 'a planted raw host-tier copy is caught and rewritten credential-free'
    Check ($out.Contains('identity.default_password') -and -not @($secretMarks | Where-Object { $out.Contains($_) }).Count) 'the repair names the key, never the value'

    Write-Host '== mios-boot-win-03: no other writer of the operator layer into the host tier'
    $tok = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tok, [ref]$errs)
    $rawHostWrites = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            $n.Member.Extent.Text -eq 'WriteAllText' -and $n.Extent.Text -match '\$_miosHostToml' }, $true))
    Check ($rawHostWrites.Count -eq 0) 'no WriteAllText of $_miosHostToml (the operator layer) anywhere'
    Check ($text -notmatch "tomlDst = if \(Test-Path 'M:\\etc\\mios'\)") '`mios build` does not promote the saved file into M:\etc\mios'
    Check ($text -match "tomlDst = Join-Path ``\`$env:USERPROFILE '\.config\\mios\\mios\.toml'") '`mios build` promotes the saved file into the user tier'

    Write-Host '== mios-boot-win-04: Defender exclusions'
    $plan = Get-MiosDefenderExclusionPlan
    Check (@($plan.paths) -contains 'C:\MiOS\bin') 'a narrow SSOT path with a reason is planned'
    Check (@($plan.processes) -contains 'C:\MiOS\bin\mios-launch.exe') 'a SSOT process with a reason is planned'
    Check (-not (@($plan.paths) | Where-Object { $_ -ieq $env:TEMP -or $_ -ieq [Environment]::ExpandEnvironmentVariables('%TEMP%') })) '%TEMP% is refused'
    Check (-not (@($plan.paths) | Where-Object { $_ -match '^[A-Za-z]:\\?$' })) 'a whole drive is refused'
    Check (@($plan.refused | Where-Object { $_ -like '*C:\MiOS\cache*no reason*' }).Count -eq 1) 'an entry without a reason is refused'
    $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Add-MiosDefenderExclusions' }, $true)
    Check ($fn -and $fn.Body.Extent.Text -notmatch "Add-MpPreference[^\r\n]*TEMP") 'Add-MiosDefenderExclusions never adds TEMP'
    Check ($fn -and $fn.Body.Extent.Text -notmatch 'defender_exclusions''\s+-Key\s+''paths''\s+-Default') 'no code default for the exclusion list'
    Write-Host '== mios-boot-win-04: WSL VM firewall'
    # the -DefaultInboundAction argument of every Set-NetFirewallHyperVVMSetting call (comments never count)
    $inbound = @()
    foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
            $n.GetCommandName() -eq 'Set-NetFirewallHyperVVMSetting' }, $true)) {
        $els = $c.CommandElements
        for ($i = 0; $i -lt $els.Count; $i++) {
            if ($els[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and $els[$i].ParameterName -eq 'DefaultInboundAction') {
                $inbound += $(if ($els[$i].Argument) { $els[$i].Argument.Extent.Text } elseif ($i + 1 -lt $els.Count) { $els[$i + 1].Extent.Text } else { '' })
            }
        }
    }
    Check ($inbound.Count -gt 0) 'the WSL VM firewall setting is applied'
    Check (-not @($inbound | Where-Object { $_.Trim("'", '"') -ieq 'Allow' }).Count) 'no DefaultInboundAction Allow on the WSL VM firewall'
    Check (@($inbound | Where-Object { $_.Trim("'", '"') -ieq 'Block' }).Count -eq $inbound.Count) 'the WSL VM firewall keeps DefaultInboundAction Block'
    return $script:fail
}

try {
    if (-not $PlantDefect) {
        Write-Host "positive: $realScript"
        $f = Invoke-Checks $realScript
        Write-Host ''
        if ($f) { Write-Host "RESULT: FAIL ($f check(s) failed)"; exit 1 }
        Write-Host 'RESULT: PASS (every positive check holds)'
        exit 0
    }
    $plants = @(
        @{ name = 'raw host-tier write of the operator layer'
           from = "Write-MiosHostToml -Path (Join-Path `$_sysDrive 'etc\mios\mios.toml') -Text `$_miosHostToml"
           to   = "[IO.File]::WriteAllText((Join-Path `$_sysDrive 'etc\mios\mios.toml'), `$_miosHostToml)" },
        @{ name = 'DefaultInboundAction Allow'
           from = '-DefaultInboundAction Block'
           to   = '-DefaultInboundAction Allow' },
        @{ name = 'refusal rule admits %TEMP%'
           from = "if (`$p -ieq `$w -or `$p.StartsWith(`$w + '\', [StringComparison]::OrdinalIgnoreCase)) { return `"a temp directory (`$w)`" }"
           to   = '' }
    )
    $caught = 0
    foreach ($pl in $plants) {
        $src = [IO.File]::ReadAllText($realScript)
        if (-not $src.Contains($pl.from)) { Write-Host "PLANT SETUP ERROR: anchor for '$($pl.name)' not found"; exit 2 }
        $copy = Join-Path $scratch ('planted-' + ($pl.name -replace '[^A-Za-z0-9]', '-') + '.ps1')
        [IO.File]::WriteAllText($copy, $src.Replace($pl.from, $pl.to), (New-Object System.Text.UTF8Encoding($true)))
        Write-Host "negative: planted '$($pl.name)'"
        $f = Invoke-Checks $copy
        if ($f -gt 0) { Write-Host "  -> caught ($f check(s) failed, as expected)"; $caught++ } else { Write-Host '  -> NOT caught' }
    }
    Write-Host ''
    if ($caught -eq $plants.Count) { Write-Host "RESULT: PASS (every planted defect was caught: $caught/$($plants.Count))"; exit 0 }
    Write-Host "RESULT: FAIL (planted defects caught: $caught/$($plants.Count))"; exit 1
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
