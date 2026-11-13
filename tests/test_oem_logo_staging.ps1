# Source-only fixtures: AST-extracted functions, mocked vendor fetches, scratch writes only.
# No entry script runs; registry cmdlets are always shadowed.
[CmdletBinding()]
param([switch]$PlantDefect, [switch]$SkipWindows)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT' -and -not $SkipWindows) { throw 'Use -SkipWindows for portable source fixtures; Windows API and command-parser checks will remain UNRUN.' }
Write-Host 'SOURCE_FIXTURE_UNRUN LIVE_REGISTRY LIVE_ELEVATION LIVE_FETCH OEM_LIVE_ACL_WRITE'
$repoRoot = Split-Path $PSScriptRoot -Parent
$realLib = Join-Path $repoRoot 'field/autounattend/MiOS-Provision.lib.ps1'
$realProvision = Join-Path $repoRoot 'field/autounattend/Invoke-MiOSProvision.ps1'
$realUnattend = Join-Path $repoRoot 'field/autounattend/New-MiOSAutounattend.ps1'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-oem-logo-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -ErrorAction Stop | Out-Null
$script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
$utf8 = New-Object Text.UTF8Encoding($false)
$oemKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation'
$defaultLogo = 'C:\Windows\Web\MiOS\mios-logo.bmp'
$defaultRel = 'usr/share/mios/branding/mios-oem-logo.bmp'
$rawBase = 'https://raw.githubusercontent.com/mios-dev/MiOS'
$apiMain = 'https://api.github.com/repos/mios-dev/MiOS/commits/main'
$shaA = '0123456789abcdef0123456789abcdef01234567'
# Guard runs always target an absent fixture key, so even an unshadowed cmdlet cannot touch OEMInformation.
$script:inProcessKey = 'HKCU:\Software\MiOS-Fixture-' + [guid]::NewGuid().ToString('N')

function Check([bool]$Ok, [string]$What) {
    $script:checks++
    if ($Ok) { Write-Host "  PASS $What" } else { Write-Host "  FAIL $What"; $script:fail++; $script:failedChecks.Add($What) }
}
function Expect-Throw([scriptblock]$Action, [string]$What) {
    $caught = $false
    try { $null = & $Action } catch { $caught = $true }
    Check $caught $What
}
function Import-MiosFunctions([string]$Path, [string[]]$Required, [switch]$OnlyRequired) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Product source does not parse: $($errors[0].Message)" }
    $defs = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] })
    foreach ($name in $Required) { if (@($defs | Where-Object Name -eq $name).Count -ne 1) { throw "Missing/duplicate canonical function $name" } }
    if ($OnlyRequired) { $defs = @($defs | Where-Object { $Required -contains $_.Name }) }
    foreach ($d in $defs) { . ([scriptblock]::Create(($d.Extent.Text -replace '^function\s+', 'function global:'))) }
    return $ast
}
function Get-Hex([byte[]]$Bytes) {
    $stream = New-Object IO.MemoryStream (, $Bytes)
    try { return (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash.ToLowerInvariant() } finally { $stream.Dispose() }
}
function Test-SameBytes([byte[]]$A, [byte[]]$B) {
    return ($null -ne $A -and $null -ne $B -and [Convert]::ToBase64String($A) -ceq [Convert]::ToBase64String($B))
}
function New-FixtureBmp([int]$Width = 8, [int]$Height = 8, [int]$Bpp = 32, [int]$Seed = 1, [int]$Truncate = 0) {
    $len = 54 + $Width * $Height * [int]($Bpp / 8) - $Truncate
    $b = New-Object byte[] $len
    $pixels = New-Object byte[] ($len - 54)
    ([Random]::new($Seed)).NextBytes($pixels)
    [Array]::Copy($pixels, 0, $b, 54, $pixels.Length)
    $b[0] = 0x42; $b[1] = 0x4D
    [BitConverter]::GetBytes([uint32]$len).CopyTo($b, 2)
    [BitConverter]::GetBytes([uint32]54).CopyTo($b, 10)
    [BitConverter]::GetBytes([uint32]40).CopyTo($b, 14)
    [BitConverter]::GetBytes([int32]$Width).CopyTo($b, 18)
    [BitConverter]::GetBytes([int32]$Height).CopyTo($b, 22)
    [BitConverter]::GetBytes([uint16]1).CopyTo($b, 26)
    [BitConverter]::GetBytes([uint16]$Bpp).CopyTo($b, 28)
    [BitConverter]::GetBytes([uint32]0).CopyTo($b, 30)
    [BitConverter]::GetBytes([uint32]($len - 54)).CopyTo($b, 34)
    return ,$b
}
function New-Sidecar([byte[]]$Bmp, [hashtable]$Over = @{}) {
    $s = [ordered]@{ background = '#282262'; background_key = 'colors.bg'; file = 'mios-oem-logo.bmp'; px = [BitConverter]::ToInt32($Bmp, 18)
        schema = 'mios-oem-logo/1'; sha256 = (Get-Hex $Bmp); size = $Bmp.Length; source = 'usr/share/mios/portal/icon-512.png'; source_sha256 = ('5' * 64) }
    foreach ($k in $Over.Keys) { $s[$k] = $Over[$k] }
    $bytes = $utf8.GetBytes(($s | ConvertTo-Json) + "`n")
    return ,$bytes
}
function New-VendorToml([hashtable]$Over = @{}) {
    $v = @{ projection = $defaultRel; bgref = 'colors.bg'; bg = '#282262'; root = 'Windows'; logo = $defaultLogo; logoRef = 'branding.oem_logo' }
    foreach ($k in $Over.Keys) { $v[$k] = $Over[$k] }
    $text = @"
# Synthesized vendor SSOT: only the MiOS shapes this staging reads.
[colors]
bg          = "$($v.bg)"   # deep indigo
accent      = "#1A407F"

[branding]
oem_logo            = '$($v.logo)'

[units."mios-firewall-ports.service".Service]
ExecStart = '''/bin/bash -c '\
    exit 0\''''

[autounattend]
accounts = [ { name = "fixture" } ]

[windows.xbox.identity]
system_root           = '$($v.root)'
background_color_ref  = "$($v.bgref)"
oem_logo_ref          = "$($v.logoRef)"
oem_logo_projection   = "$($v.projection)"
"@
    $bytes = $utf8.GetBytes($text)
    return ,$bytes
}
function Set-Tree([byte[]]$Bmp = $script:bmpA, [byte[]]$Sidecar = $null, [byte[]]$Vendor = $null, [string]$ApiBody = $shaA) {
    if ($null -eq $Sidecar) { $Sidecar = New-Sidecar $Bmp }
    if ($null -eq $Vendor) { $Vendor = New-VendorToml }
    $t = @{}
    $t[$apiMain] = [Text.Encoding]::ASCII.GetBytes($ApiBody)
    $t["$rawBase/$shaA/usr/share/mios/mios.toml"] = $Vendor
    $t["$rawBase/$shaA/$defaultRel"] = $Bmp
    $t["$rawBase/$shaA/$defaultRel.json"] = $Sidecar
    # main has moved on since resolution: a different, self-consistent logo only the mutable ref serves.
    $t["$rawBase/main/usr/share/mios/mios.toml"] = New-VendorToml
    $t["$rawBase/main/$defaultRel"] = $script:bmpMain
    $t["$rawBase/main/$defaultRel.json"] = New-Sidecar $script:bmpMain
    $script:tree = $t; $script:failUri = ''
    $script:fetchLog.Clear(); $script:headerLog.Clear()
}
function New-View([hashtable]$Scalars = @{}) {
    $v = New-MiosTomlView
    $base = @{ 'branding.oem_logo' = $defaultLogo; 'colors.bg' = '#282262'; 'bootstrap.mios_repo' = 'https://github.com/mios-dev/MiOS.git'; 'bootstrap.mios_ref' = 'main' }
    foreach ($k in $base.Keys) { $v.scalars[$k] = $base[$k] }
    foreach ($k in $Scalars.Keys) { $v.scalars[$k] = $Scalars[$k] }
    return $v
}
function New-ReceiptFixture($View) {
    # Model the process-private receipt using scratch bytes. No product entrypoint or live destination is used.
    $file = Join-Path $scratch ('receipt-' + [guid]::NewGuid().ToString('N') + '.bmp')
    [IO.File]::WriteAllBytes($file, $script:bmpA)
    $e = [pscustomobject]@{ Path = $defaultLogo.ToUpperInvariant(); Sha256 = (Get-Hex $script:bmpA); Commit = $shaA; Size = $script:bmpA.Length }
    $script:MiOSOemLogoReceipt = @{ Evidence = $e; Path = $e.Path; FilePath = $file; Fixture = $false; Sha256 = $e.Sha256; Commit = $e.Commit; Size = $e.Size;
        BackgroundKey = 'colors.bg'; Vendor = (ConvertFrom-MiosTomlFile -ContentBytes (New-VendorToml) -ProjectedCredentials);
        Binding = (Get-MiOSOemLogoBinding -Toml $View -BackgroundKey 'colors.bg') }
    return $e
}
function Invoke-AclFixture($Acl, [switch]$VolumeRoot) {
    # Exercise the real ACL policy with an in-memory descriptor; never read or write a host ACL.
    function Get-Acl { [CmdletBinding()] param($LiteralPath) return $Acl }
    try { Assert-MiOSOemLogoAcl -Path 'C:\fixture' -VolumeRoot:$VolumeRoot; return '' } catch { return $_.Exception.Message }
}
function New-AclFixture([string]$Owner = 'S-1-5-32-544', $Rights = ([Security.AccessControl.FileSystemRights]::ReadAndExecute), [switch]$InheritOnly) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($Owner))
    $inheritance = [Security.AccessControl.InheritanceFlags]::None; $propagation = [Security.AccessControl.PropagationFlags]::None
    if ($InheritOnly) { $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit; $propagation = [Security.AccessControl.PropagationFlags]::InheritOnly }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), $Rights, $inheritance, $propagation, [Security.AccessControl.AccessControlType]::Allow))
    return $acl
}
function Invoke-Stage([string]$Case, $View, [string]$Commit, [switch]$Existing) {
    $dir = Join-Path $scratch ('stage-' + $Case + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
    $dest = Join-Path $dir 'mios-logo.bmp'
    if ($Existing) { [IO.File]::WriteAllBytes($dest, $script:oldBytes) }
    $params = @{ Toml = $View; Fetch = $script:fetch; DestinationPath = $dest }
    if ($Commit) { $params.Commit = $Commit }
    $w = $null
    $r = Install-MiOSOemLogo @params -WarningVariable w -WarningAction SilentlyContinue
    $bytes = $null
    if ([IO.File]::Exists($dest)) { $bytes = [IO.File]::ReadAllBytes($dest) }
    return @{ Result = $r; Dest = $dest; Warning = (@($w) -join ' | '); Files = @(Get-ChildItem -LiteralPath $dir -Force | ForEach-Object { $_.Name }); Bytes = $bytes }
}
function Check-Refused([string]$What, $Out, [string]$Token, [switch]$Existing) {
    $ok = $null -eq $Out.Result -and $Out.Warning.Contains('MiOS OEM logo not staged: ') -and $Out.Warning.Contains($Token)
    if ($Existing) { $ok = $ok -and @($Out.Files).Count -eq 1 -and (Test-SameBytes $Out.Bytes $script:oldBytes) }
    else { $ok = $ok -and @($Out.Files).Count -eq 0 }
    if (-not $ok) { Write-Host "    (result=$($null -ne $Out.Result) files=$(@($Out.Files) -join ',') warning=$($Out.Warning))" }
    Check $ok $What
}
function Get-GuardScript([string]$Command) {
    $m = [regex]::Match($Command, '^powershell\.exe -NoProfile -Command "(?<s>[^"]*)"$')
    if (-not $m.Success) { return $null }
    return $m.Groups['s'].Value
}
function Invoke-GuardInProcess([string]$Command, $Value, [bool]$FileExists) {
    $text = Get-GuardScript $Command
    if ($null -eq $text -or -not $text.Contains($oemKey)) { return 'unparsed' }
    $text = $text.Replace($oemKey, $script:inProcessKey)
    # Local shadows: visible to the guard's child scope only, gone when this function returns.
    $state = @{ Value = $Value; Exists = $FileExists; Removed = @() }
    function Get-ItemProperty { [CmdletBinding()] param([string]$LiteralPath, [string]$Name) if ($null -ne $state.Value) { [pscustomobject]@{ Logo = $state.Value } } }
    function Test-Path { [CmdletBinding()] param([string]$LiteralPath, $PathType) return $state.Exists }
    function Remove-ItemProperty { [CmdletBinding()] param([string]$LiteralPath, [string]$Name) $state.Removed += ($LiteralPath + '|' + $Name) }
    & ([scriptblock]::Create($text))
    return ($state.Removed -join ',')
}
function New-GuardProbe([string]$Command, [string]$Value, [string]$Marker, [string]$FixtureKey) {
    # Shadows the registry cmdlets inside the child and points the key at an absent fixture key.
    $value64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Value))
    $marker64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Marker))
    $prelude = 'function Get-ItemProperty { [CmdletBinding()] param($LiteralPath, $Name) [pscustomobject]@{ Logo = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(''' + $value64 + ''')) } }; ' +
        'function Test-Path { [CmdletBinding()] param($LiteralPath, $PathType) $false }; ' +
        'function Remove-ItemProperty { [CmdletBinding()] param($LiteralPath, $Name) [IO.File]::WriteAllText([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(''' + $marker64 + ''')), $LiteralPath + ''|'' + $Name) }; '
    if (([regex]::Matches($Command, [regex]::Escape('-Command "'))).Count -ne 1 -or -not $Command.Contains($oemKey)) { return $null }
    return $Command.Replace('-Command "', '-Command "' + $prelude).Replace($oemKey, $FixtureKey)
}

function Invoke-Checks([string]$LibPath, [string]$ProvisionPath, [switch]$SkipNative, [switch]$SkipWindows) {
    if ($SkipWindows) { $SkipNative = $true }
    $script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
    $libAst = Import-MiosFunctions $LibPath @('Find-MiosTomlMultilineEnd', 'ConvertFrom-MiosTomlFile', 'Get-MiOSVendorBytes', 'Invoke-MiOSVendorFetch',
        'Get-MiOSVendorSource', 'Resolve-MiOSVendorCommit', 'Get-MiOSOemLogoTargetGap', 'Assert-MiOSOemLogoBitmap', 'Install-MiOSOemLogo',
        'Get-MiOSOemLogoSystemRoot', 'Assert-MiOSOemLogoAcl', 'Assert-MiOSOemLogoWritePath', 'Set-MiOSOemLogoStreamAcl',
        'Get-MiOSOemLogoBinding', 'Test-MiOSOemLogoEvidence', 'New-MiOSOemLogoCommands', 'New-MiOSBrandingCommands', 'New-MiOSProvisionCommands', 'Invoke-MiOSHostCommands')
    $null = Import-MiosFunctions $realUnattend @('ConvertTo-UnattendPassword', 'New-MiOSAutounattendXml') -OnlyRequired
    # The spec-driven preference group is out of scope here and needs keys this fixture does not carry.
    function global:New-MiOSGlobalPrefCommands { param($Toml) return @() }
    $script:fetchLog = New-Object System.Collections.Generic.List[string]
    $script:headerLog = New-Object System.Collections.Generic.List[string]
    $script:fetch = {
        param([string]$Uri, [hashtable]$Headers)
        $script:fetchLog.Add($Uri)
        $script:headerLog.Add((@($Headers.Keys | Sort-Object | ForEach-Object { $_ + '=' + $Headers[$_] }) -join ';'))
        if ($script:failUri -and $Uri -ceq $script:failUri) { throw 'fixture network failure' }
        if (-not $script:tree.ContainsKey($Uri)) { throw "fixture 404: $Uri" }
        $bytes = $script:tree[$Uri]
        return ,$bytes
    }
    $script:bmpA = New-FixtureBmp -Seed 11
    $script:bmpMain = New-FixtureBmp -Seed 99
    $script:oldBytes = $utf8.GetBytes('fixture-old-logo')
    $script:MiOSOemLogoReceipt = $null

    # --- The lib's own TOML reader must read the vendor grammar it is handed -------
    $readerPath = Join-Path $scratch 'reader.toml'
    [IO.File]::WriteAllText($readerPath, ("[s]`nk = '''a`n  b\''''`nm = '''x''''`nq = 1`n"), $utf8)
    $reader = $null
    try { $reader = ConvertFrom-MiosTomlFile -Path $readerPath } catch { Write-Host "    (reader: $($_.Exception.Message))" }
    Check ($null -ne $reader -and $reader.scalars['s.k'] -ceq ('a' + [Environment]::NewLine + "  b\'") -and $reader.scalars['s.m'] -ceq "x'" -and $reader.scalars['s.q'] -ceq '1') 'reader accepts quotes before a closing triple quote'
    $bomBytes = [byte[]](@(0xEF, 0xBB, 0xBF) + [IO.File]::ReadAllBytes($readerPath))
    $fromBytes = ConvertFrom-MiosTomlFile -ContentBytes $bomBytes
    Check ($fromBytes.scalars['s.k'] -ceq $reader.scalars['s.k'] -and $fromBytes.scalars['s.m'] -ceq $reader.scalars['s.m']) 'byte input with a UTF-8 BOM uses the same multiline scanner as file input'
    Expect-Throw { ConvertFrom-MiosTomlFile -ContentBytes ([byte[]](0xFF, 0xFE, 0x61)) } 'byte input refuses invalid UTF-8'
    [IO.File]::WriteAllText($readerPath, "[s]`nbad = '''x''''''`n", $utf8)
    Expect-Throw { ConvertFrom-MiosTomlFile -Path $readerPath } 'reader still refuses a six-quote closing run'

    # --- Commit resolution ------------------------------------------------------------
    Set-Tree
    $sha = $null
    try { $sha = Resolve-MiOSVendorCommit -Toml (New-View) -Fetch $script:fetch } catch { Write-Host "    (resolve: $($_.Exception.Message))" }
    Check ($sha -ceq $shaA -and $script:fetchLog.Count -eq 1 -and $script:fetchLog[0] -ceq $apiMain -and $script:headerLog[0] -ceq 'Accept=application/vnd.github.sha') 'main resolves once through the commits API with the sha media type'
    $script:tree['https://api.github.com/repos/fixture-org/MiOS-fork/commits/release/v1'] = [Text.Encoding]::ASCII.GetBytes($shaA + "`n")
    $fork = New-View @{ 'bootstrap.mios_repo' = 'https://github.com/fixture-org/MiOS-fork.git'; 'bootstrap.mios_ref' = 'release/v1' }
    $forkSource = Get-MiOSVendorSource -Toml $fork
    $forkSha = $null
    try { $forkSha = Resolve-MiOSVendorCommit -Toml $fork -Fetch $script:fetch } catch { Write-Host "    (fork: $($_.Exception.Message))" }
    Check ($forkSha -ceq $shaA -and $forkSource.Raw -ceq 'https://raw.githubusercontent.com/fixture-org/MiOS-fork') 'vendor repo and ref come from [bootstrap].mios_repo and mios_ref'
    Set-Tree -ApiBody 'not-a-sha'
    Expect-Throw { Resolve-MiOSVendorCommit -Toml (New-View) -Fetch $script:fetch } 'a non-hex commit body throws'
    Set-Tree -ApiBody ($shaA.ToUpperInvariant())
    Expect-Throw { Resolve-MiOSVendorCommit -Toml (New-View) -Fetch $script:fetch } 'an upper-case or abbreviated commit body throws'
    Expect-Throw { Resolve-MiOSVendorCommit -Toml (New-View @{ 'bootstrap.mios_ref' = 'main/../x' }) -Fetch $script:fetch } 'a ref with .. is refused before any fetch'
    Expect-Throw { Resolve-MiOSVendorCommit -Toml (New-View @{ 'bootstrap.mios_repo' = 'https://example.invalid/mios-dev/MiOS.git' }) -Fetch $script:fetch } 'a non-github vendor repository is refused'

    # --- Staging: positive cases --------------------------------------------------------
    $vendorTempBefore = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Filter 'mios-vendor-*.toml' -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    Set-Tree
    $out = Invoke-Stage 'happy' (New-View)
    $e = $out.Result
    Check ($null -ne $e -and $e.Commit -ceq $shaA -and $e.Sha256 -ceq (Get-Hex $script:bmpA) -and $e.Size -eq $script:bmpA.Length -and
           $e.Path -ceq $out.Dest -and (Test-SameBytes $out.Bytes $script:bmpA)) 'happy path stages the exact vendor bytes and returns evidence bound to the resolved commit'
    Check ([object]::ReferenceEquals($script:MiOSOemLogoReceipt.Evidence, $e) -and $script:MiOSOemLogoReceipt.Path -ceq $out.Dest) 'staging registers only the actual destination evidence in the current process'
    $fixtureCommands = @(New-MiOSOemLogoCommands -Toml (New-View) -OemLogo $e)
    Check (@($fixtureCommands | Where-Object { $_ -match '/v Logo ' }).Count -eq 0) 'a scratch destination receipt cannot authorize a Logo at the configured live path'
    Check (@($out.Files).Count -eq 1 -and $out.Files[0] -ceq 'mios-logo.bmp' -and $out.Warning -eq '') 'staging leaves only the logo, with no warning'
    $api = @($script:fetchLog | Where-Object { $_.StartsWith('https://api.github.com/') })
    $raw = @($script:fetchLog | Where-Object { $_.StartsWith('https://raw.githubusercontent.com/') })
    Check ($api.Count -eq 1 -and $api[0] -ceq $apiMain -and $raw.Count -eq 3 -and @($raw | Where-Object { $_.StartsWith("$rawBase/$shaA/") }).Count -eq 3 -and
           @($script:fetchLog | Where-Object { $_.Contains('/main/') }).Count -eq 0) 'every vendor fetch is pinned to the resolved commit'
    Check ($raw.Count -eq 3 -and $raw[0] -ceq "$rawBase/$shaA/usr/share/mios/mios.toml" -and $raw[1] -ceq "$rawBase/$shaA/$defaultRel" -and $raw[2] -ceq "$rawBase/$shaA/$defaultRel.json") 'TOML, bitmap and sidecar are all fetched at that one commit'
    Set-Tree
    $out = Invoke-Stage 'replace' (New-View) -Existing
    Check ($null -ne $out.Result -and @($out.Files).Count -eq 1 -and (Test-SameBytes $out.Bytes $script:bmpA)) 'an existing logo is replaced by the verified bytes'
    Set-Tree
    $out = Invoke-Stage 'pinned' (New-View) -Commit $shaA
    Check ($null -ne $out.Result -and $out.Result.Commit -ceq $shaA -and @($script:fetchLog | Where-Object { $_.StartsWith('https://api.github.com/') }).Count -eq 0 -and
           @($script:fetchLog | Where-Object { $_.StartsWith("$rawBase/$shaA/") }).Count -eq 3) 'an explicit commit skips resolution and stays pinned'
    $big = New-FixtureBmp -Width 120 -Height 120 -Seed 5
    Set-Tree -Bmp $big
    $out = Invoke-Stage 'px120' (New-View)
    Check ($null -ne $out.Result -and (Test-SameBytes $out.Bytes $big)) 'a 120 px logo is accepted'
    Set-Tree
    $w = $null
    $disabled = Install-MiOSOemLogo -Toml (New-View @{ 'branding.windows.enable' = 'false' }) -Fetch $script:fetch -DestinationPath (Join-Path $scratch 'disabled.bmp') -WarningVariable w -WarningAction SilentlyContinue
    Check ($null -eq $disabled -and $script:fetchLog.Count -eq 0 -and -not (Test-Path -LiteralPath (Join-Path $scratch 'disabled.bmp')) -and @($w).Count -eq 0) 'disabled Windows branding stages nothing and fetches nothing'

    # A non-default declared system root is respected; the image drive remains C: like the renderer.
    Set-Tree -Vendor (New-VendorToml @{ root = 'WinNT'; logo = 'C:\WinNT\Web\MiOS\mios-logo.bmp' })
    $out = Invoke-Stage 'custom-root' (New-View @{ 'branding.oem_logo' = 'C:\WinNT\Web\MiOS\mios-logo.bmp'; 'windows.xbox.identity.system_root' = 'WinNT' })
    Check ($null -ne $out.Result -and (Test-SameBytes $out.Bytes $script:bmpA)) 'staging accepts the declared effective and vendor system root'
    Set-Tree -Vendor (New-VendorToml @{ root = 'WinNT'; logo = 'C:\WinNT\Web\MiOS\mios-logo.bmp' })
    $out = Invoke-Stage 'vendor-root' (New-View @{ 'branding.oem_logo' = 'C:\WinNT\Web\MiOS\mios-logo.bmp' })
    Check ($null -ne $out.Result) 'a missing effective system_root uses the pinned vendor declaration'
    Set-Tree -Vendor (New-VendorToml @{ root = 'WinNT' })
    Check-Refused 'refuses a target under the wrong vendor system root' (Invoke-Stage 'wrong-root' (New-View)) 'declared system_root'
    Set-Tree -Vendor (New-VendorToml @{ logoRef = 'branding.other_logo' })
    Check-Refused 'refuses a vendor branding ref outside branding.oem_logo' (Invoke-Stage 'logo-ref' (New-View)) 'oem_logo_ref'
    Set-Tree
    Check-Refused 'refuses an effective branding ref different from the vendor binding' (Invoke-Stage 'host-logo-ref' (New-View @{ 'windows.xbox.identity.oem_logo_ref' = 'branding.other_logo' })) 'effective oem_logo_ref'
    Set-Tree
    Check-Refused 'refuses an effective background ref different from the vendor binding' (Invoke-Stage 'host-bg-ref' (New-View @{ 'windows.xbox.identity.background_color_ref' = 'colors.accent' })) 'effective background_color_ref'

    # --- Staging: refusals (each returns $null, writes nothing, names the gap) ----------
    Set-Tree -Sidecar (New-Sidecar $script:bmpA @{ sha256 = (Get-Hex $script:bmpMain) })
    Check-Refused 'refuses a sidecar sha256 that does not match the bitmap' (Invoke-Stage 'sha' (New-View)) 'sidecar sha256'
    Set-Tree -Sidecar (New-Sidecar $script:bmpA @{ sha256 = (Get-Hex $script:bmpMain) })
    Check-Refused 'a refusal leaves an existing logo byte-identical' (Invoke-Stage 'sha-existing' (New-View) -Existing) 'sidecar sha256' -Existing
    Set-Tree -Sidecar (New-Sidecar $script:bmpA @{ size = $script:bmpA.Length + 1 })
    Check-Refused 'refuses a sidecar size that does not match the bitmap' (Invoke-Stage 'size' (New-View)) 'sidecar size'
    Set-Tree -Sidecar (New-Sidecar $script:bmpA @{ schema = 'mios-oem-logo/2' })
    Check-Refused 'refuses a wrong sidecar schema' (Invoke-Stage 'schema' (New-View)) 'sidecar schema'
    Set-Tree -Sidecar (New-Sidecar $script:bmpA @{ file = 'other-logo.bmp' })
    Check-Refused 'refuses a sidecar naming a different leaf' (Invoke-Stage 'leaf' (New-View)) 'projection leaf'
    $b24 = New-FixtureBmp -Bpp 24 -Seed 3
    Set-Tree -Bmp $b24
    Check-Refused 'refuses a non-32bpp bitmap' (Invoke-Stage 'bpp' (New-View)) '32 bits per pixel'
    $b89 = New-FixtureBmp -Width 8 -Height 9 -Seed 4
    Set-Tree -Bmp $b89
    Check-Refused 'refuses a non-square bitmap' (Invoke-Stage 'square' (New-View)) 'not square'
    $b121 = New-FixtureBmp -Width 121 -Height 121 -Seed 6
    Set-Tree -Bmp $b121
    Check-Refused 'refuses a bitmap over 120 px' (Invoke-Stage 'px121' (New-View)) 'outside 1..120'
    $bTrunc = New-FixtureBmp -Seed 7 -Truncate 16
    Set-Tree -Bmp $bTrunc
    Check-Refused 'refuses a truncated bitmap' (Invoke-Stage 'truncated' (New-View)) 'pixel data length'
    Set-Tree -Sidecar (New-Sidecar $script:bmpA @{ background_key = 'colors.accent' })
    Check-Refused 'refuses a sidecar background_key that is not the vendor background_color_ref' (Invoke-Stage 'bgkey' (New-View)) 'background_key'
    Set-Tree -Vendor (New-VendorToml @{ bg = '#101010' })
    Check-Refused 'refuses a sidecar background that differs from the vendor colour' (Invoke-Stage 'vendorbg' (New-View)) "sidecar background '#282262' is not vendor colors.bg"
    Set-Tree
    Check-Refused 'refuses an operator colour override' (Invoke-Stage 'override' (New-View @{ 'colors.bg' = '#112233' })) 'overrides vendor'
    Set-Tree
    Check-Refused 'names a missing effective required colour instead of claiming an override' (Invoke-Stage 'missing-host-bg' (New-View @{ 'colors.bg' = '' })) "effective required colour 'colors.bg' is missing"
    Set-Tree -Vendor (New-VendorToml @{ bg = '' })
    Check-Refused 'names a missing vendor required colour' (Invoke-Stage 'missing-vendor-bg' (New-View)) "vendor required colour 'colors.bg' is missing"
    foreach ($case in @(@{ Path = 'D:\Logos\mios-logo.bmp'; Name = 'refuses a target outside the C: image drive'; Token = 'system_root' },
                        @{ Path = 'C:\Windows\Web\..\mios-logo.bmp'; Name = 'refuses a target with a .. segment'; Token = "'..' segment" },
                        @{ Path = 'C:\Windows\Web\MiOS\mios-logo.png'; Name = 'refuses a non-.bmp target'; Token = 'declared system_root' },
                        @{ Path = 'C:\Windows\mios-logo.bmp'; Name = 'refuses a target without a folder under system_root'; Token = 'declared system_root' },
                        @{ Path = 'C:\Windows\Web\%MIOS%\mios-logo.bmp'; Name = 'refuses a target cmd would expand'; Token = 'cannot carry' },
                        @{ Path = 'C:\Windows\Web.\MiOS\mios-logo.bmp'; Name = 'refuses a trailing-dot alias'; Token = 'Windows-aliased' },
                        @{ Path = 'C:\Windows\Web\NUL.bmp'; Name = 'refuses a Windows device alias'; Token = 'Windows-aliased' })) {
        Set-Tree
        $out = Invoke-Stage 'target' (New-View @{ 'branding.oem_logo' = $case.Path })
        Check-Refused $case.Name $out $case.Token
        if ($case.Name -eq 'refuses a target outside the C: image drive') { Check ($script:fetchLog.Count -eq 0) 'a bad target is refused before any network fetch' }
    }
    Set-Tree -ApiBody 'not-a-sha'
    Check-Refused 'refuses a commit that does not resolve to 40 hex' (Invoke-Stage 'unresolved' (New-View)) '40-hex commit'
    Set-Tree
    Check-Refused 'refuses an explicit non-hex commit' (Invoke-Stage 'commit-main' (New-View) -Commit 'main') 'not a concrete 40-hex sha'
    Set-Tree; $script:failUri = "$rawBase/$shaA/$defaultRel.json"
    Check-Refused 'refuses when a vendor fetch fails' (Invoke-Stage 'fetch' (New-View)) 'fetch failed'
    Set-Tree -Vendor (New-VendorToml @{ projection = '../escape/mios-oem-logo.bmp' })
    Check-Refused 'refuses a projection path that leaves the tree' (Invoke-Stage 'projection' (New-View)) 'tree-relative'
    $vendorTempAfter = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Filter 'mios-vendor-*.toml' -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    Check (@($vendorTempAfter | Where-Object { $vendorTempBefore -notcontains $_ }).Count -eq 0) 'staging leaves no vendor TOML temporary file behind'

    # --- Actual scratch reparse boundary, plus in-memory Windows ACL policy -----------
    Set-Tree
    $realDirectory = Join-Path $scratch ('real-' + [guid]::NewGuid().ToString('N'))
    $linkDirectory = Join-Path $scratch ('linked-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $realDirectory -ErrorAction Stop | Out-Null
    $linkType = if ($env:OS -eq 'Windows_NT') { 'Junction' } else { 'SymbolicLink' }
    New-Item -ItemType $linkType -Path $linkDirectory -Target $realDirectory -ErrorAction Stop | Out-Null
    $w = $null
    $linked = Install-MiOSOemLogo -Toml (New-View) -Fetch $script:fetch -DestinationPath (Join-Path $linkDirectory 'mios-logo.bmp') -WarningVariable w -WarningAction SilentlyContinue
    Check ($null -eq $linked -and (@($w) -join ' ').Contains('link or not a directory') -and @(Get-ChildItem -LiteralPath $realDirectory -Force).Count -eq 0) 'staging refuses a reparse-point ancestor without writing through it'
    if (-not $SkipWindows) {
        Check ((Invoke-AclFixture (New-AclFixture)) -ceq '') 'the ACL policy permits system-owned paths with Users read access'
        Check ((Invoke-AclFixture (New-AclFixture -Owner 'S-1-5-32-545')).Contains('untrusted owner')) 'the ACL policy refuses a Users-owned destination'
        Check ((Invoke-AclFixture (New-AclFixture -Rights ([Security.AccessControl.FileSystemRights]::Modify))).Contains('write access')) 'the ACL policy refuses a destination writable by Users'
        Check ((Invoke-AclFixture (New-AclFixture -Rights ([Security.AccessControl.FileSystemRights]::Write) -InheritOnly)) -ceq '') 'an inherit-only ACE does not falsely describe current directory write access'
        Check ((Invoke-AclFixture (New-AclFixture -Rights ([Security.AccessControl.FileSystemRights]::AppendData)) -VolumeRoot) -ceq '') 'the volume-root policy permits creating sibling directories'
        Check ((Invoke-AclFixture (New-AclFixture -Rights ([Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles)) -VolumeRoot).Contains('write access')) 'the volume-root policy refuses deleting existing children'
    } else { Write-Host 'SOURCE_FIXTURE_UNRUN WINDOWS_ACL_API 6' }
    $stageAst = @($libAst.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Install-MiOSOemLogo' }, $true))[0]
    $stageText = $stageAst.Extent.Text
    Check ($stageText.Contains('ConvertFrom-MiosTomlFile -ContentBytes $vendorBytes -ProjectedCredentials') -and -not $stageText.Contains('mios-vendor-')) 'vendor parsing consumes fetched bytes without a shared temporary path'
    $writeCalls = @($stageAst.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Assert-MiOSOemLogoWritePath' }, $true))
    Check ($writeCalls.Count -eq 2 -and $writeCalls[0].Extent.StartOffset -lt $stageText.IndexOf('[IO.FileStream]::new') + $stageAst.Extent.StartOffset) 'staging checks its write boundary before temp creation and again before commit'
    $aclCall = $stageText.IndexOf('Set-MiOSOemLogoStreamAcl -Stream $stream'); $writeCall = $stageText.IndexOf('$stream.Write($bmp')
    Check ($aclCall -ge 0 -and $aclCall -lt $writeCall) 'live staging protects the temp handle ACL before writing bytes'

    # --- Branding emits Logo only from evidence; otherwise the guarded removal ---------
    $view = New-View
    $evidence = New-ReceiptFixture $view
    $logoLine = 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Logo /t REG_SZ /d "' + $defaultLogo + '" /f'
    $with = @(New-MiOSBrandingCommands -Toml $view -OemLogo $evidence)
    Check (@($with | Where-Object { $_ -match '/v Logo ' }).Count -eq 1 -and $with -ccontains $logoLine -and @($with | Where-Object { $_.Contains('Remove-ItemProperty') }).Count -eq 0) 'branding emits the Logo value from matching staging evidence'
    $bake = @(New-MiOSBrandingCommands -Toml $view)
    Check (@($bake | Where-Object { $_ -match '/v Logo ' }).Count -eq 0) 'bake-style branding (no evidence) emits no Logo value'
    $guards = @($bake | Where-Object { $_.Contains('Remove-ItemProperty') })
    Check ($guards.Count -eq 1 -and $guards[0].StartsWith('powershell.exe -NoProfile -Command "') -and $guards[0].Contains([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($defaultLogo))) -and
           $null -ne (Get-GuardScript $guards[0])) 'bake-style branding emits the guarded owned-value removal'
    $others = @($bake | Where-Object { $_ -match 'OEMInformation" /v (Manufacturer|Model|SupportURL|SupportHours) ' })
    Check ($others.Count -eq 4 -and @($with | Where-Object { $_ -match 'OEMInformation" /v (Manufacturer|Model|SupportURL|SupportHours) ' }).Count -eq 4) 'the other OEMInformation values are emitted unchanged'
    $foreign = [pscustomobject]@{ Path = (Join-Path $scratch 'stage\mios-logo.bmp'); Sha256 = $evidence.Sha256; Commit = $shaA; Size = 1 }
    $r = @(New-MiOSBrandingCommands -Toml $view -OemLogo $foreign)
    Check (@($r | Where-Object { $_ -match '/v Logo ' }).Count -eq 0 -and @($r | Where-Object { $_.Contains('Remove-ItemProperty') }).Count -eq 1) 'branding ignores evidence for a different path'
    $r = @(New-MiOSBrandingCommands -Toml $view -OemLogo ([pscustomobject]@{ Path = $defaultLogo; Sha256 = 'XYZ'; Commit = $shaA }))
    Check (@($r | Where-Object { $_ -match '/v Logo ' }).Count -eq 0) 'branding ignores evidence without a 64-hex sha256'
    $r = @(New-MiOSBrandingCommands -Toml $view -OemLogo ([pscustomobject]@{ Path = $defaultLogo; Sha256 = $evidence.Sha256; Commit = 'main' }))
    Check (@($r | Where-Object { $_ -match '/v Logo ' }).Count -eq 0) 'branding ignores evidence not bound to a concrete commit'
    $uncarriable = 'C:\Windows\Web\%X%\a"!&.bmp'
    $all = @(New-MiOSBrandingCommands -Toml (New-View @{ 'branding.oem_logo' = $uncarriable }) -OemLogo $evidence)
    $unsafeGuards = @($all | Where-Object { $_.Contains('Remove-ItemProperty') })
    Check (@($all | Where-Object { $_ -match '/v Logo ' }).Count -eq 0 -and $unsafeGuards.Count -eq 1 -and
        (Invoke-GuardInProcess $unsafeGuards[0] $uncarriable $true) -ceq ($script:inProcessKey + '|Logo')) 'a path unsafe for registry-add still receives safe owned-value cleanup'
    $groups = @(New-MiOSProvisionCommands -Toml $view -OemLogo $evidence)
    $brand = @(@($groups | Where-Object { $_.Description -like 'MiOS global branding*' })[0].Commands)
    Check ($brand -ccontains $logoLine) 'New-MiOSProvisionCommands threads staging evidence to branding'
    $groups = @(New-MiOSProvisionCommands -Toml $view)
    $brand = @(@($groups | Where-Object { $_.Description -like 'MiOS global branding*' })[0].Commands)
    Check (@($brand | Where-Object { $_ -match '/v Logo ' }).Count -eq 0 -and @($brand | Where-Object { $_.Contains('Remove-ItemProperty') }).Count -eq 1) 'New-MiOSProvisionCommands without evidence keeps the bake shape'

    # --- Current-process evidence: forged, mutated, stale, or no-longer-matching receipts are refused ---
    $copy = $evidence | ConvertTo-Json | ConvertFrom-Json
    Check (-not (Test-MiOSOemLogoEvidence -Toml $view -OemLogo $copy)) 'serialized evidence cannot replay the private staging receipt'
    Check (-not (Test-MiOSOemLogoEvidence -Toml (New-View @{ 'colors.bg' = '#112233' }) -OemLogo $evidence)) 'a receipt is invalid after an effective colour change'
    Check (-not (Test-MiOSOemLogoEvidence -Toml (New-View @{ 'windows.xbox.identity.system_root' = 'WinNT' }) -OemLogo $evidence)) 'a receipt is invalid after a system root change'
    Check (-not (Test-MiOSOemLogoEvidence -Toml (New-View @{ 'bootstrap.mios_ref' = 'other' }) -OemLogo $evidence)) 'a receipt is invalid after a vendor ref change'
    Check (-not (Test-MiOSOemLogoEvidence -Toml (New-View @{ 'windows.xbox.identity.background_color_ref' = 'colors.accent' }) -OemLogo $evidence)) 'a receipt is invalid after a colour ref change'
    $evidence.Sha256 = ('f' * 64)
    Check (-not (Test-MiOSOemLogoEvidence -Toml $view -OemLogo $evidence)) 'a receipt rejects a mutated but syntactically valid hash'
    $evidence = New-ReceiptFixture $view
    [IO.File]::WriteAllBytes($script:MiOSOemLogoReceipt.FilePath, $script:bmpMain)
    Check (-not (Test-MiOSOemLogoEvidence -Toml $view -OemLogo $evidence)) 'a receipt is invalid if the staged bytes change'
    $evidence = New-ReceiptFixture $view
    $disabledCommands = @(New-MiOSBrandingCommands -Toml (New-View @{ 'branding.windows.enable' = 'false' }) -OemLogo $evidence)
    Check ($disabledCommands.Count -eq 1 -and $disabledCommands[0].Contains('Remove-ItemProperty')) 'disabled Windows branding still cleans only the configured owned Logo value'
    $null = Install-MiOSOemLogo -Toml (New-View @{ 'branding.windows.enable' = 'false' }) -Fetch $script:fetch -DestinationPath (Join-Path $scratch 'disabled-again.bmp')
    Check (-not (Test-MiOSOemLogoEvidence -Toml $view -OemLogo $evidence)) 'a disabled staging attempt invalidates the previous receipt'
    $evidence = New-ReceiptFixture $view
    Set-Tree -Sidecar (New-Sidecar $script:bmpA @{ sha256 = (Get-Hex $script:bmpMain) })
    $failedStage = Invoke-Stage 'stale-existing' $view -Existing
    $staleCommands = @(New-MiOSBrandingCommands -Toml $view -OemLogo $evidence)
    Check ($null -eq $failedStage.Result -and (Test-SameBytes $failedStage.Bytes $script:oldBytes) -and
        @($staleCommands | Where-Object { $_ -match '/v Logo ' }).Count -eq 0 -and @($staleCommands | Where-Object { $_.Contains('Remove-ItemProperty') }).Count -eq 1) 'failed staging preserves the old file and invalidates its previous Logo receipt'

    # --- The guard's own logic, run in-process with shadowed registry cmdlets ----------
    $guard = $guards[0]
    Check ((Invoke-GuardInProcess $guard $defaultLogo.ToLowerInvariant() $false) -ceq ($script:inProcessKey + '|Logo')) 'guard removes our unverified Logo value when its file is absent'
    Check ((Invoke-GuardInProcess $guard $defaultLogo $true) -ceq ($script:inProcessKey + '|Logo')) 'guard removes our unverified Logo value even while its file exists'
    Check ((Invoke-GuardInProcess $guard 'C:\OEM\vendor-logo.bmp' $false) -ceq '') 'guard keeps a foreign Logo value'
    Check ((Invoke-GuardInProcess $guard $null $false) -ceq '') 'guard is a no-op when no Logo value exists'
    Check ((Invoke-GuardInProcess $guard ([byte[]](1, 2)) $false) -ceq '') 'guard ignores a non-string Logo value'
    $quoted = "C:\Windows\Web\O'Brien\mios-logo.bmp"
    $qGuard = @(@(New-MiOSBrandingCommands -Toml (New-View @{ 'branding.oem_logo' = $quoted })) | Where-Object { $_.Contains('Remove-ItemProperty') })
    Check ($qGuard.Count -eq 1 -and (Invoke-GuardInProcess $qGuard[0] $quoted $false) -ceq ($script:inProcessKey + '|Logo')) 'guard transports a single quote in the configured path'

    # --- Bake path: the rendered FirstLogon script carries the guard and no Logo -------
    $bakeView = New-View @{ 'identity.username' = 'fixture'; 'identity.default_password' = 'FIXTURE-ONLY'; 'autounattend.service.enable' = 'false';
                            'autounattend.autologon_enable' = 'false'; 'autounattend.run_bootstrap' = 'false' }
    $baked = @()
    # The renderer reads its entry script's parameters; these locals stand in for them.
    $ObfuscatePasswords = [switch]$false; $FullDiskWindows = [switch]$false; $BootstrapUrl = ''; $CANONICAL_BOOTSTRAP = 'https://fixture.invalid/Get-MiOS.ps1'
    try {
        [xml]$doc = New-MiOSAutounattendXml -Toml $bakeView
        $first = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String([string]$doc.unattend.Extensions.FirstLogonScript))
        $tokens = $null; $errors = $null
        $fast = [Management.Automation.Language.Parser]::ParseInput($first, [ref]$tokens, [ref]$errors)
        $baked = @($fast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.CommandElements.Count -eq 5 -and
            $n.CommandElements[0].Extent.Text -eq '$env:ComSpec' }, $true) | ForEach-Object { $_.CommandElements[4].Value })
    } catch { Write-Host "    (bake render: $($_.Exception.Message))" }
    Check ($baked.Count -gt 0 -and @($baked | Where-Object { $_ -match '/v Logo /t REG_SZ' }).Count -eq 0) 'the baked FirstLogon script carries no Logo value'
    $bakedGuard = @($baked | Where-Object { $_ -ceq ('cmd /c ' + $guard) })
    Check ($bakedGuard.Count -eq 1) 'the baked FirstLogon script carries the guard byte-exact'

    # --- Quoting survives the real cmd.exe and powershell.exe parsers (both paths) -----
    if (-not $SkipNative) {
        $fixtureKey = 'HKCU:\Software\MiOS-Fixture-' + [guid]::NewGuid().ToString('N')
        $marker = Join-Path $scratch ('live-owned-' + [guid]::NewGuid().ToString('N') + '.txt')
        Invoke-MiOSHostCommands -Commands @((New-GuardProbe $guard $defaultLogo $marker $fixtureKey))
        Check ([IO.File]::Exists($marker) -and [IO.File]::ReadAllText($marker) -ceq ($fixtureKey + '|Logo')) 'live path: cmd.exe /c delivers the guard intact and it removes our unverified value'
        $marker = Join-Path $scratch ('live-foreign-' + [guid]::NewGuid().ToString('N') + '.txt')
        & cmd.exe /c (New-GuardProbe $guard 'C:\OEM\vendor-logo.bmp' $marker $fixtureKey) *> $null
        Check ($LASTEXITCODE -eq 0 -and -not [IO.File]::Exists($marker)) 'live path: the guard runs cleanly and keeps a foreign value'
        $marker = Join-Path $scratch ('live-data-' + [guid]::NewGuid().ToString('N') + '.txt')
        & cmd.exe /v:on /c (New-GuardProbe $unsafeGuards[0] $uncarriable $marker $fixtureKey) *> $null
        Check ($LASTEXITCODE -eq 0 -and [IO.File]::Exists($marker) -and [IO.File]::ReadAllText($marker) -ceq ($fixtureKey + '|Logo')) 'live path: unsafe path text remains data through cmd delayed expansion'
        $marker = Join-Path $scratch ('baked-owned-' + [guid]::NewGuid().ToString('N') + '.txt')
        if ($bakedGuard.Count -eq 1) {
            $probe = New-GuardProbe $bakedGuard[0] $defaultLogo $marker $fixtureKey
            & $env:ComSpec /d /s /c $probe *> $null
        }
        Check ([IO.File]::Exists($marker) -and [IO.File]::ReadAllText($marker) -ceq ($fixtureKey + '|Logo')) 'bake path: the FirstLogon cmd chain delivers the guard intact'
    } else { Write-Host 'SOURCE_FIXTURE_UNRUN WINDOWS_COMMAND_PARSERS 4' }

    # --- Entry wiring (AST only; the entry scripts are never run) ----------------------
    $tokens = $null; $errors = $null
    $past = [Management.Automation.Language.Parser]::ParseFile($ProvisionPath, [ref]$tokens, [ref]$errors)
    $calls = @($past.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] }, $true))
    $wall = @($calls | Where-Object { $_.GetCommandName() -eq 'Install-MiOSLivingWallpaperAssets' })
    $stage = @($calls | Where-Object { $_.GetCommandName() -eq 'Install-MiOSOemLogo' })
    $prov = @($calls | Where-Object { $_.GetCommandName() -eq 'New-MiOSProvisionCommands' })
    $wired = $false
    if ($errors.Count -eq 0 -and $wall.Count -eq 1 -and $stage.Count -eq 1 -and $prov.Count -eq 1) {
        $assign = $stage[0].Parent.Parent
        $els = @($prov[0].CommandElements)
        $i = -1; for ($j = 0; $j -lt $els.Count; $j++) { if ($els[$j] -is [Management.Automation.Language.CommandParameterAst] -and $els[$j].ParameterName -eq 'OemLogo') { $i = $j } }
        $wired = $assign -is [Management.Automation.Language.AssignmentStatementAst] -and $i -ge 0 -and $i + 1 -lt $els.Count -and
            $els[$i + 1] -is [Management.Automation.Language.VariableExpressionAst] -and $els[$i + 1].VariablePath.UserPath -eq $assign.Left.VariablePath.UserPath -and
            $wall[0].Extent.StartOffset -lt $stage[0].Extent.StartOffset -and $stage[0].Extent.StartOffset -lt $prov[0].Extent.StartOffset
    }
    Check $wired 'live apply passes Install-MiOSOemLogo evidence to New-MiOSProvisionCommands'
    $uast = [Management.Automation.Language.Parser]::ParseFile($realUnattend, [ref]$tokens, [ref]$errors)
    $ucalls = @($uast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-MiOSProvisionCommands' }, $true))
    Check ($ucalls.Count -eq 1 -and @($ucalls[0].CommandElements | Where-Object { $_ -is [Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'OemLogo' }).Count -eq 0) 'the bake renderer still calls New-MiOSProvisionCommands without evidence'
    $fetcher = @($libAst.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-MiOSVendorBytes' }, $true))[0].Extent.Text
    Check ($fetcher.Contains('Invoke-WebRequest') -and $fetcher.Contains('-UseBasicParsing') -and $fetcher.Contains('[Net.SecurityProtocolType]::Tls12')) 'the default fetcher is Invoke-WebRequest -UseBasicParsing over TLS 1.2'

    Write-Host ('SOURCE_FIXTURE_SCOPE ' + $(if ($SkipWindows) { 'portable' } else { 'windows' }))
    Write-Host "SOURCE_FIXTURE_ASSERTIONS $($script:checks)"
    return $script:fail
}

try {
    if (-not $PlantDefect) {
        $failures = Invoke-Checks $realLib $realProvision -SkipWindows:$SkipWindows
        if ($failures) { Write-Host "RESULT: FAIL ($failures checks)"; exit 1 }
        if ($SkipWindows) { Write-Host 'RESULT: PASS (portable source fixtures; Windows ACL APIs and command parsers UNRUN)' }
        else { Write-Host 'RESULT: PASS (source fixtures; fetches mocked, scratch writes only, registry cmdlets shadowed)' }
        exit 0
    }
    # A planted defect is meaningful only after the complete, unmodified baseline passes.
    $baseline = Invoke-Checks $realLib $realProvision -SkipWindows:$SkipWindows
    if ($baseline) { Write-Host 'SOURCE_DEFECT_BASELINE_FAILED'; exit 1 }
    $plants = @(
        @{ Name = 'sha256 check removed'; File = 'lib'; Expected = 'refuses a sidecar sha256 that does not match the bitmap'; From = 'if ($actual -cne [string]$sidecar.sha256)'; To = 'if ($false)' },
        @{ Name = 'size check removed'; File = 'lib'; Expected = 'refuses a sidecar size that does not match the bitmap'; From = ' -or $sidecar.size -ne $bmp.Length)'; To = ')' },
        @{ Name = '32bpp header check removed'; File = 'lib'; Expected = 'refuses a non-32bpp bitmap'; From = '[BitConverter]::ToUInt16($Bytes, 28) -ne 32'; To = '[BitConverter]::ToUInt16($Bytes, 28) -eq 0' },
        @{ Name = 'square header check removed'; File = 'lib'; Expected = 'refuses a non-square bitmap'; From = 'if ($w -ne $h)'; To = 'if ($false)' },
        @{ Name = 'operator colour binding removed'; File = 'lib'; Expected = 'refuses an operator colour override'; From = 'if ($hostBg -ine $vendorBg)'; To = 'if ($false)' },
        @{ Name = 'vendor colour binding removed'; File = 'lib'; Expected = 'refuses a sidecar background that differs from the vendor colour'; From = ' -or $bg -ine $vendorBg)'; To = ')' },
        @{ Name = 'commit pinning replaced by main'; File = 'lib'; Expected = 'every vendor fetch is pinned to the resolved commit'; From = '$base = $source.Raw + ''/'' + $Commit + ''/'''; To = '$base = $source.Raw + ''/main/''' },
        @{ Name = 'explicit commit validation removed'; File = 'lib'; Expected = 'refuses an explicit non-hex commit'; From = 'if ($Commit -cnotmatch ''^[0-9a-f]{40}$'')'; To = 'if ($false)' },
        @{ Name = 'resolved commit validation removed'; File = 'lib'; Expected = 'refuses a commit that does not resolve to 40 hex'; From = 'if ($sha -cnotmatch ''^[0-9a-f]{40}$'')'; To = 'if ($false)' },
        @{ Name = 'target path rule removed'; File = 'lib'; Expected = 'refuses a target under the wrong vendor system root'; From = '$gap = Get-MiOSOemLogoTargetGap -Path $target -Toml $Toml -Vendor $vendor'; To = '$gap = $null' },
        @{ Name = 'Logo emitted without evidence'; File = 'lib'; Expected = 'bake-style branding (no evidence) emits no Logo value'; From = 'if ($hasEvidence) {'; To = 'if ($true) {' },
        @{ Name = 'evidence verification bypassed'; File = 'lib'; Expected = 'branding ignores evidence for a different path'; From = '(Test-MiOSOemLogoEvidence -Toml $Toml -OemLogo $OemLogo)'; To = '$true' },
        @{ Name = 'guarded removal dropped'; File = 'lib'; Expected = 'bake-style branding emits the guarded owned-value removal'; From = 'return @(''powershell.exe -NoProfile -Command "'' + $guard + ''"'')'; To = 'return @()' },
        @{ Name = 'guard value equality dropped'; File = 'lib'; Expected = 'guard keeps a foreign Logo value'; From = ' -and [string]::Equals($v, $p, [StringComparison]::OrdinalIgnoreCase)'; To = '' },
        @{ Name = 'guard incorrectly requires a missing file'; File = 'lib'; Expected = 'guard removes our unverified Logo value even while its file exists'; From = '[string]::Equals($v, $p, [StringComparison]::OrdinalIgnoreCase))'; To = '[string]::Equals($v, $p, [StringComparison]::OrdinalIgnoreCase) -and -not (Test-Path -LiteralPath $p -PathType Leaf))' },
        @{ Name = 'reader quote-run fix reverted'; File = 'lib'; Expected = 'reader accepts quotes before a closing triple quote'; From = '$i + $run - 3'; To = '$i' },
        @{ Name = 'branding threading dropped'; File = 'lib'; Expected = 'New-MiOSProvisionCommands threads staging evidence to branding'; From = 'New-MiOSBrandingCommands   -Toml $Toml -OemLogo $OemLogo'; To = 'New-MiOSBrandingCommands   -Toml $Toml' },
        @{ Name = 'disabled branding cleanup skipped'; File = 'lib'; Expected = 'disabled Windows branding still cleans only the configured owned Logo value'; From = '{ return @(New-MiOSOemLogoCommands -Toml $Toml) }'; To = '{ return @() }' },
        @{ Name = 'receipt identity check removed'; File = 'lib'; Expected = 'serialized evidence cannot replay the private staging receipt'; From = ' -or -not [object]::ReferenceEquals($receipt.Evidence, $OemLogo)'; To = '' },
        @{ Name = 'receipt input binding removed'; File = 'lib'; Expected = 'a receipt is invalid after an effective colour change'; From = '$receipt.Binding -ceq (Get-MiOSOemLogoBinding -Toml $Toml -BackgroundKey $receipt.BackgroundKey)'; To = '$true' },
        @{ Name = 'receipt byte verification removed'; File = 'lib'; Expected = 'a receipt is invalid if the staged bytes change'; From = '(Get-MiOSSha256Hex -Bytes $bytes) -ceq $receipt.Sha256'; To = '$true' },
        @{ Name = 'receipt reset dropped'; File = 'lib'; Expected = 'a disabled staging attempt invalidates the previous receipt'; From = '    $script:MiOSOemLogoReceipt = $null'; To = '    # receipt reset omitted' },
        @{ Name = 'ancestor link check removed'; File = 'lib'; Expected = 'staging refuses a reparse-point ancestor without writing through it'; From = '($attributes -band [IO.FileAttributes]::ReparsePoint) -or -not ($attributes -band [IO.FileAttributes]::Directory)'; To = '$false' },
        @{ Name = 'ACL write check removed'; WindowsOnly = $true; File = 'lib'; Expected = 'the ACL policy refuses a destination writable by Users'; From = '($rule.FileSystemRights -band $writeMask)'; To = '$false' },
        @{ Name = 'missing effective colour mislabeled'; File = 'lib'; Expected = 'names a missing effective required colour instead of claiming an override'; From = 'if (-not $hostBg)'; To = 'if ($false)' },
        @{ Name = 'live entry drops evidence'; File = 'provision'; Expected = 'live apply passes Install-MiOSOemLogo evidence to New-MiOSProvisionCommands'; From = 'New-MiOSProvisionCommands -Toml $toml -OemLogo $oemLogo'; To = 'New-MiOSProvisionCommands -Toml $toml' }
    )
    $excludedPlants = 0
    if ($SkipWindows) {
        $excluded = @($plants | Where-Object { $_.WindowsOnly }); $excludedPlants = $excluded.Count
        foreach ($plant in $excluded) { Write-Host ('SOURCE_DEFECT_UNRUN WINDOWS_ACL_API: ' + $plant.Name) }
        $plants = @($plants | Where-Object { -not $_.WindowsOnly })
    }
    $caught = 0; $index = 0
    foreach ($plant in $plants) {
        $index++
        $source = if ($plant.File -eq 'lib') { $realLib } else { $realProvision }
        $text = [IO.File]::ReadAllText($source)
        $count = ([regex]::Matches($text, [regex]::Escape($plant.From))).Count
        if ($count -ne 1) { throw "Missing defect anchor: $($plant.Name) (found $count)" }
        $copy = Join-Path $scratch ('planted-' + $index + '-' + [IO.Path]::GetFileName($source))
        [IO.File]::WriteAllText($copy, $text.Replace($plant.From, $plant.To), $utf8)
        $lib = $realLib; $prov = $realProvision
        if ($plant.File -eq 'lib') { $lib = $copy } else { $prov = $copy }
        Write-Host "PLANT $index/$($plants.Count): $($plant.Name)"
        $null = Invoke-Checks $lib $prov -SkipNative -SkipWindows:$SkipWindows
        $detected = $script:failedChecks.Contains($plant.Expected)
        Write-Host ("PLANT_RESULT {0}: {1}" -f $plant.Name, $(if ($detected) { 'caught' } else { 'MISSED' }))
        if ($detected) { $caught++ }
    }
    if ($caught -eq $plants.Count) {
        if ($SkipWindows) { Write-Host "RESULT: PASS (portable planted defects caught: $caught/$($plants.Count); Windows-only plants UNRUN: $excludedPlants)" }
        else { Write-Host "RESULT: PASS (every planted defect was caught: $caught/$($plants.Count))" }
        exit 0
    }
    Write-Host "RESULT: FAIL (planted defects caught: $caught/$($plants.Count))"; exit 1
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction Stop
}
