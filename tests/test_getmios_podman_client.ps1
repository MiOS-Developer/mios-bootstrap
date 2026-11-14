# Podman client fixtures: AST-extracted functions from Get-MiOS.ps1 and build-mios.ps1, a fake podman (scratch .cmd), and
# mocked download, signature and msiexec. Nothing is downloaded, signed-checked against a real file, or installed.
# Default runs the fixtures; -PlantDefect plants each guarded defect into a copy of the product and requires a red result.
[CmdletBinding()]
param([switch]$PlantDefect, [string]$EntryPath, [string]$BuildPath)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $EntryPath) { $EntryPath = Join-Path $repoRoot 'Get-MiOS.ps1' }
if (-not $BuildPath) { $BuildPath = Join-Path $repoRoot 'build-mios.ps1' }
$templateToml = Join-Path $repoRoot 'mios.toml'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-podman-client-' + [guid]::NewGuid().ToString('N'))
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
function Import-Functions($Ast, [string[]]$Names) {
    foreach ($name in $Names) { . ([scriptblock]::Create(((Get-Function $Ast $name).Extent.Text -replace '^function\s+', 'function global:'))) }
}
function Get-Sha256Hex([byte[]]$Bytes) {
    $h = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($h.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() } finally { $h.Dispose() }
}

function Invoke-Checks([string]$Entry, [string]$Build) {
    $script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
    $entryAst = Get-Ast $Entry; $buildAst = Get-Ast $Build
    Import-Functions $entryAst @('Get-MiosTomlValue', 'Get-MiosPodmanVersion', 'Get-MiosRequiredPodmanVersion', 'Install-MiosPodmanClient', 'Get-MiosMachineWorkerScript',
        'Get-MiosMachinePodmanExe', 'Get-MiosMachinePodmanVersion', 'Get-MiosOlderPodmanEntries', 'Get-MiosPodmanRemovalPlan', 'Remove-MiosOlderPodman',
        'Get-MiosMachinePodmanPaths', 'Remove-MiosPerUserPodman', 'Resolve-MiosPodmanExe')
    $savedProgramData = $env:ProgramData
    Import-Functions $buildAst @('Assert-MiosPodmanInitSupport')

    # --- Fake podman: a real executable script whose version and help the fixture controls; every run leaves a mark --------
    $fake = Join-Path $scratch 'podman.cmd'
    [IO.File]::WriteAllText($fake, ("@echo off`r`n" +
        "if defined MIOS_FAKE_MARKER echo ran>>""%MIOS_FAKE_MARKER%""`r`n" +
        "if ""%1""==""--version"" ( echo podman version %MIOS_FAKE_PODMAN_VERSION% & exit /b 0 )`r`n" +
        "if ""%1""==""machine"" if ""%2""==""init"" if ""%3""==""--help"" (`r`n" +
        "  echo Usage: podman machine init [options] [NAME]`r`n" +
        "  echo       --now                    Start machine now`r`n" +
        "  if ""%MIOS_FAKE_PODMAN_FLAG%""==""1"" echo       --update-connection      Set the default system connection`r`n" +
        "  echo       --rootful                Whether this machine should prefer rootful container execution`r`n" +
        "  exit /b 0 )`r`n" +
        "exit /b 125`r`n"), (New-Object Text.ASCIIEncoding))
    $script:fakeExe = $fake
    $script:marker = Join-Path $scratch 'machine-client-ran.txt'
    # The machine path is %ProgramFiles%\...\podman.exe; scenarios stand the fake in for it, the PATH scenario uses the real one.
    $script:realMachineExe = (Get-Item function:Get-MiosMachinePodmanExe).ScriptBlock
    function global:Get-MiosMachinePodmanExe {
        if ($script:useRealMachineExe) { return (& $script:realMachineExe) }
        if ($script:clientAbsent) { return $null }
        return $script:fakeExe
    }

    # --- SSOT fixtures: the vendor tier carries the pin; the operator layer tries to override it -------------------------
    $msiBytes = [byte[]](1..200 | ForEach-Object { [byte]($_ % 251) })
    $msiSha = Get-Sha256Hex $msiBytes
    $signer = 'CN="Fixture Signer, LLC", OU=Podman, O="Fixture Signer, LLC", C=US'
    $vendorUrl = 'https://example.invalid/vendor/podman-installer-windows-amd64.msi'
    function New-Vendor([string]$Url = $vendorUrl, [string]$Sha = $msiSha, [string]$Signer = $signer, [string]$Tag = '6.2') {
        $lines = @('[image]', "machine_os_tag = ""$Tag""", '', '[bootstrap.prereqs]', 'podman_cli_pkg = "RedHat.Podman"')
        if ($Url) { $lines += "podman_cli_msi_url = ""$Url""" }
        if ($Sha) { $lines += "podman_cli_msi_sha256 = ""$Sha""" }
        if ($Signer) { $lines += "podman_cli_msi_signer = '$Signer'" }
        return ($lines -join "`n") + "`n"
    }
    $operatorPins = "[bootstrap.prereqs]`npodman_cli_msi_url = ""https://example.invalid/operator/evil.msi""`npodman_cli_msi_sha256 = ""$('0' * 64)""`npodman_cli_msi_signer = 'CN=Operator'`n"
    function global:Resolve-MiosVendorTomlText { return $script:vendorText }
    function global:Resolve-MiosTomlText { return $script:operatorText }

    # --- Elevated-stage collaborators: recorded, never real ----------------------------------------------------------
    function global:Write-Info { param($m) $script:infos.Add([string]$m) }
    function global:Write-Good { param($m) }
    function global:Log-Fail { param($m) $script:logged = $m }
    function global:Assert-MiosMachineWriteBoundary { param($Path) }
    function global:New-MiosProtectedMachineDirectory { param($Path) [IO.Directory]::CreateDirectory($Path) | Out-Null }
    function global:Write-MiosPrivateMachineFile { param($Path, [byte[]]$Bytes) [IO.File]::WriteAllBytes($Path, $Bytes); $script:written.Add($Path) }
    function global:Get-MiosPinnedDownloadBytes { param($Uri) $script:downloads.Add($Uri); return , $script:servedBytes }
    function global:Get-AuthenticodeSignature {
        [CmdletBinding()] param([string]$LiteralPath)
        if ($LiteralPath -like '*.msi') {
            $script:signatureChecks.Add($LiteralPath)
            return [pscustomobject]@{ Status = $script:sigStatus; SignerCertificate = [pscustomobject]@{ Subject = $script:sigSubject } }
        }
        if ($LiteralPath -like '*podman-setup.exe') {
            $script:bundleSignatureChecks.Add($LiteralPath)
            return [pscustomobject]@{ Status = $script:bundleSigStatus; SignerCertificate = [pscustomobject]@{ Subject = $script:bundleSigSubject } }
        }
        $script:exeSignatureChecks.Add($LiteralPath)
        return [pscustomobject]@{ Status = $script:exeSigStatus; SignerCertificate = [pscustomobject]@{ Subject = $script:exeSigSubject } }
    }
    # --- Uninstall registrations: a fake registry read as data, removals recorded and applied to it, never real ------------
    $env:ProgramData = Join-Path $scratch 'ProgramData'
    $bundleKey = '{A1EC0C19-E860-4554-9787-72ECCE3E9ED7}'; $msiKey = '{C1B3D45C-260B-4853-9BAA-AA68F4A20A02}'
    $cacheExe = Join-Path $env:ProgramData ('Package Cache\' + $bundleKey + '\podman-setup.exe')
    $outsideExe = Join-Path $scratch ('elsewhere\' + $bundleKey + '\podman-setup.exe')
    foreach ($f in $cacheExe, $outsideExe) { New-Item -ItemType Directory -Force -Path (Split-Path $f) | Out-Null; [IO.File]::WriteAllText($f, 'fixture bundle') }
    $msiexecPath = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    function New-Entry([string]$Key, [string]$Name = 'Podman', [string]$Publisher = 'Red Hat', [string]$Version = '5.8.10', [string]$Cache = '', [string]$Quiet = '', [string]$Wi = '') {
        $provider = if ($Cache) { $Key } else { '' }
        return [pscustomobject]@{ Root = 'HKLM:\fixture'; Key = $Key; DisplayName = $Name; Publisher = $Publisher; DisplayVersion = $Version; WindowsInstaller = $Wi
            BundleCachePath = $Cache; BundleProviderKey = $provider; QuietUninstallString = $Quiet }
    }
    function New-RealShape([string]$Cache = $cacheExe) {
        # The shape winget's Podman 5.8.10 setup left on mios-1: a visible bundle and its hidden Windows Installer product.
        return @((New-Entry $bundleKey -Cache $Cache -Quiet ('"' + $Cache + '" /uninstall /quiet')), (New-Entry $msiKey -Name 'podman' -Publisher 'Red Hat Inc.' -Wi '1'))
    }
    $bystanders = @((New-Entry '{11111111-1111-1111-1111-111111111111}' -Name 'Podman Desktop' -Version '1.30.5' -Wi '1'),
        (New-Entry '{22222222-2222-2222-2222-222222222222}' -Publisher 'Contoso' -Wi '1'),
        (New-Entry '{33333333-3333-3333-3333-333333333333}' -Version '6.2.0' -Wi '1'))
    function global:Read-MiosPodmanUninstallEntries { return @($script:registry) }
    function global:Invoke-MiosPodmanRemoval {
        param([string]$FilePath, [string[]]$Arguments)
        $script:removals.Add($FilePath + '|' + ($Arguments -join ' '))
        $kind = if ($FilePath -like '*podman-setup.exe') { 'bundle' } elseif (@($script:related | ForEach-Object { $_.ProductCode }) -contains $Arguments[1]) { 'peruser' } else { 'msi' }
        $script:events.Add('remove-' + $kind)
        if ($script:removalExit -notin @(0, 3010) -or $script:removalLeavesEntries) { return $script:removalExit }
        if ($kind -eq 'peruser') { $script:related = @($script:related | Where-Object { $_.ProductCode -ne $Arguments[1] }); return $script:removalExit }
        $gone = if ($kind -eq 'bundle') { @($script:registry | Where-Object { $_.BundleCachePath -eq $FilePath -or ($script:bundleRemovesMsi -and $_.Key -eq $msiKey) }) }
                else { @($script:registry | Where-Object { $_.Key -eq $Arguments[1] }) }
        $script:registry = @($script:registry | Where-Object { $gone -notcontains $_ })
        $script:clientAbsent = $true
        return $script:removalExit
    }
    # --- Windows Installer: the verified package's identity and the products of its family, never real ----------------
    $productCode = '{1F3FA496-3F50-4C98-BAEA-464990EDF033}'; $upgradeCode = '{A6A9DD9C-0732-44BA-9279-FFE22EA50671}'
    $installDir = Join-Path $env:ProgramFiles 'Podman'
    function New-Related([string]$Code = $productCode, [string]$Assignment = '0', [string]$Version = '6.2.0') { return [pscustomobject]@{ ProductCode = $Code; AssignmentType = $Assignment; Version = $Version } }
    function global:Get-MiosMsiPackageInfo { param($Path) $script:events.Add('package-read'); $script:packageReads.Add($Path); return $script:package }
    function global:Get-MiosMsiRelatedProducts { param($UpgradeCode) $script:relatedQueries.Add($UpgradeCode); return @($script:related) }
    function global:Get-MiosMachinePath { return $script:machinePath }
    function global:Invoke-MiosMsiInstall {
        # Behaves like the pinned dual-purpose package (ALLUSERS=2, MSIINSTALLPERUSER=1): without ALLUSERS=1 it installs
        # per-user for the elevating account, leaving nothing under Program Files (run 5); its machine-PATH component is
        # selected only with ALLUSERS=1 AND NOT MSIINSTALLPERUSER=1.
        param($Path, [string[]]$Properties = @())
        $script:events.Add('install')
        $script:installs.Add($Path)
        $script:installProperties = @($Properties)
        $script:installedExisted = Test-Path -LiteralPath $Path
        if ($script:msiExit -notin @(0, 3010)) { return $script:msiExit }
        $perMachine = ($Properties -contains 'ALLUSERS=1') -and -not $script:forcePerUser
        $perUserProperty = if ($Properties -contains 'MSIINSTALLPERUSER=0') { '0' } else { '1' }
        $script:related = @(@($script:related | Where-Object { $_.ProductCode -ne $script:package.ProductCode }) + @(New-Related -Code $script:package.ProductCode -Assignment $(if ($perMachine) { '1' } else { '0' })))
        if ($perMachine -and $perUserProperty -ne '1') { $script:machinePath = $script:machinePath + ';' + $installDir }
        if ($perMachine -and $script:msiUpgradesTo -and -not $script:installLeavesNoExe) { $env:MIOS_FAKE_PODMAN_VERSION = $script:msiUpgradesTo; $script:clientAbsent = $false }
        return $script:msiExit
    }
    $download = Join-Path $scratch 'downloads'
    function Reset-Scenario([string]$Version = '5.8.10') {
        $env:MIOS_FAKE_PODMAN_VERSION = $Version; $env:MIOS_FAKE_PODMAN_FLAG = '0'
        $script:clientAbsent = $false; $script:vendorText = New-Vendor; $script:operatorText = $operatorPins
        $script:servedBytes = $msiBytes; $script:sigStatus = 'Valid'; $script:sigSubject = $signer
        $script:exeSigStatus = 'Valid'; $script:exeSigSubject = $signer; $script:useRealMachineExe = $false
        $script:exeSignatureChecks = New-Object System.Collections.Generic.List[string]
        $env:MIOS_FAKE_MARKER = $script:marker; Remove-Item -LiteralPath $script:marker -Force -ErrorAction SilentlyContinue
        $script:msiExit = 0; $script:msiUpgradesTo = '6.2.0'; $script:installedExisted = $false
        $script:downloads = New-Object System.Collections.Generic.List[string]; $script:installs = New-Object System.Collections.Generic.List[string]
        $script:written = New-Object System.Collections.Generic.List[string]; $script:signatureChecks = New-Object System.Collections.Generic.List[string]
        $script:registry = @(); $script:removals = New-Object System.Collections.Generic.List[string]; $script:events = New-Object System.Collections.Generic.List[string]
        $script:bundleSigStatus = 'Valid'; $script:bundleSigSubject = $signer; $script:bundleSignatureChecks = New-Object System.Collections.Generic.List[string]
        $script:removalExit = 0; $script:bundleRemovesMsi = $false; $script:removalLeavesEntries = $false
        $script:package = [pscustomobject]@{ ProductCode = $productCode; UpgradeCode = $upgradeCode; Manufacturer = 'Podman' }
        $script:related = @(); $script:machinePath = 'C:\Windows\system32;C:\Windows'; $script:installProperties = @()
        $script:infos = New-Object System.Collections.Generic.List[string]; $script:packageReads = New-Object System.Collections.Generic.List[string]
        $script:relatedQueries = New-Object System.Collections.Generic.List[string]; $script:forcePerUser = $false; $script:installLeavesNoExe = $false
        if (Test-Path -LiteralPath $download) { Remove-Item -LiteralPath $download -Recurse -Force }
    }
    function Invoke-Install { $script:outcome = $null; $script:installError = ''; try { $script:outcome = Install-MiosPodmanClient -DownloadDirectory $download } catch { $script:installError = $_.Exception.Message } }
    function Test-NothingInstalled { return ($script:installs.Count -eq 0 -and @(Get-ChildItem -LiteralPath $download -Force -ErrorAction SilentlyContinue).Count -eq 0) }

    # --- Installer path -----------------------------------------------------------------------------------------------
    Reset-Scenario '5.8.10'; Invoke-Install
    Check ($script:outcome -eq 'installed' -and $script:downloads.Count -eq 1 -and $script:installs.Count -eq 1 -and $script:installedExisted -and
           $script:signatureChecks.Count -eq 1 -and $script:signatureChecks[0] -eq $script:installs[0] -and $script:written[0] -eq $script:installs[0] -and
           @(Get-ChildItem -LiteralPath $download -Force).Count -eq 0) 'a 5.8 client takes the pinned MSI path: verified, installed from the private copy, copy removed'
    Check ($script:downloads[0] -ceq $vendorUrl) 'the pinned MSI URL comes from the system SSOT, never the operator layer'
    Check ((Test-Path -LiteralPath $script:marker) -and $script:exeSignatureChecks.Count -ge 1 -and $script:exeSignatureChecks[0] -eq $script:fakeExe) 'the machine client runs elevated only after its signature is checked'
    Reset-Scenario '5.8.10'; $script:exeSigStatus = 'NotSigned'; Invoke-Install
    Check ($script:installError -match 'never run elevated' -and -not (Test-Path -LiteralPath $script:marker) -and $script:downloads.Count -eq 0 -and (Test-NothingInstalled)) 'an unsigned machine Podman client is never run elevated'
    Reset-Scenario '5.8.10'; $script:exeSigSubject = 'CN="Planted, LLC", O="Planted, LLC"'; Invoke-Install
    Check ($script:installError -match 'not the SSOT signer; it is never run elevated' -and -not (Test-Path -LiteralPath $script:marker) -and (Test-NothingInstalled)) 'a machine Podman client from another signer is never run elevated'
    # A podman.exe planted in a user-writable directory early on PATH (WinGet Links, WindowsApps) must never run elevated.
    Reset-Scenario '5.8.10'; $script:useRealMachineExe = $true
    $planted = Join-Path $scratch 'planted'; New-Item -ItemType Directory -Force -Path $planted | Out-Null
    $plantMarker = Join-Path $scratch 'planted-ran.txt'; Remove-Item -LiteralPath $plantMarker -Force -ErrorAction SilentlyContinue
    [IO.File]::WriteAllText((Join-Path $planted 'podman.cmd'), ("@echo off`r`necho ran>>""" + $plantMarker + """`r`necho podman version 9.9.9`r`n"), (New-Object Text.ASCIIEncoding))
    $emptyProgramFiles = Join-Path $scratch 'ProgramFiles'; New-Item -ItemType Directory -Force -Path $emptyProgramFiles | Out-Null
    # Run 5's per-user copy lived in the elevating account's profile; it must never count as the machine client.
    $profileApp = Join-Path $scratch 'LocalAppData'; New-Item -ItemType Directory -Force -Path (Join-Path $profileApp 'Programs\Podman') | Out-Null
    [IO.File]::WriteAllText((Join-Path $profileApp 'Programs\Podman\podman.exe'), 'fixture per-user client')
    $savedProgramFiles = $env:ProgramFiles; $savedPath = $env:PATH; $savedLocalAppData = $env:LOCALAPPDATA
    try { $env:ProgramFiles = $emptyProgramFiles; $env:LOCALAPPDATA = $profileApp; $env:PATH = $planted + ';' + $env:PATH; Invoke-Install }
    finally { $env:ProgramFiles = $savedProgramFiles; $env:PATH = $savedPath; $env:LOCALAPPDATA = $savedLocalAppData }
    Check (-not (Test-Path -LiteralPath $plantMarker) -and $script:exeSignatureChecks.Count -eq 0) 'neither a podman planted on PATH nor a per-user profile copy is considered by the elevated check'
    # The user side finds a fresh per-machine 6.x even before the machine PATH reaches this session.
    $pf = Join-Path $scratch 'ProgramFilesWith6'; New-Item -ItemType Directory -Force -Path (Join-Path $pf 'Podman') | Out-Null
    [IO.File]::WriteAllText((Join-Path $pf 'Podman\podman.exe'), 'fixture machine client')
    $resolved = $null
    try { $env:ProgramFiles = $pf; $env:PATH = Join-Path $env:SystemRoot 'System32'; $resolved = Resolve-MiosPodmanExe }
    finally { $env:ProgramFiles = $savedProgramFiles; $env:PATH = $savedPath }
    Check ($resolved -eq (Join-Path $pf 'Podman\podman.exe')) 'the user side finds a per-machine 6.x podman.exe that is not yet on PATH'
    Reset-Scenario '6.2.0'; Invoke-Install
    Check ($script:outcome -eq 'current' -and $script:downloads.Count -eq 0 -and $script:installs.Count -eq 0) 'a 6.2 client skips the MSI path'
    Reset-Scenario '6.3.1'; Invoke-Install
    Check ($script:outcome -eq 'current' -and $script:downloads.Count -eq 0) 'a newer client than machine-os skips the MSI path'
    Reset-Scenario; $script:clientAbsent = $true; Invoke-Install
    Check ($script:outcome -eq 'installed' -and $script:installs.Count -eq 1) 'an absent client takes the pinned MSI path'
    Reset-Scenario; $script:servedBytes = [byte[]](1..200 | ForEach-Object { [byte](($_ + 1) % 251) }); Invoke-Install
    Check ($script:installError -match 'sha256' -and $script:installError -match 'Nothing was installed' -and $script:written.Count -eq 0 -and (Test-NothingInstalled)) 'a sha256 mismatch refuses before the MSI touches disk'
    Reset-Scenario; $script:sigStatus = 'NotSigned'; Invoke-Install
    Check ($script:installError -match 'signature is NotSigned' -and (Test-NothingInstalled)) 'an MSI without a Valid signature refuses and installs nothing'
    Reset-Scenario; $script:sigStatus = 'HashMismatch'; Invoke-Install
    Check ($script:installError -match 'signature is HashMismatch' -and (Test-NothingInstalled)) 'a tampered signature refuses and installs nothing'
    Reset-Scenario; $script:sigSubject = 'CN="Someone Else", O="Someone Else"'; Invoke-Install
    Check ($script:installError -match 'not the SSOT signer' -and (Test-NothingInstalled)) 'a valid signature from another signer refuses and installs nothing'
    Reset-Scenario; $script:vendorText = New-Vendor -Signer ''; Invoke-Install
    Check ($script:installError -match 'no complete pinned Podman MSI' -and $script:downloads.Count -eq 0 -and (Test-NothingInstalled)) 'an incomplete SSOT pin refuses before any download'
    Reset-Scenario; $script:vendorText = New-Vendor -Sha ($msiSha.ToUpperInvariant()); Invoke-Install
    Check ($script:installError -match 'no complete pinned Podman MSI' -and $script:downloads.Count -eq 0) 'a malformed SSOT sha256 refuses before any download'
    Reset-Scenario; $script:vendorText = New-Vendor -Url 'http://example.invalid/podman.msi'; Invoke-Install
    Check ($script:installError -match 'no complete pinned Podman MSI' -and $script:downloads.Count -eq 0) 'a non-https SSOT URL refuses before any download'
    Reset-Scenario; $script:msiExit = 1603; $script:msiUpgradesTo = $null; Invoke-Install
    Check ($script:installError -match 'exit 1603' -and @(Get-ChildItem -LiteralPath $download -Force).Count -eq 0) 'an msiexec failure is reported and the private copy is removed'
    Reset-Scenario; $script:msiUpgradesTo = $null; Invoke-Install
    Check ($script:installError -match 'Podman 5\.8\.10 is still older than machine-os 6.2') 'a client still too old after the install is refused'
    Reset-Scenario; $script:clientAbsent = $true; $script:installLeavesNoExe = $true; Invoke-Install
    Check ($script:installError -match 'no Podman client was found at ' -and $script:installError.Contains((Join-Path $env:ProgramFiles 'Podman\podman.exe')) -and
           $script:installError -notmatch 'still older') 'no client at the per-machine paths after install is reported as missing, not as older'

    # --- Install scope: the dual-purpose package must install per-machine (run 5 installed it per-user for MIOS\admin) ---
    Reset-Scenario '5.8.10'; Invoke-Install
    Check ($script:outcome -eq 'installed' -and (@($script:installProperties) -join ' ') -ceq 'ALLUSERS=1 MSIINSTALLPERUSER=0' -and
           @($script:related | Where-Object { $_.ProductCode -eq $productCode -and $_.AssignmentType -eq '1' }).Count -eq 1) 'the verified MSI is installed per-machine (ALLUSERS=1 MSIINSTALLPERUSER=0) and Windows Installer reports it per-machine'
    Check (@($script:infos | Where-Object { $_ -match '^Warning: the machine PATH' }).Count -eq 0 -and (@($script:machinePath -split ';') -contains $installDir)) 'the per-machine install selects the machine PATH component, with no PATH warning'
    Check ($script:packageReads.Count -eq 1 -and $script:packageReads[0] -eq $script:installs[0] -and @($script:relatedQueries | Where-Object { $_ -ne $upgradeCode }).Count -eq 0 -and
           @($script:infos | Where-Object { $_ -eq "Verified Podman MSI: ProductCode $productCode, UpgradeCode $upgradeCode, Manufacturer 'Podman'." }).Count -eq 1) 'ProductCode, UpgradeCode and Manufacturer come from the verified private copy, are logged, and only that UpgradeCode is queried'
    $perUserCall = $msiexecPath + '|/x ' + $productCode + ' /qn /norestart'
    Reset-Scenario; $script:clientAbsent = $true; $script:related = @(New-Related -Assignment '0'); Invoke-Install
    Check ($script:outcome -eq 'installed' -and (@($script:removals) -join ';') -ceq $perUserCall -and (@($script:events) -join ',') -ceq 'package-read,remove-peruser,install' -and
           @($script:related | Where-Object { $_.AssignmentType -eq '0' }).Count -eq 0) 'run 5''s per-user 6.2 of the elevating account is removed by its ProductCode, then the MSI installs per-machine'
    Reset-Scenario; $script:clientAbsent = $true; $script:related = @(New-Related -Code '{44444444-4444-4444-4444-444444444444}' -Assignment '1' -Version '6.1.0'); Invoke-Install
    Check ($script:outcome -eq 'installed' -and $script:removals.Count -eq 0 -and @($script:related | Where-Object { $_.ProductCode -like '{4444*' }).Count -eq 1) 'a per-machine product of the family is left to the MSI''s own upgrade'
    Reset-Scenario; $script:clientAbsent = $true; $script:related = @(New-Related -Code 'not-a-guid' -Assignment '0'); Invoke-Install
    Check ($script:installError -match 'unexpected Windows Installer registration' -and $script:removals.Count -eq 0 -and $script:installs.Count -eq 0) 'a related product with a non-GUID code refuses with nothing removed'
    Reset-Scenario; $script:clientAbsent = $true; $script:related = @(New-Related -Assignment '7'); Invoke-Install
    Check ($script:installError -match 'unexpected Windows Installer registration' -and $script:removals.Count -eq 0 -and $script:installs.Count -eq 0) 'a related product with an unknown assignment refuses with nothing removed'
    Reset-Scenario; $script:clientAbsent = $true; $script:related = @(New-Related -Assignment '0'); $script:removalExit = 1603; Invoke-Install
    Check ($script:installError -match 'per-user Podman 6\.2\.0 .* failed \(exit 1603\)' -and $script:installs.Count -eq 0) 'a per-user removal failure refuses before install'
    Reset-Scenario; $script:clientAbsent = $true; $script:related = @(New-Related -Assignment '0'); $script:removalLeavesEntries = $true; Invoke-Install
    Check ($script:installError -match 'still installed for this elevated account after removal' -and $script:installs.Count -eq 0) 'a per-user install still present after removal refuses before install'
    Reset-Scenario; $script:forcePerUser = $true; Invoke-Install
    Check ($script:installError -match 'installed per-user for this elevated account, not per-machine') 'an install Windows Installer reports per-user is refused'
    Reset-Scenario; $script:package = [pscustomobject]@{ ProductCode = $productCode; UpgradeCode = ''; Manufacturer = 'Podman' }; $script:registry = @(New-RealShape); Invoke-Install
    Check ($script:installError -match 'no valid ProductCode/UpgradeCode' -and $script:removals.Count -eq 0 -and $script:installs.Count -eq 0) 'a verified MSI without a valid UpgradeCode refuses with nothing removed'
    Reset-Scenario; $script:vendorText = New-Vendor -Tag 'latest'; Invoke-Install
    Check ($script:installError -match 'machine_os_tag') 'an unversioned machine-os tag refuses the comparison'

    # --- Older registrations the pinned MSI cannot upgrade (its installer refuses with 1603) -------------------------------
    $bundleCall = $cacheExe + '|/uninstall /quiet /norestart'; $msiCall = $msiexecPath + '|/x ' + $msiKey + ' /qn /norestart'
    Reset-Scenario '5.8.10'; $script:registry = @(New-RealShape) + $bystanders; Invoke-Install
    Check ($script:outcome -eq 'installed' -and (@($script:removals) -join ';') -ceq ($bundleCall + ';' + $msiCall) -and
           (@($script:events) -join ',') -ceq 'package-read,remove-bundle,remove-msi,install' -and $script:bundleSignatureChecks.Count -eq 1) 'an older bundle and its MSI are removed in order with fixed arguments, then 6.2 is installed'
    Check (@($script:registry | Where-Object { $bystanders -contains $_ }).Count -eq 3 -and @($script:removals | Where-Object { $_ -match '\{(1|2|3)' }).Count -eq 0) 'Podman Desktop, a non-Red Hat Podman and a current 6.2 entry are never touched'
    Reset-Scenario '5.8.10'; $script:registry = @(New-RealShape); $script:bundleRemovesMsi = $true; Invoke-Install
    Check ($script:outcome -eq 'installed' -and (@($script:removals) -join ';') -ceq $bundleCall) 'an MSI its bundle already removed is not removed again'
    Reset-Scenario '5.8.10'; $script:registry = @($bystanders); Invoke-Install
    Check ($script:outcome -eq 'installed' -and $script:removals.Count -eq 0) 'with no older Red Hat Podman registered nothing is removed'
    Reset-Scenario '5.8.10'; $script:registry = @(New-RealShape -Cache $outsideExe); Invoke-Install
    Check ($script:installError -match 'outside' -and $script:removals.Count -eq 0 -and (Test-NothingInstalled)) 'a bundle exe outside Package Cache refuses with nothing removed'
    Reset-Scenario '5.8.10'; $script:registry = @(New-RealShape); $script:bundleSigStatus = 'NotSigned'; Invoke-Install
    Check ($script:installError -match 'NotSigned signature, not Valid; nothing was removed' -and $script:removals.Count -eq 0 -and (Test-NothingInstalled)) 'an unsigned bundle exe refuses with nothing removed'
    Reset-Scenario '5.8.10'; $script:registry = @(New-RealShape); $script:bundleSigSubject = 'CN="Planted, LLC", O="Planted, LLC"'; Invoke-Install
    Check ($script:installError -match 'not the SSOT signer; nothing was removed' -and $script:removals.Count -eq 0 -and (Test-NothingInstalled)) 'a foreign-signed bundle exe refuses with nothing removed'
    Reset-Scenario '5.8.10'; $odd = @(New-RealShape); $odd[0].QuietUninstallString = '"' + $cacheExe + '" /uninstall /quiet /passive & cmd /c calc'; $script:registry = $odd; Invoke-Install
    Check ($script:installError -match 'unexpected uninstall command' -and $script:removals.Count -eq 0 -and (Test-NothingInstalled)) 'an odd uninstall-string shape refuses with nothing removed'
    Reset-Scenario '5.8.10'; $script:registry = @(New-Entry 'not-a-guid' -Wi '1'); Invoke-Install
    Check ($script:installError -match 'neither a cached setup bundle nor a Windows Installer product' -and $script:removals.Count -eq 0 -and (Test-NothingInstalled)) 'an MSI entry without a GUID key refuses with nothing removed'
    Reset-Scenario '5.8.10'; $script:registry = @(New-RealShape); $script:removalExit = 1603; Invoke-Install
    Check ($script:installError -match 'failed \(exit 1603\); the pinned Podman MSI was not installed' -and $script:installs.Count -eq 0) 'an uninstall failure code refuses before install'
    Reset-Scenario '5.8.10'; $script:registry = @(New-RealShape); $script:removalLeavesEntries = $true; Invoke-Install
    Check ($script:installError -match 'still registered after removal' -and $script:installs.Count -eq 0) 'an older Podman still registered after removal refuses before install'
    Reset-Scenario '5.8.10'; $script:registry = @(New-RealShape); $script:sigStatus = 'NotSigned'; Invoke-Install
    Check ($script:removals.Count -eq 0 -and $script:installError -match 'signature is NotSigned') 'nothing is removed unless the replacement MSI is verified first'

    # --- Guard before init ----------------------------------------------------------------------------------------------
    # The user-side guard stays PATH-based: the fake podman is first on PATH, and the refusal names the path it resolved.
    $savedPath = $env:PATH
    try {
        $env:PATH = $scratch + ';' + $env:PATH
        $env:MIOS_FAKE_PODMAN_VERSION = '5.8.10'; $env:MIOS_FAKE_PODMAN_FLAG = '0'; $script:logged = ''
        $guard = ''; try { Assert-MiosPodmanInitSupport -RequiredTag '6.2' } catch { $guard = $_.Exception.Message }
        Check ($guard.Contains("Installed 'podman version 5.8.10' ($fake)") -and $guard -match 'Podman 6\.2 or newer' -and $guard -match 're-run the MiOS installer' -and
               $guard -match 'No machine or connection was created' -and $script:logged -eq $guard) 'a client without --update-connection stops before init with version, path, requirement and remedy'
        $env:MIOS_FAKE_PODMAN_VERSION = '6.2.0'; $env:MIOS_FAKE_PODMAN_FLAG = '1'
        $guard = ''; try { Assert-MiosPodmanInitSupport -RequiredTag '6.2' } catch { $guard = $_.Exception.Message }
        Check ($guard -eq '') 'a client with --update-connection passes the guard'
    } finally { $env:PATH = $savedPath }

    # --- Source order -------------------------------------------------------------------------------------------------
    $phase = @($buildAst.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $n.Body.Extent.Text.Contains("'machine', 'init', `$BuilderDistro") }, $true))
    $ok = $false
    if ($phase.Count -eq 1) {
        $text = $phase[0].Body.Extent.Text
        $guardAt = $text.IndexOf('Assert-MiosPodmanInitSupport -RequiredTag $machineTag'); $stageAt = $text.IndexOf('Get-PodmanMachineOsImage `')
        $initAt = $text.IndexOf("'machine', 'init', `$BuilderDistro"); $tagAt = $text.IndexOf("`$machineTag = `"`$(`$Matches[1]).`$(`$Matches[2])`"")
        $ok = $guardAt -gt $tagAt -and $tagAt -ge 0 -and $guardAt -lt $stageAt -and $guardAt -lt $initAt
    }
    Check $ok 'the guard runs after the machine-os tag resolves and before the image download and init'
    $core = (Get-Function $entryAst 'Invoke-MiosMachinePreparationCore').Body.Extent.Text
    $installAt = $core.IndexOf('$null = Install-MiosPodmanClient'); $pendingAt = $core.IndexOf("if (`$_platform.Status -eq 'pending')"); $longAt = $core.IndexOf('LongPathsEnabled')
    Check ($installAt -gt $pendingAt -and $pendingAt -ge 0 -and $installAt -lt $longAt) 'elevated preparation installs the client only after a ready platform gate'
    $installText = (Get-Function $entryAst 'Install-MiosPodmanClient').Body.Extent.Text
    $shaAt = $installText.IndexOf('if ($actual -cne $sha) { throw'); $writeAt = $installText.IndexOf('Write-MiosPrivateMachineFile -Path $msi')
    $sigAt = $installText.IndexOf("if ([string]`$signature.Status -ne 'Valid') { throw"); $signerAt = $installText.IndexOf('if ($subject -cne $signer) { throw')
    $msiAt = $installText.IndexOf('Invoke-MiosMsiInstall -Path $msi')
    Check ($shaAt -ge 0 -and $shaAt -lt $writeAt -and $sigAt -gt $writeAt -and $signerAt -gt $sigAt -and $msiAt -gt $signerAt) 'sha256, then the private copy, then signature and signer, all before msiexec'
    Check (@([regex]::Matches($installText, "Get-MiosTomlValue -Section 'bootstrap\.prereqs' -Key 'podman_cli_msi_(url|sha256|signer)' -Default '' -VendorOnly")).Count -eq 3) 'every pin is read from the system SSOT tier only'
    $ensure = (Get-Function $entryAst 'Ensure-PodmanDesktop').Body.Extent.Text
    Check (-not ($ensure -match 'WebClient|DownloadFile|msiexec|podman_url|Invoke-RestMethod')) 'the user-side Podman step has no unverified download or install path'
    $machineText = (Get-Function $entryAst 'Get-MiosMachinePodmanExe').Body.Extent.Text
    $versionText = (Get-Function $entryAst 'Get-MiosMachinePodmanVersion').Body.Extent.Text
    $pathsText = (Get-Function $entryAst 'Get-MiosMachinePodmanPaths').Body.Extent.Text
    Check (-not ($installText -match 'Resolve-MiosPodmanExe|Get-Command|\$env:PATH') -and -not (($machineText + $pathsText) -match 'Get-Command|\$env:PATH|Resolve-MiosPodmanExe|LOCALAPPDATA|USERPROFILE|APPDATA') -and
           $machineText.Contains('@(Get-MiosMachinePodmanPaths)') -and $pathsText.Contains("Join-Path `${env:ProgramFiles} 'Podman\podman.exe'") -and
           $pathsText.Contains("Join-Path `${env:ProgramFiles} 'RedHat\Podman\podman.exe'") -and
           @([regex]::Matches($installText, 'Get-MiosMachinePodmanVersion -Signer \$signer')).Count -eq 3 -and
           $versionText.IndexOf('Get-AuthenticodeSignature -LiteralPath $exe') -ge 0 -and
           $versionText.IndexOf('Get-AuthenticodeSignature -LiteralPath $exe') -lt $versionText.IndexOf('Get-MiosPodmanVersion $exe')) 'the elevated check resolves only the machine path and verifies it before running it'
    $readText = (Get-Function $entryAst 'Read-MiosPodmanUninstallEntries').Body.Extent.Text
    $planText = (Get-Function $entryAst 'Get-MiosPodmanRemovalPlan').Body.Extent.Text
    $removeText = (Get-Function $entryAst 'Remove-MiosOlderPodman').Body.Extent.Text
    Check ($readText.Contains("'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'") -and $readText.Contains("'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'") -and
           $planText.Contains("Arguments = @('/uninstall', '/quiet', '/norestart')") -and $planText.Contains("Arguments = @('/x', `$e.Key, '/qn', '/norestart')") -and
           -not (($readText + $planText + $removeText) -match 'Invoke-Expression|\biex\b|cmd(\.exe)?\s+/c|\[scriptblock\]::Create|\.UninstallString') -and
           $removeText.Contains('Invoke-MiosPodmanRemoval -FilePath $step.FilePath -Arguments $step.Arguments')) 'removal reads both registry views as data and runs only fixed arguments'
    $removeAt = $installText.IndexOf('Remove-MiosOlderPodman -Required $required -Signer $signer')
    Check ($removeAt -gt $signerAt -and $removeAt -lt $msiAt) 'older registrations are removed only after the replacement MSI is verified and before it installs'
    $packageAt = $installText.IndexOf('$package = Get-MiosMsiPackageInfo -Path $msi'); $perUserAt = $installText.IndexOf('Remove-MiosPerUserPodman -UpgradeCode $package.UpgradeCode')
    $scopeAt = $installText.IndexOf('$scope = @(@(Get-MiosMsiRelatedProducts -UpgradeCode $package.UpgradeCode)')
    Check ($packageAt -gt $signerAt -and $packageAt -lt $removeAt -and $perUserAt -gt $removeAt -and $perUserAt -lt $msiAt -and $scopeAt -gt $msiAt -and
           $installText.Contains("Invoke-MiosMsiInstall -Path `$msi -Properties @('ALLUSERS=1', 'MSIINSTALLPERUSER=0')")) 'the package identity is read after the signer check; per-user removal precedes the per-machine install; the scope is checked after it'
    $msiexecText = (Get-Function $entryAst 'Invoke-MiosMsiInstall').Body.Extent.Text
    $infoText = (Get-Function $entryAst 'Get-MiosMsiPackageInfo').Body.Extent.Text
    $perUserText = (Get-Function $entryAst 'Remove-MiosPerUserPodman').Body.Extent.Text
    Check ($msiexecText.Contains("(@('/i', ('`"' + `$Path + '`"')) + @(`$Properties) + @('/qn', '/norestart'))") -and $infoText.Contains("@(`$Path, [int]0)") -and
           $perUserText.Contains("-Arguments @('/x', `$p.ProductCode, '/qn', '/norestart')") -and -not ($perUserText -match 'Invoke-Expression|\biex\b|UninstallString|cmd(\.exe)?\s+/c')) 'msiexec gets fixed properties; the MSI is opened read-only; per-user removal runs only msiexec /x {ProductCode}'
    $ensureResolveAt = $ensure.IndexOf('$machineClient = Resolve-MiosPodmanExe'); $wingetAt = $ensure.IndexOf('Get-Command winget')
    Check ($ensureResolveAt -ge 0 -and $ensureResolveAt -lt $wingetAt -and $ensure.Contains('$env:PATH = (Split-Path -Parent $machineClient) + '';'' + $env:PATH')) 'the user side adopts a per-machine client before any winget install and puts it first on PATH'
    $worker = ''; try { $worker = Get-MiosMachineWorkerScript -Source ([IO.File]::ReadAllText($Entry)) } catch { $worker = '' }
    $missingHelpers = @(@('Get-MiosMachinePodmanExe', 'Get-MiosMachinePodmanVersion', 'Get-MiosPodmanVersion', 'Get-MiosRequiredPodmanVersion', 'Get-MiosPinnedDownloadBytes',
        'Invoke-MiosMsiInstall', 'Install-MiosPodmanClient', 'Read-MiosPodmanUninstallEntries', 'Get-MiosOlderPodmanEntries', 'Get-MiosPodmanRemovalPlan',
        'Invoke-MiosPodmanRemoval', 'Remove-MiosOlderPodman', 'Get-MiosMachinePodmanPaths', 'Get-MiosMachinePath', 'Get-MiosMsiPackageInfo',
        'Get-MiosMsiRelatedProducts', 'Remove-MiosPerUserPodman') | Where-Object { $worker -notmatch ('(?m)^function ' + [regex]::Escape($_) + ' \{') })
    Check ([bool]$worker -and $missingHelpers.Count -eq 0) 'the elevated worker carries every Podman client helper'

    # --- The shipped template pin parses to the expected shapes ----------------------------------------------------------
    $script:vendorText = [IO.File]::ReadAllText($templateToml); $script:operatorText = ''
    $u = [string](Get-MiosTomlValue -Section 'bootstrap.prereqs' -Key 'podman_cli_msi_url' -Default '' -VendorOnly)
    $s = [string](Get-MiosTomlValue -Section 'bootstrap.prereqs' -Key 'podman_cli_msi_sha256' -Default '' -VendorOnly)
    $g = [string](Get-MiosTomlValue -Section 'bootstrap.prereqs' -Key 'podman_cli_msi_signer' -Default '' -VendorOnly)
    Check ($u -match '^https://github\.com/podman-container-tools/podman/releases/download/v\d+\.\d+\.\d+/podman-installer-windows-amd64\.msi$' -and
           $s -cmatch '^[0-9a-f]{64}$' -and $g.StartsWith('CN="Red Hat, LLC", OU=Podman, O="Red Hat, LLC"')) 'the template carries a parseable pinned MSI URL, sha256 and signer'

    Remove-Item Env:MIOS_FAKE_PODMAN_VERSION, Env:MIOS_FAKE_PODMAN_FLAG, Env:MIOS_FAKE_MARKER -ErrorAction SilentlyContinue
    $env:ProgramData = $savedProgramData
    Write-Host "PODMAN_CLIENT_ASSERTIONS $($script:checks)"
    return $script:fail
}

try {
    if (-not $PlantDefect) {
        $failures = Invoke-Checks $EntryPath $BuildPath
        if ($failures) { Write-Host "RESULT: FAIL ($failures checks)"; exit 1 }
        Write-Host 'RESULT: PASS (Podman client fixtures; fake podman, mocked download, signature and msiexec)'; exit 0
    }
    $baseline = Invoke-Checks $EntryPath $BuildPath
    if ($baseline) { Write-Host 'PODMAN_CLIENT_BASELINE_FAILED'; exit 1 }
    $plants = @(
        @{ Name = 'sha256 check removed'; File = 'entry'; Expected = 'a sha256 mismatch refuses before the MSI touches disk'; From = 'if ($actual -cne $sha) { throw'; To = 'if ($false) { throw' },
        @{ Name = 'signature check removed'; File = 'entry'; Expected = 'an MSI without a Valid signature refuses and installs nothing'; From = "if ([string]`$signature.Status -ne 'Valid') { throw `"The pinned Podman MSI signature"; To = "if (`$false) { throw `"The pinned Podman MSI signature" },
        @{ Name = 'signer check removed'; File = 'entry'; Expected = 'a valid signature from another signer refuses and installs nothing'; From = "if (`$subject -cne `$signer) { throw `"The pinned Podman MSI is signed by"; To = "if (`$false) { throw `"The pinned Podman MSI is signed by" },
        @{ Name = 'PATH resolution restored in the elevated check'; File = 'entry'; Expected = 'neither a podman planted on PATH nor a per-user profile copy is considered by the elevated check'
           From = "foreach (`$path in @(Get-MiosMachinePodmanPaths)) { if (Test-Path -LiteralPath `$path -PathType Leaf) { return `$path } }"
           To = "`$cmd = Get-Command podman -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1; if (`$cmd) { return [string]`$cmd.Source }; foreach (`$path in @(Get-MiosMachinePodmanPaths)) { if (Test-Path -LiteralPath `$path -PathType Leaf) { return `$path } }" },
        @{ Name = 'a profile path accepted as a machine path'; File = 'entry'; Expected = 'neither a podman planted on PATH nor a per-user profile copy is considered by the elevated check'
           From = "return @((Join-Path `${env:ProgramFiles} 'Podman\podman.exe'), "; To = "return @((Join-Path `$env:LOCALAPPDATA 'Programs\Podman\podman.exe'), (Join-Path `${env:ProgramFiles} 'Podman\podman.exe'), " },
        @{ Name = 'ALLUSERS=1 dropped'; File = 'entry'; Expected = 'the verified MSI is installed per-machine (ALLUSERS=1 MSIINSTALLPERUSER=0) and Windows Installer reports it per-machine'
           From = "-Properties @('ALLUSERS=1', 'MSIINSTALLPERUSER=0')"; To = '-Properties @()' },
        @{ Name = 'MSIINSTALLPERUSER override dropped (ALLUSERS=1 only)'; File = 'entry'; Expected = 'the per-machine install selects the machine PATH component, with no PATH warning'
           From = "-Properties @('ALLUSERS=1', 'MSIINSTALLPERUSER=0')"; To = "-Properties @('ALLUSERS=1')" },
        @{ Name = 'per-user leftover not removed'; File = 'entry'; Expected = "run 5's per-user 6.2 of the elevating account is removed by its ProductCode, then the MSI installs per-machine"
           From = "`$removed += Remove-MiosPerUserPodman -UpgradeCode `$package.UpgradeCode"; To = '$removed += 0' },
        @{ Name = 'scope check removed'; File = 'entry'; Expected = 'an install Windows Installer reports per-user is refused'
           From = "if (-not @(`$scope | Where-Object { `$_.AssignmentType -eq '1' }).Count) {"; To = "if (`$false) {" },
        @{ Name = 'RelatedProducts not filtered to AssignmentType 0'; File = 'entry'; Expected = "a per-machine product of the family is left to the MSI's own upgrade"
           From = "`$perUser = @(`$related | Where-Object { `$_.AssignmentType -eq '0' })"; To = '$perUser = @($related)' },
        @{ Name = 'machine exe signer check removed'; File = 'entry'; Expected = 'a machine Podman client from another signer is never run elevated'; From = "if (`$subject -cne `$Signer) { throw `"The machine Podman client"; To = "if (`$false) { throw `"The machine Podman client" },
        @{ Name = 'machine exe signature check removed'; File = 'entry'; Expected = 'an unsigned machine Podman client is never run elevated'; From = "if ([string]`$signature.Status -ne 'Valid') { throw `"The machine Podman client"; To = "if (`$false) { throw `"The machine Podman client" },
        @{ Name = 'guard removed'; File = 'build'; Expected = 'a client without --update-connection stops before init with version, path, requirement and remedy'; From = "if (`$help -match '(?m)^\s*(?:-\w,\s*)?--update-connection\b') { return }"; To = 'return' },
        @{ Name = 'guard call removed'; File = 'build'; Expected = 'the guard runs after the machine-os tag resolves and before the image download and init'; From = '    Assert-MiosPodmanInitSupport -RequiredTag $machineTag'; To = '    $null = $machineTag' },
        @{ Name = 'publisher filter removed'; File = 'entry'; Expected = 'Podman Desktop, a non-Red Hat Podman and a current 6.2 entry are never touched'
           From = "`$_.DisplayName -ieq 'Podman' -and `$_.Publisher -cin `$publishers -and"; To = "`$_.DisplayName -ieq 'Podman' -and" },
        @{ Name = 'version guard removed'; File = 'entry'; Expected = 'Podman Desktop, a non-Red Hat Podman and a current 6.2 entry are never touched'
           From = "(New-Object Version ([int]`$Matches[1]), ([int]`$Matches[2])) -lt `$Required })"; To = "`$true })" },
        @{ Name = 'bundle signer check removed'; File = 'entry'; Expected = 'a foreign-signed bundle exe refuses with nothing removed'
           From = "if (`$subject -cne `$Signer) { throw `"The Podman bundle"; To = "if (`$false) { throw `"The Podman bundle" },
        @{ Name = 'Package Cache path check removed'; File = 'entry'; Expected = 'a bundle exe outside Package Cache refuses with nothing removed'
           From = "if (`$full -ine `$exe -or -not `$full.StartsWith(`$cacheRoot, [StringComparison]::OrdinalIgnoreCase)) { throw"; To = "if (`$false) { throw" },
        @{ Name = 'registry arguments executed'; File = 'entry'; Expected = 'an older bundle and its MSI are removed in order with fixed arguments, then 6.2 is installed'
           From = "Arguments = @('/uninstall', '/quiet', '/norestart')"; To = 'Arguments = @(([string]$e.QuietUninstallString -replace ''^"[^"]*"\s*'', '''') -split ''\s+'')' },
        @{ Name = 'pin read from the operator layer'; File = 'entry'; Expected = 'the pinned MSI URL comes from the system SSOT, never the operator layer'; From = "-Key 'podman_cli_msi_url' -Default '' -VendorOnly"; To = "-Key 'podman_cli_msi_url' -Default ''" }
    )
    $caught = 0; $index = 0
    foreach ($plant in $plants) {
        $index++
        $source = if ($plant.File -eq 'entry') { $EntryPath } else { $BuildPath }
        $text = [IO.File]::ReadAllText($source)
        $count = ([regex]::Matches($text, [regex]::Escape($plant.From))).Count
        if ($count -ne 1) { throw "Missing or ambiguous defect anchor: $($plant.Name) (found $count)" }
        $copy = Join-Path $scratch ('planted-' + $index + '-' + [IO.Path]::GetFileName($source))
        [IO.File]::WriteAllText($copy, $text.Replace($plant.From, $plant.To), (New-Object Text.UTF8Encoding($true)))
        $entry = $EntryPath; $build = $BuildPath
        if ($plant.File -eq 'entry') { $entry = $copy } else { $build = $copy }
        $null = Invoke-Checks $entry $build
        $detected = $script:failedChecks.Contains($plant.Expected)
        Write-Host ('  {0} planted defect caught: {1}' -f $(if ($detected) { 'PASS' } else { 'FAIL' }), $plant.Name)
        if ($detected) { $caught++ }
    }
    if ($caught -eq $plants.Count) { Write-Host "RESULT: PASS (every planted defect was caught: $caught/$($plants.Count))"; exit 0 }
    Write-Host "RESULT: FAIL (planted defects caught: $caught/$($plants.Count))"; exit 1
} finally {
    Remove-Item Env:MIOS_FAKE_PODMAN_VERSION, Env:MIOS_FAKE_PODMAN_FLAG, Env:MIOS_FAKE_MARKER -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
