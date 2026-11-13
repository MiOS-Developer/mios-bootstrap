# AI-hint: Pure XML compatibility renderer over the layered MiOS credential SSOT; no host mutation or image build.
# AI-related: MiOS-Provision.lib.ps1, usr/lib/mios/mios_credentials.py, usr/libexec/mios/win/xbox/build.py
# AI-functions: ConvertTo-UnattendPassword, New-MiOSAutounattendXml
#Requires -Version 5.1
<#
.SYNOPSIS
    Render a private autounattend.xml from layered MiOS configuration.
.DESCRIPTION
    XML-only compatibility entry. MiOS-Xbox images use the canonical build.py
    pipeline. A validated private -ResolvedJson projection wins over credential
    fields in a Bootstrap vendor fork. Missing credentials refuse before output.
    FirstLogon and specialize payloads are UTF-16LE bytes in urn:mios:unattend
    extensions. Short hash-bound launchers read the Windows Setup Panther cache.
    Rendering never runs them; cache retention needs a Windows installation trial.
.PARAMETER OutXml
    Credential-bearing output, restricted to the current user/system administrators.
.PARAMETER ObfuscatePasswords
    Windows Setup Base64 obscuration; this is not encryption. Keep media private.
.PARAMETER SourceIso
    Retired; any ISO or legacy injection parameter refuses before SSOT reads.
.PARAMETER ResolvedJson
    Private mios-resolved-credentials/1 file produced by the canonical resolver.
#>
[CmdletBinding()]
param(
    [string]$TomlPath,
    [string]$OutXml = (Join-Path (Get-Location) 'autounattend.xml'),
    [string]$SourceIso,
    [string]$OutIso,
    [string]$WinutilToolsDir,
    [switch]$FullDiskWindows,
    [switch]$ObfuscatePasswords,
    [string]$BootstrapUrl,
    [string]$Edition,
    [string]$ResolvedJson
)
if ($SourceIso -or $OutIso) { throw 'MiOS-Xbox: ISO generation through this legacy entry is retired; use usr/libexec/mios/win/xbox/build.py.' }
if ($WinutilToolsDir) { throw 'MiOS-Xbox: legacy image injection is retired; this entry renders XML only.' }
$ErrorActionPreference = 'Stop'

$CANONICAL_BOOTSTRAP = 'https://raw.githubusercontent.com/mios-dev/mios-bootstrap/main/Get-MiOS.ps1'

# Shared pure render functions; actual host changes belong to the explicit live provision entry.
. (Join-Path $PSScriptRoot 'MiOS-Provision.lib.ps1')


function ConvertTo-UnattendPassword {
    # Emits the <Value>/<PlainText> pair for a LocalAccount/AutoLogon password.
    # Base64 form per Windows Setup: Base64( UTF16LE( password + "Password" ) ),
    # PlainText=false. Otherwise PlainText=true.
    param([string]$Pw,[bool]$Obfuscate)
    if ($Obfuscate) {
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Pw + 'Password'))
        return @{ Value = $enc; PlainText = 'false' }
    }
    return @{ Value = [Security.SecurityElement]::Escape($Pw); PlainText = 'true' }
}

function New-MiOSAutounattendXml {
    param($Toml)

    # Credentials are validated before any output or host-side work.
    $credentials = Resolve-MiOSCredentials -Toml $Toml
    # --- Resolve SSOT ------------------------------------------------------
    $computerName = Get-Toml $Toml 'autounattend.computer_name' (Get-Toml $Toml 'identity.hostname' 'MIOS')
    $timezone     = Get-Toml $Toml 'autounattend.timezone'      (Get-Toml $Toml 'locale.timezone' 'UTC')
    $uiLang       = Get-Toml $Toml 'autounattend.ui_language'   'en-US'
    $inputLocale  = Get-Toml $Toml 'autounattend.input_locale'  '0409:00000409'
    $edition      = Get-Toml $Toml 'autounattend.image_name'    'Windows 11 Pro'
    $productKey   = Get-Toml $Toml 'autounattend.product_key'   'VK7JG-NPHTM-C97JM-9MPGT-3V66T'  # generic Pro
    $bypassHw     = (Get-Toml $Toml 'autounattend.bypass_hardware_checks' 'true') -match '^(true|1|yes)$'
    $runBootstrap = (Get-Toml $Toml 'autounattend.run_bootstrap' 'true') -match '^(true|1|yes)$'
    $bootUrl      = if ($BootstrapUrl) { $BootstrapUrl } else { Get-Toml $Toml 'autounattend.bootstrap_url' $CANONICAL_BOOTSTRAP }
    $cGb          = [int](Get-Toml $Toml 'autounattend.c_partition_gb' '128')  # Windows C: size; MiOS M:\ gets the rest
    $layoutTree   = (Get-Toml $Toml 'autounattend.layout.linux_tree' 'etc usr var home opt srv tmp bin lib root').Trim()

    # Windows <TimeZone> takes a Windows tz id (tzutil), NOT an IANA name. Map the
    # common IANA ids; an unmapped '/'-style value falls back to UTC (a valid Windows
    # id). A plain value (already a Windows id, or the UTC default) passes through.
    $_iana = @{ 'America/New_York'='Eastern Standard Time'; 'America/Chicago'='Central Standard Time'; 'America/Denver'='Mountain Standard Time'; 'America/Los_Angeles'='Pacific Standard Time'; 'America/Phoenix'='US Mountain Standard Time'; 'Europe/London'='GMT Standard Time'; 'Europe/Paris'='Romance Standard Time'; 'Europe/Berlin'='W. Europe Standard Time'; 'Asia/Tokyo'='Tokyo Standard Time'; 'Australia/Sydney'='AUS Eastern Standard Time' }
    if ($timezone -match '/') { $timezone = if ($_iana.ContainsKey($timezone)) { $_iana[$timezone] } else { 'UTC' } }
    # XML-escape scalars that land in the answer-file here-string (an SSOT value with
    # & / < / > would malform the XML). $bootUrl is escaped at its FirstLogon use.
    $computerName = [Security.SecurityElement]::Escape($computerName)
    $timezone     = [Security.SecurityElement]::Escape($timezone)
    $uiLang       = [Security.SecurityElement]::Escape($uiLang)
    $inputLocale  = [Security.SecurityElement]::Escape($inputLocale)
    $edition      = [Security.SecurityElement]::Escape($edition)
    $productKey   = [Security.SecurityElement]::Escape($productKey)

    # Account names/passwords and console sign-in come from the one layered resolver.
    $accounts = @($credentials.accounts)
    $svcUser = [string]$credentials.service.user

    $localAccountsXml = New-Object System.Text.StringBuilder
    foreach ($a in $accounts) {
        if ([string]$a.name -eq $svcUser) { continue }
        $name  = [Security.SecurityElement]::Escape([string]$a.name)
        # Strip stylistic 'quoted-word' emphasis from a display name so an SSOT value
        # like "'MiOS' User" renders clean on the logon screen (-> "MiOS User"), without
        # destroying legitimate apostrophes (O'Brien has no closing quote, so it is kept).
        $dispRaw = [string]($a.display_name | ForEach-Object { if ($_) { $_ } else { $a.name } })
        $dispRaw = ($dispRaw -replace "'([^']+)'", '$1').Trim()
        $disp  = [Security.SecurityElement]::Escape($dispRaw)
        $group = [string]($a.group | ForEach-Object { if ($_) { $_ } else { 'Users' } })
        $pw    = ConvertTo-UnattendPassword -Pw ([string]$a.password) -Obfuscate:$ObfuscatePasswords
        [void]$localAccountsXml.Append(@"
          <LocalAccount wcm:action="add">
            <Name>$name</Name>
            <DisplayName>$disp</DisplayName>
            <Group>$group</Group>
            <Password>
              <Value>$($pw.Value)</Value>
              <PlainText>$($pw.PlainText)</PlainText>
            </Password>
          </LocalAccount>

"@)
    }

    # The console account is independent of the service account and keeps the
    # resolved persistent policy. A missing or conflicting credential already refused.
    $alUser = [string]$credentials.autologon.user
    $alPwRaw = [string]$credentials.autologon.password
    $firstPw = ConvertTo-UnattendPassword -Pw $alPwRaw -Obfuscate:$ObfuscatePasswords
    $firstName = [Security.SecurityElement]::Escape($alUser)
    $firstEnabled = if ($credentials.autologon.enable) { 'true' } else { 'false' }
    $firstCount = [string]$credentials.autologon.count

    # --- FirstLogonCommands (USER context): full layout creation, offline branding,
    #     user preferences, Xbox mode, custom scripts, and the nested bootstrap.
    $firstLogonXml = ''
    $_flc = New-Object System.Text.StringBuilder
    $_flOrd = 1
    foreach ($grp in (New-MiOSProvisionCommands -Toml $Toml)) {
        foreach ($cmd in @($grp.Commands)) {
            [void]$_flc.AppendLine(('        <SynchronousCommand wcm:action="add"><Order>{0}</Order><CommandLine>cmd /c {1}</CommandLine><Description>{2}</Description></SynchronousCommand>' -f $_flOrd, [Security.SecurityElement]::Escape($cmd), [Security.SecurityElement]::Escape($grp.Description)))
            $_flOrd++
        }
    }
    # Run the custom FirstLogon.ps1 script containing guest tools installs
    $flCmd = "powershell.exe -WindowStyle Normal -ExecutionPolicy Unrestricted -NoProfile -File C:\Windows\Setup\Scripts\FirstLogon.ps1"
    [void]$_flc.AppendLine(('        <SynchronousCommand wcm:action="add"><Order>{0}</Order><CommandLine>{1}</CommandLine><Description>Custom FirstLogon defaults</Description></SynchronousCommand>' -f $_flOrd, [Security.SecurityElement]::Escape($flCmd)))
    $_flOrd++

    # Expire passwords of all local interactive/non-service accounts to force rotation on next logon
    $svcUser = [string]$credentials.service.user
    # svc_user IS the renamed built-in Administrator (RID 500) = the MiOS AI admin; its
    # account description is SSOT-driven too and stamped onto RID-500 in the specialize pass.
    $svcDesc = Get-Toml $Toml 'autounattend.service.svc_description' 'MiOS AI -- autonomous system administrator (the renamed built-in Administrator, RID 500)'
    $expireCmd = 'powershell.exe -NoProfile -Command "Get-LocalUser | Where-Object { $_.Name -ne ''Administrator'' -and $_.Name -ne ''' + $svcUser + ''' -and $_.Name -ne ''' + $alUser.Replace("'", "''") + ''' -and $_.Name -ne ''Guest'' -and $_.Name -ne ''DefaultAccount'' -and $_.Name -ne ''WDAGUtilityAccount'' } | Set-LocalUser -PasswordExpired $true"'
    [void]$_flc.AppendLine(('        <SynchronousCommand wcm:action="add"><Order>{0}</Order><CommandLine>{1}</CommandLine><Description>Expire first-boot temporary passwords</Description></SynchronousCommand>' -f $_flOrd, [Security.SecurityElement]::Escape($expireCmd)))
    $_flOrd++


    if ($runBootstrap) {
        # Escape $bootUrl -- an SSOT override with '&' would otherwise break the XML.
        $_url = [Security.SecurityElement]::Escape($bootUrl)
        $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command &quot;`$env:MIOS_AGREEMENT_ACK='accepted'; `$env:MIOS_AGREEMENT_BANNER='silent'; `$env:MIOS_PROMPT_TIMEOUT='1'; `$d = (Get-Volume | Where-Object { `$_.FileSystemLabel -in 'MiOS-Repo','MiOS-Data' } | Select-Object -First 1).DriveLetter; if (`$d -and (Test-Path `&quot;`$(`$d):\MiOS-Field.bat`&quot;)) { &amp; `&quot;`$(`$d):\MiOS-Field.bat`&quot; } else { irm $_url | iex }&quot;"
        [void]$_flc.AppendLine(('        <SynchronousCommand wcm:action="add"><Order>{0}</Order><CommandLine>{1}</CommandLine><Description>MiOS bootstrap (nested offline USB / irm|iex)</Description><RequiresUserInput>false</RequiresUserInput></SynchronousCommand>' -f $_flOrd, $cmd))
        $_flOrd++
    }
    # Complete ordered scripts stay in the namespaced extension, rather than in
    # a command line that can exceed CreateProcessW's UTF-16 length limit.
    [xml]$firstCommands = ('<Commands xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">' + $_flc.ToString() + '</Commands>')
    $firstScriptLines = @('$ErrorActionPreference = ''Stop''')
    foreach ($entry in @($firstCommands.Commands.SynchronousCommand)) {
        $firstScriptLines += ('& $env:ComSpec /d /s /c ''' + ([string]$entry.CommandLine).Replace("'", "''") + '''')
    }
    if ($credentials.autologon.persistent) {
        $firstScriptLines += '& $env:ComSpec /d /s /c ''reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoLogonCount /f'''
    }
    $firstScript = ($firstScriptLines -join "`r`n") + "`r`n"
    $firstPayload = New-MiOSUnattendPayload -Name FirstLogonScript -Script $firstScript
    $firstScriptB64 = $firstPayload.Base64
    $firstLogonXml = ('      <FirstLogonCommands><SynchronousCommand wcm:action="add"><Order>1</Order><CommandLine>{0}</CommandLine><Description>MiOS first logon from the layered SSOT</Description></SynchronousCommand></FirstLogonCommands>' -f [Security.SecurityElement]::Escape($firstPayload.CommandLine))

    # --- Optional Win11 hardware-check bypass (windowsPE) -------------------
    $bypassXml = ''
    if ($bypassHw) {
        $bypassXml = @"
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add"><Order>1</Order><Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add"><Order>2</Order><Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add"><Order>3</Order><Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassRAMCheck /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add"><Order>4</Order><Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassStorageCheck /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add"><Order>5</Order><Path>reg add HKLM\SYSTEM\Setup\LabConfig /v BypassCPUCheck /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add"><Order>6</Order><Path>reg add HKLM\SYSTEM\Setup\MoSetup /v AllowUpgradesWithUnsupportedTPMOrCPU /t REG_DWORD /d 1 /f</Path></RunSynchronousCommand>
      </RunSynchronous>
"@
    }

    # --- Disk layout: standard (C: only) OR carve M: at install -------------
    if (-not $FullDiskWindows) {
        # MiOS carve: C: = $cGb GB (Windows), the REST of the disk -> MiOS M:\ (MIOS-DEV).
        $cMb = $cGb * 1024
        $diskXml = @"
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>512</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Size>$cMb</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>4</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>3</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>4</Order><PartitionID>4</PartitionID><Format>NTFS</Format><Label>MIOS-DEV</Label><Letter>M</Letter></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
"@
        $installPartId = 3
    } else {
        $diskXml = @"
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>512</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>3</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
"@
        $installPartId = 3
    }

    # --- specialize (SYSTEM) provisioner: boot-time services ---------------------
    # MiOS as boot-time SYSTEM services (up BEFORE logon): enable WSL2, make svc_user
    # BE the MiOS AI admin (the renamed built-in Administrator / RID 500), enable RDP,
    # register the MiOS-Host ONSTART task. Runs in the Microsoft-Windows-Deployment
    # RunSynchronous below.
    # NB: the per-USER Linux-like layout is DELIBERATELY NOT here -- specialize runs
    # as SYSTEM, where HKCU=HKU\S-1-5-18 and %USERPROFILE%=systemprofile, so the
    # layout would land on the wrong profile. It is emitted in FirstLogonCommands
    # (user context) below instead.
    $_preOobe = New-Object System.Text.StringBuilder
    $_ord = 5
    foreach ($sc in @(New-MiOSHostServiceCommands -Toml $Toml)) {
        [void]$_preOobe.AppendLine(('        <RunSynchronousCommand wcm:action="add"><Order>{0}</Order><Path>cmd /c {1}</Path><Description>MiOS boot-time service plane (pre-logon)</Description></RunSynchronousCommand>' -f $_ord, [Security.SecurityElement]::Escape($sc)))
        $_ord++
    }
    # --- MiOS AI identity: the built-in Administrator (RID 500) IS svc_user ---------
    # RID-500 rename + svc_description are DELIBERATELY NOT stamped in `specialize`.
    # Identity mutation in the boot-critical pass can strand it ("The computer restarted
    # unexpectedly...") and is redundant: SetupComplete.cmd renames RID-500 + sets the SSOT
    # description POST-OOBE, where Windows Setup ignores exit codes and a failure cannot
    # abort the install (SetupComplete.cmd L66-84; New-MiOSISO substitutes __SVCUSER__ /
    # __SVCPW__ / __SVCDESC__ from mios.toml). `specialize` stays identity-mutation-free.
    [xml]$specialCommands = ('<Commands xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">' + $_preOobe.ToString() + '</Commands>')
    $specialScriptLines = @('$ErrorActionPreference = ''Stop''')
    foreach ($entry in @($specialCommands.Commands.RunSynchronousCommand)) {
        $command = ([string]$entry.Path) -replace '^cmd /c ', ''
        $specialScriptLines += ('& $env:ComSpec /d /s /c ''' + $command.Replace("'", "''") + '''')
    }
    $specialScript = ($specialScriptLines -join "`r`n") + "`r`n"
    $specialPayload = New-MiOSUnattendPayload -Name SpecializeScript -Script $specialScript
    $specialScriptB64 = $specialPayload.Base64
    $preOobeXml = ('        <RunSynchronousCommand wcm:action="add"><Order>5</Order><Path>{0}</Path><Description>MiOS service commands from the layered SSOT</Description></RunSynchronousCommand>' -f [Security.SecurityElement]::Escape($specialPayload.CommandLine))

    # Boot-into-Xbox FSE: the Microsoft-Windows-Gaming-Configuration component
    # (StartupToGamingHome + GamingHomeApp) launches the full-screen Xbox home on
    # startup. Emitted only when [autounattend.xbox].enable + .start_on_startup.
    $gamingXml = ''
    if ((Get-Toml $Toml 'autounattend.xbox.enable' 'false') -match '^(?i:true|1|yes)$' -and
        (Get-Toml $Toml 'autounattend.xbox.start_on_startup' 'true') -match '^(?i:true|1|yes)$') {
        $_homeApp = Get-Toml $Toml 'autounattend.xbox.home_app' 'Microsoft.GamingApp_8wekyb3d8bbwe!Microsoft.Xbox.App'
        $gamingXml = @"
    <component name="Microsoft-Windows-Gaming-Configuration" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <StartupToGamingHome>true</StartupToGamingHome>
      <GamingHomeApp>$([Security.SecurityElement]::Escape($_homeApp))</GamingHomeApp>
    </component>
"@
    }

    # --- Full document -----------------------------------------------------
    return @"
<?xml version="1.0" encoding="utf-8"?>
<!-- Generated by New-MiOSAutounattend.ps1 from mios.toml SSOT. Nested MiOS
     irm|iex runs Get-MiOS.ps1 at first logon. Passwords are $(if($ObfuscatePasswords){'Base64-obscured (NOT encrypted)'}else{'PLAINTEXT'}); treat as first-boot temporary. -->
<unattend xmlns="urn:schemas-microsoft-com:unattend"
          xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-SecureStartup-FilterDriver" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <PreventDeviceEncryption>true</PreventDeviceEncryption>
    </component>
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>$uiLang</UILanguage></SetupUILanguage>
      <InputLocale>$inputLocale</InputLocale>
      <SystemLocale>$uiLang</SystemLocale>
      <UILanguage>$uiLang</UILanguage>
      <UserLocale>$uiLang</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
$bypassXml
      <UserData>
        <ProductKey><Key>$productKey</Key><WillShowUI>OnError</WillShowUI></ProductKey>
        <AcceptEula>true</AcceptEula>
      </UserData>
$diskXml
      <ImageInstall>
        <OSImage>
          <InstallTo><DiskID>0</DiskID><PartitionID>$installPartId</PartitionID></InstallTo>
          <InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/NAME</Key><Value>$edition</Value></MetaData></InstallFrom>
          <Compact>true</Compact>
        </OSImage>
      </ImageInstall>
    </component>
  </settings>
  <settings pass="offlineServicing">
    <component name="Microsoft-Windows-SecureStartup-FilterDriver" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <PreventDeviceEncryption>true</PreventDeviceEncryption>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-SecureStartup-FilterDriver" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <PreventDeviceEncryption>true</PreventDeviceEncryption>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>$computerName</ComputerName>
      <RegisteredOwner>MiOS</RegisteredOwner>
      <RegisteredOrganization>MiOS</RegisteredOrganization>
      <TimeZone>$timezone</TimeZone>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add"><Order>1</Order><Path>cmd /c reg add HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f || exit 0</Path><Description>Enable NTFS long paths for MiOS</Description></RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add"><Order>2</Order><Path>cmd /c reg add HKLM\SYSTEM\CurrentControlSet\Control\BitLocker /v PreventDeviceEncryption /t REG_DWORD /d 1 /f || exit 0</Path><Description>Disable BitLocker Automatic Device Encryption</Description></RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add"><Order>3</Order><Path>cmd /c reg add HKLM\SOFTWARE\Policies\Microsoft\FVE /v PreventDeviceEncryption /t REG_DWORD /d 1 /f || exit 0</Path><Description>Disable BitLocker Group Policy Encryption</Description></RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add"><Order>4</Order><Path>cmd /c manage-bde -off C: || exit 0</Path><Description>Turn off BitLocker on SystemDrive</Description></RunSynchronousCommand>
$preOobeXml
      </RunSynchronous>
    </component>
$gamingXml  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>$inputLocale</InputLocale>
      <SystemLocale>$uiLang</SystemLocale>
      <UILanguage>$uiLang</UILanguage>
      <UserLocale>$uiLang</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
        <!-- NB: do NOT set SkipMachineOOBE/SkipUserOOBE. They are deprecated and
             SUPPRESS FirstLogonCommands (so the Linux-like layout + the nested
             irm|iex MiOS bootstrap never fire). The Hide* pages above + the
             LocalAccount + AutoLogon below already auto-complete OOBE, and
             leaving the OOBE flow intact is what lets FirstLogonCommands run. -->
      </OOBE>
      <UserAccounts>
        <LocalAccounts>
$($localAccountsXml.ToString())        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Enabled>$firstEnabled</Enabled>
        <Username>$firstName</Username>
        <LogonCount>$firstCount</LogonCount>
        <Password><Value>$($firstPw.Value)</Value><PlainText>$($firstPw.PlainText)</PlainText></Password>
      </AutoLogon>
$firstLogonXml
    </component>
  </settings>
  <Extensions xmlns="urn:mios:unattend">
    <FirstLogonScript>$firstScriptB64</FirstLogonScript>
    <SpecializeScript>$specialScriptB64</SpecializeScript>
  </Extensions>
</unattend>
"@
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if (-not $TomlPath) {
    foreach ($c in @('M:\etc\mios\mios.toml','M:\usr\share\mios\mios.toml',
                     (Join-Path $PSScriptRoot '..\..\mios.toml'))) {
        if (Test-Path -LiteralPath $c) { $TomlPath = (Resolve-Path $c).Path; break }
    }
}
# A caller-supplied -TomlPath may be relative. Read-MiosToml reads via .NET file
# APIs ([IO.File]::ReadAllLines), whose working directory is the PROCESS start dir,
# NOT PowerShell's $PWD -- so a relative path after `cd` resolves against the wrong
# root (CI runs `cd field/autounattend; -TomlPath ../../mios.toml`, which .NET
# resolved to D:\a\mios.toml and failed). Resolve against $PWD to an absolute path.
if ($TomlPath -and -not [System.IO.Path]::IsPathRooted($TomlPath)) {
    $resolved = Resolve-Path -LiteralPath $TomlPath -ErrorAction SilentlyContinue
    if ($resolved) { $TomlPath = $resolved.Path }
}
# Same $PWD-vs-.NET-cwd hazard for the OUTPUT: [IO.File]::WriteAllText resolves a
# relative -OutXml against the process cwd, not $PWD -- so `cd field/autounattend;
# -OutXml ./autounattend.xml` would write to the wrong dir and the CI verify step
# (cd field/autounattend; Test-Path ./autounattend.xml) would not find it. Anchor a
# relative -OutXml to $PWD.
if (-not [System.IO.Path]::IsPathRooted($OutXml)) {
    $OutXml = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $OutXml))
}
Write-Host "[*] Reading SSOT: $(if ($TomlPath) { $TomlPath } else { '(layered resolver inputs)' })" -ForegroundColor DarkGray
$toml = Read-MiosToml -Path $TomlPath -ResolvedJson $ResolvedJson
$toml = Apply-MiosEdition -T $toml -Edition $Edition

$xml = New-MiOSAutounattendXml -Toml $toml
Write-MiOSPrivateText -Path $OutXml -Text $xml
Write-Host "[+] autounattend.xml written: $OutXml" -ForegroundColor Green

