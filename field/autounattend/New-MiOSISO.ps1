# AI-hint: RETIRED for MiOS-Xbox images (xb-20). Refuses before SSOT reads, output creation or host changes.
# AI-related: usr/libexec/mios/win/xbox/build.py
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$SourceIso,
    [string]$OutIso,
    [string]$TomlPath,
    [string]$MergedPreset = '',
    [string]$WorkDir,
    [switch]$SkipServicing,
    [switch]$Esd,
    [string]$Edition
)
throw 'MiOS-Xbox: this legacy image entry is retired; use usr/libexec/mios/win/xbox/build.py.'

# Retained pure compatibility renderer: callers may extract this function AST.
# The retired script never invokes it or builds an image.
function Set-MiOSProvisionWiring {
    param([string]$Mount, [string]$ScriptsDst, $Toml)
    if ((Get-Toml $Toml 'autounattend.provision.enable' 'true') -notmatch '^(?i:true|1|yes)$') { return }
    $credential = Resolve-MiOSCredentials -Toml $Toml
    if (-not $credential.service.enable) { throw 'MiOS SSOT: autounattend.service.enable is required for provision wiring.' }
    function CmdValue([string]$Value, [string]$Key) {
        if ($Value -match '[\x00-\x1f\x7f"]') { throw "MiOS SSOT: $Key is not representable in this retired batch compatibility output." }
        return $Value.Replace('%', '%%')
    }
    $svcUser = CmdValue $credential.service.user 'autounattend.service.svc_user'
    $svcPass = CmdValue $credential.service.password 'autounattend.service.svc_password'
    $deskUser = CmdValue $credential.autologon.user 'autounattend.autologon_user'
    $deskPw = CmdValue $credential.autologon.password 'autounattend.autologon_user password'
    $setupCount = [int](Get-Toml $Toml 'autounattend.provision.autologon_count' '6')
    if ($setupCount -lt 1) { throw 'MiOS SSOT: autounattend.provision.autologon_count must be positive.' }
    $enabled = [int][bool]$credential.autologon.enable
    $persistent = [int][bool]$credential.autologon.persistent
    $finalCount = [int]$credential.autologon.count
    $p = New-Object System.Collections.Generic.List[string]
    $p.Add('@echo off')
    $p.Add('setlocal DisableDelayedExpansion')
    $p.Add('chcp 65001 >nul')
    $p.Add('rem Private credential-bearing compatibility output; not a MiOS-Xbox image builder.')
    $p.Add('set "LOG=%WINDIR%\Temp\mios-setupcomplete.log"')
    $p.Add('set "MIOSPD=%ProgramData%\MiOS"')
    $p.Add('set "SVCUSER=%~1"')
    $p.Add('set "SVCPW=%~2"')
    $p.Add(('if "%SVCUSER%"=="" set "SVCUSER={0}"' -f $svcUser))
    $p.Add(('if "%SVCPW%"=="" set "SVCPW={0}"' -f $svcPass))
    $p.Add(('set "ALUSER={0}"' -f $deskUser))
    $p.Add(('set "ALPW={0}"' -f $deskPw))
    $p.Add('if not exist "%MIOSPD%\MiOS-Provision.ps1" exit /b 1')
    # Protect the handover key before storing its credential (SYSTEM/admin only).
    $acl = '$p=''HKLM:\SOFTWARE\MiOS\AutoLogon''; New-Item -Path $p -Force | Out-Null; $a=New-Object System.Security.AccessControl.RegistrySecurity; $a.SetAccessRuleProtection($true,$false); foreach($s in @(''S-1-5-18'',''S-1-5-32-544'')) { $sid=New-Object System.Security.Principal.SecurityIdentifier($s); $a.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($sid,''FullControl'',''ContainerInherit'',''None'',''Allow''))) }; Set-Acl -Path $p -AclObject $a'
    $p.Add(('powershell.exe -NoProfile -NonInteractive -Command "{0}" >nul 2>&1 || exit /b 1' -f $acl))
    $p.Add('reg add "HKLM\SOFTWARE\MiOS\AutoLogon" /v User /t REG_SZ /d "%ALUSER%" /f >nul || exit /b 1')
    $p.Add('reg add "HKLM\SOFTWARE\MiOS\AutoLogon" /v Password /t REG_SZ /d "%ALPW%" /f >nul || exit /b 1')
    $p.Add(('reg add "HKLM\SOFTWARE\MiOS\AutoLogon" /v Enabled /t REG_DWORD /d {0} /f >nul || exit /b 1' -f $enabled))
    $p.Add(('reg add "HKLM\SOFTWARE\MiOS\AutoLogon" /v Persistent /t REG_DWORD /d {0} /f >nul || exit /b 1' -f $persistent))
    $p.Add(('reg add "HKLM\SOFTWARE\MiOS\AutoLogon" /v Count /t REG_DWORD /d {0} /f >nul || exit /b 1' -f $finalCount))
    $p.Add('schtasks /create /tn "MiOS-Setup-Driver" /sc MINUTE /mo 1 /rl HIGHEST /ru "%SVCUSER%" /rp "%SVCPW%" /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -File %MIOSPD%\MiOS-Provision.ps1" /f >nul 2>&1 || exit /b 1')
    $p.Add('reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f >nul || exit /b 1')
    $p.Add('reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /t REG_SZ /d "%SVCUSER%" /f >nul || exit /b 1')
    $p.Add('reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName /t REG_SZ /d "." /f >nul || exit /b 1')
    $p.Add('reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d "%SVCPW%" /f >nul || exit /b 1')
    $p.Add(('reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoLogonCount /t REG_DWORD /d {0} /f >nul || exit /b 1' -f $setupCount))
    $p.Add('reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "MiOS-SetupExperience" /t REG_SZ /d "powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File %MIOSPD%\MiOS-SetupExperience.ps1" /f >nul || exit /b 1')
    $p.Add('schtasks /run /tn "MiOS-Setup-Driver" >nul 2>&1')
    $p.Add('exit /b %ERRORLEVEL%')
    Write-MiOSPrivateText -Path (Join-Path $ScriptsDst 'mios-provision.cmd') -Text (($p -join "`r`n") + "`r`n")
}
