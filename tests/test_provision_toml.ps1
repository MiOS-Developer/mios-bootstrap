# Regression fixtures for the render-only provisioning TOML compatibility view.
# Run with -VendorToml <MiOS>/usr/share/mios/mios.toml to also read the full vendor.
#Requires -Version 5.1
[CmdletBinding()]
param([string]$VendorToml)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../field/autounattend/MiOS-Provision.lib.ps1')
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mios-toml-fixture-' + [Guid]::NewGuid().ToString('N') + '.toml')
$script:assertions = 0
function Assert-True {
    param([bool]$Value, [string]$Label)
    if (-not $Value) { throw "Provision TOML regression: $Label" }
    $script:assertions++
}
function Read-Fixture {
    param([string]$Text, [switch]$ProjectedCredentials)
    [IO.File]::WriteAllText($fixture, $Text, [Text.UTF8Encoding]::new($false))
    return ConvertFrom-MiosTomlFile -Path $fixture -ProjectedCredentials:$ProjectedCredentials
}
function Assert-Refuses {
    param([string]$Text, [string]$Message)
    $errorText = $null
    try { $null = Read-Fixture $Text } catch { $errorText = $_.Exception.Message }
    Assert-True ($null -ne $errorText -and $errorText.Contains($Message)) 'malformed/credential input must refuse with its specific error'
}
try {
    # Exact vendor construct: the shell's final apostrophe is content, followed
    # immediately by the three TOML closing quotes (four consecutive quotes).
    $source = @'
[units."mios-firewall-ports.service".Service]
ExecStart = '''/bin/bash -c '\
    exit 0\''''
[windows.xbox.preferences]
taskbar_align = 1
'@
    $view = Read-Fixture $source
    $value = Get-Toml $view 'units."mios-firewall-ports.service".Service.ExecStart'
    Assert-True ($value.StartsWith('/bin/bash -c ')) 'vendor command prefix is retained'
    Assert-True ($value.EndsWith("exit 0\'")) 'vendor trailing content apostrophe is retained'
    Assert-True ((Get-Toml $view 'windows.xbox.preferences.taskbar_align') -ceq '1') 'following table is parsed after the delimiter'

    foreach ($quote in @([string][char]39, '"')) {
        foreach ($contentQuotes in 0..2) {
            $text = '[sample]' + [Environment]::NewLine + 'value = ' + ($quote * 3) + 'text' + ($quote * (3 + $contentQuotes)) + ' # closing comment'
            $view = Read-Fixture $text
            Assert-True ((Get-Toml $view 'sample.value') -ceq ('text' + ($quote * $contentQuotes))) 'same-line legal closing quote runs preserve content'
            $text = '[sample]' + [Environment]::NewLine + 'value = ' + ($quote * 3) + [Environment]::NewLine + 'text' + ($quote * (3 + $contentQuotes))
            $view = Read-Fixture $text
            Assert-True ((Get-Toml $view 'sample.value') -ceq ('text' + ($quote * $contentQuotes))) 'subsequent-line legal closing quote runs preserve content'
        }
    }
    $escaped = @'
[sample]
value = """escaped \""" still inside
done"""
next = "parsed"
'@
    $view = Read-Fixture $escaped
    Assert-True ((Get-Toml $view 'sample.value').EndsWith('done')) 'escaped basic quote does not close the multiline string'
    Assert-True ((Get-Toml $view 'sample.next') -ceq 'parsed') 'table parsing resumes after the actual basic terminator'
    $trailingSpace = @'
[sample]
value = '''first
last'''
'@
    $trailingSpace = $trailingSpace.Replace('first', ('first' + (' ' * 3)))
    $view = Read-Fixture $trailingSpace
    Assert-True ((Get-Toml $view 'sample.value').StartsWith('first   ' + [Environment]::NewLine)) 'opening content trailing spaces remain content'

    foreach ($quote in @([string][char]39, '"')) {
        $prefix = '[sample]' + [Environment]::NewLine + 'value = ' + ($quote * 3)
        Assert-Refuses ($prefix + 'text' + ($quote * 3) + ' garbage') 'invalid multiline TOML string'
        Assert-Refuses ($prefix + [Environment]::NewLine + 'text' + ($quote * 4) + ' garbage') 'invalid multiline TOML string'
        Assert-Refuses ($prefix + 'text' + ($quote * 6)) 'invalid multiline TOML string'
        Assert-Refuses ($prefix + 'unterminated') 'unterminated multiline TOML string'
        Assert-Refuses ('[identity]' + [Environment]::NewLine + 'default_password = ' + ($quote * 3) + 'fixture' + ($quote * 3)) 'uses multiline TOML; use private -ResolvedJson'
    }
    $projected = @'
[identity]
username = "fixture-user"
default_password = '''discarded
credential''''
[sample]
next = "parsed"
'@
    $view = Read-Fixture $projected -ProjectedCredentials
    Assert-True (-not $view.scalars.ContainsKey('identity.default_password')) 'authoritative private projection discards complete multiline credential'
    Assert-True ((Get-Toml $view 'sample.next') -ceq 'parsed') 'credential discard retains following table'
    $errorText = $null
    try { $null = Resolve-MiOSCredentials -Toml $view } catch { $errorText = $_.Exception.Message }
    Assert-True ($null -ne $errorText -and $errorText.Contains("required credential key 'identity.default_password'")) 'discard never bypasses the required credential gate'

    $branding = New-MiosTomlView
    $branding.scalars['branding.cursor'] = 'false'
    $commands = @(Get-MiOSPerUserBrandingReg -Toml $branding -HivePrefix 'HKCU')
    Assert-True ($commands -ccontains 'reg add "HKCU\Control Panel\Desktop" /v WallPaper /t REG_SZ /d "" /f') 'absent wallpaper keeps the static background empty'
    $branding.scalars['branding.wallpaper'] = 'C:\Users\Operator\Pictures\custom.png'
    $commands = @(Get-MiOSPerUserBrandingReg -Toml $branding -HivePrefix 'HKCU')
    Assert-True ($commands -ccontains 'reg add "HKCU\Control Panel\Desktop" /v WallPaper /t REG_SZ /d "C:\Users\Operator\Pictures\custom.png" /f') 'explicit operator wallpaper is retained'
    $branding.scalars['branding.wallpaper'] = 'C:\bad"path.png'
    $errorText = $null
    try { $null = Get-MiOSPerUserBrandingReg -Toml $branding -HivePrefix 'HKCU' } catch { $errorText = $_.Exception.Message }
    Assert-True ($null -ne $errorText -and $errorText.Contains('branding.wallpaper')) 'a path cannot break out of the quoted registry argument'
    if ($VendorToml) {
        $view = Read-MiosToml -Path $VendorToml -SingleFile
        Assert-True ((Get-Toml $view 'windows.xbox.preferences.taskbar_align') -ceq '1') 'full canonical vendor reaches the Windows specification'
    }
    Write-Host "PROVISION_TOML_REGRESSIONS PASS ($script:assertions assertions)"
} finally {
    if ([IO.File]::Exists($fixture)) { [IO.File]::Delete($fixture) }
}
