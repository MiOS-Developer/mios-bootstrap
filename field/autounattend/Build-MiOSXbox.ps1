# AI-hint: RETIRED for MiOS-Xbox images (xb-20). Refuses before SSOT reads, output creation or host changes.
# AI-related: usr/libexec/mios/win/xbox/build.py
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$TomlPath = 'C:\mios-bootstrap\mios.toml',
    [string]$SourceIso,
    [switch]$Fresh,
    [switch]$TestVM,
    [switch]$SkipServicing,
    [bool]$SecureBoot = $true,
    # Default to the Xbox edition so this builder applies [editions.mios-xbox]
    # (gaming debloat, dev channel, posture C, xbox accent, living wallpaper,
    # autounattend.xbox.enable). Pass -Edition mios for the non-Xbox variant.
    [string]$Edition = 'mios-xbox'
)
throw 'MiOS-Xbox: this legacy image entry is retired; use usr/libexec/mios/win/xbox/build.py.'
