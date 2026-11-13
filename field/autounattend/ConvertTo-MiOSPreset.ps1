# AI-hint: RETIRED for MiOS-Xbox images (xb-20). Refuses before SSOT reads, output creation or host changes.
# AI-related: usr/libexec/mios/win/xbox/build.py
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InputPreset,
    [string]$OutputPreset,
    [string]$TomlPath,
    [string]$BootstrapUrl,
    [switch]$ObfuscatePasswords,
    [switch]$KeepVirtualizationDisabled
)
throw 'MiOS-Xbox: this legacy image entry is retired; use usr/libexec/mios/win/xbox/build.py.'
