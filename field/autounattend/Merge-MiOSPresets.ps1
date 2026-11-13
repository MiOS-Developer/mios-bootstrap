# AI-hint: RETIRED for MiOS-Xbox images (xb-20). Refuses before SSOT reads, output creation or host changes.
# AI-related: usr/libexec/mios/win/xbox/build.py
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string[]]$InputPresets = @(
        (Join-Path $PSScriptRoot 'presets\mios-xbox.xml')   # Canonical MiOS-Xbox preset
    ),
    [string]$OutputPreset
)
throw 'MiOS-Xbox: this legacy image entry is retired; use usr/libexec/mios/win/xbox/build.py.'
