# AI-hint: RETIRED for MiOS-Xbox images (xb-20). Refuses before SSOT reads, output creation or host changes.
# AI-related: usr/libexec/mios/win/xbox/build.py
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$SourceIso,
    [string]$TomlPath = 'C:\mios-bootstrap\mios.toml',
    [switch]$SkipBuild,
    [string]$VMName   = 'MiOS-XBOX-Test',
    [string]$LogDir   = 'M:\MiOS\logs',
    [int]$InstallTimeoutMin = 75,
    [int]$DeployTimeoutMin  = 50
)
throw 'MiOS-Xbox: this legacy image entry is retired; use usr/libexec/mios/win/xbox/build.py.'
