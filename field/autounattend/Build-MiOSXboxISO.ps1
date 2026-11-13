# AI-hint: RETIRED for MiOS-Xbox images (xb-20). Refuses before SSOT reads, output creation or host changes.
# AI-related: usr/libexec/mios/win/xbox/build.py
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$TomlPath,
    [string]$SourceIso,
    [string]$OutIso,
    [string]$WorkDir,
    [switch]$SkipPrereqs,
    [switch]$SkipMerge,
    [switch]$SkipWsl,
    # Edition whose [editions.<name>] overrides apply (Apply-MiosEdition, inside
    # New-MiOSISO). Empty = base config; Build-MiOSXbox.ps1 defaults it to mios-xbox.
    [string]$Edition,
    [switch]$Esd
)
throw 'MiOS-Xbox: this legacy image entry is retired; use usr/libexec/mios/win/xbox/build.py.'
