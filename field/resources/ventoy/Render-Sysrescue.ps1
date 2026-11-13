# AI-hint: Pure field credential renderer over the shared layered MiOS resolver. Validates before writing; no built-in login or wipe credential.
# AI-related: field/autounattend/MiOS-Provision.lib.ps1, field/resources/autorun/01-sysrescue-firstboot.sh
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$TargetDrive,
    [string]$TargetRoot,
    [string]$TomlPath,
    [string]$ResolvedJson,
    [string]$PartitionLabel = 'MiOS-Field'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../../autounattend/MiOS-Provision.lib.ps1')

function Assert-MiOSBootWord {
    param([string]$Value, [string]$Key)
    # These legacy boot configs transport one unquoted kernel/GRUB word. Refuse
    # an unrepresentable credential rather than changing it or emitting syntax.
    if (-not $Value -or $Value -notmatch '^[A-Za-z0-9_.:@%+=,!?/-]+$') {
        throw "MiOS SSOT: $Key cannot be represented safely in this boot configuration; no files were changed."
    }
}
function ConvertTo-MiOSShellLiteral {
    param([string]$Value)
    return "'" + $Value.Replace("'", "'\''") + "'"
}
function Get-MiOSKickstartPasswordHash {
    param($Toml, $Credentials)
    foreach ($name in @('MIOS_USER_PASSWORD_HASH', 'MIOS_PASSWORD_HASH')) {
        $value = [Environment]::GetEnvironmentVariable($name, 'Process')
        if ($value) {
            if (-not $value.StartsWith('$6$') -or $value -notmatch '^\$6\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]+$') {
                throw "MiOS SSOT: $name is not a sha512-crypt hash; no files were changed."
            }
            return $value
        }
    }
    $value = Get-Toml $Toml 'auth.password_hash' ''
    if ($value) {
        if (-not $value.StartsWith('$6$') -or $value -notmatch '^\$6\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]+$') {
            throw 'MiOS SSOT: auth.password_hash is not a sha512-crypt hash; no files were changed.'
        }
        return $value
    }
    $openssl = Get-Command openssl -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $openssl) {
        throw 'MiOS SSOT: openssl is required to hash identity.default_password; no files were changed.'
    }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $openssl.Source
    $start.Arguments = 'passwd -6 -stdin'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'MiOS SSOT: credential hash process did not start; no files were changed.' }
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes([string]$Credentials.default_password + "`n")
        $process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill()
            throw 'MiOS SSOT: credential hash process timed out; no files were changed.'
        }
        $value = $stdout.GetAwaiter().GetResult().TrimEnd([char[]]"`r`n")
        $null = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0 -or -not $value.StartsWith('$6$') -or $value -notmatch '^\$6\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]+$') {
            throw 'MiOS SSOT: identity.default_password hash generation failed; no files were changed.'
        }
        return $value
    } finally { $process.Dispose() }
}

if ([bool]$TargetRoot -eq [bool]$TargetDrive) {
    throw 'Specify exactly one of TargetRoot or TargetDrive; no files were changed.'
}
if ($TargetDrive) {
    if ($TargetDrive -notmatch '^[A-Za-z]:?$') { throw 'Invalid TargetDrive; no files were changed.' }
    $TargetRoot = $TargetDrive.TrimEnd(':') + ':\'
}
if (-not [IO.Path]::IsPathRooted($TargetRoot)) {
    $TargetRoot = Join-Path (Get-Location).Path $TargetRoot
}
$target = Get-Item -LiteralPath $TargetRoot -Force
if (-not $target.PSIsContainer -or ($target.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'TargetRoot must be an existing directory without a link; no files were changed.'
}
if (-not $TomlPath) {
    foreach ($candidate in @($env:MIOS_VENDOR_TOML, 'C:\MiOS\usr\share\mios\mios.toml', (Join-Path $PSScriptRoot '../../../mios.toml'))) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { $TomlPath = $candidate; break }
    }
}
$ventoy = Get-Item -LiteralPath (Join-Path $target.FullName 'ventoy') -Force
if (-not $ventoy.PSIsContainer -or ($ventoy.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'The rescue output directory must exist without a link; no files were changed.'
}
$environmentPath = Join-Path $target.FullName 'mios-sysrescue.env'
if (Test-Path -LiteralPath $environmentPath) {
    $existingEnvironment = Get-Item -LiteralPath $environmentPath -Force
    if ($existingEnvironment.PSIsContainer -or ($existingEnvironment.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Refusing a rescue environment output that is not a regular file; no files were changed.'
    }
}
$toml = Read-MiosToml -Path $TomlPath -ResolvedJson $ResolvedJson
if ((Get-Toml $toml 'field.sysrescue.enable' 'true') -notmatch '^(?i:true|1|yes)$') { return }
$credentials = Resolve-MiOSCredentials -Toml $toml
$user = Get-Toml $toml 'field.sysrescue.username' $credentials.username
$password = Get-Toml $toml 'field.sysrescue.password' $credentials.default_password
if ($user -notmatch '^[a-z_][a-z0-9_.-]*[$]?$' -or $credentials.username -notmatch '^[a-z_][a-z0-9_.-]*[$]?$') {
    throw 'MiOS SSOT: field.sysrescue.username must be a POSIX login name; no files were changed.'
}
Assert-MiOSBootWord -Value $password -Key 'field.sysrescue.password (identity.default_password when blank)'
$wipe = Get-Toml $toml 'field.sysrescue.wipe_passphrase' ''
Assert-MiOSBootWord -Value $wipe -Key 'field.sysrescue.wipe_passphrase'
$label = Get-Toml $toml 'field.sysrescue.ar_source_label' $PartitionLabel
if (-not $label -or $label -notmatch '^[A-Za-z0-9_.-]+$') {
    throw 'MiOS SSOT: field.sysrescue.ar_source_label is not a partition label; no files were changed.'
}
$nofirewall = (Get-Toml $toml 'field.sysrescue.nofirewall' 'true') -match '^(?i:true|1|yes)$'
$rootLogin = (Get-Toml $toml 'field.sysrescue.root_login' 'true') -match '^(?i:true|1|yes)$'
$header = if ((Get-Toml $toml 'field.sysrescue.connection_header' 'true') -match '^(?i:true|1|yes)$') { '1' } else { '0' }
$hash = Get-MiOSKickstartPasswordHash -Toml $toml -Credentials $credentials

# Project only these existing surfaces. Keep the template's guarded wipe entry,
# partition-label source and autorun0/autorun9 separation; never infer a target.
$prepared = @()
foreach ($name in @('sysrescue_grub.cfg', 'sysrescue_syslinux.cfg', 'mios-kickstart.cfg')) {
    $source = Join-Path $PSScriptRoot $name
    $path = Join-Path $ventoy.FullName $name
    $existing = Get-Item -LiteralPath $path -Force
    if ($existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Refusing a rescue output that is not a regular file; no files were changed.'
    }
    $text = [IO.File]::ReadAllText($source)
    $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($name -eq 'mios-kickstart.cfg') {
        $userLine = [regex]::Match($text, '(?m)^user --name=__mios_ks_user__ [^\r\n]+ --lock\r?$')
        if (-not $userLine.Success) {
            throw 'MiOS kickstart credential placeholder is missing; no files were changed.'
        }
        $renderedUser = $userLine.Value.Replace('__mios_ks_user__', [string]$credentials.username).Replace(' --lock', ' --iscrypted --password=' + $hash)
        $text = $text.Replace($userLine.Value, $renderedUser)
    } else {
        if (-not $text.Contains('__MIOS_SR_ROOTPASS__') -or -not $text.Contains('__MIOS_SR_USERPASS__')) {
            throw 'MiOS rescue credential placeholders are missing; no files were changed.'
        }
        if (-not $rootLogin) { $text = $text -replace 'rootpass=__MIOS_SR_ROOTPASS__\s*', '' }
        $text = $text.Replace('__MIOS_SR_ROOTPASS__', $password).Replace('__MIOS_SR_USERPASS__', $password)
        $text = $text.Replace('__MIOS_SR_WIPEPASS__', $wipe).Replace('by-label/MiOS-Field', 'by-label/' + $label)
        if (-not $nofirewall) { $text = $text.Replace(' nofirewall', '') }
    }
    if ($text -match '__MIOS_SR_|__mios_ks_user__') { throw 'An unresolved rescue placeholder remains; no files were changed.' }
    $prepared += @{ Path = $path; Text = $text; PublicTemplateSha256 = $sourceHash }
}
$environment = "# Rendered from layered MiOS field.sysrescue credentials; private, never log.`n" +
    'MIOS_SR_USER=' + (ConvertTo-MiOSShellLiteral $user) + "`n" +
    'MIOS_SR_PASS=' + (ConvertTo-MiOSShellLiteral $password) + "`n" +
    'MIOS_SR_HEADER=' + (ConvertTo-MiOSShellLiteral $header) + "`n"
foreach ($output in $prepared) {
    Write-MiOSPrivateText -Path $output.Path -Text $output.Text -Encoding UTF8 -PublicTemplateSha256 $output.PublicTemplateSha256
}
Write-MiOSPrivateText -Path $environmentPath -Text $environment -Encoding UTF8
Write-Host '[render-sysrescue] Rendered the requested rescue credential surfaces from the layered MiOS SSOT; credential values are not displayed.'
