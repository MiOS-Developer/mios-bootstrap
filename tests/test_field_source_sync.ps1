# Native-only source fixtures. Never execute installer or generated profile top-level.
# Real Git uses throwaway local repositories; archive fixtures use private scratch files.
[CmdletBinding()]
param([switch]$PlantDefect)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-field-sync-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $scratch
$script:checks = 0
$script:FieldTopLevelExecuted = $false
$environment = @{}
foreach ($name in @('GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_COUNT',
    'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_CONFIG_KEY_1', 'GIT_CONFIG_VALUE_1', 'GIT_CONFIG_KEY_2', 'GIT_CONFIG_VALUE_2')) {
    $environment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
function Check([bool]$Condition, [string]$Name) {
    $script:checks++
    if (-not $Condition) { throw ('ASSERT: ' + $Name) }
}
function Read-Ast([string]$Text) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw ('Source parser rejected a fixture: ' + $errors[0].Message) }
    return $ast
}
function Definition($Ast, [string]$Name) {
    $found = @($Ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name }, $true))
    if ($found.Count -ne 1) { throw ('Missing or duplicate fixture function: ' + $Name) }
    return $found[0]
}
function Invoke-CloneFailureFixture([string]$Source) {
    & {
        param($Program, $Target)
        . ([scriptblock]::Create($Program))
        $script:cloneAttempts = 0
        function Invoke-GitProc {
            param([string[]]$ArgList)
            if ($ArgList[0] -eq 'clone') {
                $script:cloneAttempts++
                $null = New-Item -ItemType Directory -Path $Target
                [IO.File]::WriteAllText((Join-Path $Target 'concurrent-work.txt'), 'saved while clone was running')
                return [pscustomobject]@{ ExitCode = 1 }
            }
            return [pscustomobject]@{ ExitCode = 0 }
        }
        $message = ''
        try { Initialize-MiosFieldSourceCheckout -Path $Target -RepoUrl 'fixture.invalid' -Ref main -CanonicalPath 'unused' } catch { $message = $_.Exception.Message }
        Check ($message -match 'target was preserved' -and $script:cloneAttempts -eq 1 -and
            [IO.File]::ReadAllText((Join-Path $Target 'concurrent-work.txt')) -eq 'saved while clone was running') 'a failed clone preserves concurrent source and does not delete before retrying'
        $message = ''
        try { Initialize-MiosFieldSourceCheckout -Path $Target -RepoUrl 'fixture.invalid' -Ref main -CanonicalPath 'unused' } catch { $message = $_.Exception.Message }
        Check ($message -match 'existing non-checkout data' -and $script:cloneAttempts -eq 1 -and
            [IO.File]::ReadAllText((Join-Path $Target 'concurrent-work.txt')) -eq 'saved while clone was running') 'a partial non-checkout target is refused without touching saved source'
    } $Source (Join-Path $scratch 'failed-clone')
}
function Write-Archive([string]$Name, [string]$EntryName, [int]$UnixType = 0) {
    $path = Join-Path $scratch ($Name + '.zip')
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew)
    $archive = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Create)
    try {
        $entry = $archive.CreateEntry($EntryName)
        if ($UnixType) { $entry.ExternalAttributes = $UnixType -shl 16 }
        $writer = New-Object IO.StreamWriter($entry.Open())
        try { $writer.Write('fixture source') } finally { $writer.Dispose() }
    } finally { $archive.Dispose(); $stream.Dispose() }
    return $path
}
function Invoke-StagingFixtures([string]$StagingSource) {
    $caseRoot = Join-Path $scratch ('staging-' + [guid]::NewGuid().ToString('N'))
    $parent = Join-Path $caseRoot 'destination-parent'
    $temporary = Join-Path $caseRoot 'redirected-temp'
    $null = New-Item -ItemType Directory -Path $parent -Force
    $null = New-Item -ItemType Directory -Path $temporary
    & {
        param($Program, $ParentPath, $TemporaryPath)
        . ([scriptblock]::Create($Program))
        $script:stagingAclPath = ''; $script:stagingAclReject = $false
        # Only the Windows ACL API is mocked; path selection and directory creation are real.
        function Protect-MiosFieldSourceStaging {
            param([string]$Path)
            $script:stagingAclPath = $Path
            if ($script:stagingAclReject) { throw 'Fixture ACL installation/readback refused.' }
        }
        $savedTemp = @{}
        foreach ($name in @('TEMP', 'TMP', 'TMPDIR')) {
            $savedTemp[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
            [Environment]::SetEnvironmentVariable($name, $TemporaryPath, 'Process')
        }
        $stage = ''
        try {
            $target = Join-Path $ParentPath 'checkout'
            $stage = New-MiosFieldPrivateSourceStaging -Destination $target
            Check ([IO.Directory]::GetParent($stage).FullName -ceq [IO.Path]::GetFullPath($ParentPath) -and
                [IO.Path]::GetPathRoot($stage) -ceq [IO.Path]::GetPathRoot($target) -and
                $script:stagingAclPath -ceq $stage -and (Test-Path -LiteralPath $stage -PathType Container)) 'private staging is created beside the destination despite redirected TEMP'
            Remove-MiosFieldPrivateSourceStaging -Path $stage -ExpectedParent ([IO.Directory]::GetParent($stage).FullName)
            $stage = ''
            $script:stagingAclReject = $true
            $message = ''
            try { $null = New-MiosFieldPrivateSourceStaging -Destination $target } catch { $message = $_.Exception.Message }
            Check ($message -match 'ACL installation/readback refused' -and
                -not (Test-Path -LiteralPath $script:stagingAclPath) -and -not (Test-Path -LiteralPath $target)) 'failed private ACL installation stops acquisition without a fallback staging directory'
        } finally {
            if ($stage -and (Test-Path -LiteralPath $stage)) {
                Remove-MiosFieldPrivateSourceStaging -Path $stage -ExpectedParent ([IO.Directory]::GetParent($stage).FullName)
            }
            foreach ($name in $savedTemp.Keys) { [Environment]::SetEnvironmentVariable($name, $savedTemp[$name], 'Process') }
        }
    } $StagingSource $parent $temporary
    $link = Join-Path $caseRoot 'linked-parent'
    $linkType = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'Junction' } else { 'SymbolicLink' }
    $null = New-Item -ItemType $linkType -Path $link -Target $parent -ErrorAction Stop
    $message = ''
    try { $null = Get-MiosFieldSourceParent -Destination (Join-Path $link 'checkout') } catch { $message = $_.Exception.Message }
    Check ($message -match 'reparse point' -and
        ((Get-Item -LiteralPath $link -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) 'a destination parent link is rejected and preserved'
}
function Invoke-ArchiveFixtures([string]$EnsureSource, [string]$StagingSource, [string]$ParentSource) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $archive = Write-Archive 'safe-source' 'repo/source.txt'
    $destination = Join-Path $scratch 'safe-extraction'
    Expand-MiosFieldSourceArchive -Archive $archive -Destination $destination
    Check ([IO.File]::ReadAllText((Join-Path $destination 'repo/source.txt')) -eq 'fixture source') 'a bounded regular archive extracts its source bytes'
    foreach ($case in @(
        @{ Name = 'traversal'; Entry = '../escape.txt'; Type = 0 },
        @{ Name = 'absolute'; Entry = '/escape.txt'; Type = 0 },
        @{ Name = 'windows-drive'; Entry = 'C:/escape.txt'; Type = 0 },
        @{ Name = 'windows-device'; Entry = 'repo/CON.txt'; Type = 0 },
        @{ Name = 'symlink'; Entry = 'repo/link'; Type = 0xA000 }
    )) {
        $archive = Write-Archive $case.Name $case.Entry $case.Type
        $destination = Join-Path $scratch ($case.Name + '-extraction')
        $message = ''
        try { Expand-MiosFieldSourceArchive -Archive $archive -Destination $destination } catch { $message = $_.Exception.Message }
        Check ($message -match 'unsafe path or entry type' -and -not (Test-Path -LiteralPath $destination)) ('unsafe archive rejected before extraction: ' + $case.Name)
    }
    $archive = Write-Archive 'expanded-limit' 'repo/oversized.txt'
    $bytes = [IO.File]::ReadAllBytes($archive)
    $central = -1
    for ($offset = 0; $offset -lt $bytes.Length - 28; $offset++) {
        if ([BitConverter]::ToUInt32($bytes, $offset) -eq 0x02014b50) { $central = $offset; break }
    }
    if ($central -lt 0) { throw 'Fixture ZIP central directory was not found.' }
    # A declared expansion bomb is rejected before an entry stream is opened.
    [Array]::Copy([BitConverter]::GetBytes([uint32](256MB + 1)), 0, $bytes, $central + 24, 4)
    [IO.File]::WriteAllBytes($archive, $bytes)
    $destination = Join-Path $scratch 'expanded-limit-extraction'
    $message = ''
    try { Expand-MiosFieldSourceArchive -Archive $archive -Destination $destination } catch { $message = $_.Exception.Message }
    Check ($message -match 'expanded size limit' -and -not (Test-Path -LiteralPath $destination)) 'an oversized ZIP expansion is refused before extracting bytes'
    & {
        param($Program, $StagingProgram, $ParentProgram, $Target)
        . ([scriptblock]::Create($Program))
        . ([scriptblock]::Create($StagingProgram))
        . ([scriptblock]::Create(($ParentProgram -replace '^function\s+Get-MiosFieldSourceParent', 'function Get-FixtureSourceParent')))
        $script:sourceNetworkCalls = 0; $script:publicationRace = $false; $script:rejectParentAfterDownload = $false; $script:downloadCompleted = $false
        function Get-Command { param($Name, $ErrorAction) return $null }
        function Protect-MiosFieldSourceStaging {
            param([string]$Path)
            $script:publicationStaging = $Path
        }
        function Get-MiosFieldSourceParent {
            param([string]$Destination)
            if ($script:rejectParentAfterDownload -and $script:downloadCompleted) { throw 'Fixture publication parent became a reparse point.' }
            return Get-FixtureSourceParent -Destination $Destination
        }
        function Invoke-WebRequest {
            param($Uri, $OutFile, [switch]$UseBasicParsing, $TimeoutSec, $ErrorAction)
            $script:sourceNetworkCalls++
            if ($script:publicationRace) {
                # Simulate another local worker creating the destination during download.
                $null = New-Item -ItemType Directory -Path $Target
                [IO.File]::WriteAllText((Join-Path $Target 'operator.txt'), 'concurrent operator content')
            }
            $entry = Write-Archive ('publish-' + [guid]::NewGuid().ToString('N')) 'repo/field/autounattend/Build-MiOSXboxISO.ps1'
            Copy-Item -LiteralPath $entry -Destination $OutFile
            $script:downloadCompleted = $true
        }
        $complete = $Target + '-complete'
        $result = Ensure-MiosBootstrapRepo -Root $complete
        Check ($result -ceq [IO.Path]::GetFullPath($complete) -and
            [IO.File]::ReadAllText((Join-Path $complete 'field/autounattend/Build-MiOSXboxISO.ps1')) -eq 'fixture source' -and
            [IO.Directory]::GetParent($script:publicationStaging).FullName -ceq [IO.Directory]::GetParent($complete).FullName -and
            -not (Test-Path -LiteralPath $script:publicationStaging)) 'an absent target publishes successfully from private sibling staging and removes only that staging'
        $script:publicationRace = $true
        $message = ''
        try { $null = Ensure-MiosBootstrapRepo -Root $Target } catch { $message = $_.Exception.Message }
        Check ($message -ne '' -and $script:sourceNetworkCalls -eq 2 -and
            [IO.File]::ReadAllText((Join-Path $Target 'operator.txt')) -eq 'concurrent operator content' -and
            -not (Test-Path -LiteralPath (Join-Path $Target 'field'))) 'archive publication refuses a concurrent target without merging source over it'
        $message = ''
        try { $null = Ensure-MiosBootstrapRepo -Root $Target } catch { $message = $_.Exception.Message }
        Check ($message -match 'incomplete or existing tree' -and $script:sourceNetworkCalls -eq 2 -and
            [IO.File]::ReadAllText((Join-Path $Target 'operator.txt')) -eq 'concurrent operator content') 'an existing partial archive target is refused before any network request'
        $empty = $Target + '-empty'; $null = New-Item -ItemType Directory -Path $empty
        $message = ''
        try { $null = Ensure-MiosBootstrapRepo -Root $empty } catch { $message = $_.Exception.Message }
        Check ($message -match 'including an empty target' -and $script:sourceNetworkCalls -eq 2 -and
            (Test-Path -LiteralPath $empty -PathType Container)) 'an existing empty target is preserved and explicitly refused before acquisition'
        $link = $Target + '-link'
        $linkType = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'Junction' } else { 'SymbolicLink' }
        $null = New-Item -ItemType $linkType -Path $link -Target $complete -ErrorAction Stop
        $message = ''
        try { $null = Ensure-MiosBootstrapRepo -Root $link } catch { $message = $_.Exception.Message }
        Check ($message -match 'target link is preserved' -and $script:sourceNetworkCalls -eq 2 -and
            ((Get-Item -LiteralPath $link -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) 'a final target link is preserved even when its destination contains a complete checkout'
        $script:publicationRace = $false; $script:downloadCompleted = $false; $script:rejectParentAfterDownload = $true
        $unsafe = $Target + '-changed-parent'
        $message = ''
        try { $null = Ensure-MiosBootstrapRepo -Root $unsafe } catch { $message = $_.Exception.Message }
        Check ($message -match 'parent became a reparse point' -and -not (Test-Path -LiteralPath $unsafe) -and
            (Test-Path -LiteralPath $script:publicationStaging)) 'publication rechecks parent safety after download and retains staging when cleanup is unsafe'
        $script:rejectParentAfterDownload = $false
        Remove-MiosFieldPrivateSourceStaging -Path $script:publicationStaging -ExpectedParent ([IO.Directory]::GetParent($script:publicationStaging).FullName)
    } $EnsureSource $StagingSource $ParentSource (Join-Path $scratch 'publish-target')
}

try {
    # All subprocesses, including the real Field helper, inherit isolated Git preferences.
    $noHooks = Join-Path $scratch 'no-hooks'; $null = New-Item -ItemType Directory -Path $noHooks
    $emptyConfig = Join-Path $scratch 'empty.gitconfig'; [IO.File]::WriteAllText($emptyConfig, '')
    $env:GIT_CONFIG_GLOBAL = $emptyConfig; $env:GIT_CONFIG_NOSYSTEM = '1'; $env:GIT_CONFIG_COUNT = '3'
    $env:GIT_CONFIG_KEY_0 = 'core.hooksPath'; $env:GIT_CONFIG_VALUE_0 = $noHooks
    $env:GIT_CONFIG_KEY_1 = 'merge.autoStash'; $env:GIT_CONFIG_VALUE_1 = 'false'
    $env:GIT_CONFIG_KEY_2 = 'protocol.file.allow'; $env:GIT_CONFIG_VALUE_2 = 'always'

    $fieldText = [IO.File]::ReadAllText((Join-Path $repoRoot 'field/lib/Get-MiOS-Backend.ps1')).Replace("`r`n", "`n")
    $fieldAst = Read-Ast $fieldText
    $canonicalText = [IO.File]::ReadAllText((Join-Path $repoRoot 'Get-MiOS.ps1')).Replace("`r`n", "`n")
    $canonicalAst = Read-Ast $canonicalText
    $canonicalPath = Join-Path $scratch 'Get-MiOS.ps1'
    $canonicalText = $canonicalText.Insert($canonicalAst.ParamBlock.Extent.EndOffset,
        "`n`$script:FieldTopLevelExecuted = `$true; throw 'CANONICAL_TOP_LEVEL_EXECUTED'`n")
    [IO.File]::WriteAllText($canonicalPath, $canonicalText)
    foreach ($name in @('Get-MiosFieldCanonicalPath', 'Get-MiosFieldCanonicalFunctions', 'Update-MiosFieldCheckout',
        'Get-MiosFieldCheckoutProfileBlock', 'Initialize-MiosFieldSourceCheckout', 'Invoke-GitProc', 'Expand-MiosFieldSourceArchive',
        'Get-MiosFieldSourceParent', 'Remove-MiosFieldPrivateSourceStaging')) {
        . ([scriptblock]::Create((Definition $fieldAst $name).Extent.Text))
    }
    # Reuse the existing real Git acceptance fixture without running its installer/profile suite.
    $sharedAst = Read-Ast ([IO.File]::ReadAllText((Join-Path $repoRoot 'tests/test_build_savedconfig_security.ps1')))
    foreach ($name in @('Get-HereString', 'Test-UnsafeGeneratedGitCommand', 'Invoke-LosslessRefreshFixture')) {
        . ([scriptblock]::Create((Definition $sharedAst $name).Extent.Text))
    }
    $windowsRefreshBlock = Get-MiosFieldCheckoutProfileBlock -CanonicalPath $canonicalPath
    $profileHelperAst = Read-Ast $windowsRefreshBlock
    $canonicalHelper = (Definition $canonicalAst 'Update-MiosWindowsBuildCheckout').Extent.Text
    $profileHelper = (Definition $profileHelperAst 'Update-MiosWindowsBuildCheckout').Extent.Text
    Check ($profileHelper.Replace("`r`n", "`n") -ceq $canonicalHelper) 'Field embeds the canonical lossless refresh function verbatim'
    # Expand only the actual profile template string. Never invoke its initialization or applications.
    $miosBuildRefLiteral = "'main'"; $_miosCols = 80; $_miosRows = 40; $_miosScroll = 9000
    $_miosFrameH = 18; $_miosFrameW = 80; $_miosRightMargin = 2; $_themeFontFace = 'monospace'; $_themeFontSize = 12
    $ompBlobBase64 = ''; $Script:MiosBootstrapRaw = 'https://fixture.invalid/bootstrap'
    $profile = [string](& ([scriptblock]::Create((Get-HereString $fieldAst 'miosScriptBody'))))
    $profileAst = Read-Ast $profile
    $pull = Definition $profileAst 'mios-pull'
    $calls = @($pull.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))
    Check (@($calls | Where-Object { $_.GetCommandName() -eq 'Update-MiosWindowsBuildCheckout' }).Count -eq 1 -and
        -not @($calls | Where-Object { $_.GetCommandName() -eq 'git' }).Count) 'the generated Field pull verb invokes the shared refresh instead of direct Git'
    $commands = @($profileAst.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))
    Check (-not @($commands | Where-Object { Test-UnsafeGeneratedGitCommand $_ }).Count) 'the generated Field profile has no destructive, shallow, or stashing Git command'
    $init = Definition $fieldAst 'Initialize-MiosFieldSourceCheckout'
    $commands = @($init.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))
    Check (-not @($commands | Where-Object { $_.GetCommandName() -eq 'Remove-Item' }).Count -and
        @($commands | Where-Object { $_.GetCommandName() -eq 'Update-MiosFieldCheckout' }).Count -eq 1) 'the active checkout initializer uses shared refresh and never deletes its target'
    $initCalls = @($fieldAst.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Initialize-MiosFieldSourceCheckout' }, $true))
    $handoff = @($fieldAst.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.CommandElements[0].Extent.Text -eq '$entry' }, $true))
    Check ($initCalls.Count -eq 1 -and $handoff.Count -eq 1 -and $initCalls[0].Extent.EndOffset -lt $handoff[0].Extent.StartOffset) 'the actual Field ready path initializes source before handing off to bootstrap'
    Check ($fieldText -notmatch '(?im)^\s*(?:&\s+)?git\s+(?:reset|clean|stash|checkout|switch)\b' -and
        $fieldText -notmatch "'reset'\s*,\s*'--hard'") 'Field contains no alternate reset, clean, stash, or force-checkout update path'
    $ensureSource = (Definition $fieldAst 'Ensure-MiosBootstrapRepo').Extent.Text
    $ensureAst = Read-Ast $ensureSource
    $commands = @($ensureAst.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))
    Check (-not @($commands | Where-Object { $_.GetCommandName() -in @('Copy-Item', 'Expand-Archive') }).Count) 'alternate source acquisition does not merge archive files over an existing tree'

    Invoke-LosslessRefreshFixture $profileHelper
    $safePath = "'" + $canonicalPath.Replace("'", "''") + "'"
    $initializerAdapter = @"
function Update-MiosWindowsBuildCheckout {
    param([string]`$Path, [string]`$Ref)
    Initialize-MiosFieldSourceCheckout -Path `$Path -RepoUrl 'unused-local-fixture' -Ref `$Ref -CanonicalPath $safePath
}
"@
    Invoke-LosslessRefreshFixture $initializerAdapter
    Invoke-CloneFailureFixture $init.Extent.Text
    $stagingSource = (Definition $fieldAst 'New-MiosFieldPrivateSourceStaging').Extent.Text
    Invoke-StagingFixtures $stagingSource
    Invoke-ArchiveFixtures $ensureSource $stagingSource (Definition $fieldAst 'Get-MiosFieldSourceParent').Extent.Text
    Check (-not $script:FieldTopLevelExecuted) 'source refresh imports no installer top-level statements'
    $baseline = $script:checks
    Write-Host "FIELD_SOURCE_SYNC_ASSERTIONS $baseline"
    if ($PlantDefect) {
        $plants = @(
            @{ Name = 'destructive reset'; Source = 'function Update-MiosWindowsBuildCheckout { param([string]$Path, [string]$Ref) & git -C $Path fetch origin $Ref *> $null; & git -C $Path reset --hard FETCH_HEAD *> $null }'; Expected = 'dirty Windows companion source preserves' },
            @{ Name = 'ignored file overwrite'; Source = $profileHelper.Replace('--no-overwrite-ignore', '--overwrite-ignore'); Expected = 'preserves ignored files when the remote starts tracking their paths' }
        )
        $caught = 0
        foreach ($plant in $plants) {
            $message = ''
            try { Invoke-LosslessRefreshFixture $plant.Source } catch { $message = $_.Exception.Message }
            if (-not $message -or $message -notmatch [regex]::Escape($plant.Expected)) { throw ('Plant did not reach its intended real Git control: ' + $plant.Name) }
            $caught++
        }
        $message = ''
        $unsafeStaging = $stagingSource.Replace('Join-Path $parent (', 'Join-Path ([IO.Path]::GetTempPath()) (')
        if ($unsafeStaging -ceq $stagingSource) { throw 'Missing staging location mutation anchor.' }
        try { Invoke-StagingFixtures $unsafeStaging } catch { $message = $_.Exception.Message }
        if ($message -notmatch 'private staging is created beside the destination') { throw 'The staging fixture did not detect the former TEMP-based staging location.' }
        $caught++
        Write-Host "FIELD_SOURCE_SYNC_PLANTS PASS ($caught/$($plants.Count + 1))"
    } else { Write-Host 'RESULT: PASS (Field source sync; isolated real Git and archive fixtures)' }
} finally {
    foreach ($name in $environment.Keys) { [Environment]::SetEnvironmentVariable($name, $environment[$name], 'Process') }
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
