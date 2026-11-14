# Machine boundary recovery fixtures: AST-extracted functions only; real Windows ACLs on scratch trees, never C:\usr, C:\etc or M:.
# Default and -PlantDefect run unelevated. -Prepare (operator) then -Elevated (one UAC) prove recovery, siblings unchanged and restore.
[CmdletBinding()]
param([switch]$PlantDefect, [switch]$Prepare, [switch]$Elevated, [string]$ScratchRoot, [string]$OriginSid, [string]$ProductPath)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $ProductPath) { $ProductPath = Join-Path $repoRoot 'Get-MiOS.ps1' }
$onWindows = $env:OS -eq 'Windows_NT'
# Admission and the canonical descriptor stay byte-identical to their reviewed source (CR stripped before hashing).
$pinned = @{
    'Assert-MiosMachineWriteBoundary' = '0765bc3d67cc38ae35bb132058afd587700b25bffb723f97417f7e70f1daeb59'
    'New-MiosMachineCreationAcl'      = '52b8961e9692d5f3322878dd9c5ea8e42558feca0d11f937f3afaa4113803d3b'
    'Assert-MiosNoReparsePath'        = '9fdaffcaf6123e9c4228a81688688d56de3a7d948622a0b3d5b3f0ad06078d5c'
}
$recoveryHelpers = @('Initialize-MiosMachineBoundaryApi', 'Get-MiosMachineBoundaryGap', 'Read-MiosBoundaryObject', 'Get-MiosBoundaryDescendants',
    'Get-MiosExplicitAces', 'Test-MiosSameExplicitAces', 'Get-MiosInheritedWriteGrants', 'Get-MiosBoundaryOwnerAction', 'Assert-MiosBoundaryAcePolicy',
    'New-MiosSharedPrefixSddl', 'New-MiosLeafSddl', 'Open-MiosBoundaryAncestors', 'Update-MiosBoundaryInheritance', 'Save-MiosBoundaryBackup',
    'Invoke-MiosMachineBoundaryRecovery')
$imported = @('Assert-MiosNoReparsePath', 'Assert-MiosMachineWriteBoundary', 'New-MiosMachineCreationAcl', 'New-MiosProtectedMachineDirectory',
    'Write-MiosPrivateMachineFile', 'Test-MiosElevated', 'Restore-MiosMachineBoundary', 'Get-MiosMachineWorkerScript') + $recoveryHelpers
$self = '(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)'

$script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
function Check([bool]$Ok, [string]$What) {
    $script:checks++
    if ($Ok) { Write-Host "  PASS $What" } else { Write-Host "  FAIL $What"; $script:fail++; $script:failedChecks.Add($What) }
}
function Expect-ThrowMatch([scriptblock]$Action, [string]$Pattern, [string]$What) {
    $message = $null
    try { $null = & $Action } catch { $message = $_.Exception.Message }
    Check ($null -ne $message -and $message -match $Pattern) $What
}
function Get-Sha256Text([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($Text -replace "`r", '')))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Import-Product([string]$Path) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Product source does not parse: $($errors[0].Message)" }
    foreach ($name in $imported) {
        $defs = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true))
        if ($defs.Count -ne 1) { throw "Missing/duplicate canonical function $name" }
        . ([scriptblock]::Create(($defs[0].Extent.Text -replace '^function\s+', 'function global:')))
    }
    return $ast
}
function Get-Function($Ast, [string]$Name) {
    return @($Ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true))[0]
}
function Get-Calls($Node, [string]$Name) {
    return @($Node.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq $Name }, $true))
}
function Add-Ace([string]$Path, [string]$Sid, [string]$Rights, [string]$Inherit, [string]$Type = 'Allow') {
    $acl = Get-Acl -LiteralPath $Path
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier $Sid), $Rights, $Inherit, 'None', $Type)))
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function New-Tree([string]$Root) {
    foreach ($d in 'usr\share\mios\sub', 'usr\local', 'etc\mios', 'etc\ssh') { New-Item -ItemType Directory -Force -Path (Join-Path $Root $d) | Out-Null }
    $files = @{ 'usr\share\mios\mios.toml' = "[meta]`nfixture = 'vendor'`n"; 'usr\share\mios\build-manifest.json' = "{`"fixture`": true}`n"
                'usr\share\mios\sub\note.txt' = "descendant`n"; 'usr\local\keep.txt' = "sibling`n"; 'etc\ssh\sshd_config' = "# sibling`n"
                'etc\mios\mios.toml' = "[meta]`nfixture = 'host'`n" }
    foreach ($k in $files.Keys) { [IO.File]::WriteAllText((Join-Path $Root $k), $files[$k]) }
    # Like C:\: every new top-level directory inherits an Authenticated Users Modify grant.
    Add-Ace $Root 'S-1-5-11' 'Modify' 'ContainerInherit,ObjectInherit'
}

function Invoke-SourceChecks([string]$Path) {
    $script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
    $ast = Import-Product $Path
    $text = [IO.File]::ReadAllText($Path)
    foreach ($name in $pinned.Keys) { Check ((Get-Sha256Text (Get-Function $ast $name).Extent.Text) -eq $pinned[$name]) "admission helper $name is unchanged from its reviewed source" }
    $core = Get-Function $ast 'Invoke-MiosMachinePreparationCore'
    $origin = Get-Calls $core 'Assert-MiosOriginContext'; $recover = Get-Calls $core 'Invoke-MiosMachineBoundaryRecovery'; $publish = Get-Calls $core 'Publish-MiosMachineToml'
    Check ($origin.Count -eq 1 -and $recover.Count -eq 1 -and $publish.Count -eq 1 -and $origin[0].Extent.StartOffset -lt $recover[0].Extent.StartOffset -and
           $recover[0].Extent.StartOffset -lt $publish[0].Extent.StartOffset -and $recover[0].Extent.Text -match '\$Context\.Sid') 'recovery runs after origin validation and before TOML publication, with the origin SID'
    Check ((Get-Calls (Get-Function $ast 'Publish-MiosMachineToml') 'Invoke-MiosMachineBoundaryRecovery').Count -eq 0 -and
           @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-MiosMachineBoundaryRecovery' }, $true)).Count -eq 1) 'recovery has exactly one caller'
    $invoke = Get-Function $ast 'Invoke-MiosMachineBoundaryRecovery'
    Check ($invoke.Extent.Text -notmatch "M:" -and $invoke.Extent.Text -match "\`$env:SystemDrive") 'recovery defaults to the system drive and never names M:'
    $host_ = Get-Function $ast 'Initialize-MiosHostTierDirectory'
    Check ((Get-Calls $host_ 'Set-MiosHostTierAcl').Count -eq 0 -and (Get-Calls $host_ 'Assert-MiosMachineWriteBoundary').Count -ge 1 -and
           (Get-Calls $host_ 'New-MiosProtectedMachineDirectory').Count -eq 1 -and (Get-Calls $host_ 'New-Item').Count -eq 0) 'host-tier directories use strict admission or atomic protected creation'
    $members = @($invoke.FindAll({ param($n) $n -is [Management.Automation.Language.InvokeMemberExpressionAst] }, $true))
    $set = @($members | Where-Object { $_.Member.Extent.Text -eq 'SetSddl' })
    $save = Get-Calls $invoke 'Save-MiosBoundaryBackup'; $elev = Get-Calls $invoke 'Test-MiosElevated'; $pin = Get-Calls $invoke 'Open-MiosBoundaryAncestors'
    $owner = Get-Calls $invoke 'Get-MiosBoundaryOwnerAction'; $policy = Get-Calls $invoke 'Assert-MiosBoundaryAcePolicy'; $inherit = Get-Calls $invoke 'Update-MiosBoundaryInheritance'
    Check ($set.Count -eq 1 -and $save.Count -eq 1 -and $elev.Count -eq 1 -and $owner.Count -eq 1 -and $policy.Count -eq 1 -and
           $elev[0].Extent.StartOffset -lt $save[0].Extent.StartOffset -and $owner[0].Extent.StartOffset -lt $save[0].Extent.StartOffset -and
           $policy[0].Extent.StartOffset -lt $save[0].Extent.StartOffset -and $save[0].Extent.StartOffset -lt $set[0].Extent.StartOffset) 'recovery validates policy and owners and backs up before changing any descriptor'
    Check ($pin.Count -eq 1 -and $pin[0].Extent.StartOffset -lt $set[0].Extent.StartOffset) 'every repair pins its ancestors first'
    Check ($inherit.Count -eq 1 -and $inherit[0].Extent.StartOffset -gt $set[0].Extent.StartOffset) 'leaf descendants are re-inherited after the descriptor change'
    $descend = Get-Calls $invoke 'Get-MiosBoundaryDescendants'
    Check ($descend.Count -eq 1 -and $descend[0].Parent.Extent.Text -match '\|\s*Where-Object\s*\{\s*\$_\s+-notin\s+\$planned\s*\}') 'a planned target below a leaf is its own step, not a leaf descendant'
    $worker = ''; try { $worker = Get-MiosMachineWorkerScript -Source $text } catch { }
    $missing = @($recoveryHelpers | Where-Object { $worker -notmatch ('(?m)^function ' + [regex]::Escape($_) + ' \{') })
    Check ($worker -and $missing.Count -eq 0) 'the elevated worker carries every recovery helper'
    if ($worker) {
        # Transitive closure from the recovery entry point inside the extracted worker: every product function it reaches must be there.
        $productNames = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
        $tokens = $null; $errors = $null
        $wast = [Management.Automation.Language.Parser]::ParseInput($worker, [ref]$tokens, [ref]$errors)
        $byName = @{}; foreach ($f in $wast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) { $byName[$f.Name] = $f }
        $seen = @{}; $unresolved = New-Object System.Collections.Generic.List[string]
        $queue = New-Object System.Collections.Generic.Queue[string]; $queue.Enqueue('Invoke-MiosMachineBoundaryRecovery')
        while ($queue.Count) {
            $name = $queue.Dequeue()
            if ($seen.ContainsKey($name)) { continue }
            $seen[$name] = $true
            if (-not $byName.ContainsKey($name)) { $unresolved.Add($name); continue }
            foreach ($c in @($byName[$name].FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } |
                Where-Object { $_ -and $_ -in $productNames })) { $queue.Enqueue($c) }
        }
        if ($unresolved.Count) { Write-Host ('    worker is missing: ' + ($unresolved -join ', ')) }
        Check ($errors.Count -eq 0 -and $unresolved.Count -eq 0) 'worker extraction resolves every helper the recovery calls'
    }
    $op = 'S-1-5-21-1-2-3-1001'
    Check ((Get-MiosBoundaryOwnerAction -Owner 'S-1-5-18' -OriginSid $op -Path 'x') -eq 'S-1-5-18' -and
           (Get-MiosBoundaryOwnerAction -Owner 'S-1-5-32-544' -OriginSid $op -Path 'x') -eq 'S-1-5-32-544') 'a SYSTEM or Administrators owner is kept'
    Check ((Get-MiosBoundaryOwnerAction -Owner $op -OriginSid $op -Path 'x') -eq 'S-1-5-32-544') 'the validated operator owner is replaced by Administrators'
    Expect-ThrowMatch { Get-MiosBoundaryOwnerAction -Owner 'S-1-5-19' -OriginSid $op -Path 'x' } 'only SYSTEM, Administrators or the validated operator' 'any other owner is refused'
    $okSddl = 'O:BAD:AI(A;OICIID;FA;;;SY)(A;ID;0x1301bf;;;AU)'
    $ok = $true; try { Assert-MiosBoundaryAcePolicy -Sddl $okSddl -Path 'x' } catch { $ok = $false }
    Check $ok 'plain allow ACEs are accepted policy'
    Expect-ThrowMatch { Assert-MiosBoundaryAcePolicy -Sddl 'O:BAD:(D;;FA;;;WD)(A;;FA;;;SY)' -Path 'x' } 'unreviewed ACE' 'an explicit deny ACE is refused'
    Expect-ThrowMatch { Assert-MiosBoundaryAcePolicy -Sddl 'O:BAD:(OA;;CR;edacfd8f-ffb3-11d1-b41d-00a0c968a5ba;;WD)(A;;FA;;;SY)' -Path 'x' } 'unreviewed ACE' 'an object ACE is refused'
    Expect-ThrowMatch { Assert-MiosBoundaryAcePolicy -Sddl 'O:BAD:NO_ACCESS_CONTROL' -Path 'x' } 'NULL DACL' 'a NULL DACL is refused'
    $input_ = 'O:BAD:AI(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)(A;OICIID;0x1200a9;;;BU)(A;ID;0x1301bf;;;AU)(A;OICIIOID;SDGXGWGR;;;AU)(A;CI;0x1301bf;;;S-1-5-21-9)'
    $shared = New-MiosSharedPrefixSddl -Sddl $input_ -Owner 'S-1-5-32-544'
    Check ($shared -ceq "O:BAD:P$self(A;OICIIO;FA;;;BA)(A;OICIIO;FA;;;SY)(A;OICIIO;0x1200a9;;;BU)(A;OICIIO;SDGXGWGR;;;AU)(A;CIIO;0x1301bf;;;S-1-5-21-9)") 'a shared prefix keeps only trusted self access and every inheritable ACE as an InheritOnly template'
    $applies = @(@((New-Object Security.AccessControl.RawSecurityDescriptor $shared).DiscretionaryAcl) | Where-Object { -not ([int]$_.AceFlags -band 0x08) })
    Check (@($applies | Where-Object { $_.SecurityIdentifier.Value -notin @('S-1-5-18', 'S-1-5-32-544') -and ($_.AccessMask -band 0x116) }).Count -eq 0) 'nothing that applies to the shared directory itself grants an untrusted account write'
    Check ((New-MiosSharedPrefixSddl -Sddl $input_ -Owner 'S-1-5-18') -clike 'O:SYD:P*') 'a shared prefix keeps the owner the policy decided'
    $canonical = (New-MiosMachineCreationAcl -Directory).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Owner, Access')
    Check ((New-MiosLeafSddl -Directory $true -Owner 'S-1-5-32-544') -ceq $canonical -and (New-MiosLeafSddl -Directory $true -Owner 'S-1-5-18') -ceq ($canonical -replace '^O:BA', 'O:SY')) 'a leaf gets exactly the descriptor fresh creation uses, with the decided owner'
    Check ((Get-MiosExplicitAces 'O:BAD:P(A;OICI;FA;;;SY)(A;OICIID;0x1301bf;;;AU)').Count -eq 1) 'inherited ACEs are excluded from the explicit set'
    $same = Test-MiosSameExplicitAces -Before 'O:BAD:AI(A;OICIID;0x1301bf;;;AU)(A;OICIID;FA;;;SY)' -After 'O:BAD:AI(A;OICIID;FA;;;BA)'
    $differs = Test-MiosSameExplicitAces -Before 'O:BAD:AI(A;OICIID;FA;;;SY)' -After 'O:BAD:AI(A;OICI;0x1301bf;;;AU)(A;OICIID;FA;;;SY)'
    Check ($same -is [bool] -and $same -and $differs -is [bool] -and -not $differs) 'explicit ACE comparison ignores inherited changes and detects explicit ones'
    Check (@(Get-MiosInheritedWriteGrants 'O:BAD:AI(A;ID;0x1301bf;;;AU)(A;ID;FA;;;SY)') -join ',' -eq 'S-1-5-11' -and
           @(Get-MiosInheritedWriteGrants 'O:BAD:AI(A;ID;0x1200a9;;;BU)(A;ID;FA;;;BA)').Count -eq 0 -and
           @(Get-MiosInheritedWriteGrants 'O:BAD:PAI(A;;FA;;;AU)').Count -eq 0 -and
           @(Get-MiosInheritedWriteGrants 'O:BAD:AI(A;OICIIOID;GA;;;AU)').Count -eq 0) 'inherited write grants are found only where they apply to the object'
    if (-not $onWindows) { Write-Host 'BOUNDARY_RECOVERY_WINDOWS_ACL UNRUN (not Windows)'; return $script:fail }

    $work = Join-Path ([IO.Path]::GetTempPath()) ('mios-boundary-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    try {
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Initialize-MiosMachineBoundaryApi
        $tree = Join-Path $work 'tree'; New-Tree $tree
        $script:saves = 0
        function global:Save-MiosBoundaryBackup { $script:saves++; throw 'Fixture: no backup may be written in an unelevated check.' }
        function global:Get-MiosMachineBoundaryGap { return '' }
        $result = 'threw'; try { $result = Invoke-MiosMachineBoundaryRecovery -OriginSid $me -Root $tree } catch { }
        Check ($null -eq $result -and $script:saves -eq 0) 'a run where every path already passes admission changes nothing'
        $null = Import-Product $Path
        function global:Save-MiosBoundaryBackup { $script:saves++; throw 'Fixture: no backup may be written in an unelevated check.' }
        $before = (Read-MiosBoundaryObject (Join-Path $tree 'usr')).Sddl
        if (-not (Test-MiosElevated)) {
            Expect-ThrowMatch { Invoke-MiosMachineBoundaryRecovery -OriginSid $me -Root $tree } 'requires an elevated token' 'an unelevated run refuses recovery'
            Check ($script:saves -eq 0 -and (Read-MiosBoundaryObject (Join-Path $tree 'usr')).Sddl -ceq $before) 'no backup and no descriptor change without elevation'
        }
        $file = Join-Path $tree 'usr\share\mios\mios.toml'
        $plain = Read-MiosBoundaryObject $file -WithBytes
        Check ($plain.Kind -eq 'file' -and $plain.Owner -eq $me -and $plain.Sha256 -match '^[0-9a-f]{64}$' -and $plain.Index -match '^[0-9a-f]{16}$' -and
               [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($plain.Bytes)) -ceq [IO.File]::ReadAllText($file)) 'a file reads by handle with owner, descriptor, identity, hash and exact bytes'
        $handle = [MiosMachineBoundaryNative]::Open($file, $true)
        try { $blocked = $false; try { [IO.File]::Open($file, 'Open', 'ReadWrite', 'ReadWrite').Dispose() } catch { $blocked = $true } } finally { $handle.Dispose() }
        Check $blocked 'a recovery write handle denies a concurrent data write'
        $deep = Join-Path $work 'pin\a\b'; New-Item -ItemType Directory -Force -Path $deep | Out-Null; [IO.File]::WriteAllText((Join-Path $deep 'c.txt'), "c`n")
        $pins = @(Open-MiosBoundaryAncestors (Join-Path $deep 'c.txt'))
        try { $renamed = $true; try { [IO.Directory]::Move($deep, "$deep-moved") } catch { $renamed = $false } } finally { foreach ($p in $pins) { $p.Handle.Dispose() } }
        Check (-not $renamed -and $pins.Count -ge 3) 'pinned ancestors cannot be renamed during a repair'
        $outside = Join-Path $work 'outside.txt'; [IO.File]::WriteAllText($outside, "outside`n")
        $link = Join-Path $tree 'usr\share\linked.txt'; New-Item -ItemType HardLink -Path $link -Target $outside | Out-Null
        Expect-ThrowMatch { Read-MiosBoundaryObject $link } 'hard-linked file' 'a hard-linked file is refused'
        Check ((Read-MiosBoundaryObject $link -Lenient).Links -eq '2') 'a lenient read records a sibling without refusing it'
        $elsewhere = Join-Path $work 'elsewhere'; New-Item -ItemType Directory -Path $elsewhere | Out-Null; [IO.File]::WriteAllText((Join-Path $elsewhere 'inner.txt'), "x`n")
        $junction = Join-Path $tree 'usr\share\mios\sub\junction'; New-Item -ItemType Junction -Path $junction -Target $elsewhere | Out-Null
        Expect-ThrowMatch { Read-MiosBoundaryObject $junction } 'reparse point' 'a junction is refused at the target'
        Expect-ThrowMatch { Read-MiosBoundaryObject (Join-Path $junction 'inner.txt') } 'resolves elsewhere' 'a path through a junction is refused'
        Expect-ThrowMatch { Get-MiosBoundaryDescendants (Join-Path $tree 'usr\share\mios') } 'reparse point below' 'a junction below a leaf is refused'
        [IO.Directory]::Delete($junction)
        Check (@(Get-MiosBoundaryDescendants (Join-Path $tree 'usr\share\mios')).Count -eq 4) 'descendants of a clean leaf are listed'
        Expect-ThrowMatch { Get-MiosBoundaryDescendants (Join-Path $tree 'usr') -Limit 3 } 'more than 3 descendants' 'the descendant guard is bounded'
        $parent = Join-Path $work 'inherit'; New-Item -ItemType Directory -Path $parent | Out-Null
        $child = Join-Path $parent 'child.txt'; [IO.File]::WriteAllText($child, "c`n")
        $sealed = Join-Path $parent 'sealed.txt'; [IO.File]::WriteAllText($sealed, "s`n")
        $h = [MiosMachineBoundaryNative]::Open($parent, $true)
        try { [MiosMachineBoundaryNative]::SetDacl($h, "D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$me)", $true) } finally { $h.Dispose() }
        Add-Ace $child 'S-1-1-0' 'ReadAndExecute' 'None'
        $h = [MiosMachineBoundaryNative]::Open($sealed, $true)
        try { [MiosMachineBoundaryNative]::SetDacl($h, "D:(A;;FA;;;$me)", $true) } finally { $h.Dispose() }
        $sealedBefore = (Read-MiosBoundaryObject $sealed).Sddl
        Update-MiosBoundaryInheritance -Object (Read-MiosBoundaryObject $child) -Backup 'fixture'
        Update-MiosBoundaryInheritance -Object (Read-MiosBoundaryObject $sealed) -Backup 'fixture'
        $after = New-Object Security.AccessControl.RawSecurityDescriptor (Read-MiosBoundaryObject $child).Sddl
        $inheritedSids = @(@($after.DiscretionaryAcl) | Where-Object { [int]$_.AceFlags -band 0x10 } | ForEach-Object { $_.SecurityIdentifier.Value } | Sort-Object)
        Check ((Get-MiosExplicitAces (Read-MiosBoundaryObject $child).Sddl).Count -eq 1 -and
               ($inheritedSids -join ',') -eq ((@('S-1-5-18', 'S-1-5-32-544', $me) | Sort-Object) -join ',')) 'an inheritance update keeps explicit ACEs and takes inherited ACEs from the parent'
        Check ((Read-MiosBoundaryObject $sealed).Sddl -ceq $sealedBefore) 'a protected descendant is left untouched'
        $stale = Read-MiosBoundaryObject $child; $stale.Index = '0000000000000000'
        Expect-ThrowMatch { Update-MiosBoundaryInheritance -Object $stale -Backup 'fixture' } 'changed before its inheritance update' 'an inheritance update refuses a replaced object'
    } finally {
        Get-ChildItem -LiteralPath $work -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue | ForEach-Object { [IO.Directory]::Delete($_.FullName) }
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
    return $script:fail
}

function Invoke-Prepare([string]$Root) {
    if (Test-Path -LiteralPath $Root) { throw "Scratch root already exists: $Root" }
    New-Item -ItemType Directory -Path $Root | Out-Null
    foreach ($name in 'tree', 'foreign', 'deny', 'hardlink', 'junction') { New-Tree (Join-Path $Root $name) }
    Add-Ace (Join-Path $Root 'deny\usr') 'S-1-1-0' 'Delete' 'None' 'Deny'
    [IO.File]::WriteAllText((Join-Path $Root 'outside.txt'), "outside`n")
    New-Item -ItemType HardLink -Path (Join-Path $Root 'hardlink\usr\share\mios\sub\linked.txt') -Target (Join-Path $Root 'outside.txt') | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $Root 'elsewhere') | Out-Null
    New-Item -ItemType Junction -Path (Join-Path $Root 'junction\usr\share\mios\sub\junction') -Target (Join-Path $Root 'elsewhere') | Out-Null
    [IO.File]::WriteAllText((Join-Path $Root 'origin.sid'), [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    Write-Host "BOUNDARY_RECOVERY_PREPARED $Root"
}

function Set-FixtureOwner([string]$Path, [string]$Sid) {
    $h = [MiosMachineBoundaryNative]::Open($Path, $true)
    try {
        $raw = New-Object Security.AccessControl.RawSecurityDescriptor ([MiosMachineBoundaryNative]::GetSddl($h))
        $raw.Owner = New-Object Security.Principal.SecurityIdentifier $Sid
        [MiosMachineBoundaryNative]::SetSddl($h, $raw.GetSddlForm([Security.AccessControl.AccessControlSections]'Owner, Access'))
    } finally { $h.Dispose() }
}

function Invoke-ElevatedChecks([string]$Root) {
    $script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
    $null = Import-Product $ProductPath
    if (-not (Test-MiosElevated)) { throw '-Elevated must run in an elevated session.' }
    Initialize-MiosMachineBoundaryApi
    [MiosMachineBoundaryNative]::EnablePrivilege('SeRestorePrivilege')
    $op = if ($OriginSid) { $OriginSid } else { [IO.File]::ReadAllText((Join-Path $Root 'origin.sid')).Trim() }
    $tree = Join-Path $Root 'tree'
    # Shape the real machine: usr owned by Administrators, etc by SYSTEM, the MiOS leaves and usr\share by the operator.
    Set-FixtureOwner (Join-Path $tree 'usr') 'S-1-5-32-544'; Set-FixtureOwner (Join-Path $tree 'etc') 'S-1-5-18'
    Set-FixtureOwner (Join-Path $Root 'foreign\usr') 'S-1-5-19'
    $targets = @('usr', 'usr\share', 'usr\share\mios', 'usr\share\mios\mios.toml', 'etc', 'etc\mios') | ForEach-Object { Join-Path $tree $_ }
    $siblings = @('usr\local', 'usr\local\keep.txt', 'etc\ssh', 'etc\ssh\sshd_config') | ForEach-Object { Join-Path $tree $_ }
    $leafKids = @('usr\share\mios\build-manifest.json', 'usr\share\mios\sub', 'usr\share\mios\sub\note.txt', 'etc\mios\mios.toml') | ForEach-Object { Join-Path $tree $_ }
    Check (@($targets | Where-Object { -not (Get-MiosMachineBoundaryGap $_) }).Count -eq 0) 'every prepared boundary object is refused by admission before recovery'
    $orig = @{}; foreach ($p in $targets + $siblings + $leafKids) { $orig[$p] = Read-MiosBoundaryObject $p -Lenient }
    $tomlBytes = @{}; foreach ($t in 'usr\share\mios\mios.toml', 'etc\mios\mios.toml') { $tomlBytes[(Join-Path $tree $t)] = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $tree $t))) }
    $vault = Join-Path $Root 'vault'; New-MiosProtectedMachineDirectory $vault
    $backupDir = Join-Path $vault 'boundary-recovery'
    $backup = Invoke-MiosMachineBoundaryRecovery -OriginSid $op -Root $tree -BackupDirectory $backupDir
    Check (@($targets | Where-Object { Get-MiosMachineBoundaryGap $_ }).Count -eq 0) 'every boundary object passes the unchanged admission after recovery'
    $owners = @{}; foreach ($p in $targets) { $owners[$p.Substring($tree.Length + 1)] = (Read-MiosBoundaryObject $p).Owner }
    Check ($owners['usr'] -eq 'S-1-5-32-544' -and $owners['etc'] -eq 'S-1-5-18' -and $owners['usr\share'] -eq 'S-1-5-32-544' -and $owners['usr\share\mios'] -eq 'S-1-5-32-544' -and
           $owners['etc\mios'] -eq 'S-1-5-32-544') 'trusted owners are kept and only the operator owners are replaced'
    $usr = (Read-MiosBoundaryObject (Join-Path $tree 'usr')).Sddl
    Check ($usr -clike "O:BAD:P$self*" -and $usr -match '\(A;OICIIO;0x1301bf;;;AU\)') 'a shared prefix gets trusted self access and keeps its child templates as InheritOnly'
    $sibOk = $true
    foreach ($p in $siblings) { $now = Read-MiosBoundaryObject $p -Lenient; foreach ($f in 'Sddl', 'Owner', 'Index', 'Written', 'Sha256') { if ($now.$f -cne $orig[$p].$f) { $sibOk = $false; Write-Host "    sibling $p $f changed" } } }
    Check $sibOk 'siblings under shared prefixes keep their descriptor, identity and bytes'
    $kidOk = $true
    foreach ($p in $leafKids) {
        $now = Read-MiosBoundaryObject $p
        foreach ($f in 'Owner', 'Index', 'Written', 'Sha256') { if ($now.$f -ne $orig[$p].$f) { $kidOk = $false } }
        if (-not (Test-MiosSameExplicitAces -Before $orig[$p].Sddl -After $now.Sddl) -or @(Get-MiosInheritedWriteGrants $now.Sddl).Count) { $kidOk = $false }
    }
    Check $kidOk 'leaf descendants keep owner, explicit ACEs and bytes and lose inherited write grants'
    $backups = @(Get-ChildItem -LiteralPath $backupDir -Filter '*.json')
    $doc = [IO.File]::ReadAllText($backups[0].FullName) | ConvertFrom-Json
    Check ($backups.Count -eq 1 -and $backup -eq $backups[0].FullName -and $doc.schema -ceq 'mios-boundary-recovery/2') 'one schema-tagged backup per recovery run'
    $recorded = @{}; foreach ($o in @($doc.objects)) { $recorded[$o.Path] = $o.Sddl }
    Check (@($targets | Where-Object { $recorded[$_] -cne $orig[$_].Sddl }).Count -eq 0 -and @($leafKids | Where-Object { $recorded[$_] -cne $orig[$_].Sddl }).Count -eq 0) 'the backup holds the original descriptor of every recovered object and leaf descendant'
    Check (@($doc.tomls).Count -eq 2 -and @(@($doc.tomls) | Where-Object { $tomlBytes[$_.Path] -cne $_.Bytes }).Count -eq 0) 'the backup holds the exact original vendor and host TOML bytes'
    $acl = Get-Acl -LiteralPath $backup
    $sids = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value })
    Check ($acl.AreAccessRulesProtected -and $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544' -and
           @($sids | Where-Object { $_ -notin @('S-1-5-18', 'S-1-5-32-544') }).Count -eq 0) 'the backup leaf is private to SYSTEM and Administrators'
    $again = Invoke-MiosMachineBoundaryRecovery -OriginSid $op -Root $tree -BackupDirectory $backupDir
    Check ($null -eq $again -and @(Get-ChildItem -LiteralPath $backupDir -Filter '*.json').Count -eq 1) 'a second run changes nothing and writes no backup'
    Restore-MiosMachineBoundary -BackupPath $backup
    $mismatch = @($targets + $leafKids | Where-Object { (Read-MiosBoundaryObject $_).Sddl -cne $orig[$_].Sddl })
    if ($mismatch.Count) { $mismatch | ForEach-Object { Write-Host "    restore mismatch $_`n      was $($orig[$_].Sddl)`n      now $((Read-MiosBoundaryObject $_).Sddl)" } }
    Check ($mismatch.Count -eq 0) 'restoring the backup returns every original descriptor exactly'
    $sibOk = $true; foreach ($p in $siblings) { if ((Read-MiosBoundaryObject $p -Lenient).Sddl -cne $orig[$p].Sddl) { $sibOk = $false } }
    Check $sibOk 'siblings are still unchanged after the restore'
    $null = Invoke-MiosMachineBoundaryRecovery -OriginSid $op -Root $tree -BackupDirectory $backupDir
    Check (@($targets | Where-Object { Get-MiosMachineBoundaryGap $_ }).Count -eq 0) 'recovery works again after a restore'
    foreach ($case in @(@('foreign', 'only SYSTEM, Administrators or the validated operator'), @('deny', 'unreviewed ACE'), @('hardlink', 'hard-linked file'), @('junction', 'reparse point below'))) {
        $t = Join-Path $Root $case[0]; $usrBefore = (Read-MiosBoundaryObject (Join-Path $t 'usr') -Lenient).Sddl
        $count = @(Get-ChildItem -LiteralPath $backupDir -Filter '*.json').Count
        Expect-ThrowMatch { Invoke-MiosMachineBoundaryRecovery -OriginSid $op -Root $t -BackupDirectory $backupDir } $case[1] "recovery refuses the $($case[0]) tree"
        Check ((Read-MiosBoundaryObject (Join-Path $t 'usr') -Lenient).Sddl -ceq $usrBefore -and @(Get-ChildItem -LiteralPath $backupDir -Filter '*.json').Count -eq $count) "the $($case[0]) refusal changes nothing and writes no backup"
    }
    Write-Host "BOUNDARY_RECOVERY_ELEVATED_ASSERTIONS $($script:checks)"
    return $script:fail
}

if ($Prepare) { if (-not $ScratchRoot) { throw '-Prepare needs -ScratchRoot.' }; Invoke-Prepare $ScratchRoot; exit 0 }
if ($Elevated) {
    if (-not $ScratchRoot) { throw '-Elevated needs -ScratchRoot.' }
    $log = Join-Path $ScratchRoot ('elevated-' + $PSVersionTable.PSEdition + '.log')
    Start-Transcript -LiteralPath $log -Force | Out-Null
    try {
        $failures = Invoke-ElevatedChecks $ScratchRoot
        if ($failures) { Write-Host "RESULT: FAIL ($failures checks)" } else { Write-Host 'RESULT: PASS (elevated scratch recovery, siblings unchanged, restore)' }
    } catch { Write-Host "RESULT: ERROR $($_.Exception.Message)"; $failures = 1 } finally { Stop-Transcript | Out-Null }
    exit ([int]($failures -ne 0))
}
if (-not $PlantDefect) {
    $failures = Invoke-SourceChecks $ProductPath
    Write-Host "BOUNDARY_RECOVERY_ASSERTIONS $($script:checks)"
    if ($failures) { Write-Host "RESULT: FAIL ($failures checks)"; exit 1 }
    Write-Host 'RESULT: PASS (boundary recovery source and unelevated Windows ACL fixtures)'; exit 0
}
$baseline = Invoke-SourceChecks $ProductPath
if ($baseline) { throw 'BOUNDARY_RECOVERY_BASELINE_FAILED' }
$plants = @(
    @{ Name = 'shared self access writable'; Expected = 'a shared prefix keeps only trusted self access and every inheritable ACE as an InheritOnly template'; From = "@('S-1-5-32-545', 0x1200A9)"; To = "@('S-1-5-32-545', 0x1301BF)" },
    @{ Name = 'templates not InheritOnly'; Expected = 'a shared prefix keeps only trusted self access and every inheritable ACE as an InheritOnly template'; From = '(($flags -bor 0x08) -band (-bnot 0x10))'; To = '($flags -band (-bnot 0x10))' },
    @{ Name = 'foreign owner accepted'; Expected = 'any other owner is refused'; From = 'throw "Boundary recovery refuses $Path owned by'; To = 'return ''S-1-5-32-544''; throw "Boundary recovery refuses $Path owned by' },
    @{ Name = 'trusted owner replaced'; Expected = 'a SYSTEM or Administrators owner is kept'; From = "if (`$Owner -in @('S-1-5-18', 'S-1-5-32-544')) { return `$Owner }"; To = "if (`$Owner -in @('S-1-5-18', 'S-1-5-32-544')) { return 'S-1-5-32-544' }" },
    @{ Name = 'deny ACE accepted'; Expected = 'an explicit deny ACE is refused'; From = "-or [string]`$ace.AceQualifier -ne 'AccessAllowed' -or `$ace.IsCallback"; To = '-or $ace.IsCallback' },
    @{ Name = 'M: default scope'; Expected = 'recovery defaults to the system drive and never names M:'; From = "if (-not `$Root) { `$Root = if (`$env:SystemDrive) { `$env:SystemDrive } else { 'C:' } }"; To = "if (-not `$Root) { `$Root = 'M:' }" },
    @{ Name = 'recovery removed from preparation'; Expected = 'recovery runs after origin validation and before TOML publication, with the origin SID'; From = '    $null = Invoke-MiosMachineBoundaryRecovery -OriginSid ([string]$Context.Sid)'; To = '    $null = [string]$Context.Sid' },
    @{ Name = 'host tier rewrites existing parents'; Expected = 'host-tier directories use strict admission or atomic protected creation'; From = 'if (Test-Path -LiteralPath $d) { Assert-MiosMachineWriteBoundary $d } else { New-MiosProtectedMachineDirectory $d }'; To = 'if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -ErrorAction Stop | Out-Null }; Set-MiosHostTierAcl $d' },
    @{ Name = 'backup skipped'; Expected = 'recovery validates policy and owners and backs up before changing any descriptor'; From = '$backup = Save-MiosBoundaryBackup -Objects'; To = '$backup = Write-Output -InputObject' },
    @{ Name = 'ancestors not pinned'; Expected = 'every repair pins its ancestors first'; From = '$pins = @(Open-MiosBoundaryAncestors $step.Path)'; To = '$pins = @()' },
    @{ Name = 'write handle shares write'; Expected = 'a recovery write handle denies a concurrent data write'; From = 'write ? 1u : 7u'; To = '7u'; Native = $true },
    @{ Name = 'write handle without data access'; Expected = 'a recovery write handle denies a concurrent data write'; From = '(write ? (0x1u | 0x40000u | 0x80000u) : 0u)'; To = '(write ? (0x40000u | 0x80000u) : 0u)'; Native = $true },
    @{ Name = 'ancestor pin shares delete'; Expected = 'pinned ancestors cannot be renamed during a repair'; From = 'CreateFileW(path, 0x1u | 0x20000u | 0x80u, 3u,'; To = 'CreateFileW(path, 0x1u | 0x20000u | 0x80u, 7u,'; Native = $true },
    @{ Name = 'ancestor pin without data access'; Expected = 'pinned ancestors cannot be renamed during a repair'; From = 'CreateFileW(path, 0x1u | 0x20000u | 0x80u, 3u,'; To = 'CreateFileW(path, 0x20000u | 0x80u, 3u,'; Native = $true },
    @{ Name = 'target reparse check removed'; Expected = 'a junction is refused at the target'; From = 'if ($isReparse) { throw "Boundary recovery refuses a reparse point: $full" }'; To = '' },
    @{ Name = 'hardlink check removed'; Expected = 'a hard-linked file is refused'; From = 'if (-not $isDirectory -and $info.Links -ne 1) {'; To = 'if ($false) {' },
    @{ Name = 'descendant reparse check removed'; Expected = 'a junction below a leaf is refused'; From = 'if ($attributes -band [IO.FileAttributes]::ReparsePoint) { throw'; To = 'if ($false) { throw' },
    @{ Name = 'descendant bound removed'; Expected = 'the descendant guard is bounded'; From = 'if ($found.Count -ge $Limit) {'; To = 'if ($false) {' },
    @{ Name = 'elevation check removed'; Expected = 'an unelevated run refuses recovery'; From = 'if (-not (Test-MiosElevated)) { throw "Boundary recovery requires'; To = 'if ($false) { throw "Boundary recovery requires' },
    @{ Name = 'compliant run not skipped'; Expected = 'a run where every path already passes admission changes nothing'; From = 'if (-not $plan.Count) { return $null }'; To = '' },
    @{ Name = 'admission weakened'; Expected = 'admission helper Assert-MiosMachineWriteBoundary is unchanged from its reviewed source'; From = "if (`$owner -notin `$trusted) { throw 'An existing machine TOML path has an untrusted owner.' }"; To = '' },
    @{ Name = 'worker lacks a helper'; Expected = 'worker extraction resolves every helper the recovery calls'; From = "'Assert-MiosBoundaryAcePolicy', 'New-MiosSharedPrefixSddl', 'New-MiosLeafSddl', 'Open-MiosBoundaryAncestors',"; To = "'Assert-MiosBoundaryAcePolicy', 'New-MiosSharedPrefixSddl', 'New-MiosLeafSddl'," },
    @{ Name = 'planned target kept as a leaf descendant'; Expected = 'a planned target below a leaf is its own step, not a leaf descendant'; From = 'Get-MiosBoundaryDescendants $step.Path | Where-Object { $_ -notin $planned } |'; To = 'Get-MiosBoundaryDescendants $step.Path |' },
    @{ Name = 'inheritance update skipped'; Expected = 'leaf descendants are re-inherited after the descriptor change'; From = 'Update-MiosBoundaryInheritance -Object $child -Backup $backup'; To = '$null = $child' },
    @{ Name = 'inheritance update drops explicit ACEs'; Expected = 'an inheritance update keeps explicit ACEs and takes inherited ACEs from the parent'; From = 'if (-not ([int]$ace.AceFlags -band 0x10)) { $explicit.InsertAce'; To = 'if ([int]$ace.AceFlags -band 0x10) { $explicit.InsertAce' },
    @{ Name = 'explicit ACE comparison precedence'; Expected = 'explicit ACE comparison ignores inherited changes and detects explicit ones'; From = "return [bool](((Get-MiosExplicitAces `$Before) -join ';') -ceq ((Get-MiosExplicitAces `$After) -join ';'))"; To = "return (Get-MiosExplicitAces `$Before) -join ';' -ceq (Get-MiosExplicitAces `$After) -join ';'" },
    @{ Name = 'inherited write grants ignored'; Expected = 'inherited write grants are found only where they apply to the object'; From = "[string]`$_.AceQualifier -eq 'AccessAllowed' -and (`$_.AccessMask"; To = "[string]`$_.AceQualifier -eq 'Never' -and (`$_.AccessMask" },
    @{ Name = 'leaf descriptor private'; Expected = 'a leaf gets exactly the descriptor fresh creation uses, with the decided owner'; From = '(New-MiosMachineCreationAcl -Directory:$Directory)'; To = '(New-MiosMachineCreationAcl -Directory:$Directory -Private)' }
)
$caught = 0
$copyDir = Join-Path ([IO.Path]::GetTempPath()) ('mios-boundary-plants-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $copyDir | Out-Null
try {
    foreach ($plant in $plants) {
        $source = [IO.File]::ReadAllText($ProductPath)
        $at = $source.IndexOf($plant.From, [StringComparison]::Ordinal)
        if ($at -lt 0 -or $source.IndexOf($plant.From, $at + 1, [StringComparison]::Ordinal) -ge 0) { throw "Missing or ambiguous defect anchor: $($plant.Name)" }
        $copy = Join-Path $copyDir ('planted-' + $caught + '-' + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.ps1')
        [IO.File]::WriteAllText($copy, $source.Replace($plant.From, $plant.To), (New-Object Text.UTF8Encoding($false)))
        # The native type is compiled once per process; a planted C# change needs a fresh engine to take effect.
        if ($plant.Native) {
            $engine = (Get-Process -Id $PID).Path
            $out = & $engine -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $PSCommandPath -ProductPath $copy 2>&1
            $detected = [bool]($out | Where-Object { "$_" -match ('^\s*FAIL ' + [regex]::Escape($plant.Expected)) })
        } else {
            $null = Invoke-SourceChecks $copy
            $detected = $script:failedChecks.Contains($plant.Expected)
        }
        Write-Host ('  {0} planted defect caught: {1}' -f $(if ($detected) { 'PASS' } else { 'FAIL' }), $plant.Name)
        if ($detected) { $caught++ }
    }
} finally { Remove-Item -LiteralPath $copyDir -Recurse -Force -ErrorAction SilentlyContinue }
if ($caught -eq $plants.Count) { Write-Host "RESULT: PASS (every planted defect was caught: $caught/$($plants.Count))"; exit 0 }
Write-Host "RESULT: FAIL (planted defects caught: $caught/$($plants.Count))"; exit 1
