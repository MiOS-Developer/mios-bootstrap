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
    'New-MiosSharedPrefixSddl', 'New-MiosLeafSddl', 'Open-MiosBoundaryAncestors', 'Update-MiosBoundaryInheritance', 'Get-MiosNamedStreams',
    'Get-MiosNewReaders', 'Initialize-MiosBoundaryBackupDirectory', 'Assert-MiosPrivateBackupLeaf', 'Save-MiosTomlBackup', 'Save-MiosBoundaryBackup',
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
    $tomlSave = Get-Calls $invoke 'Save-MiosTomlBackup'; $readers = Get-Calls $invoke 'Get-MiosNewReaders'
    Check ($set.Count -eq 1 -and $save.Count -eq 1 -and $tomlSave.Count -eq 1 -and $elev.Count -eq 1 -and $owner.Count -eq 1 -and $policy.Count -eq 1 -and
           $elev[0].Extent.StartOffset -lt $tomlSave[0].Extent.StartOffset -and $owner[0].Extent.StartOffset -lt $tomlSave[0].Extent.StartOffset -and
           $policy[0].Extent.StartOffset -lt $tomlSave[0].Extent.StartOffset -and $tomlSave[0].Extent.StartOffset -lt $save[0].Extent.StartOffset -and
           $save[0].Extent.StartOffset -lt $set[0].Extent.StartOffset) 'recovery validates policy and owners and backs up TOML bytes and descriptors before changing any descriptor'
    Check (@($readers | Where-Object { $_.Extent.StartOffset -lt $tomlSave[0].Extent.StartOffset }).Count -ge 2) 'recovery refuses read growth on every target and inheriting descendant before any backup'
    Check ($pin.Count -eq 2 -and $pin[0].Extent.StartOffset -lt $tomlSave[0].Extent.StartOffset -and $pin[1].Extent.StartOffset -lt $set[0].Extent.StartOffset) 'every repair pins its ancestors first'
    Check ($invoke.Extent.Text.Contains("-cne (`$step.Chain -join ';')")) 'the ancestor chain recorded at planning is compared before each repair'
    $vendorAt = $invoke.Extent.Text.IndexOf("Rel = 'usr\share\mios\mios.toml'; Policy = 'vendor-toml'"); $leafAt = $invoke.Extent.Text.IndexOf("Rel = 'usr\share\mios'; Policy = 'leaf'")
    $hostAt = $invoke.Extent.Text.IndexOf("Rel = 'etc\mios\mios.toml'; Policy = 'host-toml'"); $etcLeafAt = $invoke.Extent.Text.IndexOf("Rel = 'etc\mios'; Policy = 'leaf'")
    Check ($vendorAt -ge 0 -and $vendorAt -lt $leafAt -and $hostAt -ge 0 -and $hostAt -lt $etcLeafAt -and
           $invoke.Extent.Text.Contains("'host-toml' { New-MiosLeafSddl -Directory `$false -Owner `$owner -Private }")) 'both TOML files are protected before their namespace directory, the host TOML privately'
    Check ($inherit.Count -eq 1 -and $inherit[0].Extent.StartOffset -gt $set[0].Extent.StartOffset) 'leaf descendants are re-inherited after the descriptor change'
    # The elevated worker holds SeRestorePrivilege disabled: an administrator cannot assign SYSTEM as owner, so a kept owner
    # (SYSTEM on C:\etc) must never be rewritten. Only the protected DACL changes; a replaced owner is always Administrators.
    $daclSet = @($members | Where-Object { $_.Member.Extent.Text -eq 'SetDacl' })
    Check ($daclSet.Count -eq 1 -and $set.Count -eq 1 -and $daclSet[0].Extent.StartOffset -lt $set[0].Extent.StartOffset -and
           $invoke.Extent.Text.Contains('if ($step.Owner -eq $step.Record.Owner) { [MiosMachineBoundaryNative]::SetDacl($handle, $target, $true) }') -and
           -not $invoke.Extent.Text.Contains('EnablePrivilege')) 'a kept owner is never rewritten, so recovery needs no SeRestorePrivilege'
    $descend = Get-Calls $invoke 'Get-MiosBoundaryDescendants'
    Check ($descend.Count -eq 1 -and $descend[0].Parent.Extent.Text -match '\|\s*Where-Object\s*\{\s*\$_\s+-notin\s+\$planned\s*\}') 'a planned target below a leaf is its own step, not a leaf descendant'
    $tomlBackup = Get-Function $ast 'Save-MiosTomlBackup'
    Check ($tomlBackup.Extent.Text.Contains('Owner = $record.Owner; Sddl = $record.Sddl') -and
        -not $invoke.Extent.Text.Contains('if (-not $plan.Count) { return $null }')) 'every TOML backup retains owner and descriptor and compliant runs write private metadata'
    $restore = Get-Function $ast 'Restore-MiosMachineBoundary'
    $restorePins = Get-Calls $restore 'Open-MiosBoundaryAncestors'
    $restoreMembers = @($restore.FindAll({ param($n) $n -is [Management.Automation.Language.InvokeMemberExpressionAst] }, $true))
    $restoreHashes = @($restoreMembers | Where-Object { $_.Member.Extent.Text -eq 'Sha256' })
    $restoreSets = @($restoreMembers | Where-Object { $_.Member.Extent.Text -eq 'SetSddl' })
    Check ($restorePins.Count -eq 1 -and $restoreHashes.Count -eq 2 -and $restoreSets.Count -eq 1 -and
        $restoreHashes[1].Extent.StartOffset -lt $restoreSets[0].Extent.StartOffset -and
        $restore.Extent.Text.Contains('$handle = $target.Handle') -and
        $restore.Extent.Text.Contains('foreach ($target in $targets) { $target.Handle.Dispose() }')) 'restore retains ancestor and target handles and hashes through the apply handle'
    Check ((Get-Function $ast 'Read-MiosBoundaryObject').Extent.Text.Contains('[MiosMachineBoundaryNative]::ReadBytes($handle)') -and
        -not (Get-Function $ast 'Read-MiosBoundaryObject').Extent.Text.Contains('[IO.File]::ReadAllBytes')) 'boundary byte snapshots use their validated data handle'
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
    $privateFile = (New-MiosMachineCreationAcl -Private).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Owner, Access')
    Check ((New-MiosLeafSddl -Directory $false -Owner 'S-1-5-32-544' -Private) -ceq $privateFile -and $privateFile -notmatch ';BU\)|;AU\)|;WD\)') 'a private leaf is SYSTEM and Administrators only'
    $op9 = 'S-1-5-21-9-9-9-1001'
    $leafAfter = New-MiosLeafSddl -Directory $true -Owner 'S-1-5-32-544'
    Check (@(Get-MiosNewReaders -Before 'O:BAD:AI(A;ID;0x1301bf;;;AU)(A;ID;FA;;;SY)' -After $leafAfter).Count -eq 0 -and
           @(Get-MiosNewReaders -Before 'O:BAD:AI(A;ID;0x1200a9;;;BU)' -After $leafAfter).Count -eq 0 -and
           @(Get-MiosNewReaders -Before 'O:BAD:(A;;FR;;;WD)' -After 'O:BAD:(A;;FR;;;S-1-5-21-1)').Count -eq 0 -and
           @(Get-MiosNewReaders -Before 'O:BAD:NO_ACCESS_CONTROL' -After $leafAfter).Count -eq 0 -and
           @(Get-MiosNewReaders -Before "O:BAD:P(A;;FA;;;$op9)" -After "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;OICIIO;FR;;;BU)").Count -eq 0) 'read already granted to Users, Authenticated Users or Everyone, or only to SYSTEM and Administrators, is not growth'
    Check ((@(Get-MiosNewReaders -Before "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;$op9)" -After $leafAfter) -join ',') -eq 'S-1-5-32-545' -and
           (@(Get-MiosNewReaders -Before 'O:BAD:P(A;;FA;;;SY)' -After "O:BAD:P(A;;GR;;;$op9)") -join ',') -eq $op9) 'read growth is detected for Users and for any other new reader'
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
        if (-not ('MiosBoundaryFixtureOpen' -as [type])) {
            Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class MiosBoundaryFixtureOpen {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    // Opens a directory with the given access and full sharing; 0 on success, otherwise the Win32 error.
    public static int Try(string path, uint access) {
        using (SafeFileHandle handle = CreateFileW(path, access, 7u, IntPtr.Zero, 3u, 0x02000000u, IntPtr.Zero)) { return handle.IsInvalid ? Marshal.GetLastWin32Error() : 0; }
    }
}
'@
        }
        $tree = Join-Path $work 'tree'; New-Tree $tree
        $script:saves = 0; $script:tomlSaves = New-Object System.Collections.Generic.List[string]
        $script:compliantObjects = @()
        function global:Save-MiosBoundaryBackup { param($Objects, $Tomls, $Directory, $Reason) $script:saves++; $script:compliantObjects = @($Objects); return 'fixture-private-run.json' }
        function global:Save-MiosTomlBackup { param($Path, $Role, $Directory) $script:tomlSaves.Add($Role); Read-MiosBoundaryObject $Path }
        function global:Get-MiosMachineBoundaryGap { return '' }
        function global:Test-MiosElevated { return $true }
        $result = 'threw'; try { $result = Invoke-MiosMachineBoundaryRecovery -OriginSid $me -Root $tree } catch { Write-Host "    compliant run threw: $($_.Exception.Message)" }
        Check ($result -eq 'fixture-private-run.json' -and $script:saves -eq 1 -and $script:compliantObjects.Count -eq 2 -and
            @($script:compliantObjects | Where-Object { -not $_.Owner -or -not $_.Sddl }).Count -eq 0) 'a compliant run records both original descriptors before publication without ACL recovery'
        Check (($script:tomlSaves -join ',') -eq 'vendor,host') 'a compliant run still preserves both TOML files before any writer'
        $null = Import-Product $Path
        $script:saves = 0
        $script:tomlSaves.Clear()
        function global:Save-MiosBoundaryBackup { $script:saves++; throw 'Fixture: no backup may be written in an unelevated check.' }
        function global:Save-MiosTomlBackup { param($Path, $Role, $Directory) $script:tomlSaves.Add($Role); throw 'Fixture: no TOML backup may be written in an unelevated check.' }
        $before = (Read-MiosBoundaryObject (Join-Path $tree 'usr')).Sddl
        if (-not (Test-MiosElevated)) {
            Expect-ThrowMatch { Invoke-MiosMachineBoundaryRecovery -OriginSid $me -Root $tree } 'requires an elevated token' 'an unelevated run refuses recovery'
            Check ($script:saves -eq 0 -and $script:tomlSaves.Count -eq 0 -and (Read-MiosBoundaryObject (Join-Path $tree 'usr')).Sddl -ceq $before) 'no backup and no descriptor change without elevation'
        }
        $null = Import-Product $Path
        $streamed = Join-Path $work 'streamed.toml'; [IO.File]::WriteAllText($streamed, "[meta]`n")
        Check (@(Get-MiosNamedStreams $streamed).Count -eq 0) 'a plain file has no alternate data streams'
        Set-Content -LiteralPath $streamed -Stream 'mios.fixture' -Value 'hidden'
        Check ((@(Get-MiosNamedStreams $streamed) -join ',') -eq ':mios.fixture:$DATA') 'an alternate data stream is found by name'
        $adsDir = Join-Path $work 'ads-backups'
        Expect-ThrowMatch { Save-MiosTomlBackup -Path $streamed -Role vendor -Directory $adsDir } 'alternate data stream' 'a TOML with an alternate data stream is refused'
        Check (-not (Test-Path -LiteralPath $adsDir)) 'the alternate data stream refusal writes no backup'
        Expect-ThrowMatch { Assert-MiosPrivateBackupLeaf (Join-Path $tree 'usr\share\mios\mios.toml') } 'Not a private MiOS boundary backup' 'an ordinary file is not accepted as a private backup leaf'
        $file = Join-Path $tree 'usr\share\mios\mios.toml'
        $plain = Read-MiosBoundaryObject $file -WithBytes
        Check ($plain.Kind -eq 'file' -and $plain.Owner -eq $me -and $plain.Sha256 -match '^[0-9a-f]{64}$' -and $plain.Index -match '^[0-9a-f]{16}$' -and
               [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($plain.Bytes)) -ceq [IO.File]::ReadAllText($file)) 'a file reads by handle with owner, descriptor, identity, hash and exact bytes'
        $handle = [MiosMachineBoundaryNative]::Open($file, $true)
        try { $blocked = $false; try { [IO.File]::Open($file, 'Open', 'ReadWrite', 'ReadWrite').Dispose() } catch { $blocked = $true } } finally { $handle.Dispose() }
        Check $blocked 'a recovery write handle denies a concurrent data write'
        $deep = Join-Path $work 'pin\a\b'; New-Item -ItemType Directory -Force -Path $deep | Out-Null; [IO.File]::WriteAllText((Join-Path $deep 'c.txt'), "c`n")
        $pins = @(Open-MiosBoundaryAncestors (Join-Path $deep 'c.txt'))
        try {
            $renamed = $true; try { [IO.Directory]::Move($deep, "$deep-moved") } catch { $renamed = $false }
            $writer = [MiosBoundaryFixtureOpen]::Try($deep, 0x2)   # FILE_ADD_FILE: a directory opened for writing
            $deleter = [MiosBoundaryFixtureOpen]::Try($deep, 0x10000)   # DELETE: a directory opened to be removed or renamed
        } finally { foreach ($p in $pins) { $p.Handle.Dispose() } }
        Check (-not $renamed -and $pins.Count -ge 3) 'pinned ancestors cannot be renamed during a repair'
        Check ($deleter -eq 32) 'pinned ancestors deny a concurrent delete open'
        Check ($writer -eq 32 -and [MiosBoundaryFixtureOpen]::Try($deep, 0x2) -eq 0) 'pinned ancestors deny a concurrent writer and release it afterwards'
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
    foreach ($name in 'tree', 'foreign', 'deny', 'hardlink', 'junction', 'narrow', 'narrowkids', 'ads') { New-Tree (Join-Path $Root $name) }
    Add-Ace (Join-Path $Root 'deny\usr') 'S-1-1-0' 'Delete' 'None' 'Deny'
    # narrow: a private namespace (no Users or Authenticated Users read), so hardening its TOML would add a reader.
    # narrowkids: the namespace itself is readable by Authenticated Users but its children are not (no vendor TOML here).
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($name in 'narrow', 'narrowkids') {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in 'S-1-5-18', 'S-1-5-32-544', $me) {
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier $sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        if ($name -eq 'narrowkids') { $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-5-11'), 'ReadAndExecute', 'None', 'None', 'Allow'))) }
        Set-Acl -LiteralPath (Join-Path $Root "$name\usr\share\mios") -AclObject $acl
    }
    Remove-Item -LiteralPath (Join-Path $Root 'narrowkids\usr\share\mios\mios.toml')
    Set-Content -LiteralPath (Join-Path $Root 'ads\usr\share\mios\mios.toml') -Stream 'mios.fixture' -Value 'hidden'
    [IO.File]::WriteAllText((Join-Path $Root 'outside.txt'), "outside`n")
    New-Item -ItemType HardLink -Path (Join-Path $Root 'hardlink\usr\share\mios\sub\linked.txt') -Target (Join-Path $Root 'outside.txt') | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $Root 'elsewhere') | Out-Null
    New-Item -ItemType Junction -Path (Join-Path $Root 'junction\usr\share\mios\sub\junction') -Target (Join-Path $Root 'elsewhere') | Out-Null
    [IO.File]::WriteAllText((Join-Path $Root 'origin.sid'), [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    Write-Host "BOUNDARY_RECOVERY_PREPARED $Root"
}

function Set-FixtureOwner([string]$Path, [string]$Sid) {
    # A separate process plants the owner (icacls enables SeRestorePrivilege only for itself), so this process keeps the
    # production worker's token: elevated, with SeRestorePrivilege held but disabled.
    $out = & "$env:SystemRoot\System32\icacls.exe" $Path /setowner "*$Sid" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls could not plant owner $Sid on ${Path}: $($out -join ' ')" }
    if ((Read-MiosBoundaryObject $Path -Lenient).Owner -ne $Sid) { throw "Planted owner $Sid is not on $Path" }
}
function Test-RestorePrivilegeEnabled {
    # A child process starts with a copy of this token, including which privileges are enabled.
    $row = @(& "$env:SystemRoot\System32\whoami.exe" /priv /fo csv /nh | ConvertFrom-Csv -Header 'Name', 'Description', 'State' | Where-Object { $_.Name -eq 'SeRestorePrivilege' })
    return ($row.Count -eq 1 -and $row[0].State -eq 'Enabled')
}

function Invoke-ElevatedChecks([string]$Root) {
    $script:fail = 0; $script:checks = 0; $script:failedChecks = New-Object System.Collections.Generic.List[string]
    $null = Import-Product $ProductPath
    if (-not (Test-MiosElevated)) { throw '-Elevated must run in an elevated session.' }
    Initialize-MiosMachineBoundaryApi
    $op = if ($OriginSid) { $OriginSid } else { [IO.File]::ReadAllText((Join-Path $Root 'origin.sid')).Trim() }
    $tree = Join-Path $Root 'tree'
    # Shape the real machine: usr owned by Administrators, etc by SYSTEM, the MiOS leaves and usr\share by the operator.
    Set-FixtureOwner (Join-Path $tree 'usr') 'S-1-5-32-544'; Set-FixtureOwner (Join-Path $tree 'etc') 'S-1-5-18'
    Set-FixtureOwner (Join-Path $Root 'foreign\usr') 'S-1-5-19'
    $targets = @('usr', 'usr\share', 'usr\share\mios', 'usr\share\mios\mios.toml', 'etc', 'etc\mios', 'etc\mios\mios.toml') | ForEach-Object { Join-Path $tree $_ }
    $siblings = @('usr\local', 'usr\local\keep.txt', 'etc\ssh', 'etc\ssh\sshd_config') | ForEach-Object { Join-Path $tree $_ }
    $leafKids = @('usr\share\mios\build-manifest.json', 'usr\share\mios\sub', 'usr\share\mios\sub\note.txt') | ForEach-Object { Join-Path $tree $_ }
    Check (@($targets | Where-Object { -not (Get-MiosMachineBoundaryGap $_) }).Count -eq 0) 'every prepared boundary object is refused by admission before recovery'
    $orig = @{}; foreach ($p in $targets + $siblings + $leafKids) { $orig[$p] = Read-MiosBoundaryObject $p -Lenient }
    $tomlBytes = @{}; foreach ($t in 'usr\share\mios\mios.toml', 'etc\mios\mios.toml') { $tomlBytes[(Join-Path $tree $t)] = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $tree $t))) }
    $vault = Join-Path $Root 'vault'; New-MiosProtectedMachineDirectory $vault
    $backupDir = Join-Path $vault 'boundary-recovery'
    Check (-not (Test-RestorePrivilegeEnabled)) 'the first recovery runs with SeRestorePrivilege disabled, like the production worker'
    $backup = Invoke-MiosMachineBoundaryRecovery -OriginSid $op -Root $tree -BackupDirectory $backupDir
    Check (@($targets | Where-Object { Get-MiosMachineBoundaryGap $_ }).Count -eq 0) 'every boundary object passes the unchanged admission after recovery'
    $owners = @{}; foreach ($p in $targets) { $owners[$p.Substring($tree.Length + 1)] = (Read-MiosBoundaryObject $p).Owner }
    Check ($owners['usr'] -eq 'S-1-5-32-544' -and $owners['etc'] -eq 'S-1-5-18' -and $owners['usr\share'] -eq 'S-1-5-32-544' -and $owners['usr\share\mios'] -eq 'S-1-5-32-544' -and
           $owners['etc\mios'] -eq 'S-1-5-32-544' -and $owners['usr\share\mios\mios.toml'] -eq 'S-1-5-32-544' -and $owners['etc\mios\mios.toml'] -eq 'S-1-5-32-544') 'trusted owners are kept and only the operator owners are replaced'
    # Windows stores a protected DACL set by handle as D:PAI (auto-inherited); compare what the descriptor grants, not its SDDL prefix.
    $templates = { param($raw) (@(@($raw.DiscretionaryAcl) | Where-Object { [int]$_.AceFlags -band 0x03 } |
        ForEach-Object { '{0}|{1}|{2}' -f $_.SecurityIdentifier.Value, $_.AccessMask, ([int]$_.AceFlags -band 0x03) }) -join ';') }
    $sharedOk = $true
    foreach ($p in 'usr', 'usr\share', 'etc') {
        $now = New-Object Security.AccessControl.RawSecurityDescriptor (Read-MiosBoundaryObject (Join-Path $tree $p)).Sddl
        $was = New-Object Security.AccessControl.RawSecurityDescriptor $orig[(Join-Path $tree $p)].Sddl
        $selfAces = (@(@($now.DiscretionaryAcl) | Where-Object { -not ([int]$_.AceFlags -band 0x08) } |
            ForEach-Object { '{0}|{1}|{2}' -f $_.SecurityIdentifier.Value, $_.AccessMask, [int]$_.AceFlags }) -join ';')
        $templatesOnly = @(@($now.DiscretionaryAcl) | Where-Object { ([int]$_.AceFlags -band 0x03) -and -not ([int]$_.AceFlags -band 0x08) }).Count -eq 0
        if (-not ([int]$now.ControlFlags -band 0x1000) -or $selfAces -cne 'S-1-5-18|2032127|0;S-1-5-32-544|2032127|0;S-1-5-32-545|1179817|0' -or
            -not $templatesOnly -or (& $templates $now) -cne (& $templates $was)) { $sharedOk = $false; Write-Host "    shared $p now $($now.GetSddlForm('Owner, Access'))" }
    }
    Check $sharedOk 'a shared prefix gets trusted self access and keeps its child templates as InheritOnly'
    $leafOk = $true
    foreach ($p in 'usr\share\mios', 'usr\share\mios\mios.toml', 'etc\mios', 'etc\mios\mios.toml') {
        $record = Read-MiosBoundaryObject (Join-Path $tree $p)
        $now = New-Object Security.AccessControl.RawSecurityDescriptor $record.Sddl
        $want = New-Object Security.AccessControl.RawSecurityDescriptor (New-MiosLeafSddl -Directory ($record.Kind -eq 'directory') -Owner 'S-1-5-32-544' -Private:($p -eq 'etc\mios\mios.toml'))
        $aces = { param($raw) (@(@($raw.DiscretionaryAcl) | ForEach-Object { '{0}|{1}|{2}' -f $_.SecurityIdentifier.Value, $_.AccessMask, [int]$_.AceFlags }) -join ';') }
        if (-not ([int]$now.ControlFlags -band 0x1000) -or (& $aces $now) -cne (& $aces $want)) { $leafOk = $false; Write-Host "    leaf $p now $($record.Sddl)" }
    }
    Check $leafOk 'a namespaced leaf gets exactly the protected canonical creation ACEs, the host TOML the private ones'
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
    $tomlOk = @($doc.tomls).Count -eq 2
    foreach ($t in @($doc.tomls)) {
        $leafOkToml = $false
        try { $null = Assert-MiosPrivateBackupLeaf ([string]$t.Backup); $leafOkToml = $true } catch { Write-Host "    toml leaf $($t.Backup): $($_.Exception.Message)" }
        if (-not $leafOkToml -or $t.Owner -cne $orig[[string]$t.Path].Owner -or $t.Sddl -cne $orig[[string]$t.Path].Sddl -or
            [Convert]::ToBase64String([IO.File]::ReadAllBytes([string]$t.Backup)) -cne $tomlBytes[[string]$t.Path] -or
            (Split-Path -Leaf ([string]$t.Backup)) -cne ('{0}-{1}.toml' -f $t.Role, $t.Sha256) -or (Split-Path -Parent ([string]$t.Backup)) -ine $backupDir) { $tomlOk = $false }
    }
    Check ($tomlOk -and (@($doc.tomls | ForEach-Object { $_.Role }) -join ',') -eq 'vendor,host') 'both TOML files are preserved byte-exact in private content-addressed leaves'
    $acl = Get-Acl -LiteralPath $backup
    $sids = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value })
    Check ($acl.AreAccessRulesProtected -and $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544' -and
           @($sids | Where-Object { $_ -notin @('S-1-5-18', 'S-1-5-32-544') }).Count -eq 0) 'the backup leaf is private to SYSTEM and Administrators'
    $compliantBefore = @{}; foreach ($p in $targets + $leafKids) { $compliantBefore[$p] = Read-MiosBoundaryObject $p }
    $again = Invoke-MiosMachineBoundaryRecovery -OriginSid $op -Root $tree -BackupDirectory $backupDir
    $againDoc = [IO.File]::ReadAllText($again) | ConvertFrom-Json
    $compliantUnchanged = $true
    foreach ($p in $targets + $leafKids) {
        $now = Read-MiosBoundaryObject $p
        foreach ($field in 'Owner', 'Sddl', 'Volume', 'Index', 'Written', 'Size', 'Sha256') { if ($now.$field -cne $compliantBefore[$p].$field) { $compliantUnchanged = $false } }
    }
    Check ($again -ne $backup -and @(Get-ChildItem -LiteralPath $backupDir -Filter '*.json').Count -eq 2 -and
        @(Get-ChildItem -LiteralPath $backupDir -Filter '*.toml').Count -eq 2 -and $compliantUnchanged) 'a compliant second run writes a private metadata record and reuses byte blobs without changing originals'
    Check (@($againDoc.objects).Count -eq 2 -and @($againDoc.tomls).Count -eq 2 -and
        @($againDoc.tomls | Where-Object { $_.Owner -cne $compliantBefore[[string]$_.Path].Owner -or $_.Sddl -cne $compliantBefore[[string]$_.Path].Sddl }).Count -eq 0) 'a compliant run preserves each TOML current original owner and descriptor'
    # Restore validates the backup leaf and every object before it changes anything.
    $usrRecovered = (Read-MiosBoundaryObject (Join-Path $tree 'usr')).Sddl
    $copied = Join-Path $Root 'copied-backup.json'; [IO.File]::Copy($backup, $copied)
    Expect-ThrowMatch { Restore-MiosMachineBoundary -BackupPath $copied -BackupDirectory $backupDir } 'accepts only a recovery backup in' 'restore refuses a backup outside the backup directory'
    $loose = Join-Path $backupDir 'loose.json'; [IO.File]::WriteAllBytes($loose, [IO.File]::ReadAllBytes($backup))
    Expect-ThrowMatch { Restore-MiosMachineBoundary -BackupPath $loose -BackupDirectory $backupDir } 'Not a private MiOS boundary backup' 'restore refuses a backup leaf that is not private'
    [IO.File]::Delete($loose)
    $vendorToml = Join-Path $tree 'usr\share\mios\mios.toml'; $vendorBytes = [IO.File]::ReadAllBytes($vendorToml)
    [IO.File]::AppendAllText($vendorToml, "# rewritten after the backup`n")
    Expect-ThrowMatch { Restore-MiosMachineBoundary -BackupPath $backup -BackupDirectory $backupDir } 'content changed since the backup' 'restore refuses to put an old descriptor on rewritten content'
    Check ((Read-MiosBoundaryObject (Join-Path $tree 'usr')).Sddl -ceq $usrRecovered) 'a refused restore changes no descriptor'
    [IO.File]::WriteAllBytes($vendorToml, $vendorBytes)
    # Reproduce a write after the old preflight has accepted every file, before apply handles are acquired.
    $script:restoreRacePath = $vendorToml; $script:restoreRaceInjected = $false
    $script:restoreRaceAncestors = (Get-Command Open-MiosBoundaryAncestors).ScriptBlock
    $beforeRace = @{}; foreach ($p in $targets + $leafKids) { $beforeRace[$p] = (Read-MiosBoundaryObject $p).Sddl }
    function global:Open-MiosBoundaryAncestors {
        param([string]$Path)
        $held = @(& $script:restoreRaceAncestors $Path)
        if (-not $script:restoreRaceInjected) {
            [IO.File]::AppendAllText($script:restoreRacePath, "# written between restore validation and apply`n")
            $script:restoreRaceInjected = $true
        }
        return $held
    }
    try {
        Expect-ThrowMatch { Restore-MiosMachineBoundary -BackupPath $backup -BackupDirectory $backupDir } 'content changed since the backup' 'restore refuses an in-place mutation after initial validation before any ACL apply'
        $raceUnchanged = $script:restoreRaceInjected
        foreach ($p in $targets + $leafKids) { if ((Read-MiosBoundaryObject $p).Sddl -cne $beforeRace[$p]) { $raceUnchanged = $false } }
        Check $raceUnchanged 'a mid-validation restore mutation changes no original descriptor'
    } finally { $null = Import-Product $ProductPath; [IO.File]::WriteAllBytes($vendorToml, $vendorBytes) }
    Restore-MiosMachineBoundary -BackupPath $backup -BackupDirectory $backupDir
    $mismatch = @($targets + $leafKids | Where-Object { (Read-MiosBoundaryObject $_).Sddl -cne $orig[$_].Sddl })
    if ($mismatch.Count) { $mismatch | ForEach-Object { Write-Host "    restore mismatch $_`n      was $($orig[$_].Sddl)`n      now $((Read-MiosBoundaryObject $_).Sddl)" } }
    Check ($mismatch.Count -eq 0) 'restoring the backup returns every original descriptor exactly'
    $sibOk = $true; foreach ($p in $siblings) { if ((Read-MiosBoundaryObject $p -Lenient).Sddl -cne $orig[$p].Sddl) { $sibOk = $false } }
    Check $sibOk 'siblings are still unchanged after the restore'
    $null = Invoke-MiosMachineBoundaryRecovery -OriginSid $op -Root $tree -BackupDirectory $backupDir
    Check (@($targets | Where-Object { Get-MiosMachineBoundaryGap $_ }).Count -eq 0) 'recovery works again after a restore'
    $cases = @(@('foreign', 'only SYSTEM, Administrators or the validated operator'), @('deny', 'unreviewed ACE'), @('hardlink', 'hard-linked file'),
        @('junction', 'reparse point below'), @('narrow', 'its recovered descriptor would let S-1-5-32-545 read it'),
        @('narrowkids', 're-inheriting from the recovered .+ would let S-1-5-32-545 read it'), @('ads', 'alternate data stream'))
    foreach ($case in $cases) {
        $t = Join-Path $Root $case[0]
        $watch = @('usr', 'usr\share', 'usr\share\mios') | ForEach-Object { Join-Path $t $_ }
        $before = @($watch | ForEach-Object { (Read-MiosBoundaryObject $_ -Lenient).Sddl }) -join '|'
        $count = @(Get-ChildItem -LiteralPath $backupDir -Filter '*.json').Count; $tomlCount = @(Get-ChildItem -LiteralPath $backupDir -Filter '*.toml').Count
        Expect-ThrowMatch { Invoke-MiosMachineBoundaryRecovery -OriginSid $op -Root $t -BackupDirectory $backupDir } $case[1] "recovery refuses the $($case[0]) tree"
        Check ((@($watch | ForEach-Object { (Read-MiosBoundaryObject $_ -Lenient).Sddl }) -join '|') -ceq $before -and @(Get-ChildItem -LiteralPath $backupDir -Filter '*.json').Count -eq $count -and
               @(Get-ChildItem -LiteralPath $backupDir -Filter '*.toml').Count -eq $tomlCount) "the $($case[0]) refusal changes nothing and writes no backup"
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
# Match the complete production call with or without an explicitly validated root; never leave trailing arguments in a plant.
$recoveryPreparationCall = @([IO.File]::ReadAllLines($ProductPath) | Where-Object { $_ -match '^\s*\$null = Invoke-MiosMachineBoundaryRecovery -OriginSid' })
if ($recoveryPreparationCall.Count -ne 1) { throw 'Missing or ambiguous preparation recovery call.' }
$plants = @(
    @{ Name = 'shared self access writable'; Expected = 'a shared prefix keeps only trusted self access and every inheritable ACE as an InheritOnly template'; From = "@('S-1-5-32-545', 0x1200A9)"; To = "@('S-1-5-32-545', 0x1301BF)" },
    @{ Name = 'templates not InheritOnly'; Expected = 'a shared prefix keeps only trusted self access and every inheritable ACE as an InheritOnly template'; From = '(($flags -bor 0x08) -band (-bnot 0x10))'; To = '($flags -band (-bnot 0x10))' },
    @{ Name = 'foreign owner accepted'; Expected = 'any other owner is refused'; From = 'throw "Boundary recovery refuses $Path owned by'; To = 'return ''S-1-5-32-544''; throw "Boundary recovery refuses $Path owned by' },
    @{ Name = 'trusted owner replaced'; Expected = 'a SYSTEM or Administrators owner is kept'; From = "if (`$Owner -in @('S-1-5-18', 'S-1-5-32-544')) { return `$Owner }"; To = "if (`$Owner -in @('S-1-5-18', 'S-1-5-32-544')) { return 'S-1-5-32-544' }" },
    @{ Name = 'deny ACE accepted'; Expected = 'an explicit deny ACE is refused'; From = "-or [string]`$ace.AceQualifier -ne 'AccessAllowed' -or `$ace.IsCallback"; To = '-or $ace.IsCallback' },
    @{ Name = 'M: default scope'; Expected = 'recovery defaults to the system drive and never names M:'; From = "if (-not `$Root) { `$Root = if (`$env:SystemDrive) { `$env:SystemDrive } else { 'C:' } }"; To = "if (-not `$Root) { `$Root = 'M:' }" },
    @{ Name = 'recovery removed from preparation'; Expected = 'recovery runs after origin validation and before TOML publication, with the origin SID'; From = $recoveryPreparationCall[0]; To = '    $null = [string]$Context.Sid' },
    @{ Name = 'host tier rewrites existing parents'; Expected = 'host-tier directories use strict admission or atomic protected creation'; From = 'if (Test-Path -LiteralPath $d) { Assert-MiosMachineWriteBoundary $d } else { New-MiosProtectedMachineDirectory $d }'; To = 'if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -ErrorAction Stop | Out-Null }; Set-MiosHostTierAcl $d' },
    @{ Name = 'backup skipped'; Expected = 'recovery validates policy and owners and backs up TOML bytes and descriptors before changing any descriptor'; From = '$backup = Save-MiosBoundaryBackup -Objects'; To = '$backup = Write-Output -InputObject' },
    @{ Name = 'ancestors not pinned'; Expected = 'every repair pins its ancestors first'; From = '$pins = @(Open-MiosBoundaryAncestors $step.Path)'; To = '$pins = @()' },
    @{ Name = 'write handle shares write'; Expected = 'a recovery write handle denies a concurrent data write'; From = 'write ? 1u : 7u'; To = '7u'; Native = $true },
    @{ Name = 'write handle without data access'; Expected = 'a recovery write handle denies a concurrent data write'; From = '(write ? (0x1u | 0x40000u | 0x80000u) : 0x1u)'; To = '(write ? (0x40000u | 0x80000u) : 0x1u)'; Native = $true },
    @{ Name = 'ancestor pin shares delete'; Expected = 'pinned ancestors deny a concurrent delete open'; From = 'CreateFileW(path, 0x1u | 0x20000u | 0x80u, 1u,'; To = 'CreateFileW(path, 0x1u | 0x20000u | 0x80u, 5u,'; Native = $true },
    @{ Name = 'ancestor pin without data access'; Expected = 'pinned ancestors cannot be renamed during a repair'; From = 'CreateFileW(path, 0x1u | 0x20000u | 0x80u, 1u,'; To = 'CreateFileW(path, 0x20000u | 0x80u, 1u,'; Native = $true },
    @{ Name = 'ancestor pin shares write'; Expected = 'pinned ancestors deny a concurrent writer and release it afterwards'; From = 'CreateFileW(path, 0x1u | 0x20000u | 0x80u, 1u,'; To = 'CreateFileW(path, 0x1u | 0x20000u | 0x80u, 3u,'; Native = $true },
    @{ Name = 'host TOML not private'; Expected = 'both TOML files are protected before their namespace directory, the host TOML privately'; From = "'host-toml' { New-MiosLeafSddl -Directory `$false -Owner `$owner -Private }"; To = "'host-toml' { New-MiosLeafSddl -Directory `$false -Owner `$owner }" },
    @{ Name = 'TOML after its namespace'; Expected = 'both TOML files are protected before their namespace directory, the host TOML privately'; From = "@{ Rel = 'usr\share\mios\mios.toml'; Policy = 'vendor-toml'; Parent = 'usr\share\mios' }, @{ Rel = 'usr\share\mios'; Policy = 'leaf' }"; To = "@{ Rel = 'usr\share\mios'; Policy = 'leaf' }, @{ Rel = 'usr\share\mios\mios.toml'; Policy = 'vendor-toml'; Parent = 'usr\share\mios' }" },
    @{ Name = 'target read growth unchecked'; Expected = 'recovery refuses read growth on every target and inheriting descendant before any backup'; From = 'foreach ($sid in @(Get-MiosNewReaders -Before $record.Sddl -After $target)) { throw'; To = 'foreach ($sid in @()) { throw' },
    @{ Name = 'descendant read growth unchecked'; Expected = 'recovery refuses read growth on every target and inheriting descendant before any backup'; From = 'foreach ($sid in @(Get-MiosNewReaders -Before $c.Sddl -After $after)) { throw'; To = 'foreach ($sid in @()) { throw' },
    @{ Name = 'Users read always covered'; Expected = 'read growth is detected for Users and for any other new reader'; From = "-not (`$_ -eq 'S-1-5-32-545' -and `$old -contains 'S-1-5-11')"; To = "-not (`$_ -eq 'S-1-5-32-545')" },
    @{ Name = 'alternate data stream accepted'; Expected = 'a TOML with an alternate data stream is refused'; From = 'if ($streams.Count) { throw "Boundary recovery refuses ${Path}: it has'; To = 'if ($false) { throw "Boundary recovery refuses ${Path}: it has' },
    @{ Name = 'compliant run skips TOML backup'; Expected = 'a compliant run still preserves both TOML files before any writer'; From = 'if (-not $plan.Count -and -not $tomlItems.Count) { return $null }'; To = 'if (-not $plan.Count) { return $null }' },
    @{ Name = 'ancestor chain not compared'; Expected = 'the ancestor chain recorded at planning is compared before each repair'; From = "-cne (`$step.Chain -join ';')) {"; To = "-cne (`$step.Path -join ';') -and `$false) {" },
    @{ Name = 'target reparse check removed'; Expected = 'a junction is refused at the target'; From = 'if ($isReparse) { throw "Boundary recovery refuses a reparse point: $full" }'; To = '' },
    @{ Name = 'hardlink check removed'; Expected = 'a hard-linked file is refused'; From = 'if (-not $isDirectory -and $info.Links -ne 1) {'; To = 'if ($false) {' },
    @{ Name = 'descendant reparse check removed'; Expected = 'a junction below a leaf is refused'; From = 'if ($attributes -band [IO.FileAttributes]::ReparsePoint) { throw'; To = 'if ($false) { throw' },
    @{ Name = 'descendant bound removed'; Expected = 'the descendant guard is bounded'; From = 'if ($found.Count -ge $Limit) {'; To = 'if ($false) {' },
    @{ Name = 'elevation check removed'; Expected = 'an unelevated run refuses recovery'; From = 'if (-not (Test-MiosElevated)) { throw "Boundary recovery requires'; To = 'if ($false) { throw "Boundary recovery requires' },
    @{ Name = 'compliant run JSON skipped'; Expected = 'every TOML backup retains owner and descriptor and compliant runs write private metadata'; From = '$reason = if ($plan.Count)'; To = 'if (-not $plan.Count) { return $null }; $reason = if ($plan.Count)' },
    @{ Name = 'TOML original descriptor dropped'; Expected = 'every TOML backup retains owner and descriptor and compliant runs write private metadata'; From = 'Owner = $record.Owner; Sddl = $record.Sddl'; To = 'Owner = $record.Owner; Sddl = $null' },
    @{ Name = 'restore apply hash omitted'; Expected = 'restore retains ancestor and target handles and hashes through the apply handle'; From = "if (`$object.Kind -eq 'file' -and [MiosMachineBoundaryNative]::Sha256(`$handle) -cne [string]`$object.Sha256)"; To = 'if ($false)' },
    @{ Name = 'admission weakened'; Expected = 'admission helper Assert-MiosMachineWriteBoundary is unchanged from its reviewed source'; From = "if (`$owner -notin `$trusted) { throw 'An existing machine TOML path has an untrusted owner.' }"; To = '' },
    @{ Name = 'worker lacks a helper'; Expected = 'worker extraction resolves every helper the recovery calls'; From = "'Assert-MiosBoundaryAcePolicy', 'New-MiosSharedPrefixSddl', 'New-MiosLeafSddl', 'Open-MiosBoundaryAncestors',"; To = "'Assert-MiosBoundaryAcePolicy', 'New-MiosSharedPrefixSddl', 'New-MiosLeafSddl'," },
    @{ Name = 'planned target kept as a leaf descendant'; Expected = 'a planned target below a leaf is its own step, not a leaf descendant'; From = 'Get-MiosBoundaryDescendants $step.Path | Where-Object { $_ -notin $planned } |'; To = 'Get-MiosBoundaryDescendants $step.Path |' },
    @{ Name = 'inheritance update skipped'; Expected = 'leaf descendants are re-inherited after the descriptor change'; From = 'Update-MiosBoundaryInheritance -Object $child -Backup $backup'; To = '$null = $child' },
    @{ Name = 'inheritance update drops explicit ACEs'; Expected = 'an inheritance update keeps explicit ACEs and takes inherited ACEs from the parent'; From = 'if (-not ([int]$ace.AceFlags -band 0x10)) { $explicit.InsertAce'; To = 'if ([int]$ace.AceFlags -band 0x10) { $explicit.InsertAce' },
    @{ Name = 'explicit ACE comparison precedence'; Expected = 'explicit ACE comparison ignores inherited changes and detects explicit ones'; From = "return [bool](((Get-MiosExplicitAces `$Before) -join ';') -ceq ((Get-MiosExplicitAces `$After) -join ';'))"; To = "return (Get-MiosExplicitAces `$Before) -join ';' -ceq (Get-MiosExplicitAces `$After) -join ';'" },
    @{ Name = 'inherited write grants ignored'; Expected = 'inherited write grants are found only where they apply to the object'; From = "[string]`$_.AceQualifier -eq 'AccessAllowed' -and (`$_.AccessMask"; To = "[string]`$_.AceQualifier -eq 'Never' -and (`$_.AccessMask" },
    @{ Name = 'leaf descriptor private'; Expected = 'a leaf gets exactly the descriptor fresh creation uses, with the decided owner'; From = '(New-MiosMachineCreationAcl -Directory:$Directory -Private:$Private)'; To = '(New-MiosMachineCreationAcl -Directory:$Directory -Private)' },
    @{ Name = 'kept owner rewritten'; Expected = 'a kept owner is never rewritten, so recovery needs no SeRestorePrivilege'; From = 'if ($step.Owner -eq $step.Record.Owner) { [MiosMachineBoundaryNative]::SetDacl($handle, $target, $true) }'; To = 'if ($false) { [MiosMachineBoundaryNative]::SetDacl($handle, $target, $true) }' },
    @{ Name = 'recovery enables restore privilege'; Expected = 'a kept owner is never rewritten, so recovery needs no SeRestorePrivilege'; From = 'if ($step.Owner -eq $step.Record.Owner) { [MiosMachineBoundaryNative]::SetDacl('; To = '[MiosMachineBoundaryNative]::EnablePrivilege(''SeRestorePrivilege''); if ($step.Owner -eq $step.Record.Owner) { [MiosMachineBoundaryNative]::SetDacl(' }
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
