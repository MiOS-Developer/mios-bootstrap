# Native PowerShell fixtures for bounded answer-file launchers. Only synthetic
# scripts run, in scratch directories; no Windows provisioning entry runs.
# Synthetic children replace only three exact OS/filesystem calls. The real
# Windows folder lookup, reparse metadata, owner/DACL and cache retention remain
# separate Windows acceptance; no product environment override is introduced.
# Windows Setup's retention of custom XML is a separate installation acceptance.
# Native: pwsh -NoProfile -File tests/test_unattend_launcher.ps1 -VendorToml <MiOS>/usr/share/mios/mios.toml
#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$VendorToml)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../field/autounattend/MiOS-Provision.lib.ps1')
$renderer = Join-Path $PSScriptRoot '../field/autounattend/New-MiOSAutounattend.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($renderer, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Unattend fixture: renderer source does not parse' }
foreach ($name in @('ConvertTo-UnattendPassword','New-MiOSAutounattendXml')) {
    $definitions = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $name })
    if ($definitions.Count -ne 1) { throw 'Unattend fixture: missing or duplicate renderer function' }
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('mios-unattend-fixture-' + [Guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory((Join-Path $scratch 'Panther'))
$answer = Join-Path (Join-Path $scratch 'Panther') 'unattend.xml'
$resultFile = Join-Path $scratch 'result.txt'
$unicode = [Text.UnicodeEncoding]::new($false, $false, $true)
$script:assertions = 0
$secret = 'fixture-private-password-' + [Guid]::NewGuid().ToString('N')
$fixtureEnvironment = @('MIOS_UNATTEND_FIXTURE_RESULT','MIOS_UNATTEND_FIXTURE_ANSWER','MIOS_UNATTEND_FIXTURE_WINDOWS','MIOS_UNATTEND_FIXTURE_REPARSE','MIOS_UNATTEND_FIXTURE_TRACE','MIOS_UNATTEND_FIXTURE_OPEN')
$savedEnvironment = @{}
foreach ($name in $fixtureEnvironment) { $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$env:MIOS_UNATTEND_FIXTURE_RESULT = $resultFile
$env:MIOS_UNATTEND_FIXTURE_ANSWER = $answer
$env:MIOS_UNATTEND_FIXTURE_WINDOWS = 'C:\Windows'
$env:MIOS_UNATTEND_FIXTURE_REPARSE = ''
$env:MIOS_UNATTEND_FIXTURE_TRACE = Join-Path $scratch 'attributes.txt'
$env:MIOS_UNATTEND_FIXTURE_OPEN = Join-Path $scratch 'cache-opened.txt'
$CANONICAL_BOOTSTRAP = 'https://example.invalid/fixture.ps1'
$BootstrapUrl = ''; $ObfuscatePasswords = $true; $FullDiskWindows = $true

function Assert-True([bool]$Value, [string]$Label) {
    if (-not $Value) { throw ('Unattend launcher regression: ' + $Label) }
    $script:assertions++
}
function Assert-SameBytes([byte[]]$Expected, [byte[]]$Actual, [string]$Label) {
    Assert-True ([Convert]::ToBase64String($Expected) -ceq [Convert]::ToBase64String($Actual)) $Label
}
function Set-FixtureAnswer([string]$PayloadName, [string]$Base64, [string]$Extra = '') {
    $xml = '<unattend xmlns="urn:schemas-microsoft-com:unattend"><Extensions xmlns="urn:mios:unattend"><' + $PayloadName + '>' + $Base64 + '</' + $PayloadName + '>' + $Extra + '</Extensions></unattend>'
    Write-MiOSPrivateText -Path $answer -Text $xml
}
function Invoke-FixtureLauncher($Payload) {
    $match = [regex]::Match($Payload.CommandLine, '^powershell\.exe -nop -c "(?<body>[^"]+)"$')
    Assert-True $match.Success 'launcher has the fixed command form without execution-policy overrides'
    $body = $match.Groups['body'].Value
    $boundaries = @('[Environment]::GetFolderPath(36)', '[IO.File]::GetAttributes($p)', '[Xml.XmlReader]::Create($p,')
    foreach ($boundary in $boundaries) {
        Assert-True (([regex]::Matches($body, [regex]::Escape($boundary))).Count -eq 1) 'each synthetic filesystem boundary has one exact source call'
    }
    Assert-True (-not $body.Contains('$env:WINDIR')) 'product launcher never sources its Windows directory from mutable environment'
    # Explicit child-copy mocks, leaving path validation/order, XML, digest,
    # Unicode, invocation and failure handling as the actual product source.
    foreach ($trace in @($env:MIOS_UNATTEND_FIXTURE_TRACE, $env:MIOS_UNATTEND_FIXTURE_OPEN)) { if ([IO.File]::Exists($trace)) { [IO.File]::Delete($trace) } }
    $body = $body.Replace($boundaries[0], '$env:MIOS_UNATTEND_FIXTURE_WINDOWS')
    $body = $body.Replace($boundaries[1], '(Get-MiOSFixtureAttributes $p)')
    $body = $body.Replace($boundaries[2], '[Xml.XmlReader]::Create($(& { [IO.File]::WriteAllText($env:MIOS_UNATTEND_FIXTURE_OPEN, ''opened''); $env:MIOS_UNATTEND_FIXTURE_ANSWER }),')
    $prelude = 'function Get-MiOSFixtureAttributes { param([string]$Path) [IO.File]::AppendAllText($env:MIOS_UNATTEND_FIXTURE_TRACE,$Path+[char]10); if($Path -ceq $env:MIOS_UNATTEND_FIXTURE_REPARSE){return [IO.FileAttributes]1024};return [IO.FileAttributes]16 }; '

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Get-Process -Id $PID).Path
    $start.Arguments = '-nop -c "' + $prelude + $body + '"'
    Assert-True (($start.FileName.Length + 3 + $start.Arguments.Length) -lt 32767) 'fixture child command fits CreateProcess including quoted executable and NUL'
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $start
    try {
        Assert-True ($process.Start()) 'synthetic launcher process starts'
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) { $process.Kill(); throw 'Unattend fixture: synthetic launcher timed out' }
        $out = $stdout.GetAwaiter().GetResult(); $err = $stderr.GetAwaiter().GetResult()
        Assert-True (-not ($out + $err).Contains($secret)) 'process output never reveals the private credential sentinel'
        return @{ ExitCode = $process.ExitCode; Out = $out; Error = $err }
    } finally { $process.Dispose() }
}
function Assert-Refused($Payload, [string]$Label) {
    $run = Invoke-FixtureLauncher $Payload
    Assert-True ($run.ExitCode -ne 0) $Label
    Assert-True (-not [IO.File]::Exists($resultFile)) 'refusal occurs before any payload statement'
    Assert-True ($run.Error.Contains('MiOS payload failed.')) 'failure reports a fixed diagnostic'
}
try {
    # A single script far beyond the original command-line limit; retain mixed
    # newlines, non-BMP Unicode, quotes, a private value, and shared ordered state.
    $nonBmp = [char]::ConvertFromUtf32(0x1F30D)
    $large = ('$ErrorActionPreference = ''Stop''' + "`r`n" + '$value = ''first''' + "`n" +
        ('# quotes '' " & < > ' + $nonBmp + "`r`n") * 6000 +
        '$private = ''' + $secret + '''' + "`r`n" +
        'function Add-Second { param($Text) $Text + ''|second'' }; $value = Add-Second $value' + "`n" +
        '$value += ''|third''; [IO.File]::WriteAllText($env:MIOS_UNATTEND_FIXTURE_RESULT, $value)' + "`r`n")
    foreach ($name in @('FirstLogonScript','SpecializeScript')) {
        $payload = New-MiOSUnattendPayload -Name $name -Script $large
        Assert-True ($payload.Base64.Length -gt 32767) 'large payload would overflow the old encoded command'
        Assert-True ($payload.CommandLine.Length -lt 1024) 'large payload fits the Windows Setup command-line field cap'
        Assert-SameBytes ($unicode.GetBytes($large)) ([Convert]::FromBase64String($payload.Base64)) 'complete UTF-16LE payload bytes survive exactly'
        Assert-True (-not $payload.CommandLine.Contains($secret)) 'launcher contains no plaintext credential'
        Set-FixtureAnswer $name $payload.Base64
        $run = Invoke-FixtureLauncher $payload
        Assert-True ($run.ExitCode -eq 0) 'matching cached payload runs successfully'
        Assert-True ([IO.File]::ReadAllText($resultFile) -ceq 'first|second|third') 'one process preserves functions, state and statement order'
        [IO.File]::Delete($resultFile)
        $tiny = New-MiOSUnattendPayload -Name $name -Script 'exit 0'
        Assert-True ($tiny.CommandLine.Length -eq $payload.CommandLine.Length) 'launcher length is independent of payload length'

        Set-FixtureAnswer $name $tiny.Base64
        Assert-Refused $payload 'changed payload digest refuses nonzero'
        Set-FixtureAnswer $name 'not-base64'
        Assert-Refused $payload 'malformed base64 refuses nonzero'
        Set-FixtureAnswer $name $payload.Base64 ('<' + $name + '>' + $payload.Base64 + '</' + $name + '>')
        Assert-Refused $payload 'duplicate payload refuses nonzero'
        Set-FixtureAnswer 'OtherScript' $payload.Base64
        Assert-Refused $payload 'missing required payload refuses nonzero'
        [IO.File]::Delete($answer)
        Assert-Refused $payload 'missing Panther cache refuses without network or media fallback'
    }
    # Local element names alone are insufficient, and the namespace must not
    # make two separate extension containers appear as one executable payload.
    $namespacePayload = New-MiOSUnattendPayload -Name FirstLogonScript -Script $large
    $xmlPrefix = '<unattend xmlns="urn:schemas-microsoft-com:unattend">'
    $extension = '<Extensions xmlns="urn:mios:unattend"><FirstLogonScript>' + $namespacePayload.Base64 + '</FirstLogonScript></Extensions>'
    Write-MiOSPrivateText -Path $answer -Text ($xmlPrefix + $extension.Replace('<FirstLogonScript>', '<FirstLogonScript xmlns="urn:fixture:other">') + '</unattend>')
    Assert-Refused $namespacePayload 'same payload local name in another namespace refuses'
    Write-MiOSPrivateText -Path $answer -Text ($xmlPrefix + $extension.Replace('xmlns="urn:mios:unattend"', 'xmlns=""') + '</unattend>')
    Assert-Refused $namespacePayload 'missing extension namespace refuses'
    Write-MiOSPrivateText -Path $answer -Text ($xmlPrefix + $extension + $extension + '</unattend>')
    Assert-Refused $namespacePayload 'duplicate extension containers refuse before payload invocation'
    # The actual guard must refuse before any attribute/open boundary is called.
    Set-FixtureAnswer FirstLogonScript $namespacePayload.Base64
    $env:MIOS_UNATTEND_FIXTURE_WINDOWS = '\\example.invalid\Windows'
    Assert-Refused $namespacePayload 'UNC known-folder value refuses before filesystem access'
    Assert-True (-not [IO.File]::Exists($env:MIOS_UNATTEND_FIXTURE_TRACE)) 'UNC refusal performs no attribute lookup'
    Assert-True (-not [IO.File]::Exists($env:MIOS_UNATTEND_FIXTURE_OPEN)) 'UNC refusal never opens the cache'
    $env:MIOS_UNATTEND_FIXTURE_WINDOWS = 'C:\Windows'
    $expectedPaths = @('C:\', 'C:\\Windows', 'C:\\Windows\Panther', 'C:\\Windows\Panther\unattend.xml')
    for ($i = 0; $i -lt $expectedPaths.Count; $i++) {
        $env:MIOS_UNATTEND_FIXTURE_REPARSE = $expectedPaths[$i]
        Assert-Refused $namespacePayload 'reparse component refuses before cache open'
        $trace = [IO.File]::ReadAllText($env:MIOS_UNATTEND_FIXTURE_TRACE)
        Assert-True ($trace -ceq (($expectedPaths[0..$i] -join ([string][char]10)) + [char]10)) 'attribute guards walk root-first and stop before traversing a reparse component'
        Assert-True (-not [IO.File]::Exists($env:MIOS_UNATTEND_FIXTURE_OPEN)) 'reparse refusal never opens the cache'
    }
    $env:MIOS_UNATTEND_FIXTURE_REPARSE = ''
    $throwing = New-MiOSUnattendPayload -Name FirstLogonScript -Script ('throw ''' + $secret + '''')
    Set-FixtureAnswer FirstLogonScript $throwing.Base64
    Assert-Refused $throwing 'terminating script failure returns nonzero without logging its credential-bearing exception'
    Write-MiOSPrivateText -Path $answer -Text '<!DOCTYPE unattend [<!ENTITY fixture "private">]><unattend xmlns="urn:schemas-microsoft-com:unattend">&fixture;</unattend>'
    Assert-Refused $throwing 'DTD declarations refuse without resolution'
    # Exercise runtime decoding separately from the render-time Unicode gate:
    # bind a fixture-only launcher to deliberately malformed UTF-16 bytes.
    $invalidBytes = [byte[]]@(0, 216)
    $invalid = New-MiOSUnattendPayload -Name FirstLogonScript -Script 'exit 0'
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $invalidDigest = [Convert]::ToBase64String($hash.ComputeHash($invalidBytes)) }
    finally { $hash.Dispose() }
    $invalid.CommandLine = [regex]::Replace($invalid.CommandLine, '[A-Za-z0-9+/]{43}=', $invalidDigest)
    Set-FixtureAnswer FirstLogonScript ([Convert]::ToBase64String($invalidBytes))
    Assert-Refused $invalid 'strict runtime UTF-16 decoding refuses malformed payload bytes'
    $exiting = New-MiOSUnattendPayload -Name FirstLogonScript -Script 'exit 23'
    Set-FixtureAnswer FirstLogonScript $exiting.Base64
    $run = Invoke-FixtureLauncher $exiting
    Assert-True ($run.ExitCode -eq 23) 'explicit payload exit status reaches the caller'
    $badSyntax = New-MiOSUnattendPayload -Name FirstLogonScript -Script 'if ('
    Set-FixtureAnswer FirstLogonScript $badSyntax.Base64
    Assert-Refused $badSyntax 'payload syntax failure returns nonzero'
    # Invalid UTF-16 cannot be silently replaced by the render-time encoder.
    $refused = $false
    try { $null = New-MiOSUnattendPayload -Name FirstLogonScript -Script ([string][char]0xD800) } catch { $refused = $true }
    Assert-True $refused 'unpaired Unicode surrogates refuse instead of corrupting bytes'

    if ($VendorToml) {
        # Exercise the real ordered command emitters over the full vendor grammar;
        # the fixture provides only credentials and disables the existing network
        # bootstrap command. The resulting Windows commands are inspected, never run.
        $view = Read-MiosToml -Path $VendorToml -SingleFile
        $view.scalars['identity.username'] = 'fixture-user'
        $view.scalars['identity.default_password'] = $secret
        $view.scalars['autounattend.autologon_user'] = 'fixture-user'
        $view.scalars['autounattend.service.svc_user'] = 'fixture-service'
        $view.scalars['autounattend.service.svc_password'] = $secret
        $view.scalars['autounattend.run_bootstrap'] = 'false'
        $view.accounts = @(); $view.has_accounts = $false
        [xml]$document = New-MiOSAutounattendXml -Toml $view
        $ns = [Xml.XmlNamespaceManager]::new($document.NameTable)
        $ns.AddNamespace('u', 'urn:schemas-microsoft-com:unattend'); $ns.AddNamespace('m', 'urn:mios:unattend')
        foreach ($node in $document.SelectNodes('//u:Path|//u:CommandLine', $ns)) {
            Assert-True ($node.InnerText.Length -lt 32767) 'every rendered Setup command fits Windows CreateProcess'
            Assert-True (-not $node.InnerText.Contains($secret)) 'Setup commands contain no plaintext credential'
        }
        foreach ($name in @('FirstLogonScript','SpecializeScript')) {
            $blob = $document.SelectSingleNode('/u:unattend/m:Extensions/m:' + $name, $ns).InnerText
            $scriptText = $unicode.GetString([Convert]::FromBase64String($blob))
            $expectedPayload = New-MiOSUnattendPayload -Name $name -Script $scriptText
            $selector = if ($name -ceq 'FirstLogonScript') { '//u:FirstLogonCommands/u:SynchronousCommand/u:CommandLine' } else { '//u:settings[@pass="specialize"]//u:RunSynchronousCommand[u:Order="5"]/u:Path' }
            $launcherNode = $document.SelectSingleNode($selector, $ns)
            Assert-True ($null -ne $launcherNode -and $launcherNode.InnerText -ceq $expectedPayload.CommandLine) 'renderer binds each launch phase to its complete exact extension payload'
            Assert-True ($launcherNode.InnerText.Length -lt 1024) 'both real Setup phase launchers fit the stricter field cap'
            $nativeTokens = $null; $nativeErrors = $null
            $nativeAst = [Management.Automation.Language.Parser]::ParseInput($scriptText, [ref]$nativeTokens, [ref]$nativeErrors)
            Assert-True ($nativeErrors.Count -eq 0) 'full vendor ordered payload parses'
            $commands = @($nativeAst.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.CommandElements.Count -eq 5 }, $true))
            Assert-True ($commands.Count -gt 0) 'full vendor payload has inspectable ordered native commands'
            foreach ($command in $commands) {
                # The generated call has a fixed /d /s /c wrapper and a literal
                # complete command. Reserve 512 units for the ComSpec path/quoting.
                $literal = $command.CommandElements[4]
                Assert-True (($literal.Value.Length + 512) -lt 32767) 'each nested ComSpec command fits CreateProcess with wrapper reserve'
            }
        }
    }
    Write-Host "UNATTEND_LAUNCHER_REGRESSIONS PASS ($script:assertions assertions)"
} finally {
    foreach ($name in $fixtureEnvironment) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
    if ([IO.Directory]::Exists($scratch)) { [IO.Directory]::Delete($scratch, $true) }
}
