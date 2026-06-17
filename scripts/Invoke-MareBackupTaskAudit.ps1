param(
    [string]$TaskName = '\Microsoft\Windows\Application Experience\MareBackup',
    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,
    [switch]$SkipNtObjectManager,
    [switch]$TestDirectSameBytesWrite
)

$ErrorActionPreference = 'Stop'

function Write-Result {
    param([string]$Name, [object]$Value)
    "{0,-36} {1}" -f ($Name + ':'), $Value
}

function Get-TaskFilePath {
    param([string]$Name)
    $relative = $Name.TrimStart('\') -replace '\\', [IO.Path]::DirectorySeparatorChar
    Join-Path $env:windir ("System32\Tasks\" + $relative)
}

function Test-UsersFullControl {
    param([System.Security.AccessControl.FileSecurity]$Acl)
    [bool]($Acl.Access | Where-Object {
        $_.IdentityReference.Value -eq 'BUILTIN\Users' -and
        $_.AccessControlType -eq 'Allow' -and
        (($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl)
    } | Select-Object -First 1)
}

$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

$taskFile = Get-TaskFilePath $TaskName
if (-not (Test-Path -LiteralPath $taskFile)) {
    throw "Task file not found: $taskFile"
}

$xmlText = & schtasks.exe /Query /TN $TaskName /XML 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "schtasks query failed: $xmlText"
}
$xmlJoined = $xmlText -join "`n"
$taskXmlPath = Join-Path $OutputRoot 'task_query.xml'
Set-Content -LiteralPath $taskXmlPath -Value $xmlJoined -Encoding UTF8

$xml = [xml]$xmlJoined
$ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
$ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
$taskSddlNode = $xml.SelectSingleNode('//t:RegistrationInfo/t:SecurityDescriptor', $ns)
$principalNode = $xml.SelectSingleNode('//t:Principals/t:Principal/t:UserId', $ns)
$taskSddl = if ($taskSddlNode) { $taskSddlNode.InnerText } else { '' }
$principal = if ($principalNode) { $principalNode.InnerText } else { '' }

$actions = @()
foreach ($exec in $xml.SelectNodes('//t:Actions/t:Exec', $ns)) {
    $cmd = $exec.SelectSingleNode('t:Command', $ns).InnerText
    $argNode = $exec.SelectSingleNode('t:Arguments', $ns)
    $args = if ($argNode) { $argNode.InnerText } else { '' }
    $actions += (($cmd + ' ' + $args).Trim())
}

$acl = Get-Acl -LiteralPath $taskFile
$hashBefore = (Get-FileHash -LiteralPath $taskFile -Algorithm SHA256).Hash
$usersFull = Test-UsersFullControl -Acl $acl
$embeddedBuGenericAll = [bool]($taskSddl -match '\(A;;GA;;;BU\)')
$principalIsSystem = $principal -in @('S-1-5-18', 'SYSTEM', 'NT AUTHORITY\SYSTEM')

$medium = [ordered]@{
    Attempted = $false
    User = ''
    Integrity = ''
    Elevated = ''
    TaskGenericAll = ''
    FileReadWrite = ''
    Error = ''
}

if (-not $SkipNtObjectManager) {
    $medium.Attempted = $true
    try {
        Import-Module NtObjectManager -Force
        $explorer = Get-Process explorer -ErrorAction Stop | Select-Object -First 1
        $token = Get-NtToken -ProcessId $explorer.Id -Access MaximumAllowed -Duplicate -TokenType Impersonation -ImpersonationLevel Impersonation
        try {
            $medium.User = $token.User.ToString()
            $medium.Integrity = $token.IntegrityLevel.ToString()
            $medium.Elevated = $token.Elevated.ToString()
            $taskAccess = Get-AccessibleScheduledTask -Token $token -Access GenericAll |
                Where-Object { $_.Name -eq $TaskName } |
                Select-Object -First 1
            $medium.TaskGenericAll = if ($taskAccess) { $taskAccess.GrantedAccessString } else { 'not GenericAll' }
            $medium.FileReadWrite = Invoke-NtToken -Token $token -Script {
                try {
                    $fs = [IO.File]::Open($taskFile, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
                    $fs.Close()
                    'OK'
                } catch {
                    'ERR ' + $_.Exception.Message
                }
            }
        } finally {
            if ($token) { $token.Close() }
        }
    } catch {
        $medium.Error = $_.Exception.Message
    }
}

$sameBytes = [ordered]@{
    Attempted = [bool]$TestDirectSameBytesWrite
    Result = ''
    HashAfter = ''
    HashUnchanged = $false
    Error = ''
}

if ($TestDirectSameBytesWrite) {
    $beforeBytes = [IO.File]::ReadAllBytes($taskFile)
    try {
        [IO.File]::WriteAllBytes($taskFile, $beforeBytes)
        $sameBytes.Result = 'OK'
    } catch {
        $sameBytes.Result = 'ERR'
        $sameBytes.Error = $_.Exception.Message
    } finally {
        [IO.File]::WriteAllBytes($taskFile, $beforeBytes)
    }
    $sameBytes.HashAfter = (Get-FileHash -LiteralPath $taskFile -Algorithm SHA256).Hash
    $sameBytes.HashUnchanged = ($hashBefore -eq $sameBytes.HashAfter)
}

$summary = [ordered]@{
    TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
    Mode = if ($TestDirectSameBytesWrite) { 'same-bytes-write-validation' } else { 'read-only' }
    TaskName = $TaskName
    TaskFile = $taskFile
    Principal = $principal
    PrincipalIsSystem = $principalIsSystem
    EmbeddedSddl = $taskSddl
    EmbeddedBuGenericAll = $embeddedBuGenericAll
    BuiltinUsersFileFullControl = $usersFull
    Actions = $actions
    TaskFileSha256Before = $hashBefore
    MediumToken = $medium
    SameBytesWrite = $sameBytes
    Interpretation = 'Permissive MareBackup task/file rights are evidence. Direct XML-edit SYSTEM execution is not proven by this script.'
}

$summaryPath = Join-Path $OutputRoot 'summary.json'
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

Write-Result 'SummaryJson' $summaryPath
Write-Result 'PrincipalIsSystem' $principalIsSystem
Write-Result 'Embedded_BU_GenericAll' $embeddedBuGenericAll
Write-Result 'BUILTIN_Users_FileFullControl' $usersFull
Write-Result 'MediumTokenFileReadWrite' $medium.FileReadWrite
Write-Result 'SameBytesWriteResult' $sameBytes.Result
Write-Result 'HashUnchanged' $sameBytes.HashUnchanged
