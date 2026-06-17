param(
    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,
    [switch]$ProbeCreate
)

$ErrorActionPreference = 'Stop'

function Write-Result {
    param([string]$Name, [object]$Value)
    "{0,-36} {1}" -f ($Name + ':'), $Value
}

function Test-LowPrivilegeWriteAce {
    param([string]$Path)

    $lowIds = @(
        'BUILTIN\Users',
        'Everyone',
        'NT AUTHORITY\Authenticated Users',
        'NT AUTHORITY\INTERACTIVE'
    )
    $writeBits = @(
        [Security.AccessControl.FileSystemRights]::CreateFiles,
        [Security.AccessControl.FileSystemRights]::AppendData,
        [Security.AccessControl.FileSystemRights]::WriteData,
        [Security.AccessControl.FileSystemRights]::WriteAttributes,
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes,
        [Security.AccessControl.FileSystemRights]::Modify,
        [Security.AccessControl.FileSystemRights]::FullControl
    )

    $hits = @()
    try {
        $acl = Get-Acl -LiteralPath $Path
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($lowIds -notcontains $ace.IdentityReference.Value) { continue }
            $hasWrite = $false
            foreach ($bit in $writeBits) {
                if (($ace.FileSystemRights -band $bit) -eq $bit) {
                    $hasWrite = $true
                    break
                }
            }
            if ($hasWrite) {
                $hits += "$($ace.IdentityReference.Value) $($ace.FileSystemRights)"
            }
        }
    } catch {
        $hits += 'ACL_ERROR ' + $_.Exception.Message
    }

    $hits
}

function Test-CreateProbe {
    param([string]$Path)

    $probeName = '.marebackup_path_probe_' + ([Guid]::NewGuid().ToString('N')) + '.tmp'
    $probePath = Join-Path $Path $probeName
    try {
        Set-Content -LiteralPath $probePath -Value 'create-delete probe' -Encoding ASCII -NoNewline
        Remove-Item -LiteralPath $probePath -Force
        'OK'
    } catch {
        try { Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue } catch {}
        'ERR ' + $_.Exception.Message
    }
}

$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

$systemPath = (Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name Path).Path
$entries = $systemPath -split ';' | Where-Object { $_ -and $_.Trim() } | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim()) }

$powerShellPath = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0'
$powerShellIndex = -1
for ($i = 0; $i -lt $entries.Count; $i++) {
    if ($entries[$i].TrimEnd('\') -ieq $powerShellPath.TrimEnd('\')) {
        $powerShellIndex = $i
        break
    }
}

if ($powerShellIndex -gt 0) {
    $entriesBeforePowerShell = $entries[0..($powerShellIndex - 1)]
} elseif ($powerShellIndex -eq 0) {
    $entriesBeforePowerShell = @()
} else {
    $entriesBeforePowerShell = $entries
}

$results = @()
for ($i = 0; $i -lt $entriesBeforePowerShell.Count; $i++) {
    $entry = $entriesBeforePowerShell[$i]
    $exists = Test-Path -LiteralPath $entry
    $aces = @()
    $probe = 'not requested'
    if ($exists) {
        $aces = Test-LowPrivilegeWriteAce -Path $entry
        if ($ProbeCreate) {
            $probe = Test-CreateProbe -Path $entry
        }
    }
    $results += [ordered]@{
        Index = $i
        Path = $entry
        Exists = $exists
        LowPrivilegeWritableAce = ($aces.Count -gt 0)
        MatchingLowPrivilegeAces = $aces
        CreateProbe = $probe
    }
}

$confirmedCreate = @($results | Where-Object { $_.CreateProbe -eq 'OK' })
$aclWritable = @($results | Where-Object { $_.LowPrivilegeWritableAce })

$summary = [ordered]@{
    TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
    Mode = if ($ProbeCreate) { 'acl-plus-create-delete-probe' } else { 'acl-only' }
    PowerShellPath = $powerShellPath
    PowerShellPathIndex = $powerShellIndex
    EntriesBeforePowerShell = $entriesBeforePowerShell.Count
    LowPrivilegeWritableAceBeforePowerShell = $aclWritable.Count
    ConfirmedCreateBeforePowerShell = $confirmedCreate.Count
    Results = $results
    Interpretation = 'itm4n PATH hijack precondition is strongest when ConfirmedCreateBeforePowerShell is greater than zero before Windows PowerShell.'
}

$summaryPath = Join-Path $OutputRoot 'path_hijack_preconditions.json'
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

Write-Result 'SummaryJson' $summaryPath
Write-Result 'PowerShellPathIndex' $powerShellIndex
Write-Result 'EntriesBeforePowerShell' $entriesBeforePowerShell.Count
Write-Result 'LowPrivWritableAceBeforePS' $aclWritable.Count
Write-Result 'ConfirmedCreateBeforePS' $confirmedCreate.Count
Write-Result 'ProbeCreate' ([bool]$ProbeCreate)
