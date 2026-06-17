# MareBackup Validation Kit

Defensive validation kit for the Windows `\Microsoft\Windows\Application Experience\MareBackup` scheduled task.

This repository is intentionally non-weaponized. It collects evidence for two related but distinct issues:

1. MareBackup task permissions: the task runs as SYSTEM and may expose excessive low-privilege task/file rights.
2. MareBackup PATH search-order hijack preconditions: the public itm4n write-up shows SYSTEM code execution is possible when a low-privilege writable folder appears in the system `PATH` before the real Windows PowerShell directory.

## What This Kit Does

- Audits the MareBackup task principal, actions, SDDL, file ACL, and medium-token access.
- Optionally performs a same-bytes write check that restores the original bytes and verifies the hash is unchanged.
- Checks whether system `PATH` entries before Windows PowerShell are low-privilege writable.
- Produces evidence summaries suitable for reporting or triage.

## What This Kit Does Not Do

- It does not drop a fake `powershell.exe`.
- It does not run MareBackup by default.
- It does not spawn a shell, create users, modify groups, install persistence, or alter security settings.
- It does not claim the direct XML-edit path is a verified LPE.

## Quick Start

Open a non-elevated PowerShell prompt:

```powershell
cd .\scripts

.\Invoke-MareBackupTaskAudit.ps1 -OutputRoot ..\evidence\local-task-audit

.\Test-MareBackupPathHijackPreconditions.ps1 -OutputRoot ..\evidence\local-path-check
```

For an explicit same-bytes task-file write validation:

```powershell
.\Invoke-MareBackupTaskAudit.ps1 -OutputRoot ..\evidence\local-task-audit-samebytes -TestDirectSameBytesWrite
```

For an explicit benign create/delete probe in PATH folders:

```powershell
.\Test-MareBackupPathHijackPreconditions.ps1 -OutputRoot ..\evidence\local-path-check-probe -ProbeCreate
```

## Interpretation

- If task audit passes, you have evidence of the permissive MareBackup task/file ACL condition.
- If `PATH` precondition check finds a low-privilege writable directory before `%SystemRoot%\System32\WindowsPowerShell\v1.0`, the itm4n PATH hijack condition may be present.
- A full LPE claim requires a controlled lab proof. This repository does not provide a weaponized exploit.

## References

- itm4n, "Hijacking the Windows MareBackup Scheduled Task for Privilege Escalation": https://itm4n.github.io/hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/
- Local evidence summary: `docs/evidence-summary.md`
- Chain comparison: `docs/itm4n-comparison.md`
