# Comparison With itm4n's MareBackup PATH Hijack

The public itm4n article and the local task-permission checks cover related but distinct chains.

## itm4n Chain

The itm4n chain is a PATH search-order hijack:

- MareBackup runs `CompatTelRunner.exe` as SYSTEM.
- The telemetry path launches `powershell.exe` without an absolute path.
- If a low-privilege writable directory appears before the real Windows PowerShell directory in the system `PATH`, a planted `powershell.exe` can be selected first.
- MareBackup can be started by a low/medium user because of permissive task rights.

The vulnerable condition is the weak writable `PATH` entry before PowerShell, not direct task XML modification.

Reference: https://itm4n.github.io/hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/

## Local Task-Permission Chain

The local checks confirm:

- MareBackup runs as SYSTEM.
- Its embedded task SDDL grants `BUILTIN\Users` GenericAll.
- Its task file grants `BUILTIN\Users` Full Control.
- A medium unelevated token can open and same-bytes rewrite the task file.

However, direct task-file modification is likely blocked by Task Scheduler integrity checks and registry checksums. This means the task-permission primitive is useful evidence but is not the same as a complete LPE.

## Practical Difference

| Question | itm4n PATH chain | Local XML/ACL checks |
|---|---|---|
| Requires weak writable PATH entry | Yes | No |
| Requires modifying task XML | No | Hypothesis only |
| Uses MareBackup DACL | To start/enable the task | To demonstrate permissive task/file rights |
| Full SYSTEM execution shown | Yes, when PATH precondition exists | Not proven |
| Best defensive check | PATH ordering and folder writeability | Task SDDL/file ACL audit |

## Recommended Report Wording

Use conservative wording:

- "MareBackup has permissive task/file rights and can be started by low/medium users."
- "A PATH search-order hijack is exploitable when a low-privilege writable folder precedes Windows PowerShell in the system PATH."
- Do not claim direct XML replacement is verified LPE unless a disposable lab proves Task Scheduler accepts and executes the modified definition.
