# Evidence Summary

Local benign checks were run on 2026-06-17.

## MareBackup Task Audit

Observed:

- Task: `\Microsoft\Windows\Application Experience\MareBackup`
- Task file: `C:\WINDOWS\System32\Tasks\Microsoft\Windows\Application Experience\MareBackup`
- Principal: `S-1-5-18`
- Embedded SDDL: `D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;GA;;;BU)(A;;FRFX;;;LS)`
- `BUILTIN\Users` file Full Control: true
- Embedded `BUILTIN\Users` GenericAll: true
- Medium token task access: Full Access
- Medium token file read/write open: OK
- Same-bytes write validation: OK
- Task file SHA256 before and after same-bytes validation: `7C7E4A48F86BE63276A41BAB758D1751769267069658FB68C07CB7D719445380`

Conclusion: the permissive task/file rights primitive is reproducible locally. This alone does not prove SYSTEM execution through direct XML modification.

## Offline Candidate XML

An offline XML review candidate was generated from captured task XML. It was not applied to Task Scheduler.

Observed:

- Simulator mode: offline XML copy transform
- Applied to system: false
- Expected input properties: true
- Candidate generated: true
- Candidate action: `%windir%\System32\cmd.exe /c whoami /all > "C:\ProgramData\MareBackupVmValidation_20260617_052718.txt"`

Conclusion: the candidate is a lab review artifact only. It is not proof of LPE.

## Remaining Proof Required

A complete LPE claim requires a disposable lab proof that a low/medium user-controlled execution path produces a SYSTEM marker. For the itm4n chain, the key precondition is a low-privilege writable directory before the real Windows PowerShell directory in the system `PATH`.

## PATH Hijack Preconditions On This Host

The included PATH checker was run in both ACL-only mode and explicit create/delete probe mode.

Observed:

- Windows PowerShell path index in system `PATH`: 6
- Entries before Windows PowerShell: 6
- Low-privilege writable ACE entries before PowerShell: 0
- Confirmed create/delete entries before PowerShell: 0

Conclusion: itm4n's PATH search-order hijack precondition does not appear present on this host based on the current checks.
