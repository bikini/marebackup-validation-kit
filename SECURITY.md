# Security Notes

This repository is intended for authorized defensive validation only.

The included scripts avoid exploit payloads and default to read-only checks. Optional probes are limited to:

- same-bytes rewrite of the MareBackup task file with hash verification;
- create/delete tests of random temporary files in `PATH` directories.

Do not use this repository to deploy payloads, spawn SYSTEM shells, create users, modify groups, disable security tooling, or establish persistence.
