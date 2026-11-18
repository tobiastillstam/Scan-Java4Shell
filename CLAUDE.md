# Scan-Java4Shell - project context for Claude Code

Single read-only PowerShell script that finds Java runtimes on Windows
servers (AD discovery or `-ComputerName`, parallel WinRM) and reports
whether they are affected by Java4Shell (CVE-2026-114938). Results come
back as an exit code, a runtime CSV, a hosts CSV and a transcript.

Owner: Tobias Tillstam / Tillnet. License: MIT.

## Advisory data

The tables at the top of the script are the single source:
- `$FixedOracle`: affected lines 17 / 21 / 25 / 27 and the Oracle fixed
  versions. The generic rule for any vendor is to compare `JAVA_VERSION`
  with these.
- `$FixedCorretto`, `$FixedZulu`, `$FixedGraalEE`, `$FixedJava8PerfUpd`:
  vendor build numbers.
- `$AffectedFrom`: 17.0.6 is the only known lower bound.

When a vendor ships a fix:
1. Add it to the script tables.
2. Bump Version, Last Modified and the Change Log.
3. Update README.md (fixed-builds table and version badge) and CHANGELOG.md.

## Coding conventions (house template)

- `#Requires -Version 5.1` and `#Requires -RunAsAdministrator`.
- NOTES holds Author, Webpage, GitHub, Company, License, Version (semver),
  Date Created, Last Modified, Change Log, Operational notes.
- Every parameter has `[Parameter(Mandatory = $false)]` plus a one-line
  comment.
- Flat try/catch/finally, `Write-Verbose` bookends, section banners. The
  catch block uses `Write-Error -ErrorAction Continue` (the script sets
  `$ErrorActionPreference = 'Stop'`) and then `throw`. `exit $exitCode`
  is the last line of finally.
- Script source and console/log output are pure ASCII (`Write-Log` folds
  accents). CSV files are UTF-8 with BOM.
- Keep PS 5.1 compatibility (no ternary, no `??`). The scan block must run
  on the default remote endpoint, which is Windows PowerShell 5.1.
- In the scan block, use `[IO.Path]::Combine`, not `Join-Path`. PS 5.1
  `Join-Path` throws on a path whose drive does not exist (stale registry
  entries).
- `-and` / `-or` have equal precedence: always parenthesize.

## Design decisions

- **Read-only.** Nothing is gated by ShouldProcess. Transcript and CSV
  writes pass `-WhatIf:$false`, so a `-WhatIf` run is a normal scan.
- **Never runs a found binary.** Versions come from the `release` file
  (`JAVA_VERSION`, `IMPLEMENTOR`, `IMPLEMENTOR_VERSION`, `GRAALVM_VERSION`,
  `JVM_VARIANT`, `OS_ARCH`). The fallback is the `jvm.dll` ProductVersion:
  `8.0.5110.33` means 8u511 (update x10), and `17.0.10.0` maps directly.
  FileVersion is not used: on Java 7/8 it is the HotSpot version (24.80).
  Version 0.x is treated as unreadable (WARN).
- **The scan block collects facts, the main body classifies.** The advisory
  tables live in one place and are never shipped to the targets.
- **The JVM is `jvm.dll`.** The walk enumerates only `jvm.dll`; `java.exe`
  launchers (Oracle javapath) are not runtimes.
  - Home is `<home>\bin\<variant>\jvm.dll`.
  - In the JDK 8 layout, `<jdk>\jre\...` maps to `<jdk>` when the
    `release` file is there.
- **References add homes**: Uninstall InstallLocation, JavaSoft JavaHome,
  machine JAVA_HOME, PATH entries ending in `bin`, service `java(w).exe`,
  Procrun `Jvm`, process `java(w).exe`. A home is probed at the known
  `jvm.dll` subpaths. A registered product without a JVM is a host note,
  not WARN.
- **Annotations always apply**, even with `-SkipReferences`:
  - `RegisteredAs`;
  - `RunningProcesses` / `Services` (path under the home);
  - `Mitigation` (`-XX:-UseBASE64Intrinsics`, `-XX:UseAVX=0..2` from
    machine env vars, service command lines, Procrun Options and process
    command lines).
- **Classification order**:
  1. No version: WARN.
  2. 8 and older: UNAFFECTED, except the 8 Performance Pack (`perf` in the
     release or resource strings).
  3. 9-16: UNAFFECTED.
  4. 17 below 17.0.6: UNAFFECTED.
  5. aarch64: UNAFFECTED.
  6. OpenJ9: WARN.
  7. A line outside 17/21/25/27: WARN.
  8. 32-bit x86: WARN.
  9. Otherwise check for a fix, using the first matching vendor rule:
     GraalVM EE (`GRAALVM_VERSION` 21.3.x), then Corretto, then Zulu, then
     the generic Oracle version. Not fixed means NEEDS PATCH.
- **CPU and mitigation never change the status** (decision: report only).
  CPU check:
  - ARM64 host: No.
  - .NET 8 `Avx512Vbmi.IsSupported`, when present.
  - Otherwise `IsProcessorFeaturePresent`: 41 (AVX-512F) gives Possible;
    40 (AVX2) without 41 gives No; neither gives Unknown, because older
    Windows does not know these feature numbers.
- **Exit codes** follow the house convention: 0 / 1 NEEDS PATCH / 2
  partial or WARN / 3 error, where the highest applicable code wins.
  - A target counts as scanned only if it returned its final `Status`
    record with `Complete`.
  - Complete is false when no walk root existed.
  - Denied folders are counted, not in the exit code.
- **Targets**:
  - With `-ComputerName`, AD is not used. Without it, `Get-ADComputer`
    (Enabled, `*Windows Server*`, `DNSHostName`) runs.
  - Combining `-ComputerName` and `-SearchBase` is an error.
  - A missing AD module is exit 3 with a hint.
  - Local names (localhost, `.`, 127.0.0.1, ::1, own name / FQDN) run
    in-process, once.
- **No `#Requires -Modules ActiveDirectory`**: it would block
  `-ComputerName` use and fail at binding (exit 1).
- **Report names**: `<Name>-<HOST>-yyyyMMdd-HHmmss-fff`, reserved with
  `FileMode.CreateNew`, with a `-N` suffix if taken. Evidence files are
  written in finally, also on errors.

## Test harness

`Tests\` is git-ignored and kept local. It is dependency-free (no Pester).

- `Tests\Invoke-ScannerTest.ps1 -Exe powershell.exe|pwsh.exe`:
  - builds fixture Java homes (release files plus x64 stub DLLs compiled
    with a chosen version resource) on a `subst` drive;
  - runs a copy without `#Requires -RunAsAdministrator` with `-File`;
  - covers static template checks and 14 scenarios.
- `-SkipLive` skips the scenario that reads the test machine's own Java
  installs.
- Run it under PS 5.1, PS 7 and 32-bit PS 5.1 (SysWOW64), non-elevated
  and once elevated.

## Backlog

- WinSW (`jenkins.xml`) arguments and startup scripts for mitigation flags.
- Load the fixed-build tables from a file so a vendor fix needs no release.
- Optional `-IncludeWorkstations` for the AD query.
