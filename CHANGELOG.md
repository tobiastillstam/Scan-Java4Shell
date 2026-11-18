# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-11-18

### Fixed
- GraalVM Enterprise 21.3 runtimes on a Java 8, 11 or pre-17.0.6 base were
  reported `UNAFFECTED` before the GraalVM check ran. `GRAALVM_VERSION`
  21.3.x is now classified first, for any base JDK (ARM64 stays
  `UNAFFECTED`).

### Changed
- Runtime CSV and `-PassThru` output are sorted for triage: status, then
  `CpuAvx512Vbmi` (Yes, Possible, Unknown, No), then unmitigated runtimes
  first. Status rules are unchanged.
- Fixed builds cross-checked against Rapid7 and the Canadian Centre for
  Cyber Security (AL26-029); the tables are unchanged.

## [1.0.0] - 2026-11-18

### Added
- Initial release of `Scan-Java4Shell.ps1` for Java4Shell (CVE-2026-114938).
- Active Directory target discovery (enabled Windows Server computer
  accounts, optional `-SearchBase`) or explicit `-ComputerName`. Parallel
  WinRM scan with `-ThrottleLimit`, Windows PowerShell 5.1 compatible.
- Disk walk for `jvm.dll` (no junctions followed, long paths, system
  excludes). Java homes are also found through Uninstall entries, JavaSoft
  keys, machine `JAVA_HOME` / `PATH`, services, Apache Procrun and running
  processes.
- Version from the `release` file, with the `jvm.dll` version resource as a
  fallback. No Java binary is ever run.
- Vendor-aware classification: Oracle / GraalVM, Amazon Corretto, Azul Zulu
  and GraalVM Enterprise fixed builds. Vendors without a fixed build are
  `NEEDS PATCH`.
- Report-only context: AVX-512 VBMI support, mitigation flags, running
  processes, services, registration.
- Runtime CSV, hosts CSV and transcript on every run. Exit codes 0 / 1 / 2 / 3,
  where the highest applicable code wins.

### Tested
- Local harness (115 assertions: static template checks, 14 scenarios)
  passes under Windows PowerShell 5.1, PowerShell 7 and 32-bit Windows
  PowerShell 5.1, non-elevated, scanning the local computer. Scenarios:
  - every status branch and vendor rule;
  - JDK 8 `jre` layout and the `jvm.dll` version fallback;
  - junctions not followed, denied folder, paths over 260 characters,
    non-ASCII paths;
  - missing `-Path`, unreachable remote target, AD module missing;
  - input validation, `-WhatIf`, `-PassThru`, local-name dedupe;
  - mitigation flags on a running process, `-ExcludePath`, concurrent runs;
  - a live scan of installed runtimes through references.
