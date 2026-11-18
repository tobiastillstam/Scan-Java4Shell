# Scan-Java4Shell

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)
![Platform](https://img.shields.io/badge/Windows%20Server-2016%2B-0078D6)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/version-1.0.0-blue)

Finds Java runtimes on the Windows servers in your domain and reports whether
they are affected by **Java4Shell** (CVE-2026-114938). This is a memory
corruption flaw in the OpenJDK HotSpot x86-64 Base64 decoder that can give
**pre-authentication remote code execution** in applications such as Jira,
Jenkins and Keycloak.

Read-only. Java is never executed: versions come from each runtime's
`release` file and the `jvm.dll` version resource. Running a `java.exe` found
on disk would run whatever sits in a writable folder under that name, with
the scanner's admin rights. The script returns one exit code per run, so it
fits RMM tools and scheduled tasks.

---

## What it does

- **Finds targets** in Active Directory: every enabled computer account with
  a Windows Server OS, optionally below one OU (`-SearchBase`). Or pass
  `-ComputerName` to name the targets yourself.
- **Scans in parallel** over WinRM (`Invoke-Command -ThrottleLimit`, works
  on Windows PowerShell 5.1). Names that mean this computer are scanned
  in-process.
- **Walks the fixed drives for `jvm.dll`**, the JVM itself. This also finds
  runtimes that are bundled with an application and never registered in
  Windows. The installed-programs list alone misses those.
- **Reads what points at Java**: Uninstall entries, `JavaSoft` registry keys,
  machine `JAVA_HOME` and `PATH`, services, Apache Procrun services (Tomcat
  and friends) and running processes. A referenced home is checked even
  where the walk does not reach.
- **Reports exposure context** without changing the status:
  - `CpuAvx512Vbmi`: the flaw needs AVX-512 VBMI (Intel Ice Lake and
    newer, AMD Zen 4 and newer).
  - `Mitigation`: `-XX:-UseBASE64Intrinsics` or `-XX:UseAVX=0..2` found
    in machine `JAVA_TOOL_OPTIONS` / `_JAVA_OPTIONS` / `JDK_JAVA_OPTIONS`,
    in a service command line, in Procrun options or on a running
    process's command line.
  - `RunningProcesses`, `Services` and `RegisteredAs`, so you can tell a
    live runtime from a forgotten zip.

### Classification

| Status | Meaning |
| --- | --- |
| `NEEDS PATCH` | Affected line (17.0.6+, 21, 25, 27, Oracle 8 Performance Pack) below the fixed build for its vendor. Vendors with no fixed build yet are `NEEDS PATCH`. |
| `UNAFFECTED` | Fixed build; a line the advisory does not list (8, 11, 9-16, 17.0.0-17.0.5); or an ARM64 build. |
| `WARN` | Version unreadable; a non-LTS line the advisory does not cover (18-20, 22-24, 26, newer than 27); a 32-bit x86 build; or an OpenJ9 VM. Check these by hand. |

### Fixed builds (as of 2026-11-18)

| Line | Oracle JDK / GraalVM for JDK | Amazon Corretto | Azul Zulu |
| --- | --- | --- | --- |
| 17 | 17.0.21.1 | 17.0.21.1.2 | 17.70.201 |
| 21 | 21.0.13.1 | 21.0.13.1.2 | 21.54.201 |
| 25 | 25.0.5.1 | 25.0.5.1.2 | 25.38.201 |
| 27 | 27.0.1.1 | 27.0.1.1.4 | 27.30.201 |

- Oracle Java 8 Performance Pack: fixed in `8u513-perf`.
- GraalVM Enterprise 21.3: fixed in `21.3.20.1`.
- **Other vendors** (Eclipse Temurin, Microsoft, Red Hat, BellSoft Liberica,
  SapMachine) had no confirmed fixed build on 2026-11-18. Their runtimes in
  an affected line are reported as `NEEDS PATCH`. A runtime counts as fixed
  once its `JAVA_VERSION` reaches the Oracle fixed version for its line.
- The tables are at the top of the script (`$FixedOracle`, `$FixedCorretto`,
  `$FixedZulu`). Update them as vendors ship.

---

## Requirements

- Windows Server 2016 or later / Windows 10 or later.
- Windows PowerShell 5.1 (also runs on PowerShell 7).
- An **elevated** session (`#Requires -RunAsAdministrator`).
- For the AD query: the `ActiveDirectory` module (RSAT AD DS tools). It is
  not needed with `-ComputerName`.
- For remote targets: WinRM enabled on the targets, and an account that is a
  local administrator there.

---

## Quick start

```powershell
# All enabled Windows Server computer accounts in the domain
.\Scan-Java4Shell.ps1

# One OU, 40 targets at a time
.\Scan-Java4Shell.ps1 -SearchBase 'OU=Servers,DC=example,DC=com' -ThrottleLimit 40

# This computer only (no AD needed)
.\Scan-Java4Shell.ps1 -ComputerName localhost

# Named servers; return what needs attention as objects
.\Scan-Java4Shell.ps1 -ComputerName app01,app02 -PassThru | Where-Object Status -ne 'UNAFFECTED'

# Fast inventory: registry, services and processes only, no disk walk
.\Scan-Java4Shell.ps1 -SkipDiskWalk
```

### Parameters

| Parameter | Description |
| --- | --- |
| `-ComputerName` | Targets to scan instead of querying AD. A comma-separated string is split. |
| `-SearchBase` | OU distinguished name for the AD query. Cannot be combined with `-ComputerName`. |
| `-Credential` | Credential for AD and WinRM. |
| `-ThrottleLimit` | Targets scanned at the same time, 1-256. Default 20. |
| `-Path` | Folders to walk on every target instead of all fixed drives. |
| `-ExcludePath` | Extra folders to skip on every target. |
| `-SkipDiskWalk` | Registry, environment, services and processes only. |
| `-SkipReferences` | Disk walk only. |
| `-LogPath` | Folder for the transcript and CSV files. Default: the script folder. |
| `-PassThru` | Also write one object per runtime to the pipeline. |

---

## Output

All files go to `-LogPath`, base name
`Scan-Java4Shell-<HOST>-<yyyyMMdd-HHmmss-fff>`. Names are reserved atomically,
so concurrent runs never overwrite each other.

| File | Content |
| --- | --- |
| `.log` | Transcript of the run. |
| `.csv` | One row per runtime: `ComputerName, Status, JavaHome, Vendor, JavaVersion, Feature, Arch, FixedIn, Action, CpuAvx512Vbmi, Mitigation, RunningProcesses, Services, RegisteredAs, FoundBy, Files, Note`. |
| `-hosts.csv` | One row per target: `Target, ComputerName, ScanStatus (Scanned / Not scanned / Unreachable), OperatingSystem, Runtimes, NeedsPatch, Warn, CpuArch, CpuName, CpuAvx512Vbmi, FoldersScanned, FoldersDenied, Note`. |

Both CSV files are written on every run, header-only when empty, also when
the script fails. They are UTF-8 with BOM, so non-ASCII paths survive and
Excel opens them correctly. Console and log output are ASCII.

### Exit codes

The highest applicable code wins.

| Code | Meaning |
| --- | --- |
| `0` | Every target scanned, no affected runtime. |
| `1` | At least one runtime `NEEDS PATCH`. |
| `2` | Partial: a target was not scanned (unreachable, nothing to walk) or a runtime is `WARN`. |
| `3` | Script error (bad input, AD module missing, ...). |

Parameter binding errors (unknown parameter name, wrong value type) are
raised by PowerShell before the script runs and exit with `1`.

---

## Notes and limits

- **Not a proof of exposure.** The flaw also needs an x86-64 CPU with
  AVX-512 VBMI and the decoder compiled by the C2 JIT. The version decides
  the status because VMs move between hosts and JVM flags drift. Use
  `CpuAvx512Vbmi` and `Mitigation` to prioritize.
- `CpuAvx512Vbmi` is `Yes`/`No` when the scanning PowerShell has .NET 8
  intrinsics (PowerShell 7.4+, local scans). On the default remote endpoint
  (Windows PowerShell 5.1) it is:
  - `No` when Windows reports AVX2 but not AVX-512F;
  - `Possible` when AVX-512F is present (VBMI is not checked);
  - `Unknown` on older Windows versions.

  ARM64 hosts are `No`. A VM reports what the hypervisor exposes.
- Oracle 8 Performance Pack builds are recognised only when `perf` appears in
  the `release` file or the `jvm.dll` version resource.
- Junctions and symlinks are not followed. Long paths (> 260 characters)
  are supported. Cloud placeholder files are not read, because reading them
  would download them.
- Folders that cannot be read are counted per host (`FoldersDenied`, first
  20 in the log). They do not change the exit code.
- Command lines of other users' processes are visible only when elevated.
  Flags inside WinSW XML files or startup scripts are not read.
- `-Path` and `-ExcludePath` are not split on commas, because paths can
  contain them. With `powershell.exe -File`, pass one path each.

---

## Mitigation (until you can patch)

The researchers suggest either JVM option. Neither Oracle nor the OpenJDK
advisory mentions them, so test before relying on them:

```text
-XX:-UseBASE64Intrinsics     disables only the Base64 intrinsic
-XX:UseAVX=2                 disables AVX-512 (x86-64 only; an ARM JVM fails to start with it)
```

---

## Sources

- Calif research write-up: <https://calif.io/java4shell/>
- Tenable FAQ: <https://www.tenable.com/blog/java4shell-cve-2026-114938-frequently-asked-questions-about-openjdk-rce-vulnerability>
- Censys advisory: <https://censys.com/advisory/cve-2026-114938/>
- The Hacker News: <https://thehackernews.com/2026/11/java4shell-cve-2026-114938-enables-pre.html>
- OpenJDK advisory (reference for upstream fixed versions):
  <https://openjdk.org/groups/vulnerability/advisories/2026-11-17>

---

## License

MIT - see [LICENSE](LICENSE). Copyright (c) 2026 Tobias Tillstam
([Tillnet](https://tillnet.se)).
