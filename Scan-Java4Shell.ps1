#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Finds Java runtimes on Windows servers and reports whether they are
    affected by Java4Shell (CVE-2026-114938).

.DESCRIPTION
    Java4Shell is an out-of-bounds write in the HotSpot x86-64 Base64 decoder
    intrinsic (AVX-512 VBMI code path). It can lead to pre-authentication
    remote code execution in applications that Base64-decode untrusted input.

    Targets come from Active Directory (enabled computer accounts with a
    Windows Server operating system, optionally below -SearchBase) or from
    -ComputerName. Remote targets are scanned in parallel over WinRM with
    Invoke-Command -ThrottleLimit; names that mean this computer are scanned
    in-process.

    On each target the script:
      - walks the local fixed drives (or -Path) for jvm.dll, the JVM itself,
        so bundled runtimes (Jira, Jenkins, Keycloak, ...) are found too;
      - reads places that point at a Java home: Uninstall entries, JavaSoft
        registry keys, machine JAVA_HOME and PATH, services, Apache Procrun
        services and running processes;
      - reads each home's 'release' file, falling back to the jvm.dll
        version resource. No Java binary is ever executed;
      - reports CPU support for AVX-512 VBMI and mitigation flags
        (-XX:-UseBASE64Intrinsics, -XX:UseAVX=0..2) found in machine
        environment variables, service command lines, Procrun options and
        running process command lines.

    Each runtime is classified centrally:

      NEEDS PATCH  affected release line (17.0.6+, 21, 25, 27, Oracle 8
                   Performance Pack) below the fixed build for its vendor.
                   Vendors with no known fixed build are NEEDS PATCH.
      UNAFFECTED   fixed build, a line the advisory does not list (8, 11,
                   9-16, 17.0.0-17.0.5) or an ARM64 build
      WARN         version unreadable, non-LTS line not covered by the
                   advisory (18-20, 22-24, 26, newer than 27), 32-bit x86
                   build, or OpenJ9 VM

    CPU support and mitigation flags are reported only; they never change
    the status (VMs move between hosts, flags drift).

    The script changes nothing on any target. It writes its own transcript
    and CSV files only, also under -WhatIf.

    Exit codes (highest applicable wins):
      0 = no affected runtime, every target scanned
      1 = at least one runtime NEEDS PATCH
      2 = partial: a target was not scanned, or a runtime is WARN
      3 = script error

.PARAMETER ComputerName
    Targets to scan instead of querying Active Directory. Comma-separated
    values are split (scheduled tasks pass "A,B" as one string).

.PARAMETER SearchBase
    Distinguished name of an OU to limit the Active Directory query to.
    Cannot be combined with -ComputerName (exit 3).

.PARAMETER Credential
    Credential for Active Directory and WinRM. Default: the current user.

.PARAMETER ThrottleLimit
    Maximum number of targets scanned at the same time (1-256). Default: 20.

.PARAMETER Path
    Folders to walk on every target instead of all local fixed drives.

.PARAMETER ExcludePath
    Extra folders to leave out of the walk on every target, on top of the
    built-in system folders.

.PARAMETER SkipDiskWalk
    Do not walk the disk; only read registry, environment, services and
    processes for Java homes (fast, misses unregistered bundled runtimes).

.PARAMETER SkipReferences
    Walk the disk only; do not add Java homes from registry, environment,
    services or processes. Annotations (RegisteredAs, RunningProcesses,
    Mitigation) are still filled in.

.PARAMETER LogPath
    Folder for the transcript and CSV files. Default: the script folder, or
    the current directory when the script path is unavailable.

.PARAMETER PassThru
    Also write one result object per runtime to the pipeline.

.EXAMPLE
    .\Scan-Java4Shell.ps1
    Scans every enabled Windows Server computer account in the domain.

.EXAMPLE
    .\Scan-Java4Shell.ps1 -SearchBase 'OU=Servers,DC=example,DC=com' -ThrottleLimit 40
    Scans the servers in one OU, 40 at a time.

.EXAMPLE
    .\Scan-Java4Shell.ps1 -ComputerName localhost -Verbose
    Scans this computer only, no Active Directory needed.

.EXAMPLE
    .\Scan-Java4Shell.ps1 -ComputerName app01,app02 -PassThru | Where-Object Status -ne 'UNAFFECTED'
    Scans two servers and returns the runtimes that need attention.

.NOTES
    Author        : Tobias Tillstam, Tillnet
    Webpage       : https://tillnet.se
    GitHub        : https://github.com/tobiastillstam
    Company       : Tillnet
    License       : MIT
    Version       : 1.1.0
    Date Created  : 2026-11-18
    Last Modified : 2026-11-18

    Change Log
    ----------
    1.0.0 (2026-11-18) - Initial release.
    1.1.0 (2026-11-18) - GraalVM Enterprise 21.3 is classified before the
                         Java feature-version gates (a Java 8/11/17 base
                         no longer hides it). Runtime CSV sorted by status,
                         CPU exposure and missing mitigation.

    Operational notes:
    - Fixed builds known on 2026-11-18 (see $FixedOracle, $FixedCorretto,
      $FixedZulu, $FixedGraalEE): Oracle JDK / GraalVM for JDK 17.0.21.1,
      21.0.13.1, 25.0.5.1, 27.0.1.1; Oracle 8 Performance Pack 8u513-perf;
      Amazon Corretto 17.0.21.1.2, 21.0.13.1.2, 25.0.5.1.2, 27.0.1.1.4;
      Azul Zulu 17.70.201, 21.54.201, 25.38.201, 27.30.201; GraalVM
      Enterprise 21.3.20.1 (any base JDK; the advisory names none). Any other vendor counts as fixed once its
      JAVA_VERSION reaches the Oracle fixed version for the line. Eclipse
      Temurin, Microsoft, Red Hat, BellSoft Liberica and SapMachine had no
      confirmed fixed build: their runtimes in affected lines are NEEDS
      PATCH until that changes. Update the tables when vendors ship.
    - Runtime CSV order: status (NEEDS PATCH, WARN, UNAFFECTED), then
      CpuAvx512Vbmi (Yes, Possible, Unknown, No), then rows without a
      mitigation flag first. The order is a triage aid only; CPU and
      mitigation never change the status.
    - Oracle 8 Performance Pack builds are recognised only when 'perf'
      appears in the release file or the jvm.dll version resource.
    - Read-only: nothing is gated by ShouldProcess because nothing on any
      target changes. Transcript and CSV writes pass -WhatIf:$false, so a
      -WhatIf run is a normal scan.
    - Never runs a found binary: versions come from the release file and
      the version resource only. The scan runs as admin, so a planted
      java.exe would otherwise run with admin rights.
    - Output in <LogPath>, base name Scan-Java4Shell-<HOST>-<yyyyMMdd-HHmmss-fff>
      (reserved with CreateNew, -N suffix when taken): .log (transcript),
      .csv (one row per runtime) and -hosts.csv (one row per target). Both
      CSV files are written on every run, header-only when empty, UTF-8
      with BOM.
    - A target counts as scanned only when it returned its final status
      record. Unreachable targets, targets where no walk root existed and
      targets whose scan failed are 'not scanned' (exit 2). Folders that
      could not be read are counted per host in the log and -hosts.csv,
      not in the exit code.
    - Reparse points (junctions, symlinks) are not followed. Long paths
      are handled with \\?\ paths. Cloud placeholder files are not read.
    - CpuAvx512Vbmi: Yes / No from .NET 8 intrinsics when the scanning
      PowerShell has them (PS 7.4+); otherwise No when Windows reports AVX2
      but not AVX-512F, Possible when it reports AVX-512F (VBMI not
      checked), Unknown on Windows versions that do not report either.
      ARM64 hosts are No. A VM reports what the hypervisor exposes.
    - Process command lines of other users are visible only when elevated.
      Mitigation flags inside a WinSW XML or a startup script are not read.
    - The remote endpoint is the default Windows PowerShell 5.1 session.
      WinRM must be enabled on the targets; a slow full-drive walk on a
      large file server delays only that target's result.
    - Parameter binding errors (unknown parameter, wrong value type) are
      raised by PowerShell before the script runs and exit with code 1.
    - Sources: calif.io/java4shell, Tenable, Censys and Rapid7 advisories,
      Canadian Centre for Cyber Security AL26-029, The Hacker News
      (2026-11-17/18). The OpenJDK advisory
      (openjdk.org/groups/vulnerability/advisories/2026-11-17) is the
      reference for upstream fixed versions.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # Targets to scan instead of querying Active Directory.
    [Parameter(Mandatory = $false)]
    [string[]]$ComputerName,

    # OU distinguished name for the Active Directory query. Default: whole domain.
    [Parameter(Mandatory = $false)]
    [string]$SearchBase,

    # Credential for Active Directory and WinRM. Default: current user.
    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    # Maximum number of targets scanned at the same time (1-256).
    [Parameter(Mandatory = $false)]
    [int]$ThrottleLimit = 20,

    # Folders to walk on every target instead of all local fixed drives.
    [Parameter(Mandatory = $false)]
    [string[]]$Path,

    # Extra folders to leave out of the walk on every target (full paths).
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludePath,

    # Do not walk the disk; only read registry, environment, services, processes.
    [Parameter(Mandatory = $false)]
    [switch]$SkipDiskWalk,

    # Walk the disk only; do not add Java homes from registry, services, processes.
    [Parameter(Mandatory = $false)]
    [switch]$SkipReferences,

    # Folder for the transcript and CSV files. Default: script folder.
    [Parameter(Mandatory = $false)]
    [string]$LogPath,

    # Also write one result object per runtime to the pipeline.
    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

# -------------------------------------------------------------------------
# Constants: advisory data (keep README.md in sync)
# -------------------------------------------------------------------------

$ScriptVersion = '1.0.0'
$AdvisoryDate  = '2026-11-18'

# Affected HotSpot release lines and the Oracle fixed version per line.
# Other vendors count as fixed once JAVA_VERSION reaches this version.
$FixedOracle = @{
    17 = '17.0.21.1'
    21 = '21.0.13.1'
    25 = '25.0.5.1'
    27 = '27.0.1.1'
}
# First affected version per line (only 17 has a known lower bound).
$AffectedFrom = @{ 17 = '17.0.6' }

# Vendor build numbers that carry the fix.
$FixedCorretto = @{
    17 = '17.0.21.1.2'
    21 = '21.0.13.1.2'
    25 = '25.0.5.1.2'
    27 = '27.0.1.1.4'
}
$FixedZulu = @{
    17 = '17.70.201'
    21 = '21.54.201'
    25 = '25.38.201'
    27 = '27.30.201'
}
$FixedGraalEE       = '21.3.20.1'
$FixedJava8PerfUpd  = 513

# Folders below each drive root that are not readable even when elevated
# and never hold a Java runtime.
$SystemExcludes = @(
    'System Volume Information'
    '$Recycle.Bin'
    'Recovery'
    'Windows\CSC'
    'Windows\System32\LogFiles\WMI\RtBackup'
    'Windows\System32\WebThreatDefSvc'
    'Windows\System32\config\BFS'
    'Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc'
    'ProgramData\Microsoft\Windows\SystemData'
    'ProgramData\Microsoft\Windows\CapabilityAccessManager'
    'ProgramData\Microsoft\Windows Defender Advanced Threat Protection'
    'Program Files\Windows Defender Advanced Threat Protection'
)

$StatusOrder = @{ 'NEEDS PATCH' = 0; 'WARN' = 1; 'UNAFFECTED' = 2 }
# Runtime CSV sort rank for CpuAvx512Vbmi (most exposed first); '' sorts as Unknown.
$CpuOrder    = @{ 'Yes' = 0; 'Possible' = 1; 'Unknown' = 2; '' = 2; 'No' = 3 }

$RuntimeColumns = @(
    'ComputerName', 'Status', 'JavaHome', 'Vendor', 'JavaVersion', 'Feature',
    'Arch', 'FixedIn', 'Action', 'CpuAvx512Vbmi', 'Mitigation',
    'RunningProcesses', 'Services', 'RegisteredAs', 'FoundBy', 'Files', 'Note'
)
$HostColumns = @(
    'Target', 'ComputerName', 'ScanStatus', 'OperatingSystem', 'Runtimes',
    'NeedsPatch', 'Warn', 'CpuArch', 'CpuName', 'CpuAvx512Vbmi',
    'FoldersScanned', 'FoldersDenied', 'Note'
)

# -------------------------------------------------------------------------
# Scan block (runs on each target, in-process or via Invoke-Command)
# Collects facts only; classification happens in the main body.
# Must stay Windows PowerShell 5.1 compatible (default remote endpoint).
# -------------------------------------------------------------------------

$ScanBlock = {
    param(
        [string[]]$ScanPath,
        [string[]]$ExcludePath,
        [string[]]$SystemExcludes,
        [bool]$SkipDiskWalk,
        [bool]$SkipReferences,
        [bool]$ShowProgress
    )

    $ErrorActionPreference = 'Stop'
    $state = @{
        Dirs         = 0
        Denied       = 0
        DeniedSample = New-Object System.Collections.Generic.List[string]
        Notes        = New-Object System.Collections.Generic.List[string]
    }
    $placeholderMask = 0x1000 -bor 0x40000 -bor 0x400000
    $flagPattern     = '(?i)(-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2](?![0-9]))'
    $jvmSubPaths     = @(
        'bin\server\jvm.dll', 'bin\client\jvm.dll',
        'jre\bin\server\jvm.dll', 'jre\bin\client\jvm.dll',
        'bin\default\jvm.dll', 'bin\j9vm\jvm.dll'
    )

    # --- Helpers ---------------------------------------------------------
    function Get-LongPath {
        param([string]$LiteralPath)
        if ($LiteralPath.StartsWith('\\?\')) { return $LiteralPath }
        if ($LiteralPath.StartsWith('\\')) { return '\\?\UNC\' + $LiteralPath.Substring(2) }
        '\\?\' + $LiteralPath
    }

    function Get-DisplayPath {
        param([string]$LiteralPath)
        if ($LiteralPath.StartsWith('\\?\UNC\')) { return '\\' + $LiteralPath.Substring(8) }
        if ($LiteralPath.StartsWith('\\?\')) { return $LiteralPath.Substring(4) }
        $LiteralPath
    }

    function Get-InnerMessage {
        param([System.Exception]$Exception)
        while ($Exception.InnerException) { $Exception = $Exception.InnerException }
        $Exception.Message
    }

    function ConvertTo-NormPath {
        # Trimmed, no trailing backslash (except a drive root), env vars expanded.
        param([string]$Value)
        if (-not $Value) { return '' }
        $p = [Environment]::ExpandEnvironmentVariables($Value.Trim().Trim('"').Trim())
        $p = $p -replace '/', '\'
        if ($p.Length -gt 3) { $p = $p.TrimEnd('\') }
        if ($p -match '^[A-Za-z]:$') { $p += '\' }
        $p
    }

    function Test-UnderPath {
        param([string]$Child, [string]$Parent)
        if (-not $Child -or -not $Parent) { return $false }
        $Child.Equals($Parent, [StringComparison]::OrdinalIgnoreCase) -or
            $Child.StartsWith($Parent.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
    }

    function Get-ExeFromCommandLine {
        # First token of a command line: quoted path, or up to the first '.exe'.
        param([string]$CommandLine)
        if (-not $CommandLine) { return '' }
        $c = $CommandLine.Trim()
        if ($c.StartsWith('"')) {
            $end = $c.IndexOf('"', 1)
            if ($end -gt 1) { return $c.Substring(1, $end - 1) }
            return ''
        }
        $m = [regex]::Match($c, '^(.+?\.exe)(\s|$)', 'IgnoreCase')
        if ($m.Success) { return $m.Groups[1].Value }
        ($c -split '\s+')[0]
    }

    function Get-HomeFromJvm {
        # <home>\bin\server\jvm.dll -> <home>; JDK 8 <jdk>\jre\... -> <jdk>
        # when the release file sits in <jdk>.
        param([string]$JvmPath)
        $dir = [IO.Path]::GetDirectoryName($JvmPath)
        $leaf = [IO.Path]::GetFileName($dir)
        if ($leaf -ieq 'bin') { $homeDir = [IO.Path]::GetDirectoryName($dir) }
        else {
            $parent = [IO.Path]::GetDirectoryName($dir)
            if ([IO.Path]::GetFileName($parent) -ieq 'bin') { $homeDir = [IO.Path]::GetDirectoryName($parent) }
            else { $homeDir = $dir }
        }
        if ([IO.Path]::GetFileName($homeDir) -ieq 'jre') {
            $outer = [IO.Path]::GetDirectoryName($homeDir)
            if ($outer -and [IO.File]::Exists((Get-LongPath ([IO.Path]::Combine($outer, 'release'))))) { $homeDir = $outer }
        }
        $homeDir
    }

    function Find-JvmInHome {
        # jvm.dll at the known layouts below one home; nothing when absent.
        param([string]$HomeDir)
        foreach ($sub in $jvmSubPaths) {
            $p = [IO.Path]::Combine($HomeDir, $sub)
            if ([IO.File]::Exists((Get-LongPath $p))) { $p }
        }
    }

    function Find-JvmFile {
        # Iterative walk, reparse points not followed. Writes jvm.dll paths.
        param([string]$Root, $ExcludeSet)
        $stack = New-Object 'System.Collections.Generic.Stack[string]'
        $stack.Push((Get-LongPath $Root))
        while ($stack.Count -gt 0) {
            $dir = $stack.Pop()
            $state.Dirs++
            if ($ShowProgress -and (($state.Dirs % 2000) -eq 0)) {
                Write-Progress -Activity 'Scanning for jvm.dll' -Status "$($state.Dirs) folders" -CurrentOperation (Get-DisplayPath $dir)
            }
            try {
                $info = New-Object System.IO.DirectoryInfo $dir
                foreach ($file in $info.EnumerateFiles('jvm.dll')) {
                    Get-DisplayPath $file.FullName
                }
                foreach ($sub in $info.EnumerateDirectories()) {
                    if ($sub.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                    if ($ExcludeSet.Contains((Get-DisplayPath $sub.FullName))) { continue }
                    $stack.Push($sub.FullName)
                }
            }
            catch {
                $state.Denied++
                if ($state.DeniedSample.Count -lt 20) {
                    $state.DeniedSample.Add(('{0} ({1})' -f (Get-DisplayPath $dir), (Get-InnerMessage $_.Exception)))
                }
            }
        }
        if ($ShowProgress) { Write-Progress -Activity 'Scanning for jvm.dll' -Completed }
    }

    function Read-ReleaseFile {
        # KEY="value" lines of <home>\release; $null when absent or unreadable.
        param([string]$HomeDir)
        $file = [IO.Path]::Combine($HomeDir, 'release')
        $long = Get-LongPath $file
        if (-not [IO.File]::Exists($long)) { return $null }
        $values = @{}
        try {
            if (([int][IO.File]::GetAttributes($long) -band $placeholderMask) -ne 0) {
                $values['_ERROR'] = 'release file is a cloud placeholder, not read'
                return $values
            }
            foreach ($line in [IO.File]::ReadAllLines($long)) {
                $m = [regex]::Match($line, '^\s*([A-Z0-9_]+)\s*=\s*"?([^"]*)"?\s*$')
                if ($m.Success -and ($m.Groups[1].Value -ne 'MODULES')) {
                    $values[$m.Groups[1].Value] = $m.Groups[2].Value.Trim()
                }
            }
        }
        catch {
            $values['_ERROR'] = "release file unreadable: $(Get-InnerMessage $_.Exception)"
        }
        $values
    }

    function Get-PeMachine {
        # Machine type from the PE header: x86_64, x86, aarch64 or ''.
        param([string]$FilePath)
        try {
            $fs = [IO.File]::Open((Get-LongPath $FilePath), 'Open', 'Read', 'ReadWrite')
            try {
                $buf = New-Object byte[] 4096
                $n = $fs.Read($buf, 0, $buf.Length)
                if ($n -lt 64) { return '' }
                $pe = [BitConverter]::ToInt32($buf, 0x3C)
                if (($pe -lt 0) -or (($pe + 6) -gt $n)) { return '' }
                switch ([BitConverter]::ToUInt16($buf, $pe + 4)) {
                    0x8664 { return 'x86_64' }
                    0x014C { return 'x86' }
                    0xAA64 { return 'aarch64' }
                    default { return '' }
                }
            }
            finally { $fs.Dispose() }
        }
        catch { return '' }
    }

    function Get-CpuInfo {
        $arch = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE', 'Machine')
        $name = ''
        try {
            $name = (@(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)[0].Name -replace '\s+', ' ').Trim()
        }
        catch { $name = '' }
        $vbmi = 'Unknown'
        if ($arch -ieq 'ARM64') {
            $vbmi = 'No'
        }
        else {
            $type = 'System.Runtime.Intrinsics.X86.Avx512Vbmi' -as [type]
            if ($type -and ([Environment]::Is64BitProcess)) {
                if ($type::IsSupported) { $vbmi = 'Yes' } else { $vbmi = 'No' }
            }
            else {
                try {
                    if (-not ('Tillnet.J4S.Cpu' -as [type])) {
                        Add-Type -Namespace 'Tillnet.J4S' -Name 'Cpu' -MemberDefinition '[DllImport("kernel32.dll")] public static extern bool IsProcessorFeaturePresent(uint feature);'
                    }
                    $avx2    = [Tillnet.J4S.Cpu]::IsProcessorFeaturePresent(40)
                    $avx512f = [Tillnet.J4S.Cpu]::IsProcessorFeaturePresent(41)
                    if ($avx512f)  { $vbmi = 'Possible' }
                    elseif ($avx2) { $vbmi = 'No' }
                }
                catch { $vbmi = 'Unknown' }
            }
        }
        [pscustomobject]@{ Arch = $arch; Name = $name; Vbmi = $vbmi }
    }

    function Get-HklmSubKey {
        # Subkeys of an HKLM path in both registry views (64-bit and 32-bit),
        # so a 32-bit host process sees the same as a 64-bit one.
        param([string]$SubPath)
        foreach ($view in 'Registry64', 'Registry32') {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', $view)
            try {
                $key = $base.OpenSubKey($SubPath)
                if ($key) {
                    foreach ($name in $key.GetSubKeyNames()) {
                        try {
                            $sk = $key.OpenSubKey($name)
                            if ($sk) {
                                [pscustomobject]@{ View = $view; Name = $name; Key = $sk }
                            }
                        }
                        catch { }
                    }
                }
            }
            finally { $base.Dispose() }
        }
    }

    # --- Host facts ------------------------------------------------------
    $cpu = Get-CpuInfo
    $os  = ''
    try { $os = [string](Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption } catch { }

    # Machine-wide JVM option variables (mitigation flags, report only).
    $envFlags = New-Object System.Collections.Generic.List[string]
    foreach ($var in 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS') {
        $v = [Environment]::GetEnvironmentVariable($var, 'Machine')
        if ($v) {
            foreach ($m in [regex]::Matches($v, $flagPattern)) { $envFlags.Add("$($m.Value) (machine $var)") }
        }
    }

    # Uninstall entries for Java products (annotation and reference).
    $javaName = '(?i)\b(Java|OpenJDK|JDK|JRE|GraalVM|Temurin|Corretto|Zulu|Liberica|SapMachine|Semeru)\b'
    $uninstall = New-Object System.Collections.Generic.List[object]
    foreach ($e in @(Get-HklmSubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')) {
        $dn = [string]$e.Key.GetValue('DisplayName')
        if ($dn -match $javaName) {
            $uninstall.Add([pscustomobject]@{
                Name     = ('{0} {1}' -f $dn, [string]$e.Key.GetValue('DisplayVersion')).Trim()
                Location = ConvertTo-NormPath ([string]$e.Key.GetValue('InstallLocation'))
            })
        }
        $e.Key.Dispose()
    }

    # Services (Win32_Service command line) and Apache Procrun services.
    $services = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
            if ($s.PathName) {
                $services.Add([pscustomobject]@{
                    Name = [string]$s.Name
                    Exe  = ConvertTo-NormPath (Get-ExeFromCommandLine $s.PathName)
                    Jvm  = ''
                    Args = [string]$s.PathName
                })
            }
        }
    }
    catch { $state.Notes.Add("services not read: $(Get-InnerMessage $_.Exception)") }
    foreach ($e in @(Get-HklmSubKey 'SOFTWARE\Apache Software Foundation\Procrun 2.0')) {
        try {
            $jk = $e.Key.OpenSubKey('Parameters\Java')
            if ($jk) {
                $jvm = ConvertTo-NormPath ([string]$jk.GetValue('Jvm'))
                $opts = @($jk.GetValue('Options')) + @($jk.GetValue('Options9')) | Where-Object { $_ }
                $services.Add([pscustomobject]@{
                    Name = "$($e.Name) (Procrun)"
                    Exe  = ''
                    Jvm  = $jvm
                    Args = ($opts -join ' ')
                })
                $jk.Dispose()
            }
        }
        catch { }
        $e.Key.Dispose()
    }

    # Running processes (command line visible for other users when elevated).
    $processes = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($p in @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)) {
            if ($p.ExecutablePath) {
                $processes.Add([pscustomobject]@{
                    Id   = $p.ProcessId
                    Name = [string]$p.Name
                    Exe  = ConvertTo-NormPath $p.ExecutablePath
                    Args = [string]$p.CommandLine
                })
            }
        }
    }
    catch { $state.Notes.Add("processes not read: $(Get-InnerMessage $_.Exception)") }

    # --- Collect homes ---------------------------------------------------
    # Key = home path, value = files and how it was found.
    $homes = @{}
    $addHome = {
        param([string]$HomeDir, [string[]]$JvmFiles, [string]$Source)
        $key = $HomeDir.ToLowerInvariant()
        if (-not $homes.ContainsKey($key)) {
            $homes[$key] = [pscustomobject]@{
                Home    = $HomeDir
                Files   = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                FoundBy = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            }
        }
        foreach ($f in $JvmFiles) { [void]$homes[$key].Files.Add($f) }
        [void]$homes[$key].FoundBy.Add($Source)
    }

    $rootsScanned = 0
    if (-not $SkipDiskWalk) {
        $roots = @()
        if ($ScanPath -and $ScanPath.Count -gt 0) {
            foreach ($p in $ScanPath) {
                $np = ConvertTo-NormPath $p
                if ([IO.Directory]::Exists((Get-LongPath $np))) { $roots += $np }
                else { $state.Notes.Add("path not found: $np") }
            }
        }
        else {
            $roots = @([IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } | ForEach-Object { $_.RootDirectory.FullName })
            if ($roots.Count -eq 0) { $state.Notes.Add('no fixed drive found') }
        }

        $excludeSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($x in $ExcludePath) { if ($x) { [void]$excludeSet.Add((ConvertTo-NormPath $x)) } }
        foreach ($d in @([IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' })) {
            foreach ($x in $SystemExcludes) { [void]$excludeSet.Add([IO.Path]::Combine($d.RootDirectory.FullName, $x)) }
        }

        foreach ($root in $roots) {
            $rootsScanned++
            foreach ($jvm in @(Find-JvmFile -Root $root -ExcludeSet $excludeSet)) {
                & $addHome (Get-HomeFromJvm $jvm) @($jvm) 'disk'
            }
        }
    }

    if (-not $SkipReferences) {
        $refs = New-Object System.Collections.Generic.List[object]
        foreach ($u in $uninstall) {
            if ($u.Location) { $refs.Add([pscustomobject]@{ Home = $u.Location; Source = 'uninstall' }) }
        }
        foreach ($e in @(Get-HklmSubKey 'SOFTWARE\JavaSoft')) {
            foreach ($ver in $e.Key.GetSubKeyNames()) {
                try {
                    $vk = $e.Key.OpenSubKey($ver)
                    if ($vk) {
                        $jh = ConvertTo-NormPath ([string]$vk.GetValue('JavaHome'))
                        if ($jh) { $refs.Add([pscustomobject]@{ Home = $jh; Source = 'JavaSoft' }) }
                        $vk.Dispose()
                    }
                }
                catch { }
            }
            $e.Key.Dispose()
        }
        $jhEnv = ConvertTo-NormPath ([Environment]::GetEnvironmentVariable('JAVA_HOME', 'Machine'))
        if ($jhEnv) { $refs.Add([pscustomobject]@{ Home = $jhEnv; Source = 'JAVA_HOME' }) }
        foreach ($entry in ([string][Environment]::GetEnvironmentVariable('Path', 'Machine')) -split ';') {
            $np = ConvertTo-NormPath $entry
            if ($np -and ([IO.Path]::GetFileName($np) -ieq 'bin')) {
                $refs.Add([pscustomobject]@{ Home = [IO.Path]::GetDirectoryName($np); Source = 'PATH' })
            }
        }
        foreach ($s in $services) {
            if ($s.Jvm -and ($s.Jvm -match '\\jvm\.dll$')) {
                $refs.Add([pscustomobject]@{ Home = (Get-HomeFromJvm $s.Jvm); Source = "service $($s.Name)" })
            }
            elseif ($s.Exe -match '\\javaw?\.exe$') {
                $refs.Add([pscustomobject]@{ Home = [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($s.Exe)); Source = "service $($s.Name)" })
            }
        }
        foreach ($p in $processes) {
            if ($p.Exe -match '\\javaw?\.exe$') {
                $refs.Add([pscustomobject]@{ Home = [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($p.Exe)); Source = 'process' })
            }
        }
        foreach ($r in $refs) {
            if (-not $r.Home) { continue }
            try {
                $jvms = @(Find-JvmInHome $r.Home)
                if ($jvms.Count -gt 0) { & $addHome (Get-HomeFromJvm $jvms[0]) $jvms $r.Source }
                elseif ($r.Source -eq 'uninstall') {
                    $state.Notes.Add("registered Java product without a JVM at $($r.Home)")
                }
            }
            catch { $state.Notes.Add("reference $($r.Home) not read: $(Get-InnerMessage $_.Exception)") }
        }
    }

    # --- Describe each home ----------------------------------------------
    foreach ($h in $homes.Values) {
        $rel = Read-ReleaseFile $h.Home
        $note = New-Object System.Collections.Generic.List[string]
        if ($rel -and $rel.ContainsKey('_ERROR')) { $note.Add($rel['_ERROR']) }
        if (-not $rel) { $rel = @{} }

        # Version resource of each jvm.dll (fallback when no release file).
        $fileVersion = ''; $fileCompany = ''; $fileProduct = ''; $peArch = ''
        foreach ($f in @($h.Files | Sort-Object)) {
            try {
                if (([int][IO.File]::GetAttributes((Get-LongPath $f)) -band $placeholderMask) -ne 0) {
                    $note.Add("$f is a cloud placeholder, not read")
                    continue
                }
                $fv = [Diagnostics.FileVersionInfo]::GetVersionInfo((Get-LongPath $f))
                if (-not $fileVersion -and $fv.ProductVersion) {
                    $fileVersion = [string]$fv.ProductVersion
                    $fileCompany = [string]$fv.CompanyName
                    $fileProduct = [string]$fv.ProductName
                }
                if (-not $peArch) { $peArch = Get-PeMachine $f }
            }
            catch { $note.Add("$f unreadable: $(Get-InnerMessage $_.Exception)") }
        }

        # Annotations: registration, services, processes, mitigation flags.
        $registered = @($uninstall | Where-Object { $_.Location -and (Test-UnderPath $h.Home $_.Location) } | ForEach-Object { $_.Name } | Sort-Object -Unique)
        $svcHits = @($services | Where-Object { (Test-UnderPath $_.Exe $h.Home) -or (Test-UnderPath $_.Jvm $h.Home) })
        $procHits = @($processes | Where-Object { Test-UnderPath $_.Exe $h.Home })
        $mitigation = New-Object System.Collections.Generic.List[string]
        foreach ($x in $envFlags) { $mitigation.Add($x) }
        foreach ($s in $svcHits) {
            foreach ($m in [regex]::Matches($s.Args, $flagPattern)) { $mitigation.Add("$($m.Value) (service $($s.Name))") }
        }
        foreach ($p in $procHits) {
            foreach ($m in [regex]::Matches($p.Args, $flagPattern)) { $mitigation.Add("$($m.Value) (process $($p.Id) $($p.Name))") }
        }

        [pscustomobject]@{
            RecordType         = 'Runtime'
            ComputerName       = $env:COMPUTERNAME
            JavaHome           = $h.Home
            Files              = (@($h.Files | ForEach-Object { if (Test-UnderPath $_ $h.Home) { $_.Substring($h.Home.Length).TrimStart('\') } else { $_ } } | Sort-Object) -join ', ')
            FoundBy            = (@($h.FoundBy | Sort-Object) -join ', ')
            JavaVersion        = [string]$rel['JAVA_VERSION']
            RuntimeVersion     = [string]$rel['JAVA_RUNTIME_VERSION']
            Implementor        = [string]$rel['IMPLEMENTOR']
            ImplementorVersion = [string]$rel['IMPLEMENTOR_VERSION']
            GraalVersion       = [string]$rel['GRAALVM_VERSION']
            JvmVariant         = [string]$rel['JVM_VARIANT']
            BuildType          = [string]$rel['BUILD_TYPE']
            OsArch             = [string]$rel['OS_ARCH']
            PeArch             = $peArch
            FileVersion        = $fileVersion
            FileCompany        = $fileCompany
            FileProduct        = $fileProduct
            RegisteredAs       = ($registered -join '; ')
            RunningProcesses   = $procHits.Count
            Services           = (@($svcHits | ForEach-Object { $_.Name } | Sort-Object -Unique) -join ', ')
            Mitigation         = (@($mitigation | Select-Object -Unique) -join '; ')
            ReadNote           = ($note -join '; ')
        }
    }

    # Final status record: its arrival marks the target as answered.
    [pscustomobject]@{
        RecordType      = 'Status'
        ComputerName    = $env:COMPUTERNAME
        OperatingSystem = $os
        CpuArch         = $cpu.Arch
        CpuName         = $cpu.Name
        CpuAvx512Vbmi   = $cpu.Vbmi
        Complete        = ($SkipDiskWalk -or ($rootsScanned -gt 0))
        FoldersScanned  = $state.Dirs
        FoldersDenied   = $state.Denied
        DeniedSample    = @($state.DeniedSample)
        Notes           = @($state.Notes)
    }
}

# -------------------------------------------------------------------------
# Helper functions (main body)
# -------------------------------------------------------------------------

function ConvertTo-Ascii {
    param([string]$Text)
    if (-not $Text) { return $Text }
    # Fold accents (a-ring -> a), replace anything else non-ASCII with '?'.
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $Text.Normalize([Text.NormalizationForm]::FormD).ToCharArray()) {
        if ([Globalization.CharUnicodeInfo]::GetUnicodeCategory($c) -eq 'NonSpacingMark') { continue }
        if ([int]$c -lt 128) { [void]$sb.Append($c) } else { [void]$sb.Append('?') }
    }
    $sb.ToString()
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [string]$Level = 'INFO'
    )
    Write-Host ('{0} [{1,-5}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, (ConvertTo-Ascii $Message))
}

function Stop-RunTranscript {
    # PS 7 Stop-Transcript honours -WhatIf (PS 5.1 has no such parameter).
    $p = @{}
    if ((Get-Command Stop-Transcript).Parameters.ContainsKey('WhatIf')) { $p['WhatIf'] = $false }
    Stop-Transcript @p | Out-Null
}

function New-ReportBaseName {
    # Reserves <Prefix>.csv (or <Prefix>-1.csv, -2 ...) with CreateNew, which
    # fails if the file exists: concurrent runs into one folder never share a name.
    param([string]$Folder, [string]$Prefix)
    for ($n = 0; $n -lt 1000; $n++) {
        $name = if ($n -eq 0) { $Prefix } else { "$Prefix-$n" }
        $csv  = Join-Path $Folder "$name.csv"
        if ([IO.File]::Exists($csv) -or [IO.File]::Exists((Join-Path $Folder "$name.log")) -or
            [IO.File]::Exists((Join-Path $Folder "$name-hosts.csv"))) { continue }
        try {
            [IO.File]::Open($csv, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write).Dispose()
            return $name
        }
        catch [System.IO.IOException] {
            # Taken by a concurrent run between the check and the create.
        }
    }
    throw "No free report name for '$Prefix' in $Folder"
}

function ConvertTo-VersionParts {
    # '1.8.0_511' -> 8,0,511,0; '17.0.21.1' -> 17,0,21,1; '21' -> 21,0,0,0.
    # Suffixes (+7, -ea, -b33) are ignored. $null when no number is found.
    param([string]$Text)
    if (-not $Text) { return $null }
    $t = $Text.Trim()
    $m = [regex]::Match($t, '^1\.(\d+)\.\d+(?:_(\d+))?')
    if ($m.Success) {
        $upd = 0
        if ($m.Groups[2].Success) { $upd = [int]$m.Groups[2].Value }
        return , @([int]$m.Groups[1].Value, 0, $upd, 0)
    }
    $m = [regex]::Match($t, '^(\d+)((?:\.\d+)*)')
    if ((-not $m.Success) -or ([int]$m.Groups[1].Value -lt 1)) { return $null }
    $parts = @([int]$m.Groups[1].Value)
    foreach ($p in ($m.Groups[2].Value -split '\.' | Where-Object { $_ })) { $parts += [int]$p }
    while ($parts.Count -lt 4) { $parts += 0 }
    , $parts
}

function ConvertFrom-FileVersion {
    # jvm.dll ProductVersion: '8.0.5110.33' (update x10) or '17.0.10.0'.
    param([string]$Text)
    $m = [regex]::Match([string]$Text, '^\s*(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?')
    if (-not $m.Success) { return $null }
    $major = [int]$m.Groups[1].Value
    if ($major -lt 1) { return $null }  # 0.0.0.0: no real version resource
    if ($major -le 8) { return , @($major, 0, [int][math]::Floor([int]$m.Groups[3].Value / 10), 0) }
    $rev = 0
    if ($m.Groups[4].Success) { $rev = [int]$m.Groups[4].Value }
    , @($major, [int]$m.Groups[2].Value, [int]$m.Groups[3].Value, $rev)
}

function Compare-VersionParts {
    # -1 / 0 / 1; missing parts count as 0.
    param([int[]]$A, [int[]]$B)
    $len = [math]::Max($A.Count, $B.Count)
    for ($i = 0; $i -lt $len; $i++) {
        $x = 0; $y = 0
        if ($i -lt $A.Count) { $x = $A[$i] }
        if ($i -lt $B.Count) { $y = $B[$i] }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    0
}

function Get-ArchName {
    param([string]$OsArch, [string]$PeArch)
    switch -Regex ($OsArch) {
        '^(?i)(amd64|x86_64|x64)$'     { return 'x86_64' }
        '^(?i)(i[3-6]86|x86)$'         { return 'x86' }
        '^(?i)(aarch64|arm64)$'        { return 'aarch64' }
    }
    $PeArch
}

function Get-RuntimeResult {
    # Classifies one Runtime record from the scan block into a CSV row.
    param($Rec, [string]$CpuVbmi)

    $notes = New-Object System.Collections.Generic.List[string]
    if ($Rec.ReadNote) { $notes.Add($Rec.ReadNote) }

    $versionText = $Rec.JavaVersion
    $parts = ConvertTo-VersionParts $Rec.JavaVersion
    if (-not $parts) {
        $parts = ConvertTo-VersionParts $Rec.RuntimeVersion
        $versionText = $Rec.RuntimeVersion
    }
    if (-not $parts -and $Rec.FileVersion) {
        $parts = ConvertFrom-FileVersion $Rec.FileVersion
        $versionText = $Rec.FileVersion
        if ($parts) { $notes.Add('no release file; version from jvm.dll resource') }
    }

    $vendor = $Rec.Implementor
    if (-not $vendor -and $Rec.FileCompany -and ($Rec.FileCompany -ne 'N/A')) { $vendor = $Rec.FileCompany }
    if ($Rec.ImplementorVersion) { $vendor = ('{0} ({1})' -f $vendor, $Rec.ImplementorVersion).Trim() }

    $arch = Get-ArchName $Rec.OsArch $Rec.PeArch
    $row = [ordered]@{
        ComputerName     = $Rec.ComputerName
        Status           = 'WARN'
        JavaHome         = $Rec.JavaHome
        Vendor           = $vendor
        JavaVersion      = $versionText
        Feature          = ''
        Arch             = $arch
        FixedIn          = ''
        Action           = 'check by hand'
        CpuAvx512Vbmi    = $CpuVbmi
        Mitigation       = $Rec.Mitigation
        RunningProcesses = $Rec.RunningProcesses
        Services         = $Rec.Services
        RegisteredAs     = $Rec.RegisteredAs
        FoundBy          = $Rec.FoundBy
        Files            = $Rec.Files
        Note             = ''
    }

    if (-not $parts) {
        $notes.Insert(0, 'version could not be read')
        $row.Note = $notes -join '; '
        return [pscustomobject]$row
    }

    $feature = $parts[0]
    $row.Feature = $feature
    $allText = @($Rec.Implementor, $Rec.JavaVersion, $Rec.RuntimeVersion, $Rec.ImplementorVersion, $Rec.BuildType, $Rec.FileProduct, $Rec.FileVersion) -join ' '
    $patchText = "update to a fixed build; until then consider -XX:-UseBASE64Intrinsics"

    # GraalVM EE 21.3 is listed without a base JDK, so it is checked before
    # the feature-version gates (its base can be Java 8, 11 or 17).
    $graal = [regex]::Match([string]$Rec.GraalVersion, '^21\.3\.')

    if ($graal.Success -and ($arch -ne 'aarch64')) {
        if (-not $arch) { $notes.Add('architecture unknown; treated as x86-64') }
        if (-not $FixedOracle.ContainsKey($feature)) {
            $notes.Add("GraalVM Enterprise 21.3 on a Java $feature base; the advisory names no base JDK, so it is treated as affected")
        }
        $row.FixedIn = "GraalVM Enterprise $FixedGraalEE"
        if ((Compare-VersionParts (ConvertTo-VersionParts $Rec.GraalVersion) (ConvertTo-VersionParts $FixedGraalEE)) -ge 0) {
            $row.Status = 'UNAFFECTED'; $row.Action = 'none'
        }
        else { $row.Status = 'NEEDS PATCH'; $row.Action = $patchText }
    }
    elseif ($feature -le 8) {
        if (($feature -eq 8) -and ($allText -match '(?i)perf')) {
            $row.FixedIn = "8u$FixedJava8PerfUpd-perf (Oracle Performance Pack)"
            if ($parts[2] -ge $FixedJava8PerfUpd) { $row.Status = 'UNAFFECTED'; $row.Action = 'none' }
            else { $row.Status = 'NEEDS PATCH'; $row.Action = "update to 8u$FixedJava8PerfUpd-perf or later" }
        }
        else {
            $row.Status = 'UNAFFECTED'; $row.Action = 'none'
            $notes.Insert(0, 'Java 8 and older not affected (only the Oracle 8 Performance Pack is listed)')
        }
    }
    elseif ($feature -le 16) {
        $row.Status = 'UNAFFECTED'; $row.Action = 'none'
        $notes.Insert(0, "Java $feature not listed by the advisory")
    }
    elseif (($feature -eq 17) -and ((Compare-VersionParts $parts (ConvertTo-VersionParts $AffectedFrom[17])) -lt 0)) {
        $row.Status = 'UNAFFECTED'; $row.Action = 'none'
        $notes.Insert(0, "before $($AffectedFrom[17]), which introduced the affected intrinsic")
    }
    elseif ($arch -eq 'aarch64') {
        $row.Status = 'UNAFFECTED'; $row.Action = 'none'
        $notes.Insert(0, 'ARM64 build; the flaw is in the x86-64 intrinsic')
    }
    elseif (($Rec.JvmVariant -match '(?i)openj9') -or ($allText -match '(?i)openj9|semeru')) {
        $row.Action = 'check with the vendor (IBM Semeru / OpenJ9)'
        $notes.Insert(0, 'OpenJ9 VM: the advisory covers HotSpot; not confirmed either way')
    }
    elseif (-not $FixedOracle.ContainsKey($feature)) {
        if ($feature -gt 27) { $notes.Insert(0, "Java $feature is newer than the advisory") }
        else { $notes.Insert(0, "Java $feature (non-LTS, end of life) is not covered by the advisory") }
        $row.Action = 'replace with a fixed LTS build (17.0.21.1, 21.0.13.1, 25.0.5.1 or later)'
    }
    elseif ($arch -eq 'x86') {
        $row.Action = 'replace with a fixed x86-64 build, or confirm with the vendor'
        $notes.Insert(0, '32-bit x86 build; the advisory names x86-64 only')
    }
    else {
        if (-not $arch) { $notes.Add('architecture unknown; treated as x86-64') }
        $corretto = [regex]::Match([string]$Rec.ImplementorVersion, '^(?i)Corretto-(\d+(?:\.\d+)+)')
        $zulu     = [regex]::Match([string]$Rec.ImplementorVersion, '^(?i)Zulu(\d+)\.(\d+)\+(\d+)')
        $fixed = $false
        if ($corretto.Success) {
            $row.FixedIn = "Corretto $($FixedCorretto[$feature])"
            $fixed = (Compare-VersionParts (ConvertTo-VersionParts $corretto.Groups[1].Value) (ConvertTo-VersionParts $FixedCorretto[$feature])) -ge 0
        }
        elseif ($zulu.Success) {
            $row.FixedIn = "Zulu $($FixedZulu[$feature])"
            $zp = @([int]$zulu.Groups[1].Value, [int]$zulu.Groups[2].Value, [int]$zulu.Groups[3].Value)
            $fixed = (Compare-VersionParts $zp (ConvertTo-VersionParts $FixedZulu[$feature])) -ge 0
        }
        else {
            $row.FixedIn = $FixedOracle[$feature]
            $fixed = (Compare-VersionParts $parts (ConvertTo-VersionParts $FixedOracle[$feature])) -ge 0
            if (-not $fixed -and ($Rec.Implementor -notmatch '(?i)oracle')) {
                $notes.Add("no fixed build confirmed for this vendor on $AdvisoryDate; fixed once it reaches Java $($FixedOracle[$feature])")
            }
        }
        if ($fixed) { $row.Status = 'UNAFFECTED'; $row.Action = 'none' }
        else { $row.Status = 'NEEDS PATCH'; $row.Action = $patchText }
    }

    $row.Note = $notes -join '; '
    [pscustomobject]$row
}

# -------------------------------------------------------------------------
# Begin script body
# -------------------------------------------------------------------------

Write-Verbose "Starting $($MyInvocation.MyCommand.Name)"

$exitCode          = 3
$transcriptStarted = $false
$csvPath           = $null
$hostsCsvPath      = $null
$csvEncoding       = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
$results           = New-Object System.Collections.Generic.List[object]
$hostRows          = New-Object System.Collections.Generic.List[object]

try {
    # --- Logging ------------------------------------------------------------
    # Logs and reports are evidence, not state changes: -WhatIf:$false.
    if (-not $LogPath) { $LogPath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path } }
    if (-not (Test-Path -LiteralPath $LogPath -PathType Container)) {
        New-Item -ItemType Directory -Path $LogPath -Force -WhatIf:$false -Confirm:$false -ErrorAction Stop | Out-Null
    }
    $scriptName   = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    $baseName     = New-ReportBaseName -Folder $LogPath -Prefix ('{0}-{1}-{2}' -f $scriptName, $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
    $csvPath      = Join-Path $LogPath "$baseName.csv"
    $hostsCsvPath = Join-Path $LogPath "$baseName-hosts.csv"
    Start-Transcript -LiteralPath (Join-Path $LogPath "$baseName.log") -NoClobber -WhatIf:$false -Confirm:$false -ErrorAction Stop | Out-Null
    $transcriptStarted = $true
    Write-Log "Scan-Java4Shell $ScriptVersion (CVE-2026-114938, fixed-build table $AdvisoryDate) on $env:COMPUTERNAME as $([Environment]::UserDomainName)\$([Environment]::UserName)"
    if ($WhatIfPreference) { Write-Log 'Read-only scan: -WhatIf has no effect; the reports and log are still written.' }

    # --- Input validation ---------------------------------------------------
    # powershell.exe -File passes "A,B" as one string; host names never hold commas.
    $ComputerName = @($ComputerName | ForEach-Object { ([string]$_) -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $Path         = @($Path | Where-Object { $_ })
    $ExcludePath  = @($ExcludePath | Where-Object { $_ })
    if (($ThrottleLimit -lt 1) -or ($ThrottleLimit -gt 256)) { throw "ThrottleLimit must be 1-256, got $ThrottleLimit" }
    if ($SkipDiskWalk -and $SkipReferences) { throw '-SkipDiskWalk and -SkipReferences together leave nothing to scan' }
    if (($ComputerName.Count -gt 0) -and $SearchBase) { throw 'Use either -ComputerName or -SearchBase, not both' }

    # --- Resolve targets ----------------------------------------------------
    $targets = New-Object System.Collections.Generic.List[string]
    $seen    = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $adOs    = @{}
    if ($ComputerName.Count -gt 0) {
        foreach ($n in $ComputerName) { if ($seen.Add($n)) { $targets.Add($n) } }
    }
    else {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw 'The ActiveDirectory module is not available. Install RSAT (AD DS tools) or pass -ComputerName.'
        }
        Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
        $adParams = @{
            Filter     = "Enabled -eq 'True' -and OperatingSystem -like '*Windows Server*'"
            Properties = @('DNSHostName', 'OperatingSystem')
        }
        if ($SearchBase) { $adParams.SearchBase = $SearchBase }
        if ($Credential) { $adParams.Credential = $Credential }
        $adComputers = @(Get-ADComputer @adParams | Where-Object { $_.DNSHostName } | Sort-Object DNSHostName)
        foreach ($c in $adComputers) {
            if ($seen.Add($c.DNSHostName)) {
                $targets.Add($c.DNSHostName)
                $adOs[$c.DNSHostName] = [string]$c.OperatingSystem
            }
        }
        Write-Log ("Active Directory: {0} enabled Windows Server computer(s){1}" -f $targets.Count, $(if ($SearchBase) { " below $SearchBase" } else { '' }))
    }

    # Names that mean "this computer" are scanned in-process, never over WinRM.
    $localNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @('localhost', '.', '127.0.0.1', '::1', $env:COMPUTERNAME)) { [void]$localNames.Add($n) }
    $dnsDomain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
    if ($dnsDomain) { [void]$localNames.Add("$env:COMPUTERNAME.$dnsDomain") }
    $localTargets  = @($targets | Where-Object { $localNames.Contains($_) })
    $remoteTargets = @($targets | Where-Object { -not $localNames.Contains($_) })

    if ($targets.Count -eq 0) {
        Write-Log 'No targets in scope: nothing was scanned.' 'WARN'
    }
    else {
        Write-Log ("Targets: {0} ({1} local, {2} remote, throttle {3})" -f $targets.Count, [math]::Min(1, $localTargets.Count), $remoteTargets.Count, $ThrottleLimit)
    }
    if ($Path.Count -gt 0)  { Write-Log "Walk limited to: $($Path -join ', ')" }
    if ($SkipDiskWalk)      { Write-Log 'Disk walk skipped: registry, environment, services and processes only.' }
    if ($SkipReferences)    { Write-Log 'References skipped: disk walk only.' }

    # --- Scan -----------------------------------------------------------------
    $scanArgs = @($Path, $ExcludePath, $SystemExcludes, [bool]$SkipDiskWalk, [bool]$SkipReferences)
    $records  = New-Object System.Collections.Generic.List[object]
    $errorsByTarget = @{}

    if ($localTargets.Count -gt 0) {
        Write-Log "Scanning this computer ($($localTargets -join ', '))"
        $localArgs = $scanArgs + @($true)
        foreach ($rec in @(& $ScanBlock @localArgs)) {
            $rec | Add-Member -NotePropertyName Target -NotePropertyValue $localTargets[0] -Force
            $records.Add($rec)
        }
    }
    if ($remoteTargets.Count -gt 0) {
        Write-Log "Scanning $($remoteTargets.Count) remote target(s) over WinRM"
        $remoteErrors = $null
        $icmParams = @{
            ComputerName  = $remoteTargets
            ScriptBlock   = $ScanBlock
            ArgumentList  = $scanArgs + @($false)
            ThrottleLimit = $ThrottleLimit
            ErrorAction   = 'SilentlyContinue'
            ErrorVariable = 'remoteErrors'
        }
        if ($Credential) { $icmParams.Credential = $Credential }
        foreach ($rec in @(Invoke-Command @icmParams)) {
            $rec | Add-Member -NotePropertyName Target -NotePropertyValue ([string]$rec.PSComputerName) -Force
            $records.Add($rec)
        }
        foreach ($err in @($remoteErrors)) {
            if (-not $err) { continue }
            $t = ''
            if ($err.TargetObject -is [string]) { $t = $err.TargetObject }
            elseif ($err.OriginInfo) { $t = [string]$err.OriginInfo.PSComputerName }
            $msg = ($err.Exception.Message -split "`r?`n")[0]
            if ($t) { $errorsByTarget[$t] = $msg }
            Write-Log ("Remote error{0}: {1}" -f $(if ($t) { " ($t)" } else { '' }), $msg) 'WARN'
        }
    }

    # --- Classify and summarize per target ------------------------------------
    $statusByTarget = @{}
    foreach ($s in @($records | Where-Object { $_.RecordType -eq 'Status' })) { $statusByTarget[[string]$s.Target] = $s }

    $scanned = 0; $notScanned = 0
    foreach ($t in $targets) {
        if ($localNames.Contains($t) -and ($t -ne $localTargets[0])) { continue }  # scanned once as the first local name
        $s = $statusByTarget[$t]
        $hostRow = [ordered]@{
            Target = $t; ComputerName = ''; ScanStatus = 'Not scanned'; OperatingSystem = [string]$adOs[$t]
            Runtimes = 0; NeedsPatch = 0; Warn = 0; CpuArch = ''; CpuName = ''; CpuAvx512Vbmi = ''
            FoldersScanned = 0; FoldersDenied = 0; Note = ''
        }
        if (-not $s) {
            $hostRow.ScanStatus = 'Unreachable'
            $hostRow.Note = if ($errorsByTarget.ContainsKey($t)) { $errorsByTarget[$t] } else { 'no status record returned' }
            $notScanned++
            Write-Log "$t : not scanned ($($hostRow.Note))" 'WARN'
            $hostRows.Add([pscustomobject]$hostRow)
            continue
        }

        $rows = @($records |
            Where-Object { ($_.RecordType -eq 'Runtime') -and ([string]$_.Target -eq $t) } |
            ForEach-Object { Get-RuntimeResult -Rec $_ -CpuVbmi $s.CpuAvx512Vbmi } |
            Sort-Object @{ Expression = { $StatusOrder[$_.Status] } }, JavaHome)
        foreach ($r in $rows) { $results.Add($r) }

        $hostRow.ComputerName    = $s.ComputerName
        if ($s.OperatingSystem) { $hostRow.OperatingSystem = $s.OperatingSystem }
        $hostRow.Runtimes        = $rows.Count
        $hostRow.NeedsPatch      = @($rows | Where-Object { $_.Status -eq 'NEEDS PATCH' }).Count
        $hostRow.Warn            = @($rows | Where-Object { $_.Status -eq 'WARN' }).Count
        $hostRow.CpuArch         = $s.CpuArch
        $hostRow.CpuName         = $s.CpuName
        $hostRow.CpuAvx512Vbmi   = $s.CpuAvx512Vbmi
        $hostRow.FoldersScanned  = $s.FoldersScanned
        $hostRow.FoldersDenied   = $s.FoldersDenied
        $hostRow.Note            = (@($s.Notes) -join '; ')
        if ($s.Complete) { $hostRow.ScanStatus = 'Scanned'; $scanned++ }
        else { $hostRow.ScanStatus = 'Not scanned'; $notScanned++ }
        $hostRows.Add([pscustomobject]$hostRow)

        Write-Log ("{0} ({1}): {2}, {3} runtime(s), {4} NEEDS PATCH, {5} WARN, {6} folder(s), {7} unreadable, AVX-512 VBMI {8}" -f
            $t, $s.ComputerName, $hostRow.ScanStatus, $rows.Count, $hostRow.NeedsPatch, $hostRow.Warn,
            $s.FoldersScanned, $s.FoldersDenied, $s.CpuAvx512Vbmi)
        foreach ($n in @($s.Notes)) { Write-Log "  note: $n" }
        foreach ($d in @($s.DeniedSample)) { Write-Log "  unreadable: $d" }
        foreach ($r in $rows) {
            $line = "  {0,-11} {1} | {2} | {3}" -f $r.Status, $r.JavaHome, $r.JavaVersion, $r.Vendor
            if ($r.Status -ne 'UNAFFECTED') { $line += " | $($r.Action)" }
            if ($r.Mitigation) { $line += " | mitigation: $($r.Mitigation)" }
            if ($r.Note) { $line += " | $($r.Note)" }
            Write-Log $line $(if ($r.Status -eq 'UNAFFECTED') { 'INFO' } else { 'WARN' })
        }
    }

    # --- Exit code (highest wins) -----------------------------------------------
    $needsPatch = @($results | Where-Object { $_.Status -eq 'NEEDS PATCH' }).Count
    $warn       = @($results | Where-Object { $_.Status -eq 'WARN' }).Count
    Write-Log ("Summary: {0} target(s) scanned, {1} not scanned; {2} runtime(s): {3} NEEDS PATCH, {4} WARN" -f
        $scanned, $notScanned, $results.Count, $needsPatch, $warn)
    if (($notScanned -gt 0) -or ($warn -gt 0) -or ($targets.Count -eq 0)) { $exitCode = 2 }
    elseif ($needsPatch -gt 0) { $exitCode = 1 }
    else { $exitCode = 0 }

    # Runtime report order: status, then CPU exposure, then unmitigated first.
    # Report only; the status itself never depends on CPU or mitigation.
    $sorted = @($results | Sort-Object `
        @{ Expression = { $StatusOrder[$_.Status] } },
        @{ Expression = { $v = $CpuOrder[[string]$_.CpuAvx512Vbmi]; if ($null -eq $v) { 2 } else { $v } } },
        @{ Expression = { if ($_.Mitigation) { 1 } else { 0 } } },
        ComputerName, JavaHome)
    $results.Clear()
    foreach ($r in $sorted) { $results.Add($r) }

    if ($PassThru) { $results | Select-Object -Property $RuntimeColumns }
}
catch {
    $exitCode = 3
    Write-Error $_ -ErrorAction Continue
    throw
}
finally {
    # Evidence files on every run, header-only when empty, also on errors.
    if ($csvPath) {
        try {
            $csvSet = @(
                @{ Path = $csvPath; Rows = $results; Columns = $RuntimeColumns },
                @{ Path = $hostsCsvPath; Rows = $hostRows; Columns = $HostColumns }
            )
            foreach ($c in $csvSet) {
                if ($c.Rows.Count -gt 0) {
                    $c.Rows | Select-Object -Property $c.Columns |
                        Export-Csv -LiteralPath $c.Path -NoTypeInformation -Encoding $csvEncoding -WhatIf:$false -Confirm:$false
                }
                else {
                    $header = ($c.Columns | ForEach-Object { '"' + $_ + '"' }) -join ','
                    Set-Content -LiteralPath $c.Path -Value $header -Encoding $csvEncoding -WhatIf:$false -Confirm:$false
                }
            }
            Write-Log "Report: $csvPath"
            Write-Log "Hosts:  $hostsCsvPath"
        }
        catch {
            $exitCode = 3
            Write-Log "Could not write reports: $($_.Exception.Message)" 'ERROR'
        }
    }
    Write-Log "Exit code: $exitCode"
    if ($transcriptStarted) { Stop-RunTranscript }
    Write-Verbose "Finished $($MyInvocation.MyCommand.Name)"
    # exit in finally overrides the rethrow's exit 1 (verified PS 5.1 and 7)
    exit $exitCode
}
