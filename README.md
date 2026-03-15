# EyeStorm

User-mode host-based intrusion detection system for Windows 10/11, written in pure C with no external dependencies.

EyeStorm captures cryptographically-verified system snapshots and diffs them to surface changes indicative of compromise. Its central design problem is anti-spoofing: sophisticated malware hooks Windows enumeration APIs to hide itself from conventional tools. EyeStorm defeats this by querying three independent subsystems simultaneously and flagging discrepancies as rootkit indicators.

---

## What it monitors

- Running processes (path, parent, command line, SHA-256, username, creation time)
- Loaded modules per process
- TCP/UDP network connections with owning PID
- Windows services and their binary paths
- Registry auto-run keys (HKLM + HKCU Run/RunOnce)
- Scheduled tasks (full folder tree, not just root)

---

## Anti-spoofing mechanism

Process enumeration runs across three independent APIs:

| Source | API |
|--------|-----|
| Toolhelp32 | `CreateToolhelp32Snapshot` |
| PSAPI | `EnumProcesses` |
| WMI | `Win32_Process` via COM |

A process visible to PSAPI or WMI but absent from Toolhelp32 is flagged as a hidden PID -- a strong indicator of user-mode API hooking. Two consecutive byte-identical snapshots on a live system are flagged as evidence of a kernel-mode driver returning fabricated enumeration data.

---

## Process legitimacy auditing

Each process is independently checked across four layers:

1. **Authenticode signature** -- WinVerifyTrust offline verification
2. **Path legitimacy** -- must reside in a known-good system directory
3. **Parent-process rules** -- PPID must match known Windows process tree relationships (e.g. svchost.exe must descend from services.exe)
4. **Name spoofing** -- system process name running from wrong path, digit-suffix variants (svchost1.exe), trailing whitespace

Singleton violations (multiple instances of lsass.exe, smss.exe etc.) are also detected.

---

## Snapshot integrity

Every snapshot is SHA-256 hashed over its full payload. Loading a modified .bin file fails with a tamper alert. Sequence numbers are Unix timestamps, making snapshots self-describing and sortable without an external index.

---

## Build

Requires Visual Studio 2019/2022 (or MinGW). From a Developer Command Prompt:

```
build.bat
```

The script auto-detects cl.exe or gcc and links all required Windows libraries. A `Directory.Build.props` file is included for Visual Studio IDE builds -- drop it next to your .vcxproj and the IDE picks up all preprocessor defines and linker dependencies automatically.

---

## Usage

All commands require Administrator privileges.

```
eyestorm.exe whitelist                        prepare AV/EDR exclusion before first run
eyestorm.exe snapshot  baseline.bin           capture system state
eyestorm.exe snapshot  after.bin              capture again
eyestorm.exe compare   baseline.bin after.bin full diff
eyestorm.exe compare   baseline.bin after.bin --crit   critical changes only
eyestorm.exe watch     60 snapshots\          continuous monitoring, 60s interval
eyestorm.exe audit     baseline.bin           legitimacy flags only
eyestorm.exe procs     baseline.bin           process list with all flags
eyestorm.exe net       baseline.bin           network connections
eyestorm.exe tasks     baseline.bin           scheduled tasks with signatures
eyestorm.exe verify    baseline.bin           verify snapshot file integrity
```

Run `whitelist` first. The combination of SeDebugPrivilege, NtQueryInformationProcess, and WinVerifyTrust called across all running processes matches the behavioural signature of credential-dumping tools. Windows Defender will quarantine the binary before the first snapshot completes without an exclusion.

---

## Limitations

EyeStorm operates entirely in user space. A kernel-mode rootkit using DKOM (Direct Kernel Object Manipulation) can hide processes from all three enumeration sources simultaneously. For that threat tier, a kernel driver component is required. All other detections function correctly against user-mode and service-layer threats.

---

## Dependencies

None. All functionality uses APIs and COM interfaces present in every Windows 10/11 installation: Win32, NTDLL, CNG (bcrypt.dll), WMI, Task Scheduler, and IP Helper.
