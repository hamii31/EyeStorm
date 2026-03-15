/*
 * sysmon.h  --  Windows System Monitor / Snapshot Engine
 *
 * A host-based intrusion detection aid that:
 *   * captures full system snapshots (processes, modules, network, services,
 *     registry auto-run keys, scheduled tasks)
 *   * cross-validates process lists from three independent APIs to detect
 *     API-hooking malware feeding phony data
 *   * diffs consecutive snapshots to surface changes
 *   * verifies digital signatures and parent-process legitimacy
 *
 * Targets: Windows 10 / 11  (MSVC or MinGW, x64)
 * Build:   see build.bat
 */

#ifndef SYSMON_H
#define SYSMON_H

 /* -- MSVC CRT deprecation suppression ---------------------------------------
  * MSVC marks strncpy, fopen, sprintf, sscanf and other ISO C functions as
  * "deprecated" (C4996) and promotes _s variants.  All CRT calls in this
  * project are already written with explicit null-termination and bounded
  * sizes, so the _s variants add no safety benefit here.
  *
  * _CRT_SECURE_NO_WARNINGS   -- suppresses C4996 on strncpy, fopen, etc.
  * _CRT_NONSTDC_NO_WARNINGS  -- suppresses C4996 on POSIX names (_snprintf)
  *
  * These MUST be defined before the first CRT header inclusion.
  * They are also passed as /D flags in build.bat for command-line builds.
  * For VS IDE builds: Project ? Properties ? C/C++ ? Preprocessor ?
  *   add _CRT_SECURE_NO_WARNINGS;_CRT_NONSTDC_NO_WARNINGS
  * --------------------------------------------------------------------------- */
#ifndef _CRT_SECURE_NO_WARNINGS
#  define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _CRT_NONSTDC_NO_WARNINGS
#  define _CRT_NONSTDC_NO_WARNINGS
#endif

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00   /* Windows 10 */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <ntsecapi.h>
#include <wbemidl.h>
#include <taskschd.h>
#include <WinSock2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

  /* -- limits ------------------------------------------------------------------
   * Sized to realistic Windows 10/11 ceilings, not theoretical maxima.
   * Typical live system: ~200-350 processes, ~150 connections, ~400 services.
   * These values give comfortable headroom while keeping each SystemSnapshot
   * at ~3.4 MB rather than ~10.8 MB.
   * --------------------------------------------------------------------------- */
#define MAX_PROCESSES       1024   /* was 4096 -- typical peak ~350             */
#define MAX_MODULE_ENTRIES  1024   /* total loaded modules across all procs    */
#define MAX_CONNECTIONS     512    /* was 2048                                  */
#define MAX_SERVICES        512    /* was 1024                                  */
#define MAX_REGKEYS         128    /* was 256                                   */
#define MAX_TASKS           256    /* was 512                                   */
#define MAX_PATH_EXTENDED   32767
#define SHA256_LEN          32
#define SNAPSHOT_MAGIC      0x534E4150UL   /* "SNAP" */
#define SNAPSHOT_VERSION    3              /* bumped: struct layout changed     */

   /* -- WMI enumeration timeout ----------------------------------------------- */
#define WMI_TIMEOUT_MS      5000   /* 5 s -- abandon WMI PID source if stuck   */

/* -- known-good system directories (lowercase) ----------------------------- */
static const char* LEGIT_DIRS[] = {
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    /* Windows 11: drivers and OEM components live under DriverStore         */
    "c:\\windows\\system32\\driverstore\\",
    /* Windows 11: UWP / inbox apps live under SystemApps and WindowsApps   */
    "c:\\windows\\systemapps\\",
    "c:\\program files\\windowsapps\\",
    NULL
};

/* -- known-good parent ? child relationships ------------------------------
 * Rules reflect observed Windows 10/11 process tree patterns.
 * A '*' child means the parent may spawn any child (e.g. task scheduler).
 * A '*' parent means the child may come from any parent.
 * Only children that appear in at least one rule are checked -- unlisted
 * children are implicitly allowed from any parent.
 * --------------------------------------------------------------------------- */
typedef struct { const char* parent; const char* child; } ParentChildRule;
static const ParentChildRule PPID_RULES[] = {
    /* Core boot chain */
    { "smss.exe",           "wininit.exe"              },
    { "smss.exe",           "csrss.exe"                },
    { "smss.exe",           "smss.exe"                 }, /* session clone */
    { "wininit.exe",        "services.exe"             },
    { "wininit.exe",        "lsass.exe"                },
    { "wininit.exe",        "lsaiso.exe"               }, /* Credential Guard */
    { "wininit.exe",        "lsm.exe"                  },
    { "wininit.exe",        "fontdrvhost.exe"          }, /* font driver host */

    /* Session / logon */
    { "smss.exe",           "winlogon.exe"             },
    { "winlogon.exe",       "userinit.exe"             },
    { "winlogon.exe",       "dwm.exe"                  },
    { "winlogon.exe",       "fontdrvhost.exe"          },
    { "winlogon.exe",       "mpnotify.exe"             },
    { "userinit.exe",       "explorer.exe"             },

    /* Services spawning svchost and service binaries */
    { "services.exe",       "svchost.exe"              },
    { "services.exe",       "dllhost.exe"              },
    { "services.exe",       "spoolsv.exe"              },
    { "services.exe",       "msiexec.exe"              },
    { "services.exe",       "*"                        }, /* services spawns all service hosts */

    /* svchost spawning common children (Windows 10/11) */
    { "svchost.exe",        "runtimebroker.exe"        },
    { "svchost.exe",        "searchindexer.exe"        },
    { "svchost.exe",        "dllhost.exe"              },
    { "svchost.exe",        "wmiapsrv.exe"             },
    { "svchost.exe",        "wmiprvse.exe"             },
    { "svchost.exe",        "audiodg.exe"              },
    { "svchost.exe",        "wlanext.exe"              },
    { "svchost.exe",        "dashost.exe"              },
    { "svchost.exe",        "taskhostw.exe"            },
    { "svchost.exe",        "backgroundtaskhost.exe"   },
    { "svchost.exe",        "applicationframehost.exe" },
    { "svchost.exe",        "smartscreen.exe"          },
    { "svchost.exe",        "lockapp.exe"              },
    { "svchost.exe",        "searchhost.exe"           },
    { "svchost.exe",        "shellexperiencehost.exe"  },
    { "svchost.exe",        "startmenuexperiencehost.exe"},
    { "svchost.exe",        "sihost.exe"               },
    { "svchost.exe",        "ctfmon.exe"               },
    { "svchost.exe",        "wudfdrvhost.exe"          },
    { "svchost.exe",        "wudfhost.exe"             },
    { "svchost.exe",        "ngciso.exe"               },
    { "svchost.exe",        "aggregatorhost.exe"       },
    { "svchost.exe",        "useroobebroker.exe"       },
    { "svchost.exe",        "widgetboard.exe"          },
    { "svchost.exe",        "widgetservice.exe"        },
    { "svchost.exe",        "microsoftstartfeedprovider.exe" },
    { "svchost.exe",        "securityhealthservice.exe"},
    { "svchost.exe",        "*"                        }, /* svchost is a general host */

    /* Explorer spawning user apps */
    { "explorer.exe",       "cmd.exe"                  },
    { "explorer.exe",       "powershell.exe"           },
    { "explorer.exe",       "msiexec.exe"              },
    { "explorer.exe",       "*"                        }, /* explorer launches user apps */

    /* Task scheduler */
    { "taskeng.exe",        "*"                        },
    { "taskhostw.exe",      "*"                        },
    { "svchost.exe",        "taskeng.exe"              },

    /* WMI */
    { "svchost.exe",        "wmiprvse.exe"             },
    { "wmiprvse.exe",       "*"                        },

    /* System (PID 4) spawns kernel-mode helpers */
    { "system",             "*"                        },

    /* conhost.exe -- console host, can be spawned by almost any process */
    { "*",                  "conhost.exe"              },

    /* Multi-process applications that self-spawn (parent == child) */
    { "firefox.exe",        "firefox.exe"              },
    { "firefox.exe",        "crashhelper.exe"          },
    { "msedgewebview2.exe", "msedgewebview2.exe"       },
    { "msedge.exe",         "msedge.exe"               },
    { "chrome.exe",         "chrome.exe"               },
    { "steamwebhelper.exe", "steamwebhelper.exe"       },
    { "steam.exe",          "steamwebhelper.exe"       },
    { "nvcontainer.exe",    "nvcontainer.exe"          },
    /* SearchHost spawns Edge WebView for Windows Search UI */
    { "searchhost.exe",     "*"                        },

    /* NVDisplay container self-spawns */
    { "nvdisplay.container.exe", "nvdisplay.container.exe" },
    { "razorappengine.exe", "razorappengine.exe"       },
    { "razerappengine.exe", "razerappengine.exe"       },

    /* Razer SDK service spawning its device manager sub-processes */
    { "rzsdkservice.exe",   "*"                        },
    { "razerappengine.exe", "*"                        },

    /* SearchIndexer spawning protocol/filter hosts */
    { "searchindexer.exe",  "searchprotocolhost.exe"   },
    { "searchindexer.exe",  "searchfilterhost.exe"     },

    /* Visual Studio and dev tools */
    { "devenv.exe",         "*"                        },
    { "vshost.exe",         "*"                        },
    { "msbuild.exe",        "*"                        },

    /* NahimicService spawning APO volume helper */
    { "nahimicservice.exe", "*"                        },

    /* ipf_uf.exe spawning its helper */
    { "ipf_uf.exe",         "*"                        },

    /* sihost.exe spawning shell components */
    { "sihost.exe",         "*"                        },

    /* Apps spawning from AppData (Ollama, user-installed tools) */
    { "ollama app.exe",     "*"                        },
    { "ollama.exe",         "*"                        },

    { NULL, NULL }
};

/* -- single-instance system processes ---------------------------------------
 * csrss.exe is intentionally excluded: Windows runs one per session,
 * so Session 0 + Session 1 = 2 instances is completely normal.           */
static const char* SINGLETON_PROCS[] = {
    "lsass.exe", "lsm.exe", "wininit.exe", "smss.exe",
    "services.exe", NULL
};

/* -- SHA-256 context (simple WINAPI CNG wrapper) --------------------------- */
typedef struct {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_HASH_HANDLE hHash;
    BYTE              buf[512];
} Sha256Ctx;

/* -- process entry --------------------------------------------------------- */
typedef struct {
    DWORD    pid;
    DWORD    ppid;
    char     name[MAX_PATH];
    char     path[MAX_PATH];
    char     cmdline[1024];
    char     username[256];
    BYTE     exe_hash[SHA256_LEN];       /* SHA-256 of the on-disk binary    */
    BOOL     hash_ok;
    BOOL     signature_valid;
    BOOL     signature_present;
    BOOL     path_legit;                 /* lives in a known-good directory   */
    BOOL     ppid_legit;                 /* parent matches known rules        */
    BOOL     singleton_violation;        /* >1 instance of a singleton proc   */
    BOOL     name_spoof;                 /* name looks like a system proc     */
    FILETIME create_time;
} ProcessEntry;

/* -- loaded module entry --------------------------------------------------- */
typedef struct {
    DWORD pid;
    char  name[MAX_PATH];
    char  path[MAX_PATH];
    BYTE  hash[SHA256_LEN];
    BOOL  hash_ok;
    BOOL  signature_valid;
} ModuleEntry;

/* -- TCP/UDP connection entry ---------------------------------------------- */
typedef enum { CONN_TCP4, CONN_TCP6, CONN_UDP4, CONN_UDP6 } ConnProto;
typedef struct {
    ConnProto proto;
    DWORD     pid;
    char      local_addr[64];
    USHORT    local_port;
    char      remote_addr[64];
    USHORT    remote_port;
    DWORD     state;             /* MIB_TCP_STATE_* */
} ConnEntry;

/* -- Windows service entry ------------------------------------------------- */
typedef struct {
    char  name[256];
    char  display[256];
    char  binary[MAX_PATH];
    DWORD type;
    DWORD start_type;
    DWORD state;
    BOOL  signature_valid;
} ServiceEntry;

/* -- registry auto-run entry ----------------------------------------------- */
typedef struct {
    char hive[16];      /* "HKLM" / "HKCU" */
    char subkey[512];
    char value_name[256];
    char value_data[MAX_PATH];
} RegRunEntry;

/* -- scheduled task entry -------------------------------------------------- */
typedef struct {
    char  name[256];
    char  path[256];
    char  action[MAX_PATH];
    char  author[256];
    BOOL  enabled;
    BOOL  signature_valid;
} TaskEntry;

/* -- cross-source PID list (anti-spoofing) --------------------------------- */
typedef struct {
    DWORD pids_toolhelp[MAX_PROCESSES];
    DWORD count_toolhelp;
    DWORD pids_psapi[MAX_PROCESSES];
    DWORD count_psapi;
    DWORD pids_wmi[MAX_PROCESSES];
    DWORD count_wmi;
    BOOL  wmi_timed_out;                  /* WMI source abandoned              */
    DWORD hidden_pids[MAX_PROCESSES];     /* in PSAPI/WMI but not Toolhelp     */
    DWORD hidden_count;
    DWORD phantom_pids[MAX_PROCESSES];    /* in Toolhelp but not PSAPI         */
    DWORD phantom_count;
} PidCrossCheck;

/* -- full system snapshot -------------------------------------------------- */
typedef struct {
    DWORD         magic;
    DWORD         version;
    SYSTEMTIME    captured_at;
    ULONGLONG     seq;                    /* monotonic counter                 */
    BYTE          self_hash[SHA256_LEN];  /* hash of this struct (integrity)   */

    ProcessEntry  procs[MAX_PROCESSES];
    DWORD         proc_count;

    ModuleEntry   modules[MAX_MODULE_ENTRIES];
    DWORD         module_count;

    ConnEntry     conns[MAX_CONNECTIONS];
    DWORD         conn_count;

    ServiceEntry  services[MAX_SERVICES];
    DWORD         svc_count;

    RegRunEntry   reg_runs[MAX_REGKEYS];
    DWORD         reg_count;

    TaskEntry     tasks[MAX_TASKS];
    DWORD         task_count;

    PidCrossCheck pid_check;
} SystemSnapshot;

/* -- WMI thread argument block (used by snapshot.c) ----------------------- */
typedef struct {
    SystemSnapshot* snap;
    BOOL            done;
    BOOL            succeeded;
} WmiThreadArgs;

/* -- diff result ----------------------------------------------------------- */
typedef enum {
    CHG_PROC_NEW = 1,
    CHG_PROC_GONE,
    CHG_PROC_HASH_CHANGED,
    CHG_PROC_PATH_CHANGED,
    CHG_CONN_NEW,
    CHG_CONN_GONE,
    CHG_SVC_NEW,
    CHG_SVC_GONE,
    CHG_SVC_BINARY_CHANGED,
    CHG_REG_NEW,
    CHG_REG_GONE,
    CHG_REG_DATA_CHANGED,
    CHG_TASK_NEW,
    CHG_TASK_GONE,
    CHG_TASK_ACTION_CHANGED,
    CHG_HIDDEN_PID,
    CHG_PHANTOM_PID,
    CHG_SNAPSHOT_IDENTICAL,   /* consecutive snapshots byte-identical -- suspicious */
} ChangeKind;

typedef struct {
    ChangeKind kind;
    DWORD      severity;       /* 1=info 2=warning 3=critical                */
    char       description[512];
} ChangeRecord;

typedef struct {
    ChangeRecord* records;
    DWORD         count;
    DWORD         capacity;
    BOOL          snapshots_identical;
} DiffResult;

/* -- alert severity -------------------------------------------------------- */
#define SEV_INFO     1
#define SEV_WARN     2
#define SEV_CRITICAL 3

/* -- function declarations ------------------------------------------------- */

/* snapshot.c */
BOOL  snapshot_capture(SystemSnapshot* out, ULONGLONG seq);
BOOL  snapshot_save(const SystemSnapshot* snap, const char* path);
BOOL  snapshot_load(SystemSnapshot* out, const char* path);
void  snapshot_print_summary(const SystemSnapshot* snap);
BOOL  snapshot_compute_self_hash(SystemSnapshot* snap);
BOOL  snapshot_verify_integrity(const SystemSnapshot* snap);

/* compare.c */
DiffResult* diff_snapshots(const SystemSnapshot* old_s,
    const SystemSnapshot* new_s);
void        diff_print(const DiffResult* diff, BOOL critical_only);
void        diff_free(DiffResult* diff);

/* legitimacy.c */
BOOL  legit_verify_signature(const char* path);
BOOL  legit_path_is_system(const char* path);
BOOL  legit_check_ppid(const char* child_name, const char* parent_name);
BOOL  legit_check_name_spoof(const char* name, const char* path);
void  legit_audit_process(ProcessEntry* pe, const SystemSnapshot* snap);
void  legit_audit_snapshot(SystemSnapshot* snap);

/* sha256.c */
BOOL  sha256_file(const char* path, BYTE out[SHA256_LEN]);
BOOL  sha256_buf(const BYTE* data, SIZE_T len, BYTE out[SHA256_LEN]);
void  sha256_to_hex(const BYTE in[SHA256_LEN], char out[65]);

/* util.c */
void  util_lower(char* s);
BOOL  util_pid_to_path(DWORD pid, char* out, DWORD out_size);
BOOL  util_pid_to_user(DWORD pid, char* out, DWORD out_size);
BOOL  util_pid_to_cmdline(DWORD pid, char* out, DWORD out_size);
void  util_filetime_to_str(const FILETIME* ft, char* out, DWORD out_size);
void  util_print_separator(void);
void  util_log(DWORD severity, const char* fmt, ...);

#endif /* SYSMON_H */
