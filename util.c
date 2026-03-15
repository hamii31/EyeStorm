/*
 * util.c  --  misc helpers
 */

#include "sysmon.h"
#include <stdarg.h>
#pragma comment(lib, "ntdll.lib")

 /* -- in-place ASCII lowercase ---------------------------------------------- */
void util_lower(char* s)
{
    for (; *s; s++)
        if (*s >= 'A' && *s <= 'Z') *s += 32;
}

/* -- resolve PID ? full executable path ----------------------------------- */
BOOL util_pid_to_path(DWORD pid, char* out, DWORD out_size)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return FALSE;
    DWORD sz = out_size;
    BOOL ok = QueryFullProcessImageNameA(h, 0, out, &sz);
    CloseHandle(h);
    return ok;
}

/* -- resolve PID ? owning username ---------------------------------------- */
BOOL util_pid_to_user(DWORD pid, char* out, DWORD out_size)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) { strncpy(out, "<access denied>", out_size); return FALSE; }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc);
        strncpy(out, "<no token>", out_size);
        return FALSE;
    }

    TOKEN_USER* pUser = NULL;
    DWORD needed = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &needed);
    pUser = (TOKEN_USER*)HeapAlloc(GetProcessHeap(), 0, needed);

    BOOL ok = FALSE;
    if (pUser && GetTokenInformation(hToken, TokenUser, pUser, needed, &needed)) {
        char   name[256] = { 0 }, domain[256] = { 0 };
        DWORD  nLen = 256, dLen = 256;
        SID_NAME_USE use;
        if (LookupAccountSidA(NULL, pUser->User.Sid,
            name, &nLen, domain, &dLen, &use)) {
            _snprintf(out, out_size, "%s\\%s", domain, name);
            ok = TRUE;
        }
    }
    if (!ok) strncpy(out, "<unknown>", out_size);

    if (pUser) HeapFree(GetProcessHeap(), 0, pUser);
    CloseHandle(hToken);
    CloseHandle(hProc);
    return ok;
}

/* -- resolve PID ? command-line string --------------------------------------
 *
 * Strategy (two independent paths, fallback if primary fails):
 *
 *  PRIMARY:  NtQueryInformationProcess class 60 (ProcessCommandLineInformation)
 *            Available on Windows 8+.  One kernel call, returns UNICODE_STRING
 *            pointing directly to the PEB's command-line buffer.
 *
 *  FALLBACK: ProcessBasicInformation (class 0) ? PEB base address ?
 *            ReadProcessMemory(PEB.ProcessParameters) ?
 *            ReadProcessMemory(RTL_USER_PROCESS_PARAMETERS.CommandLine)
 *            Documented, works on all NT versions, requires PROCESS_VM_READ.
 *            Offsets below are for x64 only (our build target).
 * --------------------------------------------------------------------------- */

 /* x64 PEB offsets we actually need (avoids including undocumented headers) */
#define PEB_OFF_PROCESS_PARAMS   0x20   /* PEB.ProcessParameters (PVOID)      */
#define RTL_OFF_CMDLINE          0x70   /* RTL_USER_PROCESS_PARAMETERS.CmdLine */
/* RTL_USER_PROCESS_PARAMETERS.CommandLine is a UNICODE_STRING:
 *   +0x00  USHORT  Length
 *   +0x02  USHORT  MaximumLength
 *   +0x08  PWSTR   Buffer           (x64 -- 8-byte pointer after 4 bytes + pad) */
#define USTR_OFF_LEN             0x00
#define USTR_OFF_BUF             0x08

typedef NTSTATUS(WINAPI* pfnNtQIP)(HANDLE, DWORD, PVOID, ULONG, PULONG);

static pfnNtQIP get_ntqip(void)
{
    static pfnNtQIP fn = NULL;
    if (!fn) {
        /* ntdll.dll is always loaded in every Windows process, but
         * GetModuleHandleA can still return NULL in theory -- guard it. */
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll)
            fn = (pfnNtQIP)GetProcAddress(hNtdll,
                "NtQueryInformationProcess");
    }
    return fn;
}

/* Primary: class 60 ------------------------------------------------------- */
static BOOL cmdline_via_class60(HANDLE hProc, char* out, DWORD out_size)
{
    pfnNtQIP NtQIP = get_ntqip();
    if (!NtQIP) return FALSE;

    ULONG sz = 0;
    /* First call: get required buffer size (returns STATUS_INFO_LENGTH_MISMATCH) */
    NtQIP(hProc, 60, NULL, 0, &sz);
    if (sz == 0) return FALSE;

    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz + 16);
    if (!buf) return FALSE;

    BOOL ok = FALSE;
    if (NtQIP(hProc, 60, buf, sz, &sz) == 0) {
        UNICODE_STRING* us = (UNICODE_STRING*)buf;
        if (us->Buffer && us->Length > 0) {
            WideCharToMultiByte(CP_ACP, 0, us->Buffer, us->Length / 2,
                out, out_size - 1, NULL, NULL);
            out[out_size - 1] = '\0';
            ok = TRUE;
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return ok;
}

/* Fallback: PEB via class 0 + ReadProcessMemory (x64 only) --------------- */
static BOOL cmdline_via_peb(HANDLE hProc, char* out, DWORD out_size)
{
    pfnNtQIP NtQIP = get_ntqip();
    if (!NtQIP) return FALSE;

    /* Step 1: get PEB base address via ProcessBasicInformation (class 0) */
    typedef struct {
        PVOID    ExitStatus;
        PVOID    PebBaseAddress;
        PVOID    AffinityMask;
        PVOID    BasePriority;
        PVOID    UniqueProcessId;
        PVOID    InheritedFromUniqueProcessId;
    } PROC_BASIC_INFO;

    PROC_BASIC_INFO pbi;
    ULONG ret = 0;
    if (NtQIP(hProc, 0, &pbi, sizeof(pbi), &ret) != 0)
        return FALSE;
    if (!pbi.PebBaseAddress) return FALSE;

    /* Step 2: read PEB.ProcessParameters pointer */
    PVOID params_ptr = NULL;
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProc,
        (BYTE*)pbi.PebBaseAddress + PEB_OFF_PROCESS_PARAMS,
        &params_ptr, sizeof(params_ptr), &read)
        || read != sizeof(params_ptr) || !params_ptr)
        return FALSE;

    /* Step 3: read UNICODE_STRING header from RTL_USER_PROCESS_PARAMETERS */
    USHORT ustr_len = 0;
    PWSTR  ustr_buf = NULL;
    if (!ReadProcessMemory(hProc,
        (BYTE*)params_ptr + RTL_OFF_CMDLINE + USTR_OFF_LEN,
        &ustr_len, sizeof(ustr_len), &read)
        || read != sizeof(ustr_len) || ustr_len == 0)
        return FALSE;

    if (!ReadProcessMemory(hProc,
        (BYTE*)params_ptr + RTL_OFF_CMDLINE + USTR_OFF_BUF,
        &ustr_buf, sizeof(ustr_buf), &read)
        || read != sizeof(ustr_buf) || !ustr_buf)
        return FALSE;

    /* Step 4: read the actual wide-char command line */
    DWORD wchar_count = ustr_len / 2;
    WCHAR* wbuf = (WCHAR*)HeapAlloc(GetProcessHeap(), 0,
        (wchar_count + 1) * sizeof(WCHAR));
    if (!wbuf) return FALSE;

    BOOL ok = FALSE;
    if (ReadProcessMemory(hProc, ustr_buf, wbuf,
        wchar_count * sizeof(WCHAR), &read)
        && read > 0)
    {
        wbuf[wchar_count] = L'\0';
        WideCharToMultiByte(CP_ACP, 0, wbuf, wchar_count,
            out, out_size - 1, NULL, NULL);
        out[out_size - 1] = '\0';
        ok = (out[0] != '\0');
    }
    HeapFree(GetProcessHeap(), 0, wbuf);
    return ok;
}

BOOL util_pid_to_cmdline(DWORD pid, char* out, DWORD out_size)
{
    out[0] = '\0';

    /* Class 60 needs QUERY_LIMITED_INFORMATION only.
     * PEB fallback additionally needs PROCESS_VM_READ.
     * Request VM_READ upfront so one handle serves both paths.             */
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc) return FALSE;

    /* Try primary path first */
    BOOL ok = cmdline_via_class60(hProc, out, out_size);

    /* Fall back to PEB if class 60 failed (e.g. cross-session process,
     * or a future Windows build where class 60 behaviour changes)          */
    if (!ok)
        ok = cmdline_via_peb(hProc, out, out_size);

    CloseHandle(hProc);
    return ok;
}


/* -- FILETIME ? readable string ------------------------------------------- */
void util_filetime_to_str(const FILETIME* ft, char* out, DWORD out_size)
{
    SYSTEMTIME st;
    FileTimeToSystemTime(ft, &st);
    _snprintf(out, out_size, "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
}

/* -- console separator ----------------------------------------------------- */
void util_print_separator(void)
{
    printf("%-80s\n",
        "----------------------------------------"
        "----------------------------------------");
}

/* -- coloured severity log ------------------------------------------------- */
void util_log(DWORD severity, const char* fmt, ...)
{
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hCon, &csbi);
    WORD orig = csbi.wAttributes;

    const char* prefix;
    switch (severity) {
    case SEV_CRITICAL:
        SetConsoleTextAttribute(hCon, FOREGROUND_RED | FOREGROUND_INTENSITY);
        prefix = "[CRIT]";
        break;
    case SEV_WARN:
        SetConsoleTextAttribute(hCon,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        prefix = "[WARN]";
        break;
    default:
        SetConsoleTextAttribute(hCon,
            FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        prefix = "[INFO]";
        break;
    }

    printf("%s ", prefix);
    SetConsoleTextAttribute(hCon, orig);

    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}
