/*
 * legitimacy.c  --  Process and binary legitimacy checks
 *
 * Four independent checks per process:
 *   1. Digital signature (WinVerifyTrust / Authenticode)
 *   2. Path in a known-good system directory
 *   3. Parent-process relationship matches known rules
 *   4. Name-spoofing (e.g. "lsass .exe", "svchost32.exe", homoglyph tricks)
 */

#include "sysmon.h"
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

 /* ==========================================================================
    1. DIGITAL SIGNATURE
    ========================================================================== */

BOOL legit_verify_signature(const char* path)
{
    if (!path || path[0] == '\0') return FALSE;

    /* Convert to wide string */
    WCHAR wpath[MAX_PATH_EXTENDED];
    MultiByteToWideChar(CP_ACP, 0, path, -1, wpath,
        MAX_PATH_EXTENDED);

    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wpath;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wtd = { 0 };
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;   /* offline-safe */
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fileInfo;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.dwProvFlags = WTD_SAFER_FLAG |
        WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG result = WinVerifyTrust(NULL, &policy, &wtd);

    /* Close the state handle */
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policy, &wtd);

    return (result == ERROR_SUCCESS);
}

/* ==========================================================================
   2. PATH LEGITIMACY
   ========================================================================== */

BOOL legit_path_is_system(const char* path)
{
    if (!path || path[0] == '\0') return FALSE;

    char lower[MAX_PATH];
    strncpy(lower, path, MAX_PATH - 1);
    lower[MAX_PATH - 1] = '\0';
    util_lower(lower);

    for (int i = 0; LEGIT_DIRS[i]; i++) {
        if (strncmp(lower, LEGIT_DIRS[i], strlen(LEGIT_DIRS[i])) == 0)
            return TRUE;
    }
    return FALSE;
}

/* ==========================================================================
   3. PARENT-PROCESS LEGITIMACY
   ========================================================================== */

BOOL legit_check_ppid(const char* child_name, const char* parent_name)
{
    if (!child_name || !parent_name) return TRUE;

    char child[MAX_PATH], parent[MAX_PATH];
    strncpy(child, child_name, MAX_PATH - 1); child[MAX_PATH - 1] = '\0';
    strncpy(parent, parent_name, MAX_PATH - 1); parent[MAX_PATH - 1] = '\0';
    util_lower(child);
    util_lower(parent);

    /* Step 1: Is this child EXPLICITLY named in any rule?
     *
     * IMPORTANT: only count rules where rule.child is a specific name,
     * NOT wildcard ("*"). A wildcard-child rule like { "services.exe", "*" }
     * means "services.exe can spawn anything" -- it should NOT mark every
     * process as "restricted". If we counted wildcards here, every process
     * would have child_has_any_rule=TRUE and then fail when their specific
     * parent isn't listed.                                                  */
    BOOL child_is_restricted = FALSE;
    for (int i = 0; PPID_RULES[i].parent; i++) {
        char rc[MAX_PATH];
        strncpy(rc, PPID_RULES[i].child, MAX_PATH - 1);
        rc[MAX_PATH - 1] = '\0';
        util_lower(rc);
        if (strcmp(rc, "*") != 0 && strcmp(rc, child) == 0) {
            child_is_restricted = TRUE;
            break;
        }
    }

    /* Step 2: If the child is not explicitly restricted, allow by default.
     * Also check wildcard-parent rules (e.g. { "services.exe", "*" }) --
     * if the actual parent is a known unrestricted spawner, allow.          */
    if (!child_is_restricted) {
        /* Check: is there a { parent, "*" } rule matching this parent? */
        for (int i = 0; PPID_RULES[i].parent; i++) {
            char rc[MAX_PATH], rp[MAX_PATH];
            strncpy(rc, PPID_RULES[i].child, MAX_PATH - 1); rc[MAX_PATH - 1] = '\0';
            strncpy(rp, PPID_RULES[i].parent, MAX_PATH - 1); rp[MAX_PATH - 1] = '\0';
            util_lower(rc);
            util_lower(rp);
            if (strcmp(rc, "*") == 0 &&
                (strcmp(rp, "*") == 0 || strcmp(rp, parent) == 0))
                return TRUE;
        }
        return TRUE; /* unrestricted child, unknown parent -- allow */
    }

    /* Step 3: Child IS restricted -- find a rule that permits this parent. */
    for (int i = 0; PPID_RULES[i].parent; i++) {
        char rc[MAX_PATH], rp[MAX_PATH];
        strncpy(rc, PPID_RULES[i].child, MAX_PATH - 1); rc[MAX_PATH - 1] = '\0';
        strncpy(rp, PPID_RULES[i].parent, MAX_PATH - 1); rp[MAX_PATH - 1] = '\0';
        util_lower(rc);
        util_lower(rp);

        BOOL child_matches = (strcmp(rc, child) == 0 || strcmp(rc, "*") == 0);
        BOOL parent_matches = (strcmp(rp, parent) == 0 || strcmp(rp, "*") == 0);
        if (child_matches && parent_matches)
            return TRUE;
    }
    return FALSE;
}

/* ==========================================================================
   4. NAME SPOOFING DETECTION
   ========================================================================== */

   /* System process names that are commonly spoofed */
static const char* SYSTEM_PROC_NAMES[] = {
    "lsass.exe", "svchost.exe", "services.exe", "csrss.exe",
    "smss.exe",  "wininit.exe", "winlogon.exe", "taskhost.exe",
    "taskhostw.exe", "explorer.exe", "spoolsv.exe", "lsm.exe",
    NULL
};

BOOL legit_check_name_spoof(const char* name, const char* path)
{
    if (!name) return FALSE;

    /* If the path is unresolved we cannot verify location -- do NOT flag.
     * A missing path means access denied (protected process), not a spoof.
     * Flagging unresolved paths produces false positives on every protected
     * system process and is not actionable.                               */
    if (!path || path[0] == '\0') return FALSE;

    char lname[MAX_PATH];
    strncpy(lname, name, MAX_PATH - 1);
    lname[MAX_PATH - 1] = '\0';
    util_lower(lname);

    for (int i = 0; SYSTEM_PROC_NAMES[i]; i++) {
        if (strcmp(lname, SYSTEM_PROC_NAMES[i]) != 0) continue;

        /* Name matches a known system proc -- verify it lives in system32 */
        char lpath[MAX_PATH];
        strncpy(lpath, path, MAX_PATH - 1);
        lpath[MAX_PATH - 1] = '\0';
        util_lower(lpath);

        char expected[MAX_PATH];
        UINT sysDir = GetSystemDirectoryA(expected, MAX_PATH);
        if (!sysDir) return FALSE;
        util_lower(expected);

        char full_expected[MAX_PATH];
        _snprintf(full_expected, MAX_PATH, "%s\\%s",
            expected, SYSTEM_PROC_NAMES[i]);

        /* Explorer lives in Windows dir, not system32 */
        if (strcmp(SYSTEM_PROC_NAMES[i], "explorer.exe") == 0) {
            char windir[MAX_PATH];
            GetWindowsDirectoryA(windir, MAX_PATH);
            util_lower(windir);
            _snprintf(full_expected, MAX_PATH, "%s\\explorer.exe", windir);
        }

        if (strcmp(lpath, full_expected) != 0)
            return TRUE; /* SPOOF: correct name, wrong path */
    }

    /* Trailing whitespace */
    size_t len = strlen(name);
    if (len > 4 && (name[len - 1] == ' ' || name[len - 1] == '\t'))
        return TRUE;

    /* Digit suffix on known names: "svchost1.exe", "lsass2.exe"
     * Only flag if the character immediately after the base name is a digit.
     * This prevents false positives on legitimate names like taskhostw.exe
     * which shares the "taskhost" base but is a real Windows binary.       */
    for (int i = 0; SYSTEM_PROC_NAMES[i]; i++) {
        size_t slen = strlen(SYSTEM_PROC_NAMES[i]) - 4; /* strip .exe */
        if (strncmp(lname, SYSTEM_PROC_NAMES[i], slen) == 0 &&
            strcmp(lname, SYSTEM_PROC_NAMES[i]) != 0) {
            /* Only flag if the first extra character is a digit */
            char extra = lname[slen];
            if (extra >= '0' && extra <= '9')
                return TRUE;
        }
    }

    return FALSE;
}

/* ==========================================================================
   FULL PROCESS AUDIT
   ========================================================================== */

void legit_audit_process(ProcessEntry* pe, const SystemSnapshot* snap)
{
    /* 1. Signature */
    pe->signature_present = FALSE;
    pe->signature_valid = FALSE;
    if (pe->path[0] != '\0') {
        pe->signature_present = TRUE;
        pe->signature_valid = legit_verify_signature(pe->path);
    }

    /* 2. Path in known-good dir */
    pe->path_legit = legit_path_is_system(pe->path);

    /* 3. PPID legitimacy -- find parent name in snapshot */
    pe->ppid_legit = TRUE;
    if (snap) {
        const char* parent_name = NULL;
        for (DWORD i = 0; i < snap->proc_count; i++) {
            if (snap->procs[i].pid == pe->ppid) {
                parent_name = snap->procs[i].name;
                break;
            }
        }
        if (parent_name)
            pe->ppid_legit = legit_check_ppid(pe->name, parent_name);
    }

    /* 4. Name spoofing */
    pe->name_spoof = legit_check_name_spoof(pe->name, pe->path);

    /* 5. Singleton violation */
    pe->singleton_violation = FALSE;
    if (snap) {
        char lname[MAX_PATH];
        strncpy(lname, pe->name, MAX_PATH - 1);
        util_lower(lname);

        for (int s = 0; SINGLETON_PROCS[s]; s++) {
            if (strcmp(lname, SINGLETON_PROCS[s]) == 0) {
                DWORD count = 0;
                for (DWORD i = 0; i < snap->proc_count; i++) {
                    char ln2[MAX_PATH];
                    strncpy(ln2, snap->procs[i].name, MAX_PATH - 1);
                    util_lower(ln2);
                    if (strcmp(ln2, SINGLETON_PROCS[s]) == 0) count++;
                }
                if (count > 1) pe->singleton_violation = TRUE;
                break;
            }
        }
    }
}

/* -- audit every process in a snapshot ------------------------------------ */
void legit_audit_snapshot(SystemSnapshot* snap)
{
    for (DWORD i = 0; i < snap->proc_count; i++)
        legit_audit_process(&snap->procs[i], snap);
}
