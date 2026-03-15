/*
 * main.c  --  CLI entry point for the Windows System Monitor
 *
 * Usage:
 *   sysmon.exe snapshot  <out.snap>         capture a new snapshot
 *   sysmon.exe compare   <a.snap> <b.snap>  diff two snapshots
 *   sysmon.exe compare   <a.snap> <b.snap> --critical-only
 *   sysmon.exe watch     <interval_sec>     continuous monitoring loop
 *   sysmon.exe audit     <snap>             re-run legitimacy checks
 *   sysmon.exe tasks     <snap>             list scheduled tasks
 *   sysmon.exe procs     <snap>             list all processes with flags
 *   sysmon.exe net       <snap>             list network connections
 *   sysmon.exe verify    <snap>             verify snapshot integrity
 */

#include "sysmon.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ntdll.lib")

 /* -- privilege helper ------------------------------------------------------ */
static BOOL enable_privilege(const char* name)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueA(NULL, name, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken); return FALSE;
    }
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp,
        sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ok;
}

static void setup_privileges(void)
{
    enable_privilege(SE_DEBUG_NAME);
    enable_privilege(SE_SECURITY_NAME);
    enable_privilege("SeSystemInformationPrivilege");
}

/* -- banner ---------------------------------------------------------------- */
static void print_banner(void)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(h, FOREGROUND_BLUE | FOREGROUND_GREEN |
        FOREGROUND_INTENSITY);
    printf(
        "\n"
        "  +----------------------------------------------------------+\n"
        "  |   SysMon  --  Windows System Snapshot & Integrity Monitor  |\n"
        "  |   Anti-spoofing  |  Task legitimacy  |  Live diff         |\n"
        "  +----------------------------------------------------------+\n"
        "\n"
    );
    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN |
        FOREGROUND_BLUE);
}

/* -- usage ----------------------------------------------------------------- */
static void usage(void)
{
    printf(
        "Usage:\n"
        "  sysmon snapshot  <out.snap>                 Capture system state\n"
        "  sysmon compare   <a.snap> <b.snap>          Diff two snapshots\n"
        "  sysmon compare   <a.snap> <b.snap> --crit   Critical only\n"
        "  sysmon watch     <interval_sec> [<dir>]     Continuous monitor\n"
        "  sysmon audit     <snap>                     Show legitimacy flags\n"
        "  sysmon tasks     <snap>                     List scheduled tasks\n"
        "  sysmon procs     <snap>                     List processes\n"
        "  sysmon net       <snap>                     List connections\n"
        "  sysmon verify    <snap>                     Verify integrity\n"
        "  sysmon whitelist                            Print AV/EDR exclusion commands\n"
        "\n"
        "Requires elevated privileges (run as Administrator).\n"
    );
}

/* -- format a Unix timestamp (seq) as a readable date/time string --------- */
static void seq_to_str(ULONGLONG ts, char* out, DWORD out_size)
{
    time_t t = (time_t)ts;
    struct tm* tm_info = localtime(&t);
    if (tm_info)
        strftime(out, out_size, "%Y-%m-%d %H:%M:%S", tm_info);
    else
        _snprintf(out, out_size, "%llu", ts);
}

/* ========================================================================
   COMMAND: snapshot
   ======================================================================== */

static int cmd_snapshot(const char* outpath)
{
    /* Use Unix timestamp as sequence number so it is unique across
     * separate invocations of the binary and carries capture time.
     * Two snapshots taken within the same second are disambiguated
     * by the SYSTEMTIME field in the struct itself.               */
    ULONGLONG seq = (ULONGLONG)time(NULL);
    char ts_str[32];
    seq_to_str(seq, ts_str, sizeof(ts_str));

    SystemSnapshot* snap = (SystemSnapshot*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SystemSnapshot));
    if (!snap) { fprintf(stderr, "OOM\n"); return 1; }

    printf("[*] Capturing snapshot  %s...\n\n", ts_str);
    if (!snapshot_capture(snap, seq)) {
        fprintf(stderr, "[!] Capture failed.\n");
        HeapFree(GetProcessHeap(), 0, snap);
        return 1;
    }

    snapshot_print_summary(snap);

    if (!snapshot_save(snap, outpath)) {
        fprintf(stderr, "[!] Failed to write: %s\n", outpath);
        HeapFree(GetProcessHeap(), 0, snap);
        return 1;
    }
    printf("[+] Snapshot saved: %s\n\n", outpath);
    HeapFree(GetProcessHeap(), 0, snap);
    return 0;
}

/* ========================================================================
   COMMAND: compare
   ======================================================================== */

static int cmd_compare(const char* path_a, const char* path_b,
    BOOL critical_only)
{
    SystemSnapshot* a = (SystemSnapshot*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SystemSnapshot));
    SystemSnapshot* b = (SystemSnapshot*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SystemSnapshot));
    if (!a || !b) { fprintf(stderr, "OOM\n"); return 1; }

    if (!snapshot_load(a, path_a)) {
        fprintf(stderr, "[!] Cannot load: %s\n", path_a); return 1;
    }
    if (!snapshot_load(b, path_b)) {
        fprintf(stderr, "[!] Cannot load: %s\n", path_b); return 1;
    }

    char ts_a[32], ts_b[32];
    seq_to_str(a->seq, ts_a, sizeof(ts_a));
    seq_to_str(b->seq, ts_b, sizeof(ts_b));
    printf("[*] Comparing snapshot  %s  vs  %s\n\n", ts_a, ts_b);

    DiffResult* diff = diff_snapshots(a, b);
    if (!diff) { fprintf(stderr, "OOM\n"); return 1; }

    diff_print(diff, critical_only);

    diff_free(diff);
    HeapFree(GetProcessHeap(), 0, a);
    HeapFree(GetProcessHeap(), 0, b);
    return 0;
}

/* ========================================================================
   COMMAND: watch  (continuous monitoring loop)
   ======================================================================== */

static int cmd_watch(DWORD interval_sec, const char* snap_dir)
{
    char dir[MAX_PATH] = ".";
    if (snap_dir) strncpy(dir, snap_dir, MAX_PATH - 1);

    printf("[*] Watch mode: interval=%us  dir=%s\n"
        "    Press Ctrl+C to stop.\n\n", interval_sec, dir);

    SystemSnapshot* prev = (SystemSnapshot*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SystemSnapshot));
    SystemSnapshot* curr = (SystemSnapshot*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SystemSnapshot));
    if (!prev || !curr) { fprintf(stderr, "OOM\n"); return 1; }

    /* First capture -- no diff yet */
    ULONGLONG seq = (ULONGLONG)time(NULL);
    char ts_str[32];
    seq_to_str(seq, ts_str, sizeof(ts_str));
    printf("[*] Initial capture  %s...\n", ts_str);
    snapshot_capture(prev, seq);
    snapshot_print_summary(prev);

    while (TRUE) {
        Sleep(interval_sec * 1000);
        seq = (ULONGLONG)time(NULL);
        seq_to_str(seq, ts_str, sizeof(ts_str));
        printf("\n[*] Capturing snapshot  %s...\n", ts_str);
        snapshot_capture(curr, seq);

        DiffResult* diff = diff_snapshots(prev, curr);
        if (diff) {
            if (diff->count > 0) {
                diff_print(diff, FALSE);
            }
            else {
                printf("[=] No changes detected.\n");
            }
            diff_free(diff);
        }

        /* Save snapshot to disk with timestamp-based filename */
        char snap_path[MAX_PATH];
        _snprintf(snap_path, MAX_PATH, "%s\\snap_%llu.bin", dir, curr->seq);
        snapshot_save(curr, snap_path);

        /* Rotate: curr ? prev */
        memcpy(prev, curr, sizeof(SystemSnapshot));
        memset(curr, 0, sizeof(SystemSnapshot));
    }

    HeapFree(GetProcessHeap(), 0, prev);
    HeapFree(GetProcessHeap(), 0, curr);
    return 0;
}

/* ========================================================================
   COMMAND: audit
   ======================================================================== */

static int cmd_audit(const char* snap_path)
{
    SystemSnapshot* snap = (SystemSnapshot*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SystemSnapshot));
    if (!snap) return 1;

    if (!snapshot_load(snap, snap_path)) return 1;

    util_print_separator();
    printf("  LEGITIMACY AUDIT  --  Snapshot #%llu\n", snap->seq);
    util_print_separator();

    for (DWORD i = 0; i < snap->proc_count; i++) {
        const ProcessEntry* pe = &snap->procs[i];

        /* PID 0 ([System Process] / Idle) and PID 4 (System) are kernel
         * pseudo-processes. They can never have a resolvable path or valid
         * signature -- flagging them produces only noise.                   */
        if (pe->pid == 0 || pe->pid == 4) continue;

        BOOL flagged = (!pe->signature_valid && pe->path[0]) ||
            !pe->path_legit || !pe->ppid_legit ||
            pe->name_spoof || pe->singleton_violation;
        if (!flagged) continue;

        DWORD sev = (pe->name_spoof || pe->singleton_violation ||
            !pe->ppid_legit) ? SEV_CRITICAL : SEV_WARN;

        /* Find parent name */
        const char* par = "<unknown>";
        for (DWORD j = 0; j < snap->proc_count; j++)
            if (snap->procs[j].pid == pe->ppid)
            {
                par = snap->procs[j].name; break;
            }

        char hash_str[65] = "N/A";
        if (pe->hash_ok) sha256_to_hex(pe->exe_hash, hash_str);

        util_log(sev,
            "PID %-6u  %-25s  parent=%-20s(PPID=%u)\n"
            "           path=%s\n"
            "           hash=%s\n"
            "           sig=%-3s  path_ok=%-3s  ppid_ok=%-3s"
            "  spoof=%-3s  singleton=%-3s",
            pe->pid, pe->name, par, pe->ppid,
            pe->path[0] ? pe->path : "<not resolved>",
            hash_str,
            pe->signature_valid ? "Y" : "N",
            pe->path_legit ? "Y" : "N",
            pe->ppid_legit ? "Y" : "N",
            pe->name_spoof ? "YES" : "N",
            pe->singleton_violation ? "YES" : "N");
    }

    printf("\n");
    HeapFree(GetProcessHeap(), 0, snap);
    return 0;
}

/* ========================================================================
   COMMAND: tasks
   ======================================================================== */

static int cmd_tasks(const char* snap_path)
{
    SystemSnapshot* snap = (SystemSnapshot*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SystemSnapshot));
    if (!snap) return 1;
    if (!snapshot_load(snap, snap_path)) return 1;

    util_print_separator();
    printf("  SCHEDULED TASKS  --  %u tasks\n", snap->task_count);
    util_print_separator();

    for (DWORD i = 0; i < snap->task_count; i++) {
        const TaskEntry* t = &snap->tasks[i];
        DWORD sev = t->signature_valid ? SEV_INFO : SEV_WARN;
        util_log(sev,
            "%-40s  enabled=%-3s  sig=%-3s\n"
            "    action : %s\n"
            "    author : %s",
            t->path,
            t->enabled ? "Y" : "N",
            t->signature_valid ? "Y" : "N",
            t->action[0] ? t->action : "<none>",
            t->author[0] ? t->author : "<none>");
    }
    printf("\n");
    HeapFree(GetProcessHeap(), 0, snap);
    return 0;
}

/* ========================================================================
   COMMAND: procs
   ======================================================================== */

static int cmd_procs(const char* snap_path)
{
    SystemSnapshot* snap = (SystemSnapshot*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SystemSnapshot));
    if (!snap) return 1;
    if (!snapshot_load(snap, snap_path)) return 1;

    util_print_separator();
    printf("  PROCESSES  --  %u total (snapshot #%llu)\n",
        snap->proc_count, snap->seq);
    printf("  %-6s  %-6s  %-6s  %-25s  %-3s %-3s %-3s %-3s  %s\n",
        "PID", "PPID", "USER", "NAME", "SIG", "PTH", "PID", "SPF", "PATH");
    util_print_separator();

    for (DWORD i = 0; i < snap->proc_count; i++) {
        const ProcessEntry* pe = &snap->procs[i];
        BOOL bad = !pe->signature_valid || !pe->path_legit ||
            !pe->ppid_legit || pe->name_spoof;
        DWORD sev = bad ? SEV_WARN : SEV_INFO;
        if (pe->name_spoof || pe->singleton_violation) sev = SEV_CRITICAL;

        char user[20];
        strncpy(user, pe->username, 19);
        user[19] = '\0';
        /* Trim domain prefix */
        char* bs = strrchr(user, '\\');
        if (bs) memmove(user, bs + 1, strlen(bs));

        util_log(sev,
            "%-6u %-6u %-6s %-25s  %-3s %-3s %-3s %-3s  %s",
            pe->pid, pe->ppid, user, pe->name,
            pe->signature_valid ? "Y" : "N",
            pe->path_legit ? "Y" : "N",
            pe->ppid_legit ? "Y" : "N",
            pe->name_spoof ? "!" : "N",
            pe->path[0] ? pe->path : "<unresolved>");
    }
    printf("\n");
    HeapFree(GetProcessHeap(), 0, snap);
    return 0;
}

/* ========================================================================
   COMMAND: net
   ======================================================================== */

static int cmd_net(const char* snap_path)
{
    SystemSnapshot* snap = (SystemSnapshot*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SystemSnapshot));
    if (!snap) return 1;
    if (!snapshot_load(snap, snap_path)) return 1;

    static const char* TCP_STATES[] = {
        "?", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD",
        "ESTAB", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT",
        "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"
    };

    util_print_separator();
    printf("  NETWORK CONNECTIONS  --  %u total\n", snap->conn_count);
    util_print_separator();

    for (DWORD i = 0; i < snap->conn_count; i++) {
        const ConnEntry* c = &snap->conns[i];
        /* find process name */
        const char* pname = "<?>";
        for (DWORD j = 0; j < snap->proc_count; j++)
            if (snap->procs[j].pid == c->pid)
            {
                pname = snap->procs[j].name; break;
            }

        const char* state = (c->proto == CONN_TCP4 || c->proto == CONN_TCP6)
            && c->state < 13 ? TCP_STATES[c->state] : "-";

        printf("  %-4s  PID=%-6u %-20s  %-20s:%-5u  ->  %-20s:%-5u  %s\n",
            (c->proto == CONN_TCP4 ? "TCP4" : c->proto == CONN_TCP6 ? "TCP6" :
                c->proto == CONN_UDP4 ? "UDP4" : "UDP6"),
            c->pid, pname,
            c->local_addr, c->local_port,
            c->remote_addr[0] ? c->remote_addr : "*",
            c->remote_port,
            state);
    }
    printf("\n");
    HeapFree(GetProcessHeap(), 0, snap);
    return 0;
}

/* ========================================================================
   COMMAND: verify
   ======================================================================== */

static int cmd_verify(const char* snap_path)
{
    SystemSnapshot* snap = (SystemSnapshot*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SystemSnapshot));
    if (!snap) return 1;

    /* Load without integrity check first so we can report on it */
    FILE* f = fopen(snap_path, "rb");
    if (!f) { fprintf(stderr, "[!] Cannot open: %s\n", snap_path); return 1; }
    fread(snap, sizeof(*snap), 1, f);
    fclose(f);

    if (snap->magic != SNAPSHOT_MAGIC) {
        util_log(SEV_CRITICAL, "Invalid magic bytes -- file corrupted or not "
            "a sysmon snapshot.");
        return 1;
    }
    if (snap->version != SNAPSHOT_VERSION) {
        util_log(SEV_WARN, "Version mismatch: file=%u expected=%u",
            snap->version, SNAPSHOT_VERSION);
    }

    if (snapshot_verify_integrity(snap)) {
        util_log(SEV_INFO,
            "Integrity OK  -- snapshot #%llu  %04d-%02d-%02d %02d:%02d",
            snap->seq,
            snap->captured_at.wYear, snap->captured_at.wMonth,
            snap->captured_at.wDay, snap->captured_at.wHour,
            snap->captured_at.wMinute);
    }
    else {
        util_log(SEV_CRITICAL,
            "Integrity FAILED -- snapshot has been modified or corrupted!");
        return 1;
    }

    HeapFree(GetProcessHeap(), 0, snap);
    return 0;
}

/* ========================================================================
   COMMAND: whitelist

   Computes the SHA-256 of the running sysmon.exe and emits ready-to-run
   PowerShell commands to add it to Windows Defender and a generic path
   exclusion for the snapshot output directory.

   Why hash-based rather than path-based:
     Path exclusions are trivially abused -- any binary dropped at the
     excluded path is also excluded.  Hash-based exclusions (Add-MpPreference
     -ExclusionProcess) tie the exclusion to a specific binary.  Both are
     emitted so the analyst can choose.
   ======================================================================== */

static int cmd_whitelist(void)
{
    /* Resolve own executable path */
    char self_path[MAX_PATH] = { 0 };
    if (!GetModuleFileNameA(NULL, self_path, MAX_PATH)) {
        fprintf(stderr, "[!] Could not resolve own path.\n");
        return 1;
    }

    /* Hash the binary */
    BYTE  hash[SHA256_LEN];
    char  hex[65];
    BOOL  hashed = sha256_file(self_path, hash);
    if (!hashed) {
        fprintf(stderr, "[!] Could not hash %s\n", self_path);
        return 1;
    }
    sha256_to_hex(hash, hex);

    util_print_separator();
    printf("  WHITELIST / AV EXCLUSION HELPER\n");
    util_print_separator();
    printf("\n  Binary  : %s\n", self_path);
    printf("  SHA-256 : %s\n\n", hex);

    /* -- Windows Defender (Defender ATP / MDE) -------------------------- */
    printf("  -- Windows Defender  (run in elevated PowerShell) --\n\n");

    /* Process exclusion -- ties to this specific binary hash */
    printf("  # Hash-based process exclusion (preferred)\n");
    printf("  Add-MpPreference -ExclusionProcess \"%s\"\n\n",
        self_path);

    /* Folder exclusion for snapshot output dir */
    char snap_dir[MAX_PATH] = { 0 };           /* zero-init: SAL-safe before strncpy */
    strncpy(snap_dir, self_path, MAX_PATH - 1);
    /* snap_dir[MAX_PATH-1] is already '\0' from the zero-init above,
     * but be explicit for clarity.                                    */
    snap_dir[MAX_PATH - 1] = '\0';
    /* Strip filename to get directory */
    char* last_sep = strrchr(snap_dir, '\\');
    if (last_sep) *(last_sep + 1) = '\0';
    printf("  # Directory exclusion for snapshot .bin files\n");
    printf("  Add-MpPreference -ExclusionPath \"%s\"\n\n", snap_dir);

    /* -- Manual verification command ----------------------------------- */
    printf("  -- Verify the binary has not changed since whitelisting --\n\n");
    printf("  (Get-FileHash \"%s\" -Algorithm SHA256).Hash\n", self_path);
    printf("  # Expected: %s\n\n", hex);

    /* -- EDR note ------------------------------------------------------ */
    printf("  -- For third-party EDR (CrowdStrike, SentinelOne, etc.) --\n\n");
    printf("  Most EDRs support hash-based exclusions in their management\n"
        "  console. Add this SHA-256 as a trusted process hash:\n\n"
        "  %s\n\n", hex);

    printf("  NOTE: Re-run 'sysmon whitelist' after any recompile -- the\n"
        "  binary hash changes with every build, invalidating prior\n"
        "  hash-based exclusions.\n\n");

    util_print_separator();
    return 0;
}

/* ========================================================================
   ENTRY POINT
   ======================================================================== */

int main(int argc, char* argv[])
{
    print_banner();
    setup_privileges();

    if (argc < 2) { usage(); return 0; }

    const char* cmd = argv[1];

    if (strcmp(cmd, "snapshot") == 0) {
        if (argc < 3) { usage(); return 1; }
        return cmd_snapshot(argv[2]);
    }

    if (strcmp(cmd, "compare") == 0) {
        if (argc < 4) { usage(); return 1; }
        BOOL crit = (argc >= 5 && strcmp(argv[4], "--crit") == 0);
        return cmd_compare(argv[2], argv[3], crit);
    }

    if (strcmp(cmd, "watch") == 0) {
        if (argc < 3) { usage(); return 1; }
        DWORD interval = (DWORD)atoi(argv[2]);
        if (interval < 1) interval = 30;
        return cmd_watch(interval, argc >= 4 ? argv[3] : NULL);
    }

    if (strcmp(cmd, "audit") == 0) {
        if (argc < 3) { usage(); return 1; }
        return cmd_audit(argv[2]);
    }

    if (strcmp(cmd, "tasks") == 0) {
        if (argc < 3) { usage(); return 1; }
        return cmd_tasks(argv[2]);
    }

    if (strcmp(cmd, "procs") == 0) {
        if (argc < 3) { usage(); return 1; }
        return cmd_procs(argv[2]);
    }

    if (strcmp(cmd, "net") == 0) {
        if (argc < 3) { usage(); return 1; }
        return cmd_net(argv[2]);
    }

    if (strcmp(cmd, "verify") == 0) {
        if (argc < 3) { usage(); return 1; }
        return cmd_verify(argv[2]);
    }

    if (strcmp(cmd, "whitelist") == 0) {
        return cmd_whitelist();
    }

    fprintf(stderr, "[!] Unknown command: %s\n\n", cmd);
    usage();
    return 1;
}
