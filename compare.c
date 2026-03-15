/*
 * compare.c  --  Snapshot diffing engine
 *
 * Compares two SystemSnapshot structs and produces a DiffResult containing
 * prioritised change records.  The most critical check is:
 *
 *   CHG_SNAPSHOT_IDENTICAL  -- two consecutive snapshots are byte-for-byte
 *                              identical (excluding metadata).  This almost
 *                              never happens on a real system and strongly
 *                              suggests a rootkit/driver returning cached /
 *                              fabricated data.
 */

#include "sysmon.h"

 /* -- dynamic array helpers ------------------------------------------------- */

static BOOL diff_push(DiffResult* d, ChangeKind kind,
    DWORD severity, const char* desc)
{
    if (d->count >= d->capacity) {
        DWORD newcap = d->capacity ? d->capacity * 2 : 64;
        ChangeRecord* tmp = (ChangeRecord*)realloc(
            d->records, newcap * sizeof(ChangeRecord));
        if (!tmp) return FALSE;
        d->records = tmp;
        d->capacity = newcap;
    }
    ChangeRecord* r = &d->records[d->count++];
    r->kind = kind;
    r->severity = severity;
    strncpy(r->description, desc, 511);
    r->description[511] = '\0';
    return TRUE;
}

/* -- check if two snapshots look suspiciously identical ---------------------
 *
 * A genuine rootkit returning cached data will produce snapshots where:
 *   1. All process payload is byte-identical
 *   2. All connection payload is byte-identical
 *   3. At least some processes had resolvable hashes (i.e. the comparison
 *      is meaningful, not just two arrays of zeros)
 *
 * We require condition 3 to avoid false positives when most processes are
 * unresolvable (access denied) -- in that case the hash fields are all zero
 * and two consecutive snapshots of a quiet system can legitimately match.
 * --------------------------------------------------------------------------- */
static BOOL data_identical(const SystemSnapshot* a, const SystemSnapshot* b)
{
    /* Quick count mismatch exits */
    if (a->proc_count != b->proc_count)   return FALSE;
    if (a->conn_count != b->conn_count)   return FALSE;
    if (a->module_count != b->module_count) return FALSE;
    if (a->svc_count != b->svc_count)    return FALSE;
    if (a->reg_count != b->reg_count)    return FALSE;
    if (a->task_count != b->task_count)   return FALSE;

    /* Must have at least 5 resolved hashes -- otherwise the process array
     * is mostly zeroed and two quiet snapshots can legitimately appear equal */
    DWORD resolved = 0;
    for (DWORD i = 0; i < a->proc_count; i++)
        if (a->procs[i].hash_ok) resolved++;
    if (resolved < 5) return FALSE;

    /* Full payload comparison */
    return (
        memcmp(a->procs, b->procs,
            a->proc_count * sizeof(ProcessEntry)) == 0 &&
        memcmp(a->conns, b->conns,
            a->conn_count * sizeof(ConnEntry)) == 0 &&
        memcmp(a->reg_runs, b->reg_runs,
            a->reg_count * sizeof(RegRunEntry)) == 0 &&
        memcmp(a->tasks, b->tasks,
            a->task_count * sizeof(TaskEntry)) == 0
        );
}

/* ========================================================================
   PROCESS DIFF
   ======================================================================== */

static void diff_processes(const SystemSnapshot* old_s,
    const SystemSnapshot* new_s,
    DiffResult* d)
{
    char buf[512];

    /* -- processes gone -------------------------------------------------- */
    for (DWORD i = 0; i < old_s->proc_count; i++) {
        const ProcessEntry* op = &old_s->procs[i];
        BOOL found = FALSE;
        for (DWORD j = 0; j < new_s->proc_count; j++) {
            if (new_s->procs[j].pid == op->pid) { found = TRUE; break; }
        }
        if (!found) {
            _snprintf(buf, 511, "Process GONE  PID=%-6u  %s  (%s)",
                op->pid, op->name, op->path);
            diff_push(d, CHG_PROC_GONE, SEV_INFO, buf);
        }
    }

    /* -- processes new / changed ----------------------------------------- */
    for (DWORD i = 0; i < new_s->proc_count; i++) {
        const ProcessEntry* np = &new_s->procs[i];
        BOOL  existed = FALSE;
        const ProcessEntry* op = NULL;

        for (DWORD j = 0; j < old_s->proc_count; j++) {
            if (old_s->procs[j].pid == np->pid) {
                existed = TRUE;
                op = &old_s->procs[j];
                break;
            }
        }

        if (!existed) {
            /* New process */
            DWORD sev = SEV_INFO;
            if (np->name_spoof || np->singleton_violation ||
                !np->ppid_legit || !np->signature_valid)
                sev = SEV_CRITICAL;
            else if (!np->path_legit)
                sev = SEV_WARN;

            _snprintf(buf, 511,
                "Process NEW  PID=%-6u  %s  path=%s  user=%s"
                "  [sig=%s path_ok=%s ppid_ok=%s spoof=%s]",
                np->pid, np->name, np->path, np->username,
                np->signature_valid ? "Y" : "N",
                np->path_legit ? "Y" : "N",
                np->ppid_legit ? "Y" : "N",
                np->name_spoof ? "YES!" : "N");
            diff_push(d, CHG_PROC_NEW, sev, buf);

            /* Attach command line if available */
            if (np->cmdline[0] != '\0') {
                _snprintf(buf, 511, "  +- cmdline: %.400s", np->cmdline);
                diff_push(d, CHG_PROC_NEW, sev, buf);
            }
        }
        else if (op) {
            /* Process existed -- check for changes */
            if (op->hash_ok && np->hash_ok &&
                memcmp(op->exe_hash, np->exe_hash, SHA256_LEN) != 0) {
                char h1[65], h2[65];
                sha256_to_hex(op->exe_hash, h1);
                sha256_to_hex(np->exe_hash, h2);
                _snprintf(buf, 511,
                    "Process HASH CHANGED  PID=%-6u  %s\n"
                    "    old=%s\n    new=%s",
                    np->pid, np->name, h1, h2);
                diff_push(d, CHG_PROC_HASH_CHANGED, SEV_CRITICAL, buf);
            }

            if (op->path[0] && np->path[0] &&
                strcmp(op->path, np->path) != 0) {
                _snprintf(buf, 511,
                    "Process PATH CHANGED  PID=%-6u  %s\n"
                    "    old=%s\n    new=%s",
                    np->pid, np->name, op->path, np->path);
                diff_push(d, CHG_PROC_PATH_CHANGED, SEV_CRITICAL, buf);
            }
        }

        /* Legitimacy alerts (always, not just on diff) */
        if (np->name_spoof) {
            _snprintf(buf, 511,
                "NAME SPOOF  PID=%-6u  '%s' is impersonating a system "
                "process from: %s",
                np->pid, np->name, np->path);
            diff_push(d, CHG_PROC_NEW, SEV_CRITICAL, buf);
        }
        if (np->singleton_violation) {
            _snprintf(buf, 511,
                "SINGLETON VIOLATION  Multiple instances of '%s' (PID %u)",
                np->name, np->pid);
            diff_push(d, CHG_PROC_NEW, SEV_CRITICAL, buf);
        }
        if (!np->ppid_legit) {
            /* Resolve parent name */
            const char* par = "<unknown>";
            for (DWORD j = 0; j < new_s->proc_count; j++) {
                if (new_s->procs[j].pid == np->ppid) {
                    par = new_s->procs[j].name; break;
                }
            }
            _snprintf(buf, 511,
                "PPID ANOMALY  PID=%-6u  '%s' started by unexpected "
                "parent '%s' (PPID=%u)",
                np->pid, np->name, par, np->ppid);
            diff_push(d, CHG_PROC_NEW, SEV_WARN, buf);
        }
    }
}

/* ========================================================================
   NETWORK CONNECTION DIFF
   ======================================================================== */

static const char* proto_str(ConnProto p)
{
    switch (p) {
    case CONN_TCP4: return "TCP4";
    case CONN_TCP6: return "TCP6";
    case CONN_UDP4: return "UDP4";
    case CONN_UDP6: return "UDP6";
    default:        return "???";
    }
}

static BOOL conn_eq(const ConnEntry* a, const ConnEntry* b)
{
    return (a->proto == b->proto &&
        a->pid == b->pid &&
        a->local_port == b->local_port &&
        a->remote_port == b->remote_port &&
        strcmp(a->local_addr, b->local_addr) == 0 &&
        strcmp(a->remote_addr, b->remote_addr) == 0);
}

static void diff_network(const SystemSnapshot* old_s,
    const SystemSnapshot* new_s,
    DiffResult* d)
{
    char buf[512];

    for (DWORD i = 0; i < new_s->conn_count; i++) {
        const ConnEntry* nc = &new_s->conns[i];
        BOOL found = FALSE;
        for (DWORD j = 0; j < old_s->conn_count; j++)
            if (conn_eq(nc, &old_s->conns[j])) { found = TRUE; break; }

        if (!found) {
            /* Find process name */
            const char* pname = "<unknown>";
            for (DWORD j = 0; j < new_s->proc_count; j++)
                if (new_s->procs[j].pid == nc->pid) {
                    pname = new_s->procs[j].name; break;
                }

            DWORD sev = SEV_INFO;
            /* Flag suspicious remote ports */
            if (nc->remote_port == 4444 || nc->remote_port == 1337 ||
                nc->remote_port == 31337 || nc->remote_port == 8888)
                sev = SEV_CRITICAL;
            /* Flag outbound from system processes */
            char ln[MAX_PATH];
            strncpy(ln, pname, MAX_PATH - 1); util_lower(ln);
            if (strcmp(ln, "lsass.exe") == 0 ||
                strcmp(ln, "services.exe") == 0)
                sev = SEV_CRITICAL;

            _snprintf(buf, 511,
                "Connection NEW  %s  PID=%-6u(%s)  %s:%u -> %s:%u",
                proto_str(nc->proto), nc->pid, pname,
                nc->local_addr, nc->local_port,
                nc->remote_addr, nc->remote_port);
            diff_push(d, CHG_CONN_NEW, sev, buf);
        }
    }

    for (DWORD i = 0; i < old_s->conn_count; i++) {
        const ConnEntry* oc = &old_s->conns[i];
        BOOL found = FALSE;
        for (DWORD j = 0; j < new_s->conn_count; j++)
            if (conn_eq(oc, &new_s->conns[j])) { found = TRUE; break; }
        if (!found) {
            _snprintf(buf, 511,
                "Connection GONE  %s  PID=%-6u  %s:%u -> %s:%u",
                proto_str(oc->proto), oc->pid,
                oc->local_addr, oc->local_port,
                oc->remote_addr, oc->remote_port);
            diff_push(d, CHG_CONN_GONE, SEV_INFO, buf);
        }
    }
}

/* ========================================================================
   SERVICE DIFF
   ======================================================================== */

static void diff_services(const SystemSnapshot* old_s,
    const SystemSnapshot* new_s,
    DiffResult* d)
{
    char buf[512];

    for (DWORD i = 0; i < new_s->svc_count; i++) {
        const ServiceEntry* ns = &new_s->services[i];
        BOOL found = FALSE;
        for (DWORD j = 0; j < old_s->svc_count; j++) {
            if (strcmp(old_s->services[j].name, ns->name) == 0) {
                found = TRUE;
                const ServiceEntry* os = &old_s->services[j];
                if (strcmp(os->binary, ns->binary) != 0) {
                    _snprintf(buf, 511,
                        "Service BINARY CHANGED  '%s'\n"
                        "    old=%s\n    new=%s",
                        ns->name, os->binary, ns->binary);
                    diff_push(d, CHG_SVC_BINARY_CHANGED, SEV_CRITICAL, buf);
                }
                break;
            }
        }
        if (!found) {
            DWORD sev = ns->signature_valid ? SEV_WARN : SEV_CRITICAL;
            _snprintf(buf, 511,
                "Service NEW  '%s' (%s)  binary=%s  [sig=%s]",
                ns->name, ns->display, ns->binary,
                ns->signature_valid ? "Y" : "N");
            diff_push(d, CHG_SVC_NEW, sev, buf);
        }
    }

    for (DWORD i = 0; i < old_s->svc_count; i++) {
        const ServiceEntry* os = &old_s->services[i];
        BOOL found = FALSE;
        for (DWORD j = 0; j < new_s->svc_count; j++)
            if (strcmp(new_s->services[j].name, os->name) == 0)
            {
                found = TRUE; break;
            }
        if (!found) {
            _snprintf(buf, 511, "Service GONE  '%s'", os->name);
            diff_push(d, CHG_SVC_GONE, SEV_INFO, buf);
        }
    }
}

/* ========================================================================
   REGISTRY DIFF
   ======================================================================== */

static void diff_registry(const SystemSnapshot* old_s,
    const SystemSnapshot* new_s,
    DiffResult* d)
{
    char buf[512];

    for (DWORD i = 0; i < new_s->reg_count; i++) {
        const RegRunEntry* nr = &new_s->reg_runs[i];
        BOOL found = FALSE;
        for (DWORD j = 0; j < old_s->reg_count; j++) {
            const RegRunEntry* or_ = &old_s->reg_runs[j];
            if (strcmp(or_->subkey, nr->subkey) == 0 &&
                strcmp(or_->value_name, nr->value_name) == 0) {
                found = TRUE;
                if (strcmp(or_->value_data, nr->value_data) != 0) {
                    _snprintf(buf, 511,
                        "Registry CHANGED  [%s\\%s] '%s'\n"
                        "    old=%s\n    new=%s",
                        nr->hive, nr->subkey, nr->value_name,
                        or_->value_data, nr->value_data);
                    diff_push(d, CHG_REG_DATA_CHANGED, SEV_CRITICAL, buf);
                }
                break;
            }
        }
        if (!found) {
            _snprintf(buf, 511,
                "Registry NEW  [%s\\%s] '%s' = '%s'",
                nr->hive, nr->subkey, nr->value_name, nr->value_data);
            diff_push(d, CHG_REG_NEW, SEV_WARN, buf);
        }
    }

    for (DWORD i = 0; i < old_s->reg_count; i++) {
        const RegRunEntry* or_ = &old_s->reg_runs[i];
        BOOL found = FALSE;
        for (DWORD j = 0; j < new_s->reg_count; j++) {
            const RegRunEntry* nr = &new_s->reg_runs[j];
            if (strcmp(nr->subkey, or_->subkey) == 0 &&
                strcmp(nr->value_name, or_->value_name) == 0)
            {
                found = TRUE; break;
            }
        }
        if (!found) {
            _snprintf(buf, 511, "Registry GONE  [%s\\%s] '%s'",
                or_->hive, or_->subkey, or_->value_name);
            diff_push(d, CHG_REG_GONE, SEV_INFO, buf);
        }
    }
}

/* ========================================================================
   TASK DIFF
   ======================================================================== */

static void diff_tasks(const SystemSnapshot* old_s,
    const SystemSnapshot* new_s,
    DiffResult* d)
{
    char buf[512];

    for (DWORD i = 0; i < new_s->task_count; i++) {
        const TaskEntry* nt = &new_s->tasks[i];
        BOOL found = FALSE;
        for (DWORD j = 0; j < old_s->task_count; j++) {
            if (strcmp(old_s->tasks[j].path, nt->path) == 0) {
                found = TRUE;
                if (strcmp(old_s->tasks[j].action, nt->action) != 0) {
                    _snprintf(buf, 511,
                        "Task ACTION CHANGED  '%s'\n"
                        "    old=%s\n    new=%s",
                        nt->name,
                        old_s->tasks[j].action, nt->action);
                    diff_push(d, CHG_TASK_ACTION_CHANGED, SEV_CRITICAL, buf);
                }
                break;
            }
        }
        if (!found) {
            DWORD sev = nt->signature_valid ? SEV_INFO : SEV_WARN;
            _snprintf(buf, 511,
                "Task NEW  '%s'  action=%s  author=%s  [sig=%s]",
                nt->name, nt->action, nt->author,
                nt->signature_valid ? "Y" : "N");
            diff_push(d, CHG_TASK_NEW, sev, buf);
        }
    }

    for (DWORD i = 0; i < old_s->task_count; i++) {
        const TaskEntry* ot = &old_s->tasks[i];
        BOOL found = FALSE;
        for (DWORD j = 0; j < new_s->task_count; j++)
            if (strcmp(new_s->tasks[j].path, ot->path) == 0)
            {
                found = TRUE; break;
            }
        if (!found) {
            _snprintf(buf, 511, "Task GONE  '%s'", ot->name);
            diff_push(d, CHG_TASK_GONE, SEV_INFO, buf);
        }
    }
}

/* ========================================================================
   PID CROSS-CHECK DIFF
   ======================================================================== */

static void diff_pid_crosscheck(const SystemSnapshot* new_s, DiffResult* d)
{
    char buf[512];
    const PidCrossCheck* cc = &new_s->pid_check;

    for (DWORD i = 0; i < cc->hidden_count; i++) {
        /* Try to resolve path via direct handle */
        char path[MAX_PATH] = "<path unknown>";
        util_pid_to_path(cc->hidden_pids[i], path, MAX_PATH);

        _snprintf(buf, 511,
            "HIDDEN PID %u detected -- visible to PSAPI/WMI but HIDDEN from "
            "Toolhelp32.  Path: %s  "
            "This is a strong indicator of user-mode API hooking / rootkit.",
            cc->hidden_pids[i], path);
        diff_push(d, CHG_HIDDEN_PID, SEV_CRITICAL, buf);
    }

    for (DWORD i = 0; i < cc->phantom_count; i++) {
        _snprintf(buf, 511,
            "PHANTOM PID %u -- in Toolhelp32 but not PSAPI "
            "(possible race condition or rootkit fabrication)",
            cc->phantom_pids[i]);
        diff_push(d, CHG_PHANTOM_PID, SEV_WARN, buf);
    }
}

/* ========================================================================
   MAIN DIFF ENTRY POINT
   ======================================================================== */

DiffResult* diff_snapshots(const SystemSnapshot* old_s,
    const SystemSnapshot* new_s)
{
    DiffResult* d = (DiffResult*)calloc(1, sizeof(DiffResult));
    if (!d) return NULL;

    /* -- Anti-spoofing: identical snapshot check -------------------------- */
    if (data_identical(old_s, new_s)) {
        d->snapshots_identical = TRUE;
        diff_push(d, CHG_SNAPSHOT_IDENTICAL, SEV_CRITICAL,
            "CONSECUTIVE SNAPSHOTS ARE BYTE-IDENTICAL.  On a live Windows "
            "system this is virtually impossible.  A kernel-mode rootkit or "
            "driver may be returning cached / fabricated system data to "
            "enumerate APIs.  Immediate investigation is warranted.");
    }

    diff_pid_crosscheck(new_s, d);
    diff_processes(old_s, new_s, d);
    diff_network(old_s, new_s, d);
    diff_services(old_s, new_s, d);
    diff_registry(old_s, new_s, d);
    diff_tasks(old_s, new_s, d);

    return d;
}

/* ========================================================================
   PRINT DIFF
   ======================================================================== */

void diff_print(const DiffResult* d, BOOL critical_only)
{
    DWORD critical = 0, warn = 0, info = 0;
    for (DWORD i = 0; i < d->count; i++) {
        switch (d->records[i].severity) {
        case SEV_CRITICAL: critical++; break;
        case SEV_WARN:     warn++;     break;
        default:           info++;     break;
        }
    }

    util_print_separator();
    printf("  DIFF RESULTS:  %u critical  |  %u warning  |  %u info\n",
        critical, warn, info);
    util_print_separator();

    for (DWORD i = 0; i < d->count; i++) {
        const ChangeRecord* r = &d->records[i];
        if (critical_only && r->severity < SEV_CRITICAL) continue;
        util_log(r->severity, "%s", r->description);
    }
    printf("\n");
}

void diff_free(DiffResult* d)
{
    if (d) {
        free(d->records);
        free(d);
    }
}
