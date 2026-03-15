/*
 * snapshot.c  --  Full system snapshot capture
 *
 * ANTI-SPOOFING strategy:
 *   Malware that hooks user-mode APIs (e.g. NtQuerySystemInformation) can
 *   hide itself from Toolhelp32 enumeration.  We cross-reference three
 *   independent sources:
 *     A. CreateToolhelp32Snapshot (Toolhelp32)
 *     B. EnumProcesses (PSAPI)
 *     C. WMI Win32_Process
 *   PIDs present in B or C but absent from A are flagged as HIDDEN.
 *   PIDs present in A but absent from B are flagged as PHANTOM.
 *
 * UNICODE note:
 *   This file is compiled in ANSI mode regardless of the project's UNICODE
 *   setting.  All internal strings are char-based; forcing ANSI here means
 *   PROCESSENTRY32, MODULEENTRY32, and related Toolhelp32 types resolve to
 *   their char[] variants without needing explicit A-suffixed names.
 *   The undefs must appear before any Windows headers are pulled in via
 *   sysmon.h.
 */

 /* Force ANSI mode for this translation unit */
#ifdef UNICODE
#  undef UNICODE
#endif
#ifdef _UNICODE
#  undef _UNICODE
#endif

#include "sysmon.h"
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")

/* ==========================================================================
   PROCESS ENUMERATION  (Toolhelp32 -- primary source)
   ========================================================================== */

static DWORD capture_processes_toolhelp(SystemSnapshot* s)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    /* UNICODE is undefined at the top of this file so PROCESSENTRY32,
     * Process32First, and Process32Next all resolve to their ANSI (char[])
     * variants -- szExeFile is char[], not WCHAR[].                        */
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    DWORD count = 0;

    if (Process32First(hSnap, &pe32)) {
        do {
            if (count >= MAX_PROCESSES) break;
            ProcessEntry* pe = &s->procs[count++];
            memset(pe, 0, sizeof(*pe));

            pe->pid = pe32.th32ProcessID;
            pe->ppid = pe32.th32ParentProcessID;
            strncpy(pe->name, pe32.szExeFile, MAX_PATH - 1);
            pe->name[MAX_PATH - 1] = '\0';

            /* Resolve full path */
            util_pid_to_path(pe->pid, pe->path, MAX_PATH);

            /* Username */
            util_pid_to_user(pe->pid, pe->username, 256);

            /* Command line */
            util_pid_to_cmdline(pe->pid, pe->cmdline, 1024);

            /* SHA-256 of the executable */
            if (pe->path[0] != '\0')
                pe->hash_ok = sha256_file(pe->path, pe->exe_hash);

            /* Creation time */
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE, pe->pid);
            if (hProc) {
                FILETIME exit_t, kernel_t, user_t;
                GetProcessTimes(hProc, &pe->create_time,
                    &exit_t, &kernel_t, &user_t);
                CloseHandle(hProc);
            }

            /* PID to cross-check list */
            s->pid_check.pids_toolhelp[s->pid_check.count_toolhelp++] = pe->pid;

        } while (Process32Next(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return count;
}

/* ==========================================================================
   PROCESS ENUMERATION  (PSAPI -- second source)
   ========================================================================== */

static void capture_processes_psapi(SystemSnapshot* s)
{
    DWORD pids[MAX_PROCESSES], needed;
    if (!EnumProcesses(pids, sizeof(pids), &needed)) return;

    DWORD count = needed / sizeof(DWORD);
    s->pid_check.count_psapi = 0;
    for (DWORD i = 0; i < count && i < MAX_PROCESSES; i++)
        s->pid_check.pids_psapi[s->pid_check.count_psapi++] = pids[i];
}

/* ==========================================================================
   PROCESS ENUMERATION  (WMI Win32_Process -- third source)

   Runs in a dedicated thread so capture_snapshot can abandon it after
   WMI_TIMEOUT_MS milliseconds if winmgmt is wedged or slow.

   LEAK FIXES applied here:
     * pSvc is released inside the same scope it is obtained -- no path
       to wmi_done can skip its Release once ConnectServer succeeds.
     * query / wql BSTRs are freed in all exit paths via a goto that
       always passes through the free block.
     * pEnum is always released before pSvc.
   ========================================================================== */

static void capture_processes_wmi_body(SystemSnapshot* s)
{
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IEnumWbemClassObject* pEnum = NULL;
    BSTR query = NULL, wql = NULL;

    if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
        return;

    if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL)))
        goto wmi_cleanup;

    if (FAILED(CoCreateInstance(&CLSID_WbemLocator, 0,
        CLSCTX_INPROC_SERVER, &IID_IWbemLocator,
        (LPVOID*)&pLoc)))
        goto wmi_cleanup;

    {
        BSTR ns = SysAllocString(L"ROOT\\CIMV2");
        HRESULT hr = pLoc->lpVtbl->ConnectServer(
            pLoc, ns, NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
        SysFreeString(ns);
        if (FAILED(hr)) goto wmi_cleanup;  /* pSvc is NULL on failure */
    }

    /* CoSetProxyBlanket failure is non-fatal -- WMI queries still work
     * with default security; cast to void to acknowledge the return.    */
    (void)CoSetProxyBlanket((IUnknown*)pSvc,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE);

    query = SysAllocString(L"SELECT ProcessId FROM Win32_Process");
    wql = SysAllocString(L"WQL");

    if (SUCCEEDED(pSvc->lpVtbl->ExecQuery(pSvc, wql, query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnum)))
    {
        IWbemClassObject* pObj = NULL;
        ULONG ret = 0;
        while (pEnum && s->pid_check.count_wmi < MAX_PROCESSES) {
            HRESULT hr = pEnum->lpVtbl->Next(pEnum,
                WBEM_INFINITE, 1, &pObj, &ret);
            if (hr != WBEM_S_NO_ERROR || ret == 0) break;

            VARIANT v; VariantInit(&v);
            if (SUCCEEDED(pObj->lpVtbl->Get(pObj, L"ProcessId",
                0, &v, NULL, NULL))) {
                s->pid_check.pids_wmi[s->pid_check.count_wmi++] =
                    (DWORD)v.uintVal;
                VariantClear(&v);
            }
            pObj->lpVtbl->Release(pObj);
        }
        if (pEnum) { pEnum->lpVtbl->Release(pEnum); pEnum = NULL; }
    }

    /* Free BSTRs before releasing pSvc */
    if (query) { SysFreeString(query); query = NULL; }
    if (wql) { SysFreeString(wql);   wql = NULL; }
    pSvc->lpVtbl->Release(pSvc);
    pSvc = NULL;

wmi_cleanup:
    /* Any path that bypasses the block above lands here.
     * Guards are defensive -- all should already be NULL at this point
     * on the normal path, but protect against future edits.             */
    if (pEnum) { pEnum->lpVtbl->Release(pEnum); }
    if (query) { SysFreeString(query); }
    if (wql) { SysFreeString(wql); }
    if (pSvc) { pSvc->lpVtbl->Release(pSvc); }
    if (pLoc) { pLoc->lpVtbl->Release(pLoc); }
    CoUninitialize();
}

/* Thread entry point ----------------------------------------------------- */
static DWORD WINAPI wmi_thread_proc(LPVOID arg)
{
    WmiThreadArgs* a = (WmiThreadArgs*)arg;
    capture_processes_wmi_body(a->snap);
    a->succeeded = (a->snap->pid_check.count_wmi > 0);
    a->done = TRUE;
    return 0;
}

static void capture_processes_wmi(SystemSnapshot* s)
{
    WmiThreadArgs args = { s, FALSE, FALSE };

    HANDLE hThread = CreateThread(NULL, 0, wmi_thread_proc, &args, 0, NULL);
    if (!hThread) {
        util_log(SEV_WARN, "WMI: could not create enumeration thread");
        return;
    }

    DWORD waited = WaitForSingleObject(hThread, WMI_TIMEOUT_MS);
    if (waited == WAIT_TIMEOUT) {
        util_log(SEV_WARN,
            "WMI enumeration timed out after %u ms -- "
            "winmgmt may be wedged. WMI PID source disabled for this snapshot.",
            WMI_TIMEOUT_MS);
        s->pid_check.wmi_timed_out = TRUE;
        /* TerminateThread is a last resort but necessary here:
         * the thread is stuck inside a blocking COM/RPC call that
         * we cannot unblock from outside. The WMI objects it holds
         * will leak, but that is acceptable vs. blocking the monitor.
         * C6258: intentional -- no safe alternative exists for a hung
         * blocking COM call.                                           */
#pragma warning(suppress: 6258)
        TerminateThread(hThread, 1);
    }
    CloseHandle(hThread);
}

/* ==========================================================================
   CROSS-CHECK -- find hidden / phantom PIDs
   ========================================================================== */

static BOOL pid_in_list(DWORD pid, const DWORD* list, DWORD count)
{
    for (DWORD i = 0; i < count; i++)
        if (list[i] == pid) return TRUE;
    return FALSE;
}

static void cross_check_pids(SystemSnapshot* s)
{
    PidCrossCheck* cc = &s->pid_check;
    cc->hidden_count = 0;
    cc->phantom_count = 0;

    /* Hidden: in PSAPI or WMI but not Toolhelp */
    for (DWORD i = 0; i < cc->count_psapi; i++) {
        DWORD pid = cc->pids_psapi[i];
        if (pid == 0) continue;
        if (!pid_in_list(pid, cc->pids_toolhelp, cc->count_toolhelp)) {
            if (cc->hidden_count < MAX_PROCESSES)
                cc->hidden_pids[cc->hidden_count++] = pid;
        }
    }
    for (DWORD i = 0; i < cc->count_wmi; i++) {
        DWORD pid = cc->pids_wmi[i];
        if (pid == 0) continue;
        if (!pid_in_list(pid, cc->pids_toolhelp, cc->count_toolhelp) &&
            !pid_in_list(pid, cc->hidden_pids, cc->hidden_count))
        {
            if (cc->hidden_count < MAX_PROCESSES)
                cc->hidden_pids[cc->hidden_count++] = pid;
        }
    }

    /* Phantom: in Toolhelp but not PSAPI */
    for (DWORD i = 0; i < cc->count_toolhelp; i++) {
        DWORD pid = cc->pids_toolhelp[i];
        if (pid == 0 || pid == 4) continue;   /* System / Idle PIDs */
        if (!pid_in_list(pid, cc->pids_psapi, cc->count_psapi)) {
            if (cc->phantom_count < MAX_PROCESSES)
                cc->phantom_pids[cc->phantom_count++] = pid;
        }
    }
}

/* ==========================================================================
   MODULE ENUMERATION  (loaded DLLs per process)
   ========================================================================== */

static void capture_modules(SystemSnapshot* s)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE |
        TH32CS_SNAPMODULE32, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    /* Same UNICODE-undef rationale: MODULEENTRY32 / Module32First /
     * Module32Next all resolve to ANSI variants in this translation unit. */
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(me32);
    if (!Module32First(hSnap, &me32)) { CloseHandle(hSnap); return; }

    do {
        if (s->module_count >= MAX_MODULE_ENTRIES) break;
        ModuleEntry* m = &s->modules[s->module_count++];
        memset(m, 0, sizeof(*m));

        m->pid = me32.th32ProcessID;
        strncpy(m->name, me32.szModule, MAX_PATH - 1);
        m->name[MAX_PATH - 1] = '\0';
        strncpy(m->path, me32.szExePath, MAX_PATH - 1);
        m->path[MAX_PATH - 1] = '\0';

        m->hash_ok = sha256_file(m->path, m->hash);
        m->signature_valid = legit_verify_signature(m->path);

    } while (Module32Next(hSnap, &me32));

    CloseHandle(hSnap);
}

/* ==========================================================================
   NETWORK CONNECTIONS  (TCP4, TCP6, UDP4, UDP6)
   ========================================================================== */

static void addr4_to_str(DWORD addr, char* out, DWORD sz)
{
    /* addr is in network byte order */
    BYTE* b = (BYTE*)&addr;
    _snprintf(out, sz, "%d.%d.%d.%d", b[0], b[1], b[2], b[3]);
}

static void capture_network(SystemSnapshot* s)
{
    /* -- TCP4 ------------------------------------------------------------ */
    /* Seed with minimum struct size so the SAL annotation
     * (*_Param_(2) >= sizeof(MIB_TCPTABLE)) is satisfied on the probe
     * call that intentionally returns ERROR_INSUFFICIENT_BUFFER.        */
    DWORD tcpSz = sizeof(MIB_TCPTABLE_OWNER_PID);
    GetExtendedTcpTable(NULL, &tcpSz, FALSE,
        AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    MIB_TCPTABLE_OWNER_PID* tcpTable =
        (MIB_TCPTABLE_OWNER_PID*)HeapAlloc(GetProcessHeap(), 0, tcpSz);
    if (tcpTable) {
        if (GetExtendedTcpTable(tcpTable, &tcpSz, FALSE,
            AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < tcpTable->dwNumEntries &&
                s->conn_count < MAX_CONNECTIONS; i++) {
                MIB_TCPROW_OWNER_PID* row = &tcpTable->table[i];
                ConnEntry* c = &s->conns[s->conn_count++];
                c->proto = CONN_TCP4;
                c->pid = row->dwOwningPid;
                c->state = row->dwState;
                addr4_to_str(row->dwLocalAddr, c->local_addr, 64);
                addr4_to_str(row->dwRemoteAddr, c->remote_addr, 64);
                c->local_port = ntohs((USHORT)row->dwLocalPort);
                c->remote_port = ntohs((USHORT)row->dwRemotePort);
            }
        }
        HeapFree(GetProcessHeap(), 0, tcpTable);
    }

    /* -- UDP4 ------------------------------------------------------------ */
    DWORD udpSz = sizeof(MIB_UDPTABLE_OWNER_PID);
    GetExtendedUdpTable(NULL, &udpSz, FALSE,
        AF_INET, UDP_TABLE_OWNER_PID, 0);
    MIB_UDPTABLE_OWNER_PID* udpTable =
        (MIB_UDPTABLE_OWNER_PID*)HeapAlloc(GetProcessHeap(), 0, udpSz);
    if (udpTable) {
        if (GetExtendedUdpTable(udpTable, &udpSz, FALSE,
            AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < udpTable->dwNumEntries &&
                s->conn_count < MAX_CONNECTIONS; i++) {
                MIB_UDPROW_OWNER_PID* row = &udpTable->table[i];
                ConnEntry* c = &s->conns[s->conn_count++];
                c->proto = CONN_UDP4;
                c->pid = row->dwOwningPid;
                addr4_to_str(row->dwLocalAddr, c->local_addr, 64);
                c->local_port = ntohs((USHORT)row->dwLocalPort);
                c->remote_addr[0] = '\0';
                c->remote_port = 0;
            }
        }
        HeapFree(GetProcessHeap(), 0, udpTable);
    }
}

/* ==========================================================================
   WINDOWS SERVICES
   ========================================================================== */

static void capture_services(SystemSnapshot* s)
{
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL,
        SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return;

    DWORD needed = 0, count = 0, resume = 0;
    /* First call intentionally fails with ERROR_INSUFFICIENT_BUFFER
     * to retrieve the required buffer size -- cast to void.            */
    (void)EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32 | SERVICE_DRIVER,
        SERVICE_STATE_ALL, NULL, 0,
        &needed, &count, &resume, NULL);

    if (needed == 0) { CloseServiceHandle(hSCM); return; }
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, needed);
    if (!buf) { CloseServiceHandle(hSCM); return; }

    resume = 0; count = 0;
    if (EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32 | SERVICE_DRIVER,
        SERVICE_STATE_ALL, buf, needed,
        &needed, &count, &resume, NULL)) {
        ENUM_SERVICE_STATUS_PROCESS* ssp =
            (ENUM_SERVICE_STATUS_PROCESS*)buf;
        for (DWORD i = 0; i < count && s->svc_count < MAX_SERVICES; i++) {
            ServiceEntry* svc = &s->services[s->svc_count++];
            memset(svc, 0, sizeof(*svc));

            strncpy(svc->name, ssp[i].lpServiceName, 255);
            svc->name[255] = '\0';
            strncpy(svc->display, ssp[i].lpDisplayName, 255);
            svc->display[255] = '\0';
            svc->state = ssp[i].ServiceStatusProcess.dwCurrentState;
            svc->type = ssp[i].ServiceStatusProcess.dwServiceType;

            /* Get binary path from config */
            SC_HANDLE hSvc = OpenServiceA(hSCM, ssp[i].lpServiceName,
                SERVICE_QUERY_CONFIG);
            if (hSvc) {
                DWORD cfgSz = 0;
                /* Probe call -- intentionally fails for size; cast to void */
                (void)QueryServiceConfigA(hSvc, NULL, 0, &cfgSz);
                if (cfgSz > 0) {
                    QUERY_SERVICE_CONFIGA* cfg =
                        (QUERY_SERVICE_CONFIGA*)HeapAlloc(
                            GetProcessHeap(), 0, cfgSz);
                    if (cfg) {
                        if (QueryServiceConfigA(hSvc, cfg, cfgSz, &cfgSz)) {
                            strncpy(svc->binary, cfg->lpBinaryPathName,
                                MAX_PATH - 1);
                            svc->binary[MAX_PATH - 1] = '\0';
                            svc->start_type = cfg->dwStartType;
                        }
                        HeapFree(GetProcessHeap(), 0, cfg);
                    }
                }
                CloseServiceHandle(hSvc);
            }

            /* Extract actual EXE path and verify signature */
            char exe_path[MAX_PATH];
            memset(exe_path, 0, sizeof(exe_path));
            if (svc->binary[0] != '\0') {
                strncpy(exe_path, svc->binary, MAX_PATH - 1);
                exe_path[MAX_PATH - 1] = '\0';  /* explicit termination */
                char* p = strstr(exe_path, ".exe");
                if (p) *(p + 4) = '\0';
                /* Remove leading quotes */
                if (exe_path[0] == '"') {
                    memmove(exe_path, exe_path + 1, strlen(exe_path));
                }
                svc->signature_valid = legit_verify_signature(exe_path);
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, buf);
    CloseServiceHandle(hSCM);
}

/* ==========================================================================
   REGISTRY AUTO-RUN KEYS
   ========================================================================== */

static const struct { HKEY hive; const char* hive_name; const char* subkey; }
REG_RUN_KEYS[] = {
    { HKEY_LOCAL_MACHINE, "HKLM",
      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { HKEY_LOCAL_MACHINE, "HKLM",
      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { HKEY_LOCAL_MACHINE, "HKLM",
      "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { HKEY_CURRENT_USER,  "HKCU",
      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { HKEY_CURRENT_USER,  "HKCU",
      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { HKEY_LOCAL_MACHINE, "HKLM",
      "SYSTEM\\CurrentControlSet\\Services" },   /* covered via services too */
    { 0, NULL, NULL }
};

static void capture_registry(SystemSnapshot* s)
{
    for (int k = 0; REG_RUN_KEYS[k].hive_name; k++) {
        HKEY hKey;
        if (RegOpenKeyExA(REG_RUN_KEYS[k].hive, REG_RUN_KEYS[k].subkey,
            0, KEY_READ, &hKey) != ERROR_SUCCESS)
            continue;

        char   val_name[256];
        BYTE   val_data[MAX_PATH];
        DWORD  name_sz, data_sz, type, idx = 0;

        while (s->reg_count < MAX_REGKEYS) {
            name_sz = 256; data_sz = MAX_PATH;
            LONG r = RegEnumValueA(hKey, idx++, val_name, &name_sz,
                NULL, &type, val_data, &data_sz);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS)       continue;
            if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

            RegRunEntry* rr = &s->reg_runs[s->reg_count++];
            memset(rr, 0, sizeof(*rr));
            strncpy(rr->hive, REG_RUN_KEYS[k].hive_name, 15);
            strncpy(rr->subkey, REG_RUN_KEYS[k].subkey, 511);
            strncpy(rr->value_name, val_name, 255);
            strncpy(rr->value_data, (char*)val_data, MAX_PATH - 1);
        }
        RegCloseKey(hKey);
    }
}

/* ==========================================================================
   SCHEDULED TASKS  (COM / Task Scheduler API)
   ========================================================================== */

static void capture_tasks_recursive(ITaskFolder* pFolder, SystemSnapshot* s);

static void capture_tasks(SystemSnapshot* s)
{
    ITaskService* pSvc = NULL;
    if (FAILED(CoCreateInstance(&CLSID_TaskScheduler, NULL,
        CLSCTX_INPROC_SERVER, &IID_ITaskService,
        (void**)&pSvc))) return;

    VARIANT empty = { 0 };
    if (FAILED(pSvc->lpVtbl->Connect(pSvc, empty, empty, empty, empty)))
        goto tasks_done;

    ITaskFolder* pRoot = NULL;
    BSTR rootPath = SysAllocString(L"\\");
    if (SUCCEEDED(pSvc->lpVtbl->GetFolder(pSvc, rootPath, &pRoot)))
        capture_tasks_recursive(pRoot, s);
    SysFreeString(rootPath);
    if (pRoot) pRoot->lpVtbl->Release(pRoot);

tasks_done:
    pSvc->lpVtbl->Release(pSvc);
}

static void capture_tasks_recursive(ITaskFolder* pFolder, SystemSnapshot* s)
{
    IRegisteredTaskCollection* pTasks = NULL;
    if (SUCCEEDED(pFolder->lpVtbl->GetTasks(pFolder, 0, &pTasks))) {
        LONG count = 0;
        pTasks->lpVtbl->get_Count(pTasks, &count);

        for (LONG i = 1; i <= count && s->task_count < MAX_TASKS; i++) {
            IRegisteredTask* pTask = NULL;
            VARIANT idx; idx.vt = VT_INT; idx.intVal = i;
            if (FAILED(pTasks->lpVtbl->get_Item(pTasks, idx, &pTask)))
                continue;

            TaskEntry* te = &s->tasks[s->task_count++];
            memset(te, 0, sizeof(*te));

            BSTR bname = NULL;
            if (SUCCEEDED(pTask->lpVtbl->get_Name(pTask, &bname)) && bname) {
                WideCharToMultiByte(CP_ACP, 0, bname, -1,
                    te->name, 255, NULL, NULL);
                SysFreeString(bname);
            }
            BSTR bpath = NULL;
            if (SUCCEEDED(pTask->lpVtbl->get_Path(pTask, &bpath)) && bpath) {
                WideCharToMultiByte(CP_ACP, 0, bpath, -1,
                    te->path, 255, NULL, NULL);
                SysFreeString(bpath);
            }
            VARIANT_BOOL en;
            if (SUCCEEDED(pTask->lpVtbl->get_Enabled(pTask, &en)))
                te->enabled = (en == VARIANT_TRUE);

            /* Get first action */
            ITaskDefinition* pDef = NULL;
            if (SUCCEEDED(pTask->lpVtbl->get_Definition(pTask, &pDef))) {
                IActionCollection* pActs = NULL;
                if (SUCCEEDED(pDef->lpVtbl->get_Actions(pDef, &pActs))) {
                    LONG acnt = 0;
                    pActs->lpVtbl->get_Count(pActs, &acnt);
                    if (acnt > 0) {
                        IAction* pAct = NULL;
                        /* IActionCollection::get_Item takes a plain long,
                         * NOT a VARIANT -- unlike IRegisteredTaskCollection
                         * and ITaskFolderCollection which do take VARIANT.  */
                        if (SUCCEEDED(pActs->lpVtbl->get_Item(
                            pActs, (long)1, &pAct))) {
                            TASK_ACTION_TYPE at;
                            if (SUCCEEDED(pAct->lpVtbl->get_Type(pAct, &at))
                                && at == TASK_ACTION_EXEC) {
                                IExecAction* pEx = NULL;
                                if (SUCCEEDED(pAct->lpVtbl->QueryInterface(
                                    pAct, &IID_IExecAction,
                                    (void**)&pEx))) {
                                    BSTR bexe = NULL;
                                    if (SUCCEEDED(pEx->lpVtbl->get_Path(
                                        pEx, &bexe)) && bexe) {
                                        WideCharToMultiByte(CP_ACP, 0,
                                            bexe, -1, te->action,
                                            MAX_PATH - 1, NULL, NULL);
                                        SysFreeString(bexe);
                                    }
                                    pEx->lpVtbl->Release(pEx);
                                }
                            }
                            pAct->lpVtbl->Release(pAct);
                        }
                    }
                    pActs->lpVtbl->Release(pActs);
                }

                /* Author */
                IRegistrationInfo* pReg = NULL;
                if (SUCCEEDED(pDef->lpVtbl->get_RegistrationInfo(
                    pDef, &pReg))) {
                    BSTR bauth = NULL;
                    if (SUCCEEDED(pReg->lpVtbl->get_Author(
                        pReg, &bauth)) && bauth) {
                        WideCharToMultiByte(CP_ACP, 0, bauth, -1,
                            te->author, 255, NULL, NULL);
                        SysFreeString(bauth);
                    }
                    pReg->lpVtbl->Release(pReg);
                }
                pDef->lpVtbl->Release(pDef);
            }

            /* Signature */
            if (te->action[0] != '\0')
                te->signature_valid = legit_verify_signature(te->action);

            pTask->lpVtbl->Release(pTask);
        }
        pTasks->lpVtbl->Release(pTasks);
    }

    /* Recurse into sub-folders */
    ITaskFolderCollection* pFolders = NULL;
    if (SUCCEEDED(pFolder->lpVtbl->GetFolders(pFolder, 0, &pFolders))) {
        LONG fcnt = 0;
        pFolders->lpVtbl->get_Count(pFolders, &fcnt);
        for (LONG i = 1; i <= fcnt; i++) {
            ITaskFolder* pSub = NULL;
            VARIANT vi; vi.vt = VT_INT; vi.intVal = i;
            if (SUCCEEDED(pFolders->lpVtbl->get_Item(pFolders, vi, &pSub))) {
                capture_tasks_recursive(pSub, s);
                pSub->lpVtbl->Release(pSub);
            }
        }
        pFolders->lpVtbl->Release(pFolders);
    }
}

/* ==========================================================================
   SNAPSHOT INTEGRITY HASH
   ========================================================================== */

BOOL snapshot_compute_self_hash(SystemSnapshot* snap)
{
    /* Zero out the hash field first so it doesn't affect the computation */
    BYTE saved[SHA256_LEN];
    memcpy(saved, snap->self_hash, SHA256_LEN);
    memset(snap->self_hash, 0, SHA256_LEN);

    BOOL ok = sha256_buf((const BYTE*)snap, sizeof(SystemSnapshot),
        snap->self_hash);
    if (!ok) memcpy(snap->self_hash, saved, SHA256_LEN);
    return ok;
}

BOOL snapshot_verify_integrity(const SystemSnapshot* snap)
{
    /* SystemSnapshot is ~3.2 MB -- allocate on heap, not stack (C6262). */
    SystemSnapshot* tmp = (SystemSnapshot*)HeapAlloc(
        GetProcessHeap(), 0, sizeof(SystemSnapshot));
    if (!tmp) return FALSE;

    memcpy(tmp, snap, sizeof(*tmp));
    memset(tmp->self_hash, 0, SHA256_LEN);

    BYTE computed[SHA256_LEN];
    BOOL ok = sha256_buf((const BYTE*)tmp, sizeof(*tmp), computed);
    HeapFree(GetProcessHeap(), 0, tmp);

    return ok && (memcmp(computed, snap->self_hash, SHA256_LEN) == 0);
}

/* ==========================================================================
   MAIN CAPTURE ENTRY POINT
   ========================================================================== */

BOOL snapshot_capture(SystemSnapshot* out, ULONGLONG seq)
{
    memset(out, 0, sizeof(*out));
    out->magic = SNAPSHOT_MAGIC;
    out->version = SNAPSHOT_VERSION;
    out->seq = seq;
    GetSystemTime(&out->captured_at);

    printf("[*] Enumerating processes (Toolhelp32)...\n");
    out->proc_count = capture_processes_toolhelp(out);

    printf("[*] Enumerating processes (PSAPI)...\n");
    capture_processes_psapi(out);

    printf("[*] Enumerating processes (WMI)...\n");
    capture_processes_wmi(out);

    printf("[*] Cross-checking PID lists...\n");
    cross_check_pids(out);

    printf("[*] Auditing process legitimacy...\n");
    legit_audit_snapshot(out);

    printf("[*] Enumerating loaded modules...\n");
    capture_modules(out);

    printf("[*] Enumerating network connections...\n");
    capture_network(out);

    printf("[*] Enumerating services...\n");
    capture_services(out);

    printf("[*] Reading registry auto-run keys...\n");
    capture_registry(out);

    printf("[*] Enumerating scheduled tasks...\n");
    /* CoInitializeEx may return S_FALSE if COM was already initialised
     * on this thread by the WMI path -- both S_OK and S_FALSE are success. */
    HRESULT hr_com = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    capture_tasks(out);
    if (SUCCEEDED(hr_com)) CoUninitialize();

    printf("[*] Computing snapshot integrity hash...\n");
    snapshot_compute_self_hash(out);

    return TRUE;
}

/* ==========================================================================
   SAVE / LOAD
   ========================================================================== */

BOOL snapshot_save(const SystemSnapshot* snap, const char* path)
{
    FILE* f = fopen(path, "wb");
    if (!f) return FALSE;
    BOOL ok = (fwrite(snap, sizeof(*snap), 1, f) == 1);
    fclose(f);
    return ok;
}

BOOL snapshot_load(SystemSnapshot* out, const char* path)
{
    FILE* f = fopen(path, "rb");
    if (!f) return FALSE;
    BOOL ok = (fread(out, sizeof(*out), 1, f) == 1);
    fclose(f);

    if (ok && out->magic != SNAPSHOT_MAGIC) {
        fprintf(stderr, "[!] Invalid snapshot magic -- file may be corrupt.\n");
        return FALSE;
    }
    if (ok && !snapshot_verify_integrity(out)) {
        fprintf(stderr, "[!] Snapshot integrity check FAILED -- tampered?\n");
        return FALSE;
    }
    return ok;
}

/* ==========================================================================
   PRINT SUMMARY
   ========================================================================== */

void snapshot_print_summary(const SystemSnapshot* snap)
{
    util_print_separator();
    /* seq is a Unix timestamp -- convert to readable local time */
    char seq_str[32] = { 0 };
    time_t t = (time_t)snap->seq;
    struct tm* tm_info = localtime(&t);
    if (tm_info)
        strftime(seq_str, sizeof(seq_str), "%Y-%m-%d %H:%M:%S", tm_info);
    else
        _snprintf(seq_str, sizeof(seq_str), "%llu", snap->seq);

    printf("  SNAPSHOT  %s  (captured %04d-%02d-%02d %02d:%02d:%02d UTC)\n",
        seq_str,
        snap->captured_at.wYear, snap->captured_at.wMonth,
        snap->captured_at.wDay, snap->captured_at.wHour,
        snap->captured_at.wMinute, snap->captured_at.wSecond);
    util_print_separator();

    char hex[65];
    sha256_to_hex(snap->self_hash, hex);
    printf("  Integrity hash : %.16s...%s\n", hex, hex + 48);
    printf("  Processes      : %u\n", snap->proc_count);
    printf("  Modules        : %u\n", snap->module_count);
    printf("  Connections    : %u\n", snap->conn_count);
    printf("  Services       : %u\n", snap->svc_count);
    printf("  Registry runs  : %u\n", snap->reg_count);
    printf("  Sched. tasks   : %u\n", snap->task_count);

    PidCrossCheck* cc = (PidCrossCheck*)&snap->pid_check;

    if (cc->wmi_timed_out) {
        util_log(SEV_WARN,
            "WMI source timed out -- cross-check ran on only 2 of 3 "
            "sources (Toolhelp32 + PSAPI). Hidden-PID detection is "
            "degraded for this snapshot.");
    }
    if (cc->hidden_count > 0) {
        util_log(SEV_CRITICAL,
            "HIDDEN PIDs detected (%u): processes visible to PSAPI/WMI "
            "but NOT to Toolhelp32 -- strong malware indicator!",
            cc->hidden_count);
        for (DWORD i = 0; i < cc->hidden_count; i++)
            printf("      PID %u\n", cc->hidden_pids[i]);
    }
    if (cc->phantom_count > 0) {
        util_log(SEV_WARN,
            "PHANTOM PIDs (%u): in Toolhelp32 but not PSAPI "
            "(may indicate rootkit or race condition)",
            cc->phantom_count);
        for (DWORD i = 0; i < cc->phantom_count; i++)
            printf("      PID %u\n", cc->phantom_pids[i]);
    }

    /* Legitimacy summary -- skip kernel pseudo-processes */
    DWORD bad_sig = 0, bad_path = 0, bad_ppid = 0, spoofed = 0, singletons = 0;
    for (DWORD i = 0; i < snap->proc_count; i++) {
        const ProcessEntry* pe = &snap->procs[i];
        if (pe->pid == 0 || pe->pid == 4) continue;
        if (pe->path[0] && !pe->signature_valid) bad_sig++;
        if (pe->path[0] && !pe->path_legit)      bad_path++;
        if (!pe->ppid_legit)                      bad_ppid++;
        if (pe->name_spoof)                       spoofed++;
        if (pe->singleton_violation)              singletons++;
    }
    printf("\n  Legitimacy audit:\n");
    printf("    Unsigned binaries      : %u\n", bad_sig);
    printf("    Out-of-place paths     : %u\n", bad_path);
    printf("    PPID anomalies         : %u\n", bad_ppid);
    printf("    Name-spoofed processes : %u\n", spoofed);
    printf("    Singleton violations   : %u\n\n", singletons);

    if (bad_sig + bad_path + bad_ppid + spoofed + singletons > 0)
        util_log(SEV_WARN,
            "Anomalies found -- run 'compare' or inspect individual "
            "processes for details.");
}
