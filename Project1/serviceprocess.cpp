#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>

#pragma comment(lib, "psapi.lib")

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

constexpr auto LOG_FILE = "C:\\Temp\\printprocess.log";

// Fonction pour écrire dans le log
void WriteLog(const char* msg) {
    FILE* f = nullptr;
    fopen_s(&f, LOG_FILE, "a");
    if (f) {
        fprintf(f, "%s\n", msg);
        fclose(f);
    }
}

// Fonction pour récupérer et loguer le PCB du worker
void LogProcessInfo(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        char buf[200];
        sprintf_s(buf, "OpenProcess a échoué. Code erreur: %lu", GetLastError());
        WriteLog(buf);
        return;
    }

    char buf[512];

    // Nom complet du processus
    char processPath[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameA(hProc, 0, processPath, &size)) {
        sprintf_s(buf, "Nom du processus: %s", processPath);
        WriteLog(buf);
    }
    else {
        sprintf_s(buf, "Nom du processus: impossible de récupérer (Code: %lu)", GetLastError());
        WriteLog(buf);
    }

    // PID
    sprintf_s(buf, "PID: %lu", pid);
    WriteLog(buf);

    // PPID
    DWORD ppid = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(hSnap, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    sprintf_s(buf, "PPID: %lu", ppid);
    WriteLog(buf);

    // Priorité
    DWORD priority = GetPriorityClass(hProc);
    sprintf_s(buf, "Priorité: %lu", priority);
    WriteLog(buf);

    // Mémoire
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
        sprintf_s(buf, "RAM utilisée (Working Set): %zu KB", pmc.WorkingSetSize / 1024);
        WriteLog(buf);
        sprintf_s(buf, "Mémoire virtuelle (Pagefile): %zu KB", pmc.PagefileUsage / 1024);
        WriteLog(buf);
    }

    // Threads
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap != INVALID_HANDLE_VALUE) {
        int threadCount = 0;
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(hThreadSnap, &te32)) {
            do {
                if (te32.th32OwnerProcessID == pid)
                    threadCount++;
            } while (Thread32Next(hThreadSnap, &te32));
        }
        CloseHandle(hThreadSnap);
        sprintf_s(buf, "Nombre de threads: %d", threadCount);
        WriteLog(buf);
    }

    // Temps CPU
    FILETIME creation, exit, kernel, user;
    if (GetProcessTimes(hProc, &creation, &exit, &kernel, &user)) {
        ULONGLONG kernelTime = (((ULONGLONG)kernel.dwHighDateTime << 32) | kernel.dwLowDateTime);
        ULONGLONG userTime = (((ULONGLONG)user.dwHighDateTime << 32) | user.dwLowDateTime);
        sprintf_s(buf, "Temps CPU Kernel: %llu µs", kernelTime / 10);
        WriteLog(buf);
        sprintf_s(buf, "Temps CPU User: %llu µs", userTime / 10);
        WriteLog(buf);
    }

    CloseHandle(hProc);
}

// Lancement du worker
void CreateProcessWorkerAndLog() {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    BOOL ok = CreateProcessA(
        "C:\\projetSe\\processusfils\\ARM64\\Debug\\processusfils.exe", // Chemin complet
        NULL,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!ok) {
        char buf[200];
        sprintf_s(buf, "Erreur CreateProcess - Code: %lu", GetLastError());
        WriteLog(buf);
        return;
    }

    WriteLog("processus fils lancé.");
    Sleep(1000); // attendre que le worker initialise

    // Log PCB du worker
    LogProcessInfo(pi.dwProcessId);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

// Thread du worker
DWORD WINAPI WorkerThread(LPVOID) {
    CreateProcessWorkerAndLog();
    return 0;
}

// Handler du service
void WINAPI ServiceCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP) {
        WriteLog("Service STOP demandé.");
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
    }
}

// Main du service
void WINAPI ServiceMain(DWORD, LPTSTR*) {
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    hStatus = RegisterServiceCtrlHandlerA("MonService", ServiceCtrlHandler);
    if (!hStatus) {
        WriteLog("Impossible de créer le handler du service.");
        return;
    }

    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hStatus, &ServiceStatus);
    WriteLog("Service lancé.");

    // Lancer worker dans un thread
    CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);

    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
        Sleep(1000);
    }
}

// Entrée principale
int main() {
    char serviceName[] = "MonService";
    SERVICE_TABLE_ENTRYA ServiceTable[] = {
        {serviceName, (LPSERVICE_MAIN_FUNCTIONA)ServiceMain},
        {NULL, NULL}
    };
    StartServiceCtrlDispatcherA(ServiceTable);
    return 0;
}
