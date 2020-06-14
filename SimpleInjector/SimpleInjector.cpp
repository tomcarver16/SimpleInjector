#include <iostream>
#include <windows.h>
#include <TlHelp32.h>

//Opens a handle to process then write to process with LoadLibraryA and execute thread
BOOL InjectDll(DWORD procID, char* dllName) {
    char fullDllName[MAX_PATH];
    LPVOID loadLibrary;
    LPVOID remoteString;

    if (procID == 0) {
        return FALSE;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    if (hProc == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    GetFullPathNameA(dllName, MAX_PATH, fullDllName, NULL);
    std::cout << "[+] Aquired full DLL path: " << fullDllName << std::endl;

    loadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    remoteString = VirtualAllocEx(hProc, NULL, strlen(fullDllName), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    WriteProcessMemory(hProc, remoteString, fullDllName, strlen(fullDllName), NULL);
    CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibrary, (LPVOID)remoteString, NULL, NULL);

    CloseHandle(hProc);
    return TRUE;
}

//Iterate all process until the name we're searching for matches
//Then return the process ID
DWORD GetProcIDByName(const char* procName) {
    HANDLE hSnap;
    BOOL done;
    PROCESSENTRY32 procEntry;
    
    ZeroMemory(&procEntry, sizeof(PROCESSENTRY32));
    procEntry.dwSize = sizeof(PROCESSENTRY32);

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    done = Process32First(hSnap, &procEntry);
    do {
        if (_strnicmp(procEntry.szExeFile, procName, sizeof(procEntry.szExeFile)) == 0) {
            return procEntry.th32ProcessID;
        }
    } while (Process32Next(hSnap, &procEntry));
    
    return 0;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cout << "Sample Usage:" << std::endl;
        std::cout << argv[0] << " <name of process> <path of dll to load>";
        return 0;
    }
    const char* processName = argv[1];
    char* dllName = argv[2];
    DWORD procID = GetProcIDByName(processName);
    std::cout << "[+] Got process ID for " << processName << " PID: " << procID << std::endl;
    if (InjectDll(procID, dllName)) {
        std::cout << "DLL now injected!" << std::endl;
    } else {
        std::cout << "DLL couldn't be injected" << std::endl;
    }
    return 0;
}