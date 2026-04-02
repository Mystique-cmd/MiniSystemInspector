#include <windows.h> //Includes declarations for all the functions in the windows API
#include <tlhelp32.h> // provides declarations for the Tool Help Library
#include <stdio.h> // standard input and output

void procEnum() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Error: Could not create process snapshot.\n");
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        printf("Error: Could not retrieve first process.\n");
        CloseHandle(hSnapshot);
        return;
    }

    printf("PID\tParent PID\tProcess Name\n");
    printf("--------------------------------------------------\n");

    do {
        printf("%lu\t%lu\t\t%s\n", pe32.th32ProcessID, pe32.th32ParentProcessID, pe32.szExeFile);
        ThreadEnum(pe32.th32ProcessID); // Call ThreadEnum for each process
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
}

int main() {
    procEnum();
    return 0;
}

void ThreadEnum(DWORD dwOwnerPID){
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        printf("Error: Could not create thread snapshot.\n");
        return;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32)) {
        printf("Error: Could not retrieve first thread.\n");
        CloseHandle(hThreadSnap);
        return;
    }

    printf("\nThreads for Process ID: %lu\n", dwOwnerPID);
    printf("--------------------------------------------------\n");

    do {
        if (te32.th32OwnerProcessID == dwOwnerPID) {
            printf("  Thread ID: %lu\n", te32.th32ThreadID);
            // TODO: Use GetThreadContext to inspect registers (safe)
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
}


