#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

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
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
}

int main() {
    procEnum();
    return 0;
}
