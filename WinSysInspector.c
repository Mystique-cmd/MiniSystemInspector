#include <windows.h> 
#include <tlhelp32.h> 
#include <stdio.h> 
#include <winternl.h> // For UNICODE_STRING and OBJECT_INFORMATION_CLASS


// Structures and function pointers for NtQuerySystemInformation and NtQueryObject
typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    UCHAR ObjectTypeNumber;
    UCHAR Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// UNICODE_STRING is already defined in <winternl.h>

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG QuotaPoolUsage;
    ULONG Reserved[8];
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemHandleInformation = 16, // Corresponds to SYSTEM_HANDLE_INFORMATION
} SYSTEM_INFORMATION_CLASS;

// OBJECT_INFORMATION_CLASS is already defined in <winternl.h>

typedef NTSTATUS (NTAPI *_NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *_NtQueryObject)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

// Handle the case if these are not defined in older SDKs
#ifndef NTSTATUS
#define NTSTATUS LONG
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

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
        handleenum(pe32.th32ProcessID); // Call handleenum for each process
        memoryMapEnum(pe32.th32ProcessID); // Call memoryMapEnum for each process
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
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

void handleEnum(DWORD dwOwnerPID) {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) {
        printf("Error: Could not load ntdll.dll\n");
        return;
    }

    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    _NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");

    if (!NtQuerySystemInformation || !NtQueryObject) {
        printf("Error: Could not get address of NtQuerySystemInformation or NtQueryObject\n");
        FreeLibrary(hNtdll);
        return;
    }

    PSYSTEM_HANDLE_INFORMATION pHandleInfo = NULL;
    ULONG bufferSize = 0x10000; // Initial buffer size
    NTSTATUS status;

    do {
        pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(pHandleInfo, bufferSize);
        if (!pHandleInfo) {
            printf("Error: Failed to allocate memory for handle information.\n");
            FreeLibrary(hNtdll);
            return;
        }

        status = NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, bufferSize, &bufferSize);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize += 0x10000; // Increase buffer size and try again
        } else if (!NT_SUCCESS(status)) {
            printf("Error: NtQuerySystemInformation failed with status 0x%X\n", status);
            free(pHandleInfo);
            FreeLibrary(hNtdll);
            return;
        }

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    printf("\nHandles for Process ID: %lu\n", dwOwnerPID);
    printf("--------------------------------------------------\n");

    for (ULONG i = 0; i < pHandleInfo->HandleCount; i++) {
        SYSTEM_HANDLE sysHandle = pHandleInfo->Handles[i];

        // Filter handles by PID
        if (sysHandle.ProcessId != dwOwnerPID) {
            continue;
        }
        
        // Skip invalid handles or handles from the current process
        // GetCurrentProcessId() identifies the PID of the WinSysInspector itself
        if (sysHandle.Handle == 0 || sysHandle.ProcessId == GetCurrentProcessId()) {
            continue;
        }

        HANDLE hDuplicatedHandle = NULL;
        // Duplicate the handle
        // DUPLICATE_SAME_ACCESS ensures the duplicated handle has the same access rights
        // as the source handle, but we could also request specific access rights.
        if (!DuplicateHandle(
            OpenProcess(PROCESS_DUP_HANDLE, FALSE, sysHandle.ProcessId), // Source process handle
            (HANDLE)sysHandle.Handle,                                   // Source handle
            GetCurrentProcess(),                                        // Target process handle
            &hDuplicatedHandle,                                         // Duplicated handle
            0,                                                          // Desired access (ignored with DUPLICATE_SAME_ACCESS)
            FALSE,                                                      // Inherit handle
            DUPLICATE_SAME_ACCESS))                                     // Options
        {
            // If duplication fails, it might be due to insufficient access rights
            // or the handle being invalid. Continue to the next handle.
            continue;
        }

        // Query its type
        POBJECT_TYPE_INFORMATION pObjectTypeInfo = NULL;
        ULONG typeInfoSize = 0x1000; // Initial buffer size
        
        do {
            pObjectTypeInfo = (POBJECT_TYPE_INFORMATION)realloc(pObjectTypeInfo, typeInfoSize);
            if (!pObjectTypeInfo) {
                printf("Error: Failed to allocate memory for object type information.\n");
                break; // Break from inner loop, try next handle
            }

            status = NtQueryObject(
                hDuplicatedHandle,
                ObjectTypeInformation,
                pObjectTypeInfo,
                typeInfoSize,
                &typeInfoSize
            );

            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                // Buffer too small, reallocate and try again
                typeInfoSize += 0x1000;
            } else if (NT_SUCCESS(status)) {
                // Successfully got type information
                // Print handle value and type name
                wprintf(L"  Handle: 0x%X, Type: %.*s\n", sysHandle.Handle, 
                        pObjectTypeInfo->TypeName.Length / sizeof(WCHAR), 
                        pObjectTypeInfo->TypeName.Buffer);
            } else {
                // NtQueryObject failed for other reasons
                // printf("Error: NtQueryObject failed for handle 0x%X with status 0x%X\n", sysHandle.Handle, status);
            }

        } while (status == STATUS_INFO_LENGTH_MISMATCH);

        if (pObjectTypeInfo) {
            free(pObjectTypeInfo);
            pObjectTypeInfo = NULL;
        }
        if (hDuplicatedHandle) {
            CloseHandle(hDuplicatedHandle);
        }
    }

    if (pHandleInfo) {
        free(pHandleInfo);
    }
    FreeLibrary(hNtdll);
}

void memoryMapEnum(DWORD dwOwnerPID) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | VIRTUAL_MEM_READ, FALSE, dwOwnerPID);
    if (hProcess == NULL) {
        // printf("Error: Could not open process for PID %lu. Error: %lu\n", dwOwnerPID, GetLastError());
        return;
    }

    printf("\nMemory Map for Process ID: %lu\n", dwOwnerPID);
    printf("--------------------------------------------------\n");
    printf("Base Address\tSize\t\tProtection\n");
    printf("--------------------------------------------------\n");

    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID lpAddress = 0;

    while (VirtualQueryEx(hProcess, lpAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        printf("%p\t%lu\t\t", mbi.BaseAddress, mbi.RegionSize);

        // Interpret protection flags
        if (mbi.Protect == 0) { // No protection
            printf("---");
        } else {
            if (mbi.Protect & PAGE_READONLY) printf("R");
            if (mbi.Protect & PAGE_READWRITE) printf("RW");
            if (mbi.Protect & PAGE_EXECUTE) printf("X"); // Use X for execute
            if (mbi.Protect & PAGE_EXECUTE_READ) printf("RX");
            if (mbi.Protect & PAGE_EXECUTE_READWRITE) printf("RWX");
            // Add more common flags if needed, e.g., PAGE_NOACCESS, PAGE_GUARD
            // For simplicity, I'll focus on the primary access types.
        }
        
        printf("\n");

        // Move to the next region
        // This is crucial to avoid an infinite loop
        if (mbi.RegionSize == 0) { // Avoid infinite loop if RegionSize is somehow 0
            lpAddress = (LPCVOID)((char*)lpAddress + 4096); // Advance by a page size
        } else {
            lpAddress = (LPCVOID)((char*)mbi.BaseAddress + mbi.RegionSize);
        }
        if (lpAddress == NULL) break; // Reached end of address space (or overflowed)
    }

    CloseHandle(hProcess);
}



