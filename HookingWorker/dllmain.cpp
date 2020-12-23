// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include <Tlhelp32.h>
#include <string.h>
#include <stdlib.h>
#include <Winternl.h>
#include <Dbghelp.h>
#include <string>

#pragma comment(lib, "Dbghelp.lib")

#pragma pack(push)
#pragma pack(1)
struct far_jmp
{
    BYTE PushOp;
    PVOID PushArg;
    BYTE RetOp;
};
#pragma pack(pop)
HANDLE CurrProc;

far_jmp OldCreateFile, JmpCreateFile;
PVOID AdrCreateFile;
far_jmp OldWriteFile, JmpWriteFile;
PVOID AdrWriteFile;
far_jmp OldReadFile, JmpReadFile;
PVOID AdrReadFile;

HANDLE hStdOut;

VOID WriteLog(std::wstring message)
{
    WriteConsole(hStdOut, message.c_str(), message.size(), NULL, NULL);
}

HANDLE WINAPI NewCreateFile(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    DWORD Written;
    WriteProcessMemory(GetCurrentProcess(), AdrCreateFile, &OldCreateFile, sizeof(far_jmp), &Written);
    HANDLE ret = CreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    WriteLog(L"Log: Create file " + (std::wstring)lpFileName + L"\n");
    WriteProcessMemory(GetCurrentProcess(), AdrCreateFile, &JmpCreateFile, sizeof(far_jmp), &Written);
    return ret;
}
BOOL WINAPI NewWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    DWORD Written;
    WriteProcessMemory(GetCurrentProcess(), AdrWriteFile, &OldWriteFile, sizeof(far_jmp), &Written);
    BOOL ret = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    WriteLog(L"Log: Write to file\n");
    WriteProcessMemory(GetCurrentProcess(), AdrWriteFile, &JmpWriteFile, sizeof(far_jmp), &Written);
    return ret;
}
BOOL WINAPI NewReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    DWORD Written;
    WriteProcessMemory(GetCurrentProcess(), AdrReadFile, &OldReadFile, sizeof(far_jmp), &Written);
    BOOL ret = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    WriteLog(L"Log: Read from file\n");
    WriteProcessMemory(GetCurrentProcess(), AdrReadFile, &JmpReadFile, sizeof(far_jmp), &Written);
    return ret;
}

void SetHook(LPCSTR procName, LPCWSTR libName, PVOID procHandler, PVOID* procAdr, far_jmp* old_header, far_jmp* new_header)
{
    DWORD Written;

    *procAdr = GetProcAddress(GetModuleHandle(libName), procName);

    if (*procAdr == 0)
    {
        MessageBox(0, 0, 0, 0);
        return;
    }

    new_header->PushOp = 0x68;
    new_header->PushArg = procHandler;
    new_header->RetOp = 0xC3;

    ReadProcessMemory(GetCurrentProcess(), *procAdr, old_header, sizeof(far_jmp), &Written);
    WriteProcessMemory(GetCurrentProcess(), *procAdr, new_header, sizeof(far_jmp), &Written);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    DWORD Written;
    unsigned char bom[] = { 0xFF, 0xFE };
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        SetHook("CreateFileW", L"kernel32.dll", NewCreateFile, &AdrCreateFile, &OldCreateFile, &JmpCreateFile);
        SetHook("ReadFile", L"kernel32.dll", NewReadFile, &AdrReadFile, &OldReadFile, &JmpReadFile);
        SetHook("WriteFile", L"kernel32.dll", NewWriteFile, &AdrWriteFile, &OldWriteFile, &JmpWriteFile);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        CloseHandle(hStdOut);
        break;
    }
    return TRUE;
}

