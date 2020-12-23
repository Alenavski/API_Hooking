// API_Hooking.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <iostream>
#include <Windows.h>



int main()
{
    STARTUPINFOA* si = new STARTUPINFOA();
    PROCESS_INFORMATION* pi = new PROCESS_INFORMATION();
    std::wstring dll = L"..\\Debug\\HookingWorker.dll";
    if (!CreateProcessA("..\\Debug\\TestAPP.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, si, pi))
        printf("Can't create process.\n");
    void* loadLibraryW = GetProcAddress(GetModuleHandle(L"Kernel32"), "LoadLibraryW");
    
    LPVOID lpvMemory = VirtualAllocEx(pi->hProcess, NULL, dll.size() * sizeof(wchar_t) + 1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(pi->hProcess, lpvMemory, dll.c_str(), dll.size() * sizeof(wchar_t) + 1, NULL);

    HANDLE hRemoteThread = CreateRemoteThread(pi->hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibraryW, lpvMemory, NULL, NULL);
    WaitForSingleObject(hRemoteThread, INFINITE);
    CloseHandle(hRemoteThread);
    
    ResumeThread(pi->hThread);
    WaitForSingleObject(pi->hProcess, INFINITE);

    VirtualFreeEx(pi->hProcess, lpvMemory, 0, MEM_RELEASE);
    
    CloseHandle(pi->hProcess);
    CloseHandle(pi->hThread);
    
    std::cout << "Hello World!\n";
}
