# Post-Quantum-Handshake

> Repository for the development of an implementation of the NIST Post-Quantum standard FIPS 203 document turned into a handshake between two devices. Specific parameter set used is ML-KEM-512.

---

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installing MSYS2 and MinGW](#installing-msys2-and-mingw)
- [Installing Dependencies](#installing-dependencies)
  - [OpenSSL](#openssl)
  - [liboqs](#liboqs)
- [Building the Project](#building-the-project)
- [VS Code Setup](#vs-code-setup)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before cloning this project, ensure you have the following installed:

- **Windows 10/11** (64-bit)
- **MSYS2** — [Download here](https://www.msys2.org)
- **Git** — [Download here](https://git-scm.com)
- **VS Code** (optional) — [Download here](https://code.visualstudio.com)

> ⚠️ **Important:** Always use the **"MSYS2 MinGW x64"** terminal for all commands in this guide, NOT the plain "MSYS2 MSYS" terminal.

---

## Installing MSYS2 and MinGW

1. Download and install MSYS2 from [msys2.org](https://www.msys2.org)
2. Open **MSYS2 MinGW x64** from the Start Menu
3. Update the package database:
```bash
pacman -Syu
```
4. If the terminal closes, reopen it and run:
```bash
pacman -Su
```
5. Install the core MinGW toolchain:
```bash
pacman -S mingw-w64-x86_64-gcc
pacman -S mingw-w64-x86_64-make
```
6. Add MinGW to your Windows PATH:
   - Search **"Environment Variables"** in the Start Menu
   - Under **System Variables**, find and edit `Path`
   - Add: `C:\msys64\mingw64\bin`
   - Click OK and restart any open terminals

---

## Installing Dependencies

### OpenSSL

OpenSSL is available directly through the MSYS2 package manager:

```bash
pacman -S mingw-w64-x86_64-openssl
```

Verify the installation:
```bash
ls /mingw64/include/openssl
```

---

### liboqs

liboqs (Open Quantum Safe) must be built from source. Follow these steps carefully.

**1. Install build dependencies:**
```bash
pacman -S mingw-w64-x86_64-cmake
pacman -S mingw-w64-x86_64-ninja
pacman -S git
```

Verify CMake installed correctly:
```bash
cmake --version
```

**2. Clone the liboqs repository:**
```bash
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
```

**3. Build and install:**
```bash
mkdir build
cd build
cmake -G "Ninja" .. -DCMAKE_INSTALL_PREFIX=C:/msys64/mingw64
ninja
ninja install
```

> ⚠️ **Note:** Some warnings during the build are normal and safe to ignore:
> - `Could NOT find Doxygen` — only affects documentation generation
> - `Disabling features requiring OpenSSL` — only affects hybrid schemes
> - `Tests disabled` — only affects running test suites
>
> Only hard `ERROR` messages require attention.

**4. Verify the installation:**
```bash
ls /mingw64/include/oqs
ls /mingw64/include/openssl/evp.h
ls /mingw64/lib/liboqs.a
ls /mingw64/lib/libcrypto.a
```

All four paths should return file listings. If any are missing, re-run the relevant install step.

---

## Building the Project

This project uses **g++ directly** — no CMake required to build.

**1. Clone this repository:**
```bash
git clone https://github.com/yourusername/Post-Quantum-Handshake.git
cd Post-Quantum-Handshake
```

**2. Build the server:**
```bash
g++ -std=c++20 -g kem_utils.cpp server.cpp -o server.exe \
  -I C:/msys64/mingw64/include \
  -L C:/msys64/mingw64/lib \
  -lws2_32 -lwsock32 -lssl -lcrypto -loqs
```

**3. Build the client:**
```bash
g++ -std=c++20 -g kem_utils.cpp client.cpp -o client.exe \
  -I C:/msys64/mingw64/include \
  -L C:/msys64/mingw64/lib \
  -lws2_32 -lwsock32 -lssl -lcrypto -loqs
```

**4. Run the handshake:**

Open two separate terminals in the project folder. Start the server first, then the client:

```bash
# Terminal 1
./server.exe

# Terminal 2
./client.exe
```

You will see the handshake steps print across both terminals as they communicate.

> ⚠️ **Important:** `-std=c++20` is required. This project uses `std::span`, which was introduced in C++20 and is not available in C++17.

---

## VS Code Setup

### 1. Install the C/C++ extension
- Open VS Code
- Press `Ctrl+Shift+X`
- Search for **"C/C++"** and install the Microsoft extension

### 2. Configure `c_cpp_properties.json`

Press `Ctrl+Shift+P` → **"C/C++: Edit Configurations (JSON)"** and use:

```json
{
    "configurations": [
        {
            "name": "Win32",
            "includePath": [
                "${workspaceFolder}/**",
                "C:/msys64/mingw64/include",
                "C:/msys64/mingw64/lib/gcc/x86_64-w64-mingw32/15.2.0/include"
            ],
            "defines": [
                "_DEBUG",
                "UNICODE",
                "_UNICODE"
            ],
            "compilerPath": "C:/msys64/mingw64/bin/g++.exe",
            "cStandard": "c17",
            "cppStandard": "c++20",
            "intelliSenseMode": "windows-gcc-x64"
        }
    ],
    "version": 4
}
```

> ⚠️ `cppStandard` must be `c++20`, not `c++17`. Setting it to `c++17` will cause IntelliSense to flag `std::span` as an error even though the build itself works correctly.

### 3. Configure `tasks.json`

Press `Ctrl+Shift+P` → **"Tasks: Configure Default Build Task"** and use:

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "type": "cppbuild",
            "label": "Build Server",
            "command": "C:/msys64/mingw64/bin/g++.exe",
            "args": [
                "-std=c++20",
                "-g",
                "${workspaceFolder}/kem_utils.cpp",
                "${workspaceFolder}/server.cpp",
                "-o",
                "${workspaceFolder}/server.exe",
                "-I", "C:/msys64/mingw64/include",
                "-L", "C:/msys64/mingw64/lib",
                "-lws2_32",
                "-lwsock32",
                "-lssl",
                "-lcrypto",
                "-loqs"
            ],
            "options": {
                "cwd": "${workspaceFolder}"
            },
            "problemMatcher": ["$gcc"],
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "detail": "Builds server.exe from kem_utils + server"
        },
        {
            "type": "cppbuild",
            "label": "Build Client",
            "command": "C:/msys64/mingw64/bin/g++.exe",
            "args": [
                "-std=c++20",
                "-g",
                "${workspaceFolder}/kem_utils.cpp",
                "${workspaceFolder}/client.cpp",
                "-o",
                "${workspaceFolder}/client.exe",
                "-I", "C:/msys64/mingw64/include",
                "-L", "C:/msys64/mingw64/lib",
                "-lws2_32",
                "-lwsock32",
                "-lssl",
                "-lcrypto",
                "-loqs"
            ],
            "options": {
                "cwd": "${workspaceFolder}"
            },
            "problemMatcher": ["$gcc"],
            "group": "build",
            "detail": "Builds client.exe from kem_utils + client"
        }
    ]
}
```

- Press `Ctrl+Shift+B` to build the server (default task)
- Press `Ctrl+Shift+P` → **"Run Task"** → **"Build Client"** to build the client

---

## Project Structure

```
Post-Quantum-Handshake/
├── .vscode/
│   ├── c_cpp_properties.json   — IntelliSense configuration
│   └── tasks.json              — Build tasks for VS Code
├── kem_common.hpp              — Shared types, RAII classes, constants
├── kem_utils.cpp               — KEM operations, HKDF, socket framing
├── server.cpp                  — Server: keygen → send pubkey → decapsulate
├── client.cpp                  — Client: receive pubkey → encapsulate → send
└── README.md
```

---

## How It Works

The handshake follows these steps each time a connection is made:

```
  SERVER                                       CLIENT
    |                                             |
    |  1. Generate ML-KEM-512 key pair            |
    |                                             |
    |<---- MsgType::PubKey (800 bytes) -----------|
    |                                             |
    |              2. Encapsulate against pubkey  |
    |                 => ciphertext + sharedSecret|
    |                                             |
    |---- MsgType::Ciphertext (768 bytes) ------->|
    |                                             |
    |  3. Decapsulate ciphertext                  |
    |     => same sharedSecret as client          |
    |                                             |
    |  Both: HKDF-SHA256(sharedSecret)            |
    |        => 32-byte session key               |
    |                                             |
    |<---- MsgType::Finished -------------------->|
    |                                             |
    |         [ Encrypted application data ]      |
```

A fresh ephemeral key pair is generated for every connection, which means forward secrecy is built in by design — compromising one session's keys reveals nothing about past or future sessions.

---

## Security Notes

The following items are **not yet implemented** and are required before this can be used in production:

- **Server authentication** — the public key is currently sent unauthenticated. A MITM can substitute their own key. Fix by signing the public key with a long-term ML-DSA (Dilithium) signing key.
- **Nonce exchange** — add random nonces on both sides and use them as the HKDF salt to prevent replay attacks.
- **Transcript hashing** — hash the full handshake exchange and include it in the HKDF info field to bind the session key to the exact conversation.
- **AEAD for application data** — use the session key with AES-256-GCM or ChaCha20-Poly1305 to encrypt all post-handshake communication.

---

## Troubleshooting

**`Libraries not found` either liboqs or openSSL**
Check and make sure that you actually have installed them and can find the required libraries in their respective directories. You can always use the include testSockets.cpp file that tests to find the version numbers of your builds. You can do this by running
```powershell
g++ testSockets.cpp -o testVersion.exe -lws2_32 -lssl -lcrypto -loqs -lwsock32
```

**`std::span` errors or C++20 features not found**
Make sure `-std=c++20` is present in your build command and `cppStandard` is set to `c++20` in `c_cpp_properties.json`. This project will not compile under C++17.

**CMake command not found**
Make sure you are using the **MSYS2 MinGW x64** terminal and that CMake was installed with the correct prefix:
```bash
pacman -S mingw-w64-x86_64-cmake
```

**Headers not found in VS Code**
- Confirm `compilerPath` in `c_cpp_properties.json` points to `g++.exe`, not `cl.exe`
- Confirm `intelliSenseMode` is set to `windows-gcc-x64`, not `windows-msvc-x64`
- Press `Ctrl+Shift+P` → **"C/C++: Reset IntelliSense Database"**
- Fully restart VS Code

**Linker errors when compiling**
Make sure all link flags are present and in the correct order — source files and `-o` output first, all `-l` flags last:
```bash
g++ -std=c++20 kem_utils.cpp server.cpp -o server.exe -lws2_32 -lwsock32 -lssl -lcrypto -loqs
```

**`vector` or standard library types not found**
Standard library headers must be included before Windows headers in `kem_common.hpp`. The correct order is: standard library → Windows headers → third-party headers. See `kem_common.hpp` for the correct include order.

**"Squiggles disabled" warning in VS Code**
- Check the bottom right of VS Code and confirm the correct configuration is selected
- Press `Ctrl+Shift+P` → **"C/C++: Restart Language Server"**

---

## Dependencies Summary

| Library | Version | Install Method |
|---|---|---|
| OpenSSL | Latest | `pacman -S mingw-w64-x86_64-openssl` |
| liboqs | Latest | Built from source via CMake |
| Winsock2 | Built-in | Included with Windows SDK |
| g++ / MinGW64 | 15.x | `pacman -S mingw-w64-x86_64-gcc` |
