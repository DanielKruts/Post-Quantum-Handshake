# Post-Quantum-Handshake

> Repository for the development of an implementation of the NIST Post-Quantum standard NIPS203 document turned into a handshake between two devices. Specific parameter set used is ML-KEM-512

---

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installing MSYS2 and MinGW](#installing-msys2-and-mingw)
- [Installing Dependencies](#installing-dependencies)
  - [OpenSSL](#openssl)
  - [liboqs](#liboqs)
- [Building the Project](#building-the-project)
- [VS Code Setup](#vs-code-setup)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before cloning this project, ensure you have the following installed or another alternative to what I have proposed. For the sake of the project, this is what I used and the steps I took to develop the program files:

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

> ⚠️ **Note:** Some steps during the build may print warnings or say certain optional features are disabled — this is normal. Only hard `ERROR` messages require attention. Common safe-to-ignore messages include:
> - `Could NOT find Doxygen` — only affects documentation generation
> - `Disabling features requiring OpenSSL` — only affects hybrid schemes
> - `Tests disabled` — only affects running test suites

**4. Verify the installation:**
```bash
ls /mingw64/include/oqs
```

---

## Building the Project

1. Clone this repository:
```bash
git clone https://github.com/yourusername/yourproject.git
cd yourproject
```

2. Compile the project:
```bash
g++ main.cpp -o main -lws2_32 -lssl -lcrypto -loqs -lwsock32
```

3. Run the program:
```bash
./main
```

---

## VS Code Setup

If you are using VS Code, you will need to configure it to use the MinGW compiler.

**1. Install the C/C++ extension:**
- Open VS Code
- Press `Ctrl+Shift+X`
- Search for **"C/C++"** and install the extension by Microsoft

**2. Configure `c_cpp_properties.json`:**

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
            "compilerPath": "C:/msys64/mingw64/bin/g++.exe",
            "cStandard": "c17",
            "cppStandard": "c++17",
            "intelliSenseMode": "windows-gcc-x64"
        }
    ],
    "version": 4
}
```

**3. Configure `tasks.json`:**

Press `Ctrl+Shift+P` → **"Tasks: Configure Default Build Task"** and use:

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "type": "cppbuild",
            "label": "Build",
            "command": "C:/msys64/mingw64/bin/g++.exe",
            "args": [
                "-g",
                "${file}",
                "-o",
                "${fileDirname}/${fileBasenameNoExtension}.exe",
                "-lws2_32",
                "-lssl",
                "-lcrypto",
                "-loqs",
                "-lboost_system",
                "-lwsock32"
            ],
            "group": {
                "kind": "build",
                "isDefault": true
            }
        }
    ]
}
```

Press `Ctrl+Shift+B` to build.

---

## Troubleshooting

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
Make sure all link flags are present in your build command:
```bash
-lws2_32 -lssl -lcrypto -loqs -lboost_system -lwsock32
```

**"Squiggles disabled" warning in VS Code**
- Check the bottom right of VS Code and confirm the correct configuration is selected
- Press `Ctrl+Shift+P` → **"C/C++: Restart Language Server"**

---

## Dependencies Summary

| Library | Version | Install Method |
|---|---|---|
| OpenSSL | Latest | `pacman -S mingw-w64-x86_64-openssl` |
| liboqs | Latest | Built from source via CMake |
| Winsock2 | Built-in | Already included with Windows |
