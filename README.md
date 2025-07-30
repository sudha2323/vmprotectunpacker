# 🧩 VMProtectUnpacker

A custom C++ debugger that dynamically unpacks VMProtect-protected binaries, dumps in-memory decrypted code, and disassembles it using Capstone.

---

## 📁 Project Overview

This tool leverages a custom Windows debugger to:

- Launch protected binaries in suspended mode  
- Locate the real entry point (OEP) post-unpacking  
- Set an `INT3` breakpoint to capture unpacking  
- Dump memory of the real, unpacked executable  
- Disassemble the code using Capstone engine  

---

## 🛠️ Building with CMake

This project uses **CMake (v3.16 or higher)** and **C++17**. Capstone is required as an external dependency.

### ✅ Prerequisites

- Capstone Engine installed:
  - Headers: `C:/Program Files/capstone/include`  
  - Libs: `C:/Program Files/capstone/lib`
- CMake 3.16+
- Visual Studio (MSVC) or any C++17-compatible compiler

### 🏗️ Build Steps

```bash
# Clone the repo
git clone https://github.com/sudha2323/vmprotectunpacker.git
cd vmprotectunpacker

# Configure with CMake
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build --config Release
