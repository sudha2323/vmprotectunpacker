#pragma once

#include <Windows.h>
#include <string>

class VMPDebugger {
public:
    VMPDebugger() = default;

    // Launches and debugs the VMProtect-packed binary
    bool Run(const std::string& exePath);

    // Optional: Access to internal handles
    HANDLE GetProcessHandle() const { return processHandle; }
    HANDLE GetThreadHandle() const { return threadHandle; }

private:
    HANDLE processHandle = nullptr;
    HANDLE threadHandle = nullptr;

    // Helper to dump memory to a file
    bool DumpProcessImage(HANDLE hProcess, LPVOID base, SIZE_T size, const std::string& outFile);
    bool Disassemble(LPVOID address, size_t size = 32);

};
