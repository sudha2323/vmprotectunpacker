#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include "vmprotectunpacker/Peparser.h"

class ShellcodeDumper {
public:
    ShellcodeDumper(const std::string& binaryPath);

    // Scans the binary for shellcode-like regions
    bool ScanForShellcode();

    // Dumps detected shellcode to a file
    bool DumpShellcode(const std::string& outputPath);
    void Dump(PEParser& parser);

private:
    std::string filePath;
    std::vector<BYTE> binaryData;

    // Shellcode candidate offsets and sizes
    struct Region {
        DWORD offset;
        DWORD size;
    };
    std::vector<Region> shellcodeRegions;

    // Heuristic function to detect shellcode
    bool IsShellcodeCandidate(const BYTE* data, size_t size);

    // Utility functions
    bool LoadBinary();
};
