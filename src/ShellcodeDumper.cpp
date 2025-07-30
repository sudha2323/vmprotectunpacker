#include "vmprotectunpacker/ShellcodeDumper.h"
#include <fstream>
#include <iostream>
#include "vmprotectunpacker/Logger.h"
ShellcodeDumper::ShellcodeDumper(const std::string& binaryPath)
    : filePath(binaryPath) {}

bool ShellcodeDumper::LoadBinary() {
    std::ifstream file(filePath, std::ios::binary);
    if (!file)
        return false;

    file.seekg(0, std::ios::end);
    size_t size = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    binaryData.resize(size);
    file.read(reinterpret_cast<char*>(&binaryData[0]), size);
    return true;
}

bool ShellcodeDumper::IsShellcodeCandidate(const BYTE* data, size_t size) {
    // Heuristic: starts with common shellcode instructions (e.g., 0x55, 0xE8, 0x60) and contains high entropy
    if (size < 16) return false;

    if (data[0] == 0x60 || data[0] == 0x55 || data[0] == 0xE8) {
        int entropyScore = 0;
        for (size_t i = 0; i < 32 && i < size; ++i) {
            if (data[i] > 0x7F || data[i] == 0xCC || data[i] == 0x90) {
                entropyScore++;
            }
        }
        return entropyScore > 20;
    }

    return false;
}

bool ShellcodeDumper::ScanForShellcode() {
    if (!LoadBinary())
        return false;

    const size_t scanWindow = 512;

    for (size_t i = 0; i < binaryData.size() - scanWindow; i += 16) {
        if (IsShellcodeCandidate(&binaryData[i], scanWindow)) {
            Region region;
            region.offset = static_cast<DWORD>(i);
            region.size = static_cast<DWORD>(scanWindow);
            shellcodeRegions.push_back(region);
        }
    }

    std::cout << "[+] Found " << shellcodeRegions.size() << " possible shellcode region(s).\n";
    return !shellcodeRegions.empty();
}

bool ShellcodeDumper::DumpShellcode(const std::string& outputPath) {
    if (shellcodeRegions.empty()) {
        std::cerr << "[-] No shellcode found to dump.\n";
        return false;
    }

    std::ofstream out(outputPath, std::ios::binary);
    if (!out) {
        std::cerr << "[-] Failed to open output file.\n";
        return false;
    }

    for (const auto& region : shellcodeRegions) {
        out.write(reinterpret_cast<char*>(&binaryData[region.offset]), region.size);
    }

    std::cout << "[+] Shellcode dumped to: " << outputPath << "\n";
    return true;
}
void ShellcodeDumper::Dump(PEParser& parser) {
   
    

    Logger::Log("[*] Scanning for decrypted shellcode in: " + filePath, LogLevel::INFO);

    
    

    // Step 3: Scan for shellcode-like patterns
    if (ScanForShellcode()) {
        Logger::Log("[-] No shellcode patterns detected in the binary.", LogLevel::WARNING);
        return;
    }

    // Step 4: Create output dump path
    std::string dumpPath = "decrypted_shellcode.bin";

    // Step 5: Dump to file
    if (DumpShellcode(dumpPath)) {
        Logger::Log("[+] Shellcode successfully dumped to: " + dumpPath, LogLevel::INFO);
    }
    else {
        Logger::Log("[-] Shellcode dump failed.", LogLevel::Error);
    }
}