#include "vmprotectunpacker/Analyzer.h"
#include "vmprotectunpacker/Logger.h"
#include "vmprotectunpacker/PEParser.h"
#include <fstream>
#include <vector>
#include <capstone/capstone.h>

bool IsPEFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return false;

    uint16_t mz;
    file.read(reinterpret_cast<char*>(&mz), sizeof(mz));
    return mz == 0x5A4D; // 'MZ'
}

bool DisassembleShellcode(const std::vector<uint8_t>& shellcode, const std::string& outputPath = "disassembled_shellcode.txt") {
    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        Logger::Log("[-] Capstone failed to initialize", LogLevel::Error);
        return false;
    }

    count = cs_disasm(handle, shellcode.data(), shellcode.size(), 0x1000, 0, &insn);
    if (count > 0) {
        std::ofstream out(outputPath);
        if (!out) {
            Logger::Log("[-] Failed to open output file for disassembly", LogLevel::Error);
            cs_free(insn, count);
            cs_close(&handle);
            return false;
        }

        Logger::Log("[*] Disassembled Shellcode:", LogLevel::INFO);
        out << "Disassembled Shellcode:\n";

        for (size_t i = 0; i < count; i++) {
            char line[128];
            snprintf(line, sizeof(line), "0x%llx:\t%s\t%s",
                insn[i].address, insn[i].mnemonic, insn[i].op_str);
            out << line << "\n";
            //printf("%s\n", line);
        }

        out.close();
        Logger::Log("[+] Disassembly written to: " + outputPath, LogLevel::INFO);

        cs_free(insn, count);
        cs_close(&handle);
        return true;
    }
    else {
        Logger::Log("[-] Failed to disassemble shellcode", LogLevel::Error);
        cs_close(&handle);
        return false;
    }
}

bool Analyzer::AnalyzeDump(const std::string& filePath) {
    Logger::Log("[*] Starting analysis of unpacked dump...");

    if (IsPEFile(filePath)) {
        Logger::Log("[+] Detected valid PE file in dump.");
        PEParser parser;
        if (parser.Load(filePath)) {
            auto sections = parser.GetAllSectionHeaders();
            for (const auto& sec : sections) {
                printf("[*] Section: %s | Size: 0x%X\n", sec.Name, sec.SizeOfRawData);
            }
            Logger::Log("[+] Static analysis complete.");
        } else {
            Logger::Log("[-] Failed to parse PE for analysis.");
        }
    } else {
        Logger::Log("[*] Dump is not a valid PE. Treating as raw shellcode.");
        std::ifstream in(filePath, std::ios::binary);
        std::vector<uint8_t> shellcode((std::istreambuf_iterator<char>(in)), {});
        return DisassembleShellcode(shellcode);
    }
}
