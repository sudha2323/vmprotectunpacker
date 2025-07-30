#include "vmprotectunpacker/BytecodeExtractor.h"
#include <fstream>
#include <iostream>
#include <capstone/capstone.h>
#include "vmprotectunpacker/Logger.h"
#include "vmprotectunpacker/Utils.h"


BytecodeExtractor::BytecodeExtractor(PEParser* parser)
    : parser(parser) {}

bool BytecodeExtractor::ExtractVMBytecode() {
    auto sections = parser->GetAllSectionHeaders();
    BYTE* base = parser->GetMappedImage();

    for (auto& sec : sections) {
        std::string secName = parser->SectionName(&sec);
        DWORD rawSize = sec.SizeOfRawData;

        if (rawSize == 0) {
            Logger::Log(Utils::Format("[!] Skipping section %s: raw size is 0", secName.c_str()), LogLevel::WARNING);

            // If it's executable, log it as suspicious
            if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
                Logger::Log(Utils::Format("[!] Section %s is executable but empty — may be runtime-modified (suspicious)", secName.c_str()), LogLevel::WARNING);
            }

            continue;
        }

        BYTE* data = base + sec.PointerToRawData;
        Logger::Log(Utils::Format("[+] Checking section: %s, size: %u", secName.c_str(), rawSize), LogLevel::DEBUG);

        if (IsLikelyVMBytecode(data, rawSize)) {
            extractedBytecode.assign(data, data + rawSize);
            Logger::Log(Utils::Format("[+] Extracted suspicious VM bytecode from: %s", secName.c_str()), LogLevel::INFO);
            return true;
        }
    }

    Logger::Log("[-] No candidate section matched VM bytecode heuristics.", LogLevel::Error);
    return false;
}



const std::vector<BYTE>& BytecodeExtractor::GetExtractedBytecode() const {
    return extractedBytecode;
}

bool BytecodeExtractor::SaveBytecodeToFile(const std::string& outputPath) {
    std::ofstream ofs(outputPath, std::ios::binary);
    if (!ofs) return false;
    ofs.write(reinterpret_cast<const char*>(extractedBytecode.data()), extractedBytecode.size());
    return true;
}

bool BytecodeExtractor::FindVMProtectSection(std::string& sectionName) {
    static const std::vector<std::string> vmpSections = {
        ".vmp0", ".vmp1", ".vmp2", ".themida", ".secure"
    };

    for (const auto& name : vmpSections) {
        if (parser->GetSectionHeader(name)) {
            sectionName = name;
            return true;
        }
    }
    return false;
}

bool BytecodeExtractor::IsLikelyVMBytecode(BYTE* data, DWORD size) {
    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return false;

    count = cs_disasm(handle, data, size, 0x0, 0, &insn);
    if (count == 0) {
        cs_close(&handle);
        Logger::Log("[-] Failed to disassemble bytecode as count is zero = suspicious: " + std::string(cs_strerror(cs_errno(handle))), LogLevel::Error);
        return true; // Failed to decode = suspicious
    }

    size_t invalidCount = 0;
    for (size_t i = 0; i < count; i++) {
        if (insn[i].id == X86_INS_INVALID)
            invalidCount++;
    }
    double ratio = (double)invalidCount / count;

    cs_free(insn, count);
    cs_close(&handle);

    return ratio > 0.3; // Arbitrary threshold
}

bool BytecodeExtractor::IsRWX(const IMAGE_SECTION_HEADER* section) {
    DWORD characteristics = section->Characteristics;

    bool isReadable  = (characteristics & IMAGE_SCN_MEM_READ)    != 0;
    bool isWritable  = (characteristics & IMAGE_SCN_MEM_WRITE)   != 0;
    bool isExecutable= (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

    return isReadable && isWritable && isExecutable;
}
bool BytecodeExtractor::IsExecutableSection(const IMAGE_SECTION_HEADER* section) {
    return (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}