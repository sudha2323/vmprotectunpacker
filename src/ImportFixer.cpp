#include "vmprotectunpacker/ImportFixer.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <capstone/capstone.h>
#include "vmprotectunpacker/PEParser.h"
#include "vmprotectunpacker/Logger.h"
#include "vmprotectunpacker/Utils.h"


ImportFixer::ImportFixer(const std::string& dumpedExePath)
    : dumpedPath(dumpedExePath) {}

bool ImportFixer::LoadBinary() {
    std::ifstream file(dumpedPath, std::ios::binary);
    if (!file) return false;

    binary = std::vector<BYTE>(std::istreambuf_iterator<char>(file), {});
    return true;
}

bool ImportFixer::FixImports() {
    if (!LoadBinary()) return false;
    Logger::Log("[*] Loaded dumped binary. Fixing imports...");

    
    guessedImports["kernel32.dll"] = {"LoadLibraryA", "GetProcAddress"};

    return RebuildImportTable();
}

bool ImportFixer::RebuildImportTable() {
    
    Logger::Log("[*] Rebuilding Import Table...");
   
    return true;
}

bool ImportFixer::SaveFixedBinary(const std::string& outputPath) {
    std::ofstream out(outputPath, std::ios::binary);
    if (!out) return false;

    out.write(reinterpret_cast<const char*>(binary.data()), binary.size());
    return true;
}

DWORD ImportFixer::RVAToOffset(DWORD rva) {
    PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(binary.data());
    PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(binary.data() + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        DWORD sectionStartRVA = section->VirtualAddress;
        DWORD sectionEndRVA = sectionStartRVA + section->Misc.VirtualSize;
        if (rva >= sectionStartRVA && rva < sectionEndRVA) {
            return rva - sectionStartRVA + section->PointerToRawData;
        }
    }
    return 0;
}
void ImportFixer::Fix(PEParser& parser) {
    
    auto importMap = ScanForImports(parser);

    if (importMap.empty()) {
        Logger::Log("[-] No valid imports detected to fix.", LogLevel::WARNING);
        return;
    }

    Logger::Log("[+] Rebuilding import table...", LogLevel::INFO);

    BYTE* image = parser.GetMappedImage();
    size_t imageSize = parser.GetImageSize();
    PIMAGE_NT_HEADERS nt = parser.GetNtHeaders();

    
    IMAGE_SECTION_HEADER newSec = { 0 };
    strcpy_s((char*)newSec.Name,8, ".idata");

    newSec.Misc.VirtualSize = 0x1000;
    newSec.SizeOfRawData = 0x1000;
    newSec.VirtualAddress = ALIGN(nt->OptionalHeader.SizeOfImage, nt->OptionalHeader.SectionAlignment);
    newSec.PointerToRawData = ALIGN(imageSize, nt->OptionalHeader.FileAlignment);
    newSec.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    
    auto allSections = parser.GetAllSectionHeaders();
    BYTE* extendedImage = new BYTE[newSec.PointerToRawData + newSec.SizeOfRawData];
    memcpy(extendedImage, image, imageSize);
    memset(extendedImage + newSec.PointerToRawData, 0, newSec.SizeOfRawData);

    BYTE* idataBase = extendedImage + newSec.PointerToRawData;
    DWORD idataRVA = newSec.VirtualAddress;
    DWORD offset = 0;

    std::vector<IMAGE_IMPORT_DESCRIPTOR> descriptors;

    for (auto& pair : importMap) {
        const std::string& dll = pair.first;
        const auto& funcs = pair.second;

        DWORD thunkRVA = idataRVA + offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) * (importMap.size() + 1);
        DWORD nameRVA = thunkRVA + (funcs.size() + 1) * sizeof(IMAGE_THUNK_DATA);

        IMAGE_IMPORT_DESCRIPTOR desc = { 0 };
        desc.OriginalFirstThunk = thunkRVA;
        desc.FirstThunk = thunkRVA;

        DWORD thunkOffset = nameRVA;
        DWORD thunkIndex = 0;

        for (const auto& func : funcs) {
            DWORD hintNameRVA = idataRVA + thunkOffset;
            IMAGE_THUNK_DATA thunk = { 0 };
            thunk.u1.AddressOfData = hintNameRVA;
            memcpy(idataBase + thunkRVA + thunkIndex * sizeof(IMAGE_THUNK_DATA), &thunk, sizeof(thunk));

            WORD hint = 0;
            memcpy(idataBase + thunkOffset, &hint, sizeof(hint));
            strcpy_s((char*)(idataBase + thunkOffset + 2), 100, func.c_str());

            thunkOffset += 2 + (DWORD)func.length() + 1;
            thunkIndex++;
        }

       
        IMAGE_THUNK_DATA zeroThunk = { 0 };
        memcpy(idataBase + thunkRVA + thunkIndex * sizeof(IMAGE_THUNK_DATA), &zeroThunk, sizeof(zeroThunk));

        
        DWORD dllNameRVA = idataRVA + thunkOffset;
        strcpy_s((char*)(idataBase + thunkOffset), 100, dll.c_str());
        desc.Name = dllNameRVA;

        descriptors.push_back(desc);

        offset = thunkOffset + (DWORD)dll.length() + 1;
    }

   
    for (size_t i = 0; i < descriptors.size(); ++i) {
        memcpy(idataBase + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), &descriptors[i], sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }

    IMAGE_IMPORT_DESCRIPTOR nullDesc = { 0 };
    memcpy(idataBase + descriptors.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR), &nullDesc, sizeof(nullDesc));

    
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = newSec.VirtualAddress;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = offset;

   
    PIMAGE_SECTION_HEADER newSecPtr = IMAGE_FIRST_SECTION(nt) + nt->FileHeader.NumberOfSections;
    *newSecPtr = newSec;
    nt->FileHeader.NumberOfSections++;
    nt->OptionalHeader.SizeOfImage = newSec.VirtualAddress + ALIGN(newSec.SizeOfRawData, nt->OptionalHeader.SectionAlignment);

    
    parser.ReplaceImage(extendedImage, newSec.PointerToRawData + newSec.SizeOfRawData);
    delete[] extendedImage;

    Logger::Log("[+] Import table rebuilt and injected.", LogLevel::INFO);
}


std::map<std::string, std::set<std::string>> ImportFixer::ScanForImports(PEParser& parser) {
    std::map<std::string, std::set<std::string>> importMap;

    
    auto section = parser.GetSectionHeader(".text");
    if (!section) {
        Logger::Log("[-] .text section not found.", LogLevel::Error);
        return importMap;
    }

    BYTE* code = parser.GetMappedImage() + section->PointerToRawData;
    size_t codeSize = section->SizeOfRawData;
    DWORD codeVA = *(DWORD*)parser.RvaToVa(section->VirtualAddress);

    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        Logger::Log("[-] Capstone failed to initialize.", LogLevel::Error);
        return importMap;
    }

    count = cs_disasm(handle, code, codeSize, codeVA, 0, &insn);
    if (count <= 0) {
        cs_close(&handle);
        Logger::Log("[-] Disassembly failed.", LogLevel::Error);
        return importMap;
    }

    for (size_t i = 0; i < count; i++) {
        if (insn[i].id == X86_INS_CALL || insn[i].id == X86_INS_JMP) {
            cs_x86* x86 = &insn[i].detail->x86;
            if (x86->op_count == 1 && x86->operands[0].type == X86_OP_MEM) {
                uint64_t addr = x86->operands[0].mem.disp;
                // Check if address is inside IAT
                auto resolved = parser.ResolveIAT(addr);
                if (!resolved.first.empty() && !resolved.second.empty()) {
                    importMap[resolved.first].insert(resolved.second);
                }

            }
        }
    }

    cs_free(insn, count);
    cs_close(&handle);

    Logger::Log(Utils::Format("[*] Found %zu import DLLs.", importMap.size()), LogLevel::INFO);
    return importMap;
}
