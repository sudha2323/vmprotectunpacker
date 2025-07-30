#include "vmprotectunpacker/PEParser.h"
#include <iostream>
#include <fstream>
#include "vmprotectunpacker/Logger.h"
#include <winternl.h>

PEParser::PEParser() : filePath(""), hFile(NULL), hMapping(NULL), mappedImage(nullptr), imageSize(0) {}

PEParser::~PEParser() {
    if (mappedImage) UnmapViewOfFile(mappedImage);
    if (hMapping) CloseHandle(hMapping);
    if (hFile) CloseHandle(hFile);
}

bool PEParser::Load(const std::string& filepath) {
    filePath = filepath;

 
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    std::string cmdLine = "\"" + filepath + "\"";


    
    if (!CreateProcessA(
        filePath.c_str(),        
        NULL,                
        NULL, NULL,          
        FALSE,               
        CREATE_SUSPENDED,          
        NULL, NULL,          
        &si, &pi))           
    {
        Logger::Log("[-] Failed to create process in suspended mode.", LogLevel::Error);
        return false;
    }

    // Save the handle
    HANDLE hProcess = pi.hProcess;


    typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
        HANDLE,
        PROCESSINFOCLASS,
        PVOID,
        ULONG,
        PULONG
        );

    pfnNtQueryInformationProcess NtQueryInformationProcess =
        (pfnNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        Logger::Log("[-] Failed to resolve NtQueryInformationProcess.", LogLevel::Error);
        return false;
    }


    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen = 0;

    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &retLen
    );

    if (!NT_SUCCESS(status)) {
        Logger::Log("[-] NtQueryInformationProcess failed.", LogLevel::Error);
        return false;
    }


    PVOID pebAddress = pbi.PebBaseAddress;
    PVOID imageBaseAddr = nullptr;

    
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(
        pi.hProcess,
        (BYTE*)pebAddress + 0x10, // Offset to ImageBaseAddress
        &imageBaseAddr,
        sizeof(imageBaseAddr),
        &bytesRead)) {
        Logger::Log("[-] Failed to read ImageBaseAddress from PEB.", LogLevel::Error);
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    
    BYTE dosHeader[0x1000] = {};
    if (!ReadProcessMemory(pi.hProcess, imageBaseAddr, dosHeader, sizeof(dosHeader), &bytesRead)) {
        Logger::Log("[-] Failed to read DOS header.", LogLevel::Error);
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)dosHeader;
    IMAGE_NT_HEADERS64 nth = {};

    if (!ReadProcessMemory(pi.hProcess,
        (BYTE*)imageBaseAddr + idh->e_lfanew,
        &nth, sizeof(nth), &bytesRead)) {
        Logger::Log("[-] Failed to read NT headers.", LogLevel::Error);
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    SIZE_T imageSize = nth.OptionalHeader.SizeOfImage;
    mappedImage = new BYTE[imageSize];

    if (!ReadProcessMemory(pi.hProcess, imageBaseAddr, mappedImage, imageSize, &bytesRead)) {
        Logger::Log("[-] Failed to read full image from target process.", LogLevel::Error);
        TerminateProcess(pi.hProcess, 0);
        delete[] mappedImage;
        return false;
    }

    this->imageSize = imageSize;
    this->isSuspendedDump = true;

    Logger::Log("[+] Dumped process memory from suspended process.", LogLevel::INFO);

    
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return true;
}


BYTE* PEParser::GetMappedImage() {
    return mappedImage;
}

size_t PEParser::GetImageSize() {
    return imageSize;
}

PIMAGE_NT_HEADERS PEParser::GetNtHeaders() {
    if (!mappedImage) return nullptr;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mappedImage;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(mappedImage + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    return nt;
}

PIMAGE_SECTION_HEADER PEParser::GetSectionHeader(const std::string& name) {
    PIMAGE_NT_HEADERS nt = GetNtHeaders();
    if (!nt) return nullptr;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (std::string((char*)section->Name, strnlen((char*)section->Name, 8)) == name)
            return section;
    }

    return nullptr;
}

 std::vector<IMAGE_SECTION_HEADER> PEParser::GetAllSectionHeaders() {
        std::vector<IMAGE_SECTION_HEADER> sections;

        IMAGE_NT_HEADERS* ntHeaders = GetNtHeaders();
        if (!ntHeaders) return sections;

        IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
            sections.push_back(section[i]);
        }

        return sections;
    }

 std::string PEParser::SectionName(const IMAGE_SECTION_HEADER* section) const {
     if (!section) return "";

     char name[9] = { 0 }; 
     memcpy(name, section->Name, 8);

     return std::string(name);
 }
 bool PEParser::ReplaceImage(BYTE* newData, size_t newSize) {
     
     if (mappedImage) {
         UnmapViewOfFile(mappedImage);
         mappedImage = nullptr;
     }

     if (hMapping) {
         CloseHandle(hMapping);
         hMapping = nullptr;
     }

     if (hFile) {
         CloseHandle(hFile);
         hFile = nullptr;
     }

     
     mappedImage = new BYTE[newSize];
     if (!mappedImage) return false;

     memcpy(mappedImage, newData, newSize);
     imageSize = newSize;

     // Mark these as null since there's no file/mapping now
     hFile = nullptr;
     hMapping = nullptr;

     return true;
 }
 BYTE* PEParser::RvaToVa(DWORD rva) {
     PIMAGE_NT_HEADERS nt = GetNtHeaders();
     if (!nt) return nullptr;

     PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
     for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
         DWORD sectionStart = section->VirtualAddress;
         DWORD sectionEnd = sectionStart + max(section->Misc.VirtualSize, section->SizeOfRawData);

         if (rva >= sectionStart && rva < sectionEnd) {
             DWORD offset = rva - section->VirtualAddress;
             return mappedImage + section->PointerToRawData + offset;
         }
     }

     // Fallback: within headers
     if (rva < nt->OptionalHeader.SizeOfHeaders) {
         return mappedImage + rva;
     }

     return nullptr;
 }
 std::pair<std::string, std::string> PEParser::ResolveIAT(uint64_t addr) {
     PIMAGE_NT_HEADERS nt = GetNtHeaders();
     if (!nt) return { "", "" };

     IMAGE_DATA_DIRECTORY importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
     if (importDir.VirtualAddress == 0 || importDir.Size == 0) {
         return { "", "" }; // No imports
     }

     IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)RvaToVa(importDir.VirtualAddress);
     if (!importDesc) return { "", "" };

     while (importDesc->Name) {
         const char* dllName = (const char*)RvaToVa(importDesc->Name);

         // Thunks: where the actual imported addresses are written
         IMAGE_THUNK_DATA* origThunk = (IMAGE_THUNK_DATA*)RvaToVa(importDesc->OriginalFirstThunk);
         IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)RvaToVa(importDesc->FirstThunk);

         if (!thunk) {
             importDesc++;
             continue;
         }

         for (; origThunk && thunk && origThunk->u1.AddressOfData; ++origThunk, ++thunk) {
             // Only handle imported-by-name (not ordinal)
             if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;

             IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)RvaToVa((DWORD)origThunk->u1.AddressOfData);
             if (!importByName) continue;

             void* iatAddress = (void*)(uintptr_t)(nt->OptionalHeader.ImageBase + thunk->u1.Function);
             if ((uint64_t)iatAddress == addr) {
                 return { std::string(dllName), std::string((char*)importByName->Name) };
             }
         }

         importDesc++;
     }

     return { "", "" }; // Not found
 }
 std::string& PEParser::GetFilePath() {
     return filePath;
 }

 void PEParser::SetFilePath(std::string& outPath) {
     filePath = outPath;
     Load(filePath);
 }


 bool PEParser::Save(const std::string& outputPath) const {
     if (!mappedImage || imageSize == 0) {
         return false;
     }

     std::ofstream outFile(outputPath, std::ios::binary);
     if (!outFile) {
         return false;
     }

     outFile.write(reinterpret_cast<const char*>(mappedImage), imageSize);
     return outFile.good();
 }

 bool PEParser::LoadF(const std::string& filepath) {
     filePath = filepath;

     
     hFile = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

     if (hFile == INVALID_HANDLE_VALUE) {
         Logger::Log("[-] Failed to open file: " + filepath, LogLevel::Error);
         return false;
     }

     
     DWORD signature = 0;
     DWORD bytesRead = 0;
     BOOL readOk = ReadFile(hFile, &signature, sizeof(DWORD), &bytesRead, NULL);

     if (!readOk || signature != 0x5A4D) {
         Logger::Log("[-] File is not a valid PE (missing MZ header): " + filepath, LogLevel::Error);
         CloseHandle(hFile);
         return false;
     }

     
     SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

    
     hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
     if (!hMapping) {
         Logger::Log("[-] Failed to create file mapping.", LogLevel::Error);
         CloseHandle(hFile);
         return false;
     }

     
     mappedImage = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
     if (!mappedImage) {
         Logger::Log("[-] Failed to map view of file.", LogLevel::Error);
         CloseHandle(hMapping);
         CloseHandle(hFile);
         return false;
     }

    
     imageSize = GetFileSize(hFile, NULL);
     Logger::Log("[+] Successfully loaded PE file: " + filepath, LogLevel::INFO);

     return true;
 }

 DWORD PEParser::GetOEP() {
     DWORD addressofentrypoint = GetNtHeaders()->OptionalHeader.AddressOfEntryPoint;
     return (!addressofentrypoint) ? 0 : addressofentrypoint;

 }

 DWORD PEParser::GetImageBase() {
     DWORD imgBase = GetNtHeaders()->OptionalHeader.ImageBase;
     return(!imgBase) ? 0 : imgBase;
 }
