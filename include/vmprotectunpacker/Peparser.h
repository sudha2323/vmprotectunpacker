#pragma once
#include <windows.h>
#include <string>
#include <vector> 

class PEParser {
public:
    PEParser();
    ~PEParser();

    bool Load(const std::string& filepath);
    BYTE* GetMappedImage();
    size_t GetImageSize();
    PIMAGE_NT_HEADERS GetNtHeaders();
    PIMAGE_SECTION_HEADER GetSectionHeader(const std::string& name);
    std::vector<IMAGE_SECTION_HEADER> GetAllSectionHeaders();
    // Returns the name of a given IMAGE_SECTION_HEADER
    std::string SectionName(const IMAGE_SECTION_HEADER* section) const;
    bool PEParser::ReplaceImage(BYTE* newData, size_t newSize);
    BYTE* PEParser::RvaToVa(DWORD rva);
    std::pair<std::string, std::string> PEParser::ResolveIAT(uint64_t addr);
    std::string& PEParser::GetFilePath();
    bool Save(const std::string& outputPath) const;
    bool PEParser::LoadF(const std::string& filepath);
    DWORD GetOEP();
    DWORD GetImageBase();
    void PEParser::SetFilePath(std::string& outPath);

private:
    std::string filePath;
    HANDLE hFile;
    HANDLE hMapping;
    BYTE* mappedImage;
    size_t imageSize;
    bool isSuspendedDump = false;
};
