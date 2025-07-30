#pragma once

#include "PEParser.h"
#include <vector>
#include <string>
#include <Windows.h>

class BytecodeExtractor {
public:
    
    BytecodeExtractor(PEParser* parser);

    
    bool ExtractVMBytecode();

   
    static std::vector<BYTE> Extract(PEParser* parser) {
        BytecodeExtractor extractor(parser);
        if (extractor.ExtractVMBytecode()) {
            return extractor.GetExtractedBytecode();
        }
        return {};
    }

   
    const std::vector<BYTE>& GetExtractedBytecode() const;

    
    bool SaveBytecodeToFile(const std::string& outputPath);

private:
    // Attempts to locate a known VMProtect section name
    bool FindVMProtectSection(std::string& sectionName);
    bool IsRWX(const IMAGE_SECTION_HEADER* section);
    bool IsLikelyVMBytecode(BYTE* data, DWORD size);
    bool IsExecutableSection(const IMAGE_SECTION_HEADER* section);

private:
    PEParser* parser;
    std::vector<BYTE> extractedBytecode;
};
