#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include "vmprotectunpacker/Peparser.h"
#include <set>

class ImportFixer {
public:
    
    ImportFixer(const std::string& dumpedExePath);

   
    bool FixImports();

   
    bool SaveFixedBinary(const std::string& outputPath);
    static void Fix(PEParser& parser);

private:
    std::string dumpedPath;           
    std::vector<BYTE> binary;         
    #define ALIGN(val, align) (((val) + ((align)-1)) & ~((align)-1))


   
    bool LoadBinary();

    
    bool RebuildImportTable();
    static std::map<std::string, std::set<std::string>> ImportFixer::ScanForImports(PEParser& parser);

  
    IMAGE_IMPORT_DESCRIPTOR* CreateImportDescriptor(
        const std::string& dllName,
        const std::vector<std::string>& functions
    );

    
    DWORD RVAToOffset(DWORD rva);

   
    std::map<std::string, std::vector<std::string>> guessedImports;
};
