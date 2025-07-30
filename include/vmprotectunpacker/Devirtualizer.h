#pragma once

#include <vector>
#include <string>
#include <unordered_map>
#include "BytecodeExtractor.h"

class Devirtualizer {
public:
    Devirtualizer(BytecodeExtractor* extractor);

    bool AnalyzeHandlers();
    bool DevirtualizeToFile(const std::string& outPath);
    static bool Devirtualize(PEParser* parser,const BYTE* region);
    

private:
    BytecodeExtractor* extractor;
    std::vector<BYTE> bytecode;
    
   
    struct HandlerEntry {
        uint64_t address;  
        uint64_t target;   
        uint32_t vOpcode;  
    };
    static std::unordered_map<uint64_t, HandlerEntry> handlerMap;
    std::unordered_map<BYTE, std::string> handlerOpcodes;

    void BuildHandlerMap();
    std::string DisassembleInstruction(BYTE opcode);
};