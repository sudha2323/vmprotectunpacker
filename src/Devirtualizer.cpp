#include "vmprotectunpacker/Devirtualizer.h"
#include "vmprotectunpacker/Logger.h"
#include <capstone/capstone.h>
#include <fstream>
#include "vmprotectunpacker/Utils.h"



std::unordered_map<uint64_t, Devirtualizer::HandlerEntry> Devirtualizer::handlerMap;


Devirtualizer::Devirtualizer(BytecodeExtractor* extractor) : extractor(extractor) {
    bytecode = extractor->GetExtractedBytecode();
}

bool Devirtualizer::AnalyzeHandlers() {
    if (bytecode.empty()) return false;
    BuildHandlerMap();
    return true;
}

void Devirtualizer::BuildHandlerMap() {
    // Example static mapping - to be replaced with more accurate analysis
    handlerOpcodes[0x01] = "MOV";
    handlerOpcodes[0x02] = "ADD";
    handlerOpcodes[0x03] = "SUB";
    handlerOpcodes[0x04] = "XOR";
    handlerOpcodes[0x05] = "JMP";
    // Add more as discovered
}

std::string Devirtualizer::DisassembleInstruction(BYTE opcode) {
    if (handlerOpcodes.count(opcode))
        return handlerOpcodes[opcode];
    else
        return "UNKNOWN";
}

bool Devirtualizer::DevirtualizeToFile(const std::string& outPath) {
    std::ofstream out(outPath);
    if (!out.is_open()) return false;

    for (BYTE b : bytecode) {
        std::string instr = DisassembleInstruction(b);
        out << instr << "\n";
    }

    out.close();
    return true;
}
bool Devirtualizer::Devirtualize(PEParser* parser, const BYTE* region) {
    
    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        Logger::Log("[-] Capstone init failed.", LogLevel::Error);
        return false;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    Logger::Log("[*] Disassembling VM region for handler stubs...");

    const size_t scanSize = 0x1000;  
    count = cs_disasm(handle, region, scanSize, (uint64_t)region, 0, &insn);

    if (count > 1) {
        for (size_t i = 0; i < count - 1; ++i) {
            cs_insn& movInst = insn[i];
            cs_insn& jmpInst = insn[i + 1];

            if (movInst.id == X86_INS_MOV && jmpInst.id == X86_INS_JMP &&
                movInst.detail && jmpInst.detail) {

                auto& movOps = movInst.detail->x86.operands;
                auto& jmpOps = jmpInst.detail->x86.operands;

                if (movInst.detail->x86.op_count == 2 &&
                    movOps[0].type == X86_OP_REG &&
                    movOps[1].type == X86_OP_IMM &&
                    jmpInst.detail->x86.op_count == 1 &&
                    jmpOps[0].type == X86_OP_REG &&
                    movOps[0].reg == jmpOps[0].reg) {

                    HandlerEntry entry;
                    entry.address = movInst.address;
                    entry.target = movOps[1].imm;
                    entry.vOpcode = static_cast<uint32_t>(movOps[1].imm);

                    handlerMap[entry.address] = entry;

                    Logger::Log(
                        Utils::Format("[*] Handler found: VirtualOpcode=0x%02X at 0x%p → Handler=0x%p",
                            entry.vOpcode, entry.address, entry.target),
                        LogLevel::INFO
                    );
                }
            }
        }

        cs_free(insn, count);
    }
    else {
        Logger::Log("[-] Failed to disassemble VM region.", LogLevel::Error);
        cs_close(&handle);
        return false;
    }

    cs_close(&handle);
}
