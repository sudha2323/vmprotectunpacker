#include <Windows.h>
#include <winternl.h>
#include <vector>
#include <fstream>
#include <sstream>
#include "vmprotectunpacker/VMPDebugger.h"
#include "vmprotectunpacker/Logger.h"
#include "vmprotectunpacker/Utils.h"
#include <capstone/capstone.h>
#include <iomanip>
#include <sstream>


bool VMPDebugger::Run(const std::string& exePath) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    Logger::Log("[*] Launching malware in suspended mode...");
    if (!CreateProcessA(exePath.c_str(), NULL, NULL, NULL, FALSE,
        DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        Logger::Log("[-] Failed to launch malware", LogLevel::Error);
        return false;
    }

    Logger::Log("[+] Malware launched in suspended mode");

    using pNtQueryInformationProcess = NTSTATUS(WINAPI*)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    auto NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        Logger::Log("[-] Failed to resolve NtQueryInformationProcess", LogLevel::Error);
        return false;
    }

    PROCESS_BASIC_INFORMATION pbi = {};
    NTSTATUS status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (status != 0) {
        Logger::Log("[-] NtQueryInformationProcess failed", LogLevel::Error);
        return false;
    }

    PVOID imageBase = nullptr;
    if (!ReadProcessMemory(pi.hProcess, (BYTE*)pbi.PebBaseAddress + 0x10, &imageBase, sizeof(PVOID), nullptr)) {
        Logger::Log("[-] Failed to read ImageBaseAddress from PEB", LogLevel::Error);
        return false;
    }

    BYTE headers[0x1000] = {};
    if (!ReadProcessMemory(pi.hProcess, imageBase, headers, sizeof(headers), nullptr)) {
        Logger::Log("[-] Failed to read PE headers", LogLevel::Error);
        return false;
    }

    auto* dos = (IMAGE_DOS_HEADER*)headers;
    auto* nt = (IMAGE_NT_HEADERS64*)((BYTE*)headers + dos->e_lfanew);
    DWORD oepRVA = nt->OptionalHeader.AddressOfEntryPoint;
    LPVOID oepVA = (BYTE*)imageBase + oepRVA;
    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;

    Logger::Log("[+] OEP: 0x" + ToHex((uintptr_t)oepVA));

    BYTE originalByte = 0;
    SIZE_T read, written;
    ReadProcessMemory(pi.hProcess, oepVA, &originalByte, 1, &read);
    BYTE int3 = 0xCC;
    WriteProcessMemory(pi.hProcess, oepVA, &int3, 1, &written);
    FlushInstructionCache(pi.hProcess, oepVA, 1);
    Logger::Log("[+] INT3 set at OEP");

    ResumeThread(pi.hThread);

    DEBUG_EVENT debugEvent = {};
    while (WaitForDebugEvent(&debugEvent, INFINITE)) {
        if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const auto& ex = debugEvent.u.Exception.ExceptionRecord;

            if (ex.ExceptionCode == EXCEPTION_BREAKPOINT && (LPVOID)ex.ExceptionAddress == oepVA) {
                Logger::Log("[+] OEP Breakpoint hit!");

                WriteProcessMemory(pi.hProcess, oepVA, &originalByte, 1, &written);
                FlushInstructionCache(pi.hProcess, oepVA, 1);

                // === Read PE headers again to locate section ===
                if (!ReadProcessMemory(pi.hProcess, imageBase, headers, sizeof(headers), nullptr)) {
                    Logger::Log("[-] Failed to re-read PE headers", LogLevel::Error);
                    break;
                }

                dos = (IMAGE_DOS_HEADER*)headers;
                nt = (IMAGE_NT_HEADERS64*)((BYTE*)headers + dos->e_lfanew);
                IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
                DWORD oepOffset = (DWORD)((uintptr_t)oepVA - (uintptr_t)imageBase);
                SIZE_T sectionSize = 0;

                for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                    DWORD start = sections[i].VirtualAddress;
                    DWORD end = start + sections[i].Misc.VirtualSize;
                    if (oepOffset >= start && oepOffset < end) {
                        sectionSize = sections[i].Misc.VirtualSize;
                        Logger::Log("[+] OEP is in section: " + std::string((char*)sections[i].Name, 8) +
                            " | RVA: 0x" + ToHex(start) +
                            " | Size: 0x" + ToHex(sectionSize));
                        break;
                    }
                }

                if (sectionSize == 0) {
                    Logger::Log("[-] Failed to locate section containing OEP", LogLevel::Error);
                    break;
                }

                SuspendThread(pi.hThread);

                Logger::Log("[*] Disassembling OEP region...");
                processHandle = pi.hProcess; // Ensure it's set before disassembling
                if (!Disassemble(oepVA, 0x1000)) {
                    Logger::Log("[-] Disassembly failed.", LogLevel::Error);
                }

                Logger::Log("[*] Dumping process memory...");
                if (!DumpProcessImage(pi.hProcess, imageBase, imageSize, "unpacked_dump.bin")) {
                    Logger::Log("[-] Dump failed.", LogLevel::Error);
                }
                else {
                    Logger::Log("[+] Process unpacked and dumped.");
                }
                break;
            }
        }
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
    }

    processHandle = pi.hProcess;
    threadHandle = pi.hThread;

    return true;
}




bool VMPDebugger::DumpProcessImage(HANDLE hProcess, LPVOID baseAddress, SIZE_T imageSize, const std::string& dumpPath) {
    std::vector<BYTE> buffer(imageSize);
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(hProcess, baseAddress, buffer.data(), imageSize, &bytesRead) || bytesRead != imageSize) {
        Logger::Log("[-] Failed to read memory from process for dump.", LogLevel::Error);
        return false;
    }

    // === Dump to file ===
    std::ofstream outFile(dumpPath, std::ios::binary);
    if (!outFile) {
        Logger::Log("[-] Failed to open dump file for writing.", LogLevel::Error);
        return false;
    }

    outFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    outFile.close();

    Logger::Log("[+] Memory dumped to: " + dumpPath);

    // === Dump to console in hex ===
    Logger::Log("[*] Memory (hex dump of first 512 bytes):");

    std::ostringstream oss;
    size_t maxBytes = std::min<size_t>(512, buffer.size());

    for (size_t i = 0; i < maxBytes; ++i) {
        if (i % 16 == 0) {
            oss << "\n0x" << std::hex << std::setw(8) << std::setfill('0') << i << ": ";
        }
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i] << " ";
    }

    Logger::Log(oss.str());
    return true;
}

bool VMPDebugger::Disassemble(LPVOID address, size_t size) {
    std::vector<uint8_t> buffer(size);
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(processHandle, address, buffer.data(), size, &bytesRead)) {
        Logger::Log("[-] Failed to read memory for disassembly", LogLevel::Error);
        return false;
    }

    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        Logger::Log("[-] Capstone failed to initialize", LogLevel::Error);
        return false;
    }

    count = cs_disasm(handle, buffer.data(), bytesRead, (uint64_t)address, 0, &insn);
    if (count > 0) {
        Logger::Log("[+] Disassembly at OEP:");
        for (size_t i = 0; i < count; i++) {
            std::ostringstream oss;
            oss << "0x" << std::hex << insn[i].address << ": "
                << insn[i].mnemonic << " " << insn[i].op_str;
            Logger::Log(oss.str());
        }
        cs_free(insn, count);
    }
    else {
        Logger::Log("[-] Failed to disassemble code", LogLevel::Error);
    }

    cs_close(&handle);
    return true;
}
