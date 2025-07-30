#include "vmprotectunpacker/VMProtectDetector.h"
#include <iostream>
#include <cmath>
#include <map>
#include "vmprotectunpacker/Logger.h"
#include "vmprotectunpacker/Utils.h"

VMProtectDetector::VMProtectDetector(PEParser* parser) : parser(parser) {}

bool VMProtectDetector::IsVMProtectPresent() {
    if (CheckVMProtectSignature()) return true;
    if (CheckSectionEntropy()) return true;
    if (CheckEntryPointLocation()) return true;
    return false;
}

std::string VMProtectDetector::GetDetectionReason() {
    return detectionReason;
}

bool VMProtectDetector::CheckVMProtectSignature() {
    auto section = parser->GetSectionHeader(".vmp0");
    if (section) {
        detectionReason = ".vmp0 section found (VMProtect)";
        return true;
    }
    section = parser->GetSectionHeader(".vmp1");
    if (section) {
        detectionReason = ".vmp1 section found (VMProtect)";
        return true;
    }
    section = parser->GetSectionHeader(".themida");
    if (section) {
        detectionReason = ".themida section found (VMProtect/Themida)";
        return true;
    }
    return false;
}

bool VMProtectDetector::CheckEntryPointLocation() {
    auto nt = parser->GetNtHeaders();
    if (!nt) return false;

    DWORD epRVA = nt->OptionalHeader.AddressOfEntryPoint;
    DWORD imageBase = nt->OptionalHeader.ImageBase;

    auto sec = parser->GetSectionHeader(".text");
    if (sec) {
        DWORD textStart = sec->VirtualAddress;
        DWORD textEnd = textStart + sec->Misc.VirtualSize;

        if (epRVA < textStart || epRVA > textEnd) {
            detectionReason = "Entry point outside .text section";
            return true;
        }
    }
    return false;
}

bool VMProtectDetector::CheckSectionEntropy() {
    auto sec = parser->GetSectionHeader(".text");
    if (!sec) return false;

    BYTE* image = parser->GetMappedImage();
    if (!image) return false;

    BYTE* sectionData = image + sec->PointerToRawData;
    DWORD size = sec->SizeOfRawData;

    std::map<BYTE, int> freq;
    for (DWORD i = 0; i < size; ++i)
        freq[sectionData[i]]++;

    double entropy = 0.0;
    for (const auto& pair : freq) {
        double p = (double)pair.second / size;
        entropy -= p * std::log2(p);
    }

    if (entropy > 7.5) {
        detectionReason = "High entropy in .text section (Possible VMProtect)";
        return true;
    }
    return false;
}

bool VMProtectDetector::Detect(PEParser& parser, std::string& reason) {
    Logger::Log("[*] Starting VMProtectDetector::Detect...", LogLevel::INFO);
    VMProtectDetector detector(&parser);
    bool result = detector.IsVMProtectPresent();
    if (result) {
        reason = detector.GetDetectionReason();
        Logger::Log(Utils::Format("[+] VMProtect detected: %s", reason.c_str()), LogLevel::INFO);
        return result;
    }
}
