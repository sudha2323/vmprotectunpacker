#pragma once

#include <string>
#include <vector>
#include <Windows.h>
#include <string>
#include <sstream>
#include <cstring>
#include <iomanip>


inline std::string ToHex(uintptr_t addr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(sizeof(uintptr_t) * 2) << std::setfill('0') << addr;
    return oss.str();
}

namespace Utils {

    
    inline DWORD Align(DWORD value, DWORD alignment) {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    
    inline DWORD PtrToRVA(BYTE* base, BYTE* ptr) {
        return static_cast<DWORD>(ptr - base);
    }

    
    inline bool ReadFileToBuffer(const std::string& filepath, std::vector<BYTE>& outBuffer) {
        HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            return false;

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
            CloseHandle(hFile);
            return false;
        }

        outBuffer.resize(fileSize);
        DWORD bytesRead = 0;
        bool result = ReadFile(hFile, outBuffer.data(), fileSize, &bytesRead, NULL);
        CloseHandle(hFile);
        return result && bytesRead == fileSize;
    }

    
    inline bool WriteBufferToFile(const std::string& filepath, const BYTE* data, DWORD size) {
        HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            return false;

        DWORD bytesWritten = 0;
        bool result = WriteFile(hFile, data, size, &bytesWritten, NULL);
        CloseHandle(hFile);
        return result && bytesWritten == size;
    }

    
    inline std::string ToHex(DWORD val) {
        char buf[16];
        sprintf_s(buf, "0x%08X", val);
        return std::string(buf);
    }

    
    inline std::string GetSectionName(PIMAGE_SECTION_HEADER section) {
        char name[9] = { 0 };
        memcpy(name, section->Name, 8);
        return std::string(name);
    }

    inline std::string FormatImpl(const char* fmt) {
        return std::string(fmt);
    }

    
    template<typename T, typename... Args>
    std::string FormatImpl(const char* fmt, T value, Args... args) {
        std::ostringstream oss;

        while (*fmt) {
            if (*fmt == '%' && *(fmt + 1) == 's' || *fmt == '%' && *(fmt + 1) == 'u' || *fmt == '0x%' && *(fmt + 1) == 'p') {
                oss << value;  
                fmt += 2;      
                oss << FormatImpl(fmt, args...); 
                return oss.str();
            }
            else {
                oss << *fmt++;
            }
        }

        return oss.str(); 
    }

    
    template<typename... Args>
   static std::string Format(const char* fmt, Args... args) {
        return FormatImpl(fmt, args...);
    }

}
