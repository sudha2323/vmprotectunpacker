#include "vmprotectunpacker/Logger.h"
#include <fstream>
#include <iostream>
#include <ctime>
#include <sstream>

std::string Logger::logFile = "log.txt";

void Logger::Init(const std::string& logfilePath) {
    logFile = logfilePath;
    std::ofstream out(logFile, std::ios::trunc); // Clear existing log
    if (out.is_open()) {
        out << "==== VMProtect Unpacker Log Started ====\n";
        out.close();
    }
}

std::string Logger::GetPrefix(LogLevel level) {
    switch (level) {
        case LogLevel::INFO: return "[INFO] ";
        case LogLevel::WARNING: return "[WARNING] ";
        case LogLevel::Error: return "[Error] ";
        case LogLevel::DEBUG: return "[DEBUG]";
        default: return "[LOG] ";
    }
}

void Logger::Log(const std::string& msg, LogLevel level) {
    std::ofstream out(logFile, std::ios::app);
    if (!out.is_open()) return;

    // Timestamp
    std::time_t now = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &now);
#else
    localtime_r(&now, &tm);
#endif
    char timeBuf[32];
    std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", &tm);

    out << timeBuf << " " << GetPrefix(level) << msg << "\n";
    out.close();

    // Also print to console
    std::cout << GetPrefix(level) << msg << std::endl;
}
