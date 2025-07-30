#pragma once

#include <string>

enum class LogLevel {
    INFO,
    WARNING,
    Error,
    DEBUG
};

class Logger {
public:
    static void Init(const std::string& logfilePath);
    static void Log(const std::string& msg, LogLevel level = LogLevel::INFO);

private:
    static std::string logFile;
    static std::string GetPrefix(LogLevel level);
};
