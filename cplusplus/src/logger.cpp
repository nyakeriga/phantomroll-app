#include "core/logger.hpp"


std::mutex Logger::log_mutex_;

// --- Constructor for instance logger ---
Logger::Logger(Level minLevel) : minLevel_(minLevel) {}

// --- Instance methods ---
void Logger::info(const std::string& message)  { if (minLevel_ <= INFO)  log(message, INFO); }
void Logger::warn(const std::string& message)  { if (minLevel_ <= WARNING) log(message, WARNING); }
void Logger::error(const std::string& message) { if (minLevel_ <= ERROR) log(message, ERROR); }
void Logger::debug(const std::string& message) { if (minLevel_ <= DEBUG) log(message, DEBUG); }

// --- Global methods ---
void Logger::infoGlobal(const std::string& message)  { log(message, INFO); }
void Logger::warnGlobal(const std::string& message)  { log(message, WARNING); }
void Logger::errorGlobal(const std::string& message) { log(message, ERROR); }
void Logger::debugGlobal(const std::string& message) { log(message, DEBUG); }

// --- Common log function ---
void Logger::log(const std::string& message, Level level) {
    std::lock_guard<std::mutex> lock(log_mutex_);

    std::string levelStr;
    switch (level) {
        case INFO:    levelStr = "[INFO]"; break;
        case WARNING: levelStr = "[WARN]"; break;
        case ERROR:   levelStr = "[ERROR]"; break;
        case DEBUG:   levelStr = "[DEBUG]"; break;
    }

    std::cout << timestamp() << " " << levelStr << " " << message << std::endl;
}

// --- Timestamp helper ---
std::string Logger::timestamp() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto itt = system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &itt);
#else
    localtime_r(&itt, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}
