#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>
#include <mutex>
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>

class Logger {
public:
    enum Level {
        INFO,
        WARNING,
        ERROR,
        DEBUG
    };

    // --- Constructors for instance-based logging ---
    explicit Logger(Level minLevel = INFO);

    // --- Instance methods ---
    void info(const std::string& message);
    void warn(const std::string& message);
    void error(const std::string& message);
    void debug(const std::string& message);

    // --- Global convenience wrappers ---
    static void infoGlobal(const std::string& message);
    static void warnGlobal(const std::string& message);
    static void errorGlobal(const std::string& message);
    static void debugGlobal(const std::string& message);
private:
    Level minLevel_;

    // Common log function
    static void log(const std::string& message, Level level);

    // Format timestamp
    static std::string timestamp();

    // Mutex for thread-safety
    static std::mutex log_mutex_;
};

#endif // LOGGER_HPP


