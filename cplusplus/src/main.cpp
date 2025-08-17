#include <iostream>
#include <csignal>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include "core/telegram_session.hpp"
#include "core/message_handler.hpp"
#include "core/socket_server.hpp"
#include "nlohmann/json.hpp"

// TDLib wrappers
namespace utils {
    class ConfigLoader {
    public:
        explicit ConfigLoader(const std::string &path) : path_(path) {}
        nlohmann::json get() const {
            std::ifstream f(path_);
            if (!f.is_open()) throw std::runtime_error("Unable to open config file: " + path_);
            nlohmann::json j;
            f >> j;
            return j;
        }
    private:
        std::string path_;
    };
}

using json = nlohmann::json;

// Global pointers for graceful shutdown
static SocketServer* g_control_server = nullptr;
static MessageHandler* g_handler = nullptr;

static void signal_handler(int signal) {
    std::cerr << "\n[INFO] Termination signal (" << signal << ") received. Shutting down PhantomRoll..." << std::endl;

    // Stop Telegram session
    TelegramSession::get_instance().close();

    // Stop control server if running
    if (g_control_server) {
        g_control_server->stop();
    }

    // Stop handler if running
    if (g_handler) {
        g_handler->stop(); // You must ensure MessageHandler has stop() method
    }

    std::exit(signal);
}

void start_heartbeat() {
    std::thread([] {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(60));
            std::time_t now = std::time(nullptr);
            std::cout << "[HEARTBEAT] PhantomRoll alive at " << std::ctime(&now);
        }
    }).detach();
}

int main(int argc, char* argv[]) {
    std::cout.sync_with_stdio(true);
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    std::cout << "[INFO] PhantomRoll starting...\n";

    std::string session_suffix = "default";
    bool debug_mode = false, force_login = false;
    std::string config_path;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") {
            std::cout << "Usage: PhantomRoll [--session SESSION_NAME] [--debug] [--login] [--config CONFIG_PATH]\n";
            return 0;
        } else if (arg == "--version") {
            std::cout << "PhantomRoll version 1.0.0\n";
            return 0;
        } else if (arg == "--session" && i + 1 < argc) {
            session_suffix = argv[++i];
        } else if (arg == "--debug") {
            debug_mode = true;
        } else if (arg == "--login") {
            force_login = true;
        } else if (arg == "--config" && i + 1 < argc) {
            config_path = argv[++i];
        }
    }

    std::cout << "╔══════════════════════════════════════════════╗\n";
    std::cout << "║  PhantomRoll - Stealth Telegram Dice Bot   ║\n";
    std::cout << "╚══════════════════════════════════════════════╝\n";

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    try {
        // Use config path from --config if provided, otherwise use default
        if (config_path.empty()) {
            config_path = std::filesystem::current_path().string() + "/resources/config/config.json";
        }
        std::cout << "[INFO] Using config: " << config_path << "\n";
        utils::ConfigLoader config(config_path);
        json settings = config.get();

        if (!settings.is_object() || !settings.contains("api_id") || !settings.contains("api_hash"))
            throw std::runtime_error("Missing 'api_id' or 'api_hash' in configuration.");

        TelegramSession& session = TelegramSession::get_instance();
        session.set_session_suffix(session_suffix);
        if (force_login) session.reset_session_files();
        session.initialize(settings);

        MessageHandler handler(session, settings);
        g_handler = &handler; // set global pointer

        auto logger = std::make_shared<Logger>(Logger::Level::INFO);
        SocketServer control_server(8879, logger);
        g_control_server = &control_server; // set global pointer

        // Start TCP socket server for GUI/production
        control_server.start();
        std::cout << "[INFO] Control server running on port 8879\n";

        // Authentication thread
        std::thread auth_thread([&]() { session.authenticate(); });

        while (!session.is_authorized()) {
            std::string input;
            std::cout << "Enter login code / 2FA (or 'exit'): ";
            std::getline(std::cin, input);
            if (input == "exit") {
                session.close();
                auth_thread.join();
                return EXIT_SUCCESS;
            }
            if (session.is_waiting_for_code()) session.submit_code_async(input);
            else if (session.is_waiting_for_password()) session.submit_2fa_async(input);
        }

        auth_thread.join();
        std::cout << "[INFO] Authenticated successfully.\n";

        std::thread handler_thread([&handler]() { handler.run(); });

        start_heartbeat();

        while (session.is_authorized()) std::this_thread::sleep_for(std::chrono::seconds(60));

        handler_thread.join();

    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << "\n";
        return EXIT_FAILURE;
    }

    return 0;
}

