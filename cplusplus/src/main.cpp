#include <iostream>
#include <csignal>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <ctime>
#include <filesystem>

#include <td/telegram/td_json_client.h>
#include "utils/config_loader.hpp"
#include "core/telegram_session.hpp"
#include "core/message_handler.hpp"
#include "core/socket_server.hpp"
#include "nlohmann/json.hpp"

using json = nlohmann::json;
using namespace std;

static void signal_handler(int signal) {
    std::cerr << "\n[INFO] Termination signal (" << signal << ") received. Shutting down PhantomRoll cleanly..." << std::endl;
    TelegramSession::get_instance().close();
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
    std::cerr << ">>> If you're seeing this, PhantomRoll is alive but muted!" << std::endl;
    std::cout.sync_with_stdio(true);
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    std::cout << "[DEBUG] PhantomRoll starting..." << std::endl;
    std::string session_suffix = "default";
    bool debug_mode = false, force_login = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") {
            std::cout << "Usage: PhantomRoll [--session SESSION_NAME] [--debug] [--login]\n";
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
        }
    }

    std::cout << "\n\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║        幽影掷点 (PhantomRoll)                               ║\n";
    std::cout << "║  Stealth Telegram Dice Controller                           ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    try {
        std::string config_path = std::filesystem::current_path().string() + "/resources/config/config.json";
        std::cout << "[DEBUG] Using config path: " << config_path << std::endl;
        utils::ConfigLoader config(config_path);
        json settings = config.get();

        if (!settings.contains("api_id") || !settings.contains("api_hash")) {
            throw std::runtime_error("Missing 'api_id' or 'api_hash' in configuration.");
        }

        TelegramSession& session = TelegramSession::get_instance();
        session.set_session_suffix(session_suffix);
        if (force_login) session.reset_session_files();
        session.initialize(settings);

        std::cout << "[DEBUG] Launching control socket on port 8879..." << std::endl;

        MessageHandler handler(session, settings);  // ✅ Declare handler before socket

        try {
            SocketServer* control_server = new SocketServer(8879);
            std::thread socket_thread([&session, &handler, control_server]() {
                control_server->start([&session, &handler](const std::string& cmd) {
                    if (cmd == "START") {
                        std::cout << "[CONTROL] START command received.\n";
                    } else if (cmd == "STOP") {
                        std::cout << "[CONTROL] STOP command received.\n";
                        session.close();
                    } else if (cmd == "STATUS") {
                        std::cout << "[CONTROL] STATUS: Authorized = "
                                  << std::boolalpha << session.is_authorized() << std::endl;
                    } else if (cmd.rfind("send_dice", 0) == 0) {
                        std::cout << "[CONTROL] Dice command: " << cmd << std::endl;
                        handler.sendCommand(cmd);  // ✅ FIXED
                    } else {
                        std::cout << "[CONTROL] Unknown command: " << cmd << std::endl;
                    }
                });
            });
            socket_thread.detach();
            std::cout << "[SOCKET] Control server is running on port 8879.\n";
        } catch (const std::exception& e) {
            std::cerr << "[SOCKET ERROR] " << e.what() << std::endl;
        }

        session.authenticate();
        std::cout << "[INFO] Session initialized and authenticated.\n";

        std::thread handler_thread([&handler]() { handler.run(); });

        start_heartbeat();

        while (session.is_authorized()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        handler_thread.join();

    } catch (const std::exception& e) {
        std::cerr << "[FATAL ERROR] " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

