#include "core/telegram_session.hpp"
#include <iostream>
#include <thread>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>

using json = nlohmann::json;

TelegramSession::TelegramSession() : client_(nullptr), authorized_(false) {}

TelegramSession::~TelegramSession() {
    close();
}

TelegramSession& TelegramSession::get_instance() {
    static TelegramSession instance;
    return instance;
}

void TelegramSession::set_session_suffix(const std::string& suffix) {
    session_suffix_ = suffix;
}

void TelegramSession::initialize(const json& config_override) {
    if (!config_override.is_null() && !config_override.empty()) {
        config_ = config_override;
    } else {
        const std::string fallback_path = "./resources/config/config.json";
        std::ifstream file(fallback_path);
        if (!file) {
            throw std::runtime_error("❌ Failed to open fallback config: " + fallback_path);
        }
        file >> config_;
        std::cout << "[DEBUG] Loaded fallback config from: " << fallback_path << std::endl;
    }

    client_ = td_json_client_create();

    json tdlib_params = {
        {"@type", "setTdlibParameters"},
        {"use_test_dc", config_.value("use_test_dc", false)},
        {"database_directory", "tdlib-data/" + session_suffix_},
        {"files_directory", config_.value("files_directory", "td_files")},
        {"use_file_database", config_.value("use_file_database", false)},
        {"use_chat_info_database", true},
        {"use_message_database", config_.value("use_message_database", false)},
        {"use_secret_chats", config_.value("use_secret_chats", false)},
        {"api_id", config_["api_id"].get<int>()},
        {"api_hash", config_["api_hash"].get<std::string>()},
        {"system_language_code", config_.value("system_language_code", "en")},
        {"device_model", config_.value("device_model", "PhantomRoll")},
        {"system_version", config_.value("system_version", "1.0")},
        {"application_version", config_.value("application_version", "1.0")},
        {"enable_storage_optimizer", config_.value("enable_storage_optimizer", true)}
    };

    send(tdlib_params.dump());

    std::cout << "[DEBUG] Using api_id = " << config_["api_id"]
              << ", api_hash = " << config_["api_hash"] << std::endl;
}

void TelegramSession::authenticate() {
    authorized_ = false;
    bool sent_encryption_key = false;
    bool sent_phone = false;

    while (!authorized_) {
        std::string response = receive(5.0);
        if (response.empty()) continue;

        json json_data = json::parse(response, nullptr, false);
        if (!json_data.is_object() || !json_data.contains("@type")) continue;

        if (json_data["@type"] == "updateAuthorizationState") {
            const auto& state = json_data["authorization_state"];
            const std::string auth_type = state["@type"];

            std::cout << "[AUTH DEBUG] auth_type = " << auth_type << std::endl;
            std::cout.flush();

            if (auth_type == "authorizationStateWaitTdlibParameters") {
                std::cout << "[AUTH] TDLib parameters acknowledged." << std::endl;
            }
            else if (auth_type == "authorizationStateWaitEncryptionKey" && !sent_encryption_key) {
                send(R"({"@type":"checkDatabaseEncryptionKey","encryption_key":""})");
                sent_encryption_key = true;
                std::cout << "[AUTH] Sent encryption key." << std::endl;
            }
            else if (auth_type == "authorizationStateWaitPhoneNumber" && !sent_phone) {
                std::string phone = config_.value("phone_number", "");
                if (!phone.empty()) {
                    json req = {
                        {"@type", "setAuthenticationPhoneNumber"},
                        {"phone_number", phone}
                    };
                    send(req.dump());
                    sent_phone = true;
                    std::cout << "[AUTH] Sent phone number: " << phone << std::endl;
                } else {
                    std::cerr << "[ERROR] Phone number not provided in config." << std::endl;
                    break;
                }
            }
            else if (auth_type == "authorizationStateWaitCode") {
                std::string code;
                std::cout << "[INPUT] Enter the Telegram login code sent to your phone: ";
                std::cin >> code;

                json req = {
                    {"@type", "checkAuthenticationCode"},
                    {"code", code}
                };
                send(req.dump());
                std::cout << "[AUTH] Sent login code." << std::endl;
            }
            else if (auth_type == "authorizationStateReady") {
                authorized_ = true;
                std::cout << "[AUTH ✅] Successfully logged in to Telegram." << std::endl;

                std::cout << "[INFO] Verifying login with getMe..." << std::endl;
                send(R"({"@type":"getMe"})");
                std::string me_response = receive(3.0);
                std::cout << "[DEBUG] getMe: " << me_response << std::endl;

                std::cout << "[INFO] Fetching recent chats..." << std::endl;
                send(R"({"@type":"getChats","limit":20})");
                std::string chats_response = receive(3.0);
                std::cout << "[DEBUG] getChats: " << chats_response << std::endl;
            }
            else if (auth_type == "authorizationStateClosed") {
                std::cerr << "[AUTH ❌] TDLib session closed unexpectedly." << std::endl;
                break;
            }
        }
        else if (json_data["@type"] == "error") {
            std::cerr << "[ERROR] TDLib reported error: " << json_data.dump(2) << std::endl;
        }
    }
}

void TelegramSession::send(const std::string& request) {
    std::lock_guard<std::mutex> lock(client_mutex_);
    td_json_client_send(client_, request.c_str());
}

std::string TelegramSession::receive(double timeout) {
    std::lock_guard<std::mutex> lock(client_mutex_);
    const double max_wait = timeout;
    const double sleep_interval = 0.1;
    double waited = 0;

    while (waited < max_wait) {
        const char* result = td_json_client_receive(client_, sleep_interval);
        if (result) {
            std::string response(result);
            std::cout << "[DEBUG TDLib] " << response << std::endl;
            return response;
        }
        waited += sleep_interval;
    }

    return "";
}

void TelegramSession::close() {
    if (client_) {
        td_json_client_destroy(client_);
        client_ = nullptr;
    }
}

bool TelegramSession::is_authorized() const {
    return authorized_;
}

void TelegramSession::reset_session_files() {
    std::string dir = "tdlib-data/" + session_suffix_;
    try {
        std::filesystem::remove_all(dir);
        std::cout << "[INFO] Session files deleted at: " << dir << std::endl;
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "[ERROR] Failed to delete session files: " << e.what() << std::endl;
    }
}

// ✅ NEW: Get own user ID for fallback delete
int64_t TelegramSession::get_own_user_id() {
    send(R"({"@type": "getMe"})");
    std::string response = receive(3.0);
    if (response.empty()) return 0;

    auto json = nlohmann::json::parse(response, nullptr, false);
    if (!json.is_object() || !json.contains("id")) return 0;

    return json["id"].get<int64_t>();
}

