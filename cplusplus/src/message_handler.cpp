// message_handler.cpp
#include "core/message_handler.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <sstream>
#include <set>
#include <regex>
#include <vector>
#include <algorithm>
#include <mutex>
#include <optional>
#include <tuple>
#include <array>
#ifdef _WIN32
#include <windows.h>
#endif
#include <ctime>
using namespace std;
// Extern declaration for GUI status function implemented in telegram_session.cpp
extern void send_event_to_gui(const std::string& event, const nlohmann::json& payload);
// Helper to select which dice to keep (3 indices) based on valid sums
static std::set<int> select_indices(const std::vector<std::pair<int64_t,int>>& rolled, const std::set<int>& valid_sums) {
    std::set<int> keep;
    int n = static_cast<int>(rolled.size());
    if (n >= 3) {
        for (int i = 0; i < n - 2; ++i) {
            for (int j = i + 1; j < n - 1; ++j) {
                for (int k = j + 1; k < n; ++k) {
                    int sum = rolled[i].second + rolled[j].second + rolled[k].second;
                    if (valid_sums.count(sum)) {
                        return {i, j, k};
                    }
                }
            }
        }
        return {0, 1, 2}; // fallback
    }
    return keep;
}
MessageHandler::MessageHandler(TelegramSession& session, const nlohmann::json& config)
    : session_(session), config_(config) {
#ifdef _WIN32
    SetDllDirectoryA("resources/tdlib");
#endif
    std::srand(static_cast<unsigned>(std::time(nullptr)));
}
void MessageHandler::run() {
    std::thread([this]() { send_dice_and_delete_loop(); }).detach();
    std::cout << "[INFO] PhantomRoll dice handler started." << std::endl;
    while (session_.is_authorized()) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
}
}
void MessageHandler::stop() {
    running_ = false;
}
void MessageHandler::sendCommand(const std::string& command) {
    // Handle custom dice commands from GUI
    try {
        auto j = nlohmann::json::parse(command);
        if (j.is_object() && j.contains("command") && j["command"].is_string()) {
            std::string cmd = j["command"];
            if (cmd == "send_best3_dice_to_public") {
                session_.append_audit("Received send_best3_dice_to_public from GUI");
                std::thread([this]() {
                    this->process_dice_roll_and_publish();
                }).detach();
                return;
            }
            if (cmd == "set_public_group_id" && j.contains("group_id")) {
                std::string group_id = j["group_id"].get<std::string>();
                std::cout << "[GROUP] Received set_public_group_id from GUI: " << group_id << std::endl;
                this->set_public_group_id(group_id);
                session_.append_audit("Set public group id from GUI: " + group_id);
                int64_t gid = 0;
                try { gid = std::stoll(group_id); } catch (...) { gid = 0; }
                if (gid != 0) {
                    std::lock_guard<std::mutex> lk(state_mutex_);
                    if (!config_.contains("groups") || !config_["groups"].is_array()) {
                        config_["groups"] = nlohmann::json::array();
                    }
                    bool found = false;
                    for (auto& g : config_["groups"]) {
                        if (g.contains("id")) {
                            g["id"] = gid;
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        nlohmann::json obj;
                        obj["id"] = gid;
                        config_["groups"].push_back(obj);
                    }
                }
                send_event_to_gui("public_group_changed", { {"group_id", group_id} });
                return;
            }
            // Add similar handling for other dice/group commands as needed
        }
    } catch (...) { /* Not a JSON command, ignore here */ }
    std::cout << "[GUI CMD] " << command << std::endl; // Log GUI command
    // Try to parse as JSON for command dispatch
    bool is_json = false;
    try {
        auto j = nlohmann::json::parse(command);
        is_json = true;
        if (j.is_object() && j.contains("command") && j["command"].is_string()) {
            std::string cmd = j["command"];
            if (cmd == "ping") {
                std::cout << "[PING] received from GUI" << std::endl;
                session_.append_audit("Ping received and processed");
                return;
            }
            if (cmd == "dice") {
                // Check for allowed sums in the command and update if present
                if (j.contains("allowed") && j["allowed"].is_array()) {
                    std::set<int> allowed_sums;
                    for (const auto& val : j["allowed"]) {
                        if (val.is_number_integer()) {
                            allowed_sums.insert(val.get<int>());
                        }
                    }
                    if (!allowed_sums.empty()) {
                        std::cout << "[INFO] Updating allowed sums from GUI: ";
                        for (int s : allowed_sums) std::cout << s << " ";
                        std::cout << std::endl;
                        set_allowed_sums(allowed_sums);
                        session_.append_audit("Updated allowed sums from GUI");
                    }
                }
                session_.append_audit("Processed GUI dice command (json): " + command);
                std::thread([this]() {
                    this->process_dice_roll_and_publish();
                }).detach();
                return;
            }
            if (cmd == "login_phone" && j.contains("phone")) {
                std::string phone = j["phone"].get<std::string>();
                std::cout << "[LOGIN] Received phone from GUI: " << phone << std::endl;
                this->start_login(phone);
                return;
            }
            if ((cmd == "login_code" || cmd == "submit_code") && j.contains("code")) {
                std::string code = j["code"].get<std::string>();
                std::cout << "[LOGIN] Received code from GUI: " << code << std::endl;
                this->submit_code(code);
                return;
            }
            if ((cmd == "login_password" || cmd == "submit_password") && j.contains("password")) {
                std::string password = j["password"].get<std::string>();
                std::cout << "[LOGIN] Received password from GUI." << std::endl;
                this->submit_password(password);
                return;
            }
        }
    } catch (...) {}

    if (!is_json) {
        // Only run regex on non-JSON commands
        std::regex cmd_regex(R"(^([\x{1F3B2}-\x{1F3FF}]):(\d+):(-?\d+))",
                             std::regex::ECMAScript | std::regex::icase | std::regex::optimize);
        std::smatch match;
        if (std::regex_match(command, match, cmd_regex)) {
            std::string emoji = match[1];
            int target = std::stoi(match[2]);
            int64_t chat_id = std::stoll(match[3]);

            session_.append_audit("Processed GUI command: " + command); // Echo back to GUI

            std::thread([=]() {
                this->process_dice_command(emoji, target, chat_id);
            }).detach();
        } else {
            std::cerr << "[WARN] Invalid command format: " << command << std::endl;
            session_.append_audit("Invalid GUI command: " + command); // Echo invalid command
        }
    }
}
void MessageHandler::process_dice_command(const std::string& emoji, int target_value, int64_t chat_id) {
    const int max_attempts = 50;
    const int interval_ms = 1;
    const int per_dice_timeout_ms = 2000;
    session_.set_dice_emoji(emoji);

    for (int attempt = 0; attempt < max_attempts && session_.is_authorized(); ++attempt) {
        int msg_id = session_.sendDice(chat_id, 0);
        if (msg_id == 0) {
            send_event_to_gui("dice_send_failed", { {"chat_id", chat_id}, {"detail", "Failed to send dice to chat"} });
            continue;
        }
        int value = session_.waitForDiceValue(chat_id, msg_id, per_dice_timeout_ms);
        if (value == -1) {
            send_event_to_gui("dice_result_timeout", { {"chat_id", chat_id}, {"detail", "No dice result for chat"} });
            continue;
        }

        std::cout << "[DEBUG] Rolled " << value << " targeting " << target_value << " in chat " << chat_id << std::endl;
        send_event_to_gui("dice_rolled", { {"chat_id", chat_id}, {"value", value}, {"target", target_value} });

        if (value == target_value) {
            send_event_to_gui("dice_target_success", { {"chat_id", chat_id}, {"target", target_value}, {"detail", "Matched target"} });
            break;
        }

        int delay_ms = 100;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            delay_ms = config_["dice_settings"].value(emoji, nlohmann::json::object()).value("delete_delay_ms", 100);
        }

        std::thread([this, chat_id, msg_id = static_cast<int64_t>(msg_id), delay_ms]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
            this->delete_message(chat_id, msg_id);
        }).detach();

        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }
}
void MessageHandler::process_dice_command(const std::string& emoji, const std::vector<int>& target_values, int64_t chat_id) {
    for (int target : target_values) {
        process_dice_command(emoji, target, chat_id);
    }
}
void MessageHandler::process_dynamic_dice(const std::string& emoji, const std::set<int>& valid_sums, int64_t chat_id) {
    session_.set_dice_emoji(emoji);
    const int pacing_ms = 100;
    const int per_dice_timeout_ms = 2000;
    const int dice_count = 10; // Changed from 3 to 10
    auto msg_ids = session_.sendDiceBatch(chat_id, dice_count, pacing_ms);
    auto vals = session_.waitForDiceResults(msg_ids, per_dice_timeout_ms);
    if (vals.size() != dice_count) {
        std::cerr << "[WARN] Expected " << dice_count << " dice, got " << vals.size() << std::endl; // Fallback logging
        return;
    }

    std::vector<std::pair<int64_t, int>> rolled;
    for (size_t i = 0; i < msg_ids.size(); ++i) {
        rolled.emplace_back(msg_ids[i].msg_id, vals[i]);
    }

    auto keep = select_indices(rolled, valid_sums);
    for (int idx = 0; idx < static_cast<int>(rolled.size()); ++idx) {
        if (!keep.count(idx)) {
            auto [msg_id, val] = rolled[idx];
            if (msg_id > 0) {
                int delay_ms = 10;
                {
                    std::lock_guard<std::mutex> lk(state_mutex_);
                    delay_ms = config_["dice_settings"].value(emoji, nlohmann::json::object()).value("delete_delay_ms", 100);
                }
                std::thread([this, chat_id, msg_id, delay_ms]() {
                    std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
                    this->delete_message(chat_id, msg_id);
                }).detach();
            }
        }
    }
}
void MessageHandler::process_dice_roll_and_publish() {
    if (!session_.is_authorized()) {
        send_event_to_gui("dice_error", nlohmann::json{{"error", "Not authorized. Please log in first."}});
        session_.append_audit("Dice command rejected: not authorized");
        return;
    }
    session_.send_best3_dice_to_public();
}
void MessageHandler::set_public_group_id(const std::string& group_id) {
    public_group_id_str_ = group_id;
    try {
        public_group_id_ = std::stoll(group_id);
    } catch (...) {
        public_group_id_ = 0;
    }
}
void MessageHandler::send_dice_and_delete_loop() {
    // copy runtime config under lock to avoid races with add_group_by_name
    nlohmann::json local_config;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        local_config = config_;
    }
    if (!local_config.contains("groups") || !local_config.contains("valid_sums")) return;

    const auto groups = local_config["groups"];
    const auto valid_sum_array = local_config["valid_sums"];
    std::set<int> valid_sums(valid_sum_array.begin(), valid_sum_array.end());

    const std::string emoji = "";
    const int interval_ms = local_config.value("group_interval_ms", 50000);
    const int pacing_ms = 100;
    const int per_dice_timeout_ms = 2000;
    const int dice_count = 10; // Changed from 3 to 10

    while (session_.is_authorized() && running_) {
        for (const auto& group : groups) {
            int64_t chat_id = 0;
            if (group.contains("id")) {
                chat_id = group["id"];
            } else if (group.contains("name")) {
                chat_id = resolve_chat_id_from_name(group["name"]);
                if (chat_id == 0) continue;
            } else continue;

            auto msg_ids = session_.sendDiceBatch(chat_id, dice_count, pacing_ms);
            auto vals = session_.waitForDiceResults(msg_ids, per_dice_timeout_ms);
            if (vals.size() != dice_count) {
                std::cerr << "[WARN] Expected " << dice_count << " dice, got " << vals.size() << std::endl; // Fallback logging
                continue;
            }

            std::vector<std::pair<int64_t, int>> rolled;
            for (size_t i = 0; i < msg_ids.size(); ++i) {
                rolled.emplace_back(msg_ids[i].msg_id, vals[i]);
            }

            auto keep = select_indices(rolled, valid_sums);
            for (int idx = 0; idx < static_cast<int>(rolled.size()); ++idx) {
                if (!keep.count(idx)) {
                    auto [msg_id, val] = rolled[idx];
                    if (msg_id > 0) {
                        int delay_ms = 100;
                        {
                            std::lock_guard<std::mutex> lk(state_mutex_);
                            delay_ms = config_["dice_settings"].value(emoji, nlohmann::json::object()).value("delete_delay_ms", 100);
                        }
                        std::thread([this, chat_id, msg_id, delay_ms]() {
                            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
                            this->delete_message(chat_id, msg_id);
                        }).detach();
                    }
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));

        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            local_config = config_;
        }
    }
}
std::string MessageHandler::build_dice_message(const std::string& emoji, int64_t chat_id) {
    std::ostringstream ss;
    ss << R"({"@type":"sendMessage","chat_id":)" << chat_id;
    ss << R"(,"input_message_content":{"@type":"inputMessageDice","emoji":")" << emoji << R"("}})";
    return ss.str();
}
int MessageHandler::extract_dice_value(const nlohmann::json& dice_json) {
    return dice_json.value("value", -1);
}
void MessageHandler::delete_message(int64_t chat_id, int64_t message_id) {
    if (!chat_id || !message_id) return;
    std::ostringstream ss;
    ss << R"({
    "@type": "deleteMessages",
    "chat_id": )" << chat_id << R"(
    "message_thread_id": 0,
    "message_ids": [)" << message_id << R"(],
    "revoke": false
})";
    std::string payload = ss.str();
    std::cout << "[DELETE] Payload: " << payload << std::endl;

    int retries = 0;
    const int max_retries = 3;
    while (session_.is_authorized() && retries < max_retries) {
        session_.send(payload);
        auto resp = session_.receive(0.5);
        std::cout << "[DELETE] Response: " << resp << std::endl;
        if (!resp.empty() && resp.find("\"@type\":\"ok\"") != std::string::npos) {
            std::cout << "[DELETE ] msg_id=" << message_id << std::endl;
            return;
        }
        retries++;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    std::cerr << "[DELETE ] Failed to delete msg_id=" << message_id << " after " << retries << " tries\n";
}
int64_t MessageHandler::resolve_group_name_to_id(const std::string& group_name) {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        auto it = group_name_to_id_.find(group_name);
        if (it != group_name_to_id_.end()) {
            return it->second;
        }
    }
    int64_t id = resolve_chat_id_from_name(group_name);

    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        group_name_to_id_[group_name] = id;
    }
    return id;
}
int64_t MessageHandler::resolve_chat_id_from_name(const std::string& name) {
    std::ostringstream ss;
    ss << R"({"@type":"searchPublicChat","username":")" << name << R"("})";
    session_.send(ss.str());
    auto resp = session_.receive(3.0);
    auto json = nlohmann::json::parse(resp, nullptr, false);
    return json.value("id", 0LL);
}
bool MessageHandler::has_group_access(int64_t chat_id) {
    return true;
}
void MessageHandler::start_login(const std::string& phone) {
    try {
        try {
            session_.submit_phone_async(phone);
            std::cout << "[INFO] start_login: submitted phone async: " << phone << std::endl;
            return;
        } catch (...) {
        }
        session_.add_phone_number(phone);
        std::cout << "[INFO] start_login: added phone: " << phone << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] start_login exception: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "[ERROR] start_login unknown exception\n";
    }
}
void MessageHandler::logout() {
    try {
        session_.close();
        std::cout << "[INFO] logout: session closed\n";
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] logout exception: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "[ERROR] logout unknown exception\n";
    }
}
void MessageHandler::add_group_by_name(const std::string& group) {
    try {
        int64_t id = resolve_group_name_to_id(group);
        std::cout << "[INFO] add_group_by_name: '" << group << "' -> id=" << id << std::endl;
        try {
            std::lock_guard<std::mutex> lk(state_mutex_);
            if (!config_.contains("groups")) config_["groups"] = nlohmann::json::array();
            if (id != 0) {
                nlohmann::json obj;
                obj["id"] = id;
                config_["groups"].push_back(obj);
            } else {
                nlohmann::json obj;
                obj["name"] = group;
                config_["groups"].push_back(obj);
            }
        } catch (...) {
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] add_group_by_name exception: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "[ERROR] add_group_by_name unknown exception\n";
    }
}
void MessageHandler::set_allowed_sums(const std::set<int>& s) {
    session_.set_allowed_sums(s);
}
void MessageHandler::submit_code(const std::string& code) {
    session_.submit_code_async(code);
    send_event_to_gui("auth_status", nlohmann::json{{"status", "code_submitted"}, {"detail", "Code submitted to backend"}});
}
void MessageHandler::submit_password(const std::string& password) {
    session_.submit_2fa_async(password);
    send_event_to_gui("auth_status", nlohmann::json{{"status", "password_submitted"}, {"detail", "Password submitted to backend"}});
}
void MessageHandler::get_status(nlohmann::json& resp) {
    resp["authorized"] = session_.is_authorized();
    resp["auth_stage"] = static_cast<int>(session_.get_auth_stage());
    resp["waiting_for_code"] = session_.is_waiting_for_code();
    resp["waiting_for_password"] = session_.is_waiting_for_password();
    resp["paused"] = session_.is_paused();
}
std::optional<std::tuple<int,int,int>> MessageHandler::pick_best_triple(const std::array<int,10>& dice_values) const {
    int best_sum = -1;
    std::tuple<int,int,int> best_idx(0,0,0);
    bool found = false;
    const int N = static_cast<int>(dice_values.size());
    for (int i = 0; i < N - 2; ++i) {
        if (dice_values[i] < 0) continue;
        for (int j = i + 1; j < N - 1; ++j) {
            if (dice_values[j] < 0) continue;
            for (int k = j + 1; k < N; ++k) {
                if (dice_values[k] < 0) continue;
                int sum = dice_values[i] + dice_values[j] + dice_values[k];
                if (!found || sum > best_sum) {
                    best_sum = sum;
                    best_idx = std::make_tuple(i, j, k);
                    found = true;
                }
            }
        }
    }
    if (found) return best_idx;
    return std::nullopt;
}
// Forwarding setters for dice config values
void MessageHandler::set_dice_emoji(const std::string& emoji) {
    session_.set_dice_emoji(emoji);
}
void MessageHandler::set_dice_count(int count) {
    session_.set_dice_count(count);
}
void MessageHandler::set_dice_result_timeout_ms(int ms) {
    session_.set_dice_result_timeout_ms(ms);
}
void MessageHandler::set_auto_delete_private_rolls(bool value) {
    session_.set_auto_delete_private_rolls(value);
}
void MessageHandler::set_max_attempts(int attempts) {
    session_.set_max_attempts(attempts);
}
void MessageHandler::set_auto_delete_delay_ms(int ms) {
    session_.set_auto_delete_delay_ms(ms);
}
void MessageHandler::pause_dice() {
    session_.pause_dice();
}
void MessageHandler::resume_dice() {
    session_.resume_dice();
}

