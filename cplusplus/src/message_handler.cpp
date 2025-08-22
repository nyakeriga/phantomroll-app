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
    std::regex cmd_regex(R"(^([\x{1F3B2}-\x{1F3FF}]):(\d+):(-?\d+))",
                         std::regex::ECMAScript | std::regex::icase | std::regex::optimize);
    std::smatch match;
    if (std::regex_match(command, match, cmd_regex)) {
        std::string emoji = match[1];
        int target = std::stoi(match[2]);
        int64_t chat_id = std::stoll(match[3]);

        std::thread([=]() {
            this->process_dice_command(emoji, target, chat_id);
        }).detach();
    } else {
        std::cerr << "[WARN] Invalid command format: " << command << std::endl;
    }
}

void MessageHandler::process_dice_command(const std::string& emoji, int target_value, int64_t chat_id) {
    const int max_attempts = 50;
    const int interval_ms = 1;
    for (int attempt = 0; attempt < max_attempts && session_.is_authorized(); ++attempt) {
        std::string dice_request = build_dice_message(emoji, chat_id);
        session_.send(dice_request);

        std::string response = session_.receive(0.5);
        if (response.empty()) continue;

        auto json = nlohmann::json::parse(response, nullptr, false);
        if (json.is_discarded() || !json.contains("result") || !json["result"].contains("message"))
            continue;

        auto msg = json["result"]["message"];
        if (!msg.contains("id") || !msg.contains("dice") || !msg.contains("is_outgoing") || !msg["is_outgoing"].get<bool>())
            continue;

        int64_t message_id = msg["id"];
        int value = extract_dice_value(msg["dice"]);
        std::cout << "[DEBUG] Rolled " << value << " targeting " << target_value << " in chat " << chat_id << std::endl;

        int delay_ms = 100;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            delay_ms = config_["dice_settings"].value(emoji, nlohmann::json::object()).value("delete_delay_ms", 100);
        }

        std::thread([this, chat_id, message_id, delay_ms]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
            this->delete_message(chat_id, message_id);
        }).detach();

        if (value == target_value) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }
}

void MessageHandler::process_dice_command(const std::string& emoji, const std::vector<int>& target_values, int64_t chat_id) {
    for (int target : target_values) {
        process_dice_command(emoji, target, chat_id);
    }
}

void MessageHandler::process_dynamic_dice(const std::string& emoji, const std::set<int>& valid_sums, int64_t chat_id) {
    // Example: roll dice and keep only those matching valid_sums
    std::vector<std::pair<int64_t, int>> rolled;
    for (int i = 0; i < 3; ++i) {
        std::string dice_request = build_dice_message(emoji, chat_id);
        session_.send(dice_request);

        std::string response = session_.receive(0.5);
        if (response.empty()) continue;

        auto json = nlohmann::json::parse(response, nullptr, false);
        if (json.is_discarded() || !json.contains("result") || !json["result"].contains("message"))
            continue;

        auto msg = json["result"]["message"];
        if (!msg.contains("id") || !msg.contains("dice") || !msg.contains("is_outgoing") || !msg["is_outgoing"].get<bool>())
            continue;

        int64_t message_id = msg["id"];
        int value = extract_dice_value(msg["dice"]);
        rolled.emplace_back(message_id, value);
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

void MessageHandler::process_dice_roll_and_publish() {
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

    const std::string emoji = "🎲";
    const int interval_ms = local_config.value("group_interval_ms", 50000);

    while (session_.is_authorized() && running_) {
        for (const auto& group : groups) {
            int64_t chat_id = 0;
            if (group.contains("id")) {
                chat_id = group["id"];
            } else if (group.contains("name")) {
                chat_id = resolve_chat_id_from_name(group["name"]);
                if (chat_id == 0) continue;
            } else continue;

            std::vector<std::pair<int64_t, int>> rolled;
            rolled.reserve(3);
            for (int i = 0; i < 3; ++i) {
                session_.send(build_dice_message(emoji, chat_id));
                auto resp = session_.receive(0.5);
                auto json = nlohmann::json::parse(resp, nullptr, false);
                if (json.is_discarded()) continue;

                if (json.contains("result") && json["result"].contains("message")) {
                    auto msg = json["result"]["message"];
                    if (!msg.contains("id") || !msg.contains("dice") || !msg.contains("is_outgoing") || !msg["is_outgoing"].get<bool>())
                        continue;

                    rolled.emplace_back(msg.value("id", 0LL), extract_dice_value(msg["dice"]));
                }
            }

            // keep logic in case future validation still needs it
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

        // refresh local copy of config occasionally to pick up runtime changes
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
        "chat_id": )" << chat_id << R"(,
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
            std::cout << "[DELETE ✅] msg_id=" << message_id << std::endl;
            return;
        }
        retries++;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    std::cerr << "[DELETE ❌] Failed to delete msg_id=" << message_id << " after " << retries << " tries\n";
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
    // Example: always return true for now
    return true;
}

// ----------------- Helper control APIs invoked by control server -----------------

void MessageHandler::start_login(const std::string& phone) {
    try {
        // prefer async submission if available in TelegramSession
        try {
            session_.submit_phone_async(phone);
            std::cout << "[INFO] start_login: submitted phone async: " << phone << std::endl;
            return;
        } catch (...) {
            // fallback to add_phone_number if async not present/throws
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

        // Append to runtime config so send_dice_and_delete_loop sees it
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
            // non-fatal
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

// ----------------- Utility: pick best triple from up to 10 dice values -----------------

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
