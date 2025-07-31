// File: message_handler.cpp

#include "core/message_handler.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <sstream>
#include <set>
#include <regex>
#include <vector>
#include <algorithm>
#include <windows.h>
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
    SetDllDirectoryA("resources/tdlib");
    std::srand(static_cast<unsigned>(std::time(nullptr)));
}

void MessageHandler::run() {
    std::thread([this]() { send_dice_and_delete_loop(); }).detach();
    std::cout << "[INFO] PhantomRoll dice handler started." << std::endl;

    while (session_.is_authorized()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
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

        int delay_ms = config_["dice_settings"].value(emoji, nlohmann::json::object()).value("delete_delay_ms", 100);
        std::thread([this, chat_id, message_id, delay_ms]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
            this->delete_message(chat_id, message_id);
        }).detach();

        if (value == target_value) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }
}

void MessageHandler::send_dice_and_delete_loop() {
    if (!config_.contains("groups") || !config_.contains("valid_sums")) return;

    const auto groups = config_["groups"];
    const auto valid_sum_array = config_["valid_sums"];
    std::set<int> valid_sums(valid_sum_array.begin(), valid_sum_array.end());

    const std::string emoji = "🎲";
    const int interval_ms = config_.value("group_interval_ms", 50000);

    while (session_.is_authorized()) {
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
                        int delay_ms = config_["dice_settings"].value(emoji, nlohmann::json::object()).value("delete_delay_ms", 100);
                        std::thread([this, chat_id, msg_id, delay_ms]() {
                            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
                            this->delete_message(chat_id, msg_id);
                        }).detach();
                    }
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
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
        Sleep(1);
    }
    std::cerr << "[DELETE ❌] Failed to delete msg_id=" << message_id << " after " << retries << " tries\n";
}

int64_t MessageHandler::resolve_chat_id_from_name(const std::string& name) {
    std::ostringstream ss;
    ss << R"({"@type":"searchPublicChat","username":")" << name << R"("})";
    session_.send(ss.str());
    auto resp = session_.receive(3.0);
    auto json = nlohmann::json::parse(resp, nullptr, false);
    return json.value("id", 0LL);
}
