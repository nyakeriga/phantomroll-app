// ...existing code...
#ifndef CORE_MESSAGE_HANDLER_HPP
#define CORE_MESSAGE_HANDLER_HPP

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <unordered_map>
#include <set>
#include <cstdint>
#include <optional>
#include <mutex>
#include "core/bot_types.hpp"
#include "core/telegram_session.hpp"

class MessageHandler {
public:
    // Construct with a TelegramSession reference and config JSON
    MessageHandler(TelegramSession& session, const nlohmann::json& config);

    // Main blocking processing loop
    void run();

    // Stop the processing loop
    void stop();

    // Accepts raw commands (from socket/UI/etc.)
    void sendCommand(const std::string& command);

    // Process a dice roll command for a single target value
    void process_dice_command(const std::string& emoji, int target_value, int64_t chat_id);

    // Process a dice roll command for multiple target values
    void process_dice_command(const std::string& emoji, const std::vector<int>& target_values, int64_t chat_id);

    // Process a dice roll using a set of allowed sums (dynamic rules)
    void process_dynamic_dice(const std::string& emoji, const std::set<int>& valid_sums, int64_t chat_id);

    // Roll dice in private group, pick best triple, and post to public group
    void process_dice_roll_and_publish();

    // Set the public group ID (string form) for publishing dice results
    void set_public_group_id(const std::string& group_id);

    // Pick best triple (for use with dice logic)
    std::optional<std::tuple<int,int,int>> pick_best_triple(const std::array<int,10>& dice_values) const;

    // Control APIs invoked by control server
    void start_login(const std::string& phone);
    void logout();
    void add_group_by_name(const std::string& group);

private:
    // Loop: send dice, filter bad rolls, delete unwanted messages
    void send_dice_and_delete_loop();

    // Construct the message payload for sending a dice roll
    std::string build_dice_message(const std::string& emoji, int64_t chat_id);

    // Parse dice value from a TDLib update
    int extract_dice_value(const nlohmann::json& dice_json);

    // Delete a specific message in a chat
    void delete_message(int64_t chat_id, int64_t message_id);

    // Resolve a group name to a chat ID, with caching
    int64_t resolve_group_name_to_id(const std::string& group_name);

    // Resolve chat ID directly from a provided string name or ID
    int64_t resolve_chat_id_from_name(const std::string& name);

    // Check if the bot/account has access to a given group
    bool has_group_access(int64_t chat_id);

private:
    TelegramSession& session_;
    nlohmann::json config_;

    // Group name -> chat ID cache
    std::unordered_map<std::string, int64_t> group_name_to_id_;

    // Public group ID in string form (for publishing)
    std::string public_group_id_str_;

    // Dice/game parameters
    int dice_count_ = 10;
    int publish_count_ = 3;
    int max_attempts_ = 5;
    int inter_dice_delay_ms_ = 15;
    int dice_result_timeout_ms_ = 1500;
    std::set<int> allowed_sums_;
    int64_t public_group_id_ = 0;

    // running flag (made atomic for thread-safety)
    std::atomic<bool> running_{true};

    // mutex to protect config_ and group_name_to_id_ when modified at runtime
    std::mutex state_mutex_;

    // If you need to store group/dice settings
    std::vector<GroupInfo> public_groups_;
    std::unordered_map<std::string, DiceSetting> dice_settings_;

};

