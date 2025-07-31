#ifndef CORE_MESSAGE_HANDLER_HPP
#define CORE_MESSAGE_HANDLER_HPP

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <unordered_map>  // ✅ Added to support mapping names to IDs
#include <set>            // ✅ Required for std::set
#include "core/telegram_session.hpp"

class MessageHandler {
public:
    MessageHandler(TelegramSession& session, const nlohmann::json& config);
    void run();

    void sendCommand(const std::string& command);  // ✅ matches .cpp
    void process_dice_command(const std::string& emoji, int target_value, int64_t chat_id);  // ✅ matches .cpp

    // ✅ NEW: Add support for multiple allowed dice values (e.g., 3, 5, 7, etc.)
    void process_dice_command(const std::string& emoji, const std::vector<int>& target_values, int64_t chat_id);

    // ✅ MISSING DECLARATION ADDED HERE
    void process_dynamic_dice(const std::string& emoji, const std::set<int>& valid_sums, int64_t chat_id);

private:
    void send_dice_and_delete_loop();
    std::string build_dice_message(const std::string& emoji, int64_t chat_id);  // ✅ correct overload
    int extract_dice_value(const nlohmann::json& dice_json);  // ✅ matches .cpp
    void delete_message(int64_t chat_id, int64_t message_id);

    // ✅ NEW: Resolve group name to chat ID
    int64_t resolve_group_name_to_id(const std::string& group_name);

    // ✅ REQUIRED BY IMPLEMENTATION — ADD THESE:
    int64_t resolve_chat_id_from_name(const std::string& name);   // 🔧 Fix for missing symbol
    bool has_group_access(int64_t chat_id);                       // 🔧 Fix for missing symbol

private:
    TelegramSession& session_;
    nlohmann::json config_;

    // ✅ NEW: Cache of resolved group name → chat_id
    std::unordered_map<std::string, int64_t> group_name_to_id_;
};

#endif // CORE_MESSAGE_HANDLER_HPP

