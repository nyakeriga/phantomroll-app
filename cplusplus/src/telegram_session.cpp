

#include "core/telegram_session.hpp"

// --- Dice roll buffer for last 10 real dice values ---
void TelegramSession::collectDiceRoll10(int value) {
    if (value < 1 || value > 6) {
        // ignore -1 or invalid values
        return;
    }
    last10Dice.push_back(value);
    if (last10Dice.size() > 10) {
        last10Dice.pop_front();
    }
}

std::optional<int> TelegramSession::computeBestTripleFrom10() {
    if (last10Dice.size() < 3) {
        return std::nullopt; // not enough data yet
    }
    int bestSum = -1;
    for (size_t i = 0; i < last10Dice.size(); i++) {
        for (size_t j = i + 1; j < last10Dice.size(); j++) {
            for (size_t k = j + 1; k < last10Dice.size(); k++) {
                int sum = last10Dice[i] + last10Dice[j] + last10Dice[k];
                if (sum > bestSum) {
                    bestSum = sum;
                }
            }
        }
    }
    return std::make_optional(bestSum);
}

// #include <nlohmann/json.hpp> // removed duplicate, included below after all system headers
// Unified event sender for GUI (stdout, replace with socket if needed)
inline void send_event_to_gui(const std::string& event, const nlohmann::json& data = nlohmann::json()) {
    nlohmann::json j;
    j["event"] = event;
    if (!data.is_null() && !data.empty()) j["data"] = data;
    std::cout << j.dump() << std::endl;
    std::cout.flush();
}

// telegram_session.cpp
// ----------------------------------------------------------------------------
// PhantomRoll – Telegram Session implementation
// ----------------------------------------------------------------------------
#include "core/telegram_session.hpp"
#include <mutex>
#include "core/message_handler.hpp" 
#include <td/telegram/td_api.h>
#include <td/telegram/td_json_client.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <chrono>
#include <thread>
#include <cmath>
#include <climits>
#include <algorithm>
#include <cctype>
#include <exception>
#include <optional>
#include <tuple>
#include <array>


#include <vector>
#include <set>
#include <numeric>
#include <random>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <stdexcept>
#include <cstdio>
#include <atomic>
#include <map>
#include <regex> // IMPROVEMENT: Added for regex functionality

#include "core/logger.hpp"

using nlohmann::json;

using namespace std::literals::chrono_literals;

// alias for monotonic time
using Clock = std::chrono::steady_clock;

#ifdef __unix__
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#endif

// forward-declare MessageHandler so extern can compile without including header
class MessageHandler;
extern MessageHandler* g_handler;

// static control-server globals (keeps header changes optional)
static std::atomic<bool> s_control_server_running{false};
static std::thread s_control_thread;
int s_control_server_fd = -1;

// ----------------- internal helpers & anonymous namespace -----------------
namespace {

    std::string now_ts() {
        using namespace std::chrono;
        auto n = system_clock::now();
        auto t = system_clock::to_time_t(n);
        std::tm tm{};
    #ifdef _WIN32
        localtime_s(&tm, &t);
    #else
        localtime_r(&t, &tm);
    #endif
        auto ms = duration_cast<milliseconds>(n.time_since_epoch()) % 1000;
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
            << "." << std::setw(3) << std::setfill('0') << ms.count();
        return oss.str();
    }

    void sleep_ms(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

    std::string rand_token() {
        static thread_local std::mt19937_64 rng{std::random_device{}()};
        std::uniform_int_distribution<uint64_t> d;
        std::ostringstream o; o << std::hex << d(rng);
        return o.str();
    }

    std::size_t hash_allowed(const std::set<int>& S) {
        std::size_t h = 1469598103934665603ull;
        for (int x : S) { h ^= static_cast<std::size_t>(x); h *= 1099511628211ull; }
        return h;
    }

    inline int roll_die(std::mt19937_64& rng) {
        static thread_local std::uniform_int_distribution<int> d(1,6);
        return d(rng);
    }

    inline double variance3(int a, int b, int c) {
        double m = (a + b + c) / 3.0;
        double v1 = a - m, v2 = b - m, v3 = c - m;
        return (v1*v1 + v2*v2 + v3*v3) / 3.0;
    }

    struct BestTriple { int i=-1,j=-1,k=-1; int sum=-1; double var=0.0; bool found=false; };

    BestTriple best_triple_from_vector(const std::vector<int>& V, const std::set<int>& allowed) {
        BestTriple bt;
        if (V.size() < 3) return bt;
        const bool unconstrained = allowed.empty();
        int n = (int)V.size();
        for (int i=0;i<n;++i) for (int j=i+1;j<n;++j) for (int k=j+1;k<n;++k) {
            int s = V[i] + V[j] + V[k];
            if (!unconstrained && !allowed.count(s)) continue;
            double v = variance3(V[i], V[j], V[k]);
            if (!bt.found ||
                (s > bt.sum) ||
                (s == bt.sum && v < bt.var) ||
                (s == bt.sum && std::abs(v - bt.var) < 1e-12 && std::tie(i,j,k) < std::tie(bt.i, bt.j, bt.k))) {
                bt = {i,j,k,s,v,true};
            }
        }
        return bt;
    }


    int simulate_best_sum_once(int N, const std::set<int>& allowed, std::mt19937_64& rng) {
        std::vector<int> V; V.reserve(N);
        for (int t=0;t<N;++t) V.push_back(roll_die(rng));
        auto bt = best_triple_from_vector(V, allowed);
        return bt.found ? bt.sum : -1;
    }
} // end anonymous namespace

// Static wrappers for demo use in main.cpp
std::size_t TelegramSession::hash_allowed_for_demo(const std::set<int>& S) { return ::hash_allowed(S); }
int TelegramSession::simulate_best_sum_once_for_demo(int N, const std::set<int>& allowed, std::mt19937_64& rng) { return ::simulate_best_sum_once(N, allowed, rng); }

// Comment out unused function to suppress warning
/*
double estimate_expected_best_sum_m(int N, the std::set<int>& allowed, int m_attempts, int trials = 3000) {
    if (m_attempts <= 0) return -1.0;
    static std::unordered_map<uint64_t,double> cache;
    uint64_t key = (uint64_t(N) & 0xffff)
                 | (uint64_t(m_attempts) & 0xffff) << 16
                 | (uint64_t(hash_allowed(allowed)) << 32);
    auto it = cache.find(key);
    if (it != cache.end()) return it->second;

    std::mt19937_64 rng{std::random_device{}()};
    long long acc = 0;
    int valid = 0;
    for (int t=0;t<trials;++t) {
        int best = -1;
        for (int a=0;a<m_attempts;++a) {
            int s = simulate_best_sum_once(N, allowed, rng);
            if (s > best) best = s;
        }
        if (best >= 0) { acc += best; ++valid; }
    }
    double ev = (valid > 0) ? double(acc) / valid : -1.0;
    cache[key] = ev;
    return ev;
}
*/

    bool json_has_extra(const json& j, const std::string& extra) {
        return j.contains("@extra") && j["@extra"].is_string() && j["@extra"].get<std::string>() == extra;
    }

// ----------------- dice result tracking globals -----------------
static std::unordered_map<DiceKey,int,DiceKeyHash> g_dice_values;
static std::mutex g_dice_mtx;
static std::condition_variable g_dice_cv;

// ----------------- helpers that call TelegramSession methods -----------------
static nlohmann::json request_with_extra_blocking(TelegramSession* self, nlohmann::json req, const std::string& extra, double total_timeout_sec) {
    using Clock = std::chrono::steady_clock;

    req["@extra"] = extra;
    self->send(req.dump());

    auto deadline = Clock::now() + std::chrono::milliseconds(static_cast<int>(total_timeout_sec * 1000.0));
    while (Clock::now() < deadline) {
        std::string resp = self->receive(0.5);
        if (resp.empty()) continue;
        try {
            nlohmann::json jr = nlohmann::json::parse(resp);
            if (json_has_extra(jr, extra)) return jr;
            self->on_update(jr);
        } catch (const std::exception& e) {
            Logger::errorGlobal("request_with_extra_blocking: JSON parse error: " + std::string(e.what()));
        }
    }
    return nlohmann::json();
}

// ----------------- TelegramSession implementation -----------------

TelegramSession::TelegramSession()
    : client_(nullptr)
    , logger_(std::make_unique<Logger>(Logger::Level::INFO))
    , authorized_(false)
    , listening_(false)
, stop_update_listener_flag_(false)
, current_auth_stage_(AuthStage::None)
, api_id_(0)
, private_group_id_(0)
, private_dice_group_id_(0)
, is_paused_(false)
{
}

TelegramSession::~TelegramSession() {
    stop_update_listener();
    stop_control_server();
    std::lock_guard<std::mutex> lk(client_mutex_);
    if (client_) {
        try { td_json_client_destroy(client_); } catch(...) {}
        client_ = nullptr;
    }
}

void TelegramSession::initialize(const nlohmann::json& config_override) {
    std::string config_path = "(override)";
    if (!config_override.is_null() && !config_override.empty()) {
        config_ = config_override;
    } else {
        const std::string fallback_path = std::filesystem::absolute("resources/config/config.json").string();
        std::ifstream file(fallback_path);
        if (!file) {
            throw std::runtime_error(" Failed to open fallback config: " + fallback_path);
        }
        file >> config_;
        config_path = fallback_path;
        std::cout << "[DEBUG] Loaded fallback config from: " << fallback_path << std::endl;
    }

    // Log the loaded private_dice_group_id_ value and config path
    std::cout << "[DEBUG] Config path: " << config_path << std::endl;
    if (config_.contains("private_dice_group_id")) {
        std::cout << "[DEBUG] Config private_dice_group_id: " << config_["private_dice_group_id"] << std::endl;
    } else {
        std::cout << "[DEBUG] Config has NO private_dice_group_id!" << std::endl;
    }

    // Validate config
    if (!config_.contains("api_id") || !config_["api_id"].is_number_integer()) {
        throw std::runtime_error("Missing or invalid 'api_id' in config.");
    }
    if (!config_.contains("api_hash") || !config_["api_hash"].is_string()) {
        throw std::runtime_error("Missing or invalid 'api_hash' in config.");
    }
    if (config_.contains("groups") && !config_["groups"].is_array()) {
        throw std::runtime_error("Invalid 'groups' field in config; must be an array.");
    }
    if (config_.contains("dice_settings") && !config_["dice_settings"].is_object()) {
        throw std::runtime_error("Invalid 'dice_settings' field in config; must be an object.");
    }

    private_dice_group_id_ = config_.value("private_dice_group_id", private_dice_group_id_);
    if (config_.contains("groups") && config_["groups"].is_array()) {
        public_groups_.clear();
        for (const auto &g : config_["groups"]) {
            GroupInfo gi;
            gi.id = g.value("id", 0LL);
            gi.name = g.value("name", std::string());
            gi.interval_ms = g.value("interval_ms", 1000);
            if (gi.id != 0 || !gi.name.empty()) public_groups_.push_back(gi);
        }
    }

    client_ = td_json_client_create();

    nlohmann::json tdlib_params = {
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

void TelegramSession::sendTdlibParameters() {
    if (!client_) {
        client_ = td_json_client_create();
    }

    nlohmann::json tdlib_params = {
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

    try {
        send(tdlib_params.dump());
        if (logger_) logger_->info("sendTdlibParameters(): sent setTdlibParameters");
    } catch (const std::exception& ex) {
        if (logger_) logger_->error(std::string("sendTdlibParameters(): exception: ") + ex.what());
        else std::cerr << "sendTdlibParameters(): exception: " << ex.what() << std::endl;
    }

    int loglvl = config_.value("tdlib_log_level", 1);
    nlohmann::json log_msg = {
        {"@type", "setLogVerbosityLevel"},
        {"new_verbosity_level", loglvl}
    };
    try {
        send(log_msg.dump());
        if (logger_) logger_->info("sendTdlibParameters(): sent setLogVerbosityLevel=" + std::to_string(loglvl));
    } catch (const std::exception&) {
        // non-fatal: continue
    }
}

bool TelegramSession::authenticate() {
    bool use_external_auth = false;

    if (config_.contains("external_auth") && config_["external_auth"].is_boolean()) {
        use_external_auth = config_["external_auth"].get<bool>();
    }

    // Only accept login/phone/code from GUI via JSON commands.
    sendTdlibParameters();
    // Notify GUI to prompt for phone and code as needed.
    // (Implementation: send status/event JSON to GUI socket)
    // Do not prompt or log here; GUI handles all user interaction and logging.
    return true;
}

void TelegramSession::forceLogin() { 
    // GUI handles forceLogin; no logging here
}

void TelegramSession::submit_phone_async(const std::string& phone) {
    std::string clean_phone = trim(phone);
    if (clean_phone.empty()) {
        send_event_to_gui("auth_status", nlohmann::json{{"status", "error"}, {"detail", "empty_phone"}});
        logger_->error("submit_phone_async: empty phone received");
        return;
    }
    current_phone_ = clean_phone;
    json req = { {"@type","setAuthenticationPhoneNumber"}, {"phone_number", clean_phone} };
    logger_->info("submit_phone_async: sending setAuthenticationPhoneNumber to TDLib for phone: " + clean_phone);
    auto resp = request_with_extra_blocking(this, req, "auth_phone:" + rand_token(), 10.0);
    if (!resp.is_object()) {
        logger_->error("submit_phone_async: No response from TDLib after sending phone");
        send_event_to_gui("auth_status", nlohmann::json{{"status", "error"}, {"detail", "No response from Telegram after submitting phone"}});
        return;
    }
    if (resp.contains("@type") && resp["@type"] == "error") {
        logger_->error("submit_phone_async: TDLib error: " + resp.dump());
        send_event_to_gui("auth_status", nlohmann::json{{"status", "error"}, {"detail", resp.dump()}});
        return;
    }
    logger_->info("submit_phone_async: Phone submitted, waiting for code");
    send_event_to_gui("auth_status", nlohmann::json{{"status", "waiting_code"}, {"detail", "Phone submitted, waiting for code"}});
}

void TelegramSession::submit_code_async(const std::string& code) {
    std::string clean_code = trim(code);
    if (clean_code.empty()) {
        send_event_to_gui("auth_status", nlohmann::json{{"status", "error"}, {"detail", "empty_code"}});
        return;
    }
    json req = { {"@type","checkAuthenticationCode"}, {"code", clean_code} };
    auto resp = request_with_extra_blocking(this, req, "auth_code:" + rand_token(), 10.0);
    // Check if login is now ready or if password is needed
    if (resp.is_object() && resp.contains("@type")) {
        std::string tp = resp["@type"].get<std::string>();
        if (tp == "ok" || tp == "authorizationStateReady") {
            authorized_ = true;
            update_auth_stage(AuthStage::Ready);
            send_event_to_gui("auth_status", nlohmann::json{{"status", "authorized"}, {"detail", "Authorization ready"}});
            send_event_to_gui("login_success", nlohmann::json{{"message", "Successfully logged in"}});
            return;
        } else if (tp == "authorizationStateWaitPassword") {
            send_event_to_gui("auth_status", nlohmann::json{{"status", "waiting_password"}, {"detail", "Code submitted, waiting for password"}});
            update_auth_stage(AuthStage::WaitPassword);
            return;
        } else if (tp == "error") {
            send_event_to_gui("auth_status", nlohmann::json{{"status", "error"}, {"detail", resp.dump()}});
            return;
        }
    }
    // Fallback: if we don't know, just say waiting for password
    send_event_to_gui("auth_status", nlohmann::json{{"status", "waiting_password"}, {"detail", "Code submitted, waiting for password if needed"}});
}

void TelegramSession::submit_2fa_async(const std::string& password) {
    std::string clean_pwd = trim(password);
    if (clean_pwd.empty()) {
        send_event_to_gui("auth_status", nlohmann::json{{"status", "error"}, {"detail", "empty_password"}});
        return;
    }
    json req = { {"@type","checkAuthenticationPassword"}, {"password", clean_pwd} };
    request_with_extra_blocking(this, req, "auth_pwd:" + rand_token(), 10.0);
    send_event_to_gui("auth_status", nlohmann::json{{"status", "auth_checking"}, {"detail", "Password submitted, checking..."}});
}

void TelegramSession::submit_code(const std::string& code) { submit_code_async(code); }
void TelegramSession::submit2FA(const std::string& password) { submit_2fa_async(password); }
void TelegramSession::add_phone_number(const std::string& phone) { submit_phone_async(phone); }

void TelegramSession::set_auth_callback(std::function<void(AuthStage)> cb) {
    auth_callback_ = std::move(cb);
}

TelegramSession::AuthStage TelegramSession::get_auth_stage() const {
    return current_auth_stage_;
}

void TelegramSession::set_allowed_sums(const std::set<int>& allowed) {
    allowed_sums_ = allowed;
}
const std::set<int>& TelegramSession::get_allowed_sums() const {
    return allowed_sums_;
}

void TelegramSession::set_dice_emoji(const std::string& emoji) {
    dice_emoji_ = emoji;
}

void TelegramSession::set_group_target(const std::string& group_name_or_id) {
    target_group_ = group_name_or_id;
}

void TelegramSession::add_group_name(const std::string& group) {
    GroupInfo gi; gi.name = group; gi.id = 0; gi.interval_ms = 1000;
    public_groups_.push_back(gi);
}

void TelegramSession::send(const std::string& payload) {
    std::lock_guard<std::mutex> lk(client_mutex_);
    if (!client_) {
        Logger::errorGlobal("send(): TDLib client not initialized");
        return;
    }

    try {
        auto jp = json::parse(payload);
        if (jp.is_object() && jp.contains("@type") && jp["@type"].is_string() && jp["@type"] == "sendMessage") {
            if (jp.contains("input_message_content") && jp["input_message_content"].is_object()) {
                const auto &imc = jp["input_message_content"];
                if (imc.contains("@type") && imc["@type"].is_string() && imc["@type"] == "inputMessageDice") {
                    bool enabled = config_.value("enable_auto_publish", false);
                    if (!enabled) {
                        std::string reason = "Blocked inputMessageDice send (enable_auto_publish=false)";
                        if (logger_) logger_->warn(reason);
                        append_audit(reason + " payload=" + jp.dump());
                        return;
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        Logger::errorGlobal("send(): JSON parse error: " + std::string(e.what()));
    }

    try {
        td_json_client_send(client_, payload.c_str());
        if (logger_) logger_->info("TDLib send: " + (payload.size() > 200 ? payload.substr(0,200) + "..." : payload));
    } catch (const std::exception& e) {
        if (logger_) logger_->error(std::string("send exception: ") + e.what());
    }
}

std::string TelegramSession::receive(double timeout_seconds) {
    std::lock_guard<std::mutex> lk(client_mutex_);
    if (!client_) {
        Logger::errorGlobal("receive(): TDLib client not initialized");
        return {};
    }
    const char* resp = td_json_client_receive(client_, timeout_seconds);
    if (!resp) return {};
    return std::string(resp);
}

void TelegramSession::handle_update(const json& update) {
    if (!update.is_object() || !update.contains("@type")) return;
    std::string t = update["@type"].get<std::string>();

    if (t == "updateAuthorizationState") {
        handle_auth_update(update.value("authorization_state", json{}));
        return;
    }

    if (t == "updateNewMessage" && update.contains("message")) {
        const auto& m = update["message"];
        if (m.contains("chat_id") && m.contains("id") && m.contains("content")) {
            int64_t chat_id = m["chat_id"].get<int64_t>();
            int64_t msg_id  = m["id"].get<int64_t>();
            const auto& content = m["content"];
            if (content.contains("@type") && content["@type"] == "messageDice" && content.contains("value")) {
                int value = content["value"].get<int>();
                if (value >= 1 && value <= 6) {
                    std::lock_guard<std::mutex> lk(g_dice_mtx);
                    g_dice_values[{chat_id,msg_id}] = value;
                    g_dice_cv.notify_all();
                    append_audit("Received dice result chat=" + std::to_string(chat_id) + " msg=" + std::to_string(msg_id) + " value=" + std::to_string(value));
                    // Send dice result event to GUI
                    nlohmann::json data = { {"chat_id", chat_id}, {"msg_id", msg_id}, {"value", value} };
                    send_event_to_gui("dice_result", data);
                } else {
                    append_audit("Ignored dice result with invalid value=" + std::to_string(value) + " for chat=" + std::to_string(chat_id) + " msg=" + std::to_string(msg_id));
                }
            }
        }
        return;
    }

    if (t == "updateMessageContent") {
        if (update.contains("chat_id") && update.contains("message_id")) {
            int64_t chat_id = update["chat_id"].get<int64_t>();
            int64_t msg_id  = update["message_id"].get<int64_t>();
            const auto& content = update["new_content"];
            if (content.contains("@type") && content["@type"] == "messageDice" && content.contains("value")) {
                int value = content["value"].get<int>();
                if (value >= 1 && value <= 6) {
                    std::lock_guard<std::mutex> lk(g_dice_mtx);
                    g_dice_values[{chat_id,msg_id}] = value;
                    g_dice_cv.notify_all();
                    append_audit("Received edited dice content chat=" + std::to_string(chat_id) + " msg=" + std::to_string(msg_id) + " value=" + std::to_string(value));
                    nlohmann::json data = { {"chat_id", chat_id}, {"msg_id", msg_id}, {"value", value}, {"edited", true} };
                    send_event_to_gui("dice_result", data);
                } else {
                    append_audit("Ignored edited dice content with invalid value=" + std::to_string(value) + " for chat=" + std::to_string(chat_id) + " msg=" + std::to_string(msg_id));
                }
            }
        }
        return;
    }
}

void TelegramSession::handle_auth_update(const json& st) {
    if (!st.is_object() || !st.contains("@type")) {
        logger_->error("handle_auth_update: invalid or missing @type in state: " + st.dump());
        return;
    }
    std::string tp = st["@type"].get<std::string>();
    logger_->info("handle_auth_update: received state: " + tp);
    if (tp == "authorizationStateReady") {
        authorized_ = true;
        update_auth_stage(AuthStage::Ready);
        logger_->info("Authorization ready");
        send_event_to_gui("auth_status", nlohmann::json{{"status", "authorized"}, {"detail", "Authorization ready"}});
        // Send explicit login success event for GUI
        send_event_to_gui("login_success", nlohmann::json{{"message", "Successfully logged in"}});
    } else if (tp == "authorizationStateClosed") {
        authorized_ = false;
        update_auth_stage(AuthStage::Closed);
        logger_->warn("Authorization closed");
        send_event_to_gui("auth_status", nlohmann::json{{"status", "closed"}, {"detail", "Authorization closed"}});
    } else if (tp == "authorizationStateWaitPhoneNumber") {
        logger_->info("handle_auth_update: Waiting for phone number");
        send_event_to_gui("auth_status", nlohmann::json{{"status", "waiting_phone"}, {"detail", "Waiting for phone number"}});
        update_auth_stage(AuthStage::WaitPhoneNumber);
    } else if (tp == "authorizationStateWaitCode") {
        logger_->info("handle_auth_update: Waiting for code");
        send_event_to_gui("auth_status", nlohmann::json{{"status", "waiting_code"}, {"detail", "Waiting for code"}});
        update_auth_stage(AuthStage::WaitCode);
    } else if (tp == "authorizationStateWaitPassword") {
        logger_->info("handle_auth_update: Waiting for password");
        send_event_to_gui("auth_status", nlohmann::json{{"status", "waiting_password"}, {"detail", "Waiting for password"}});
        update_auth_stage(AuthStage::WaitPassword);
    } else {
        logger_->warn("handle_auth_update: Unhandled state: " + tp);
        send_event_to_gui("auth_status", nlohmann::json{{"status", "unknown_state"}, {"detail", st.dump()}});
    }
}

void TelegramSession::update_auth_stage(AuthStage s) {
    {
        std::lock_guard<std::mutex> lk(auth_mutex_);
        current_auth_stage_ = s;
    }
    auth_cv_.notify_all();
    if (auth_callback_) auth_callback_(s);
}

void TelegramSession::start_update_listener() {
    if (listening_) return;
    stop_update_listener_flag_ = false;
    listening_ = true;
    update_listener_thread_ = std::thread([this]() {
        logger_->info("update listener started");
        while (!stop_update_listener_flag_) {
            try {
                std::string s = receive(1.0);
                if (s.empty()) continue;
                try {
                    json j = json::parse(s);
                    handle_update(j);
                } catch (const std::exception& e) {
                    logger_->error("update listener: JSON parse error: " + std::string(e.what()));
                }
            } catch (const std::exception& e) {
                logger_->error("update listener: exception: " + std::string(e.what()));
            }
        }
        logger_->info("update listener stopped");
    });
}

void TelegramSession::stop_update_listener() {
    if (!listening_) return;
    stop_update_listener_flag_ = true;
    if (update_listener_thread_.joinable()) update_listener_thread_.join();
    listening_ = false;
}

// Production: cache forum info, robust error handling, clear logging
int TelegramSession::sendDice(int64_t chat_id, int /*dice_value*/) {
    static std::unordered_map<int64_t, std::pair<bool, int64_t>> forum_cache; // chat_id -> (is_forum, message_thread_id)
    std::string emoji = dice_emoji_.empty() ? "🎲" : dice_emoji_;
    logger_->info("[PROD] Attempting to send dice: chat_id=" + std::to_string(chat_id) + ", emoji='" + emoji + "'");

    bool is_forum = false;
    int64_t message_thread_id = 0;
    // Check cache first
    auto it = forum_cache.find(chat_id);
    if (it != forum_cache.end()) {
        is_forum = it->second.first;
        message_thread_id = it->second.second;
    } else {
        try {
            nlohmann::json chat_req = {
                {"@type", "getChat"},
                {"chat_id", chat_id}
            };
            std::string extra = "getforum:" + std::to_string(chat_id) + ":" + rand_token();
            nlohmann::json chat_resp = request_with_extra_blocking(this, chat_req, extra, 10.0);
            if (chat_resp.is_object() && chat_resp.contains("type") && chat_resp["type"].is_object()) {
                auto& type = chat_resp["type"];
                if (type.contains("@type") && type["@type"] == "chatTypeSupergroup") {
                    if (type.contains("is_forum")) {
                        is_forum = type["is_forum"].get<bool>();
                    }
                }
            }
            if (is_forum) {
                if (chat_resp.contains("message_thread_id")) {
                    message_thread_id = chat_resp["message_thread_id"].get<int64_t>();
                } else {
                    message_thread_id = chat_id; // fallback
                }
            }
            forum_cache[chat_id] = std::make_pair(is_forum, message_thread_id);
        } catch (const std::exception& e) {
            logger_->error(std::string("[PROD] sendDice: error checking forum info: ") + e.what());
        }
    }

    json req = {
        {"@type","sendMessage"},
        {"chat_id", chat_id},
        {"input_message_content", { {"@type","inputMessageDice"}, {"emoji", emoji} }}
    };
    // Do NOT set "value" here. Telegram will ignore it; the real value comes in updateMessageContent.
    if (is_forum && message_thread_id != 0) {
        req["message_thread_id"] = message_thread_id;
        logger_->info("[PROD] Sending dice to forum thread: " + std::to_string(message_thread_id));
    }

    std::string extra = "senddice:" + std::to_string(chat_id) + ":" + rand_token();
    json resp = request_with_extra_blocking(this, req, extra, 10.0);
    logger_->info("[PROD] TDLib response for sendDice: " + resp.dump());
    if (!resp.is_object()) {
        logger_->error("[PROD] sendDice: timeout");
        append_audit("sendDice timeout chat=" + std::to_string(chat_id));
        send_event_to_gui("dice_send_failed", { {"chat_id", chat_id}, {"detail", "Timeout sending dice to chat"} });
        return 0;
    }
    if (resp.contains("@type") && resp["@type"] == "error") {
        logger_->error("[PROD] sendDice error: " + resp.dump());
        append_audit("sendDice error: " + resp.dump());
        send_event_to_gui("dice_send_failed", { {"chat_id", chat_id}, {"detail", resp.dump()} });
        return 0;
    }
    if (resp.contains("@type") && resp["@type"] == "message" && resp.contains("id")) {
        int64_t mid = resp["id"].get<int64_t>();
        append_audit("Sent dice chat=" + std::to_string(chat_id) + " msg=" + std::to_string(mid));
        send_event_to_gui("dice_sent", { {"chat_id", chat_id}, {"msg_id", mid}, {"detail", "Dice sent successfully"} });
        return static_cast<int>(mid);
    }
    send_event_to_gui("dice_send_failed", { {"chat_id", chat_id}, {"detail", "Unknown error sending dice"} });
    return 0;
}

int TelegramSession::waitForDiceValue(int64_t chat_id, int msg_id, int timeout_ms) {
    std::unique_lock<std::mutex> lk(g_dice_mtx);
    DiceKey key{chat_id, (int64_t)msg_id};
    auto pred = [&](){
        auto it = g_dice_values.find(key);
        return it != g_dice_values.end() && it->second >= 1 && it->second <= 6;
    };
    bool got = g_dice_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), pred);
    if (!got) {
        logger_->warn("[DICE] waitForDiceValue: Timed out waiting for dice value for chat_id=" + std::to_string(chat_id) + ", msg_id=" + std::to_string(msg_id));
        append_audit("[DICE] waitForDiceValue: Timed out waiting for dice value for chat_id=" + std::to_string(chat_id) + ", msg_id=" + std::to_string(msg_id));
        return -1;
    }
    int value = g_dice_values[key];
    logger_->info("[DICE] waitForDiceValue: Got value=" + std::to_string(value) + " for chat_id=" + std::to_string(chat_id) + ", msg_id=" + std::to_string(msg_id));
    append_audit("[DICE] waitForDiceValue: Got value=" + std::to_string(value) + " for chat_id=" + std::to_string(chat_id) + ", msg_id=" + std::to_string(msg_id));
    return value;
}


std::vector<DiceKey> TelegramSession::sendDiceBatch(int64_t chat_id, int count, int pacing_ms, const std::string& emoji) {
    std::string saved = dice_emoji_;
    if (!emoji.empty()) {
        dice_emoji_ = emoji;
    } else if (dice_emoji_.empty()) {
        dice_emoji_ = "🎲";
    }
    std::vector<DiceKey> keys; keys.reserve(count);
    for (int i=0;i<count;++i) {
        int id = sendDice(chat_id);
        keys.push_back(DiceKey{chat_id, (int64_t)id});
        if (pacing_ms > 0) sleep_ms(pacing_ms);
    }
    if (!emoji.empty()) dice_emoji_ = saved;
    return keys;
}


std::vector<int> TelegramSession::waitForDiceResults(const std::vector<DiceKey>& dice_keys, int per_dice_timeout_ms) {
    std::vector<int> vals; vals.reserve(dice_keys.size());
    for (const auto& key : dice_keys) {
        vals.push_back(waitForDiceValue(key.chat_id, (int)key.msg_id, per_dice_timeout_ms));
    }
    return vals;
}

std::optional<std::tuple<int,int,int>> TelegramSession::pick_best_triple(const std::array<int,10>& dice_values) const {
    std::vector<int> vec(dice_values.begin(), dice_values.end());
    const auto& allowed = valid_sums_.empty() ? allowed_sums_ : valid_sums_;
    std::cout << "[DEBUG] Dice values: ";
    for (int v : vec) std::cout << v << " ";
    std::cout << std::endl;
    std::cout << "[DEBUG] Allowed sums: ";
    for (int s : allowed) std::cout << s << " ";
    std::cout << std::endl;
    BestTriple bt = best_triple_from_vector(vec, allowed);
    if (!bt.found) return std::nullopt;
    return std::make_tuple(bt.i, bt.j, bt.k);
}

std::vector<int> TelegramSession::pick_best_triple(const std::vector<int>& dice_values) const {
    const auto& allowed = valid_sums_.empty() ? allowed_sums_ : valid_sums_;
    std::cout << "[DEBUG] Dice values: ";
    for (int v : dice_values) std::cout << v << " ";
    std::cout << std::endl;
    std::cout << "[DEBUG] Allowed sums: ";
    for (int s : allowed) std::cout << s << " ";
    std::cout << std::endl;
    BestTriple bt = best_triple_from_vector(dice_values, allowed);
    if (!bt.found) {
        return {};
    }
    return {bt.i, bt.j, bt.k};
}

void TelegramSession::on_update(const nlohmann::json& update) {
    try {
        // Log every update received from TDLib for debugging
        std::cout << "[TDLIB-UPDATE] " << update.dump() << std::endl;


        if (!update.contains("@type")) return;

        const std::string& type = update["@type"].get<std::string>();

        // --- Robust dice value extraction and logging ---
        auto store_dice_value = [](int64_t chat_id, int64_t msg_id, int value, const char* src) {
            std::lock_guard<std::mutex> lk(g_dice_mtx);
            g_dice_values[{chat_id, msg_id}] = value;
            g_dice_cv.notify_all();
            std::cout << "[DICE] " << src << ": Stored dice value " << value << " for (chat_id=" << chat_id << ", msg_id=" << msg_id << ")" << std::endl;
        };

        if (type == "updateNewMessage") {
            const auto& msg = update.value("message", json{});
            std::cout << "[UPDATE] New message from chat "
                      << msg.value("chat_id", 0)
                      << ": " << msg.dump() << std::endl;

            {
                std::lock_guard<std::mutex> lock(client_mutex_);
                last_private_msgs_.push_back(msg.value("id", 0));
                if (last_private_msgs_.size() > 100) last_private_msgs_.erase(last_private_msgs_.begin());
            }

            // If this message is a dice roll, update the last10Dice buffer
            if (msg.contains("content") && msg["content"].contains("@type") && msg["content"]["@type"] == "messageDice") {
                int value = -1;
                bool found_direct = false, found_nested = false;
                if (msg["content"].contains("value")) {
                    value = msg["content"]["value"].get<int>();
                    found_direct = true;
                } else if (msg["content"].contains("dice") && msg["content"]["dice"].contains("value")) {
                    value = msg["content"]["dice"]["value"].get<int>();
                    found_nested = true;
                }
                std::cout << "[DEBUG] Dice message received: value=" << value << ", found_direct=" << found_direct << ", found_nested=" << found_nested << ", msg=" << msg.dump() << std::endl;

                // --- Store dice value for waitForDiceValue ---
                if (msg.contains("chat_id") && msg.contains("id")) {
                    int64_t chat_id = msg["chat_id"].get<int64_t>();
                    int64_t msg_id = msg["id"].get<int64_t>();
                    if (value >= 1 && value <= 6) {
                        store_dice_value(chat_id, msg_id, value, "updateNewMessage");
                    } else {
                        std::cout << "[DEBUG] Invalid dice value received (not 1-6): " << value << ". chat_id=" << chat_id << ", msg_id=" << msg_id << std::endl;
                    }
                } else {
                    std::cout << "[DEBUG] Dice message missing chat_id or id: " << msg.dump() << std::endl;
                }

                if (value >= 1 && value <= 6) {
                    collectDiceRoll10(value);
                    std::cout << "[BUFFER] Added dice value to last10Dice: " << value << std::endl;
                    // Trigger best triple calculation
                    auto best = computeBestTripleFrom10();
                    if (best) {
                        std::cout << "[TRIPLE] Best triple sum from last 10: " << *best << std::endl;
                    } else {
                        std::cout << "[TRIPLE] Not enough dice to compute best triple." << std::endl;
                    }
                } else {
                    std::cout << "[DEBUG] Dice value not added to last10Dice: " << value << std::endl;
                }
            }

        } else if (type == "updateMessageContent") {
            if (update.contains("chat_id") && update.contains("message_id")) {
                int64_t chat_id = update["chat_id"].get<int64_t>();
                int64_t msg_id  = update["message_id"].get<int64_t>();
                const auto& content = update["new_content"];
                if (content.contains("@type") && content["@type"] == "messageDice" && content.contains("value")) {
                    int value = content["value"].get<int>();
                    if (value >= 1 && value <= 6) {
                        store_dice_value(chat_id, msg_id, value, "updateMessageContent");
                    } else {
                        std::cout << "[DEBUG] Invalid dice value in updateMessageContent (not 1-6): " << value << ". chat_id=" << chat_id << ", msg_id=" << msg_id << std::endl;
                    }
                }
            }
            return;
        } else if (type == "updateMessageSendSucceeded") {
        } else if (type == "updateMessageSendFailed") {
            std::cerr << "[WARN] Message send failed: " << update.dump() << std::endl;
        } else if (type == "updateDeleteMessages") {
            const auto& ids = update.value("message_ids", json::array());
            std::cout << "[UPDATE] Messages deleted: ";
            for (auto& id : ids) std::cout << id << " ";
            std::cout << std::endl;

            {
                std::lock_guard<std::mutex> lock(client_mutex_);
                for (auto& id : ids) {
                    auto it = std::find(last_private_msgs_.begin(), last_private_msgs_.end(), id.get<int64_t>());
                    if (it != last_private_msgs_.end()) last_private_msgs_.erase(it);
                }
            }
        } else {
            std::cout << "[UPDATE] " << type << ": " << update.dump() << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception in on_update: " << e.what() << std::endl;
        logger_->error("on_update: exception: " + std::string(e.what()));
    } catch (...) {
        std::cerr << "[ERROR] Unknown exception in on_update" << std::endl;
        logger_->error("on_update: unknown exception");
    }
}

void TelegramSession::send_best3_dice_to_public() {
    logger_->info("[DEBUG] send_best3_dice_to_public called");
    send_event_to_gui("dice_batch_start", nlohmann::json{});
    if (!config_.value("enable_auto_publish", false)) {
        logger_->info("send_best3_dice_to_public: auto publish disabled by config");
        append_audit("Auto-publish disabled; skipping send_best3_dice_to_public");
        return;
    }

    if (is_paused_) {
        logger_->warn("send_best3_dice_to_public: paused");
        append_audit("[DEBUG] send_best3_dice_to_public: paused");
        return;
    }
    if (!authorized_) {
        logger_->warn("send_best3_dice_to_public: not authorized");
        append_audit("[DEBUG] send_best3_dice_to_public: not authorized");
        return;
    }
    logger_->info("[DEBUG] Using private_dice_group_id_=" + std::to_string(private_dice_group_id_));
    append_audit("[DEBUG] Using private_dice_group_id_=" + std::to_string(private_dice_group_id_));
    if (private_dice_group_id_ == 0) {
        logger_->error("private group not configured");
        append_audit("[DEBUG] private group not configured");
        return;
    }
    if (public_groups_.empty()) {
        logger_->error("no public groups configured");
        append_audit("[DEBUG] no public groups configured");
        return;
    }

    // Check if bot has access to private group before proceeding
    nlohmann::json chat_req = {{"@type", "getChat"}, {"chat_id", private_dice_group_id_}};
    std::string extra_check = "checkprivate:" + std::to_string(private_dice_group_id_) + ":" + rand_token();
    nlohmann::json chat_resp = request_with_extra_blocking(this, chat_req, extra_check, 10.0);
    if (chat_resp.contains("@type") && chat_resp["@type"] == "error" && chat_resp.contains("message") && chat_resp["message"] == "Chat not found") {
        logger_->error("Private group not found or bot not added");
        append_audit("[DEBUG] Private group not found or bot not added");
        send_event_to_gui("error", {{"detail", "Bot not added to private dice group. Please add the bot to the group as a member or admin."}});
        return;
    }

    const int MAX_ATTEMPTS = config_.value("max_attempts", 3);
    const int TOTAL = config_.value("dice_count", 10);
    const int PER_DICE_TIMEOUT_MS = config_.value("dice_result_timeout_ms", 6000);
    const int SEND_PACING_MS = std::max(1, static_cast<int>(dice_settings_[dice_emoji_].interval_ms));
    const auto& allowed = valid_sums_.empty() ? allowed_sums_ : valid_sums_; // Use allowed sums
    bool auto_delete = config_.value("auto_delete_private_rolls", false);

    for (int attempt=1; attempt<=MAX_ATTEMPTS; ++attempt) {
        logger_->info("[DEBUG] Attempt " + std::to_string(attempt) + " rolling " + std::to_string(TOTAL) + " dice privately to group " + std::to_string(private_dice_group_id_));
        append_audit("[DEBUG] Attempt " + std::to_string(attempt) + " rolling private dice to group " + std::to_string(private_dice_group_id_));

    auto dice_keys = sendDiceBatch(private_dice_group_id_, TOTAL, SEND_PACING_MS);
    logger_->info("[DEBUG] Sent " + std::to_string(dice_keys.size()) + " dice to private group " + std::to_string(private_dice_group_id_));
    append_audit("[DEBUG] Sent private dice count=" + std::to_string(dice_keys.size()) + " to group " + std::to_string(private_dice_group_id_));

    auto vals = waitForDiceResults(dice_keys, PER_DICE_TIMEOUT_MS);
    // Log all 10 dice values
    std::ostringstream dice_log;
    dice_log << "[DEBUG] All 10 dice values: ";
    for (int v : vals) dice_log << v << " ";
    logger_->info(dice_log.str());
    append_audit(dice_log.str());

        logger_->info("[DEBUG] Received " + std::to_string(vals.size()) + " dice results from private group " + std::to_string(private_dice_group_id_));
        std::ostringstream dice_debug;
        dice_debug << "[DEBUG] Dice values received: ";
        for (int v : vals) dice_debug << v << " ";
        logger_->info(dice_debug.str());
        append_audit(dice_debug.str());
        if ((int)vals.size() != TOTAL) {
            logger_->warn("[DEBUG] unexpected results count from private group");
            append_audit("[DEBUG] unexpected results count from private group");
            continue;
        }
        bool any_bad = false;
        for (int v : vals) if (v < 1 || v > 6) { any_bad = true; break; }
        if (any_bad) {
            logger_->warn("[DEBUG] some dice invalid in private group, but proceeding to publish sum anyway");
            append_audit("[DEBUG] some dice invalid in private group, but proceeding to publish sum anyway");
        }

        // --- New pickTriple logic ---
        struct Triple {
            int i, j, k;
            int s;
            double var;
        };
        auto variance3 = [](int a, int b, int c) {
            double m = (a + b + c) / 3.0;
            return ((a - m)*(a - m) + (b - m)*(b - m) + (c - m)*(c - m)) / 3.0;
        };
        std::vector<Triple> all;
        for (int i = 0; i < (int)vals.size(); ++i)
            for (int j = i + 1; j < (int)vals.size(); ++j)
                for (int k = j + 1; k < (int)vals.size(); ++k) {
                    int a = vals[i], b = vals[j], c = vals[k];
                    if (a < 1 || b < 1 || c < 1) continue;
                    int s = a + b + c;
                    all.push_back({i, j, k, s, variance3(a, b, c)});
                }
        if (all.empty()) {
            logger_->info("[DEBUG] No valid triple found in private group (all dice invalid)");
            append_audit("[DEBUG] No valid triple in private group (all dice invalid)");
            send_event_to_gui("public_dice_not_allowed", nlohmann::json{{"detail", "No valid triple (all dice invalid); nothing announced to public group."}});
            return;
        }
        std::vector<int> validSums(allowed.begin(), allowed.end());
        std::sort(validSums.begin(), validSums.end());
        auto isAllowed = [&](int s){
            if (validSums.empty()) return true;
            return std::binary_search(validSums.begin(), validSums.end(), s);
        };
        std::vector<Triple> exact;
        if (!validSums.empty()) {
            for (auto &t : all) if (isAllowed(t.s)) exact.push_back(t);
        } else {
            exact = all;
        }
        auto better = [](const Triple& A, const Triple& B) {
            if (A.var != B.var) return A.var < B.var;
            if (A.s   != B.s)   return A.s   > B.s;
            if (A.i   != B.i)   return A.i   < B.i;
            if (A.j   != B.j)   return A.j   < B.j;
            return A.k < B.k;
        };
        std::optional<Triple> chosen;
        if (!exact.empty()) {
            chosen = *std::min_element(exact.begin(), exact.end(), better);
        } else {
            // No exact match, pick closest
            auto distToAllowed = [&](int s){
                int d = INT_MAX;
                for (int v : validSums) d = std::min(d, std::abs(s - v));
                return d;
            };
            const Triple* best = &all[0];
            int bestD = distToAllowed(all[0].s);
            for (auto &t : all) {
                int d = distToAllowed(t.s);
                if (d < bestD || (d == bestD && better(t, *best))) {
                    bestD = d; best = &t;
                }
            }
            chosen = *best;
        }
        // Logging for exact/closest match
        if (chosen && isAllowed(chosen->s)) {
            logger_->info(std::string("[DEBUG] Picked triple meeting valid_sums: ") +
                std::to_string(vals[chosen->i]) + ", " + std::to_string(vals[chosen->j]) + ", " + std::to_string(vals[chosen->k]) +
                " (sum = " + std::to_string(chosen->s) + ", var = " + std::to_string(chosen->var) + ")");
        } else if (chosen) {
            logger_->warn(std::string("[DEBUG] No exact valid_sums match; picked closest sum ") +
                std::to_string(chosen->s) + " from values " +
                std::to_string(vals[chosen->i]) + ", " + std::to_string(vals[chosen->j]) + ", " + std::to_string(vals[chosen->k]) +
                " (var = " + std::to_string(chosen->var) + ")");
        }
        int v1 = vals[chosen->i], v2 = vals[chosen->j], v3 = vals[chosen->k];
        int sum = v1 + v2 + v3;
        append_audit("[DEBUG] Picked triple indices (" + std::to_string(chosen->i) + "," + std::to_string(chosen->j) + "," + std::to_string(chosen->k) + ") values (" + std::to_string(v1)+","+std::to_string(v2)+","+std::to_string(v3)+") sum=" + std::to_string(sum));
        logger_->info("[DEBUG] Picked triple sum=" + std::to_string(sum) + " from private group " + std::to_string(private_dice_group_id_));
        // End pickTriple logic

        for (const auto& g : public_groups_) {
            logger_->info("[DEBUG] Attempting to send to public group id: " + std::to_string(g.id));
            if (g.id == 0) continue;
            logger_->info("[DEBUG] Announcing best triple to public group " + std::to_string(g.id));

            // 1. Send 3 dice animations that match the real best triple values
            std::string emoji = dice_emoji_;
            if (emoji.empty()) emoji = "🎲";
            std::array<int, 3> triple_vals = {v1, v2, v3};
            for (int n = 0; n < 3; ++n) {
                json req_dice = {
                    {"@type","sendMessage"},
                    {"chat_id", g.id},
                    {"input_message_content", { {"@type","inputMessageDice"}, {"emoji", emoji} }}
                };
                // Do NOT set "value" here. The real dice value will be set by Telegram and received in updateMessageContent.
                send(req_dice.dump());
                sleep_ms(SEND_PACING_MS);
                nlohmann::json data = { {"group_id", g.id}, {"dice_num", n+1}, {"value", triple_vals[n]} };
                send_event_to_gui("public_dice_sent", data);
            }

            // 2. Announce the real picked values and sum in a text message
            std::ostringstream disc;
            disc << "🎲 Official result: " << v1 << ", " << v2 << ", " << v3 << " (sum = " << sum << ")";
            json req_sum = { {"@type","sendMessage"}, {"chat_id", g.id}, {"input_message_content", { {"@type","inputMessageText"}, {"text", { {"@type","formattedText"}, {"text", disc.str()} } } } } };
            send(req_sum.dump());

            // Notify GUI of summary message
            nlohmann::json summary = { {"group_id", g.id}, {"sum", sum}, {"v1", v1}, {"v2", v2}, {"v3", v3} };
            send_event_to_gui("public_dice_summary", summary);
        }

        if (auto_delete) {
            // Wait 10 minutes before deleting the remaining 7 dice
            logger_->info("[DEBUG] Waiting 10 minutes before deleting remaining private dice messages...");
            std::this_thread::sleep_for(std::chrono::minutes(10));
            // Delete only the 7 dice not used in the chosen triple
            std::vector<int64_t> to_delete;
            if (chosen) {
                for (int idx = 0; idx < (int)dice_keys.size(); ++idx) {
                    if (idx != chosen->i && idx != chosen->j && idx != chosen->k) {
                        to_delete.push_back(dice_keys[idx].msg_id);
                    }
                }
            }
            bool ok = delete_private_messages(private_dice_group_id_, to_delete);
            if (ok) append_audit("[DEBUG] Auto-deleted remaining private rolls after 10 minutes");
            else append_audit("[DEBUG] Auto-delete failed after 10 minutes");
        }

        logger_->info("[DEBUG] Completed send_best3_dice_to_public successfully");
        return;
    }

    logger_->warn("[DEBUG] All attempts exhausted; failed to publish best triple");
    append_audit("[DEBUG] Failed to publish best triple after attempts");
}

bool TelegramSession::delete_private_messages(int64_t chat_id, const std::vector<int64_t>& message_ids) {
    if (message_ids.empty()) return true;
    try {
        json req = { {"@type","deleteMessages"}, {"chat_id", chat_id}, {"message_ids", message_ids}, {"revoke", true} };
        std::string extra = "del:" + std::to_string(chat_id) + ":" + rand_token();
        json resp = request_with_extra_blocking(this, req, extra, 10.0);
        if (!resp.is_object() || (resp.contains("@type") && resp["@type"]=="error")) {
            if (resp.is_object() && resp.contains("code") && resp["code"] == 400) {
                logger_->warn("deleteMessages skipped error 400: " + resp.dump());
                append_audit("deleteMessages skipped error 400: " + resp.dump());
                return true;
            }
            logger_->warn("deleteMessages failed: " + resp.dump());
            append_audit("deleteMessages failed: " + resp.dump());
            return false;
        }
        append_audit("Deleted private messages chat=" + std::to_string(chat_id) + " count=" + std::to_string(message_ids.size()));
        return true;
    } catch (const std::exception& e) {
        logger_->warn(std::string("deleteMessages exception: ") + e.what());
        append_audit(std::string("deleteMessages exception: ") + e.what());
        return false;
    }
}

void TelegramSession::delete_message(long chat_id, long message_id) {
    json req;
    req["@type"] = "deleteMessages";
    req["chat_id"] = chat_id;
    req["message_ids"] = { message_id };
    req["revoke"] = true;
    send(req.dump());
}

json TelegramSession::copy_messages_to_public(int64_t from_chat_id, int64_t to_chat_id, const std::vector<int64_t>& message_ids) {
    if (message_ids.empty()) return json();
    json req = {
        {"@type","copyMessages"},
        {"chat_id", to_chat_id},
        {"from_chat_id", from_chat_id},
        {"message_ids", message_ids},
        {"options", { {"@type","messageSendOptions"} }},
        {"send_copy", true},
        {"remove_caption", false}
    };
    std::string extra = "copy:" + std::to_string(from_chat_id) + ":" + rand_token();
    json resp = request_with_extra_blocking(this, req, extra, 10.0);
    if (!resp.is_object() || (resp.contains("@type") && resp["@type"]=="error")) {
        logger_->warn("copyMessages failed: " + resp.dump());
        append_audit("copyMessages failed: " + resp.dump());
        return json();
    }
    append_audit("Copied " + std::to_string(message_ids.size()) + " messages from " + std::to_string(from_chat_id) + " to " + std::to_string(to_chat_id));
    return resp;
}

// Singleton instance for TelegramSession
TelegramSession& TelegramSession::get_instance() {
    static TelegramSession instance;
    return instance;
}
void TelegramSession::close() { 
    stop_update_listener(); 
#ifdef __unix__
    s_control_server_running = false;
    if (s_control_server_fd != -1) {
        shutdown(s_control_server_fd, SHUT_RDWR);
        ::close(s_control_server_fd);
        s_control_server_fd = -1;
    }
#endif
}

void TelegramSession::switch_account(const std::string& new_phone) {
    if (new_phone.empty()) {
        logger_->error("switch_account: empty phone number");
        return;
    }
    logger_->info("switch_account: switching to phone " + new_phone);
    close();
    submit_phone_async(new_phone);
}

void TelegramSession::set_session_suffix(const std::string& suffix) { session_suffix_ = suffix; }

void TelegramSession::reset_session_files() {
    try {
        std::filesystem::remove_all("tdlib-data/" + session_suffix_);
        logger_->info("reset_session_files: cleared session files for " + session_suffix_);
    } catch (const std::exception& e) {
        logger_->error("reset_session_files: failed to remove session files: " + std::string(e.what()));
    }
}

void TelegramSession::remove_session() {
    close();
    reset_session_files();
    authorized_ = false;
    update_auth_stage(AuthStage::Closed);
    logger_->info("remove_session: session removed");
}

void TelegramSession::save_config() {
    try {
        std::ofstream file("resources/config/config.json");
        if (!file) {
            logger_->error("save_config: failed to open config file");
            return;
        }
        file << config_.dump(2);
        logger_->info("save_config: configuration saved");
    } catch (const std::exception& e) {
        logger_->error("save_config: error: " + std::string(e.what()));
    }
}

bool TelegramSession::is_authorized() const { return authorized_; }
int64_t TelegramSession::get_own_user_id() { return 0; }
bool TelegramSession::is_paused() const { return is_paused_; }
void TelegramSession::pause_dice() { is_paused_ = true; }
void TelegramSession::resume_dice() { is_paused_ = false; }

void TelegramSession::parse_dice_command(const std::string& command) {
    std::regex cmd_regex(R"(^([\x{1F3B2}-\x{1F3FF}]):(\d+):(-?\d+))",
                         std::regex::ECMAScript | std::regex::icase | std::regex::optimize);
    std::smatch match;
    if (std::regex_match(command, match, cmd_regex)) {
        std::string emoji = match[1];
        int target = std::stoi(match[2]);
        int64_t chat_id = std::stoll(match[3]);
        set_dice_emoji(emoji);
        if (g_handler) {
            g_handler->process_dice_command(emoji, target, chat_id);
            append_audit("Parsed dice command: " + command);
        }
    } else {
        logger_->warn("parse_dice_command: invalid command format: " + command);
        append_audit("Invalid dice command: " + command);
    }
}

void TelegramSession::set_language(const std::string& lang_code) { system_language_code_ = lang_code; }

int64_t TelegramSession::get_private_group_id() const { return private_dice_group_id_; }

std::vector<int64_t> TelegramSession::get_last_private_msgs(int count) {
    auto it = group_message_cache_.find(private_dice_group_id_);
    if (it == group_message_cache_.end()) return {};
    std::vector<int64_t> out;
    auto &v = it->second;
    for (int i = std::max(0, (int)v.size() - count); i < (int)v.size(); ++i) out.push_back(v[i]);
    return out;
}

bool TelegramSession::has_access_to_group(int64_t chat_id) {
    for (auto &g : public_groups_) if (g.id == chat_id) return true;
    if (chat_id == private_dice_group_id_) return true;
    return false;
}

int64_t TelegramSession::resolve_group_name(const std::string& name) {
    try { return std::stoll(name); } catch(...) {}
    for (auto &g : public_groups_) if (g.name == name) return g.id;
    return 0;
}

void TelegramSession::log_info(const std::string& s) { if (logger_) logger_->info(s); }
void TelegramSession::log_warn(const std::string& s) { if (logger_) logger_->warn(s); }
void TelegramSession::log_error(const std::string& s) { if (logger_) logger_->error(s); }

bool TelegramSession::is_waiting_for_code() const { return current_auth_stage_ == AuthStage::WaitCode; }
bool TelegramSession::is_waiting_for_password() const { return current_auth_stage_ == AuthStage::WaitPassword; }

void TelegramSession::append_audit(const std::string& s) {
    static std::ofstream f("dice_rolls.log", std::ios::app);
    if (!f) return;
    f << "[" << now_ts() << "] " << s << std::endl;
    f.flush();
}

std::vector<std::string> TelegramSession::get_audit_logs(int max_lines) {
    std::vector<std::string> logs;
    std::ifstream f("dice_rolls.log");
    if (!f) {
        logger_->error("get_audit_logs: failed to open dice_rolls.log");
        return logs;
    }
    std::string line;
    while (std::getline(f, line) && (max_lines <= 0 || logs.size() < static_cast<size_t>(max_lines))) {
        logs.push_back(line);
    }
    return logs;
}

void TelegramSession::start_control_server() {
#ifdef __unix__
    if (s_control_server_running.load()) return;
    s_control_server_running = true;
    s_control_thread = std::thread([this]() {
        int port = config_.value("control_port", 8879);
        int srv = ::socket(AF_INET, SOCK_STREAM, 0);
        if (srv < 0) { if (logger_) logger_->error("control server: socket failed"); s_control_server_running = false; return; }
        int one = 1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        if (::bind(srv, (struct sockaddr*)&addr, sizeof(addr)) != 0) { 
            ::close(srv); 
            if (logger_) logger_->error("control server: bind failed on port " + std::to_string(port)); 
            s_control_server_running = false; 
            return; 
        }
        if (::listen(srv, 4) != 0) { ::close(srv); if (logger_) logger_->error("control server: listen failed"); s_control_server_running = false; return; }
        s_control_server_fd = srv;
        if (logger_) logger_->info("Control server running on port " + std::to_string(port));
        while (s_control_server_running) {
            struct sockaddr_in peer{}; socklen_t plen = sizeof(peer);
            int fd = accept(srv, (struct sockaddr*)&peer, &plen);
            if (fd < 0) { if (!s_control_server_running) break; sleep_ms(50); continue; }
            std::string line;
            char buf[1024];
            ssize_t n;
            struct timeval tv; tv.tv_sec = 5; tv.tv_usec = 0;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) {
                line.append(buf, buf + n);
                if (!line.empty() && line.back() == '\n') break;
                if (line.size() > 65536) break;
            }
            if (!line.empty() && line.back() == '\n') line.pop_back();
            std::string reply;
            try { 
                reply = this->handle_control_command(line); 
            } catch (const std::exception& ex) { 
                json err; err["ok"]=false; err["error"]="handler_exception: " + std::string(ex.what()); reply = err.dump(); 
            } catch (...) { 
                json err; err["ok"]=false; err["error"]="unknown_exception"; reply = err.dump(); 
            }
            reply.push_back('\n');
            ::send(fd, reply.data(), reply.size(), 0);
            ::close(fd);
        }
        ::close(srv);
        s_control_server_fd = -1;
        if (logger_) logger_->info("Control server stopped");
    });
    s_control_thread.detach();
#endif
}

void TelegramSession::stop_control_server() {
#ifdef __unix__
    s_control_server_running = false;
    if (s_control_server_fd != -1) {
        shutdown(s_control_server_fd, SHUT_RDWR);
        ::close(s_control_server_fd);
        s_control_server_fd = -1;
    }
#endif
}

// List accessible group chats and check if private_dice_group_id_ is present
void TelegramSession::list_accessible_groups() {
    // Request a list of chats (groups, supergroups, channels)
    nlohmann::json req = {
        {"@type", "getChats"},
        {"limit", 100} // Adjust as needed
    };
    std::string extra = "listgroups:" + rand_token();
    nlohmann::json resp = request_with_extra_blocking(this, req, extra, 10.0);

    std::vector<int64_t> group_ids;
    if (resp.is_object() && resp.contains("chat_ids")) {
        for (const auto& id : resp["chat_ids"]) {
            group_ids.push_back(id.get<int64_t>());
        }
    }

    // Check if private_dice_group_id_ is present
    bool found = std::find(group_ids.begin(), group_ids.end(), this->private_dice_group_id_) != group_ids.end();

    // Send result to GUI
    nlohmann::json data = {
        {"all_group_ids", group_ids},
        {"private_dice_group_id", this->private_dice_group_id_},
        {"private_group_accessible", found}
    };
    send_event_to_gui("group_list_check", data);
}

std::string TelegramSession::handle_control_command(const std::string& line) {
    try {
        json req;
        if (!line.empty() && (line.front() == '{' || line.front() == '[')) {
            req = json::parse(line);
            if (req.is_object() && req.contains("command") && req["command"].is_string()) {
                std::string cmd = req["command"].get<std::string>();
                if (cmd == "get_audit_logs") {
                    int max_lines = req.value("max_lines", 100);
                    auto logs = get_audit_logs(max_lines);
                    json resp;
                    resp["ok"] = true;
                    resp["logs"] = logs;
                    return resp.dump();
                }
                if (cmd == "send_best3_dice_to_public" || cmd == "dice_batch") {
                    send_best3_dice_to_public();
                    json resp; resp["ok"] = true; resp["status"] = "dice_sent";
                    return resp.dump();
                }
                if (cmd == "list_accessible_groups") {
                    list_accessible_groups();
                    json resp; resp["ok"] = true; resp["status"] = "groups_listed";
                    return resp.dump();
                }
                if (cmd == "get_forum_info" && req.contains("group_id")) {
                    int64_t group_id = 0;
                    try { group_id = req["group_id"].get<int64_t>(); } catch(...) {}
                    nlohmann::json chat_req = {
                        {"@type", "getChat"},
                        {"chat_id", group_id}
                    };
                    std::string extra = "getforum:" + std::to_string(group_id) + ":" + rand_token();
                    nlohmann::json chat_resp = request_with_extra_blocking(this, chat_req, extra, 10.0);
                    bool is_forum = false;
                    int64_t default_thread_id = 0;
                    std::string title;
                    if (chat_resp.is_object() && chat_resp.contains("type") && chat_resp["type"].is_object()) {
                        auto& type = chat_resp["type"];
                        if (type.contains("@type") && type["@type"] == "chatTypeSupergroup") {
                            if (type.contains("is_forum")) {
                                is_forum = type["is_forum"].get<bool>();
                            }
                            if (type.contains("supergroup_id")) {
                                // Optionally, can use getForumTopics to list topics
                            }
                        }
                    }
                    if (chat_resp.contains("title")) title = chat_resp["title"].get<std::string>();
                    // For forums, the default thread is the group id itself, but you may want to use a specific topic
                    if (is_forum) {
                        // Try to get the default topic/thread id
                        if (chat_resp.contains("message_thread_id")) {
                            default_thread_id = chat_resp["message_thread_id"].get<int64_t>();
                        } else {
                            default_thread_id = group_id; // fallback
                        }
                    }
                    nlohmann::json resp;
                    resp["ok"] = true;
                    resp["group_id"] = group_id;
                    resp["is_forum"] = is_forum;
                    resp["title"] = title;
                    resp["default_message_thread_id"] = default_thread_id;
                    resp["raw_chat"] = chat_resp;
                    return resp.dump();
                }
                if (g_handler) g_handler->sendCommand(cmd);
                json ok; ok["ok"]=true; return ok.dump();
            }
        }
        if (!line.empty()) {
            if (g_handler) g_handler->sendCommand(line);
            json ok; ok["ok"]=true; return ok.dump();
        }
        json err; err["ok"]=false; err["error"]="empty_command";
        return err.dump();
    } catch (const std::exception& ex) {
        json err; err["ok"]=false; err["error"]=std::string("exception:")+ex.what();
        return err.dump();
    } catch (...) {
        json err; err["ok"]=false; err["error"]="unknown_exception";
        return err.dump();
    }
}

// Public setters for dice config values
void TelegramSession::set_dice_count(int count) {
    config_["dice_count"] = count;
}
void TelegramSession::set_dice_result_timeout_ms(int ms) {
    config_["dice_result_timeout_ms"] = ms;
}
void TelegramSession::set_auto_delete_private_rolls(bool value) {
    config_["auto_delete_private_rolls"] = value;
}
void TelegramSession::set_max_attempts(int attempts) {
    config_["max_attempts"] = attempts;
}
void TelegramSession::set_auto_delete_delay_ms(int ms) {
    config_["auto_delete_delay_ms"] = ms;
}
// String trim implementation for TelegramSession
std::string TelegramSession::trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\n\r");
    return s.substr(start, end - start + 1);
}
