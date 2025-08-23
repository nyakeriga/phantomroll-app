// PhantomRollUI.java
package com.phantomroll.gui;
import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

public class PhantomRollUI {
private static DefaultListModel<String> groupListModel = new DefaultListModel<>();
private static final File CONFIG_FILE = new File("config.json");
private static final java.util.List<String> accountList = new ArrayList<>();
private static final JComboBox<String> accountDropdown = new JComboBox<>();
private static String currentLanguage = "zh"; // Default Chinese

private static Map<String, String[]> translations = new HashMap<>();

// --- Color Palette ---
private static final Color ACCENT = new Color(51, 153, 255);
private static final Color ACCENT2 = new Color(0, 204, 102);
private static final Color BACKGROUND = new Color(28, 32, 40);
private static final Color PANEL_BG = new Color(36, 40, 48);
private static final Color BORDER_COLOR = new Color(60, 60, 80);
private static final Color GROUP_BG = new Color(44, 48, 56);
private static final Color GROUP_FG = new Color(180, 220, 255);
private static final Color LOG_BG = new Color(20, 22, 28);
private static final Color LOG_FG = new Color(0, 255, 128);

// central log reference (used by background send method and buttons)
private static JTextArea mainLogArea;

// UI component references (so language change updates whole UI)
private static JFrame frame;
private static JButton loginBtn, logoutBtn; // Removed langToggle from here
private static JButton loginMenuButton;
private static JMenu settingsMenu, languageMenu;
private static JMenuItem chineseItem, englishItem;
private static JScrollPane centerScroll;
private static JList<String> groupList;
private static JScrollPane groupsScroll;
private static JButton btnRemove, btnSave, btnSwitch, btnPause, btnOTP, btnAdd, btnSend;

// chosen UI font family (CJK-capable if available)
private static String UI_FONT_FAMILY = "SansSerif";

// auth state
private static boolean loggedIn = false;

static {
    // [Chinese, English]
    translations.put("loginTelegram", new String[]{"登录 Telegram", "Login to Telegram"});
    translations.put("addAccount", new String[]{"添加账户", "Add Account"});
    translations.put("addGroup", new String[]{"群组", "Groups"});
    translations.put("removeSelected", new String[]{"删除所选", "Remove Selected"});
    translations.put("saveConfig", new String[]{"保存配置", "Save Config"});
    translations.put("switchAccount", new String[]{"切换账户", "Switch Account"});
    translations.put("send", new String[]{"发送", "Send"});
    translations.put("pause", new String[]{"暂停", "Pause"});
    translations.put("submitPassword", new String[]{"提交二次验证密码", "Submit 2FA Password"});
    translations.put("activityLog", new String[]{"活动日志", "Activity Log"});
    translations.put("settings", new String[]{"设置", "Settings"});
    translations.put("language", new String[]{"语言", "Language"});
    translations.put("chinese", new String[]{"中文", "Chinese"});
    translations.put("english", new String[]{"英文", "English"});
    translations.put("enterPhone", new String[]{"请输入手机号:", "Enter phone number:"});
    translations.put("languageSwitched", new String[]{"语言已切换", "Language switched"});
    translations.put("backendNotReady", new String[]{" 后端未准备好，请稍后重试。", " Backend not ready after several attempts."});
    translations.put("connectionError", new String[]{"连接错误", "Connection Error"});
    translations.put("error", new String[]{"错误", "Error"});
    translations.put("logout", new String[]{"登出", "Logout"});
    translations.put("logoutSuccess", new String[]{"已登出", "Logged out"});
    // Login dialog
    translations.put("loginPromptTitle", new String[]{"登录", "Login"});
    translations.put("loginPromptMsg", new String[]{"请输入手机号登录 Telegram:", "Please enter your phone number to login to Telegram:"});
    translations.put("loginBtn", new String[]{"登录", "Login"});
    translations.put("loginSuccess", new String[]{" 登录成功", " Login successful"});
    translations.put("loginFailed", new String[]{" 登录失败", " Login failed"});
    translations.put("loginInProgress", new String[]{"正在登录...", "Logging in..."});
    translations.put("enter2fa", new String[]{"请输入二次验证密码:", "Enter 2FA password:"});
    translations.put("enterCode", new String[]{"请输入验证码:", "Enter verification code:"});
    translations.put("submitCode", new String[]{"提交验证码", "Submit Code"});
}

private static String t(String key) {
    String[] vals = translations.getOrDefault(key, new String[]{key, key});
    return currentLanguage.equals("zh") ? vals[0] : vals[1];
}

private static boolean isBackendRunning() {
    try (Socket socket = new Socket("localhost", 8879)) {
        return true;
    } catch (IOException e) {
        return false;
    }
}

private static void waitForBackendReady() {
    int retries = 15;
    while (retries-- > 0) {
        try (Socket socket = new Socket("localhost", 8879)) {
            return;
        } catch (IOException e) {
            try { Thread.sleep(500); } catch (InterruptedException ignored) {}
        }
    }
    JOptionPane.showMessageDialog(frame, t("backendNotReady"), t("connectionError"), JOptionPane.ERROR_MESSAGE);
}

private static void startBackendIfNotRunning(String sessionName) {
    if (!isBackendRunning()) {
        try {
            String exePath = new File("phantomroll_exec.exe").getAbsolutePath();
            ProcessBuilder pb = new ProcessBuilder(exePath, "--session", sessionName);
            pb.redirectErrorStream(true);
            pb.start();
        } catch (IOException e) {
            JOptionPane.showMessageDialog(frame, " " + e.getMessage(), t("error"), JOptionPane.ERROR_MESSAGE);
        }
    }
}

private static void saveConfig() {
    try {
        JSONObject config = new JSONObject();
        config.put("language", currentLanguage);
        JSONArray groupsArr = new JSONArray();
        for (int i = 0; i < groupListModel.getSize(); i++) {
            groupsArr.put(groupListModel.getElementAt(i));
        }
        config.put("groups", groupsArr);
        // write using UTF-8 to preserve Chinese correctly
        Files.writeString(CONFIG_FILE.toPath(), config.toString(2), StandardCharsets.UTF_8);
        if (mainLogArea != null) mainLogArea.append("[INFO] Config saved to " + CONFIG_FILE.getAbsolutePath() + "\n");
    } catch (IOException | JSONException e) {
        JOptionPane.showMessageDialog(frame, " " + e.getMessage(), t("error"), JOptionPane.ERROR_MESSAGE);
    }
}

private static void loadConfig() {
    if (!CONFIG_FILE.exists()) return;
    try {
        // read using UTF-8 to preserve Chinese correctly
        String content = Files.readString(CONFIG_FILE.toPath(), StandardCharsets.UTF_8);
        JSONObject config = new JSONObject(content);
        if (config.has("language")) {
            currentLanguage = config.getString("language").equals("zh") ? "zh" : "en";
        }
        if (config.has("groups")) {
            JSONArray groupsArr = config.getJSONArray("groups");
            for (int i = 0; i < groupsArr.length(); i++) {
                String group = groupsArr.getString(i);
                if (!groupListModel.contains(group)) {
                    groupListModel.addElement(group);
                }
            }
        }
        if (mainLogArea != null) mainLogArea.append("[INFO] Loaded config from " + CONFIG_FILE.getAbsolutePath() + "\n");
    } catch (IOException | JSONException e) {
        JOptionPane.showMessageDialog(frame, " " + e.getMessage(), t("error"), JOptionPane.ERROR_MESSAGE);
    }
}

// update login/logout UI state
private static void setLoggedIn(boolean v) {
    loggedIn = v;
    if (loginBtn != null) loginBtn.setVisible(!v);
    if (logoutBtn != null) logoutBtn.setVisible(v);
    if (loginMenuButton != null) loginMenuButton.setText(v ? t("logout") : t("loginBtn"));
}

// Send command to backend in background thread (sends JSON)
private static String sendCommandToBackend(String cmdJsonStr) {
    String response = null;
    try (Socket socket = new Socket("localhost", 8879);
         OutputStreamWriter writer = new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8);
         BufferedWriter out = new BufferedWriter(writer);
         BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))) {

        out.write(cmdJsonStr);
        out.write("\n");
        out.flush();

        SwingUtilities.invokeLater(() -> {
            if (mainLogArea != null) mainLogArea.append("> " + cmdJsonStr + "\n");
        });

        // read single-line response
        response = in.readLine();
        if (response != null) {
            final String resp = response; // make final copy for lambda capture
            SwingUtilities.invokeLater(() -> {
                if (mainLogArea != null) mainLogArea.append("< " + resp + "\n");
            });
        }

    } catch (IOException e) {
        SwingUtilities.invokeLater(() -> {
            if (mainLogArea != null) mainLogArea.append("[ERROR] Failed to send command: " + e.getMessage() + "\n");
        });
    }
    return response;
}

private static void sendCommandToBackendAsync(String cmdJsonStr) {
    new Thread(() -> {
        String response = sendCommandToBackend(cmdJsonStr);
        if (response != null) {
            final String finalResponse = response;
            SwingUtilities.invokeLater(() -> {
                if (mainLogArea != null) mainLogArea.append("< " + finalResponse + "\n");
            });
            try {
                JSONObject respObj = new JSONObject(response);
                if (respObj.has("event")) {
                    String ev = respObj.getString("event");
                    if ("login_success".equalsIgnoreCase(ev)) {
                        SwingUtilities.invokeLater(() -> setLoggedIn(true));
                    } else if ("logout_success".equalsIgnoreCase(ev)) {
                        SwingUtilities.invokeLater(() -> setLoggedIn(false));
                    }
                }
            } catch (JSONException je) {
                // non-JSON response is OK
            }
        }
    }).start();
}

// Get status from backend
private static JSONObject getBackendStatus() {
    String response = sendCommandToBackend("{\"command\":\"status\"}");
    if (response != null) {
        try {
            return new JSONObject(response);
        } catch (JSONException e) {
            // invalid
        }
    }
    return null;
}

// Poll status and handle auth flow (prompt code/2fa)
private static void pollAuthStatus() {
    new Thread(() -> {
        boolean wasWaitingCode = false;
        boolean wasWaitingPassword = false;
        while (true) {
            JSONObject status = getBackendStatus();
            if (status == null) {
                try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
                continue;
            }

            final boolean authorized = status.optBoolean("authorized", false);
            final boolean waitingCode = status.optBoolean("waiting_for_code", false);
            final boolean waitingPassword = status.optBoolean("waiting_for_password", false);
            final int authStage = status.optInt("auth_stage", 0);

            SwingUtilities.invokeLater(() -> {
                if (mainLogArea != null) mainLogArea.append("[STATUS] Authorized: " + authorized + ", Stage: " + authStage + "\n");
            });

            if (authorized) {
                SwingUtilities.invokeLater(() -> setLoggedIn(true));
                break;
            }

            if (waitingCode && !wasWaitingCode) {
                wasWaitingCode = true;
                SwingUtilities.invokeLater(() -> {
                    String code = JOptionPane.showInputDialog(frame, t("enterCode"));
                    if (code != null && !code.isBlank()) {
                        try {
                            JSONObject cmd = new JSONObject();
                            cmd.put("command", "submit_code");
                            cmd.put("code", code.trim());
                            sendCommandToBackendAsync(cmd.toString());
                        } catch (JSONException je) {
                            if (mainLogArea != null) mainLogArea.append("[ERROR] JSON error: " + je.getMessage() + "\n");
                        }
                    }
                });
            } else if (!waitingCode) {
                wasWaitingCode = false;
            }

            if (waitingPassword && !wasWaitingPassword) {
                wasWaitingPassword = true;
                SwingUtilities.invokeLater(() -> {
                    String pass = JOptionPane.showInputDialog(frame, t("enter2fa"));
                    if (pass != null && !pass.isBlank()) {
                        try {
                            JSONObject cmd = new JSONObject();
                            cmd.put("command", "submit_password");
                            cmd.put("password", pass.trim());
                            sendCommandToBackendAsync(cmd.toString());
                        } catch (JSONException je) {
                            if (mainLogArea != null) mainLogArea.append("[ERROR] JSON error: " + je.getMessage() + "\n");
                        }
                    }
                });
            } else if (!waitingPassword) {
                wasWaitingPassword = false;
            }

            try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
        }
    }).start();
}

// Show login dialog and send login command
private static void showLoginDialog(JTextArea logArea) {
    JPanel panel = new JPanel(new BorderLayout(5, 5));
    JLabel label = new JLabel(t("loginPromptMsg"));
    JTextField phoneField = new JTextField();
    panel.add(label, BorderLayout.NORTH);
    panel.add(phoneField, BorderLayout.CENTER);

    int result = JOptionPane.showOptionDialog(
            frame,
            panel,
            t("loginPromptTitle"),
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE,
            null,
            new Object[]{t("loginBtn"), UIManager.getString("OptionPane.cancelButtonText")},
            t("loginBtn")
    );

    if (result == JOptionPane.OK_OPTION) {
        String phone = phoneField.getText().trim();
        if (!phone.isEmpty()) {
            if (logArea != null) logArea.append(t("loginInProgress") + "\n");
            try {
                JSONObject cmd = new JSONObject();
                cmd.put("command", "login");
                cmd.put("phone", phone);
                sendCommandToBackendAsync(cmd.toString());
            } catch (JSONException je) {
                if (mainLogArea != null) mainLogArea.append("[ERROR] JSON error: " + je.getMessage() + "\n");
            }
            pollAuthStatus();
        }
    }
}

// Refresh UI text translations for all stored components
private static void refreshAllTexts() {
    if (loginBtn != null) loginBtn.setText(t("loginBtn"));
    if (logoutBtn != null) logoutBtn.setText(t("logout"));
    if (loginMenuButton != null) loginMenuButton.setText(loggedIn ? t("logout") : t("loginBtn"));
    if (settingsMenu != null) settingsMenu.setText(t("settings"));
    if (languageMenu != null) languageMenu.setText(t("language"));
    if (chineseItem != null) chineseItem.setText(t("chinese"));
    if (englishItem != null) englishItem.setText(t("english"));
    if (btnRemove != null) btnRemove.setText(t("removeSelected"));
    if (btnSave != null) btnSave.setText(t("saveConfig"));
    if (btnSwitch != null) btnSwitch.setText(t("switchAccount"));
    if (btnPause != null) btnPause.setText(t("pause"));
    if (btnOTP != null) btnOTP.setText(t("submitPassword"));
    if (btnAdd != null) btnAdd.setText(t("addGroup"));
    if (btnSend != null) btnSend.setText(t("send") + " \uD83C\uDFB2");
    if (centerScroll != null) centerScroll.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(ACCENT, 2), t("activityLog"),
            TitledBorder.LEFT, TitledBorder.TOP, new Font(UI_FONT_FAMILY, Font.BOLD, 13), ACCENT));
    if (groupsScroll != null) groupsScroll.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(ACCENT, 1), t("addGroup"),
            TitledBorder.LEFT, TitledBorder.TOP, new Font(UI_FONT_FAMILY, Font.BOLD, 12), ACCENT));
}

// Helper for button hover and style
private static void styleBigButton(final JButton button, final Color normal, final Color hover) {
    button.setBackground(normal);
    button.setForeground(Color.WHITE);
    button.setFocusPainted(false);
    button.setBorder(BorderFactory.createLineBorder(BORDER_COLOR, 1));
    button.setFont(new Font(UI_FONT_FAMILY, Font.BOLD, 14));
    button.setPreferredSize(new Dimension(0, 52)); // taller
    button.addMouseListener(new MouseAdapter() {
        public void mouseEntered(MouseEvent evt) { button.setBackground(hover); }
        public void mouseExited(MouseEvent evt) { button.setBackground(normal); }
    });
}

private static void addHoverEffect(final JButton button, final Color normal, final Color hover) {
    button.setBackground(normal);
    button.setForeground(Color.WHITE);
    button.setFocusPainted(false);
    button.setBorder(BorderFactory.createLineBorder(BORDER_COLOR, 1));
    button.setFont(new Font(UI_FONT_FAMILY, Font.PLAIN, 13));
    button.addMouseListener(new java.awt.event.MouseAdapter() {
        public void mouseEntered(java.awt.event.MouseEvent evt) { button.setBackground(hover); }
        public void mouseExited(java.awt.event.MouseEvent evt) { button.setBackground(normal); }
    });
}

public static void main(String[] args) {
    // load config early (so language and groups are available while building UI)
    loadConfig();

    SwingUtilities.invokeLater(() -> {
        try { UIManager.setLookAndFeel("javax.swing.plaf.nimbus.NimbusLookAndFeel"); } catch (Exception ignored) {}

        // Font setup - prefer CJK-capable fonts so Chinese renders correctly
        try {
            String[] preferred = new String[] {"Microsoft YaHei", "Microsoft Yahei UI", "Noto Sans CJK SC", "SimSun", "Arial Unicode MS", "Segoe UI", "SansSerif"};
            String chosen = null;
            GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
            Set<String> available = new HashSet<>(Arrays.asList(ge.getAvailableFontFamilyNames()));
            for (String p : preferred) { if (available.contains(p)) { chosen = p; break; } }
            if (chosen == null && available.size() > 0) chosen = available.iterator().next();
            if (chosen != null) {
                UI_FONT_FAMILY = chosen;
                Font uiFont = new Font(chosen, Font.PLAIN, 13);
                UIManager.put("Button.font", uiFont);
                UIManager.put("Label.font", uiFont);
                UIManager.put("TextArea.font", uiFont);
                UIManager.put("TextField.font", uiFont);
                UIManager.put("Menu.font", uiFont);
                UIManager.put("MenuItem.font", uiFont);
                UIManager.put("OptionPane.messageFont", uiFont);
                UIManager.put("Tooltip.font", uiFont);
            }
        } catch (Throwable ignored) {}

        frame = new JFrame("PhantomRoll System – Telegram Controller");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(1100, 700);
        frame.setLocationRelativeTo(null);
        frame.getContentPane().setBackground(BACKGROUND);
        frame.setLayout(new BorderLayout(8, 8));

        // Menu bar (top)
        JMenuBar menuBar = new JMenuBar();
        menuBar.setBackground(PANEL_BG);
        menuBar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, ACCENT));
        settingsMenu = new JMenu(); settingsMenu.setOpaque(true);
        languageMenu = new JMenu();
        chineseItem = new JMenuItem();
        englishItem = new JMenuItem();
        languageMenu.add(chineseItem);
        languageMenu.add(englishItem);
        settingsMenu.add(languageMenu);
        menuBar.add(settingsMenu);
        frame.setJMenuBar(menuBar);

        // Top header: left menu button, center title, right empty (login/logout moved to toolbar)
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(BACKGROUND);
        header.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));

        // Left: popup menu button
        JButton menuBtn = new JButton("☰");
        menuBtn.setBackground(PANEL_BG);
        menuBtn.setForeground(Color.WHITE);
        menuBtn.setBorder(BorderFactory.createLineBorder(BORDER_COLOR));
        JPopupMenu popup = new JPopupMenu();
        popup.add(new JMenuItem("Settings"));
        popup.add(new JMenuItem("Profile"));
        popup.add(new JMenuItem("Record of System Usage Time"));
        popup.add(new JMenuItem("Signed In / Out"));
        menuBtn.addActionListener(e -> popup.show(menuBtn, 0, menuBtn.getHeight()));
        header.add(menuBtn, BorderLayout.WEST);

        // Center title
        JLabel title = new JLabel("PhantomRoll System – Telegram Controller", SwingConstants.CENTER);
        title.setFont(new Font(UI_FONT_FAMILY, Font.BOLD, 18));
        title.setForeground(Color.WHITE);
        header.add(title, BorderLayout.CENTER);

        frame.add(header, BorderLayout.NORTH);

        // Main panel
        JPanel main = new JPanel(new BorderLayout(10, 10));
        main.setBackground(BACKGROUND);

        // Left: display groups list only (no add button here)
        groupList = new JList<>(groupListModel);
        groupList.setBackground(GROUP_BG);
        groupList.setForeground(GROUP_FG);
        groupList.setSelectionBackground(ACCENT);
        groupList.setSelectionForeground(Color.WHITE);
        groupList.setFont(new Font(UI_FONT_FAMILY, Font.PLAIN, 14));
        groupsScroll = new JScrollPane(groupList);
        groupsScroll.setPreferredSize(new Dimension(220, 0));
        main.add(groupsScroll, BorderLayout.WEST);

        // Center: Activity Log console
        mainLogArea = new JTextArea();
        mainLogArea.setEditable(false);
        mainLogArea.setBackground(LOG_BG);
        mainLogArea.setForeground(LOG_FG);
        // use UI font for log so Chinese appears correctly
        mainLogArea.setFont(new Font(UI_FONT_FAMILY, Font.PLAIN, 13));
        mainLogArea.setLineWrap(true);
        mainLogArea.setWrapStyleWord(true);
        centerScroll = new JScrollPane(mainLogArea);
        main.add(centerScroll, BorderLayout.CENTER);

        // Right: Controls ( + target/allowed/interval)
        JPanel rightPanel = new JPanel();
        rightPanel.setBackground(PANEL_BG);
        rightPanel.setPreferredSize(new Dimension(320, 0));
        rightPanel.setLayout(new BoxLayout(rightPanel, BoxLayout.Y_AXIS));
        rightPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(ACCENT,1), "Controls",
                TitledBorder.LEFT, TitledBorder.TOP, new Font(UI_FONT_FAMILY, Font.BOLD, 12), ACCENT));

        JPanel diceRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 12));
        diceRow.setOpaque(false);
        diceRow.add(new JLabel("Dice:"));
        JLabel diceEmoji = new JLabel("\uD83C\uDFB2");
        diceEmoji.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 22));
        diceRow.add(diceEmoji);
        rightPanel.add(diceRow);

        JPanel targetRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        targetRow.setOpaque(false);
        targetRow.add(new JLabel("Target value:"));
        JSpinner targetValueSpinner = new JSpinner(new SpinnerNumberModel(3, 3, 18, 1));
        targetRow.add(targetValueSpinner);
        rightPanel.add(targetRow);

        JPanel allowedRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        allowedRow.setOpaque(false);
        allowedRow.add(new JLabel("Allowed sums:"));
        JTextField allowedField = new JTextField("3,5,7,9,11,13,15,17", 14);
        allowedField.setBackground(GROUP_BG);
        allowedField.setForeground(Color.WHITE);
        allowedRow.add(allowedField);
        rightPanel.add(allowedRow);

        JPanel intervalRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        intervalRow.setOpaque(false);
        intervalRow.add(new JLabel("Interval (ms):"));
        JSpinner intervalSpinner = new JSpinner(new SpinnerNumberModel(100, 100, 60000, 100));
        intervalRow.add(intervalSpinner);
        rightPanel.add(intervalRow);

        rightPanel.add(Box.createVerticalGlue());
        main.add(rightPanel, BorderLayout.EAST);

        frame.add(main, BorderLayout.CENTER);

        // Bottom control bar: larger buttons (Add group moved to bottom only)
        JPanel controlBar = new JPanel(new GridLayout(1, 7, 12, 8));
        controlBar.setBackground(PANEL_BG);
        controlBar.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        btnRemove = new JButton();
        btnSave = new JButton();
        btnSwitch = new JButton();
        btnPause = new JButton();
        btnOTP = new JButton();
        btnAdd = new JButton();
        btnSend = new JButton();

        styleBigButton(btnRemove, new Color(204,0,0), new Color(255,51,51));
        styleBigButton(btnSave, new Color(0,102,204), new Color(0,153,255));
        styleBigButton(btnSwitch, new Color(255,153,51), new Color(255,204,102));
        styleBigButton(btnPause, new Color(153,153,153), new Color(180,180,180));
        styleBigButton(btnOTP, new Color(102,51,153), new Color(153,102,204));
        styleBigButton(btnAdd, ACCENT, ACCENT2);
        styleBigButton(btnSend, new Color(0,153,76), new Color(0,204,102));

        // Actions
        btnRemove.addActionListener(ev -> {
            int selIdx = groupList.getSelectedIndex();
            if (selIdx == -1) {
                JOptionPane.showMessageDialog(frame, "Please select a group to remove.", "Info", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            String sel = groupListModel.getElementAt(selIdx);
            groupListModel.removeElementAt(selIdx);
            mainLogArea.append("[INFO] Removed group: " + sel + "\n");
            sendCommandToBackendAsync("{\"command\":\"remove_group\",\"group\":\"" + sel + "\"}");
        });

        btnSave.addActionListener(ev -> {
            saveConfig();
            sendCommandToBackendAsync("{\"command\":\"save_config\"}");
        });

        btnSwitch.addActionListener(ev -> {
            String sel = (String) accountDropdown.getSelectedItem();
            if (sel != null) sendCommandToBackendAsync("{\"command\":\"switch_account\",\"account\":\"" + sel + "\"}");
        });

        btnPause.addActionListener(ev -> sendCommandToBackendAsync("{\"command\":\"pause\"}"));

        btnOTP.addActionListener(ev -> {
            String pass = JOptionPane.showInputDialog(frame, t("enter2fa"));
            if (pass != null && !pass.isBlank()) sendCommandToBackendAsync("{\"command\":\"submit_password\",\"password\":\"" + pass.trim() + "\"}");
        });

        btnAdd.addActionListener(ev -> {
            String g = JOptionPane.showInputDialog(frame, t("addGroup"));
            if (g != null) {
                g = g.trim();
                if (!g.isEmpty() && !groupListModel.contains(g)) {
                    groupListModel.addElement(g);
                    if (mainLogArea != null) mainLogArea.append("[INFO] Added group: " + g + "\n");
                    sendCommandToBackendAsync("{\"command\":\"add_group\",\"group\":\"" + g + "\"}");
                } else if (groupListModel.contains(g)) {
                    JOptionPane.showMessageDialog(frame, "Group already exists.", "Info", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });

        btnSend.addActionListener(ev -> {
            String allowed = allowedField.getText().trim();
            String emoji = "\uD83C\uDFB2";
            sendCommandToBackendAsync("{\"command\":\"dice\",\"emoji\":\"" + emoji + "\",\"allowed\":\"" + allowed + "\"}");
        });

        controlBar.add(btnRemove);
        controlBar.add(btnSave);
        controlBar.add(btnSwitch);
        controlBar.add(btnPause);
        controlBar.add(btnOTP);
        controlBar.add(btnAdd);
        controlBar.add(btnSend);

        frame.add(controlBar, BorderLayout.SOUTH);

        // Language toolbar (easy access) with login/logout buttons
        JToolBar langToolBar = new JToolBar();
        langToolBar.setFloatable(false);
        langToolBar.setBackground(PANEL_BG);
        JButton zhBtn = new JButton("中文");
        JButton enBtn = new JButton("English");
        loginBtn = new JButton();
        logoutBtn = new JButton();
        addHoverEffect(zhBtn, ACCENT, ACCENT2);
        addHoverEffect(enBtn, ACCENT2, ACCENT);
        addHoverEffect(loginBtn, ACCENT, ACCENT2);
        addHoverEffect(logoutBtn, new Color(180,0,0), new Color(220,60,60));

        // Login button action
        loginBtn.addActionListener(e -> showLoginDialog(mainLogArea));

        // Logout button action
        logoutBtn.addActionListener(e -> {
            if (mainLogArea != null) mainLogArea.append("[INFO] Sending logout command\n");
            sendCommandToBackendAsync("{\"command\":\"logout\"}");
            new Thread(() -> {
                while (true) {
                    JSONObject status = getBackendStatus();
                    if (status != null && !status.optBoolean("authorized", true)) {
                        SwingUtilities.invokeLater(() -> setLoggedIn(false));
                        break;
                    }
                    try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
                }
            }).start();
            JOptionPane.showMessageDialog(frame, t("logoutSuccess"));
        });

        langToolBar.add(Box.createHorizontalGlue());
        langToolBar.add(zhBtn);
        langToolBar.add(enBtn);
        langToolBar.add(loginBtn);
        langToolBar.add(logoutBtn);
        frame.add(langToolBar, BorderLayout.PAGE_START);

        // small login shortcut on menu bar
        loginMenuButton = new JButton();
        styleBigButton(loginMenuButton, ACCENT, ACCENT2);
        loginMenuButton.addActionListener(e -> {
            if (loggedIn) {
                // perform logout
                sendCommandToBackendAsync("{\"command\":\"logout\"}");
                setLoggedIn(false);
                JOptionPane.showMessageDialog(frame, t("logoutSuccess"));
            } else {
                showLoginDialog(mainLogArea);
            }
        });
        menuBar.add(Box.createHorizontalGlue());
        menuBar.add(loginMenuButton);
        // Menu item and toolbar language actions (update whole UI)
        chineseItem.addActionListener(e -> {
            currentLanguage = "zh";
            saveConfig();
            refreshAllTexts();
            SwingUtilities.invokeLater(() -> { frame.revalidate(); frame.repaint(); });
            JOptionPane.showMessageDialog(frame, t("languageSwitched"));
        });
        englishItem.addActionListener(e -> {
            currentLanguage = "en";
            saveConfig();
            refreshAllTexts();
            SwingUtilities.invokeLater(() -> { frame.revalidate(); frame.repaint(); });
            JOptionPane.showMessageDialog(frame, t("languageSwitched"));
        });
        zhBtn.addActionListener(e -> chineseItem.doClick());
        enBtn.addActionListener(e -> englishItem.doClick());

        // initial data
        accountList.add("default");
        accountDropdown.addItem("default");

        // finalize - set texts now that components exist
        refreshAllTexts();
        // ensure login/logout are consistent
        setLoggedIn(false);

        // load config again to apply loaded language/groups into UI
        loadConfig();
        startBackendIfNotRunning("default");
        waitForBackendReady();

        // Check initial status
        JSONObject initialStatus = getBackendStatus();
        if (initialStatus != null) {
            setLoggedIn(initialStatus.optBoolean("authorized", false));
        }

        frame.setVisible(true);
        mainLogArea.append("[INFO] UI ready.\n");
    });
}
}
