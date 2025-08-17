package com.phantomroll.gui;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;

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

    static {
        // [Chinese, English]
        translations.put("loginTelegram", new String[]{"登录 Telegram", "Login to Telegram"});
        translations.put("addAccount", new String[]{"添加账户", "Add Account"});
        translations.put("addGroup", new String[]{"添加群组", "Add Group"});
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
        translations.put("languageSwitched", new String[]{"语言已切换为中文", "Language switched to English"});
        translations.put("backendNotReady", new String[]{"⚠ 后端未准备好，请稍后重试。", "⚠ Backend not ready after several attempts."});
        translations.put("connectionError", new String[]{"连接错误", "Connection Error"});
        translations.put("error", new String[]{"错误", "Error"});
        // Login dialog
        translations.put("loginPromptTitle", new String[]{"登录", "Login"});
        translations.put("loginPromptMsg", new String[]{"请输入手机号登录 Telegram:", "Please enter your phone number to login to Telegram:"});
        translations.put("loginBtn", new String[]{"登录", "Login"});
        translations.put("loginSuccess", new String[]{"✅ 登录成功", "✅ Login successful"});
        translations.put("loginFailed", new String[]{"❌ 登录失败", "❌ Login failed"});
        translations.put("loginInProgress", new String[]{"正在登录...", "Logging in..."});
        translations.put("enter2fa", new String[]{"请输入二次验证密码:", "Enter 2FA password:"});
    }

    private static JFrame frame;

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
                JOptionPane.showMessageDialog(frame, "❌ " + e.getMessage(), t("error"), JOptionPane.ERROR_MESSAGE);
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

            Files.writeString(CONFIG_FILE.toPath(), config.toString(2));
        } catch (IOException e) {
            JOptionPane.showMessageDialog(frame, "❌ " + e.getMessage(), t("error"), JOptionPane.ERROR_MESSAGE);
        }
    }

    private static void loadConfig() {
        if (!CONFIG_FILE.exists()) return;
        try {
            String content = Files.readString(CONFIG_FILE.toPath());
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
        } catch (IOException e) {
            JOptionPane.showMessageDialog(frame, "❌ " + e.getMessage(), t("error"), JOptionPane.ERROR_MESSAGE);
        }
    }

    // Send command to backend in background thread
    private static void sendCommandToBackend(String cmd, JTextArea logArea) {
        new Thread(() -> {
            try (Socket socket = new Socket("localhost", 8879);
                 OutputStreamWriter writer = new OutputStreamWriter(socket.getOutputStream(), java.nio.charset.StandardCharsets.UTF_8);
                 BufferedWriter out = new BufferedWriter(writer);
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), java.nio.charset.StandardCharsets.UTF_8))) {

                out.write(cmd);
                out.write("\n");
                out.flush();

                SwingUtilities.invokeLater(() -> logArea.append("> " + cmd + "\n"));

                String response = in.readLine();
                if (response != null) {
                    SwingUtilities.invokeLater(() -> logArea.append("< " + response + "\n"));
                }
            } catch (IOException e) {
                SwingUtilities.invokeLater(() -> logArea.append("[ERROR] Failed to send command: " + e.getMessage() + "\n"));
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
                logArea.append(t("loginInProgress") + "\n");
                sendCommandToBackend("login:" + phone, logArea);
            }
        }
    }

    // Refresh all UI texts based on current language
    private static void refreshUIText(
            JButton loginButton, JButton addAccountButton,
            JButton addButton, JButton removeButton,
            JButton saveButton, JButton switchAccountButton,
            JButton sendButton, JButton pauseButton, JButton passwordButton,
            JMenu settingsMenu, JMenu languageMenu,
            JMenuItem chineseItem, JMenuItem englishItem,
            JScrollPane logScroll,
            JButton loginMenuButton
    ) {
        loginButton.setText(t("loginTelegram"));
        addAccountButton.setText(t("addAccount"));
        addButton.setText(t("addGroup"));
        removeButton.setText(t("removeSelected"));
        saveButton.setText(t("saveConfig"));
        switchAccountButton.setText(t("switchAccount"));
        sendButton.setText(t("send"));
        pauseButton.setText(t("pause"));
        passwordButton.setText(t("submitPassword"));

        settingsMenu.setText(t("settings"));
        languageMenu.setText(t("language"));
        chineseItem.setText(t("chinese"));
        englishItem.setText(t("english"));

        logScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(ACCENT, 2), t("activityLog"),
                0, 0, new Font("Arial", Font.BOLD, 13), ACCENT));
        loginMenuButton.setText(t("loginBtn"));
    }

    // Helper for button hover effect
    private static void addHoverEffect(final JButton button, final Color normal, final Color hover) {
        button.setBackground(normal);
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setBorder(BorderFactory.createLineBorder(BORDER_COLOR, 1));
        button.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                button.setBackground(hover);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                button.setBackground(normal);
            }
        });
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel("javax.swing.plaf.nimbus.NimbusLookAndFeel");
        } catch (Exception ignored) {}

        // --- FONT / ENCODING HELPERS: ensure Chinese-capable font is used across UI ---
        try {
            String[] preferred = new String[] {"Microsoft YaHei", "Microsoft Yahei UI", "SimSun", "Arial Unicode MS", "Noto Sans CJK SC"};
            String chosen = null;
            GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
            Set<String> available = new HashSet<>(Arrays.asList(ge.getAvailableFontFamilyNames()));
            for (String p : preferred) {
                if (available.contains(p)) {
                    chosen = p;
                    break;
                }
            }
            if (chosen == null && available.size() > 0) {
                chosen = available.iterator().next();
            }
            if (chosen != null) {
                Font uiFont = new Font(chosen, Font.PLAIN, 13);

                UIManager.put("Button.font", uiFont);
                UIManager.put("ToggleButton.font", uiFont);
                UIManager.put("RadioButton.font", uiFont);
                UIManager.put("CheckBox.font", uiFont);
                UIManager.put("ColorChooser.font", uiFont);
                UIManager.put("ComboBox.font", uiFont);
                UIManager.put("Label.font", uiFont);
                UIManager.put("List.font", uiFont);
                UIManager.put("MenuBar.font", uiFont);
                UIManager.put("MenuItem.font", uiFont);
                UIManager.put("Menu.font", uiFont);
                UIManager.put("PopupMenu.font", uiFont);
                UIManager.put("OptionPane.messageFont", uiFont);
                UIManager.put("OptionPane.buttonFont", uiFont);
                UIManager.put("Panel.font", uiFont);
                UIManager.put("ProgressBar.font", uiFont);
                UIManager.put("ScrollPane.font", uiFont);
                UIManager.put("TabbedPane.font", uiFont);
                UIManager.put("Table.font", uiFont);
                UIManager.put("TableHeader.font", uiFont);
                UIManager.put("TextArea.font", uiFont);
                UIManager.put("TextField.font", uiFont);
                UIManager.put("PasswordField.font", uiFont);
                UIManager.put("TextPane.font", uiFont);
                UIManager.put("EditorPane.font", uiFont);
                UIManager.put("TitledBorder.font", uiFont);
            }
        } catch (Throwable fontEx) {
            // If anything goes wrong, silently ignore so we don't disrupt UI startup.
        }
        // --- end font setup ---

        frame = new JFrame("PhantomRoll Controller");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(820, 540);
        frame.setLocationRelativeTo(null);
        frame.getContentPane().setBackground(BACKGROUND);

        JMenuBar menuBar = new JMenuBar();
        menuBar.setBackground(PANEL_BG);
        menuBar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, ACCENT));
        JMenu settingsMenu = new JMenu();
        JMenu languageMenu = new JMenu();

        JMenuItem chineseItem = new JMenuItem();
        JMenuItem englishItem = new JMenuItem();

        // Assign translations initially
        currentLanguage = "zh"; // or load from config before if preferred

        accountList.add("default");
        accountDropdown.addItem("default");

        // Buttons and UI components
        JButton loginButton = new JButton();
        JButton addAccountButton = new JButton();
        JButton addButton = new JButton();
        JButton removeButton = new JButton();
        JButton saveButton = new JButton();
        JButton switchAccountButton = new JButton();
        JButton sendButton = new JButton();
        JButton pauseButton = new JButton();
        JButton passwordButton = new JButton();

        JTextField inputField = new JTextField();
        JTextField allowedSumsField = new JTextField("3,5,7,9,11,13,15,17");

        String[] diceTypes = {"\uD83C\uDFB2", "\uD83C\uDFAF", "\uD83C\uDFC0", "\uD83C\uDFCB"};
        JComboBox<String> diceTypeDropdown = new JComboBox<>(diceTypes);
        JSpinner targetValueSpinner = new JSpinner(new SpinnerNumberModel(3, 3, 18, 1));

        JPanel accountPanel = new JPanel(new BorderLayout(5, 0));
        JPanel controlPanel = new JPanel(new BorderLayout(5, 0));
        JPanel centerControl = new JPanel(new GridLayout(1, 5, 5, 0));
        JList<String> groupList = new JList<>(groupListModel);
        JScrollPane listScroll = new JScrollPane(groupList);
        JTextArea logArea = new JTextArea();
        JScrollPane logScroll = new JScrollPane(logArea);

        // --- Enhanced Styling ---
        accountPanel.setBackground(PANEL_BG);
        controlPanel.setBackground(PANEL_BG);
        centerControl.setBackground(PANEL_BG);

        groupList.setBackground(GROUP_BG);
        groupList.setForeground(GROUP_FG);
        groupList.setSelectionBackground(ACCENT);
        groupList.setSelectionForeground(Color.WHITE);
        groupList.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        listScroll.setPreferredSize(new Dimension(180, 0));
        listScroll.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 2, ACCENT));

        logArea.setEditable(false);
        logArea.setBackground(LOG_BG);
        logArea.setForeground(LOG_FG);
        logArea.setFont(new Font("Consolas", Font.PLAIN, 13));
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);
        logScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(ACCENT, 2), t("activityLog"),
                0, 0, new Font("Arial", Font.BOLD, 13), ACCENT));

        // Button styling and hover
        addHoverEffect(loginButton, ACCENT, ACCENT2);
        addHoverEffect(addAccountButton, ACCENT2, ACCENT);
        addHoverEffect(addButton, ACCENT, ACCENT2);
        addHoverEffect(removeButton, new Color(204, 0, 0), new Color(255, 51, 51));
        addHoverEffect(saveButton, new Color(0, 102, 204), new Color(0, 153, 255));
        addHoverEffect(switchAccountButton, new Color(255, 153, 51), new Color(255, 204, 102));
        addHoverEffect(sendButton, new Color(0, 153, 76), new Color(0, 204, 102));
        addHoverEffect(pauseButton, new Color(153, 153, 153), new Color(180, 180, 180));
        addHoverEffect(passwordButton, new Color(102, 51, 153), new Color(153, 102, 204));

        inputField.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        inputField.setBackground(GROUP_BG);
        inputField.setForeground(Color.WHITE);
        inputField.setCaretColor(ACCENT);

        allowedSumsField.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        allowedSumsField.setBackground(GROUP_BG);
        allowedSumsField.setForeground(Color.WHITE);
        allowedSumsField.setCaretColor(ACCENT2);

        diceTypeDropdown.setBackground(PANEL_BG);
        diceTypeDropdown.setForeground(ACCENT);
        targetValueSpinner.setBackground(PANEL_BG);
        targetValueSpinner.setForeground(ACCENT);

        // Layout setup
        accountPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        accountPanel.add(loginButton, BorderLayout.WEST);
        accountPanel.add(accountDropdown, BorderLayout.CENTER);
        accountPanel.add(addAccountButton, BorderLayout.EAST);

        centerControl.add(diceTypeDropdown);
        centerControl.add(targetValueSpinner);
        centerControl.add(allowedSumsField);
        centerControl.add(inputField);
        centerControl.add(addButton);

        controlPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        controlPanel.add(centerControl, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new GridLayout(1, 6, 5, 0));
        bottomPanel.setBackground(PANEL_BG);
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        bottomPanel.add(removeButton);
        bottomPanel.add(saveButton);
        bottomPanel.add(switchAccountButton);
        bottomPanel.add(sendButton);
        bottomPanel.add(pauseButton);
        bottomPanel.add(passwordButton);

        frame.setLayout(new BorderLayout());
        frame.add(accountPanel, BorderLayout.NORTH);
        frame.add(controlPanel, BorderLayout.AFTER_LINE_ENDS);
        frame.add(listScroll, BorderLayout.WEST);
        frame.add(logScroll, BorderLayout.CENTER);
        frame.add(bottomPanel, BorderLayout.SOUTH);

        // Add login button to menu bar for easy access
        JButton loginMenuButton = new JButton(t("loginBtn"));
        addHoverEffect(loginMenuButton, ACCENT, ACCENT2);
        loginMenuButton.setFont(new Font("Arial", Font.BOLD, 13));
        menuBar.add(Box.createHorizontalGlue());
        menuBar.add(loginMenuButton);

        // Set translated texts initially
        refreshUIText(loginButton, addAccountButton, addButton, removeButton, saveButton, switchAccountButton, sendButton, pauseButton, passwordButton,
                settingsMenu, languageMenu, chineseItem, englishItem, logScroll, loginMenuButton);

        // Menu items setup
        chineseItem.addActionListener(e -> {
            currentLanguage = "zh";
            saveConfig();
            refreshUIText(loginButton, addAccountButton, addButton, removeButton, saveButton, switchAccountButton, sendButton, pauseButton, passwordButton,
                    settingsMenu, languageMenu, chineseItem, englishItem, logScroll, loginMenuButton);
            JOptionPane.showMessageDialog(frame, t("languageSwitched"));
        });

        englishItem.addActionListener(e -> {
            currentLanguage = "en";
            saveConfig();
            refreshUIText(loginButton, addAccountButton, addButton, removeButton, saveButton, switchAccountButton, sendButton, pauseButton, passwordButton,
                    settingsMenu, languageMenu, chineseItem, englishItem, logScroll, loginMenuButton);
            JOptionPane.showMessageDialog(frame, t("languageSwitched"));
        });

        languageMenu.add(chineseItem);
        languageMenu.add(englishItem);
        settingsMenu.add(languageMenu);
        menuBar.add(settingsMenu);
        frame.setJMenuBar(menuBar);

        // Button listeners
        loginButton.addActionListener(e -> showLoginDialog(logArea));
        loginMenuButton.addActionListener(e -> showLoginDialog(logArea));
        addAccountButton.addActionListener(e -> {
            String phone = JOptionPane.showInputDialog(frame, t("enterPhone"));
            if (phone != null && !phone.isBlank()) {
                sendCommandToBackend("add_account:" + phone.trim(), logArea);
            }
        });
        addButton.addActionListener(e -> {
            String group = inputField.getText().trim();
            if (!group.isEmpty()) {
                groupListModel.addElement(group);
                sendCommandToBackend("add_group:" + group, logArea);
            }
        });
        removeButton.addActionListener(e -> {
            int idx = groupList.getSelectedIndex();
            if (idx != -1) {
                String removed = groupListModel.get(idx);
                groupListModel.remove(idx);
                logArea.append("[INFO] Removed group: " + removed + "\n");
            }
        });
        saveButton.addActionListener(e -> {
            saveConfig();
            sendCommandToBackend("save_config", logArea);
        });
        switchAccountButton.addActionListener(e -> {
            String selected = (String) accountDropdown.getSelectedItem();
            if (selected != null) {
                sendCommandToBackend("switch_account:" + selected, logArea);
            }
        });
        sendButton.addActionListener(e -> {
            String emoji = (String) diceTypeDropdown.getSelectedItem();
            String allowed = allowedSumsField.getText().trim();
            sendCommandToBackend("dice " + emoji + " " + allowed, logArea);
        });
        pauseButton.addActionListener(e -> sendCommandToBackend("pause", logArea));
        passwordButton.addActionListener(e -> {
            String pass = JOptionPane.showInputDialog(frame, t("enter2fa"));
            if (pass != null && !pass.isBlank()) {
                sendCommandToBackend("submit_2fa:" + pass.trim(), logArea);
            }
        });

        loadConfig();
        startBackendIfNotRunning("default");
        waitForBackendReady();

        frame.setVisible(true);
    }
}

        loadConfig();
        startBackendIfNotRunning("default");
        frame.setVisible(true);
    }
}
