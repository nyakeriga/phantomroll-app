package com.phantomroll.gui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import java.util.ArrayList;

public class PhantomRollUI {

    private static DefaultListModel<String> groupListModel = new DefaultListModel<>();
    private static final File CONFIG_FILE = new File("config.json");
    private static final java.util.List<String> accountList = new ArrayList<>();
    private static final JComboBox<String> accountDropdown = new JComboBox<>();

    private static boolean isBackendRunning() {
        try (Socket socket = new Socket("localhost", 8879)) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static void startBackendIfNotRunning(String sessionName) {
        if (!isBackendRunning()) {
            try {
                String exePath = new File("phantomroll_exec.exe").getAbsolutePath();
                ProcessBuilder pb = new ProcessBuilder(exePath, "--session", sessionName);
                pb.redirectErrorStream(true);
                pb.start();
            } catch (IOException e) {
                JOptionPane.showMessageDialog(null, "Failed to launch backend:\n" + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private static void saveConfig() {
        try (PrintWriter writer = new PrintWriter(CONFIG_FILE)) {
            ArrayList<String> groups = new ArrayList<>();
            for (int i = 0; i < groupListModel.getSize(); i++) {
                groups.add("\"" + groupListModel.getElementAt(i) + "\"");
            }
            writer.write("{\"groups\": [" + String.join(",", groups) + "]}");
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, "Error saving config: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static void loadConfig() {
        if (!CONFIG_FILE.exists()) return;
        try {
            String content = Files.readString(CONFIG_FILE.toPath());
            String[] items = content.split("[\"\\[\\],]+");
            for (String item : items) {
                if (!item.trim().isEmpty()) {
                    groupListModel.addElement(item.trim());
                }
            }
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, "Error loading config: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("PhantomRoll Controller");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 400);

        accountList.add("default");
        accountDropdown.addItem("default");

        JPanel accountPanel = new JPanel(new BorderLayout());
        JButton loginButton = new JButton("Login to Telegram");
        JButton addAccountButton = new JButton("Add Account");

        accountPanel.add(loginButton, BorderLayout.WEST);
        accountPanel.add(accountDropdown, BorderLayout.CENTER);
        accountPanel.add(addAccountButton, BorderLayout.EAST);

        loginButton.addActionListener(e -> {
            String phone = JOptionPane.showInputDialog(frame, "Enter phone number with country code:", "+254...");
            if (phone != null && !phone.trim().isEmpty()) {
                try {
                    new ProcessBuilder("phantomroll_exec.exe", "--login", phone).start();
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(frame, "Login failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        addAccountButton.addActionListener(e -> {
            String sessionName = JOptionPane.showInputDialog(frame, "Enter new session name:", "Add Account", JOptionPane.PLAIN_MESSAGE);
            if (sessionName != null && !sessionName.trim().isEmpty() && !accountList.contains(sessionName)) {
                accountList.add(sessionName);
                accountDropdown.addItem(sessionName);
            }
        });

        JPanel controlPanel = new JPanel(new BorderLayout());
        JTextField inputField = new JTextField();
        JButton addButton = new JButton("Add Group");

        String[] diceTypes = {"🎲", "🎯", "🏀", "🎳"};
        JComboBox<String> diceTypeDropdown = new JComboBox<>(diceTypes);

        JSpinner targetValueSpinner = new JSpinner(new SpinnerNumberModel(3, 3, 18, 1));

        JPanel centerControl = new JPanel(new GridLayout(1, 4));
        centerControl.add(diceTypeDropdown);
        centerControl.add(targetValueSpinner);
        centerControl.add(inputField);
        centerControl.add(addButton);
        controlPanel.add(centerControl, BorderLayout.CENTER);

        JList<String> groupList = new JList<>(groupListModel);
        JScrollPane listScroll = new JScrollPane(groupList);

        JButton removeButton = new JButton("Remove Selected");
        JButton saveButton = new JButton("Save Config");
        JButton switchAccountButton = new JButton("Switch Account");
        JButton sendButton = new JButton("Send");

        JTextArea logArea = new JTextArea();
        logArea.setEditable(false);
        JScrollPane logScroll = new JScrollPane(logArea);

        JPanel bottomPanel = new JPanel(new GridLayout(1, 4));
        bottomPanel.add(removeButton);
        bottomPanel.add(saveButton);
        bottomPanel.add(switchAccountButton);
        bottomPanel.add(sendButton);

        frame.setLayout(new BorderLayout());
        frame.add(accountPanel, BorderLayout.NORTH);
        frame.add(controlPanel, BorderLayout.AFTER_LINE_ENDS);
        frame.add(listScroll, BorderLayout.WEST);
        frame.add(logScroll, BorderLayout.CENTER);
        frame.add(bottomPanel, BorderLayout.SOUTH);

        addButton.addActionListener(e -> {
            String input = inputField.getText().trim();
            if (!input.isEmpty() && !groupListModel.contains(input)) {
                groupListModel.addElement(input);
                inputField.setText("");
            }
        });

        removeButton.addActionListener(e -> {
            String selected = groupList.getSelectedValue();
            if (selected != null) {
                groupListModel.removeElement(selected);
            }
        });

        saveButton.addActionListener(e -> saveConfig());

        switchAccountButton.addActionListener(e -> {
            String selectedSession = (String) accountDropdown.getSelectedItem();
            if (selectedSession != null) {
                startBackendIfNotRunning(selectedSession);
                JOptionPane.showMessageDialog(frame, "Switched to account: " + selectedSession);
            }
        });

        // ✅ FINAL FORMAT: 🎲:3:groupname
        sendButton.addActionListener(e -> {
            String selectedDice = (String) diceTypeDropdown.getSelectedItem();
            int targetValue = (Integer) targetValueSpinner.getValue();

            for (int i = 0; i < groupListModel.size(); i++) {
                String groupName = groupListModel.get(i);
                String formattedCommand = selectedDice + ":" + targetValue + ":" + groupName;

                try (Socket socket = new Socket("localhost", 8879);
                     PrintWriter writer = new PrintWriter(socket.getOutputStream(), true)) {
                    writer.println(formattedCommand);
                    logArea.append("Sent: " + formattedCommand + "\n");
                } catch (IOException ex) {
                    logArea.append("Error: " + ex.getMessage() + "\n");
                }
            }
        });

        loadConfig();
        startBackendIfNotRunning("default");
        frame.setVisible(true);
    }
}
