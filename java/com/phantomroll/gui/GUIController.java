package com.phantomroll.gui;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;

public class GUIController {
    public static void sendCommand(String command) throws IOException {
        try (Socket socket = new Socket("localhost", 8879);
             OutputStream out = socket.getOutputStream()) {
            out.write((command + "\n").getBytes("UTF-8"));
            out.flush();
        }
    }
}
