package com.phantomroll.gui;

import java.io.*;
import java.net.Socket;

public class GUIController {
    /**package com.phantomroll.gui;

import java.io.*;
import java.net.Socket;

public class GUIController {
    /**
     * Sends a command to the backend and returns the first line of response, or null if none.
     */
    public static String sendCommand(String command) throws IOException {
        try (Socket socket = new Socket("localhost", 8879);
             OutputStream out = socket.getOutputStream();
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out, "UTF-8"));
             BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"))) {

            writer.write(command);
            writer.write("\n");
            writer.flush();

            return reader.readLine();
        }
    }
}
