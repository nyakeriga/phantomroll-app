// GUIController.java
package com.phantomroll.gui;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
public class GUIController {
    /**
     * Sends a command to the backend and returns the first line of response, or null if none.
     */
    public static String sendCommand(String command) throws IOException {
        try (Socket socket = new Socket("localhost", 8879);
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
             BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))) {
            writer.write(command);
            writer.write("\n");
            writer.flush();

            return reader.readLine();
        }
    }
}
