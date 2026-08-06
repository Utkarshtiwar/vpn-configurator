package com.example.vpntest.utils;

import android.content.Context;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class VpnLogFileManager {

    private static volatile VpnLogFileManager instance;

    private final Object lock = new Object();

    private BufferedWriter writer;
    private File currentLogFile;

    private VpnLogFileManager() {
    }

    public static VpnLogFileManager getInstance() {
        if (instance == null) {
            synchronized (VpnLogFileManager.class) {
                if (instance == null) {
                    instance = new VpnLogFileManager();
                }
            }
        }
        return instance;
    }

    public void startSession(Context context) {

        synchronized (lock) {

            try {

                String fileName = "vpn_log_" +
                        new SimpleDateFormat(
                                "yyyy_MM_dd_HH_mm_ss",
                                Locale.getDefault())
                                .format(new Date())
                        + ".txt";

                File dir = new File(context.getCacheDir(), "vpn_logs");

                if (!dir.exists()) {
                    dir.mkdirs();
                }

                currentLogFile = new File(dir, fileName);

                writer = new BufferedWriter(new FileWriter(currentLogFile, false));

                writer.write("========== VPN SESSION ==========\n");
                writer.write("Started : "
                        + new Date().toString()
                        + "\n");
                writer.write("=================================\n\n");

                writer.flush();

            } catch (IOException e) {
                e.printStackTrace();
            }

        }

    }

    public void log(String text) {

        synchronized (lock) {

            if (writer == null)
                return;

            try {

                writer.write(text);

                writer.newLine();

                writer.flush();

            } catch (IOException e) {

                e.printStackTrace();

            }

        }

    }

    public void endSession() {

        synchronized (lock) {

            if (writer == null)
                return;

            try {

                writer.write("\n");
                writer.write("========== SESSION END ==========\n");
                writer.write("Stopped : "
                        + new Date().toString()
                        + "\n");
                writer.write("=================================\n");

                writer.flush();

                writer.close();

            } catch (IOException ignored) {

            }

            writer = null;

        }

    }

    public File getCurrentLogFile() {
        return currentLogFile;
    }

    public void deleteCurrentLogFile() {

        synchronized (lock) {

            if (currentLogFile != null && currentLogFile.exists()) {

                currentLogFile.delete();

            }

            currentLogFile = null;

        }

    }
    public void logAndPrint(String tag, String message) {

        android.util.Log.d(tag, message);

        log(message);

    }

}