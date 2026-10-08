package com.example.vpntest.utils;

import android.content.Context;
import android.util.Log;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Date;
import java.util.Locale;
import java.text.SimpleDateFormat;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class VpnLogFileManager {

    private static final String TAG = "VpnLogFileManager : ";

    private static volatile VpnLogFileManager instance;

    /*
     * =========================================================
     * SINGLE BACKGROUND LOGGER THREAD
     * =========================================================
     *
     * Every file operation is executed on this one thread.
     *
     * This guarantees:
     *
     * 1. Log order is preserved.
     * 2. Multiple VPN threads cannot write simultaneously.
     * 3. Main thread never performs file I/O.
     */
    private final ExecutorService logExecutor =
            Executors.newSingleThreadExecutor(r -> {

                Thread thread = new Thread(
                        r,
                        "VpnLogFileWriter"
                );

                thread.setDaemon(true);

                return thread;
            });

    /*
     * Current file reference.
     *
     * volatile because it can be accessed from
     * different threads.
     */
    private volatile File currentLogFile;

    /*
     * Writer is ONLY accessed by logExecutor.
     */
    private BufferedWriter writer;

    /*
     * Used to know whether a session has been started.
     */
    private volatile boolean sessionStarted = false;

    private VpnLogFileManager() {
    }

    public static VpnLogFileManager getInstance() {

        if (instance == null) {

            synchronized (VpnLogFileManager.class) {

                if (instance == null) {

                    instance =
                            new VpnLogFileManager();
                }
            }
        }

        return instance;
    }

    /**
     * =========================================================
     * START SESSION
     * =========================================================
     *
     * IMPORTANT:
     *
     * This method does NOT perform file I/O on the caller thread.
     *
     * File creation and writer initialization happen inside
     * VpnLogFileWriter background thread.
     */
    public void startSession(Context context) {

        final Context appContext =
                context.getApplicationContext();

        sessionStarted = true;

        logExecutor.execute(() -> {

            try {

                /*
                 * Close previous writer if somehow still open.
                 */
                closeWriterInternal();

                String fileName =
                        "vpn_log_" +
                                new SimpleDateFormat(
                                        "yyyy_MM_dd_HH_mm_ss",
                                        Locale.getDefault()
                                ).format(new Date()) +
                                ".txt";

                File dir =
                        new File(
                                appContext.getCacheDir(),
                                "vpn_logs"
                        );

                if (!dir.exists()) {

                    if (!dir.mkdirs() && !dir.exists()) {

                        Log.e(
                                TAG,
                                "Unable to create log directory"
                        );

                        sessionStarted = false;

                        return;
                    }
                }

                currentLogFile =
                        new File(
                                dir,
                                fileName
                        );

                writer =
                        new BufferedWriter(
                                new FileWriter(
                                        currentLogFile,
                                        false
                                )
                        );

                /*
                 * Session header.
                 */
                writer.write(
                        "========== VPN SESSION =========="
                );

                writer.newLine();

                writer.write(
                        "Started : " +
                                new Date().toString()
                );

                writer.newLine();

                writer.write(
                        "================================="
                );

                writer.newLine();

                writer.newLine();

                /*
                 * Flush only once when session starts.
                 */
                writer.flush();

                Log.d(
                        TAG,
                        "Log session started: " +
                                currentLogFile.getAbsolutePath()
                );

            } catch (IOException e) {

                Log.e(
                        TAG,
                        "Failed to start log session",
                        e
                );

                sessionStarted = false;
            }
        });
    }

    /**
     * =========================================================
     * ASYNCHRONOUS LOG
     * =========================================================
     *
     * Caller thread:
     *
     *      log()
     *        |
     *        +----> enqueue
     *        |
     *        +----> RETURN IMMEDIATELY
     *
     * Background:
     *
     *      VpnLogFileWriter
     *        |
     *        +----> writer.write()
     */
    public void log(String text) {

        if (!sessionStarted) {
            return;
        }

        if (text == null) {
            return;
        }

        /*
         * IMPORTANT:
         *
         * Only enqueue the work.
         *
         * No writer.write()
         * No writer.flush()
         * No file I/O
         * No synchronized disk operation
         */
        logExecutor.execute(() -> {

            if (writer == null) {
                return;
            }

            try {

                writer.write(text);

                writer.newLine();

                /*
                 * DO NOT flush after every log.
                 *
                 * BufferedWriter will batch writes.
                 *
                 * This is much faster than:
                 *
                 * writer.write()
                 * writer.flush()
                 * writer.write()
                 * writer.flush()
                 */
            } catch (IOException e) {

                Log.e(
                        TAG,
                        "Failed to write log",
                        e
                );
            }
        });
    }

    /**
     * =========================================================
     * LOG + ANDROID LOGCAT
     * =========================================================
     */
    public void logAndPrint(
            String tag,
            String message) {

        /*
         * Logcat itself is separate from our file writer.
         */
        Log.d(
                tag,
                message
        );

        /*
         * File logging is asynchronous.
         */
        log(message);
    }

    /**
     * =========================================================
     * END SESSION
     * =========================================================
     *
     * The close operation is also queued.
     *
     * Therefore all previously queued logs are written BEFORE
     * the session-end marker is written.
     */
    public void endSession() {

        if (!sessionStarted) {
            return;
        }

        sessionStarted = false;

        logExecutor.execute(() -> {

            if (writer == null) {
                return;
            }

            try {

                writer.newLine();

                writer.write(
                        "========== SESSION END =========="
                );

                writer.newLine();

                writer.write(
                        "Stopped : " +
                                new Date().toString()
                );

                writer.newLine();

                writer.write(
                        "================================="
                );

                writer.newLine();

                /*
                 * Flush everything that is still buffered.
                 */
                writer.flush();

            } catch (IOException e) {

                Log.e(
                        TAG,
                        "Failed to write session end",
                        e
                );

            } finally {

                closeWriterInternal();
            }
        });
    }

    /**
     * =========================================================
     * CLOSE WRITER
     * =========================================================
     *
     * MUST ONLY BE CALLED FROM logExecutor.
     */
    private void closeWriterInternal() {

        if (writer == null) {
            return;
        }

        try {

            writer.flush();

        } catch (IOException ignored) {

        }

        try {

            writer.close();

        } catch (IOException ignored) {

        }

        writer = null;
    }

    /**
     * =========================================================
     * GET CURRENT LOG FILE
     * =========================================================
     */
    public File getCurrentLogFile() {

        return currentLogFile;
    }

    /**
     * =========================================================
     * DELETE CURRENT LOG FILE
     * =========================================================
     *
     * Delete is also performed asynchronously.
     */
    public void deleteCurrentLogFile() {

        final File file =
                currentLogFile;

        currentLogFile = null;

        logExecutor.execute(() -> {

            if (file != null && file.exists()) {

                if (!file.delete()) {

                    Log.w(
                            TAG,
                            "Unable to delete log file: " +
                                    file.getAbsolutePath()
                    );
                }
            }
        });
    }

    /**
     * =========================================================
     * SHUTDOWN
     * =========================================================
     *
     * Call this only when the entire VPN logging system is
     * permanently being destroyed.
     */
    public void shutdown() {

        sessionStarted = false;

        logExecutor.execute(() -> {

            closeWriterInternal();

        });

        logExecutor.shutdown();

        try {

            if (!logExecutor.awaitTermination(
                    2,
                    TimeUnit.SECONDS
            )) {

                logExecutor.shutdownNow();
            }

        } catch (InterruptedException e) {

            Thread.currentThread().interrupt();

            logExecutor.shutdownNow();
        }
    }
}