package com.example.vpntest.webTest;

import android.util.Log;

import com.example.vpntest.repo.VpnEventRepository;

import java.io.BufferedInputStream;
// ADDED: PAGE SOURCE (RAW HTML) LOG
import java.io.BufferedReader;
// ADDED: PAGE SOURCE (RAW HTML) LOG
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
// ADDED: PAGE SOURCE (RAW HTML) LOG
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
// ADDED: PAGE SOURCE (RAW HTML) LOG
import java.nio.charset.StandardCharsets;

public class WebViewHelper {

    private static final String TAG = "WebViewHelper : ";

    private final VpnEventRepository dashboard =
            VpnEventRepository.getInstance();

    // Callback so the UI can react when the "page load" (our manual fetch) finishes,
    // just like WebViewClient.onPageFinished() used to give us.
    public interface WebTestListener {
        void onWebTestFinished(boolean success, String url);
    }

    private WebTestListener listener;

    public void setWebTestListener(WebTestListener listener) {
        this.listener = listener;
    }

    public void runWebTest(String url) {

        String host_name = url;
        String host_url;

        dashboard.logToFile(TAG + "WEB TEST START REQUESTED");
        dashboard.logToFile(TAG + "WEB TEST URL: " + url);
        dashboard.logToFile(
                TAG + "WEB TEST HELPER ENTERED (thread="
                        + Thread.currentThread().getName() + ")"
        );

        try {

            // =========================================================
            // URL VALIDATION
            // =========================================================

            try {

                if (!url.startsWith("http://")
                        && !url.startsWith("https://")) {

                    host_url = url;
                    url = "https://" + url;

                } else {

                    host_url =
                            url.replaceFirst("^https?://", "");
                }

                URL parsedUrl = new URL(url);

                String host = parsedUrl.getHost();

                if (host == null || host.isEmpty()) {

                    dashboard.logToFile(
                            TAG + "ELOG_WEB_TEST: Invalid URL: " + url
                    );

                    return;
                }

                dashboard.logToFile(
                        TAG + "WEB TEST URL PARSED: " + url
                );

            } catch (Exception e) {

                dashboard.logToFile(
                        TAG + "ELOG_WEB_TEST: Invalid URL: " + url
                );

                return;
            }


            // =========================================================
            // REQUEST START
            // Original:
            // RequestStart Time T0_0 ms
            // =========================================================

            long requestStart =
                    System.currentTimeMillis();

            dashboard.logToFile(
                    TAG
                            + "RequestStart Time T0_0 ms:"
                            + requestStart
            );
//            dashboard.logToFile(
//                    TAG
//                            + "T0_CONNECTION_START\n"
//                            + requestStart
//            );


            // =========================================================
            // DNS RESOLUTION
            // =========================================================

            long dnsStart =
                    System.nanoTime();

            dashboard.logToFile(
                    TAG
                            + "DNS Start Nano Time:"
                            + dnsStart
            );

            String host =
                    new URL(url).getHost();

            dashboard.logToFile(
                    TAG + "WEB TEST HOST: " + host
            );

            dashboard.logToFile(
                    TAG + "WEB TEST DNS START"
            );

            InetAddress[] allAddresses =
                    InetAddress.getAllByName(host);


            // Build comma-separated resolved IP list
            StringBuilder ipList =
                    new StringBuilder();

            for (int i = 0;
                 i < allAddresses.length;
                 i++) {

                ipList.append(
                        allAddresses[i].getHostAddress()
                );

                if (i < allAddresses.length - 1) {
                    ipList.append(",");
                }
            }

            InetAddress inetAddress =
                    allAddresses[0];

            String hostName =
                    inetAddress.getHostName();


            // =========================================================
            // DNS END
            // =========================================================

            long dnsEnd =
                    System.nanoTime();

            dashboard.logToFile(
                    TAG
                            + "DNS End Nano Time:"
                            + dnsEnd
            );

            double dnsDurationMs =
                    (dnsEnd - dnsStart)
                            / 1_000_000.0;

            dashboard.logToFile(
                    TAG
                            + "DNS Time in ms:"
                            + dnsDurationMs
            );

            dashboard.logToFile(
                    TAG
                            + " WEB TEST DNS COMPLETE: "
                            + ipList
                            + " ("
                            + dnsDurationMs
                            + " ms)"
            );


            // =========================================================
            // CONNECTION START
            // =========================================================

            dashboard.logToFile(
                    TAG
                            + "ELOG_WEB_TEST: going to make connection"
            );

            long connectStart =
                    System.currentTimeMillis();

//            dashboard.logToFile(
//                    TAG
//                            + "Connection start T0 Time in ms:"
//                            + connectStart
//            );

            dashboard.logToFile(
                    TAG + " WEB TEST CONNECT START"
            );


            // =========================================================
            // HTTP CONNECTION
            // =========================================================

            dashboard.logToFile(TAG+"T0_CONNECTION_START");
            HttpURLConnection urlConnection =
                    (HttpURLConnection)
                            new URL(url).openConnection();

            urlConnection.setConnectTimeout(5000);
            urlConnection.setReadTimeout(5000);
            urlConnection.setRequestMethod("GET");

            urlConnection.connect();


            // =========================================================
            // CONNECTION END / T1
            // =========================================================

            long connectEnd =
                    System.currentTimeMillis();

//            dashboard.logToFile(
//                    TAG
//                            + "T1_RESPONSE_CODE_RXD\n"
//                            + connectEnd
//            );

            dashboard.logToFile(
                    TAG + "WEB TEST CONNECT SUCCESS"
            );


            // =========================================================
            // CONNECTION TIME
            // =========================================================

            long connectionTime =
                    connectEnd - connectStart;

            dashboard.logToFile(
                    TAG
                            + "WEB TEST CONNECTION TIME: "
                            + connectionTime
                            + " ms"
            );


            long ttfbTime = 0;
            long totalTime = 0;


            // =========================================================
            // RESPONSE CODE / T2
            // =========================================================

            int responseCode =
                    urlConnection.getResponseCode();
            dashboard.logToFile(
                    TAG
                            + "T1_RESPONSE_CODE_RXD\n"
                            + responseCode
            );

            long ttfb =
                    System.currentTimeMillis();

            ttfbTime =
                    ttfb - connectStart;

            dashboard.logToFile(
                    TAG
                            + "ELOG_WEB_TEST: web test response code is "
                            + responseCode
                            + " for url "
                            + url
            );

            dashboard.logToFile(
                    TAG
                            + "T2_TTFB\n"
                            + ttfbTime
            );

            dashboard.logToFile(
                    TAG
                            + "WEB TEST RESPONSE CODE: "
                            + responseCode
            );

            dashboard.logToFile(
                    TAG
                            + "WEB TEST TTFB TIME: "
                            + ttfbTime
                            + " ms"
            );


            // ADDED: HTTPURLCONNECTION RESPONSE LOG
            try {

                StringBuilder httpResponseLog = new StringBuilder();
                httpResponseLog.append("========== HTTPURLCONNECTION RESPONSE ==========\n");
                httpResponseLog.append("Timestamp       : ").append(System.currentTimeMillis()).append("\n");
                httpResponseLog.append("URL             : ").append(url).append("\n");
                httpResponseLog.append("Response Code   : ").append(responseCode).append("\n");
                httpResponseLog.append("Response Message: ").append(urlConnection.getResponseMessage()).append("\n");
                httpResponseLog.append("Content-Type    : ").append(urlConnection.getContentType()).append("\n");
                httpResponseLog.append("Content-Length  : ").append(urlConnection.getContentLengthLong()).append("\n");
                httpResponseLog.append("Final URL       : ").append(urlConnection.getURL()).append("\n");
                httpResponseLog.append("=================================================");

                dashboard.logToFile(httpResponseLog.toString());

            } catch (Exception loggingException) {

                Log.w(
                        TAG,
                        "Failed to build/write HttpURLConnection response log",
                        loggingException
                );
            }


            // =========================================================
            // RESPONSE BODY
            // =========================================================

            long responseSize = 0;

            if (responseCode >= 200
                    && responseCode < 300) {

                InputStream inputStream =
                        urlConnection.getInputStream();

                BufferedInputStream bis =
                        new BufferedInputStream(
                                inputStream
                        );


                // ADDED: PAGE SOURCE (RAW HTML) LOG
                ByteArrayOutputStream pageSourceCapture =
                        new ByteArrayOutputStream();


                // =====================================================
                // FIRST BYTE / T3
                // =====================================================

                int firstByte =
                        bis.read();

                // ADDED: PAGE SOURCE (RAW HTML) LOG
                if (firstByte != -1) {
                    pageSourceCapture.write(firstByte);
                }

                long firstByteTime =
                        System.currentTimeMillis();

                dashboard.logToFile(
                        TAG
                                + "First byte received T3 time ms:"
                                + firstByteTime
                );

                dashboard.logToFile(
                        TAG + "WEB TEST FIRST BYTE"
                );


                // =====================================================
                // RESPONSE SIZE
                // =====================================================

                byte[] buffer =
                        new byte[8192];

                int bytesRead;

                while ((bytesRead =
                        bis.read(buffer)) != -1) {

                    responseSize += bytesRead;

                    // ADDED: PAGE SOURCE (RAW HTML) LOG
                    pageSourceCapture.write(buffer, 0, bytesRead);
                }


                dashboard.logToFile(
                        TAG
                                + "HTTP Response Size : "
                                + responseSize
                                + " bytes ("
                                + String.format(
                                "%.2f",
                                responseSize / 1024.0
                        )
                                + " KB)"
                );


                // ADDED: PAGE SOURCE (RAW HTML) LOG
                try {

                    StringBuilder source = new StringBuilder();

                    try (BufferedReader reader = new BufferedReader(
                            new InputStreamReader(
                                    new ByteArrayInputStream(pageSourceCapture.toByteArray()),
                                    StandardCharsets.UTF_8))) {

                        String line;

                        while ((line = reader.readLine()) != null) {
                            source.append(line).append("\n");
                        }
                    }

                    String pageSource = source.toString();

                    dashboard.logToFile(
                            TAG
                                    + "========== PAGE SOURCE (RAW HTML) ==========\n"
                                    + pageSource
                                    + "\n=============================================="
                    );

                } catch (Exception pageSourceLoggingException) {

                    Log.w(
                            TAG,
                            "Failed to log page source",
                            pageSourceLoggingException
                    );
                }


                bis.close();
                inputStream.close();

                // Equivalent of onPageFinished(): notify UI the "page" loaded.
                if (listener != null) {
                    listener.onWebTestFinished(true, url);
                }

            } else {

                // =====================================================
                // FAILED RESPONSE
                // =====================================================

                dashboard.logToFile(
                        TAG
                                + "WEB TEST RESPONSE FAILED: "
                                + responseCode
                );

                if (listener != null) {
                    listener.onWebTestFinished(false, url);
                }
            }


            // =========================================================
            // WEB PAGE LOAD END
            // =========================================================

            long endTime =
                    System.currentTimeMillis();

            totalTime =
                    endTime - connectStart;

            dashboard.logToFile(
                    TAG
                            + "Web page load end time ms:"
                            + endTime
            );


            // =========================================================
            // SAME TIME CALCULATIONS AS ORIGINAL
            // =========================================================

            long time =
                    totalTime - ttfbTime;

            float seconds =
                    time / 1000f;


            // =========================================================
            // SAME LOGS AS ORIGINAL runWebTest()
            // =========================================================

            /*
             * Original code has:
             *
             * Utils.appendLog("web txTotalData " + txTotalData);
             * Utils.appendLog("web rxTotalData " + rxTotalData);
             * Utils.appendLog("web totalTime " + totalTime);
             *
             * WebViewHelper currently does not have:
             *
             * totalDataTxAs
             * totalDataTxBs
             * totalDataRxAs
             * totalDataRxBs
             *
             * Therefore actual TX/RX values cannot be calculated here
             * without changing the existing logic.
             *
             * We still log the same fields so the logfile structure
             * remains consistent.
             */

            dashboard.logToFile(
                    TAG + "web txTotalData: NOT_AVAILABLE"
            );

            dashboard.logToFile(
                    TAG + "web rxTotalData: NOT_AVAILABLE"
            );

            dashboard.logToFile(
                    TAG + "web totalTime " + totalTime
            );

            dashboard.logToFile(
                    TAG + "WEB TEST TTFB TIME: "
                            + ttfbTime
                            + " ms"
            );

            dashboard.logToFile(
                    TAG + "WEB TEST TIME AFTER TTFB: "
                            + time
                            + " ms"
            );

            dashboard.logToFile(
                    TAG + "WEB TEST DURATION SECONDS: "
                            + seconds
            );

            dashboard.logToFile(
                    TAG + "WEB TEST RESPONSE SIZE: "
                            + responseSize
                            + " bytes"
            );


            // =========================================================
            // WEB TEST COMPLETE
            // =========================================================

            dashboard.logToFile(
                    TAG + "WEB TEST COMPLETE"
            );


            // =========================================================
            // TELEPHONY PARAMS
            // =========================================================

            // ---------------- Telephony Params ----------------


        } catch (IOException io) {

            dashboard.logToFile(
                    TAG
                            + "ELOG_WEB_EXCEPTION_PANEL: "
                            + io.getClass().getName()
                            + " : "
                            + io.toString()
            );

            dashboard.logToFile(
                    TAG
                            + "ELOG_WEB_EXCEPTION_PANEL_STACKTRACE: "
                            + stackTraceToString(io)
            );

            Log.e(
                    TAG,
                    "IOException in web test",
                    io
            );

            if (listener != null) {
                listener.onWebTestFinished(false, url);
            }

        } catch (Exception e) {

            dashboard.logToFile(
                    TAG
                            + "ELOG_WEB_EXCEPTION_PANEL: "
                            + e.getClass().getName()
                            + " : "
                            + e.toString()
            );

            dashboard.logToFile(
                    TAG
                            + "ELOG_WEB_EXCEPTION_PANEL_STACKTRACE: "
                            + stackTraceToString(e)
            );

            Log.e(
                    TAG,
                    "Exception in web test",
                    e
            );
        }
    }


    private static String stackTraceToString(Throwable t) {

        StringWriter sw =
                new StringWriter();

        t.printStackTrace(
                new PrintWriter(sw)
        );

        return sw.toString();
    }
}