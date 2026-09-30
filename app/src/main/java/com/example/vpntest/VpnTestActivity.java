package com.example.vpntest;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;

import java.io.File;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import android.content.pm.PackageManager;
import android.net.Uri;

import androidx.core.content.FileProvider;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.example.vpntest.appOpen.AppOpenVpnTestActivity;
import com.example.vpntest.appOpen.AppOpenYoutubeTestActivity;
import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.repo.VpnEventRepository;
import com.example.vpntest.ui.VpnDashboardViewModel;
import com.example.vpntest.ui.VpnEventAdapter;
import com.example.vpntest.utils.TestSessionManager;
import com.example.vpntest.utils.VpnLogFileManager;
import com.example.vpntest.webTest.WebViewHelper;

public class VpnTestActivity extends AppCompatActivity {

    private static final String TAG = "VpnTestActivity : ";

    private TextView tvStatus;
    private WebView webView;
    private Button btnStartVpn;
    private Button btnStopVpn;
    private Button btnPerformAppOpenTest;
    private Button btnPerformYoutubeTest;

    // Dashboard views
    private TextView tvVpnStatus, tvPermissionStatus, tvInterfaceStatus, tvReaderStatus;
    private TextView tvTotalPackets, tvTcpCount, tvUdpCount, tvIpv6Skipped;
    private TextView tvLastProtocol, tvLastSource, tvLastDest, tvLastSize, tvLastTimestamp;
    private TextView tvLastTtfb;
    private TextView tvLastTtfbWeb;

    // VPN TTFB wall-clock
    private TextView tvVpnTtfbT0;
    private TextView tvVpnTtfbT1;

    // Web TTFB wall-clock
    private TextView tvTtfbT0;
    private TextView tvTtfbT1;

    // TCP Handshake wall-clock
    private TextView tvTcpHandshakeT0;
    private TextView tvTcpHandshakeT1;

    // TLS Handshake wall-clock
    private TextView tvTlsHandshakeT0;
    private TextView tvTlsHandshakeT1;

    // DNS Resolution wall-clock
    private TextView tvDnsResolutionT0;
    private TextView tvDnsResolutionT1;

    private TextView tvTcpHandshake;
    private TextView tvTlsHandshake;
    private TextView tvDnsLookup;
    private TextView tvDnsServerIp;
    private TextView tvDnsDestinationIp;
    private TextView tvDnsHostName;

    private TextView tvTcpConnectionTime;
    private TextView tvTcpConnectionT0;
    private TextView tvTcpConnectionT1;

    private TextView tvTcpRetransmissionCount;
    private TextView tvQuicHandshake;
    private MediatorVpnService mediatorVpnService;
    private boolean deleteLogAfterShare = false;
    private boolean isServiceBound = false;

    private final ExecutorService websiteDnsExecutor =
            Executors.newSingleThreadExecutor();

    private boolean pendingUrlLoad = false;
    private String pendingTargetUrl = null;

    private final ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {

            mediatorVpnService =
                    ((MediatorVpnService.LocalBinder) service).getService();

            isServiceBound = true;

            mediatorVpnService.setVpnReadyCallback(
                    () -> runOnUiThread(() -> {

                        Log.d(
                                TAG,
                                "VPN established callback received."
                        );

                        if (pendingUrlLoad && pendingTargetUrl != null) {

                            String urlToLoad = pendingTargetUrl;

                            pendingUrlLoad = false;
                            pendingTargetUrl = null;

                            updateStatus(
                                    "VPN established. Loading "
                                            + urlToLoad
                                            + " ..."
                            );
                            // Clear WebView cache before starting the web test
                            webView.getSettings().setCacheMode(WebSettings.LOAD_NO_CACHE);
                            webView.clearCache(true);

                            resolveAndSetWebsiteTarget(urlToLoad);

                            websiteDnsExecutor.execute(
                                    () -> webViewHelper.runWebTest(urlToLoad)
                            );                        }
                    })
            );
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            mediatorVpnService = null;
            isServiceBound = false;
        }
    };

    private EditText etTargetUrl;
    private RecyclerView rvEventConsole;
    private VpnEventAdapter eventAdapter;

    private VpnDashboardViewModel viewModel;

    private final VpnEventRepository dashboardRepo =
            VpnEventRepository.getInstance();

    private final WebViewHelper webViewHelper =
            new WebViewHelper();

    private final ActivityResultLauncher<Intent> vpnPermissionLauncher =
            registerForActivityResult(
                    new ActivityResultContracts.StartActivityForResult(),
                    result -> {

                        if (result.getResultCode() == RESULT_OK) {

                            Log.d(
                                    TAG,
                                    "VPN permission granted by user."
                            );

                            dashboardRepo.setPermissionStatus("Granted");

                            dashboardRepo.logEvent(
                                    TAG + "VPN permission granted",
                                    VpnEvent.Level.SUCCESS,
                                    VpnEvent.Category.GENERAL
                            );

                            startVpnServiceAndLoadWebView();

                        } else {

                            Log.d(
                                    TAG,
                                    "VPN permission denied by user."
                            );

                            dashboardRepo.setPermissionStatus("Denied");

                            dashboardRepo.logEvent(
                                    TAG + "VPN permission denied",
                                    VpnEvent.Level.ERROR,
                                    VpnEvent.Category.ERROR
                            );

                            updateStatus("VPN permission denied.");

                            // Session was acquired before permission dialog.
                            // Release it if user denies permission.
                            TestSessionManager.stopTest();

                            updateTestButtons();

                            Toast.makeText(
                                    this,
                                    "VPN permission was denied.",
                                    Toast.LENGTH_SHORT
                            ).show();
                        }
                    }
            );

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_vpn_test);

        tvStatus = findViewById(R.id.tvStatus);
        webView = findViewById(R.id.webView);
        etTargetUrl = findViewById(R.id.etTargetUrl);

        btnStartVpn = findViewById(R.id.btnStartVpn);
        btnStopVpn = findViewById(R.id.btnStopVpn);
        btnPerformAppOpenTest =
                findViewById(R.id.btnPerformAppOpenTest);

        btnPerformYoutubeTest =
                findViewById(R.id.btnPerformYoutubeTest);
        bindDashboardViews();
        setupEventConsole();

        webView.getSettings().setJavaScriptEnabled(true);
        webView.setWebViewClient(new WebViewClient());

        // WebViewHelper now does the fetch manually.
        webViewHelper.setWebTestListener(
                (success, loadedUrl) ->
                        runOnUiThread(() -> {

                            if (success) {

                                updateStatus(
                                        "WebView Loaded: "
                                                + loadedUrl
                                );

                                tvLastTtfbWeb.setText(
                                        webViewHelper.getTtfbTime()
                                                + " ms"
                                );

                            } else {

                                updateStatus(
                                        "WebView Load Failed: "
                                                + loadedUrl
                                );

                                tvLastTtfbWeb.setText("-");
                            }
                        })
        );

        btnStartVpn.setOnClickListener(
                v -> onStartVpnClicked()
        );

        btnStopVpn.setOnClickListener(
                v -> onStopVpnClicked()
        );

        btnPerformAppOpenTest.setOnClickListener(v -> {

            Intent intent =
                    new Intent(
                            VpnTestActivity.this,
                            AppOpenVpnTestActivity.class
                    );

            startActivity(intent);
        });

        btnPerformYoutubeTest.setOnClickListener(v -> {

            Intent intent =
                    new Intent(
                            VpnTestActivity.this,
                            AppOpenYoutubeTestActivity.class
                    );

            startActivity(intent);
        });

        viewModel =
                new ViewModelProvider(this)
                        .get(VpnDashboardViewModel.class);

        viewModel.getLatestEvent()
                .observe(this, this::onNewEvent);

        viewModel.getStats().observe(this, stats -> {

            tvVpnStatus.setText(stats.vpnStatus);
            tvPermissionStatus.setText(stats.permissionStatus);
            tvInterfaceStatus.setText(stats.interfaceStatus);
            tvReaderStatus.setText(stats.readerStatus);

            tvTotalPackets.setText(
                    String.valueOf(stats.totalPackets)
            );

            tvTcpCount.setText(
                    String.valueOf(stats.tcpCount)
            );

            tvUdpCount.setText(
                    String.valueOf(stats.udpCount)
            );

            tvIpv6Skipped.setText(
                    String.valueOf(stats.ipv6SkippedCount)
            );

            tvLastProtocol.setText(
                    stats.lastProtocol
            );

            tvLastSource.setText(
                    stats.lastSourceIp
            );

            tvLastDest.setText(
                    stats.lastDestIp
            );

            tvLastSize.setText(
                    stats.lastPacketSize > 0
                            ? stats.lastPacketSize + " bytes"
                            : "-"
            );

            tvLastTimestamp.setText(
                    stats.lastPacketTimestamp > 0
                            ? android.text.format.DateFormat.format(
                            "HH:mm:ss",
                            stats.lastPacketTimestamp
                    )
                            : "-"
            );

            tvLastTtfb.setText(
                    stats.lastTtfbMs >= 0
                            ? stats.lastTtfbMs + " ms"
                            : "-"
            );

            tvVpnTtfbT0.setText(
                    "T0: " + formatWallClock(stats.ttfbT0WallTime)
            );

            tvVpnTtfbT1.setText(
                    "T1: " + formatWallClock(stats.ttfbT1WallTime)
            );
            // ============================================================
// WEB TTFB
// ============================================================

            tvTtfbT0.setText(
                    "T0: " + formatWallClock(
                            stats.webTtfbT0WallTime
                    )
            );

            tvTtfbT1.setText(
                    "T1: " + formatWallClock(
                            stats.webTtfbT1WallTime
                    )
            );
// ============================================================
// TCP HANDSHAKE
// ============================================================

            if (tvTcpHandshake != null) {

                if (stats.tcpHandshakeNano >= 0) {

                    double handshakeMs =
                            stats.tcpHandshakeNano / 1_000_000.0;

                    tvTcpHandshake.setText(
                            String.format(
                                    Locale.US,
                                    "%.2f ms",
                                    handshakeMs
                            )
                    );

                } else {

                    tvTcpHandshake.setText("-");
                }
            }

            if (tvTcpHandshakeT0 != null) {

                tvTcpHandshakeT0.setText(
                        "T0: " + formatWallClock(
                                stats.tcpHandshakeT0WallTime
                        )
                );
            }

            if (tvTcpHandshakeT1 != null) {

                tvTcpHandshakeT1.setText(
                        "T1: " + formatWallClock(
                                stats.tcpHandshakeT1WallTime
                        )
                );
            }
            // ============================================================
            // TCP CONNECTION TIME
            // ============================================================

            // ============================================================
// TCP CONNECTION TIME
// ============================================================

            if (tvTcpConnectionTime != null) {

                if (stats.tcpConnectionTimeMs >= 0) {

                    tvTcpConnectionTime.setText(
                            String.format(
                                    Locale.US,
                                    "%.3f ms",
                                    (double) stats.tcpConnectionTimeMs
                            )
                    );

                } else {

                    tvTcpConnectionTime.setText("-");
                }
            }


// ============================================================
// TCP CONNECTION T0
// ============================================================

            if (tvTcpConnectionT0 != null) {

                tvTcpConnectionT0.setText(
                        "T0: " + formatWallClock(
                                stats.tcpConnectionT0WallTime
                        )
                );
            }


// ============================================================
// TCP CONNECTION T1
// ============================================================

            if (tvTcpConnectionT1 != null) {

                tvTcpConnectionT1.setText(
                        "T1: " + formatWallClock(
                                stats.tcpConnectionT1WallTime
                        )
                );
            }

// TCP RETRANSMISSION COUNT
            tvTcpRetransmissionCount.setText(
                    String.valueOf(
                            stats.tcpRetransmissionCount
                    )
            );


// QUIC HANDSHAKE
            if (stats.quicHandshakeMs >= 0) {

                tvQuicHandshake.setText(
                        String.format(
                                Locale.US,
                                "%.3f ms",
                                stats.quicHandshakeMs
                        )
                );

            } else {

                tvQuicHandshake.setText("-");
            }


// TLS HANDSHAKE
            if (stats.tlsHandshakeMs >= 0) {

                tvTlsHandshake.setText(
                        String.format(
                                Locale.US,
                                "%.3f ms",
                                stats.tlsHandshakeMs
                        )
                );

            } else {

                tvTlsHandshake.setText("-");
            }

            tvTlsHandshakeT0.setText(
                    "T0: " + formatWallClock(
                            stats.tlsHandshakeT0WallTime
                    )
            );

            tvTlsHandshakeT1.setText(
                    "T1: " + formatWallClock(
                            stats.tlsHandshakeT1WallTime
                    )
            );

// DNS LOOKUP
            if (stats.lastDnsLookupMs >= 0) {

                tvDnsLookup.setText(
                        String.format(
                                Locale.US,
                                "%.3f ms",
                                stats.lastDnsLookupMs
                        )
                );

                tvDnsServerIp.setText(
                        "Server: " + stats.lastDnsServerIp
                );

            } else {

                tvDnsLookup.setText("-");
                tvDnsServerIp.setText("Server: -");
            }

            tvDnsResolutionT0.setText(
                    "T0: " + formatWallClock(
                            stats.dnsResolutionT0WallTime
                    )
            );

            tvDnsResolutionT1.setText(
                    "T1: " + formatWallClock(
                            stats.dnsResolutionT1WallTime
                    )
            );

// ADD: Destination IP
            if (stats.lastDestIp != null
                    && !stats.lastDestIp.isEmpty()
                    && !stats.lastDestIp.equals("-")) {

                tvDnsDestinationIp.setText(
                        "Destination IP: " + stats.lastDnsDestinationIp
                );

            } else {

                tvDnsDestinationIp.setText(
                        "Destination IP: -"
                );
            }


// Destination IP
            if (stats.lastDestIp != null
                    && !stats.lastDestIp.isEmpty()
                    && !stats.lastDestIp.equals("-")) {

                tvDnsDestinationIp.setText(
                        "Destination IP: " + stats.lastDnsDestinationIp
                );

            } else {

                tvDnsDestinationIp.setText(
                        "Destination IP: -"
                );
            }

// Host Name
            if (stats.lastDnsHostName != null
                    && !stats.lastDnsHostName.isEmpty()
                    && !stats.lastDnsHostName.equals("-")) {

                tvDnsHostName.setText(
                        "Host Name: " + stats.lastDnsHostName
                );

            } else {

                tvDnsHostName.setText(
                        "Host Name: -"
                );
            }


        });

        // Set initial button state.
        updateTestButtons();
    }

    private void bindDashboardViews() {

        // ============================================================
        // VPN HEALTH
        // ============================================================

        tvVpnStatus =
                findViewById(R.id.tvVpnStatus);

        tvPermissionStatus =
                findViewById(R.id.tvPermissionStatus);

        tvInterfaceStatus =
                findViewById(R.id.tvInterfaceStatus);

        tvReaderStatus =
                findViewById(R.id.tvReaderStatus);


        // ============================================================
        // PACKET STATISTICS
        // ============================================================

        tvTotalPackets =
                findViewById(R.id.tvTotalPackets);

        tvTcpCount =
                findViewById(R.id.tvTcpCount);

        tvUdpCount =
                findViewById(R.id.tvUdpCount);

        tvIpv6Skipped =
                findViewById(R.id.tvIpv6Skipped);


        // ============================================================
        // LAST PACKET
        // ============================================================

        tvLastProtocol =
                findViewById(R.id.tvLastProtocol);

        tvLastSource =
                findViewById(R.id.tvLastSource);

        tvLastDest =
                findViewById(R.id.tvLastDest);

        tvLastSize =
                findViewById(R.id.tvLastSize);

        tvLastTimestamp =
                findViewById(R.id.tvLastTimestamp);


        // ============================================================
        // VPN TTFB
        // ============================================================

        tvLastTtfb =
                findViewById(R.id.tvLastTtfb);

        tvVpnTtfbT0 =
                findViewById(R.id.tvVpnTtfbT0);

        tvVpnTtfbT1 =
                findViewById(R.id.tvVpnTtfbT1);


        // ============================================================
        // WEB TTFB
        // ============================================================

        tvLastTtfbWeb =
                findViewById(R.id.tvLastTtfbWeb);

        tvTtfbT0 =
                findViewById(R.id.tvTtfbT0);

        tvTtfbT1 =
                findViewById(R.id.tvTtfbT1);


        // ============================================================
        // TCP HANDSHAKE
        // ============================================================

        tvTcpHandshake =
                findViewById(R.id.tvTcpHandshake);

        tvTcpHandshakeT0 =
                findViewById(R.id.tvTcpHandshakeT0);

        tvTcpHandshakeT1 =
                findViewById(R.id.tvTcpHandshakeT1);


// ============================================================
// TCP CONNECTION
// ============================================================

        tvTcpConnectionTime =
                findViewById(R.id.tvTcpConnectionTime);

        tvTcpConnectionT0 =
                findViewById(R.id.tvTcpConnectionT0);

        tvTcpConnectionT1 =
                findViewById(R.id.tvTcpConnectionT1);


        // ============================================================
        // TCP RETRANSMISSIONS
        // ============================================================

        tvTcpRetransmissionCount =
                findViewById(R.id.tvTcpRetransmissionCount);


        // ============================================================
        // TLS HANDSHAKE
        // ============================================================

        tvTlsHandshake =
                findViewById(R.id.tvTlsHandshake);

        tvTlsHandshakeT0 =
                findViewById(R.id.tvTlsHandshakeT0);

        tvTlsHandshakeT1 =
                findViewById(R.id.tvTlsHandshakeT1);


        // ============================================================
        // DNS
        // ============================================================

        tvDnsLookup =
                findViewById(R.id.tvDnsLookup);

        tvDnsResolutionT0 =
                findViewById(R.id.tvDnsResolutionT0);

        tvDnsResolutionT1 =
                findViewById(R.id.tvDnsResolutionT1);

        tvDnsServerIp =
                findViewById(R.id.tvDnsServerIp);

        tvDnsDestinationIp =
                findViewById(R.id.tvDnsDestinationIp);

        tvDnsHostName =
                findViewById(R.id.tvDnsHostName);


        // ============================================================
        // QUIC
        // ============================================================

        tvQuicHandshake =
                findViewById(R.id.tvQuicHandshake);


        // ============================================================
// DEBUG VALIDATION
// ============================================================

        if (tvVpnStatus == null ||
                tvPermissionStatus == null ||
                tvInterfaceStatus == null ||
                tvReaderStatus == null ||
                tvTotalPackets == null ||
                tvTcpCount == null ||
                tvUdpCount == null ||
                tvIpv6Skipped == null ||
                tvLastProtocol == null ||
                tvLastSource == null ||
                tvLastDest == null ||
                tvLastSize == null ||
                tvLastTimestamp == null ||
                tvLastTtfb == null ||
                tvLastTtfbWeb == null ||
                tvVpnTtfbT0 == null ||
                tvVpnTtfbT1 == null ||
                tvTtfbT0 == null ||
                tvTtfbT1 == null ||
                tvTcpHandshake == null ||
                tvTcpHandshakeT0 == null ||
                tvTcpHandshakeT1 == null ||
                tvTcpConnectionTime == null ||
                tvTcpConnectionT0 == null ||
                tvTcpConnectionT1 == null ||
                tvTcpRetransmissionCount == null ||
                tvTlsHandshake == null ||
                tvTlsHandshakeT0 == null ||
                tvTlsHandshakeT1 == null ||
                tvDnsLookup == null ||
                tvDnsResolutionT0 == null ||
                tvDnsResolutionT1 == null ||
                tvDnsServerIp == null ||
                tvDnsDestinationIp == null ||
                tvDnsHostName == null ||
                tvQuicHandshake == null) {

            Log.e(
                    TAG,
                    "One or more dashboard views are NULL. " +
                            "Check activity_vpn_test.xml and layout variants."
            );
        }
    }

    private String formatWallClock(long wallTime) {

        if (wallTime <= 0L) {
            return "-";
        }

        return new java.text.SimpleDateFormat(
                "HH:mm:ss:SSS",
                java.util.Locale.getDefault()
        ).format(
                new java.util.Date(wallTime)
        );
    }
    private void setupEventConsole() {

        rvEventConsole =
                findViewById(R.id.rvEventConsole);

        eventAdapter =
                new VpnEventAdapter();

        rvEventConsole.setLayoutManager(
                new LinearLayoutManager(this)
        );

        rvEventConsole.setAdapter(
                eventAdapter
        );

        rvEventConsole.setHasFixedSize(true);
    }

    private void onNewEvent(VpnEvent event) {

        eventAdapter.addEvent(event);

        rvEventConsole.scrollToPosition(
                eventAdapter.getLastIndex()
        );
    }

    private void onStartVpnClicked() {

        // Prevent Web Test from starting if another test is running.
        if (!TestSessionManager.startTest(
                TestSessionManager.TestType.WEB)) {

            Toast.makeText(
                    this,
                    "Another test is already running.",
                    Toast.LENGTH_SHORT
            ).show();

            updateTestButtons();

            return;
        }
        Toast.makeText(
                this,
                "VPN test started",
                Toast.LENGTH_SHORT
        ).show();

        /*
         * ============================================================
         * RESET ALL PREVIOUS TEST RESULTS
         * ============================================================
         *
         * IMPORTANT:
         * Every timing value is reset BEFORE the new test starts.
         *
         * TTFB
         * TCP Handshake
         * TLS Handshake
         * DNS
         * TCP Connection
         * QUIC
         *
         * T0/T1 wall-clock values are also reset to -1.
         * UI will therefore show "-" until the NEW measurement arrives.
         * ============================================================
         */

// =========================
// VPN TTFB
// =========================

        dashboardRepo.resetTtfb();

// =========================
// WEB TTFB
// =========================

        dashboardRepo.resetWebTtfb();

// =========================
// TCP HANDSHAKE
// =========================

        dashboardRepo.resetTcpHandshake();

// =========================
// TCP CONNECTION
// =========================

        dashboardRepo.resetTcpConnectionTime();

// =========================
// TCP RETRANSMISSION
// =========================

        dashboardRepo.resetTcpRetransmissionCount();

// =========================
// TLS HANDSHAKE
// =========================

        dashboardRepo.resetTlsHandshake();

// =========================
// DNS
// =========================

        dashboardRepo.resetDnsLookup();
        dashboardRepo.resetDnsDestinationIp();
        dashboardRepo.resetDnsHostName();

// =========================
// QUIC
// =========================

        dashboardRepo.resetQuicHandshake();
        /*
         * ============================================================
         * CLEAR OLD VALUES FROM UI IMMEDIATELY
         * ============================================================
         */

// VPN TTFB
        if (tvLastTtfb != null) {
            tvLastTtfb.setText("-");
        }

        if (tvVpnTtfbT0 != null) {
            tvVpnTtfbT0.setText("T0: -");
        }

        if (tvVpnTtfbT1 != null) {
            tvVpnTtfbT1.setText("T1: -");
        }


// WEB TTFB
        if (tvLastTtfbWeb != null) {
            tvLastTtfbWeb.setText("-");
        }

        if (tvTtfbT0 != null) {
            tvTtfbT0.setText("T0: -");
        }

        if (tvTtfbT1 != null) {
            tvTtfbT1.setText("T1: -");
        }


// TCP HANDSHAKE
        if (tvTcpHandshake != null) {
            tvTcpHandshake.setText("-");
        }

        if (tvTcpHandshakeT0 != null) {
            tvTcpHandshakeT0.setText("T0: -");
        }

        if (tvTcpHandshakeT1 != null) {
            tvTcpHandshakeT1.setText("T1: -");
        }


// TCP CONNECTION
        if (tvTcpConnectionTime != null) {
            tvTcpConnectionTime.setText("-");
        }


// TCP RETRANSMISSION
        if (tvTcpRetransmissionCount != null) {
            tvTcpRetransmissionCount.setText("0");
        }


// TLS HANDSHAKE
        if (tvTlsHandshake != null) {
            tvTlsHandshake.setText("-");
        }

        if (tvTlsHandshakeT0 != null) {
            tvTlsHandshakeT0.setText("T0: -");
        }

        if (tvTlsHandshakeT1 != null) {
            tvTlsHandshakeT1.setText("T1: -");
        }


// DNS
        if (tvDnsLookup != null) {
            tvDnsLookup.setText("-");
        }

        if (tvDnsResolutionT0 != null) {
            tvDnsResolutionT0.setText("T0: -");
        }

        if (tvDnsResolutionT1 != null) {
            tvDnsResolutionT1.setText("T1: -");
        }

        if (tvDnsServerIp != null) {
            tvDnsServerIp.setText("Server: -");
        }

        if (tvDnsDestinationIp != null) {
            tvDnsDestinationIp.setText("Destination IP: -");
        }

        if (tvDnsHostName != null) {
            tvDnsHostName.setText("Host Name: -");
        }


// QUIC
        if (tvQuicHandshake != null) {
            tvQuicHandshake.setText("-");
        }
        updateTestButtons();

        updateStatus(
                "Requesting VPN permission..."
        );

        dashboardRepo.setPermissionStatus(
                "Requesting"
        );

        dashboardRepo.logEvent(
                TAG + "Requesting VPN permission",
                VpnEvent.Level.INFO,
                VpnEvent.Category.GENERAL
        );

        Intent prepareIntent =
                VpnService.prepare(this);

        if (prepareIntent != null) {

            vpnPermissionLauncher.launch(
                    prepareIntent
            );

        } else {

            Log.d(
                    TAG,
                    "VPN permission already granted."
            );

            dashboardRepo.setPermissionStatus(
                    "Granted"
            );

            dashboardRepo.logEvent(
                    TAG + "VPN permission already granted",
                    VpnEvent.Level.SUCCESS,
                    VpnEvent.Category.GENERAL
            );

            startVpnServiceAndLoadWebView();
        }
    }

    private void startVpnServiceAndLoadWebView() {

        String targetUrl =
                resolveTargetUrl();

        updateStatus(
                "Starting AppOpenMediatorVpnService..."
        );

        Intent serviceIntent =
                new Intent(
                        this,
                        MediatorVpnService.class
                );

        if (Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.O) {

            startForegroundService(
                    serviceIntent
            );
        }

        bindService(
                serviceIntent,
                connection,
                Context.BIND_AUTO_CREATE
        );

        pendingTargetUrl =
                targetUrl;

        pendingUrlLoad =
                true;

        updateStatus(
                "VPN service starting. Waiting for VPN establishment before loading "
                        + targetUrl
                        + " ..."
        );

        btnStartVpn.setEnabled(false);
        btnStopVpn.setEnabled(true);

        // While Web Test is running,
        // App Open navigation button is disabled.
        btnPerformAppOpenTest.setEnabled(false);
        btnPerformYoutubeTest.setEnabled(false);
    }

    private void onStopVpnClicked() {

        updateStatus(
                "Stopping VPN..."
        );

        dashboardRepo.logEvent(
                TAG + "Stopping VPN (user requested)",
                VpnEvent.Level.INFO,
                VpnEvent.Category.GENERAL
        );

        pendingUrlLoad = false;
        pendingTargetUrl = null;

        if (isServiceBound &&
                mediatorVpnService != null) {

            mediatorVpnService.setWebsiteTarget(
                    null,
                    null
            );
        }

        if (isServiceBound &&
                mediatorVpnService != null) {

            /*
             * ============================================================
             * RESOLVE SERVER HOSTNAME BEFORE STOPPING VPN
             * ============================================================
             *
             * stopVpn() will shutdown TcpForwarder and close all
             * real TCP sockets.
             *
             * Therefore hostname MUST be resolved first.
             */
            mediatorVpnService.resolveServerHostNameOnStop();

            mediatorVpnService.clearVpnReadyCallback();

            mediatorVpnService.stopVpn();

            unbindService(connection);

            isServiceBound = false;

            mediatorVpnService = null;
        }

        Intent serviceIntent =
                new Intent(
                        this,
                        MediatorVpnService.class
                );

        stopService(serviceIntent);

        dashboardRepo.setVpnStatus(
                "Stopped"
        );

        dashboardRepo.setInterfaceStatus(
                "Closed"
        );

        dashboardRepo.setReaderStatus(
                "Stopped"
        );


        dashboardRepo.logEvent(
                TAG + "VPN stopped by user",
                VpnEvent.Level.INFO,
                VpnEvent.Category.GENERAL
        );

        updateStatus(
                "VPN stopped."
        );

        VpnLogFileManager
                .getInstance()
                .endSession();

        File logFile =
                VpnLogFileManager
                        .getInstance()
                        .getCurrentLogFile();


// Show Share Log dialog.
//
// IMPORTANT:
// Do NOT change the button state here.
// The buttons will be changed only after
// the user selects YES or NO.
        showShareLogDialog(logFile);
    }

    private String resolveTargetUrl() {

        String input =
                etTargetUrl.getText() != null
                        ? etTargetUrl
                        .getText()
                        .toString()
                        .trim()
                        : "";

        if (input.isEmpty()) {
            input =
                    "https://www.google.com";
        }

        if (!input.matches(
                "^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) {

            input =
                    "https://" + input;
        }

        return input;
    }

    private String extractHostname(String url) {

        Uri uri =
                Uri.parse(url);

        return uri.getHost();
    }

    private void resolveAndSetWebsiteTarget(
            String urlToLoad) {

        String hostname =
                extractHostname(urlToLoad);

        if (hostname == null ||
                hostname.isEmpty()) {

            return;
        }

        websiteDnsExecutor.execute(() -> {

            try {

                InetAddress[] addresses =
                        InetAddress.getAllByName(
                                hostname
                        );

                Set<String> resolvedIps =
                        new HashSet<>();

                for (InetAddress address :
                        addresses) {

                    resolvedIps.add(
                            address.getHostAddress()
                    );
                }

                if (isServiceBound &&
                        mediatorVpnService != null) {

                    mediatorVpnService.setWebsiteTarget(
                            hostname,
                            resolvedIps
                    );
                }
                dashboardRepo.setDnsHostName(hostname);

                dashboardRepo.logToFile(
                        TAG+
                        "Resolved website "+
                                 hostname+
                                 " -> "+
                                 resolvedIps
                );

            } catch (UnknownHostException e) {

                dashboardRepo.logToFile(
                        TAG+
                        "DNS resolution failed for "
                                + hostname
                                + ": "
                                + e.getMessage()
                );
            }
        });
    }

    private void updateStatus(String message) {

        Log.d(
                TAG,
                message
        );

        if (tvStatus != null) {

            tvStatus.setText(
                    "Status: " + message
            );
        }
    }

    /**
     * Keeps Web Test and App Open Test mutually exclusive
     * at the UI level.
     */
    private void updateTestButtons() {

        TestSessionManager.TestType active =
                TestSessionManager.getActiveTest();

        boolean vpnRunning =
                active == TestSessionManager.TestType.WEB;

        boolean vpnStopped =
                active == TestSessionManager.TestType.NONE;

        // =========================
        // START VPN BUTTON
        // =========================

        if (btnStartVpn != null) {

            btnStartVpn.setEnabled(vpnStopped);

            // Disabled = grey
            if (vpnRunning) {
                btnStartVpn.setAlpha(0.45f);
            } else {
                btnStartVpn.setAlpha(1.0f);
            }
        }

        // =========================
        // STOP VPN BUTTON
        // =========================

        if (btnStopVpn != null) {

            btnStopVpn.setEnabled(vpnRunning);

            // Disabled = grey
            if (vpnStopped) {
                btnStopVpn.setAlpha(0.45f);
            } else {
                btnStopVpn.setAlpha(1.0f);
            }
        }

        // =========================
        // APP OPEN TEST BUTTON
        // =========================

        if (btnPerformAppOpenTest != null) {

            btnPerformAppOpenTest.setEnabled(vpnStopped);

            if (vpnRunning) {
                btnPerformAppOpenTest.setAlpha(0.45f);
            } else {
                btnPerformAppOpenTest.setAlpha(1.0f);
            }
        }

        // =========================
        // YOUTUBE TEST BUTTON
        // =========================

        if (btnPerformYoutubeTest != null) {

            btnPerformYoutubeTest.setEnabled(vpnStopped);

            if (vpnRunning) {
                btnPerformYoutubeTest.setAlpha(0.45f);
            } else {
                btnPerformYoutubeTest.setAlpha(1.0f);
            }
        }
    }
    private void setVpnStoppedUi() {

        // =========================
        // START VPN
        // Enabled + normal
        // =========================

        btnStartVpn.setEnabled(true);
        btnStartVpn.setAlpha(1.0f);


        // =========================
        // STOP VPN
        // Disabled + grey
        // =========================

        btnStopVpn.setEnabled(false);
        btnStopVpn.setAlpha(0.45f);


        // =========================
        // APP OPEN TEST
        // Enabled + normal
        // =========================

        btnPerformAppOpenTest.setEnabled(true);
        btnPerformAppOpenTest.setAlpha(1.0f);


        // =========================
        // YOUTUBE TEST
        // Enabled + normal
        // =========================

        btnPerformYoutubeTest.setEnabled(true);
        btnPerformYoutubeTest.setAlpha(1.0f);


        // =========================
        // RELEASE SESSION
        // =========================

        TestSessionManager.stopTest();


        // =========================
        // USER FEEDBACK
        // =========================

        Toast.makeText(
                this,
                "VPN test stopped. Ready for next test.",
                Toast.LENGTH_SHORT
        ).show();
    }
    private void showShareLogDialog(File logFile) {

        if (logFile == null ||
                !logFile.exists()) {

            Toast.makeText(
                    this,
                    "Log file not found.",
                    Toast.LENGTH_SHORT
            ).show();

            // No dialog will be shown,
            // so complete the stop flow here.
            setVpnStoppedUi();

            return;
        }

        new AlertDialog.Builder(this)
                .setTitle("Share Log")
                .setMessage(
                        "Do you want to share the VPN log file?"
                )
                .setCancelable(false)

                // =========================
                // YES
                // =========================

                .setPositiveButton(
                        "Yes",
                        (dialog, which) -> {

                            shareLogFile(
                                    logFile
                            );

                            // User selected YES.
                            // Now switch UI to READY state.
                            setVpnStoppedUi();
                        }
                )

                // =========================
                // NO
                // =========================

                .setNegativeButton(
                        "No",
                        (dialog, which) -> {

                            VpnLogFileManager
                                    .getInstance()
                                    .deleteCurrentLogFile();

                            Toast.makeText(
                                    this,
                                    "Log file deleted.",
                                    Toast.LENGTH_SHORT
                            ).show();

                            // User selected NO.
                            // Now switch UI to READY state.
                            setVpnStoppedUi();
                        }
                )
                .show();
    }

    private void shareLogFile(File file) {

        Uri uri =
                FileProvider.getUriForFile(
                        this,
                        getPackageName()
                                + ".fileprovider",
                        file
                );

        Intent shareIntent =
                new Intent(
                        Intent.ACTION_SEND
                );

        shareIntent.setType(
                "text/plain"
        );

        shareIntent.putExtra(
                Intent.EXTRA_STREAM,
                uri
        );

        shareIntent.addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION
        );

        PackageManager pm =
                getPackageManager();

        try {

            pm.getPackageInfo(
                    "com.whatsapp.w4b",
                    0
            );

            shareIntent.setPackage(
                    "com.whatsapp.w4b"
            );

            startActivity(
                    shareIntent
            );

        } catch (
                PackageManager.NameNotFoundException e1) {

            try {

                pm.getPackageInfo(
                        "com.whatsapp",
                        0
                );

                shareIntent.setPackage(
                        "com.whatsapp"
                );

                deleteLogAfterShare =
                        true;

                startActivity(
                        shareIntent
                );

            } catch (
                    PackageManager.NameNotFoundException e2) {

                startActivity(
                        Intent.createChooser(
                                shareIntent,
                                "Share VPN Log"
                        )
                );
            }
        }
    }

    @Override
    protected void onResume() {

        super.onResume();

        if (deleteLogAfterShare) {

            deleteLogAfterShare =
                    false;

            VpnLogFileManager
                    .getInstance()
                    .deleteCurrentLogFile();

            Toast.makeText(
                    this,
                    "VPN log deleted.",
                    Toast.LENGTH_SHORT
            ).show();
        }

        // Important when returning from App Open Test.
        updateTestButtons();
    }
}