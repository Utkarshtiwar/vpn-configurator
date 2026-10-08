package com.example.vpntest.appOpen;
import com.example.vpntest.model.VpnStats;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;

import java.io.File;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import android.content.pm.PackageManager;
import android.net.Uri;

import androidx.core.content.FileProvider;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.example.vpntest.R;
import com.example.vpntest.VpnTestActivity;
import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.repo.VpnEventRepository;
import com.example.vpntest.ui.VpnDashboardViewModel;
import com.example.vpntest.ui.VpnEventAdapter;
import com.example.vpntest.utils.TestSessionManager;
import com.example.vpntest.utils.VpnLogFileManager;

public class AppOpenVpnTestActivity extends AppCompatActivity {

    private static final String TAG =
            "AppOpen_VpnTestActivity : ";

    private static final String STATE_SELECTED_PACKAGE =
            "selected_package_name";

    private TextView tvStatus;
    private Button btnStartVpn;
    private Button btnStopVpn;
    private Spinner spinnerAppSelect;

    // Dashboard views
    private TextView tvVpnStatus,
            tvPermissionStatus,
            tvInterfaceStatus,
            tvReaderStatus;

    private TextView tvTotalPackets,
            tvTcpCount,
            tvUdpCount,
            tvIpv6Skipped;

    private TextView tvLastProtocol,
            tvLastSource,
            tvLastDest,
            tvLastSize,
            tvLastTimestamp;

    private TextView tvLastTtfb;

    // Performance views
    // Performance views
// Performance views
    private TextView tvPerformanceTtfb,
            tvPerformanceDnsLookup,
            tvPerformanceDnsServerIp,
            tvPerformanceSourceIp,
            tvPerformanceDestinationIp;

    private TextView tvAppOpenTtfbTime;
    private TextView tvAppOpenDnsTime;

    // APP OPEN TIME
    private TextView tvAppOpenTime;
    private TextView tvAppOpenTimeDetails;

    private TextView tvAppOpenTcpHandshake;
    private TextView tvAppOpenTcpHandshakeTime;
    private TextView tvAppOpenTlsHandshake;
    private TextView tvAppOpenTlsHandshakeTime;
    private TextView tvAppOpenTcpRetransmissionCount;
    private TextView tvAppOpenQuicHandshake;

    private AppOpenMediatorVpnService
            appOpenMediatorVpnService;

    private boolean deleteLogAfterShare =
            false;

    private boolean isServiceBound =
            false;

    private final List<AppInfo> installedApps =
            new ArrayList<>();

    private String selectedPackageName =
            null;

    /**
     * Set right before the VPN service is started;
     * consumed by VPN-ready callback.
     */
    private boolean pendingAppLaunch =
            false;

    private final ServiceConnection connection =
            new ServiceConnection() {

                @Override
                public void onServiceConnected(
                        ComponentName name,
                        IBinder service) {

                    appOpenMediatorVpnService =
                            ((AppOpenMediatorVpnService.LocalBinder)
                                    service)
                                    .getService();

                    isServiceBound =
                            true;

                    appOpenMediatorVpnService
                            .setVpnReadyCallback(
                                    () -> runOnUiThread(() -> {

                                        Log.d(
                                                TAG,
                                                "VPN established callback received."
                                        );

                                        if (pendingAppLaunch) {

                                            pendingAppLaunch =
                                                    false;

                                            launchSelectedApp();
                                        }
                                    })
                            );
                }

                @Override
                public void onServiceDisconnected(
                        ComponentName name) {

                    appOpenMediatorVpnService =
                            null;

                    isServiceBound =
                            false;
                }
            };

    private RecyclerView rvEventConsole;
    private VpnEventAdapter eventAdapter;

    private VpnDashboardViewModel viewModel;

    private final VpnEventRepository dashboardRepo =
            VpnEventRepository.getInstance();

    private final ActivityResultLauncher<Intent>
            vpnPermissionLauncher =
            registerForActivityResult(
                    new ActivityResultContracts.StartActivityForResult(),
                    result -> {

                        if (result.getResultCode()
                                == RESULT_OK) {

                            Log.d(
                                    TAG,
                                    "VPN permission granted by user."
                            );

                            dashboardRepo.setPermissionStatus(
                                    "Granted"
                            );

                            dashboardRepo.logEvent(
                                    TAG + "VPN permission granted",
                                    VpnEvent.Level.SUCCESS,
                                    VpnEvent.Category.GENERAL
                            );

                            startVpnServiceForSelectedApp();

                        } else {

                            Log.d(
                                    TAG,
                                    "VPN permission denied by user."
                            );

                            dashboardRepo.setPermissionStatus(
                                    "Denied"
                            );

                            dashboardRepo.logEvent(
                                    TAG + "VPN permission denied",
                                    VpnEvent.Level.ERROR,
                                    VpnEvent.Category.ERROR
                            );

                            updateStatus(
                                    "VPN permission denied."
                            );

                            // Session was acquired before
                            // permission dialog.
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
    public void onBackPressed() {

        if (TestSessionManager.getActiveTest()
                == TestSessionManager.TestType.APP_OPEN) {

            new AlertDialog.Builder(this)
                    .setTitle("Test Running")
                    .setMessage(
                            "App Open Test is currently running. "
                                    + "Stop the test before going back?"
                    )
                    .setNegativeButton(
                            "Cancel",
                            null
                    )
                    .setPositiveButton(
                            "Stop & Go Back",null
//                            (dialog, which) -> {
//
//                                // IMPORTANT:
//                                // Do NOT call onStopVpnClicked()
//                                // because that method opens the
//                                // Share Log dialog.
//                                stopAppOpenTestForBack();
//
//                                Intent intent =
//                                        new Intent(
//                                                AppOpenVpnTestActivity.this,
//                                                VpnTestActivity.class
//                                        );
//
//                                intent.addFlags(
//                                        Intent.FLAG_ACTIVITY_CLEAR_TOP
//                                                | Intent.FLAG_ACTIVITY_SINGLE_TOP
//                                );
//
//                                startActivity(
//                                        intent
//                                );
//
//                                finish();
//                            }
                    )
                    .show();

            return;
        }

        super.onBackPressed();
    }

    @Override
    protected void onCreate(
            Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);

        // IMPORTANT:
        // App Open has its own layout.
        setContentView(
                R.layout.activity_app_open_test
        );

        tvStatus =
                findViewById(R.id.tvStatus);

        btnStartVpn =
                findViewById(R.id.btnStartVpn);

        btnStopVpn =
                findViewById(R.id.btnStopVpn);

        spinnerAppSelect =
                findViewById(R.id.spinnerAppSelect);

        View btnBack = findViewById(R.id.btnBack);
        if (btnBack != null) {
            btnBack.setOnClickListener(v -> onBackPressed());
        }

        bindDashboardViews();

        setupEventConsole();

        setupAppSelectionSpinner(
                savedInstanceState
        );

        btnStartVpn.setOnClickListener(
                v -> onStartVpnClicked()
        );

        btnStopVpn.setOnClickListener(
                v -> onStopVpnClicked()
        );

        viewModel =
                new ViewModelProvider(this)
                        .get(VpnDashboardViewModel.class);

        viewModel.getLatestEvent()
                .observe(
                        this,
                        this::onNewEvent
                );

        viewModel.getStats()
                .observe(this, stats -> {

                    tvVpnStatus.setText(
                            stats.vpnStatus
                    );

                    tvPermissionStatus.setText(
                            stats.permissionStatus
                    );

                    tvInterfaceStatus.setText(
                            stats.interfaceStatus
                    );

                    tvReaderStatus.setText(
                            stats.readerStatus
                    );

                    tvTotalPackets.setText(
                            String.valueOf(
                                    stats.totalPackets
                            )
                    );

                    tvTcpCount.setText(
                            String.valueOf(
                                    stats.tcpCount
                            )
                    );

                    tvUdpCount.setText(
                            String.valueOf(
                                    stats.udpCount
                            )
                    );

                    tvIpv6Skipped.setText(
                            String.valueOf(
                                    stats.ipv6SkippedCount
                            )
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
                                    ? stats.lastPacketSize
                                    + " bytes"
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

                    tvPerformanceTtfb.setText(
                            stats.appOpenTtfbMs >= 0
                                    ? stats.appOpenTtfbMs + " ms"
                                    : "-"
                    );

                    tvAppOpenTtfbTime.setText(
                            "T0: " + formatAppOpenWallClock(
                                    stats.appOpenTtfbT0WallTime
                            )
                                    + "\nT1: " + formatAppOpenWallClock(
                                    stats.appOpenTtfbT1WallTime
                            )
                    );

                    // =====================================================
                    // APP OPEN TIME
                    // Separate from APP OPEN TTFB
                    // =====================================================

                    if (stats.appOpenTimeMs >= 0) {

                        tvAppOpenTime.setText(
                                stats.appOpenTimeMs + " ms"
                        );

                    } else {

                        tvAppOpenTime.setText(
                                "-"
                        );
                    }

                    tvAppOpenTimeDetails.setText(
                            "T0: " + formatAppOpenWallClock(
                                    stats.appOpenT0WallTime
                            )
                                    + "\nT1: " + formatAppOpenWallClock(
                                    stats.appOpenT1WallTime
                            )
                    );

                    tvPerformanceSourceIp.setText(
                            stats.lastSourceIp != null
                                    ? stats.lastSourceIp
                                    : "-"
                    );

                    tvPerformanceDestinationIp.setText(
                            stats.appOpenDnsDestinationIp != null
                                    && !stats.appOpenDnsDestinationIp.isEmpty()
                                    && !stats.appOpenDnsDestinationIp.equals("-")
                                    ? stats.appOpenDnsDestinationIp
                                    : "-"
                    );

                    tvPerformanceDnsLookup.setText(
                            stats.appOpenDnsLookupMs >= 0
                                    ? String.format(
                                    Locale.US,
                                    "%.3f ms",
                                    stats.appOpenDnsLookupMs
                            )
                                    : "-"
                    );

                    tvAppOpenDnsTime.setText(
                            "T0: " + formatAppOpenWallClock(
                                    stats.appOpenDnsLookupT0WallTime
                            )
                                    + "\nT1: " + formatAppOpenWallClock(
                                    stats.appOpenDnsLookupT1WallTime
                            )
                    );

                    tvPerformanceDnsServerIp.setText(
                            stats.appOpenDnsServerIp != null
                                    && !stats.appOpenDnsServerIp.isEmpty()
                                    && !stats.appOpenDnsServerIp.equals("-")
                                    ? "DNS Server: " + stats.appOpenDnsServerIp
                                    : "DNS Server: -"
                    );

// =====================================================
// TCP HANDSHAKE
// Same display logic as Web Test
// =====================================================

                    // =====================================================
// APP OPEN TCP HANDSHAKE
// =====================================================

                    if (stats.appOpenTcpHandshakeNano >= 0) {

                        double handshakeMs =
                                stats.appOpenTcpHandshakeNano / 1_000_000.0;

                        tvAppOpenTcpHandshake.setText(
                                String.format(
                                        Locale.US,
                                        "%.2f ms",
                                        handshakeMs
                                )
                        );

                    } else {

                        tvAppOpenTcpHandshake.setText("-");
                    }

                    tvAppOpenTcpHandshakeTime.setText(
                            "T0: "
                                    + formatAppOpenWallClock(
                                    stats.appOpenTcpHandshakeT0WallTime
                            )
                                    + "\nSYN-ACK: "
                                    + formatAppOpenWallClock(
                                    stats.appOpenTcpHandshakeSynAckWallTime
                            )
                                    + "\nT1: "
                                    + formatAppOpenWallClock(
                                    stats.appOpenTcpHandshakeT1WallTime
                            )
                    );


// =====================================================
// APP OPEN TLS HANDSHAKE
// =====================================================

                    if (stats.appOpenTlsHandshakeMs >= 0) {

                        tvAppOpenTlsHandshake.setText(
                                String.format(
                                        Locale.US,
                                        "%.3f ms",
                                        stats.appOpenTlsHandshakeMs
                                )
                        );

                    } else {

                        tvAppOpenTlsHandshake.setText("-");
                    }

                    tvAppOpenTlsHandshakeTime.setText(
                            "T0: " + formatAppOpenWallClock(
                                    stats.appOpenTlsHandshakeT0WallTime
                            )
                                    + "\nT1: " + formatAppOpenWallClock(
                                    stats.appOpenTlsHandshakeT1WallTime
                            )
                    );


// =====================================================
// APP OPEN TCP RETRANSMISSION COUNT
// =====================================================

                    tvAppOpenTcpRetransmissionCount.setText(
                            String.valueOf(
                                    stats.tcpRetransmissionCount
                            )
                    );


// =====================================================
// APP OPEN QUIC HANDSHAKE
// =====================================================

                    if (stats.quicHandshakeMs >= 0) {

                        tvAppOpenQuicHandshake.setText(
                                String.format(
                                        Locale.US,
                                        "%.3f ms",
                                        stats.quicHandshakeMs
                                )
                        );

                    } else {

                        tvAppOpenQuicHandshake.setText("-");
                    }
                });

        // Initial UI state.
        updateTestButtons();
    }

    private String formatAppOpenWallClock(
            long timestamp
    ) {
        if (timestamp <= 0L) {
            return "-";
        }

        return new java.text.SimpleDateFormat(
                "HH:mm:ss.SSS",
                Locale.US
        ).format(
                new java.util.Date(timestamp)
        );
    }

    private void bindDashboardViews() {

        tvVpnStatus =
                findViewById(R.id.tvVpnStatus);

        tvPermissionStatus =
                findViewById(R.id.tvPermissionStatus);

        tvInterfaceStatus =
                findViewById(R.id.tvInterfaceStatus);

        tvReaderStatus =
                findViewById(R.id.tvReaderStatus);

        tvTotalPackets =
                findViewById(R.id.tvTotalPackets);

        tvTcpCount =
                findViewById(R.id.tvTcpCount);

        tvUdpCount =
                findViewById(R.id.tvUdpCount);

        tvIpv6Skipped =
                findViewById(R.id.tvIpv6Skipped);

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

        tvLastTtfb =
                findViewById(R.id.tvLastTtfb);

// Performance views
        // Performance views
        tvPerformanceTtfb =
                findViewById(R.id.tvPerformanceTtfb);

        tvPerformanceDnsLookup =
                findViewById(R.id.tvPerformanceDnsLookup);

        tvPerformanceDnsServerIp =
                findViewById(R.id.tvPerformanceDnsServerIp);

        tvPerformanceSourceIp =
                findViewById(R.id.tvPerformanceSourceIp);

        tvPerformanceDestinationIp =
                findViewById(R.id.tvPerformanceDestinationIp);

        tvAppOpenTtfbTime =
                findViewById(R.id.tvAppOpenTtfbTime);

        tvAppOpenDnsTime =
                findViewById(R.id.tvAppOpenDnsTime);

// APP OPEN TIME
        tvAppOpenTime =
                findViewById(R.id.tvAppOpenTime);

        tvAppOpenTimeDetails =
                findViewById(R.id.tvAppOpenTimeDetails);

// APP OPEN TCP HANDSHAKE
        tvAppOpenTcpHandshake =
                findViewById(
                        R.id.tvAppOpenTcpHandshake
                );

        tvAppOpenTcpHandshakeTime =
                findViewById(
                        R.id.tvAppOpenTcpHandshakeTime
                );

// APP OPEN TLS HANDSHAKE
        tvAppOpenTlsHandshake =
                findViewById(
                        R.id.tvAppOpenTlsHandshake
                );

        tvAppOpenTlsHandshakeTime =
                findViewById(
                        R.id.tvAppOpenTlsHandshakeTime
                );

// APP OPEN TCP RETRANSMISSIONS
        tvAppOpenTcpRetransmissionCount =
                findViewById(
                        R.id.tvAppOpenTcpRetransmissionCount
                );

// APP OPEN QUIC HANDSHAKE
        tvAppOpenQuicHandshake =
                findViewById(
                        R.id.tvAppOpenQuicHandshake
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

        rvEventConsole.setHasFixedSize(
                true
        );
    }

    /**
     * Populates the app-selection dropdown.
     */
    private void setupAppSelectionSpinner(
            Bundle savedInstanceState) {

        loadInstalledApps();

        ArrayAdapter<AppInfo> spinnerAdapter =
                new ArrayAdapter<AppInfo>(
                        this,
                        android.R.layout.simple_spinner_item,
                        installedApps
                ) {

                    @Override
                    public View getView(
                            int position,
                            View convertView,
                            ViewGroup parent
                    ) {
                        View view = super.getView(
                                position,
                                convertView,
                                parent
                        );

                        TextView textView = (TextView) view;

                        textView.setTextColor(
                                ContextCompat.getColor(
                                        parent.getContext(),
                                        R.color.on_surface_primary
                                )
                        );

                        textView.setTextSize(16);
                        textView.setGravity(Gravity.CENTER_VERTICAL);

                        int horizontalPadding =
                                (int) (12 * parent.getResources()
                                        .getDisplayMetrics().density);

                        textView.setPadding(
                                horizontalPadding,
                                0,
                                horizontalPadding,
                                0
                        );

                        textView.setMinHeight(
                                (int) (48 * parent.getResources()
                                        .getDisplayMetrics().density)
                        );

                        return view;
                    }

                    @Override
                    public View getDropDownView(
                            int position,
                            View convertView,
                            ViewGroup parent
                    ) {
                        View view = super.getDropDownView(
                                position,
                                convertView,
                                parent
                        );

                        TextView textView = (TextView) view;

                        // Make each app row easier to see and tap
                        textView.setTextColor(
                                ContextCompat.getColor(
                                        parent.getContext(),
                                        R.color.on_surface_primary
                                )
                        );

                        textView.setTextSize(16);
                        textView.setGravity(Gravity.CENTER_VERTICAL);

                        int horizontalPadding =
                                (int) (12 * parent.getResources()
                                        .getDisplayMetrics().density);

                        textView.setPadding(
                                horizontalPadding,
                                0,
                                horizontalPadding,
                                0
                        );

                        textView.setMinHeight(
                                (int) (52 * parent.getResources()
                                        .getDisplayMetrics().density)
                        );

                        textView.setBackgroundColor(
                                ContextCompat.getColor(
                                        parent.getContext(),
                                        R.color.surface_elevated
                                )
                        );

                        return view;
                    }
                };

        spinnerAppSelect.setAdapter(
                spinnerAdapter
        );

        spinnerAppSelect.setOnItemSelectedListener(
                new AdapterView.OnItemSelectedListener() {

                    @Override
                    public void onItemSelected(
                            AdapterView<?> parent,
                            View view,
                            int position,
                            long id) {

                        if (position >= 0 &&
                                position < installedApps.size()) {

                            selectedPackageName =
                                    installedApps
                                            .get(position)
                                            .packageName;

                            Log.d(
                                    TAG,
                                    "Selected application for VPN routing = "
                                            + selectedPackageName
                            );
                        }
                    }

                    @Override
                    public void onNothingSelected(
                            AdapterView<?> parent) {

                        selectedPackageName =
                                null;
                    }
                }
        );

        String restoredPackage =
                savedInstanceState != null
                        ? savedInstanceState.getString(
                        STATE_SELECTED_PACKAGE
                )
                        : null;

        int restoredIndex =
                restoredPackage != null
                        ? indexOfPackage(
                        restoredPackage
                )
                        : -1;

        if (restoredIndex >= 0) {

            spinnerAppSelect.setSelection(
                    restoredIndex
            );

            selectedPackageName =
                    restoredPackage;

        } else if (!installedApps.isEmpty()) {

            spinnerAppSelect.setSelection(0);

            selectedPackageName =
                    installedApps
                            .get(0)
                            .packageName;

        } else {

            selectedPackageName =
                    null;
        }
    }

    /**
     * Fixed list of supported applications.
     */
    private void loadInstalledApps() {

        installedApps.clear();

        installedApps.add(
                new AppInfo(
                        "Instagram",
                        "com.instagram.android"
                )
        );

        installedApps.add(
                new AppInfo(
                        "YouTube",
                        "com.google.android.youtube"
                )
        );

        installedApps.add(
                new AppInfo(
                        "Facebook",
                        "com.facebook.katana"
                )
        );

        installedApps.add(
                new AppInfo(
                        "Chrome",
                        "com.android.chrome"
                )
        );

        installedApps.add(
                new AppInfo(
                        "WhatsApp",
                        "com.whatsapp"
                )
        );

        installedApps.add(
                new AppInfo(
                        "Netflix",
                        "com.netflix.mediaclient"
                )
        );

        installedApps.add(
                new AppInfo(
                        "Spotify",
                        "com.spotify.music"
                )
        );
    }

    private int indexOfPackage(
            String packageName) {

        if (packageName == null) {
            return -1;
        }

        for (int i = 0;
             i < installedApps.size();
             i++) {

            if (installedApps
                    .get(i)
                    .packageName
                    .equals(packageName)) {

                return i;
            }
        }

        return -1;
    }

    private void onNewEvent(
            VpnEvent event) {

        eventAdapter.addEvent(event);

        rvEventConsole.scrollToPosition(
                eventAdapter.getLastIndex()
        );
    }

    private void onStartVpnClicked() {

        if (selectedPackageName == null ||
                selectedPackageName.isEmpty()) {

            Toast.makeText(
                    this,
                    "Please select an application to route through the VPN.",
                    Toast.LENGTH_SHORT
            ).show();

            return;
        }

        Intent launchIntent =
                getPackageManager()
                        .getLaunchIntentForPackage(
                                selectedPackageName
                        );

        if (launchIntent == null) {

            String message =
                    describeUnlaunchableApp(
                            selectedPackageName
                    );

            Toast.makeText(
                    this,
                    message,
                    Toast.LENGTH_SHORT
            ).show();

            updateStatus(message);

            return;
        }

        /*
         * Acquire App Open session BEFORE asking
         * for VPN permission.
         */
        if (!TestSessionManager.startTest(
                TestSessionManager.TestType.APP_OPEN)) {

            Toast.makeText(
                    this,
                    "Another test is already running.",
                    Toast.LENGTH_SHORT
            ).show();

            updateTestButtons();

            return;
        }


// =====================================================
// RESET APP OPEN PERFORMANCE METRICS
// Same repository reset pattern as Web Test
// =====================================================

        dashboardRepo.resetAppOpenTtfb();

        dashboardRepo.resetAppOpenTime();

        dashboardRepo.resetAppOpenTlsHandshake();

        dashboardRepo.resetAppOpenTcpHandshake();

        dashboardRepo.resetTcpConnectionTime();

        dashboardRepo.resetTcpRetransmissionCount();

        dashboardRepo.resetQuicHandshake();


// Reset visible performance values immediately.

        if (tvPerformanceTtfb != null) {
            tvPerformanceTtfb.setText("-");
        }

        if (tvPerformanceDnsLookup != null) {
            tvPerformanceDnsLookup.setText("-");
        }

        if (tvAppOpenTtfbTime != null) {
            tvAppOpenTtfbTime.setText("T0: -\nT1: -");
        }

        if (tvAppOpenTime != null) {
            tvAppOpenTime.setText("-");
        }

        if (tvAppOpenTimeDetails != null) {
            tvAppOpenTimeDetails.setText(
                    "T0: -\nT1: -"
            );
        }

        if (tvAppOpenDnsTime != null) {
            tvAppOpenDnsTime.setText("T0: -\nT1: -");
        }

        if (tvPerformanceDnsServerIp != null) {
            tvPerformanceDnsServerIp.setText("Server: -");
        }

        if (tvPerformanceSourceIp != null) {
            tvPerformanceSourceIp.setText("-");
        }

        if (tvPerformanceDestinationIp != null) {
            tvPerformanceDestinationIp.setText("-");
        }

        if (tvAppOpenTcpHandshake != null) {
            tvAppOpenTcpHandshake.setText("-");
        }

        if (tvAppOpenTcpHandshakeTime != null) {
            tvAppOpenTcpHandshakeTime.setText("T0: -\nT1: -");
        }

        if (tvAppOpenTlsHandshake != null) {
            tvAppOpenTlsHandshake.setText("-");
        }

        if (tvAppOpenTlsHandshakeTime != null) {
            tvAppOpenTlsHandshakeTime.setText("T0: -\nT1: -");
        }

        if (tvAppOpenTcpRetransmissionCount != null) {
            tvAppOpenTcpRetransmissionCount.setText("0");
        }

        if (tvAppOpenQuicHandshake != null) {
            tvAppOpenQuicHandshake.setText("-");
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

            startVpnServiceForSelectedApp();
        }
    }

    private void startVpnServiceForSelectedApp() {

        if (selectedPackageName == null ||
                selectedPackageName.isEmpty()) {

            Toast.makeText(
                    this,
                    "Please select an application to route through the VPN.",
                    Toast.LENGTH_SHORT
            ).show();

            btnStartVpn.setEnabled(true);
            btnStopVpn.setEnabled(false);

            TestSessionManager.stopTest();

            updateTestButtons();

            return;
        }

        updateStatus(
                "Starting AppOpenMediatorVpnService..."
        );

        Intent serviceIntent =
                new Intent(
                        this,
                        AppOpenMediatorVpnService.class
                );

        serviceIntent.putExtra(
                AppOpenMediatorVpnService.EXTRA_SELECTED_PACKAGE,
                selectedPackageName
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

        pendingAppLaunch =
                true;

        updateStatus(
                "VPN service starting. Waiting for VPN establishment before launching "
                        + selectedPackageName
                        + " ..."
        );

        btnStartVpn.setEnabled(false);
        btnStopVpn.setEnabled(true);

        updateTestButtons();
    }

    /**
     * Launches selected Android application only
     * after VPN interface has established.
     */
    private void launchSelectedApp() {

        if (selectedPackageName == null ||
                selectedPackageName.isEmpty()) {

            updateStatus(
                    "No application selected; cannot launch."
            );

            return;
        }

        Intent launchIntent =
                getPackageManager()
                        .getLaunchIntentForPackage(
                                selectedPackageName
                        );

        if (launchIntent == null) {

            String message =
                    describeUnlaunchableApp(
                            selectedPackageName
                    );

            updateStatus(message);

            Toast.makeText(
                    this,
                    message,
                    Toast.LENGTH_SHORT
            ).show();

            dashboardRepo.logEvent(
                    TAG + message,
                    VpnEvent.Level.ERROR,
                    VpnEvent.Category.ERROR
            );

            return;
        }

        launchIntent.addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK
        );

        updateStatus(
                "VPN established. Launching "
                        + selectedPackageName
                        + " ..."
        );

        dashboardRepo.logEvent(
                TAG
                        + "VPN established; launching selected application: "
                        + selectedPackageName,
                VpnEvent.Level.SUCCESS,
                VpnEvent.Category.GENERAL
        );

        /*
         * =========================================================
         * APP OPEN T0
         * =========================================================
         *
         * T0 = immediately before startActivity().
         *
         * elapsedRealtimeNano is used for accurate duration calculation.
         * currentTimeMillis is used only for readable wall-clock logging.
         */
        long appOpenT0Nano =
                android.os.SystemClock.elapsedRealtimeNanos();

        long appOpenT0WallTime =
                System.currentTimeMillis();

        String appOpenT0Timestamp =
                new java.text.SimpleDateFormat(
                        "HH:mm:ss:SSS",
                        Locale.US
                ).format(
                        new java.util.Date(appOpenT0WallTime)
                );

        String appOpenT0Log =
                "========== APP OPEN ==========\n"
                        + "T0 Event          : START_ACTIVITY\n"
                        + "Package           : "
                        + selectedPackageName
                        + "\n"
                        + "T0 Nano            : "
                        + appOpenT0Nano
                        + " ns\n"
                        + "T0 Timestamp      : "
                        + appOpenT0Timestamp
                        + "\n";

        dashboardRepo.logEvent(
                TAG + appOpenT0Log,
                VpnEvent.Level.INFO,
                VpnEvent.Category.GENERAL
        );

        VpnLogFileManager
                .getInstance()
                .log(
                        appOpenT0Log
                );

        if (appOpenMediatorVpnService != null) {

            appOpenMediatorVpnService
                    .startAppOpenT1Monitoring(
                            selectedPackageName,
                            appOpenT0Nano,
                            appOpenT0WallTime
                    );
        }

        startActivity(
                launchIntent
        );
    }

    private String describeUnlaunchableApp(
            String packageName) {

        if (isPackageVisible(packageName)) {

            return "Selected application is installed but exposes no launchable activity: "
                    + packageName;
        }

        return "Selected application is not installed or not visible to this app: "
                + packageName;
    }

    private boolean isPackageVisible(
            String packageName) {

        try {

            getPackageManager()
                    .getPackageInfo(
                            packageName,
                            0
                    );

            return true;

        } catch (
                PackageManager.NameNotFoundException e) {

            return false;
        }
    }

    private void onStopVpnClicked() {

        // =====================================================
        // SHOW DESTINATION IP BEFORE STOPPING VPN
        // =====================================================

        VpnStats currentStats =
                dashboardRepo.getStats().getValue();

        if (currentStats != null
                && currentStats.appOpenDnsDestinationIp != null
                && !currentStats.appOpenDnsDestinationIp.isEmpty()
                && !currentStats.appOpenDnsDestinationIp.equals("-")) {

            tvPerformanceDestinationIp.setText(
                    currentStats.appOpenDnsDestinationIp
            );

            dashboardRepo.logToFile(
                    TAG
                            + "DESTINATION IP SHOWN ON STOP = "
                            + currentStats.appOpenDnsDestinationIp
            );

        } else {

            tvPerformanceDestinationIp.setText("-");

            dashboardRepo.logToFile(
                    TAG
                            + "DESTINATION IP SHOWN ON STOP = -"
            );
        }
        updateStatus(
                "Stopping VPN..."
        );

        dashboardRepo.logEvent(
                TAG + "Stopping VPN (user requested)",
                VpnEvent.Level.INFO,
                VpnEvent.Category.GENERAL
        );

        pendingAppLaunch =
                false;

        if (isServiceBound &&
                appOpenMediatorVpnService != null) {

            appOpenMediatorVpnService
                    .clearVpnReadyCallback();
            appOpenMediatorVpnService
                    .resolveServerHostnamesOnStop();

            appOpenMediatorVpnService.stopVpn();

            unbindService(
                    connection
            );

            isServiceBound =
                    false;

            appOpenMediatorVpnService =
                    null;
        }

        Intent serviceIntent =
                new Intent(
                        this,
                        AppOpenMediatorVpnService.class
                );

        stopService(
                serviceIntent
        );

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
// IMPORTANT:
// Do NOT change button state here.
// UI must remain in STOPPING/SHARE state
// until user selects Yes or No.
        showShareLogDialog(
                logFile
        );
    }

    /**
     * Dedicated stop method for Back button.
     *
     * IMPORTANT:
     * Does NOT show Share Log dialog.
     */
    private void stopAppOpenTestForBack() {

        pendingAppLaunch =
                false;

        if (isServiceBound &&
                appOpenMediatorVpnService != null) {

            appOpenMediatorVpnService
                    .clearVpnReadyCallback();

            appOpenMediatorVpnService.stopVpn();

            unbindService(
                    connection
            );

            isServiceBound =
                    false;

            appOpenMediatorVpnService =
                    null;
        }

        Intent serviceIntent =
                new Intent(
                        this,
                        AppOpenMediatorVpnService.class
                );

        stopService(
                serviceIntent
        );

        TestSessionManager.stopTest();

        btnStartVpn.setEnabled(true);
        btnStartVpn.setAlpha(1.0f);

        btnStopVpn.setEnabled(false);
        btnStopVpn.setAlpha(0.45f);

        spinnerAppSelect.setEnabled(true);
        spinnerAppSelect.setAlpha(1.0f);

        updateTestButtons();
    }

    private void updateStatus(
            String message) {

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
     * Controls App Open UI according to shared
     * test session.
     */
    /**
     * Controls App Open UI according to shared
     * test session.
     *
     * Disabled buttons are visually grey so the
     * user can clearly understand the current state.
     */
    private void updateTestButtons() {

        TestSessionManager.TestType active =
                TestSessionManager.getActiveTest();

        boolean vpnRunning =
                active == TestSessionManager.TestType.APP_OPEN;

        boolean vpnStopped =
                active == TestSessionManager.TestType.NONE;


        // =====================================================
        // START VPN BUTTON
        // =====================================================

        if (btnStartVpn != null) {

            btnStartVpn.setEnabled(
                    vpnStopped
            );

            // Grey when disabled
            if (vpnRunning) {
                btnStartVpn.setAlpha(0.45f);
            } else {
                btnStartVpn.setAlpha(1.0f);
            }
        }


        // =====================================================
        // STOP VPN BUTTON
        // =====================================================

        if (btnStopVpn != null) {

            btnStopVpn.setEnabled(
                    vpnRunning
            );

            // Grey when disabled
            if (vpnStopped) {
                btnStopVpn.setAlpha(0.45f);
            } else {
                btnStopVpn.setAlpha(1.0f);
            }
        }


        // =====================================================
        // APPLICATION SELECTOR
        // =====================================================

        if (spinnerAppSelect != null) {

            spinnerAppSelect.setEnabled(
                    vpnStopped
            );

            // Grey while VPN is running
            if (vpnRunning) {
                spinnerAppSelect.setAlpha(0.45f);
            } else {
                spinnerAppSelect.setAlpha(1.0f);
            }
        }
    }

    /**
     * Puts App Open Test UI into READY state.
     *
     * This method must be called only after the user
     * has completed the Share Log decision.
     */
    private void setVpnStoppedUi() {

        // =====================================================
        // START VPN
        // =====================================================

        btnStartVpn.setEnabled(true);
        btnStartVpn.setAlpha(1.0f);


        // =====================================================
        // STOP VPN
        // =====================================================

        btnStopVpn.setEnabled(false);
        btnStopVpn.setAlpha(0.45f);


        // =====================================================
        // APPLICATION SELECTOR
        // =====================================================

        spinnerAppSelect.setEnabled(true);
        spinnerAppSelect.setAlpha(1.0f);


        // =====================================================
        // RELEASE SHARED TEST SESSION
        // =====================================================

        TestSessionManager.stopTest();


        Toast.makeText(
                this,
                "VPN test stopped. Ready for next test.",
                Toast.LENGTH_SHORT
        ).show();
    }
    private void showShareLogDialog(
            File logFile) {

        // =====================================================
        // NO LOG FILE
        // =====================================================

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


        // =====================================================
        // SHARE LOG DIALOG
        // =====================================================

        new AlertDialog.Builder(this)
                .setTitle("Share Log")
                .setMessage(
                        "Do you want to share the VPN log file?"
                )
                .setCancelable(false)


                // =================================================
                // YES
                // =================================================

                .setPositiveButton(
                        "Yes",
                        (dialog, which) -> {

                            shareLogFile(
                                    logFile
                            );

                            // User has made the decision.
                            // Now App Open UI becomes READY.
                            setVpnStoppedUi();
                        }
                )


                // =================================================
                // NO
                // =================================================

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

                            // User has made the decision.
                            // Now App Open UI becomes READY.
                            setVpnStoppedUi();
                        }
                )

                .show();
    }

    private void shareLogFile(
            File file) {

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

        // Important:
        // If Web Test is running, App Open Start
        // must remain disabled.
        updateTestButtons();
    }

    @Override
    protected void onSaveInstanceState(
            Bundle outState) {

        super.onSaveInstanceState(
                outState
        );

        outState.putString(
                STATE_SELECTED_PACKAGE,
                selectedPackageName
        );
    }

    /**
     * Simple holder used by app-selection dropdown.
     */
    private static class AppInfo {

        final String label;
        final String packageName;

        AppInfo(
                String label,
                String packageName) {

            this.label = label;
            this.packageName = packageName;
        }

        @Override
        public String toString() {
            return label;
        }
    }
}
