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
import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.repo.VpnEventRepository;
import com.example.vpntest.ui.VpnDashboardViewModel;
import com.example.vpntest.ui.VpnEventAdapter;
import com.example.vpntest.utils.VpnLogFileManager;

public class VpnTestActivity extends AppCompatActivity {

    private static final String TAG = "VpnTestActivity";

    private TextView tvStatus;
    private WebView webView;
    private Button btnStartVpn;
    private Button btnStopVpn;

    // Dashboard views
    private TextView tvVpnStatus, tvPermissionStatus, tvInterfaceStatus, tvReaderStatus;
    private TextView tvTotalPackets, tvTcpCount, tvUdpCount, tvIpv6Skipped;
    private TextView tvLastProtocol, tvLastSource, tvLastDest, tvLastSize, tvLastTimestamp;
    private TextView tvLastTtfb;

    private MediatorVpnService mediatorVpnService;
    private boolean deleteLogAfterShare = false;
    private boolean isServiceBound = false;

    // TTFB START
    // The WebView must not start loading until the tunnel is actually
    // capturing packets — otherwise its TCP handshake happens outside
    // the tun (before per-UID VPN routing is active) and TcpForwarder
    // never sees the SYN, so TTFB can never be measured.
    private boolean pendingUrlLoad = false;
    private String pendingTargetUrl = null;
    //private static final String READER_STATUS_RUNNING = "Running";
    // TTFB END

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

                            webView.loadUrl(urlToLoad);
                        }
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
    private final VpnEventRepository dashboardRepo = VpnEventRepository.getInstance();

    private final ActivityResultLauncher<Intent> vpnPermissionLauncher =
            registerForActivityResult(
                    new ActivityResultContracts.StartActivityForResult(),
                    result -> {
                        if (result.getResultCode() == RESULT_OK) {
                            Log.d(TAG, "VPN permission granted by user.");
                            dashboardRepo.setPermissionStatus("Granted");
                            dashboardRepo.logEvent("VPN permission granted",
                                    VpnEvent.Level.SUCCESS, VpnEvent.Category.GENERAL);
                            startVpnServiceAndLoadWebView();
                        } else {
                            Log.d(TAG, "VPN permission denied by user.");
                            dashboardRepo.setPermissionStatus("Denied");
                            dashboardRepo.logEvent("VPN permission denied",
                                    VpnEvent.Level.ERROR, VpnEvent.Category.ERROR);
                            updateStatus("VPN permission denied.");
                            Toast.makeText(this,
                                    "VPN permission was denied.",
                                    Toast.LENGTH_SHORT).show();
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


        bindDashboardViews();
        setupEventConsole();

        webView.getSettings().setJavaScriptEnabled(true);
        webView.setWebViewClient(new WebViewClient());

        btnStartVpn.setOnClickListener(v -> onStartVpnClicked());
        btnStopVpn.setOnClickListener(v -> onStopVpnClicked());

        viewModel = new ViewModelProvider(this).get(VpnDashboardViewModel.class);


        viewModel.getLatestEvent().observe(this, this::onNewEvent);
        viewModel.getStats().observe(this, stats -> {
            tvVpnStatus.setText(stats.vpnStatus);
            tvPermissionStatus.setText(stats.permissionStatus);
            tvInterfaceStatus.setText(stats.interfaceStatus);
            tvReaderStatus.setText(stats.readerStatus);

            tvTotalPackets.setText(String.valueOf(stats.totalPackets));
            tvTcpCount.setText(String.valueOf(stats.tcpCount));
            tvUdpCount.setText(String.valueOf(stats.udpCount));
            tvIpv6Skipped.setText(String.valueOf(stats.ipv6SkippedCount));

            tvLastProtocol.setText(stats.lastProtocol);
            tvLastSource.setText(stats.lastSourceIp);
            tvLastDest.setText(stats.lastDestIp);
            tvLastSize.setText(stats.lastPacketSize > 0 ? stats.lastPacketSize + " bytes" : "-");
            tvLastTimestamp.setText(stats.lastPacketTimestamp > 0
                    ? android.text.format.DateFormat.format("HH:mm:ss", stats.lastPacketTimestamp)
                    : "-");
            tvLastTtfb.setText(stats.lastTtfbMs >= 0 ? stats.lastTtfbMs + " ms" : "-");


            // TTFB END
        });
    }

    private void bindDashboardViews() {
        tvVpnStatus = findViewById(R.id.tvVpnStatus);
        tvPermissionStatus = findViewById(R.id.tvPermissionStatus);
        tvInterfaceStatus = findViewById(R.id.tvInterfaceStatus);
        tvReaderStatus = findViewById(R.id.tvReaderStatus);

        tvTotalPackets = findViewById(R.id.tvTotalPackets);
        tvTcpCount = findViewById(R.id.tvTcpCount);
        tvUdpCount = findViewById(R.id.tvUdpCount);
        tvIpv6Skipped = findViewById(R.id.tvIpv6Skipped);

        tvLastProtocol = findViewById(R.id.tvLastProtocol);
        tvLastSource = findViewById(R.id.tvLastSource);
        tvLastDest = findViewById(R.id.tvLastDest);
        tvLastSize = findViewById(R.id.tvLastSize);
        tvLastTimestamp = findViewById(R.id.tvLastTimestamp);
        tvLastTtfb = findViewById(R.id.tvLastTtfb); // TTFB
    }

    private void setupEventConsole() {
        rvEventConsole = findViewById(R.id.rvEventConsole);
        eventAdapter = new VpnEventAdapter();
        rvEventConsole.setLayoutManager(new LinearLayoutManager(this));
        rvEventConsole.setAdapter(eventAdapter);
        // Fixed-size rows -> RecyclerView can skip some layout recalculation work.
        rvEventConsole.setHasFixedSize(true);
    }

    private void onNewEvent(VpnEvent event) {
        eventAdapter.addEvent(event);
        rvEventConsole.scrollToPosition(eventAdapter.getLastIndex());
    }

    private void onStartVpnClicked() {
        updateStatus("Requesting VPN permission...");
        dashboardRepo.setPermissionStatus("Requesting");
        dashboardRepo.logEvent("Requesting VPN permission",
                VpnEvent.Level.INFO, VpnEvent.Category.GENERAL);

        Intent prepareIntent = VpnService.prepare(this);

        if (prepareIntent != null) {

            vpnPermissionLauncher.launch(prepareIntent);
        } else {

            Log.d(TAG, "VPN permission already granted.");
            dashboardRepo.setPermissionStatus("Granted");
            dashboardRepo.logEvent("VPN permission already granted",
                    VpnEvent.Level.SUCCESS, VpnEvent.Category.GENERAL);
            startVpnServiceAndLoadWebView();
        }
    }


    private void startVpnServiceAndLoadWebView() {
        String targetUrl = resolveTargetUrl();

        updateStatus("Starting MediatorVpnService...");

        Intent serviceIntent =
                new Intent(this, MediatorVpnService.class);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        }

        bindService(
                serviceIntent,
                connection,
                Context.BIND_AUTO_CREATE
        );

        pendingTargetUrl = targetUrl;
        pendingUrlLoad = true;

        updateStatus(
                "VPN service starting. Waiting for VPN establishment before loading "
                        + targetUrl
                        + " ..."
        );

        btnStartVpn.setEnabled(false);
        btnStopVpn.setEnabled(true);
    }

    private void onStopVpnClicked() {
        updateStatus("Stopping VPN...");
        dashboardRepo.logEvent("Stopping VPN (user requested)",
                VpnEvent.Level.INFO, VpnEvent.Category.GENERAL);

        // TTFB START
        // Cancel any deferred load — the tunnel is going away, so there's
        // nothing left to wait for and we must not load into a torn-down session.
        pendingUrlLoad = false;
        pendingTargetUrl = null;
        // TTFB END

        if (isServiceBound && mediatorVpnService != null) {

            mediatorVpnService.clearVpnReadyCallback();

            mediatorVpnService.stopVpn();

            unbindService(connection);

            isServiceBound = false;
            mediatorVpnService = null;
        }

        Intent serviceIntent = new Intent(this, MediatorVpnService.class);
        stopService(serviceIntent);

        webView.stopLoading();
        webView.loadUrl("about:blank");

        dashboardRepo.setVpnStatus("Stopped");
        dashboardRepo.setInterfaceStatus("Closed");
        dashboardRepo.setReaderStatus("Stopped");
        dashboardRepo.logEvent("VPN stopped by user",
                VpnEvent.Level.INFO, VpnEvent.Category.GENERAL);

        updateStatus("VPN stopped.");

        VpnLogFileManager
                .getInstance()
                .endSession();

        File logFile = VpnLogFileManager
                .getInstance()
                .getCurrentLogFile();

        showShareLogDialog(logFile);

        btnStartVpn.setEnabled(true);
        btnStopVpn.setEnabled(false);
    }

    private String resolveTargetUrl() {
        String input = etTargetUrl.getText() != null
                ? etTargetUrl.getText().toString().trim()
                : "";

//        if (input.isEmpty()) {
//            input = "https://www.google.com";
//        }

        if (!input.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) {
            input = "https://" + input;
        }

        return input;
    }

    private void updateStatus(String message) {
        Log.d(TAG, message);
        if (tvStatus != null) {
            tvStatus.setText("Status: " + message);
        }
    }
    private void showShareLogDialog(File logFile) {

        if (logFile == null || !logFile.exists()) {
            Toast.makeText(this, "Log file not found.", Toast.LENGTH_SHORT).show();
            return;
        }

        new AlertDialog.Builder(this)
                .setTitle("Share Log")
                .setMessage("Do you want to share the VPN log file?")
                .setCancelable(false)
                .setPositiveButton("Yes", (dialog, which) -> {

                    // Next step
                    shareLogFile(logFile);

                })
                .setNegativeButton("No", (dialog, which) -> {

                    VpnLogFileManager.getInstance().deleteCurrentLogFile();

                    Toast.makeText(
                            this,
                            "Log file deleted.",
                            Toast.LENGTH_SHORT
                    ).show();

                })
                .show();
    }
    private void shareLogFile(File file) {

        Uri uri = FileProvider.getUriForFile(
                this,
                getPackageName() + ".fileprovider",
                file
        );

        Intent shareIntent = new Intent(Intent.ACTION_SEND);
        shareIntent.setType("text/plain");
        shareIntent.putExtra(Intent.EXTRA_STREAM, uri);
        shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

        PackageManager pm = getPackageManager();

        try {

            // Try WhatsApp Business first
            pm.getPackageInfo("com.whatsapp.w4b", 0);

            shareIntent.setPackage("com.whatsapp.w4b");
            startActivity(shareIntent);

        } catch (PackageManager.NameNotFoundException e1) {

            try {

                // Fall back to regular WhatsApp
                pm.getPackageInfo("com.whatsapp", 0);

                shareIntent.setPackage("com.whatsapp");

                deleteLogAfterShare = true;
                startActivity(shareIntent);
            } catch (PackageManager.NameNotFoundException e2) {

                // Final fallback
                startActivity(Intent.createChooser(
                        shareIntent,
                        "Share VPN Log"));

            }
        }
    }
    @Override
    protected void onResume() {
        super.onResume();

        if (deleteLogAfterShare) {

            deleteLogAfterShare = false;

            VpnLogFileManager.getInstance().deleteCurrentLogFile();

            Toast.makeText(
                    this,
                    "VPN log deleted.",
                    Toast.LENGTH_SHORT
            ).show();
        }
    }
}