package com.example.vpntest.appOpen;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebChromeClient;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.FileProvider;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.vpntest.R;
import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.repo.VpnEventRepository;
import com.example.vpntest.ui.VpnDashboardViewModel;
import com.example.vpntest.ui.VpnEventAdapter;
import com.example.vpntest.utils.TestSessionManager;
import com.example.vpntest.utils.VpnLogFileManager;

import java.io.File;

public class AppOpenYoutubeTestActivity extends AppCompatActivity {

    private static final String TAG = "YoutubeTestActivity : ";

    private static final String YOUTUBE_VIDEO_ID = "6CUk9C4q81k";
    private TextView tvStatus;
    private Button btnStart;
    private Button btnStop;
    private WebView webView;

    // Dashboard views (same shared VpnDashboardViewModel as App Open screen)
    private TextView tvVpnStatus, tvPermissionStatus, tvInterfaceStatus, tvReaderStatus;
    private TextView tvTotalPackets, tvTcpCount, tvUdpCount, tvIpv6Skipped;
    private TextView tvLastProtocol, tvLastSource, tvLastDest, tvLastSize, tvLastTimestamp;
    private TextView tvLastTtfb;

    private RecyclerView rvEventConsole;
    private VpnEventAdapter eventAdapter;
    private VpnDashboardViewModel viewModel;

    private final VpnEventRepository dashboardRepo =
            VpnEventRepository.getInstance();

    private AppOpenMediatorVpnService mediatorService;
    private boolean isServiceBound = false;
    private volatile boolean youtubeTestRunning = false;
    private boolean deleteLogAfterShare = false;

    private final ServiceConnection connection = new ServiceConnection() {

        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {

            mediatorService =
                    ((AppOpenMediatorVpnService.LocalBinder) service).getService();

            isServiceBound = true;

            mediatorService.setVpnReadyCallback(() ->
                    runOnUiThread(() -> {

                        mediatorService.startYoutubeTest();

                        loadYoutubeVideo();
                    })
            );
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {

            mediatorService = null;
            isServiceBound = false;
        }
    };

    private final ActivityResultLauncher<Intent> vpnPermissionLauncher =
            registerForActivityResult(
                    new ActivityResultContracts.StartActivityForResult(),
                    result -> {

                        if (result.getResultCode() == RESULT_OK) {

                            dashboardRepo.setPermissionStatus("Granted");

                            dashboardRepo.logEvent(
                                    TAG + "VPN permission granted",
                                    VpnEvent.Level.SUCCESS,
                                    VpnEvent.Category.GENERAL
                            );

                            startYoutubeVpnService();

                        } else {

                            dashboardRepo.setPermissionStatus("Denied");

                            dashboardRepo.logEvent(
                                    TAG + "VPN permission denied",
                                    VpnEvent.Level.ERROR,
                                    VpnEvent.Category.ERROR
                            );

                            Toast.makeText(
                                    this,
                                    "VPN permission was denied.",
                                    Toast.LENGTH_SHORT
                            ).show();

                            TestSessionManager.stopTest();

                            youtubeTestRunning = false;

                            updateButtons();
                        }
                    }
            );

    @Override
    public void onBackPressed() {

        if (youtubeTestRunning) {

            new AlertDialog.Builder(this)
                    .setMessage("Please stop the test first, then go back.")
                    .setPositiveButton("OK", null)
                    .setCancelable(false)
                    .show();

            return;
        }

        super.onBackPressed();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_app_open_youtube_test);

        tvStatus = findViewById(R.id.tvStatus);
        btnStart = findViewById(R.id.btnYoutubeStart);
        btnStop = findViewById(R.id.btnYoutubeStop);
        webView = findViewById(R.id.webViewYoutube);

        bindDashboardViews();

        setupEventConsole();

        setupWebView();

        btnStart.setOnClickListener(v -> onStartClicked());

        btnStop.setOnClickListener(v -> onStopClicked());

        viewModel =
                new ViewModelProvider(this)
                        .get(VpnDashboardViewModel.class);

        viewModel.getLatestEvent().observe(this, this::onNewEvent);

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

            tvLastProtocol.setText(stats.lastProtocol);

            tvLastSource.setText(stats.lastSourceIp);

            tvLastDest.setText(stats.lastDestIp);

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
        });

        updateButtons();
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

        tvLastTtfb = findViewById(R.id.tvLastTtfb);
    }

    private void setupEventConsole() {

        rvEventConsole = findViewById(R.id.rvEventConsole);

        eventAdapter = new VpnEventAdapter();

        rvEventConsole.setLayoutManager(
                new LinearLayoutManager(this)
        );

        rvEventConsole.setAdapter(eventAdapter);

        rvEventConsole.setHasFixedSize(true);
    }

    private void setupWebView() {

        WebSettings settings = webView.getSettings();

        settings.setJavaScriptEnabled(true);

        settings.setDomStorageEnabled(true);

        settings.setMediaPlaybackRequiresUserGesture(false);

        settings.setLoadWithOverviewMode(true);

        settings.setUseWideViewPort(true);

        webView.setWebViewClient(new WebViewClient() {

            @Override
            public boolean shouldOverrideUrlLoading(
                    WebView view,
                    String url
            ) {

                if (url != null &&
                        (url.startsWith("http://") ||
                                url.startsWith("https://"))) {

                    view.loadUrl(url);
                }

                return true;
            }
        });

        webView.setWebChromeClient(new WebChromeClient());
    }

    private void onNewEvent(VpnEvent event) {

        eventAdapter.addEvent(event);

        rvEventConsole.scrollToPosition(
                eventAdapter.getLastIndex()
        );
    }

    private void onStartClicked() {

        if (!TestSessionManager.startTest(
                TestSessionManager.TestType.YOUTUBE
        )) {

            Toast.makeText(
                    this,
                    "Another test is already running.",
                    Toast.LENGTH_SHORT
            ).show();

            return;
        }

        youtubeTestRunning = true;

        updateButtons();

        updateStatus("Requesting VPN permission...");

        dashboardRepo.setPermissionStatus("Requesting");

        dashboardRepo.logEvent(
                TAG + "Requesting VPN permission",
                VpnEvent.Level.INFO,
                VpnEvent.Category.GENERAL
        );

        dashboardRepo.logEvent(
                TAG + "========== YOUTUBE TEST START ==========\n"
                        + "YouTube Video ID : " + YOUTUBE_VIDEO_ID + "\n"
                        + "Timestamp        : "
                        + System.currentTimeMillis()
                        + "\n"
                        + "========================================",
                VpnEvent.Level.INFO,
                VpnEvent.Category.GENERAL
        );

        Intent prepareIntent = VpnService.prepare(this);

        if (prepareIntent != null) {

            vpnPermissionLauncher.launch(prepareIntent);

        } else {

            dashboardRepo.setPermissionStatus("Granted");

            startYoutubeVpnService();
        }
    }

    private void startYoutubeVpnService() {

        updateStatus(
                "Starting AppOpenMediatorVpnService for YouTube Test..."
        );

        Intent serviceIntent =
                new Intent(
                        this,
                        AppOpenMediatorVpnService.class
                );

        /*
         * WebView traffic originates from THIS app's process,
         * so the VPN must allow this app's own package through
         * the tunnel.
         */
        serviceIntent.putExtra(
                AppOpenMediatorVpnService.EXTRA_SELECTED_PACKAGE,
                getPackageName()
        );

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

            startForegroundService(serviceIntent);

        } else {

            startService(serviceIntent);
        }

        bindService(
                serviceIntent,
                connection,
                Context.BIND_AUTO_CREATE
        );
    }

    private void loadYoutubeVideo() {

        runOnUiThread(() -> {

            updateStatus(
                    "VPN established. Loading YouTube video..."
            );

            String html =
                    "<!DOCTYPE html>" +
                            "<html>" +

                            "<head>" +

                            "<meta name='viewport' " +
                            "content='width=device-width, initial-scale=1.0'>" +

                            "<style>" +

                            "html, body {" +
                            "margin:0;" +
                            "padding:0;" +
                            "width:100%;" +
                            "height:100%;" +
                            "background:#000;" +
                            "overflow:hidden;" +
                            "}" +

                            "iframe {" +
                            "width:100%;" +
                            "height:100%;" +
                            "border:0;" +
                            "display:block;" +
                            "}" +

                            "</style>" +

                            "</head>" +

                            "<body>" +

                            "<iframe " +

                            "width='100%' " +
                            "height='100%' " +

                            "src='https://www.youtube.com/embed/"
                            + YOUTUBE_VIDEO_ID
                            + "?autoplay=1"
                            + "&playsinline=1"
                            + "&loop=1"
                            + "&playlist=" + YOUTUBE_VIDEO_ID
                            + "' "+

                            "title='YouTube video player' " +

                            "frameborder='0' " +

                            "allow='accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share' " +

                            "allowfullscreen>" +

                            "</iframe>" +

                            "</body>" +

                            "</html>";

            webView.loadDataWithBaseURL(
                    "https://app.vpntest.local/",
                    html,
                    "text/html",
                    "UTF-8",
                    null
            );
        });
    }

    private void onStopClicked() {

        updateStatus("Stopping YouTube Test...");

        dashboardRepo.logEvent(
                TAG + "Stopping YouTube Test (user requested)",
                VpnEvent.Level.INFO,
                VpnEvent.Category.GENERAL
        );

        youtubeTestRunning = false;

        if (isServiceBound && mediatorService != null) {

            mediatorService.stopYoutubeTestLogging();

            mediatorService.clearVpnReadyCallback();

            mediatorService.stopVpn();

            unbindService(connection);

            isServiceBound = false;

            mediatorService = null;
        }

        stopService(
                new Intent(
                        this,
                        AppOpenMediatorVpnService.class
                )
        );

        dashboardRepo.setVpnStatus("Stopped");

        dashboardRepo.setInterfaceStatus("Closed");

        dashboardRepo.setReaderStatus("Stopped");

        dashboardRepo.logEvent(
                TAG + "VPN stopped by user",
                VpnEvent.Level.INFO,
                VpnEvent.Category.GENERAL
        );

        updateStatus("VPN stopped.");

        cleanupWebView();

        TestSessionManager.stopTest();

        updateButtons();

        VpnLogFileManager.getInstance().endSession();

        File logFile =
                VpnLogFileManager.getInstance().getCurrentLogFile();

        showShareLogDialog(logFile);
    }

    private void cleanupWebView() {
        if (webView == null) {
            return;
        }

        webView.stopLoading();

        webView.loadUrl("about:blank");

        webView.clearHistory();

        webView.clearCache(false);

        webView.setVisibility(View.VISIBLE);
    }

    private void updateButtons() {

        btnStart.setEnabled(!youtubeTestRunning);

        btnStop.setEnabled(youtubeTestRunning);
    }

    private void updateStatus(String message) {

        Log.d(TAG, message);

        if (tvStatus != null) {

            tvStatus.setText(
                    "Status: " + message
            );
        }
    }

    // ---- reused App Open sharing/deletion pattern ----

    private void showShareLogDialog(File logFile) {

        if (logFile == null || !logFile.exists()) {

            Toast.makeText(
                    this,
                    "Log file not found.",
                    Toast.LENGTH_SHORT
            ).show();

            return;
        }

        new AlertDialog.Builder(this)

                .setTitle("Share Log")

                .setMessage(
                        "Do you want to share the log file?"
                )

                .setCancelable(false)

                .setPositiveButton(
                        "YES",
                        (d, w) -> shareLogFile(logFile)
                )

                .setNegativeButton(
                        "NO",
                        (d, w) -> {

                            VpnLogFileManager
                                    .getInstance()
                                    .deleteCurrentLogFile();

                            Toast.makeText(
                                    this,
                                    "Log file deleted.",
                                    Toast.LENGTH_SHORT
                            ).show();
                        }
                )

                .show();
    }

    private void shareLogFile(File file) {

        Uri uri =
                FileProvider.getUriForFile(
                        this,
                        getPackageName() + ".fileprovider",
                        file
                );

        Intent shareIntent =
                new Intent(Intent.ACTION_SEND);

        shareIntent.setType("text/plain");

        shareIntent.putExtra(
                Intent.EXTRA_STREAM,
                uri
        );

        shareIntent.addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION
        );

        startActivity(
                Intent.createChooser(
                        shareIntent,
                        "Share VPN Log"
                )
        );
    }

    @Override
    protected void onResume() {

        super.onResume();

        if (deleteLogAfterShare) {

            deleteLogAfterShare = false;

            VpnLogFileManager
                    .getInstance()
                    .deleteCurrentLogFile();

            Toast.makeText(
                    this,
                    "VPN log deleted.",
                    Toast.LENGTH_SHORT
            ).show();
        }

        updateButtons();
    }

    @Override
    protected void onDestroy() {

        if (youtubeTestRunning) {

            // Activity destroyed without explicit STOP.
            // Avoid leaking state.

            if (isServiceBound && mediatorService != null) {

                mediatorService.stopYoutubeTestLogging();

                unbindService(connection);

                isServiceBound = false;
            }

            TestSessionManager.stopTest();
        }

        cleanupWebView();

        super.onDestroy();
    }
}