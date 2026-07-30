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

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.repo.VpnEventRepository;
import com.example.vpntest.ui.VpnDashboardViewModel;
import com.example.vpntest.ui.VpnEventAdapter;

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

    private MediatorVpnService mediatorVpnService;
    private boolean isServiceBound = false;

    private final ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            mediatorVpnService = ((MediatorVpnService.LocalBinder) service).getService();
            isServiceBound = true;
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

        Intent serviceIntent = new Intent(this, MediatorVpnService.class);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        }
        bindService(serviceIntent, connection, Context.BIND_AUTO_CREATE);

        updateStatus("VPN service starting. Loading " + targetUrl + " ...");

        //webView.clearCache(true);
        webView.loadUrl(targetUrl);

        btnStartVpn.setEnabled(false);
        btnStopVpn.setEnabled(true);
    }

    private void onStopVpnClicked() {
        updateStatus("Stopping VPN...");
        dashboardRepo.logEvent("Stopping VPN (user requested)",
                VpnEvent.Level.INFO, VpnEvent.Category.GENERAL);

        if (isServiceBound && mediatorVpnService != null) {
            mediatorVpnService.stopVpn();   // synchronous, real teardown, happens now
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
}