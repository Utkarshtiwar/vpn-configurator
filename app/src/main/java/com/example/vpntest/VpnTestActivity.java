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
import android.view.View;
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
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import android.content.pm.PackageManager;
import android.net.Uri;
import androidx.core.content.FileProvider;
import java.util.ArrayList;
import java.util.List;
import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.repo.VpnEventRepository;
import com.example.vpntest.ui.VpnDashboardViewModel;
import com.example.vpntest.ui.VpnEventAdapter;
import com.example.vpntest.utils.VpnLogFileManager;

public class VpnTestActivity extends AppCompatActivity {

    private static final String TAG = "VpnTestActivity : ";

    private static final String STATE_SELECTED_PACKAGE = "selected_package_name";

    private TextView tvStatus;
    private Button btnStartVpn;
    private Button btnStopVpn;
    private Spinner spinnerAppSelect;

    // Dashboard views
    private TextView tvVpnStatus, tvPermissionStatus, tvInterfaceStatus, tvReaderStatus;
    private TextView tvTotalPackets, tvTcpCount, tvUdpCount, tvIpv6Skipped;
    private TextView tvLastProtocol, tvLastSource, tvLastDest, tvLastSize, tvLastTimestamp;
    private TextView tvLastTtfb;

    private MediatorVpnService mediatorVpnService;
    private boolean deleteLogAfterShare = false;
    private boolean isServiceBound = false;

    private final List<AppInfo> installedApps = new ArrayList<>();
    private String selectedPackageName = null;

    /**
     * Set right before the VPN service is started; consumed by the
     * VPN-ready callback below, which launches the selected real
     * application only after the VPN interface has actually established.
     */
    private boolean pendingAppLaunch = false;

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

                        if (pendingAppLaunch) {

                            pendingAppLaunch = false;

                            launchSelectedApp();
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
                            dashboardRepo.logEvent(TAG+"VPN permission granted",
                                    VpnEvent.Level.SUCCESS, VpnEvent.Category.GENERAL);
                            startVpnServiceForSelectedApp();
                        } else {
                            Log.d(TAG, "VPN permission denied by user.");
                            dashboardRepo.setPermissionStatus("Denied");
                            dashboardRepo.logEvent(TAG+"VPN permission denied",
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
        btnStartVpn = findViewById(R.id.btnStartVpn);
        btnStopVpn = findViewById(R.id.btnStopVpn);
        spinnerAppSelect = findViewById(R.id.spinnerAppSelect);


        bindDashboardViews();
        setupEventConsole();
        setupAppSelectionSpinner(savedInstanceState);

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

    /**
     * Populates the app-selection dropdown with a fixed, hardcoded list of
     * well-known third-party applications. Restores the previously selected
     * package across Activity recreation when possible.
     */
    private void setupAppSelectionSpinner(Bundle savedInstanceState) {
        loadInstalledApps();

        ArrayAdapter<AppInfo> spinnerAdapter = new ArrayAdapter<>(
                this, android.R.layout.simple_spinner_item, installedApps);
        spinnerAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerAppSelect.setAdapter(spinnerAdapter);

        spinnerAppSelect.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (position >= 0 && position < installedApps.size()) {
                    selectedPackageName = installedApps.get(position).packageName;
                    Log.d(TAG, "Selected application for VPN routing = " + selectedPackageName);
                }
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
                selectedPackageName = null;
            }
        });

        String restoredPackage = savedInstanceState != null
                ? savedInstanceState.getString(STATE_SELECTED_PACKAGE)
                : null;

        int restoredIndex = restoredPackage != null ? indexOfPackage(restoredPackage) : -1;

        if (restoredIndex >= 0) {
            spinnerAppSelect.setSelection(restoredIndex);
            selectedPackageName = restoredPackage;
        } else if (!installedApps.isEmpty()) {
            spinnerAppSelect.setSelection(0);
            selectedPackageName = installedApps.get(0).packageName;
        } else {
            selectedPackageName = null;
        }
    }

    /**
     * Populates the app-selection dropdown with a fixed, hardcoded set of
     * well-known third-party applications (name -> package name). No
     * PackageManager-based discovery or filtering is performed here.
     */
    private void loadInstalledApps() {
        installedApps.clear();

        installedApps.add(new AppInfo("Instagram", "com.instagram.android"));
        installedApps.add(new AppInfo("YouTube", "com.google.android.youtube"));
        installedApps.add(new AppInfo("Facebook", "com.facebook.katana"));
        installedApps.add(new AppInfo("Chrome", "com.android.chrome"));
        installedApps.add(new AppInfo("WhatsApp", "com.whatsapp"));
        installedApps.add(new AppInfo("Netflix", "com.netflix.mediaclient"));
        installedApps.add(new AppInfo("Spotify", "com.spotify.music"));
    }

    private int indexOfPackage(String packageName) {
        if (packageName == null) {
            return -1;
        }
        for (int i = 0; i < installedApps.size(); i++) {
            if (installedApps.get(i).packageName.equals(packageName)) {
                return i;
            }
        }
        return -1;
    }

    private void onNewEvent(VpnEvent event) {
        eventAdapter.addEvent(event);
        rvEventConsole.scrollToPosition(eventAdapter.getLastIndex());
    }

    private void onStartVpnClicked() {

        if (selectedPackageName == null || selectedPackageName.isEmpty()) {
            Toast.makeText(this,
                    "Please select an application to route through the VPN.",
                    Toast.LENGTH_SHORT).show();
            return;
        }

        // Early feedback before we even ask for VPN permission. The
        // authoritative check happens again in launchSelectedApp() right
        // before we actually launch, since state can change while the
        // user is granting VPN permission.
        Intent launchIntent = getPackageManager().getLaunchIntentForPackage(selectedPackageName);
        if (launchIntent == null) {
            String message = describeUnlaunchableApp(selectedPackageName);
            Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
            updateStatus(message);
            return;
        }

        updateStatus("Requesting VPN permission...");
        dashboardRepo.setPermissionStatus("Requesting");
        dashboardRepo.logEvent(TAG+"Requesting VPN permission",
                VpnEvent.Level.INFO, VpnEvent.Category.GENERAL);

        Intent prepareIntent = VpnService.prepare(this);

        if (prepareIntent != null) {

            vpnPermissionLauncher.launch(prepareIntent);
        } else {

            Log.d(TAG, "VPN permission already granted.");
            dashboardRepo.setPermissionStatus("Granted");
            dashboardRepo.logEvent(TAG+"VPN permission already granted",
                    VpnEvent.Level.SUCCESS, VpnEvent.Category.GENERAL);
            startVpnServiceForSelectedApp();
        }
    }

    private void startVpnServiceForSelectedApp() {

        if (selectedPackageName == null || selectedPackageName.isEmpty()) {
            Toast.makeText(this,
                    "Please select an application to route through the VPN.",
                    Toast.LENGTH_SHORT).show();
            btnStartVpn.setEnabled(true);
            btnStopVpn.setEnabled(false);
            return;
        }

        updateStatus("Starting MediatorVpnService...");

        Intent serviceIntent =
                new Intent(this, MediatorVpnService.class);

        serviceIntent.putExtra(
                MediatorVpnService.EXTRA_SELECTED_PACKAGE,
                selectedPackageName
        );

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        }

        bindService(
                serviceIntent,
                connection,
                Context.BIND_AUTO_CREATE
        );

        pendingAppLaunch = true;

        updateStatus(
                "VPN service starting. Waiting for VPN establishment before launching "
                        + selectedPackageName
                        + " ..."
        );

        btnStartVpn.setEnabled(false);
        btnStopVpn.setEnabled(true);
    }

    /**
     * Launches the selected real Android application. Must only be called
     * after the VPN interface has actually established (i.e. from the
     * VpnReadyCallback), so that the app's traffic is guaranteed to pass
     * through our TUN interface from its very first packet.
     */
    private void launchSelectedApp() {

        if (selectedPackageName == null || selectedPackageName.isEmpty()) {
            updateStatus("No application selected; cannot launch.");
            return;
        }

        // Re-check right before launching: package visibility/availability
        // could theoretically change between the pre-flight check in
        // onStartVpnClicked() and VPN establishment completing.
        Intent launchIntent = getPackageManager().getLaunchIntentForPackage(selectedPackageName);

        if (launchIntent == null) {
            String message = describeUnlaunchableApp(selectedPackageName);

            updateStatus(message);
            Toast.makeText(this, message, Toast.LENGTH_SHORT).show();

            dashboardRepo.logEvent(TAG + message,
                    VpnEvent.Level.ERROR, VpnEvent.Category.ERROR);
            return;
        }

        launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

        updateStatus(
                "VPN established. Launching "
                        + selectedPackageName
                        + " ..."
        );

        dashboardRepo.logEvent(
                TAG + "VPN established; launching selected application: " + selectedPackageName,
                VpnEvent.Level.SUCCESS,
                VpnEvent.Category.GENERAL
        );

        startActivity(launchIntent);
    }

    /**
     * getLaunchIntentForPackage() returning null does not by itself mean
     * "not installed" - it can also mean the package is installed but
     * exposes no launchable (MAIN/LAUNCHER) activity, or that package
     * visibility is restricted. This distinguishes those cases for a more
     * accurate status/error message rather than assuming "not installed".
     */
    private String describeUnlaunchableApp(String packageName) {
        if (isPackageVisible(packageName)) {
            return "Selected application is installed but exposes no launchable activity: "
                    + packageName;
        }
        return "Selected application is not installed or not visible to this app: "
                + packageName;
    }

    private boolean isPackageVisible(String packageName) {
        try {
            getPackageManager().getPackageInfo(packageName, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private void onStopVpnClicked() {
        updateStatus("Stopping VPN...");
        dashboardRepo.logEvent(TAG+"Stopping VPN (user requested)",
                VpnEvent.Level.INFO, VpnEvent.Category.GENERAL);


        pendingAppLaunch = false;

        if (isServiceBound && mediatorVpnService != null) {

            mediatorVpnService.clearVpnReadyCallback();

            mediatorVpnService.stopVpn();

            unbindService(connection);

            isServiceBound = false;
            mediatorVpnService = null;
        }

        Intent serviceIntent = new Intent(this, MediatorVpnService.class);
        stopService(serviceIntent);

        dashboardRepo.setVpnStatus("Stopped");
        dashboardRepo.setInterfaceStatus("Closed");
        dashboardRepo.setReaderStatus("Stopped");
        dashboardRepo.logEvent(TAG+"VPN stopped by user",
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

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putString(STATE_SELECTED_PACKAGE, selectedPackageName);
    }

    /** Simple holder used by the app-selection dropdown. */
    private static class AppInfo {
        final String label;
        final String packageName;

        AppInfo(String label, String packageName) {
            this.label = label;
            this.packageName = packageName;
        }

        @Override
        public String toString() {
            return label;
        }
    }
}