package com.example.vpntest;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.VpnService;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import com.example.vpntest.model.ConnectionInfo;
import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.repo.VpnEventRepository; // [DASHBOARD]
import com.example.vpntest.utils.VpnLogFileManager;

import java.io.Closeable;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class MediatorVpnService extends VpnService {
    private static final String TAG = "MediatorVpnService";
    private static final String CHANNEL_ID = "vpn_test_channel";
    private static final int NOTIFICATION_ID = 1001;

    private final VpnEventRepository dashboard = VpnEventRepository.getInstance(); // [DASHBOARD]

    private ParcelFileDescriptor vpnInterface;
    private FileOutputStream tunOut;

    private volatile FileInputStream tunIn;
    private final Object tunWriteLock = new Object();

    private UdpForwarder udpForwarder;
    private TcpForwarder tcpForwarder;

    private Thread packetReaderThread;

    private volatile boolean isRunning = false;
    private final Map<String, ConnectionInfo> activeConnections =
            new ConcurrentHashMap<>();
    private final IBinder binder = new LocalBinder();

    public class LocalBinder extends Binder {
        MediatorVpnService getService() {
            return MediatorVpnService.this;
        }
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "onCreate: service instance created.");
    }

    @Override
    public int onStartCommand(@Nullable Intent intent, int flags, int startId) {
        Log.d(TAG, "onStartCommand: starting VPN setup.");
        dashboard.setVpnStatus("Starting");
        VpnLogFileManager.getInstance().startSession(this);

        dashboard.logEvent("Starting VPN Service",
                VpnEvent.Level.INFO,
                VpnEvent.Category.GENERAL);




        startForeground(NOTIFICATION_ID, buildNotification());

        establishVpn();
        startPacketReadingLoop();

        return START_STICKY;
    }


    private void establishVpn() {
        VpnService.Builder builder = new Builder();

        builder.setSession("MediatorVpnService-POC");

        builder.addAddress("10.0.0.2", 24);

        builder.addRoute("0.0.0.0", 0);
        ConnectivityManager cm =
                (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);

        Network activeNetwork = cm.getActiveNetwork();

        if (activeNetwork != null) {
            LinkProperties linkProperties = cm.getLinkProperties(activeNetwork);

            if (linkProperties != null) {
                Log.d(TAG, "========== SYSTEM DNS SERVERS ==========");

                for (InetAddress dnsServer : linkProperties.getDnsServers()) {

                    String dnsIp = dnsServer.getHostAddress();

                    dashboard.logEvent(
                            "========== DNS SERVER ==========\n" +
                                    "DNS Server IP : " +dnsIp+
                                    "===============================",
                            VpnEvent.Level.INFO,
                            VpnEvent.Category.UDP
                    );

                    // Add the same DNS server to VPN
                    builder.addDnsServer(dnsServer);
                }

                Log.d(TAG, "========================================");
            }
        }

        builder.setMtu(1500);

//        try {
//            builder.addDisallowedApplication(getPackageName());
//        } catch (PackageManager.NameNotFoundException e) {
//            Log.e(TAG, "Could not exclude own package from VPN", e);
//        }

//        try {
//            builder.addAllowedApplication(getPackageName());
//        } catch (PackageManager.NameNotFoundException e) {
//            Log.e(TAG, "Failed to add allowed application", e);
//        }
        vpnInterface = builder.establish();

        Log.e("VPN_TEST", "vpnInterface = " + vpnInterface);
        Log.e("VPN_TEST", "Packet reader starting");
        if (vpnInterface == null) {
            Log.e(TAG, "establish() returned null — VPN could not be started. "
                    + "Check that VpnService.prepare() consent was actually granted.");
            dashboard.setInterfaceStatus("Failed"); // [DASHBOARD]
            dashboard.setVpnStatus("Stopped"); // [DASHBOARD]
            dashboard.logEvent("VPN interface could not be established", // [DASHBOARD]
                    VpnEvent.Level.ERROR, VpnEvent.Category.ERROR); // [DASHBOARD]
            return;
        }

        Log.d(TAG, "VPN interface established successfully.");
        dashboard.setInterfaceStatus("Established"); // [DASHBOARD]
        dashboard.setVpnStatus("Running"); // [DASHBOARD]
        dashboard.logEvent("VPN interface established", // [DASHBOARD]
                VpnEvent.Level.SUCCESS, VpnEvent.Category.GENERAL);// [DASHBOARD]
        VpnLogFileManager.getInstance().log("VPN interface established");

        // TTFB START
        // New VPN session (possibly a new target URL) is starting — clear any
        // TTFB value left over from a previous run so the dashboard never
        // shows stale/misleading data for the new site.
        dashboard.resetTtfb();
        // TTFB END

        tunOut = new FileOutputStream(vpnInterface.getFileDescriptor());
        udpForwarder = new UdpForwarder(this, tunOut, tunWriteLock);
        tcpForwarder = new TcpForwarder(this, tunOut, tunWriteLock);
        // TTFB START
        // tcpForwarder is a brand-new object here, so its globalTtfbCaptured
        // field is already false by construction — this line is just an
        // explicit, self-documenting guarantee that TTFB will be recalculated
        // for this session, even if that field initialization logic ever changes.
        tcpForwarder.resetGlobalTtfb();
        Log.e("VPN_TEST", "Package = " + getPackageName());
        // TTFB END
    }


    private void startPacketReadingLoop() {
        if (vpnInterface == null) {
            Log.e(TAG, "Cannot start packet reading loop: vpnInterface is null.");
            dashboard.logEvent("Cannot start packet reading loop: interface is null", // [DASHBOARD]
                    VpnEvent.Level.ERROR, VpnEvent.Category.ERROR); // [DASHBOARD]
            return;
        }

        isRunning = true;

        packetReaderThread = new Thread(() -> {

            try {
                tunIn = new FileInputStream(vpnInterface.getFileDescriptor());

                byte[] buffer = new byte[32767];

                Log.d(TAG, "Packet reading loop started.");
                dashboard.setReaderStatus("Running"); // [DASHBOARD]
                dashboard.logEvent("Packet reading loop started", // [DASHBOARD]
                        VpnEvent.Level.SUCCESS, VpnEvent.Category.GENERAL); // [DASHBOARD]
                VpnLogFileManager.getInstance().log(
                        "Packet reading loop started");

                while (isRunning) {

                    int length;
                    try {
                        length = tunIn.read(buffer);
                    } catch (IOException e) {
                        break; // tunIn was closed by stopVpn() — exit immediately
                    }

                    if (length > 0 && isRunning) {
                        Log.d(TAG, "TCP packet intercepted");
                        handlePacket(buffer, length);
                    }
                }

            } finally {

                closeQuietly(tunIn);
                tunIn = null;
            }

            Log.d(TAG, "Packet reading loop stopped.");
            dashboard.setReaderStatus("Stopped"); // [DASHBOARD]
            dashboard.logEvent("Packet reading loop stopped", // [DASHBOARD]
                    VpnEvent.Level.INFO, VpnEvent.Category.GENERAL); // [DASHBOARD]
            VpnLogFileManager.getInstance().log(
                    "Packet reading loop stopped");
        });

        packetReaderThread.setName("VpnPacketReaderThread");
        packetReaderThread.start();
    }

    /** Logs + dashboards the packet (as before), then actually relays it. */
    private void handlePacket(byte[] packetBytes, int length) {
        if (length < 20) {
            return;
        }

        int version = (packetBytes[0] >> 4) & 0xF;
        if (version != 4) {
            Log.d(TAG, "Skipped non-IPv4 packet (version=" + version + ")");
            dashboard.recordIpv6Skipped(); // [DASHBOARD]
            dashboard.logEvent("Skipped non-IPv4 packet (version=" + version + ")", // [DASHBOARD]
                    VpnEvent.Level.WARNING, VpnEvent.Category.IPV6_SKIPPED); // [DASHBOARD]
            return;
        }

        int protocol = packetBytes[9] & 0xFF;
        String protocolName;

        if (!isRunning) {
            return; // shutdown in progress — do not start new forwarding work
        }
        switch (protocol) {
            case 6: // TCP
                protocolName = "TCP";
                break;
            case 17:
                protocolName = "UDP";
                break;
            case 1:
                protocolName = "ICMP";
                break;
            default:
                protocolName = "OTHER(" + protocol + ")";
        }

        byte[] sourceIpBytes = new byte[4];
        byte[] destIpBytes = new byte[4];
        System.arraycopy(packetBytes, 12, sourceIpBytes, 0, 4);
        System.arraycopy(packetBytes, 16, destIpBytes, 0, 4);

        String sourceIp = ipBytesToString(packetBytes, 12);
        String destIp = ipBytesToString(packetBytes, 16);

        int ipHeaderLength = (packetBytes[0] & 0x0F) * 4;

        int sourcePort = -1;
        int destinationPort = -1;

        if (protocol == 6 || protocol == 17) { // TCP or UDP
            sourcePort = ((packetBytes[ipHeaderLength] & 0xFF) << 8)
                    | (packetBytes[ipHeaderLength + 1] & 0xFF);

            destinationPort = ((packetBytes[ipHeaderLength + 2] & 0xFF) << 8)
                    | (packetBytes[ipHeaderLength + 3] & 0xFF);
        }
        String key = sourceIp + ":" + sourcePort + "->"
                + destIp + ":" + destinationPort;
        ConnectionInfo info = activeConnections.get(key);

        if (info == null) {
            info = new ConnectionInfo();
            activeConnections.put(key, info);
        }
        info.setSourceIp(sourceIp);
        info.setDestinationIp(destIp);
        info.setSourcePort(sourcePort);
        info.setDestinationPort(destinationPort);
        info.setProtocol(protocolName);
        info.setBytesSent(info.getBytesSent() + length);

        if (info.getStartTime() == 0) {
            info.setStartTime(System.currentTimeMillis());
        }
        Log.i(TAG, "Packet captured -> "
                + "Protocol: " + protocolName
                + ", Source: " + sourceIp
                + ", Destination: " + destIp
                + ", Size: " + length + " bytes");

        // [DASHBOARD] mirror this exact log line into the repository
        dashboard.recordPacket(protocolName, sourceIp, destIp, length);
        VpnEvent.Category category;
        switch (protocol) {
            case 6: category = VpnEvent.Category.TCP; break;
            case 17: category = VpnEvent.Category.UDP; break;
            case 1: category = VpnEvent.Category.ICMP; break;
            default: category = VpnEvent.Category.OTHER;
        }
        dashboard.logEvent("Packet captured -> Protocol: " + protocolName
                        + ", Source: " + sourceIp
                        + ", Destination: " + destIp
                        + ", Size: " + length + " bytes",
                VpnEvent.Level.INFO, category);

        // ---- Actually relay the packet so the app/device gets a response ----
        switch (protocol) {
            case 6: // TCP
                if (tcpForwarder != null) {
                    tcpForwarder.handlePacket(packetBytes, length, ipHeaderLength,
                            sourceIpBytes, destIpBytes, sourcePort, destinationPort);
                }
                break;
            case 17: // UDP
                if (udpForwarder != null) {
                    udpForwarder.handlePacket(packetBytes, length, ipHeaderLength,
                            sourceIpBytes, destIpBytes, sourcePort, destinationPort);
                }
                break;
            default:
                // ICMP and everything else: not relayed in this POC.
                break;
        }
    }


    private String ipBytesToString(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF) + "."
                + (bytes[offset + 1] & 0xFF) + "."
                + (bytes[offset + 2] & 0xFF) + "."
                + (bytes[offset + 3] & 0xFF);
    }


    private Notification buildNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "VPN Test Service",
                    NotificationManager.IMPORTANCE_LOW);
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }

        Intent notificationIntent = new Intent(this, VpnTestActivity.class);
        int flags = PendingIntent.FLAG_IMMUTABLE;
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0, notificationIntent, flags);

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("VPN Test POC")
                .setContentText("VPN tunnel is active (packet logging only).")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .build();
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }
    public void stopVpn() {

        isRunning = false;
        closeQuietly(tunIn);
        tunIn = null;

        if (packetReaderThread != null) {
            try {

                packetReaderThread.join(2000);
                if (packetReaderThread.isAlive()) {
                    Log.e(TAG, "packetReaderThread did not terminate within timeout!");
                }
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            packetReaderThread = null;
        }

        if (udpForwarder != null) {
            udpForwarder.shutdown();
            udpForwarder = null;
        }
        if (tcpForwarder != null) {
            tcpForwarder.shutdown();
            tcpForwarder = null;
        }

        closeQuietly(tunOut);
        tunOut = null;

        closeQuietly(vpnInterface);
        vpnInterface = null;

        dashboard.setVpnStatus("Stopped");
        dashboard.setInterfaceStatus("Closed");
    }

    private void closeQuietly(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (IOException ignored) {
            }
        }
    }


    @Override
    public void onRevoke() {
        Log.d(TAG, "onRevoke: user revoked VPN permission from system settings.");
        dashboard.logEvent("VPN permission revoked from system settings", // [DASHBOARD]
                VpnEvent.Level.WARNING, VpnEvent.Category.GENERAL); // [DASHBOARD]
        stopSelf();
        super.onRevoke();
    }
}