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
import com.example.vpntest.repo.VpnEventRepository;
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

    private final VpnEventRepository dashboard =
            VpnEventRepository.getInstance();

    private ParcelFileDescriptor vpnInterface;
    private FileOutputStream tunOut;

    private volatile FileInputStream tunIn;
    private final Object tunWriteLock = new Object();

    private UdpForwarder udpForwarder;
    private TcpForwarder tcpForwarder;

    private Thread packetReaderThread;

    private volatile boolean isRunning = false;

    /*
     * Physical network used by TcpForwarder for outbound sockets.
     */
    private Network underlyingNetwork;

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

        Log.d(
                TAG,
                "DIAG onCreate: serviceInstance="
                        + System.identityHashCode(this)
                        + " thread="
                        + Thread.currentThread().getName()
                        + "("
                        + Thread.currentThread().getId()
                        + ")"
                        + " time="
                        + System.currentTimeMillis()
        );
    }

    @Override
    public int onStartCommand(
            @Nullable Intent intent,
            int flags,
            int startId
    ) {

        Log.d(
                TAG,
                "DIAG onStartCommand ENTRY: serviceInstance="
                        + System.identityHashCode(this)
                        + " startId="
                        + startId
                        + " thread="
                        + Thread.currentThread().getName()
                        + "("
                        + Thread.currentThread().getId()
                        + ")"
                        + " vpnInterface="
                        + System.identityHashCode(vpnInterface)
                        + " vpnInterfaceNull="
                        + (vpnInterface == null)
                        + " isRunning="
                        + isRunning
                        + " time="
                        + System.currentTimeMillis()
        );

        /*
         * Prevent duplicate VPN establishment on the same service instance.
         */
        if (vpnInterface != null && isRunning) {

            Log.w(
                    TAG,
                    "DIAG onStartCommand SKIPPED (duplicate): serviceInstance="
                            + System.identityHashCode(this)
                            + " startId="
                            + startId
                            + " existing vpnInterface="
                            + System.identityHashCode(vpnInterface)
                            + " time="
                            + System.currentTimeMillis()
            );

            return START_STICKY;
        }

        Log.d(
                TAG,
                "onStartCommand: starting VPN setup. serviceInstance="
                        + System.identityHashCode(this)
                        + " startId="
                        + startId
        );

        dashboard.setVpnStatus("Starting");

        VpnLogFileManager
                .getInstance()
                .startSession(this);

        dashboard.logEvent(
                "Starting VPN Service",
                VpnEvent.Level.INFO,
                VpnEvent.Category.GENERAL
        );

        startForeground(
                NOTIFICATION_ID,
                buildNotification()
        );

        establishVpn();

        if (vpnInterface != null) {
            startPacketReadingLoop();
        }

        return START_STICKY;
    }

    private void establishVpn() {

        Log.d(
                TAG,
                "DIAG establishVpn ENTRY: serviceInstance="
                        + System.identityHashCode(this)
                        + " thread="
                        + Thread.currentThread().getName()
                        + "("
                        + Thread.currentThread().getId()
                        + ")"
                        + " previousVpnInterface="
                        + System.identityHashCode(vpnInterface)
                        + " time="
                        + System.currentTimeMillis()
        );

        VpnService.Builder builder = new Builder();

        builder.setSession("MediatorVpnService-POC");

        /*
         * VPN/TUN address.
         */
        builder.addAddress(
                "10.0.0.2",
                24
        );

        /*
         * Route application traffic through the VPN.
         */
        builder.addRoute(
                "0.0.0.0",
                0
        );

        ConnectivityManager cm =
                (ConnectivityManager)
                        getSystemService(
                                Context.CONNECTIVITY_SERVICE
                        );

        /*
         * Get the actual physical network.
         */
        underlyingNetwork = cm.getActiveNetwork();

        if (underlyingNetwork != null) {

            Log.d(
                    TAG,
                    "Underlying Network = "
                            + underlyingNetwork
            );

            /*
             * Tell Android which physical network is underneath
             * this VPN.
             */
            builder.setUnderlyingNetworks(
                    new Network[]{
                            underlyingNetwork
                    }
            );

            LinkProperties linkProperties =
                    cm.getLinkProperties(
                            underlyingNetwork
                    );

            if (linkProperties != null) {

                Log.d(
                        TAG,
                        "========== SYSTEM DNS SERVERS =========="
                );


                for (InetAddress dnsServer :
                        linkProperties.getDnsServers()) {

                    String dnsIp =
                            dnsServer.getHostAddress();

                    dashboard.logEvent(
                            "========== DNS SERVER ==========\n"
                                    + "DNS Server IP : "
                                    + dnsIp
                                    + "\n"
                                    + "===============================",
                            VpnEvent.Level.INFO,
                            VpnEvent.Category.UDP
                    );

                    builder.addDnsServer(
                            dnsServer
                    );
                }

                Log.d(
                        TAG,
                        "========================================"
                );
            }

        } else {

            Log.e(
                    TAG,
                    "NO ACTIVE UNDERLYING NETWORK FOUND"
            );

            dashboard.logEvent(
                    "No active underlying network found",
                    VpnEvent.Level.ERROR,
                    VpnEvent.Category.ERROR
            );
        }

        builder.setMtu(1500);

        /*
         * IMPORTANT:
         *
         * Only this application is routed through this VPN.
         */
        try {

            builder.addAllowedApplication(
                    getPackageName()
            );

            Log.d(
                    TAG,
                    "VPN allowed application = "
                            + getPackageName()
            );

        } catch (PackageManager.NameNotFoundException e) {

            Log.e(
                    TAG,
                    "Failed to add allowed application",
                    e
            );

            return;
        }

        vpnInterface =
                builder.establish();

        Log.e(
                "VPN_TEST",
                "vpnInterface = "
                        + vpnInterface
        );

        if (vpnInterface == null) {

            Log.e(
                    TAG,
                    "establish() returned null — VPN could not be started."
            );

            dashboard.setInterfaceStatus(
                    "Failed"
            );

            dashboard.setVpnStatus(
                    "Stopped"
            );

            dashboard.logEvent(
                    "VPN interface could not be established",
                    VpnEvent.Level.ERROR,
                    VpnEvent.Category.ERROR
            );

            return;
        }

        Log.d(
                TAG,
                "VPN interface established successfully."
        );

        Log.d(
                TAG,
                "DIAG establishVpn SUCCESS: serviceInstance="
                        + System.identityHashCode(this)
                        + " newVpnInterface="
                        + System.identityHashCode(vpnInterface)
                        + " underlyingNetwork="
                        + underlyingNetwork
                        + " time="
                        + System.currentTimeMillis()
        );

        dashboard.setInterfaceStatus(
                "Established"
        );

        dashboard.setVpnStatus(
                "Running"
        );

        dashboard.logEvent(
                "VPN interface established",
                VpnEvent.Level.SUCCESS,
                VpnEvent.Category.GENERAL
        );

        VpnLogFileManager
                .getInstance()
                .log(
                        "VPN interface established"
                );

        /*
         * Reset TTFB for this VPN session.
         */
        dashboard.resetTtfb();

        tunOut =
                new FileOutputStream(
                        vpnInterface.getFileDescriptor()
                );

        udpForwarder =
                new UdpForwarder(
                        this,
                        tunOut,
                        tunWriteLock
                );

        /*
         * IMPORTANT:
         *
         * Pass the physical Network to TcpForwarder.
         */
        tcpForwarder =
                new TcpForwarder(
                        this,
                        tunOut,
                        tunWriteLock,
                        underlyingNetwork
                );

        tcpForwarder.resetGlobalTtfb();

        Log.d(
                TAG,
                "TcpForwarder created with underlyingNetwork="
                        + underlyingNetwork
        );

        Log.e(
                "VPN_TEST",
                "Package = "
                        + getPackageName()
        );
    }

    private void startPacketReadingLoop() {

        if (vpnInterface == null) {

            Log.e(
                    TAG,
                    "Cannot start packet reading loop: vpnInterface is null."
            );

            dashboard.logEvent(
                    "Cannot start packet reading loop: interface is null",
                    VpnEvent.Level.ERROR,
                    VpnEvent.Category.ERROR
            );

            return;
        }

        Log.d(
                TAG,
                "DIAG startPacketReadingLoop ENTRY: serviceInstance="
                        + System.identityHashCode(this)
                        + " vpnInterface="
                        + System.identityHashCode(vpnInterface)
                        + " isRunningBefore="
                        + isRunning
                        + " time="
                        + System.currentTimeMillis()
        );

        isRunning = true;

        packetReaderThread =
                new Thread(
                        () -> {

                            try {

                                tunIn =
                                        new FileInputStream(
                                                vpnInterface.getFileDescriptor()
                                        );

                                byte[] buffer =
                                        new byte[32767];

                                Log.d(
                                        TAG,
                                        "Packet reading loop started."
                                );

                                Log.d(
                                        TAG,
                                        "DIAG packetReaderThread STARTED: serviceInstance="
                                                + System.identityHashCode(
                                                MediatorVpnService.this
                                        )
                                                + " vpnInterface="
                                                + System.identityHashCode(
                                                vpnInterface
                                        )
                                                + " thread="
                                                + Thread.currentThread()
                                                .getName()
                                                + "("
                                                + Thread.currentThread()
                                                .getId()
                                                + ")"
                                                + " time="
                                                + System.currentTimeMillis()
                                );

                                dashboard.setReaderStatus(
                                        "Running"
                                );

                                dashboard.logEvent(
                                        "Packet reading loop started",
                                        VpnEvent.Level.SUCCESS,
                                        VpnEvent.Category.GENERAL
                                );

                                VpnLogFileManager
                                        .getInstance()
                                        .log(
                                                "Packet reading loop started"
                                        );

                                while (isRunning) {

                                    int length;

                                    try {

                                        length =
                                                tunIn.read(
                                                        buffer
                                                );

                                    } catch (IOException e) {

                                        break;
                                    }

                                    if (length > 0 &&
                                            isRunning) {

                                        Log.d(
                                                TAG,
                                                "TCP packet intercepted"
                                        );

                                        handlePacket(
                                                buffer,
                                                length
                                        );
                                    }
                                }

                            } finally {

                                closeQuietly(
                                        tunIn
                                );

                                tunIn = null;
                            }

                            Log.d(
                                    TAG,
                                    "Packet reading loop stopped."
                            );

                            dashboard.setReaderStatus(
                                    "Stopped"
                            );

                            dashboard.logEvent(
                                    "Packet reading loop stopped",
                                    VpnEvent.Level.INFO,
                                    VpnEvent.Category.GENERAL
                            );

                            VpnLogFileManager
                                    .getInstance()
                                    .log(
                                            "Packet reading loop stopped"
                                    );
                        }
                );

        packetReaderThread.setName(
                "VpnPacketReaderThread"
        );

        packetReaderThread.start();
    }

    private void handlePacket(
            byte[] packetBytes,
            int length
    ) {

        if (length < 20) {
            return;
        }

        int version =
                (packetBytes[0] >> 4) & 0xF;

        if (version != 4) {

            Log.d(
                    TAG,
                    "Skipped non-IPv4 packet (version="
                            + version
                            + ")"
            );

            dashboard.recordIpv6Skipped();

            dashboard.logEvent(
                    "Skipped non-IPv4 packet (version="
                            + version
                            + ")",
                    VpnEvent.Level.WARNING,
                    VpnEvent.Category.IPV6_SKIPPED
            );

            return;
        }

        int protocol =
                packetBytes[9] & 0xFF;

        String protocolName;

        if (!isRunning) {
            return;
        }

        switch (protocol) {

            case 6:
                protocolName = "TCP";
                break;

            case 17:
                protocolName = "UDP";
                break;

            case 1:
                protocolName = "ICMP";
                break;

            default:
                protocolName =
                        "OTHER(" + protocol + ")";
        }

        byte[] sourceIpBytes =
                new byte[4];

        byte[] destIpBytes =
                new byte[4];

        System.arraycopy(
                packetBytes,
                12,
                sourceIpBytes,
                0,
                4
        );

        System.arraycopy(
                packetBytes,
                16,
                destIpBytes,
                0,
                4
        );

        String sourceIp =
                ipBytesToString(
                        packetBytes,
                        12
                );

        String destIp =
                ipBytesToString(
                        packetBytes,
                        16
                );

        int ipHeaderLength =
                (packetBytes[0] & 0x0F) * 4;

        int sourcePort = -1;
        int destinationPort = -1;

        if (protocol == 6 ||
                protocol == 17) {

            sourcePort =
                    ((packetBytes[ipHeaderLength] & 0xFF) << 8)
                            |
                            (packetBytes[ipHeaderLength + 1] & 0xFF);

            destinationPort =
                    ((packetBytes[ipHeaderLength + 2] & 0xFF) << 8)
                            |
                            (packetBytes[ipHeaderLength + 3] & 0xFF);
        }

        String key =
                sourceIp
                        + ":"
                        + sourcePort
                        + "->"
                        + destIp
                        + ":"
                        + destinationPort;

        ConnectionInfo info =
                activeConnections.get(
                        key
                );

        if (info == null) {

            info =
                    new ConnectionInfo();

            activeConnections.put(
                    key,
                    info
            );
        }

        info.setSourceIp(
                sourceIp
        );

        info.setDestinationIp(
                destIp
        );

        info.setSourcePort(
                sourcePort
        );

        info.setDestinationPort(
                destinationPort
        );

        info.setProtocol(
                protocolName
        );

        info.setBytesSent(
                info.getBytesSent()
                        + length
        );

        if (info.getStartTime() == 0) {

            info.setStartTime(
                    System.currentTimeMillis()
            );
        }

        Log.i(
                TAG,
                "Packet captured -> "
                        + "Protocol: "
                        + protocolName
                        + ", Source: "
                        + sourceIp
                        + ", Destination: "
                        + destIp
                        + ", Size: "
                        + length
                        + " bytes"
        );

        dashboard.recordPacket(
                protocolName,
                sourceIp,
                destIp,
                length
        );

        VpnEvent.Category category;

        switch (protocol) {

            case 6:
                category =
                        VpnEvent.Category.TCP;
                break;

            case 17:
                category =
                        VpnEvent.Category.UDP;
                break;

            case 1:
                category =
                        VpnEvent.Category.ICMP;
                break;

            default:
                category =
                        VpnEvent.Category.OTHER;
        }

        dashboard.logEvent(
                "Packet captured -> Protocol: "
                        + protocolName
                        + ", Source: "
                        + sourceIp
                        + ", Destination: "
                        + destIp
                        + ", Size: "
                        + length
                        + " bytes",
                VpnEvent.Level.INFO,
                category
        );

        switch (protocol) {

            case 6:

                if (tcpForwarder != null) {

                    tcpForwarder.handlePacket(
                            packetBytes,
                            length,
                            ipHeaderLength,
                            sourceIpBytes,
                            destIpBytes,
                            sourcePort,
                            destinationPort
                    );
                }

                break;

            case 17:

                if (udpForwarder != null) {

                    udpForwarder.handlePacket(
                            packetBytes,
                            length,
                            ipHeaderLength,
                            sourceIpBytes,
                            destIpBytes,
                            sourcePort,
                            destinationPort
                    );
                }

                break;

            default:
                break;
        }
    }

    private String ipBytesToString(
            byte[] bytes,
            int offset
    ) {

        return (bytes[offset] & 0xFF)
                + "."
                + (bytes[offset + 1] & 0xFF)
                + "."
                + (bytes[offset + 2] & 0xFF)
                + "."
                + (bytes[offset + 3] & 0xFF);
    }

    private Notification buildNotification() {

        if (Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.O) {

            NotificationChannel channel =
                    new NotificationChannel(
                            CHANNEL_ID,
                            "VPN Test Service",
                            NotificationManager.IMPORTANCE_LOW
                    );

            NotificationManager manager =
                    getSystemService(
                            NotificationManager.class
                    );

            if (manager != null) {

                manager.createNotificationChannel(
                        channel
                );
            }
        }

        Intent notificationIntent =
                new Intent(
                        this,
                        VpnTestActivity.class
                );

        int flags =
                PendingIntent.FLAG_IMMUTABLE;

        PendingIntent pendingIntent =
                PendingIntent.getActivity(
                        this,
                        0,
                        notificationIntent,
                        flags
                );

        return new NotificationCompat.Builder(
                this,
                CHANNEL_ID
        )
                .setContentTitle(
                        "VPN Test POC"
                )
                .setContentText(
                        "VPN tunnel is active (packet logging only)."
                )
                .setSmallIcon(
                        android.R.drawable.ic_lock_lock
                )
                .setContentIntent(
                        pendingIntent
                )
                .setOngoing(true)
                .build();
    }

    @Override
    public void onDestroy() {

        Log.d(
                TAG,
                "DIAG onDestroy: serviceInstance="
                        + System.identityHashCode(this)
                        + " vpnInterface="
                        + System.identityHashCode(vpnInterface)
                        + " time="
                        + System.currentTimeMillis()
        );

        dashboard.logEvent(
                "DIAG onDestroy: serviceInstance="
                        + System.identityHashCode(this)
                        + " vpnInterface="
                        + System.identityHashCode(vpnInterface)
                        + " time="
                        + System.currentTimeMillis(),
                VpnEvent.Level.INFO,
                VpnEvent.Category.GENERAL
        );

        stopVpn();

        super.onDestroy();
    }

    public void stopVpn() {

        isRunning = false;

        closeQuietly(
                tunIn
        );

        tunIn = null;

        if (packetReaderThread != null) {

            try {

                packetReaderThread.join(
                        2000
                );

                if (packetReaderThread.isAlive()) {

                    Log.e(
                            TAG,
                            "packetReaderThread did not terminate within timeout!"
                    );
                }

            } catch (InterruptedException ignored) {

                Thread.currentThread()
                        .interrupt();
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

        closeQuietly(
                tunOut
        );

        tunOut = null;

        closeQuietly(
                vpnInterface
        );

        vpnInterface = null;

        underlyingNetwork = null;

        dashboard.setVpnStatus(
                "Stopped"
        );

        dashboard.setInterfaceStatus(
                "Closed"
        );
    }

    private void closeQuietly(
            Closeable c
    ) {

        if (c != null) {

            try {

                c.close();

            } catch (IOException ignored) {
            }
        }
    }

    @Override
    public void onRevoke() {

        Log.d(
                TAG,
                "onRevoke: user revoked VPN permission from system settings."
        );

        dashboard.logEvent(
                "VPN permission revoked from system settings",
                VpnEvent.Level.WARNING,
                VpnEvent.Category.GENERAL
        );

        stopSelf();

        super.onRevoke();
    }
}