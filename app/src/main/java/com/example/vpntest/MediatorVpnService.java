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
import java.util.Collections;
import java.util.Map;
import java.util.Set;
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

    /*
     * Website-IP verification (minimal, in-memory only - no history/persistence):
     * the hostname and current DNS-resolved IP(s) of the website the user entered,
     * plus a small per-session guard so a repeated match on the same destination
     * IP doesn't spam the event console with duplicate MATCH entries.
     */
    private volatile String targetWebsiteHostname;
    private volatile Set<String> targetWebsiteResolvedIps = Collections.emptySet();
    private final Set<String> matchedIpsLoggedThisSession = ConcurrentHashMap.newKeySet();

    private final IBinder binder = new LocalBinder();

    private VpnReadyCallback vpnReadyCallback;

    public interface VpnReadyCallback {
        void onVpnEstablished();
    }

    public void setVpnReadyCallback(VpnReadyCallback callback) {
        this.vpnReadyCallback = callback;

        if (vpnInterface != null) {
            callback.onVpnEstablished();
        }
    }

    public void clearVpnReadyCallback() {
        this.vpnReadyCallback = null;
    }

    /**
     * Called by VpnTestActivity once the entered website's hostname has been
     * DNS-resolved off the main thread. Replaces the current target for the
     * active test only - no history of previous targets/resolutions is kept.
     * Passing null/empty clears the target (e.g. when the VPN stops).
     */
    public void setWebsiteTarget(
            String hostname,
            Set<String> resolvedIps) {

        this.targetWebsiteHostname = hostname;

        this.targetWebsiteResolvedIps =
                resolvedIps != null
                        ? resolvedIps
                        : Collections.emptySet();

        this.matchedIpsLoggedThisSession.clear();

        /*
         * Pass the actual website-resolved IPs to TcpForwarder.
         */
        if (tcpForwarder != null) {

            tcpForwarder.setWebsiteResolvedIps(
                    this.targetWebsiteResolvedIps
            );

            Log.d(
                    TAG,
                    "Updated TcpForwarder with website resolved IPs = "
                            + this.targetWebsiteResolvedIps
            );
        }
    }

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

        /*
         * IPv6 VPN/TUN address (ULA prefix, private to this VPN) and
         * default IPv6 route, so IPv6 packets actually reach the TUN
         * interface instead of bypassing it. Kept separate from the
         * IPv4 configuration above; IPv4 behavior is unchanged.
         */
        try {
            builder.addAddress(
                    "fd00:1:fd00::2",
                    64
            );

            builder.addRoute(
                    "::",
                    0
            );

            Log.d(
                    TAG,
                    "IPv6 VPN address/route configured (fd00:1:fd00::2/64, ::/0)"
            );

        } catch (IllegalArgumentException e) {

            Log.e(
                    TAG,
                    "Failed to configure IPv6 VPN address/route; continuing IPv4-only",
                    e
            );

            dashboard.logEvent(
                    "Failed to configure IPv6 VPN address/route; continuing IPv4-only: " + e.getMessage(),
                    VpnEvent.Level.WARNING,
                    VpnEvent.Category.GENERAL
            );
        }

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
        if (vpnReadyCallback != null) {
            vpnReadyCallback.onVpnEstablished();
        }

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


        tcpForwarder.setWebsiteResolvedIps(
                targetWebsiteResolvedIps
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

    /**
     * Compares the just-parsed packet's destination IP against the current
     * website's DNS-resolved IP(s) (NOT the system DNS resolver IPs). On a
     * match, immediately logs one RED MATCH event to the existing event
     * console. A tiny per-session set prevents duplicate MATCH spam if the
     * same destination IP appears in many packets; no history/list is kept.
     */
    private void checkWebsiteIpMatch(ParsedPacket parsed) {

        if (parsed.destinationIp == null) {
            return;
        }

        String hostname = targetWebsiteHostname;
        Set<String> resolvedIps = targetWebsiteResolvedIps;

        if (hostname == null || resolvedIps.isEmpty()) {
            return;
        }

        String matchedDnsIp = null;

        for (String resolvedIp : resolvedIps) {
            if (resolvedIp.equals(parsed.destinationIp)) {
                matchedDnsIp = resolvedIp;
                break;
            }
        }

        if (matchedDnsIp == null) {
            return;
        }

        if (!matchedIpsLoggedThisSession.add(parsed.destinationIp)) {
            return;
        }

        String matchLog =
                "[MATCH] Requested website destination IP matched\n"
                        + "Website       : " + hostname + "\n"
                        + "Destination IP: " + parsed.destinationIp + "\n"
                        + "Resolved IP   : " + matchedDnsIp + "\n"
                        + "IP Version    : IPv" + parsed.ipVersion;

        dashboard.logEvent(
                matchLog,
                VpnEvent.Level.ERROR,
                VpnEvent.Category.MATCH
        );
    }

    private void handlePacket(
            byte[] packetBytes,
            int length
    ) {

        if (!isRunning) {
            return;
        }

        if (length < 1) {
            return;
        }

        ParsedPacket parsed = PacketParser.parse(packetBytes, length);

        checkWebsiteIpMatch(parsed);

        if (parsed.status == ParsedPacket.Status.MALFORMED) {

            Log.w(
                    TAG,
                    "Malformed packet dropped: " + parsed.reason
            );

            /*
             * Reused as a general "packet could not be processed" counter.
             * It previously only counted skipped IPv6 packets; IPv6 is now
             * actually forwarded, so this now tracks malformed/unsupported
             * packets of either IP version. tvIpv6Skipped in the UI is kept
             * as-is (see VpnTestActivity) to avoid unrelated UI changes.
             */
            dashboard.recordIpv6Skipped();

            dashboard.logEvent(
                    "Malformed packet dropped: " + parsed.reason,
                    VpnEvent.Level.WARNING,
                    VpnEvent.Category.IPV6_SKIPPED
            );

            return;
        }

        if (parsed.status == ParsedPacket.Status.NON_FIRST_FRAGMENT) {

            Log.d(
                    TAG,
                    "Non-first fragment (IPv" + parsed.ipVersion + ") from "
                            + parsed.sourceIp + " to " + parsed.destinationIp
                            + " - transport header unavailable, skipping port extraction."
            );

            dashboard.logEvent(
                    "Non-first fragment (IPv" + parsed.ipVersion + ") from "
                            + parsed.sourceIp + " to " + parsed.destinationIp
                            + " - transport header unavailable",
                    VpnEvent.Level.INFO,
                    VpnEvent.Category.OTHER
            );

            return;
        }

        int protocol = parsed.transportProtocol;
        String protocolName = PacketParser.protocolName(protocol);

        String sourceIp = parsed.sourceIp;
        String destIp = parsed.destinationIp;

        int sourcePort = parsed.sourcePort;
        int destinationPort = parsed.destinationPort;

        String key = parsed.connectionKey();

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

        StringBuilder captureLog = new StringBuilder();

        captureLog.append("Packet captured -> IP Version: IPv")
                .append(parsed.ipVersion)
                .append(", Protocol: ").append(protocolName)
                .append(", Source: ").append(sourceIp)
                .append(", Destination: ").append(destIp)
                .append(", Size: ").append(length).append(" bytes");

        if (parsed.ipVersion == 6) {
            captureLog.append(", Next Header: ").append(protocol)
                    .append(", Hop Limit: ").append(parsed.ttlOrHopLimit)
                    .append(", IPv6 Header Length: ").append(parsed.ipHeaderLength)
                    .append(", Transport Offset: ").append(parsed.transportHeaderOffset)
                    .append(", Payload Length: ").append(parsed.payloadLength);
            if (sourcePort >= 0) {
                captureLog.append(", Source Port: ").append(sourcePort)
                        .append(", Destination Port: ").append(destinationPort);
            }
        }

        Log.i(
                TAG,
                captureLog.toString()
        );

        dashboard.recordPacket(
                protocolName,
                sourceIp,
                destIp,
                length
        );

        VpnEvent.Category category;

        switch (protocol) {

            case PacketParser.PROTO_TCP:
                category =
                        VpnEvent.Category.TCP;
                break;

            case PacketParser.PROTO_UDP:
                category =
                        VpnEvent.Category.UDP;
                break;

            case PacketParser.PROTO_ICMPV4:
            case PacketParser.PROTO_ICMPV6:
                category =
                        VpnEvent.Category.ICMP;
                break;

            default:
                category =
                        VpnEvent.Category.OTHER;
        }

        dashboard.logEvent(
                captureLog.toString(),
                VpnEvent.Level.INFO,
                category
        );

        switch (protocol) {

            case PacketParser.PROTO_TCP:

                if (tcpForwarder != null) {

                    tcpForwarder.handlePacket(
                            packetBytes,
                            length,
                            parsed
                    );
                }

                break;

            case PacketParser.PROTO_UDP:

                if (udpForwarder != null) {

                    udpForwarder.handlePacket(
                            packetBytes,
                            length,
                            parsed
                    );
                }

                break;

            default:
                break;
        }
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

        vpnReadyCallback = null;

        targetWebsiteHostname = null;
        targetWebsiteResolvedIps = Collections.emptySet();
        matchedIpsLoggedThisSession.clear();

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