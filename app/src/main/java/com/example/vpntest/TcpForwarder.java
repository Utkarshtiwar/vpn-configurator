package com.example.vpntest;

import android.net.Network;
import android.net.VpnService;
import android.util.Log;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.repo.VpnEventRepository;


class TcpForwarder {

    private static final String TAG = "TcpForwarder";

    private final VpnService vpnService;
    private final FileOutputStream tunOut;
    private final Object tunWriteLock;

    /*
     * Physical network used for the real outbound TCP socket.
     */
    private final Network underlyingNetwork;

    private final Random random = new Random();

    private final Map<String, TcpSession> sessions = new ConcurrentHashMap<>();

    private volatile boolean shutdown = false;

    private final VpnEventRepository dashboard = VpnEventRepository.getInstance();

    private volatile Set<String> websiteResolvedIps =
            Collections.emptySet();
    private final java.util.concurrent.atomic.AtomicBoolean globalTtfbCaptured =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    private final java.util.concurrent.atomic.AtomicBoolean globalRequestCaptured =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    /*
     * Monotonic timestamps.
     *
     * Used ONLY for accurate TTFB duration calculation.
     */
    private volatile long globalRequestSentTime = 0L;

    private volatile long globalFirstByteReceivedTime = 0L;


    private volatile long globalRequestSentWallTime = 0L;

    private volatile long globalFirstByteReceivedWallTime = 0L;

    private volatile long globalTtfbMs = -1L;

    private volatile String globalTtfbRequestConnectionKey = null;
    private volatile String globalTtfbRequestDestinationIp = null;

    TcpForwarder(VpnService vpnService, FileOutputStream tunOut, Object tunWriteLock,
                 Network underlyingNetwork) {
        this.vpnService = vpnService;
        this.tunOut = tunOut;
        this.tunWriteLock = tunWriteLock;
        this.underlyingNetwork = underlyingNetwork;

        Log.d(TAG, "TcpForwarder underlyingNetwork = " + underlyingNetwork);
    }


    /**
     * @param packet full packet bytes as read from the TUN
     * @param length total valid length of packet
     * @param parsed pre-parsed IPv4/IPv6 header info (addresses, ports, transport header offset)
     */
    void handlePacket(byte[] packet, int length, ParsedPacket parsed) {

        if (shutdown) return;

        byte[] srcIp = parsed.sourceIpBytes;
        byte[] dstIp = parsed.destinationIpBytes;
        int srcPort = parsed.sourcePort;
        int dstPort = parsed.destinationPort;

        Log.d(TAG, "========== TCP HANDLE PACKET ==========");
        Log.d(TAG, "Src: " + ipStr(srcIp) + ":" + srcPort);
        Log.d(TAG, "Dst: " + ipStr(dstIp) + ":" + dstPort);
        Log.d(TAG, "Length: " + length);
        Log.d(TAG, "=======================================");

        int tcpHeaderOffset = parsed.transportHeaderOffset;

        if (length < tcpHeaderOffset + 20) return;

        int version = parsed.ipVersion;
        int ttl = parsed.ttlOrHopLimit;

        // -------------------- TCP Header --------------------

        long seq = readUnsignedInt(packet, tcpHeaderOffset + 4);
        long ack = readUnsignedInt(packet, tcpHeaderOffset + 8);

        int dataOffsetBytes = ((packet[tcpHeaderOffset + 12] >> 4) & 0x0F) * 4;

        int flags = packet[tcpHeaderOffset + 13] & 0xFF;

        int windowSize = ((packet[tcpHeaderOffset + 14] & 0xFF) << 8)
                | (packet[tcpHeaderOffset + 15] & 0xFF);

        int checksum = ((packet[tcpHeaderOffset + 16] & 0xFF) << 8)
                | (packet[tcpHeaderOffset + 17] & 0xFF);

        int urgentPointer = ((packet[tcpHeaderOffset + 18] & 0xFF) << 8)
                | (packet[tcpHeaderOffset + 19] & 0xFF);

        int payloadOffset = tcpHeaderOffset + dataOffsetBytes;
        int payloadLen = length - payloadOffset;
        if (payloadLen < 0) payloadLen = 0;

        StringBuilder tcpHeaderLog = new StringBuilder();
        tcpHeaderLog.append("========== [TX] TCP/IP HEADER ==========\n")
                .append("IP Version         : IPv").append(version).append("\n")
                .append("Source IP          : ").append(ipStr(srcIp)).append("\n")
                .append("Destination IP     : ").append(ipStr(dstIp)).append("\n")
                .append("Source Port        : ").append(srcPort).append("\n")
                .append("Destination Port   : ").append(dstPort).append("\n");

        if (version == 4) {
            tcpHeaderLog.append("TTL                : ").append(ttl).append("\n")
                    .append("IP Header Length   : ").append(parsed.ipHeaderLength).append("\n");
        } else {
            tcpHeaderLog.append("Hop Limit          : ").append(ttl).append("\n")
                    .append("IPv6 Header Length : ").append(parsed.ipHeaderLength).append("\n")
                    .append("Transport Offset   : ").append(tcpHeaderOffset).append("\n")
                    .append("IPv6 Payload Length: ").append(parsed.payloadLength).append("\n");
        }

        tcpHeaderLog.append("TCP Header Length  : ").append(dataOffsetBytes).append("\n")
                .append("Sequence Number    : ").append(seq).append("\n")
                .append("ACK Number         : ").append(ack).append("\n")
                .append("TCP Flags          : 0x").append(Integer.toHexString(flags)).append("\n")
                .append("Window Size        : ").append(windowSize).append("\n")
                .append("Checksum           : 0x").append(Integer.toHexString(checksum)).append("\n")
                .append("Urgent Pointer     : ").append(urgentPointer).append("\n")
                .append("Payload Length     : ").append(payloadLen).append("\n")
                .append("===================================");

        Log.d(TAG, tcpHeaderLog.toString());
        dashboard.logEvent(tcpHeaderLog.toString(), VpnEvent.Level.INFO, VpnEvent.Category.TCP);

        String key = parsed.connectionKey();

        boolean isSyn = (flags & PacketUtils.TCP_SYN) != 0;
        boolean isAck = (flags & PacketUtils.TCP_ACK) != 0;
        boolean isFin = (flags & PacketUtils.TCP_FIN) != 0;
        boolean isRst = (flags & PacketUtils.TCP_RST) != 0;

        Log.d(TAG, "Flags: SYN=" + isSyn + " ACK=" + isAck + " FIN=" + isFin + " RST=" + isRst);

        TcpSession session = sessions.get(key);

        if (isSyn && !isAck) {

            if (session != null) {

                if (session.state == TcpSession.State.SYN_RCVD
                        || session.state == TcpSession.State.ESTABLISHED) {

                    if (session.synAckSent.get()) {
                        Log.d(TAG, "Retransmitted SYN for existing session " + key + ", re-sending SYN-ACK.");
                        sendSynAck(session);
                    }

                    return;
                }

                closeSession(key, session);
            }

            startNewSession(key, srcIp, srcPort, dstIp, dstPort, seq);
            return;
        }

        if (session == null) {
            if (!isRst) {
                sendRst(dstIp, dstPort, srcIp, srcPort, ack, seq + payloadLen);
            }
            return;
        }

        if (isRst) {
            closeSession(key, session);
            return;
        }

        if (session.state == TcpSession.State.SYN_RCVD && isAck) {
            Log.d(TAG, "TCP Handshake completed.");
            session.state = TcpSession.State.ESTABLISHED;
            session.startRealSocketReaderThread(this, key);
        }

        Log.d(TAG, "payload len and sessionstate : " + payloadLen + " " + session.state);

        if (payloadLen > 0 && session.state == TcpSession.State.ESTABLISHED) {

            byte[] data = new byte[payloadLen];

            System.arraycopy(
                    packet,
                    payloadOffset,
                    data,
                    0,
                    payloadLen
            );

            /*
             * =========================================================
             * TTFB REQUEST MATCH
             * =========================================================
             *
             * Only capture request start time when:
             *
             * 1. Payload size > 0
             * 2. TCP session is ESTABLISHED
             * 3. Packet destination IP matches one of the
             *    resolved IPs of the requested website
             *
             * IMPORTANT:
             * Request timestamp is captured immediately BEFORE
             * writing the request to the real socket.
             */
            String destinationIp = ipStr(dstIp);

            boolean destinationIpMatched =
                    websiteResolvedIps.contains(destinationIp);

            Log.d(
                    TAG,
                    "TTFB IP MATCH CHECK -> "
                            + "Destination IP = " + destinationIp
                            + ", Resolved IPs = " + websiteResolvedIps
                            + ", Payload Length = " + payloadLen
            );

            boolean requestTimestampCapturedForThisPacket = false;

            try {

                /*
                 * =====================================================
                 * CAPTURE REQUEST START TIME
                 * =====================================================
                 *
                 * This MUST happen immediately before write().
                 */
                if (destinationIpMatched
                        && payloadLen > 0
                        && globalRequestCaptured.compareAndSet(false, true)) {

                    /*
                     * ================================================
                     * TTFB REQUEST START TIME
                     * ================================================
                     *
                     * nanoTime():
                     * Accurate TTFB duration calculation ke liye.
                     *
                     * currentTimeMillis():
                     * Human-readable log timestamp ke liye.
                     */
                    globalRequestSentTime =
                            System.nanoTime();

                    globalRequestSentWallTime =
                            System.currentTimeMillis();

                    /*
                     * Save the TCP connection on which the
                     * TTFB request was sent.
                     */
                    globalTtfbRequestConnectionKey =
                            key;

                    requestTimestampCapturedForThisPacket = true;

                    Log.i(
                            TAG,
                            "========== TTFB REQUEST START ==========\n"
                                    + "Destination IP : " + destinationIp + "\n"
                                    + "Payload Length  : " + payloadLen + "\n"
                                    + "Connection Key  : " + key + "\n"
                                    + "Request Time    : "
                                    + formatTimestamp(globalRequestSentWallTime)
                                    + "\n"
                                    + "========================================="
                    );
                }

                /*
                 * =====================================================
                 * WRITE REQUEST TO REAL SOCKET
                 * =====================================================
                 */
                session.realOut.write(data);

                session.realOut.flush();

                Log.d(TAG, "Payload written successfully.");

                Log.d(
                        TAG,
                        "Payload Length = " + payloadLen
                );

            } catch (IOException e) {


                if (requestTimestampCapturedForThisPacket) {

                    globalRequestCaptured.set(false);
                    globalRequestSentTime = 0L;
                    globalTtfbRequestConnectionKey = null;
                }

                Log.w(
                        TAG,
                        "TCP write to real socket failed for " + key,
                        e
                );

                sendRst(
                        srcIp,
                        srcPort,
                        dstIp,
                        dstPort,
                        session.deviceSeq,
                        seq + payloadLen
                );

                closeSession(key, session);
                return;
            }

            session.clientNextSeq = seq + payloadLen;

            sendAck(session, false);
        }

        if (isFin) {
            session.clientNextSeq = seq + 1;
            sendAck(session, false);

            try {
                session.realSocket.shutdownOutput();
            } catch (IOException ignored) {
            }

            if (session.state != TcpSession.State.CLOSED) {
                session.state = TcpSession.State.CLOSING;
            }
        }
    }
    void setWebsiteResolvedIps(Set<String> resolvedIps) {

        if (resolvedIps == null) {
            websiteResolvedIps = Collections.emptySet();
        } else {
            websiteResolvedIps = resolvedIps;
        }

        Log.d(
                TAG,
                "Website resolved IPs received by TcpForwarder = "
                        + websiteResolvedIps
        );
    }

    private void startNewSession(String key, byte[] srcIp, int srcPort,
                                 byte[] dstIp, int dstPort, long clientIsn) {

        TcpSession session = new TcpSession();
        session.srcIp = srcIp;
        session.srcPort = srcPort;
        session.dstIp = dstIp;
        session.dstPort = dstPort;
        session.clientNextSeq = clientIsn + 1;
        session.deviceSeq = random.nextInt(Integer.MAX_VALUE);
        session.state = TcpSession.State.SYN_RCVD;

        sessions.put(key, session);

        new Thread(() -> {

            try {
                Log.d(TAG, "Creating new TCP session...");
                dashboard.logEvent("Creating new TCP session ..", VpnEvent.Level.INFO, VpnEvent.Category.TCP);

                Log.d(TAG, "Destination = " + intToInetName(dstIp).getHostAddress() + ":" + dstPort);
                dashboard.logEvent(
                        "Destination = " + intToInetName(dstIp).getHostAddress() + ":" + dstPort,
                        VpnEvent.Level.INFO,
                        VpnEvent.Category.TCP
                );

                /*
                 * IMPORTANT:
                 *
                 * Do NOT call vpnService.protect(socket)
                 * here.
                 *
                 * protect() was consistently returning false
                 * on the device.
                 *
                 * Instead explicitly bind this socket to the
                 * active physical Network.
                 */

                if (underlyingNetwork == null) {
                    Log.e(TAG, "No underlying Network available for " + key);
                    dashboard.logEvent("No underlying Network available for " + key,
                            VpnEvent.Level.ERROR, VpnEvent.Category.TCP);

                    sendRst(srcIp, srcPort, dstIp, dstPort, session.deviceSeq, session.clientNextSeq);
                    sessions.remove(key);
                    return;
                }

                Socket socket = new Socket();
                Log.d(TAG, "Created forwarding socket for " + key);

                try {
                    underlyingNetwork.bindSocket(socket);
                    Log.d(TAG, "Underlying Network bindSocket SUCCESS for " + key);
                    dashboard.logEvent("Underlying Network bindSocket SUCCESS for " + key,
                            VpnEvent.Level.SUCCESS, VpnEvent.Category.TCP);
                } catch (IOException e) {
                    Log.e(TAG, "Underlying Network bindSocket FAILED for " + key, e);
                    dashboard.logEvent("Underlying Network bindSocket FAILED for " + key + " : " + e.getMessage(),
                            VpnEvent.Level.ERROR, VpnEvent.Category.TCP);

                    try {
                        socket.close();
                    } catch (IOException ignored) {
                    }

                    sendRst(srcIp, srcPort, dstIp, dstPort, session.deviceSeq, session.clientNextSeq);
                    sessions.remove(key);
                    return;
                }

                Log.d(TAG, "Connecting socket to " + intToInetName(dstIp).getHostAddress() + ":" + dstPort);

                socket.connect(new InetSocketAddress(intToInetName(dstIp), dstPort), 8000);

                Log.d(TAG, "Socket connected successfully.");
                dashboard.logEvent("Socket connected successfully.", VpnEvent.Level.SUCCESS, VpnEvent.Category.TCP);

                session.realSocket = socket;

                String serverIp = socket.getInetAddress().getHostAddress();
                String serverName;

                try {
                    serverName = socket.getInetAddress().getCanonicalHostName();
                } catch (Exception e) {
                    serverName = "Unknown";
                    Log.e(TAG, "Exception while rsolving host name : "
                            + intToInetName(dstIp).getHostAddress() + ":" + dstPort, e);
                    dashboard.logEvent(
                            "Exception while rsolving host name : "
                                    + intToInetName(dstIp).getHostAddress() + ":" + dstPort
                                    + " exception is : " + e.getMessage(),
                            VpnEvent.Level.INFO, VpnEvent.Category.TCP
                    );
                }

                Log.d(TAG, "Creating TCP session");
                dashboard.logEvent(
                        "========== SERVER ==========\n"
                                + "Server IP      : " + serverIp + "\n"
                                + "Server Name    : " + serverName + "\n"
                                + "============================",
                        VpnEvent.Level.INFO, VpnEvent.Category.TCP
                );

                session.realOut = socket.getOutputStream();
                session.realIn = socket.getInputStream();

                /*
                 * Send SYN-ACK only after the real server
                 * connection is established.
                 */
                sendSynAck(session);

            } catch (IOException e) {
                Log.e(TAG, "TCP connect failed for " + key + ": " + e.getMessage(), e);
                dashboard.logEvent("TCP socket exception " + e.getMessage(),
                        VpnEvent.Level.ERROR, VpnEvent.Category.TCP);

                sendRst(srcIp, srcPort, dstIp, dstPort, session.deviceSeq, session.clientNextSeq);
                sessions.remove(key);
            }

        }, "TcpConnect-" + key).start();
    }


    private InetAddress intToInetName(byte[] ip) throws IOException {
        return InetAddress.getByAddress(ip);
    }


    private void sendSynAck(TcpSession s) {

        boolean firstSend = s.synAckSent.compareAndSet(false, true);

        writeTcpPacket(s.dstIp, s.dstPort, s.srcIp, s.srcPort, s.deviceSeq, s.clientNextSeq,
                PacketUtils.TCP_SYN | PacketUtils.TCP_ACK, null, 0);

        if (firstSend) {
            s.deviceSeq += 1;
        }
    }


    private void sendAck(TcpSession s, boolean pshFlag) {

        int flags = PacketUtils.TCP_ACK | (pshFlag ? PacketUtils.TCP_PSH : 0);

        writeTcpPacket(s.dstIp, s.dstPort, s.srcIp, s.srcPort, s.deviceSeq, s.clientNextSeq,
                flags, null, 0);
    }


    void sendDataToClient(TcpSession s, byte[] data, int len) {

        writeTcpPacket(s.dstIp, s.dstPort, s.srcIp, s.srcPort, s.deviceSeq, s.clientNextSeq,
                PacketUtils.TCP_ACK | PacketUtils.TCP_PSH, data, len);

        s.deviceSeq += len;
    }


    void sendFinToClient(TcpSession s) {

        writeTcpPacket(s.dstIp, s.dstPort, s.srcIp, s.srcPort, s.deviceSeq, s.clientNextSeq,
                PacketUtils.TCP_ACK | PacketUtils.TCP_FIN, null, 0);

        s.deviceSeq += 1;
    }


    void reportTtfb(TcpSession s, long ttfbMs, String key) {

        Log.d(TAG, "Reporting TTFB = " + ttfbMs + " ms");

        dashboard.logEvent("TTFB : " + ttfbMs + " ms  (" + key + ")",
                VpnEvent.Level.SUCCESS, VpnEvent.Category.TCP);

        dashboard.recordTtfb(ttfbMs);

        Log.d(TAG, "Dashboard updated with TTFB.");
    }


    private void sendRst(byte[] fromIp, int fromPort, byte[] toIp, int toPort, long seq, long ack) {

        writeTcpPacket(fromIp, fromPort, toIp, toPort, seq, ack, PacketUtils.TCP_RST, null, 0);
    }


    /** Builds and writes a TCP/IP packet back into the TUN. Supports IPv4 and IPv6 based on fromIp.length. */
    private void writeTcpPacket(byte[] fromIp, int fromPort, byte[] toIp, int toPort,
                                long seq, long ack, int flags, byte[] payload, int payloadLen) {

        boolean ipv6 = fromIp.length == 16;
        int ipHeaderLen = ipv6 ? 40 : 20;
        int tcpHeaderLen = 20;
        int tcpSegmentLen = tcpHeaderLen + payloadLen;
        int total = ipHeaderLen + tcpSegmentLen;

        ByteBuffer buf = ByteBuffer.allocate(total);

        if (ipv6) {
            PacketUtils.writeIPv6Header(buf, tcpSegmentLen, PacketUtils.PROTO_TCP, fromIp, toIp);
        } else {
            PacketUtils.writeIPv4Header(buf, total, PacketUtils.PROTO_TCP, fromIp, toIp);
        }

        int tcpStart = buf.position();

        PacketUtils.writeTcpHeader(buf, fromPort, toPort, seq, ack, flags, 65535);

        if (payload != null && payloadLen > 0) {
            buf.put(payload, 0, payloadLen);
        }

        PacketUtils.fixTcpChecksum(buf, 0, tcpStart, tcpSegmentLen, fromIp, toIp);

        synchronized (tunWriteLock) {
            try {
                tunOut.write(buf.array(), 0, total);
            } catch (IOException e) {
                Log.w(TAG, "Failed writing TCP packet back to TUN", e);
            }
        }
    }


    private void closeSession(String key, TcpSession session) {

        sessions.remove(key);
        session.state = TcpSession.State.CLOSED;

        try {
            if (session.realSocket != null) {
                session.realSocket.close();
            }
        } catch (IOException ignored) {
        }
    }


    void shutdown() {

        shutdown = true;

        for (Map.Entry<String, TcpSession> e : sessions.entrySet()) {
            closeSession(e.getKey(), e.getValue());
        }

        /*
         * Reset complete TTFB state when VPN session stops.
         */
        globalTtfbCaptured.set(false);
        globalRequestCaptured.set(false);
        globalRequestSentTime = 0L;
        globalFirstByteReceivedTime = 0L;
        globalRequestSentWallTime = 0L;
        globalFirstByteReceivedWallTime = 0L;
        globalTtfbMs = -1L;
        globalTtfbRequestConnectionKey = null;
    }


    void resetGlobalTtfb() {

        /*
         * Reset complete TTFB state when START is pressed
         * / a new VPN session begins.
         */
        globalTtfbCaptured.set(false);
        globalRequestCaptured.set(false);
        globalRequestSentTime = 0L;
        globalFirstByteReceivedTime = 0L;
        globalRequestSentWallTime = 0L;
        globalFirstByteReceivedWallTime = 0L;
        globalTtfbMs = -1L;
        globalTtfbRequestConnectionKey = null;
        Log.d(TAG, "GLOBAL TTFB state RESET");
    }


    private static long readUnsignedInt(byte[] b, int off) {
        return ((long) (b[off] & 0xFF) << 24)
                | ((long) (b[off + 1] & 0xFF) << 16)
                | ((long) (b[off + 2] & 0xFF) << 8)
                | ((long) (b[off + 3] & 0xFF));
    }


    /** Works for both 4-byte (IPv4) and 16-byte (IPv6) address arrays. */
    static String ipStr(byte[] ip) {
        try {
            return InetAddress.getByAddress(ip).getHostAddress();
        } catch (UnknownHostException e) {
            return "invalid-ip";
        }
    }


    /** Per-connection state. */
    static class TcpSession {

        enum State {
            SYN_RCVD,
            ESTABLISHED,
            CLOSING,
            CLOSED
        }


        State state;

        byte[] srcIp;
        int srcPort;

        byte[] dstIp;
        int dstPort;


        long clientNextSeq;
        long deviceSeq;


        Socket realSocket;

        OutputStream realOut;
        InputStream realIn;


        /*
         * These are no longer used for global TTFB.
         *
         * They are retained so that no unrelated session structure
         * is changed.
         */
        final java.util.concurrent.atomic.AtomicBoolean requestSentCaptured =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        final java.util.concurrent.atomic.AtomicBoolean firstByteCaptured =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        final java.util.concurrent.atomic.AtomicBoolean synAckSent =
                new java.util.concurrent.atomic.AtomicBoolean(false);


        volatile long requestSentTime = 0L;

        volatile long firstByteReceivedTime = 0L;

        volatile long ttfbMs = -1L;


        void startRealSocketReaderThread(TcpForwarder forwarder, String key) {

            Log.d(TAG, "Starting TCP Reader Thread...");

            Thread t = new Thread(() -> {

                byte[] buf = new byte[16384];

                try {
                    int n;

                    while ((n = realIn.read(buf)) != -1) {

                        Log.d(TAG, "Received " + n + " bytes from server.");
                        Log.d(TAG, "realIn.read() = " + n);
                        Log.d(TAG, "First byte condition checking");

                        /*
                         * ====================================================
                         * GLOBAL TTFB FIRST-BYTE CAPTURE
                         * ====================================================
                         *
                         * Only the FIRST server response byte of the
                         * complete VPN START -> STOP session is used.
                         *
                         * Any later TCP connection is ignored.
                         */
                        if (n > 0
                                && !forwarder.globalTtfbCaptured.get()
                                && forwarder.globalRequestCaptured.get()
                                && forwarder.globalRequestSentTime > 0
                                && key.equals(forwarder.globalTtfbRequestConnectionKey)) {

                            if (forwarder.globalTtfbCaptured.compareAndSet(false, true)) {

                                /*
                                 * ================================================
                                 * FIRST BYTE TIMESTAMP
                                 * ================================================
                                 */

                                forwarder.globalFirstByteReceivedTime =
                                        System.nanoTime();

                                forwarder.globalFirstByteReceivedWallTime =
                                        System.currentTimeMillis();

                                /*
                                 * ================================================
                                 * TTFB IN MILLISECONDS
                                 * ================================================
                                 */

                                forwarder.globalTtfbMs =
                                        TimeUnit.NANOSECONDS.toMillis(
                                                forwarder.globalFirstByteReceivedTime
                                                        - forwarder.globalRequestSentTime
                                        );

                                /*
                                 * ================================================
                                 * TTFB IN MICROSECONDS
                                 * ================================================
                                 */

                                long ttfbMicros =
                                        TimeUnit.NANOSECONDS.toMicros(
                                                forwarder.globalFirstByteReceivedTime
                                                        - forwarder.globalRequestSentTime
                                        );

                                /*
                                 * ================================================
                                 * HUMAN READABLE TIMESTAMPS
                                 * ================================================
                                 */

                                String requestTimestamp =
                                        forwarder.formatTimestamp(
                                                forwarder.globalRequestSentWallTime
                                        );

                                String firstByteTimestamp =
                                        forwarder.formatTimestamp(
                                                forwarder.globalFirstByteReceivedWallTime
                                        );

                                /*
                                 * ================================================
                                 * FINAL TTFB LOG
                                 * ================================================
                                 */

                                String ttfbLog =
                                        "========== TTFB ==========\n"
                                                + "Resolved IP : "
                                                + forwarder.ipStr(
                                                this.dstIp
                                        )
                                                + "\n"
                                                + "Payload Size   : "
                                                + n
                                                + " bytes\n"
                                                + "\n"
                                                + "Request Sent Time: "
                                                + requestTimestamp
                                                + "\n"
                                                + "First Byte Time  : "
                                                + firstByteTimestamp
                                                + "\n"
                                                + "\n"
                                                + "TTFB = First Byte - Request Sent\n"
                                                + "     = "
                                                + firstByteTimestamp
                                                + " - "
                                                + requestTimestamp
                                                + "\n"
                                                + "     = "
                                                + ttfbMicros
                                                + " µs\n"
                                                + "     = "
                                                + forwarder.globalTtfbMs
                                                + " ms\n"
                                                + "==========================";

                                Log.i(
                                        TAG,
                                        ttfbLog
                                );

                                forwarder.dashboard.logEvent(
                                        ttfbLog,
                                        VpnEvent.Level.INFO,
                                        VpnEvent.Category.TCP
                                );

                                forwarder.reportTtfb(
                                        this,
                                        forwarder.globalTtfbMs,
                                        key
                                );
                            }
                        }

                        if (n > 0) {

                            String rxHeaderLog =
                                    "========== [RX] TCP HEADER ==========\n"
                                            + "Source IP          : " + TcpForwarder.ipStr(dstIp) + "\n"
                                            + "Destination IP     : " + TcpForwarder.ipStr(srcIp) + "\n"
                                            + "Source Port        : " + dstPort + "\n"
                                            + "Destination Port   : " + srcPort + "\n"
                                            + "Payload Length     : " + n + "\n"
                                            + "Sequence Number    : " + deviceSeq + "\n"
                                            + "ACK Number         : " + clientNextSeq + "\n"
                                            + "=====================================";

                            forwarder.dashboard.logEvent(rxHeaderLog, VpnEvent.Level.INFO, VpnEvent.Category.TCP);
                        }

                        forwarder.sendDataToClient(this, buf, n);
                    }

                } catch (IOException ignored) {
                    // socket closed/reset
                } finally {
                    forwarder.sendFinToClient(this);
                }

            }, "TcpRead-" + key);

            t.setDaemon(true);
            t.start();

            Log.d(TAG, "TCP Reader Thread Started.");
        }
    }
    private String formatTimestamp(long timestamp) {

        return new java.text.SimpleDateFormat(
                "HH:mm:ss:SSS",
                java.util.Locale.getDefault()
        ).format(
                new java.util.Date(timestamp)
        );
    }
}