package com.example.vpntest;

import android.icu.text.IDNA;
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


public class TcpForwarder {

    private static final String TAG = "VPN_TcpForwarder : ";

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

//    private final java.util.concurrent.atomic.AtomicBoolean globalRequestCaptured =
//            new java.util.concurrent.atomic.AtomicBoolean(false);

    // Tracks whether the first outgoing IP-match event has already been logged
    private final java.util.concurrent.atomic.AtomicBoolean firstOutgoingIpMatchLogged =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    // Tracks whether the first incoming IP-match event has already been logged
    private final java.util.concurrent.atomic.AtomicBoolean firstIncomingIpMatchLogged =
            new java.util.concurrent.atomic.AtomicBoolean(false);
    private final java.util.concurrent.atomic.AtomicInteger outgoingIpMatchCount =
            new java.util.concurrent.atomic.AtomicInteger(0);

    private final java.util.concurrent.atomic.AtomicInteger incomingIpMatchCount =
            new java.util.concurrent.atomic.AtomicInteger(0);

    // Total TCP packets forwarded device -> real server (all destinations, matched or not)
    // Total TCP packets forwarded device -> real server
    private final java.util.concurrent.atomic.AtomicInteger totalPacketsSent =
            new java.util.concurrent.atomic.AtomicInteger(0);

    // Total TCP packets received real server -> device
    private final java.util.concurrent.atomic.AtomicInteger totalPacketsReceived =
            new java.util.concurrent.atomic.AtomicInteger(0);

    /*
     * ============================================================
     * TCP TRANSMISSION / RETRANSMISSION TRACKING
     * ============================================================
     *
     * Each TCP session maintains the sequence ranges that have
     * already been successfully transmitted to the real server.
     *
     * Example:
     *
     * First packet:
     * SEQ = 1000
     * LEN = 500
     * Range = 1000 - 1500
     *
     * Second packet:
     * SEQ = 1500
     * LEN = 500
     * Range = 1500 - 2000
     *
     * If SEQ = 1000 and LEN = 500 comes again,
     * it is detected as a retransmission.
     */
    private final java.util.concurrent.atomic.AtomicLong totalTcpTransmissions =
            new java.util.concurrent.atomic.AtomicLong(0);

    private final java.util.concurrent.atomic.AtomicLong totalTcpTransmissionBytes =
            new java.util.concurrent.atomic.AtomicLong(0);

    private final java.util.concurrent.atomic.AtomicLong totalTcpRetransmissions =
            new java.util.concurrent.atomic.AtomicLong(0);

    private final java.util.concurrent.atomic.AtomicLong totalTcpRetransmissionBytes =
            new java.util.concurrent.atomic.AtomicLong(0);

    /*
     * Monotonic timestamps.
     *
     * Used ONLY for accurate TTFB duration calculation.
     */
    //old ttbf logic
//    private volatile long globalRequestSentTime = 0L;
//
//    private volatile long globalFirstByteReceivedTime = 0L;
//
//
//    private volatile long globalRequestSentWallTime = 0L;
//
//    private volatile long globalFirstByteReceivedWallTime = 0L;
//
//    private volatile long globalTtfbMs = -1L;
    private volatile long tcpHandshakeSynSentNano = 0L;

    private volatile long tcpHandshakeAckNano = 0L;

    private volatile long tcpHandshakeNano = -1L;

    private volatile double tcpHandshakeMs = -1.0;


    /*
     * ============================================================
     * TCP HANDSHAKE - PER CONNECTION T0
     * ============================================================
     *
     * Every TCP connection gets its own T0.
     *
     * Key:
     * Source IP + Source Port + Destination IP + Destination Port
     *
     * Example:
     * 10.0.0.2:56714 -> 207.45.72.1:443
     *
     * The first SYN for that connection is stored.
     *
     * IMPORTANT:
     * putIfAbsent() guarantees that a SYN retransmission does
     * not overwrite the original T0.
     */
    private final Map<String, Long> tcpHandshakeT0ByConnection =
            new ConcurrentHashMap<>();


    /*
     * ============================================================
     * TCP HANDSHAKE - FIRST VALID MATCH
     * ============================================================
     *
     * Once the first TCP connection produces a valid T0/T1 pair,
     * tcpHandshakeCaptured becomes TRUE.
     *
     * Any later valid connection is logged but does NOT overwrite
     * the already selected T0/T1.
     */
    private final java.util.concurrent.atomic.AtomicBoolean
            tcpHandshakeCaptured =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    /*
     * ============================================================
     * TCP CONNECTION TIME
     * ============================================================
     *
     * This is separate from the existing TCP HANDSHAKE calculation.
     *
     * T0 = First device SYN received by VPN
     * T1 = Real server socket.connect() completed
     *
     * TCP Connection Time = T1 - T0
     */

    private volatile long tcpConnectionStartNano = 0L;

    private volatile long tcpConnectionEndNano = 0L;

    private volatile long tcpConnectionNano = -1L;

    private volatile double tcpConnectionMs = -1.0;

    private final java.util.concurrent.atomic.AtomicBoolean
            tcpConnectionStartCaptured =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    private final java.util.concurrent.atomic.AtomicBoolean
            tcpConnectionCaptured =
            new java.util.concurrent.atomic.AtomicBoolean(false);
    private volatile long globalOutgoingIpMatchTime = 0L;

    private static volatile long webViewT0Nano = 0L;

    public static void setWebViewT0(long t0Nano) {
        webViewT0Nano = t0Nano;
    }

    private volatile long globalIncomingIpMatchTime = 0L;

    private volatile long globalOutgoingIpMatchWallTime = 0L;

    private volatile long globalDnsT0Nano = 0L;
    private volatile long globalIncomingIpMatchWallTime = 0L;

    /*
     * =====================================================
     * TLS 0x17 T1
     * =====================================================
     *
     * T1 is captured when the first received TLS
     * Application Data record (ContentType = 0x17)
     * is detected.
     */
    /*
     * =====================================================
     * TLS HANDSHAKE TIMING
     * =====================================================
     *
     * T0 = First TX TLS Handshake record (0x16)
     * T1 = First RX TLS Application Data record (0x17)
     *
     * TLS Handshake Time = T1 - T0
     */
    private volatile long globalTlsRecordType16T0Nano = 0L;
    private volatile long globalTlsRecordType16T0WallTime = 0L;

    private final java.util.concurrent.atomic.AtomicBoolean
            tlsRecordType16Captured =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    private volatile long globalTlsRecordType17T1Nano = 0L;
    private volatile long globalTlsRecordType17T1WallTime = 0L;

    private final java.util.concurrent.atomic.AtomicBoolean
            tlsRecordType17Captured =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    private volatile long globalTlsHandshakeNano = -1L;
    private volatile double globalTlsHandshakeMs = -1.0;

    private volatile long globalTtfbMs = -1L;

    private volatile String globalTtfbRequestConnectionKey = null;
    private volatile String globalTtfbRequestDestinationIp = null;
    private volatile String globalTtfbRequestResolvedIp = null;
    private volatile int globalTtfbRequestPayloadSize = 0;

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

        String key = parsed.connectionKey();
        TcpSession session = sessions.get(key);
        StringBuilder tcpHeaderLog = new StringBuilder();
        tcpHeaderLog.append("========== [TX] TCP/IP HEADER ==========\n")

                .append("IP Version         : IPv").append(version).append("\n")
                .append("Source IP          : ").append(ipStr(srcIp)).append("\n")
                .append("Destination IP     : ").append(ipStr(dstIp)).append("\n")
                .append("Host Name          : ")
                .append(session != null ? session.serverName : "Unknown")
                .append("\n")
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
        dashboard.logEvent(TAG+tcpHeaderLog.toString(), VpnEvent.Level.INFO, VpnEvent.Category.TCP);



        boolean isSyn = (flags & PacketUtils.TCP_SYN) != 0;
        boolean isAck = (flags & PacketUtils.TCP_ACK) != 0;
        boolean isFin = (flags & PacketUtils.TCP_FIN) != 0;
        boolean isRst = (flags & PacketUtils.TCP_RST) != 0;

        Log.d(TAG, "Flags: SYN=" + isSyn + " ACK=" + isAck + " FIN=" + isFin + " RST=" + isRst);



        if (session != null) {
            dashboard.logEvent(
                    TAG
                            + "Session State = " + session.state,
                    VpnEvent.Level.INFO,
                    VpnEvent.Category.TCP
            );
        }

        if (flags == 0x02) {

            /*
             * ============================================================
             * TCP HANDSHAKE T0 - PER CONNECTION
             * ============================================================
             *
             * Every TCP connection is tracked independently using:
             * Source IP + Source Port + Destination IP + Destination Port
             *
             * putIfAbsent() is critical here. If the device retransmits
             * the SYN, the original T0 is preserved and cannot be replaced.
             */

            String synSourceIp = ipStr(srcIp);
            String synDestinationIp = ipStr(dstIp);

            long synDebugNano = System.nanoTime();
            long synDebugWallTime = System.currentTimeMillis();

            String synConnectionKey =
                    synSourceIp + ":" + srcPort
                            + "->"
                            + synDestinationIp + ":" + dstPort;

            Long existingT0 =
                    tcpHandshakeT0ByConnection.putIfAbsent(
                            synConnectionKey,
                            synDebugNano
                    );

            boolean firstSynForConnection = existingT0 == null;
            long connectionT0 = firstSynForConnection
                    ? synDebugNano
                    : existingT0;

            String synDebugLog =
                    "========== TCP CONNECTION | SYN CANDIDATE ==========\n"
                            + "Connection Key     : " + synConnectionKey + "\n"
                            + "Source IP          : " + synSourceIp + "\n"
                            + "Source Port        : " + srcPort + "\n"
                            + "Destination IP     : " + synDestinationIp + "\n"
                            + "Destination Port   : " + dstPort + "\n"
                            + "Sequence Number    : " + seq + "\n"
                            + "ACK Number         : " + ack + "\n"
                            + "TCP Flags          : 0x"
                            + String.format(
                            java.util.Locale.US,
                            "%02X",
                            flags
                    ) + "\n"
                            + "SYN Timestamp Nano : " + synDebugNano + " ns\n"
                            + "Timestamp          : "
                            + formatTimestamp(synDebugWallTime) + "\n"
                            + "First SYN          : " + firstSynForConnection + "\n"
                            + "Existing T0        : "
                            + (existingT0 != null ? existingT0 + " ns" : "NONE") + "\n"
                            + "Selected T0        : " + connectionT0 + " ns\n"
                            + "Existing Session   : "
                            + (session != null) + "\n"
                            + "Session State      : "
                            + (session != null ? session.state : "NONE") + "\n"
                            + "====================================================";

            Log.i(TAG, synDebugLog);
            dashboard.logToFile(TAG + synDebugLog);

            if (firstSynForConnection) {

                String t0SavedLog =
                        "========== TCP HANDSHAKE T0 SAVED | NEW CONNECTION =========="
                                + "\nConnection Key     : " + synConnectionKey
                                + "\nSource IP          : " + synSourceIp
                                + "\nSource Port        : " + srcPort
                                + "\nDestination IP     : " + synDestinationIp
                                + "\nDestination Port   : " + dstPort
                                + "\nT0                  : " + connectionT0 + " ns"
                                + "\nTimestamp           : " + formatTimestamp(synDebugWallTime)
                                + "\nMap Size            : " + tcpHandshakeT0ByConnection.size()
                                + "\n============================================================";

                Log.i(TAG, t0SavedLog);
                dashboard.logToFile(TAG + t0SavedLog);

                String txSynLog =
                        "========== TCP HANDSHAKE | TX SYN ==========" + "\n"
                                + "Source IP          : " + synSourceIp + "\n"
                                + "Destination IP     : " + synDestinationIp + "\n"
                                + "Source Port        : " + srcPort + "\n"
                                + "Destination Port   : " + dstPort + "\n"
                                + "Sequence Number    : " + seq + "\n"
                                + "ACK Number         : " + ack + "\n"
                                + "TCP Flags          : 0x"
                                + String.format(java.util.Locale.US, "%02X", flags) + "\n"
                                + "Window Size        : " + windowSize + "\n"
                                + "Checksum           : 0x"
                                + String.format(java.util.Locale.US, "%04X", checksum) + "\n"
                                + "TCP Header Length  : " + dataOffsetBytes + " bytes\n"
                                + "Payload Length     : " + payloadLen + " bytes\n"
                                + "Handshake T0       : " + connectionT0 + " ns\n"
                                + "Timestamp          : " + formatTimestamp(synDebugWallTime) + "\n"
                                + "Connection Key     : " + synConnectionKey + "\n"
                                + "==============================================";

                Log.i(TAG, txSynLog);
                dashboard.logToFile(TAG + txSynLog);

            } else {

                String retransmissionLog =
                        "========== TCP HANDSHAKE SYN RETRANSMISSION ==========" + "\n"
                                + "Connection Key     : " + synConnectionKey + "\n"
                                + "Current SYN T0     : " + synDebugNano + " ns\n"
                                + "Original T0        : " + existingT0 + " ns\n"
                                + "Action              : ORIGINAL T0 PRESERVED\n"
                                + "Reason              : Same 4-tuple already has T0\n"
                                + "Timestamp           : " + formatTimestamp(synDebugWallTime) + "\n"
                                + "========================================================";

                Log.d(TAG, retransmissionLog);
                dashboard.logToFile(TAG + retransmissionLog);
            }

            /*
             * ============================================================
             * TCP CONNECTION TIME - T0
             * ============================================================
             *
             * This remains a separate global metric and is intentionally
             * not used for the per-connection TCP handshake calculation.
             */
            if (tcpConnectionStartCaptured.compareAndSet(false, true)) {

                tcpConnectionStartNano = synDebugNano;

                String tcpConnectionStartLog =
                        "========== TCP CONNECTION | T0 SYN ==========\n"
                                + "Source IP          : " + synSourceIp + "\n"
                                + "Destination IP     : " + synDestinationIp + "\n"
                                + "Source Port        : " + srcPort + "\n"
                                + "Destination Port   : " + dstPort + "\n"
                                + "Sequence Number    : " + seq + "\n"
                                + "TCP Flags          : 0x"
                                + String.format(java.util.Locale.US, "%02X", flags) + "\n"
                                + "Connection T0      : " + tcpConnectionStartNano + " ns\n"
                                + "Timestamp          : " + formatTimestamp(synDebugWallTime) + "\n"
                                + "==============================================";

                Log.i(TAG, tcpConnectionStartLog);
                dashboard.logToFile(TAG + tcpConnectionStartLog);
            }
        }
        if (isSyn && !isAck) {

            if (session != null) {

                if (session.state == TcpSession.State.SYN_RCVD
                        || session.state == TcpSession.State.ESTABLISHED) {

                    if (session.synAckSent.get()) {
                        Log.d(TAG, "Retransmitted SYN for existing session " + key + ", re-sending SYN-ACK.");
                        dashboard.logEvent(TAG+"Retransmitted SYN for existing session " + key + ", re-sending SYN-ACK.",
                                VpnEvent.Level.INFO,
                                VpnEvent.Category.TCP
                        );
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

        if (session.state == TcpSession.State.SYN_RCVD
                && flags == 0x10) {

            /*
             * ============================================================
             * TCP HANDSHAKE T1 - PER CONNECTION
             * ============================================================
             *
             * T1 is accepted only when the ACK belongs to the exact same
             * 4-tuple that owns the stored T0.
             *
             * tcpHandshakeCaptured is GLOBAL only for selecting the FIRST
             * valid T0/T1 pair. It does not affect connection validation.
             */

            String t1SourceIp = ipStr(srcIp);
            String t1DestinationIp = ipStr(dstIp);

            long t1CandidateNano = System.nanoTime();
            long t1CandidateWallTime = System.currentTimeMillis();

            String t1ConnectionKey =
                    t1SourceIp + ":" + srcPort
                            + "->"
                            + t1DestinationIp + ":" + dstPort;

            Long connectionT0 =
                    tcpHandshakeT0ByConnection.get(t1ConnectionKey);

            boolean ackMatchesSession =
                    session.srcIp != null
                            && session.dstIp != null
                            && session.srcPort == srcPort
                            && session.dstPort == dstPort
                            && ipStr(session.srcIp).equals(t1SourceIp)
                            && ipStr(session.dstIp).equals(t1DestinationIp);

            boolean t1MatchesT0 =
                    connectionT0 != null
                            && ackMatchesSession;

            String t1DebugLog =
                    "========== TCP CONNECTION | T1 CANDIDATE ==========\n"
                            + "Connection Key       : " + t1ConnectionKey + "\n"
                            + "\n"
                            + "ACK Packet\n"
                            + "Source IP            : " + t1SourceIp + "\n"
                            + "Source Port          : " + srcPort + "\n"
                            + "Destination IP       : " + t1DestinationIp + "\n"
                            + "Destination Port     : " + dstPort + "\n"
                            + "Sequence Number      : " + seq + "\n"
                            + "ACK Number           : " + ack + "\n"
                            + "TCP Flags            : 0x"
                            + String.format(java.util.Locale.US, "%02X", flags) + "\n"
                            + "T1 Candidate         : " + t1CandidateNano + " ns\n"
                            + "Timestamp             : " + formatTimestamp(t1CandidateWallTime) + "\n"
                            + "\n"
                            + "PER-CONNECTION T0\n"
                            + "T0 Found             : " + (connectionT0 != null) + "\n"
                            + "Connection T0        : "
                            + (connectionT0 != null ? connectionT0 + " ns" : "NOT_FOUND") + "\n"
                            + "\n"
                            + "SESSION\n"
                            + "Session Source IP    : " + ipStr(session.srcIp) + "\n"
                            + "Session Source Port  : " + session.srcPort + "\n"
                            + "Session Destination  : " + ipStr(session.dstIp) + "\n"
                            + "Session Destination Port : " + session.dstPort + "\n"
                            + "Session State        : " + session.state + "\n"
                            + "ACK Matches Session  : " + ackMatchesSession + "\n"
                            + "T1 Matches T0        : " + t1MatchesT0 + "\n"
                            + "First Valid Selected : " + tcpHandshakeCaptured.get() + "\n"
                            + "====================================================";

            Log.i(TAG, t1DebugLog);
            dashboard.logToFile(TAG + t1DebugLog);

            String t0SourceIpForComparison =
                    connectionT0 != null ? t1SourceIp : "NOT_FOUND";

            String t0SourcePortForComparison =
                    connectionT0 != null ? String.valueOf(srcPort) : "NOT_FOUND";

            String t0DestinationIpForComparison =
                    connectionT0 != null ? t1DestinationIp : "NOT_FOUND";

            String t0DestinationPortForComparison =
                    connectionT0 != null ? String.valueOf(dstPort) : "NOT_FOUND";

            boolean sourceIpMatch =
                    connectionT0 != null
                            && t0SourceIpForComparison.equals(t1SourceIp);

            boolean sourcePortMatch =
                    connectionT0 != null
                            && Integer.parseInt(t0SourcePortForComparison) == srcPort;

            boolean destinationIpMatch =
                    connectionT0 != null
                            && t0DestinationIpForComparison.equals(t1DestinationIp);

            boolean destinationPortMatch =
                    connectionT0 != null
                            && Integer.parseInt(t0DestinationPortForComparison) == dstPort;

            String comparisonResult =
                    t1MatchesT0
                            ? "VALID MATCH"
                            : "NO MATCH";

            String t0T1ComparisonLog =
                    "========== TCP HANDSHAKE | T0 vs T1 COMPARISON ==========\n"
                            + "Connection Key       : " + t1ConnectionKey + "\n"
                            + "\n"

                            + "FIELD                | T0 (SYN)              | T1 (ACK)\n"
                            + "------------------------------------------------------------\n"
                            + "Source IP            | "
                            + t0SourceIpForComparison
                            + " | "
                            + t1SourceIp + "\n"

                            + "Source Port          | "
                            + t0SourcePortForComparison
                            + " | "
                            + srcPort + "\n"

                            + "Destination IP       | "
                            + t0DestinationIpForComparison
                            + " | "
                            + t1DestinationIp + "\n"

                            + "Destination Port     | "
                            + t0DestinationPortForComparison
                            + " | "
                            + dstPort + "\n"

                            + "T0 Timestamp         | "
                            + (connectionT0 != null
                            ? connectionT0 + " ns"
                            : "NOT_FOUND")
                            + " | "
                            + t1CandidateNano + " ns\n"

                            + "------------------------------------------------------------\n"

                            + "Source IP Match      : " + sourceIpMatch + "\n"
                            + "Source Port Match    : " + sourcePortMatch + "\n"
                            + "Destination IP Match : " + destinationIpMatch + "\n"
                            + "Destination Port Match: " + destinationPortMatch + "\n"
                            + "ACK Matches Session  : " + ackMatchesSession + "\n"
                            + "T0 Found             : " + (connectionT0 != null) + "\n"
                            + "T1 Matches T0        : " + t1MatchesT0 + "\n"
                            + "First Valid Selected : " + tcpHandshakeCaptured.get() + "\n"
                            + "Comparison Result    : " + comparisonResult + "\n"

                            + "============================================================";

            Log.i(TAG, t0T1ComparisonLog);
            dashboard.logToFile(TAG + t0T1ComparisonLog);

            if (!t1MatchesT0) {

                String ignoredLog =
                        "========== TCP HANDSHAKE T1 IGNORED ==========" + "\n"
                                + "Connection Key       : " + t1ConnectionKey + "\n"
                                + "Reason               : No matching per-connection T0\n"
                                + "T0 Found             : " + (connectionT0 != null) + "\n"
                                + "ACK Matches Session  : " + ackMatchesSession + "\n"
                                + "T1 Candidate         : " + t1CandidateNano + " ns\n"
                                + "Timestamp            : " + formatTimestamp(t1CandidateWallTime) + "\n"
                                + "Action               : HANDSHAKE MEASUREMENT NOT SELECTED\n"
                                + "Action               : SESSION STILL CONTINUES\n"
                                + "==============================================";

                Log.d(TAG, ignoredLog);
                dashboard.logToFile(TAG + ignoredLog);

            } else if (tcpHandshakeCaptured.compareAndSet(false, true)) {

                /*
                 * ============================================================
                 * FIRST VALID MATCH SELECTED
                 * ============================================================
                 *
                 * The exact T0 from this connection is used. Do NOT call
                 * System.nanoTime() again for T0 because that would measure
                 * a later point than the original SYN.
                 */

                tcpHandshakeSynSentNano = connectionT0;
                tcpHandshakeAckNano = t1CandidateNano;

                tcpHandshakeNano =
                        tcpHandshakeAckNano - tcpHandshakeSynSentNano;

                tcpHandshakeMs =
                        tcpHandshakeNano / 1_000_000.0;

                if (tcpHandshakeNano >= 0L) {
                    dashboard.recordTcpHandshake(tcpHandshakeNano);
                }

                long ackWallTime = t1CandidateWallTime;

                String firstValidLog =
                        "========== TCP HANDSHAKE | FIRST VALID MATCH SELECTED ==========" + "\n"
                                + "Connection Key       : " + t1ConnectionKey + "\n"
                                + "Source IP            : " + t1SourceIp + "\n"
                                + "Source Port          : " + srcPort + "\n"
                                + "Destination IP       : " + t1DestinationIp + "\n"
                                + "Destination Port     : " + dstPort + "\n"
                                + "\n"
                                + "Handshake T0         : " + tcpHandshakeSynSentNano + " ns\n"
                                + "Handshake T1         : " + tcpHandshakeAckNano + " ns\n"
                                + "T1 - T0              : " + tcpHandshakeNano + " ns\n"
                                + "Handshake Time       : "
                                + String.format(java.util.Locale.US, "%.3f", tcpHandshakeMs)
                                + " ms\n"
                                + "T0/T1 Match          : TRUE\n"
                                + "Selection            : FIRST VALID MATCH\n"
                                + "Future Matches       : LOGGED ONLY / WILL NOT OVERWRITE\n"
                                + "Timestamp            : " + formatTimestamp(ackWallTime) + "\n"
                                + "==============================================================";

                Log.i(TAG, firstValidLog);
                dashboard.logToFile(TAG + firstValidLog);

                String txAckHandshakeLog =
                        "========== TCP HANDSHAKE | TX ACK ==========" + "\n"
                                + "Source IP          : " + t1SourceIp + "\n"
                                + "Destination IP     : " + t1DestinationIp + "\n"
                                + "Source Port        : " + srcPort + "\n"
                                + "Destination Port   : " + dstPort + "\n"
                                + "Sequence Number    : " + seq + "\n"
                                + "ACK Number         : " + ack + "\n"
                                + "TCP Flags          : 0x10\n"
                                + "TCP Header Length  : " + dataOffsetBytes + " bytes\n"
                                + "Payload Length     : " + payloadLen + " bytes\n"
                                + "Timestamp          : " + formatTimestamp(ackWallTime) + "\n"
                                + "Connection Key     : " + t1ConnectionKey + "\n"
                                + "Handshake T0       : " + tcpHandshakeSynSentNano + " ns\n"
                                + "Handshake T1       : " + tcpHandshakeAckNano + " ns\n"
                                + "T1 - T0            : " + tcpHandshakeAckNano + " - "
                                + tcpHandshakeSynSentNano + " = " + tcpHandshakeNano + " ns\n"
                                + "Handshake Time     : "
                                + String.format(java.util.Locale.US, "%.3f", tcpHandshakeMs)
                                + " ms\n"
                                + "==============================================";

                Log.i(TAG, txAckHandshakeLog);
                dashboard.logToFile(TAG + txAckHandshakeLog);

                dashboard.logToFile(
                        TAG + "TCP Handshake completed - FIRST VALID MATCH SELECTED."
                );

            } else {

                /*
                 * ============================================================
                 * VALID MATCH BUT NOT SELECTED
                 * ============================================================
                 *
                 * Another connection already produced the first valid pair.
                 * This connection is still valid, but it MUST NOT overwrite
                 * the selected measurement.
                 */

                String laterValidLog =
                        "========== TCP HANDSHAKE | VALID MATCH IGNORED ==========" + "\n"
                                + "Connection Key       : " + t1ConnectionKey + "\n"
                                + "Connection T0        : " + connectionT0 + " ns\n"
                                + "Connection T1        : " + t1CandidateNano + " ns\n"
                                + "Connection T1 - T0   : "
                                + (t1CandidateNano - connectionT0) + " ns\n"
                                + "Reason               : FIRST VALID MATCH ALREADY SELECTED\n"
                                + "Selected T0          : " + tcpHandshakeSynSentNano + " ns\n"
                                + "Selected T1          : " + tcpHandshakeAckNano + " ns\n"
                                + "Selected Duration    : " + tcpHandshakeNano + " ns\n"
                                + "Action               : DO NOT OVERWRITE\n"
                                + "Action               : SESSION STILL CONTINUES\n"
                                + "Timestamp            : " + formatTimestamp(t1CandidateWallTime) + "\n"
                                + "===========================================================";

                Log.i(TAG, laterValidLog);
                dashboard.logToFile(TAG + laterValidLog);
            }

            /*
             * Session establishment is independent of which connection was
             * selected for the global handshake metric.
             */
            session.state = TcpSession.State.ESTABLISHED;

            dashboard.logToFile(
                    TAG
                            + "TCP SESSION ESTABLISHED"
                            + "\nConnection Key     : " + key
                            + "\nHandshake Selected : " + tcpHandshakeCaptured.get()
                            + "\nSession State      : " + session.state
            );

            session.startRealSocketReaderThread(this, key);
        }

        dashboard.logToFile(TAG+"payload len and sessionstate : " + payloadLen + " " + session.state);


        if (payloadLen > 0
                && session.state == TcpSession.State.ESTABLISHED) {

            byte[] data = new byte[payloadLen];

            System.arraycopy(
                    packet,
                    payloadOffset,
                    data,
                    0,
                    payloadLen
            );
            /*
             * ============================================================
             * TCP TRANSMISSION / RETRANSMISSION DETECTION
             * ============================================================
             *
             * Current packet:
             *
             * SEQ       = seq
             * PAYLOAD   = payloadLen
             * END SEQ   = seq + payloadLen
             *
             * We compare this sequence range with previously transmitted
             * ranges of the SAME TCP session.
             */
            long currentSeqStart = seq;
            long currentSeqEnd = seq + payloadLen;

            TcpSegmentRecord overlappingSegment = null;
            long retransmittedBytes = 0L;


            /*
             * Check whether any part of this sequence range was already
             * transmitted.
             */
            for (TcpSegmentRecord oldSegment :
                    session.transmittedSegments.values()) {

                long overlapStart = Math.max(
                        currentSeqStart,
                        oldSegment.seqStart
                );

                long overlapEnd = Math.min(
                        currentSeqEnd,
                        oldSegment.seqEnd
                );

                /*
                 * If overlapStart < overlapEnd,
                 * some bytes in the current packet were already sent.
                 */
                if (overlapStart < overlapEnd) {

                    long overlapBytes = overlapEnd - overlapStart;

                    if (overlapBytes > retransmittedBytes) {
                        retransmittedBytes = overlapBytes;
                        overlappingSegment = oldSegment;
                    }
                }
            }


            boolean isRetransmission = retransmittedBytes > 0;


            /*
             * ============================================================
             * TRANSMISSION / RETRANSMISSION LOG
             * ============================================================
             */
            long packetTimestampNano = System.nanoTime();
            long packetTimestampWall = System.currentTimeMillis();

            String transmissionType =
                    isRetransmission
                            ? "RETRANSMISSION"
                            : "TRANSMISSION";


            if (!isRetransmission) {
                Log.i(TAG, "TCP Retransmission Count: 0");

                dashboard.logToFile(
                        TAG + "TCP Retransmission Count: 0"
                );
            }

            if (isRetransmission) {

                long retransmissionCount =
                        totalTcpRetransmissions.incrementAndGet();

                long retransmissionByteCount =
                        totalTcpRetransmissionBytes.addAndGet(
                                retransmittedBytes
                        );

                String retransmissionLog =
                        "========== TCP RETRANSMISSION COUNT AND DATA ==========\n"
                                + "Direction          : TX / DEVICE -> SERVER\n"
                                + "Protocol           : TCP\n"
                                + "Connection Key     : " + key + "\n"
                                + "Host Name          : "
                                + (session.serverName != null
                                ? session.serverName
                                : "Unknown") + "\n"
                                + "Server IP          : "
                                + (session.serverIp != null
                                ? session.serverIp
                                : ipStr(dstIp)) + "\n"
                                + "Source IP          : " + ipStr(srcIp) + "\n"
                                + "Destination IP     : " + ipStr(dstIp) + "\n"
                                + "Source Port        : " + srcPort + "\n"
                                + "Destination Port   : " + dstPort + "\n"
                                + "Sequence Number    : " + seq + "\n"
                                + "Sequence End       : " + currentSeqEnd + "\n"
                                + "ACK Number         : " + ack + "\n"
                                + "TCP Flags          : 0x"
                                + String.format(
                                java.util.Locale.US,
                                "%02X",
                                flags
                        ) + "\n"
                                + "TCP Header Length  : "
                                + dataOffsetBytes + " bytes\n"
                                + "Payload Length     : "
                                + payloadLen + " bytes\n"
                                + "Previous SEQ Start : "
                                + overlappingSegment.seqStart + "\n"
                                + "Previous SEQ End   : "
                                + overlappingSegment.seqEnd + "\n"
                                + "Retransmitted Bytes: "
                                + retransmittedBytes + " bytes\n"
                                + "Retransmission Count : "
                                + retransmissionCount + "\n"
                                + "Total Retrans Bytes: "
                                + retransmissionByteCount + " bytes\n"
                                + "Timestamp          : "
                                + formatTimestamp(packetTimestampWall) + "\n"
                                + "Timestamp Nano     : "
                                + packetTimestampNano + " ns\n"
                                + "Raw Packet HEX     : "
                                + bytesToHex(packet, length) + "\n"
                                + "==============================================";

                Log.w(TAG, retransmissionLog);

                dashboard.logToFile(
                        TAG + retransmissionLog
                );
                dashboard.recordTcpRetransmissionCount(
                        retransmissionCount
                );

            } else {

                long transmissionCount =
                        totalTcpTransmissions.incrementAndGet();

                long transmissionByteCount =
                        totalTcpTransmissionBytes.addAndGet(
                                payloadLen
                        );

                String transmissionLog =
                        "========== TCP DATA TRANSMISSION ==========\n"
                                + "Direction          : TX / DEVICE -> SERVER\n"
                                + "Protocol           : TCP\n"
                                + "Connection Key     : " + key + "\n"
                                + "Host Name          : "
                                + (session.serverName != null
                                ? session.serverName
                                : "Unknown") + "\n"
                                + "Server IP          : "
                                + (session.serverIp != null
                                ? session.serverIp
                                : ipStr(dstIp)) + "\n"
                                + "Source IP          : " + ipStr(srcIp) + "\n"
                                + "Destination IP     : " + ipStr(dstIp) + "\n"
                                + "Source Port        : " + srcPort + "\n"
                                + "Destination Port   : " + dstPort + "\n"
                                + "Sequence Number    : " + seq + "\n"
                                + "Sequence End       : " + currentSeqEnd + "\n"
                                + "ACK Number         : " + ack + "\n"
                                + "TCP Flags          : 0x"
                                + String.format(
                                java.util.Locale.US,
                                "%02X",
                                flags
                        ) + "\n"
                                + "TCP Header Length  : "
                                + dataOffsetBytes + " bytes\n"
                                + "Payload Length     : "
                                + payloadLen + " bytes\n"
                                + "Transmission No.   : "
                                + transmissionCount + "\n"
                                + "Total TX Bytes     : "
                                + transmissionByteCount + " bytes\n"
                                + "Timestamp          : "
                                + formatTimestamp(packetTimestampWall) + "\n"
                                + "Timestamp Nano     : "
                                + packetTimestampNano + " ns\n"
                                + "Raw Packet HEX     : "
                                + bytesToHex(packet, length) + "\n"
                                + "============================================";

                Log.i(TAG, transmissionLog);

                dashboard.logToFile(
                        TAG + transmissionLog
                );
            }

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

            boolean isFirstOutgoingMatch = false;

            if (destinationIpMatched) {

                isFirstOutgoingMatch =
                        firstOutgoingIpMatchLogged.compareAndSet(false, true);

                int matchCount = outgoingIpMatchCount.incrementAndGet();

                String evtName = isFirstOutgoingMatch ? "OG_IP_MATCH" : "O_IP_MATCH";

                if (isFirstOutgoingMatch) {

                    globalOutgoingIpMatchTime =
                            System.nanoTime();

                    /*
                     * =========================================================
                     * DNS TRANSACTION CORRELATION
                     * =========================================================
                     *
                     * Search completed DNS transactions.
                     *
                     * Only the DNS transaction whose Answer IP matches
                     * this TCP destination IP is selected.
                     *
                     * The returned value is that EXACT transaction's T0.
                     */
                    long matchedDnsT0 =
                            UdpForwarder.recordDnsLookupForResolvedIp(
                                    destinationIp
                            );

                    dashboard.logToFile(
                            TAG
                                    + "DNS UI CORRELATION REQUEST\n"
                                    + "TCP Destination IP : "
                                    + destinationIp
                                    + "\n"
                                    + "Resolved IP Set    : "
                                    + websiteResolvedIps
                                    + "\n"
                                    + "Matched DNS T0     : "
                                    + matchedDnsT0
                                    + " ns\n"
                                    + "DNS UI Match       : "
                                    + (matchedDnsT0 > 0L
                                    ? "FOUND"
                                    : "NOT_FOUND")
                    );

                    /*
                     * =========================================================
                     * USE ONLY MATCHED DNS TRANSACTION T0
                     * =========================================================
                     */
                    if (matchedDnsT0 > 0L) {

                        globalDnsT0Nano =
                                matchedDnsT0;

                        Log.d(
                                TAG,
                                "MATCHED DNS T0 SELECTED = "
                                        + globalDnsT0Nano
                                        + " ns"
                        );

                    } else {

                        /*
                         * No DNS transaction had an Answer IP matching
                         * this TCP destination IP.
                         *
                         * Therefore DO NOT use latest DNS T0.
                         */
                        globalDnsT0Nano = 0L;

                        Log.d(
                                TAG,
                                "NO MATCHED DNS TRANSACTION -> "
                                        + "DNS T0 will NOT be used for TTFB"
                        );
                    }

                    globalOutgoingIpMatchWallTime =
                            System.currentTimeMillis();

                    globalTtfbRequestDestinationIp =
                            destinationIp;

                    globalTtfbRequestResolvedIp =
                            destinationIp;

                    globalTtfbRequestPayloadSize =
                            payloadLen;

                    globalTtfbRequestConnectionKey =
                            key;


//                    dashboard.logToFile(
//                            TAG +
//                                    "OG_IP_MATCH T0_Time timestamp captured = "
//                                    + globalOutgoingIpMatchTime
//                                    + " ns"
//                    );
//                    dashboard.logToFile(
//                            TAG +
//                                    "OG_IP_MATCH T0_Time timestamp captured = "
//                                    + globalOutgoingIpMatchTime
//                                    + " ns\n"
//                                    + "Source IP       : " + ipStr(srcIp) + "\n"
//                                    + "Destination IP  : " + ipStr(dstIp) + "\n"
//                                    + "Source Port     : " + srcPort + "\n"
//                                    + "Destination Port: " + dstPort + "\n"
//                                    + "Connection Key : " + key + "\n"
//                                    + "Session State  : " + session.state + "\n"
//                                    + "Match Count    : " + matchCount + "\n"
//                                    + "Protocol        : TCP\n"
//                                    + "Packet Length   : " + length + " bytes\n"
//                                    + "Payload Length  : " + payloadLen + " bytes\n"
//                                    + "Timestamp       : "
//                                    + formatTimestamp(globalOutgoingIpMatchWallTime)
//                                    + "\n"
//                                    + "Timestamp Nano  : "
//                                    + globalOutgoingIpMatchTime
//                                    + " ns\n"
//                                    + "============================================"
//                    );
                } else {
                    String ipMatchLog =
                            "========== " + evtName + " ==========\n"
                                    + "Source IP       : " + ipStr(srcIp) + "\n"
                                    + "Destination IP : " + destinationIp + "\n"
                                    + "Source Port     : " + srcPort + "\n"
                                    + "Destination Port: " + dstPort + "\n"
                                    + "Match Count    : " + matchCount + "\n"
                                    + "Payload Length : " + payloadLen + " bytes\n"
                                    + "Connection Key : " + key + "\n"
                                    + "Session State  : " + session.state + "\n"
                                    + "Protocol        : TCP\n"
                                    + "Packet Length   : " + length + " bytes\n"
                                    + "Payload Length  : " + payloadLen + " bytes\n"
                                    + "Timestamp       : "
                                    + formatTimestamp(globalOutgoingIpMatchWallTime)
                                    + "\n"
                                    + "Timestamp Nano  : "
                                    + globalOutgoingIpMatchTime
                                    + " ns\n"
                                    + "===================================";

                    Log.i(TAG, ipMatchLog);

                    dashboard.logEvent(
                            TAG + ipMatchLog,
                            VpnEvent.Level.INFO,
                            VpnEvent.Category.TCP
                    );
                    Log.i(TAG, ipMatchLog);
                }



            }

            boolean requestTimestampCapturedForThisPacket = false;

            try {

                /*
                 * ============================================================
                 * TLS STREAM PARSER - TX
                 * ============================================================
                 *
                 * IMPORTANT:
                 *
                 * data[] contains TCP stream bytes.
                 *
                 * One TCP packet/read is NOT guaranteed to contain
                 * exactly one TLS record.
                 *
                 * It can contain:
                 *
                 * 1. Partial TLS header
                 * 2. Partial TLS record
                 * 3. One complete TLS record
                 * 4. Multiple TLS records
                 * 5. End of one TLS record + beginning of another
                 *
                 * Therefore we MUST use the persistent per-session
                 * TX TLS parser.
                 *
                 * data
                 *   ↓
                 * txTlsParser
                 *   ↓
                 * complete TLS records
                 */
                if (data != null
                        && data.length > 0) {

                    /*
                     * Append this TCP payload to the persistent
                     * TX TLS stream parser.
                     */
                    session.txTlsParser.append(
                            data,
                            0,
                            data.length
                    );


                    /*
                     * Parse every complete TLS record currently
                     * available in the stream.
                     */
                    java.util.List<TlsRecord> txRecords =
                            session.txTlsParser
                                    .parseAvailableRecords();


                    /*
                     * One TCP payload can contain multiple TLS
                     * records, so process every parsed record.
                     */
                    for (TlsRecord record : txRecords) {

                        int tlsRecordType =
                                record.contentType;


                        String tlsRecordName =
                                record.recordTypeName();


                        /*
                         * =====================================================
                         * TLS HANDSHAKE T0
                         * =====================================================
                         *
                         * T0 =
                         *
                         * FIRST COMPLETE TX TLS RECORD
                         * with ContentType 0x16.
                         *
                         * IMPORTANT:
                         *
                         * The timestamp comes from the parser at the
                         * moment the COMPLETE TLS record was detected.
                         */
                        if (tlsRecordType == 0x16
                                && tlsRecordType16Captured.compareAndSet(
                                false,
                                true
                        )) {

                            globalTlsRecordType16T0Nano =
                                    record.observedNano;

                            globalTlsRecordType16T0WallTime =
                                    record.observedWallTime;


                            String tlsT0Log =
                                    "========== TLS HANDSHAKE T0 | TX 0x16 ==========\n"
                                            + "Direction          : TX / SENT\n"
                                            + "TLS Record Type    : 0x16\n"
                                            + "ContentType        : 0x16\n"
                                            + "Record Type        : Handshake\n"
                                            + "TLS Version        : 0x"
                                            + String.format(
                                            java.util.Locale.US,
                                            "%02X%02X",
                                            record.versionMajor,
                                            record.versionMinor
                                    )
                                            + "\n"
                                            + "TLS Record Length  : "
                                            + record.recordLength
                                            + " bytes\n"
                                            + "\n"
                                            + "Source IP          : "
                                            + ipStr(srcIp)
                                            + "\n"
                                            + "Destination IP     : "
                                            + ipStr(dstIp)
                                            + "\n"
                                            + "Source Port        : "
                                            + srcPort
                                            + "\n"
                                            + "Destination Port   : "
                                            + dstPort
                                            + "\n"
                                            + "Connection Key     : "
                                            + key
                                            + "\n"
                                            + "\n"
                                            + "T0 Nano            : "
                                            + globalTlsRecordType16T0Nano
                                            + " ns\n"
                                            + "T0 Timestamp       : "
                                            + formatTimestamp(
                                            globalTlsRecordType16T0WallTime
                                    )
                                            + "\n"
                                            + "==============================================";


                            Log.i(
                                    TAG,
                                    tlsT0Log
                            );


                            dashboard.logToFile(
                                    TAG + tlsT0Log
                            );
                        }


                        /*
                         * =====================================================
                         * COMPLETE TLS RECORD LOG
                         * =====================================================
                         *
                         * This logs every complete TLS record detected
                         * by the TX stream parser.
                         */
                        String tlsSentLog =
                                "========== TLS RECORD [TX/SENT] ==========\n"
                                        + "Source IP          : "
                                        + ipStr(srcIp)
                                        + "\n"
                                        + "Destination IP     : "
                                        + ipStr(dstIp)
                                        + "\n"
                                        + "Source Port        : "
                                        + srcPort
                                        + "\n"
                                        + "Destination Port   : "
                                        + dstPort
                                        + "\n"
                                        + "TLS Record Type    : 0x"
                                        + String.format(
                                        java.util.Locale.US,
                                        "%02X",
                                        tlsRecordType
                                )
                                        + "\n"
                                        + "Record Type        : "
                                        + tlsRecordName
                                        + "\n"
                                        + "TLS Version        : 0x"
                                        + String.format(
                                        java.util.Locale.US,
                                        "%02X%02X",
                                        record.versionMajor,
                                        record.versionMinor
                                )
                                        + "\n"
                                        + "TLS Record Length  : "
                                        + record.recordLength
                                        + " bytes\n"
                                        + "TCP Payload Bytes  : "
                                        + data.length
                                        + " bytes\n"
                                        + "Timestamp          : "
                                        + formatTimestamp(
                                        record.observedWallTime
                                )
                                        + "\n"
                                        + "Timestamp Nano     : "
                                        + record.observedNano
                                        + " ns\n"
                                        + "Connection Key     : "
                                        + key
                                        + "\n"
                                        + "============================================";


                        Log.i(
                                TAG,
                                tlsSentLog
                        );


                        dashboard.logToFile(
                                TAG + tlsSentLog
                        );
                    }
                }


                /*
                 * ================================================
                 * WRITE REQUEST TO REAL SOCKET
                 * ================================================
                 */
                session.realOut.write(data);

                session.realOut.flush();


                /*
                 * ============================================================
                 * STORE SUCCESSFULLY TRANSMITTED SEQUENCE RANGE
                 * ============================================================
                 *
                 * Only store the sequence range after the real socket write
                 * succeeds.
                 */
                session.transmittedSegments.put(
                        currentSeqStart,
                        new TcpSegmentRecord(
                                currentSeqStart,
                                currentSeqEnd,
                                payloadLen,
                                packetTimestampNano
                        )
                );


                int sentCount = totalPacketsSent.incrementAndGet();

                dashboard.logToFile(TAG+" Payload written successfully.");

                dashboard.logToFile(TAG+
                        "TCP DATA TYPE = "
                        + transmissionType
                );

                dashboard.logToFile(TAG+
                        "TCP SEQ RANGE = "
                        + currentSeqStart
                        + " - "
                        + currentSeqEnd
                );

                dashboard.logToFile(TAG+
                        "TCP PAYLOAD LENGTH = "
                        + payloadLen
                );

                dashboard.logToFile(TAG+
                        "TCP RETRANSMITTED BYTES = "
                        + retransmittedBytes
                );

                dashboard.logToFile(TAG+
                        "Payload Length = " + payloadLen
                );

                Log.d(TAG, "Total Packets Sent So Far = " + sentCount);
                dashboard.logEvent(TAG+"Total Packets Sent So Far = " + sentCount,
                        VpnEvent.Level.INFO,
                        VpnEvent.Category.TCP
                );

            } catch (IOException e) {


                if (requestTimestampCapturedForThisPacket) {

//                    globalRequestCaptured.set(false);
//                    globalRequestSentTime = 0L;
                    globalTtfbRequestDestinationIp = null;
                    globalTtfbRequestPayloadSize = 0;
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
                dashboard.logEvent(TAG+"Creating new TCP session ..", VpnEvent.Level.INFO, VpnEvent.Category.TCP);

                Log.d(TAG, "Destination = " + intToInetName(dstIp).getHostAddress() + ":" + dstPort);
                dashboard.logEvent(TAG+
                                "Destination = " + intToInetName(dstIp).getHostAddress() + ":" + dstPort,
                        VpnEvent.Level.INFO,
                        VpnEvent.Category.TCP
                );



                if (underlyingNetwork == null) {
                    Log.e(TAG, "No underlying Network available for " + key);
                    dashboard.logEvent(TAG+"No underlying Network available for " + key,
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
                    dashboard.logEvent(TAG+"Underlying Network bindSocket SUCCESS for " + key,
                            VpnEvent.Level.SUCCESS, VpnEvent.Category.TCP);
                } catch (IOException e) {
                    Log.e(TAG, "Underlying Network bindSocket FAILED for " + key, e);
                    dashboard.logEvent(TAG+"Underlying Network bindSocket FAILED for " + key + " : " + e.getMessage(),
                            VpnEvent.Level.ERROR, VpnEvent.Category.TCP);

                    try {
                        socket.close();
                    } catch (IOException ignored) {
                    }

                    sendRst(srcIp, srcPort, dstIp, dstPort, session.deviceSeq, session.clientNextSeq);
                    sessions.remove(key);
                    return;
                }

                Log.d(
                        TAG,
                        "Connecting socket to "
                                + intToInetName(dstIp).getHostAddress()
                                + ":"
                                + dstPort
                );


                /*
                 * ============================================================
                 * TCP CONNECTION TIME - REAL SOCKET
                 * ============================================================
                 *
                 * Capture the moment immediately before socket.connect().
                 */
                long realSocketConnectStartNano =
                        System.nanoTime();


                socket.connect(
                        new InetSocketAddress(
                                intToInetName(dstIp),
                                dstPort
                        ),
                        8000
                );


                /*
                 * T1 = socket.connect() completed successfully.
                 */
                long realSocketConnectEndNano =
                        System.nanoTime();


                Log.d(TAG, "Socket connected successfully.");

                dashboard.logEvent(
                        TAG
                                + "Socket connected successfully."
                                + "\nDst IP : "
                                + dstIp
                                + "\nDst Port : "
                                + dstPort,
                        VpnEvent.Level.SUCCESS,
                        VpnEvent.Category.TCP
                );


                /*
                 * ============================================================
                 * TCP CONNECTION TIME CALCULATION
                 * ============================================================
                 *
                 * T0 = first SYN received from device
                 * T1 = real socket.connect() completed
                 *
                 * Connection Time = T1 - T0
                 */
                if (tcpConnectionStartCaptured.get()
                        && tcpConnectionCaptured.compareAndSet(false, true)) {

                    tcpConnectionEndNano =
                            realSocketConnectEndNano;

                    tcpConnectionNano =
                            tcpConnectionEndNano
                                    - tcpConnectionStartNano;

                    tcpConnectionMs =
                            tcpConnectionNano / 1_000_000.0;

                    String tcpConnectionLog =
                            "========== TCP CONNECTION TIME ==========\n"
                                    + "Connection Key     : "
                                    + key
                                    + "\n"
                                    + "Server IP          : "
                                    + intToInetName(dstIp).getHostAddress()
                                    + "\n"
                                    + "Server Port        : "
                                    + dstPort
                                    + "\n"
                                    + "T0 SYN             : "
                                    + tcpConnectionStartNano
                                    + " ns\n"
                                    + "T1 SOCKET CONNECT  : "
                                    + tcpConnectionEndNano
                                    + " ns\n"
                                    + "T1 - T0            : "
                                    + tcpConnectionNano
                                    + " ns\n"
                                    + "TCP Connection     : "
                                    + String.format(
                                    java.util.Locale.US,
                                    "%.3f",
                                    tcpConnectionMs
                            )
                                    + " ms\n"
                                    + "==========================================";

                    Log.i(
                            TAG,
                            tcpConnectionLog
                    );
//                  This is commented until client will confirm it to show in ui and log file
//                    dashboard.logToFile(
//                            TAG + tcpConnectionLog
//                    );

                    dashboard.recordTcpConnectionTime(
                            Math.round(tcpConnectionMs)
                    );
                }


                session.realSocket = socket;

                String serverIp = socket.getInetAddress().getHostAddress();
                String serverName;

                try {
                    serverName = socket.getInetAddress().getCanonicalHostName();
                } catch (Exception e) {
                    serverName = "Unknown";
                    Log.e(TAG, "Exception while rsolving host name : "
                            + intToInetName(dstIp).getHostAddress() + ":" + dstPort, e);
                    dashboard.logEvent(TAG+
                                    "Exception while rsolving host name : "
                                    + intToInetName(dstIp).getHostAddress() + ":" + dstPort
                                    + " exception is : " + e.getMessage(),
                            VpnEvent.Level.INFO, VpnEvent.Category.TCP
                    );
                }
                session.serverIp = serverIp;
                session.serverName = serverName;

                Log.d(TAG, "Creating TCP session");
//                dashboard.logEvent(TAG+
//                        "========== SERVER ==========\n"
//                                + "Server IP      : " + serverIp + "\n"
//                                + "Server Name    : " + serverName + "\n"
//                                + "============================",
//                        VpnEvent.Level.INFO, VpnEvent.Category.TCP
//                );

                session.realOut = socket.getOutputStream();
                session.realIn = socket.getInputStream();

                /*
                 * Send SYN-ACK only after the real server
                 * connection is established.
                 */
                sendSynAck(session);

            } catch (IOException e) {
                Log.e(TAG, "TCP connect failed for " + key + ": " + e.getMessage(), e);
                dashboard.logEvent(TAG+"TCP socket exception " + e.getMessage(),
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

        boolean firstSend =
                s.synAckSent.compareAndSet(false, true);

        int flags =
                PacketUtils.TCP_SYN | PacketUtils.TCP_ACK;

        /*
         * Send SYN-ACK to device.
         *
         * Flags = 0x12
         */
        writeTcpPacket(
                s.dstIp,
                s.dstPort,
                s.srcIp,
                s.srcPort,
                s.deviceSeq,
                s.clientNextSeq,
                PacketUtils.TCP_SYN | PacketUtils.TCP_ACK,
                null,
                0
        );

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
    private static String bytesToHex(byte[] data, int length) {

        if (data == null || length <= 0) {
            return "";
        }

        int safeLength = Math.min(length, data.length);

        StringBuilder sb = new StringBuilder(
                safeLength * 3
        );

        for (int i = 0; i < safeLength; i++) {

            if (i > 0) {
                sb.append(' ');
            }

            sb.append(
                    String.format(
                            java.util.Locale.US,
                            "%02X",
                            data[i] & 0xFF
                    )
            );
        }

        return sb.toString();
    }


    void sendFinToClient(TcpSession s) {

        writeTcpPacket(s.dstIp, s.dstPort, s.srcIp, s.srcPort, s.deviceSeq, s.clientNextSeq,
                PacketUtils.TCP_ACK | PacketUtils.TCP_FIN, null, 0);

        s.deviceSeq += 1;
    }


    void reportTtfb(TcpSession s, long ttfbMs, String key) {

        Log.d(TAG, "Reporting TTFB = " + ttfbMs + " ms");

        dashboard.logEvent(TAG+"TTFB : " + ttfbMs + " ms  (" + key + ")",
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

        String handshakeConnectionKey = null;
        if (session != null
                && session.srcIp != null
                && session.dstIp != null) {
            handshakeConnectionKey =
                    ipStr(session.srcIp) + ":" + session.srcPort
                            + "->"
                            + ipStr(session.dstIp) + ":" + session.dstPort;
        }

        Long removedT0 = handshakeConnectionKey != null
                ? tcpHandshakeT0ByConnection.remove(handshakeConnectionKey)
                : null;

        Log.d(
                TAG,
                "TCP CONNECTION CLOSED"
                        + "\nSession Key       : " + key
                        + "\nHandshake Key     : " + handshakeConnectionKey
                        + "\nRemoved T0        : "
                        + (removedT0 != null ? removedT0 + " ns" : "NONE")
                        + "\nRemaining T0 Map  : " + tcpHandshakeT0ByConnection.size()
        );

        dashboard.logToFile(
                TAG
                        + "TCP CONNECTION CLOSED"
                        + "\nSession Key       : " + key
                        + "\nHandshake Key     : " + handshakeConnectionKey
                        + "\nRemoved T0        : "
                        + (removedT0 != null ? removedT0 + " ns" : "NONE")
                        + "\nRemaining T0 Map  : " + tcpHandshakeT0ByConnection.size()
        );

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

        globalOutgoingIpMatchTime = 0L;
        globalIncomingIpMatchTime = 0L;

        globalDnsT0Nano = 0L;
        globalOutgoingIpMatchWallTime = 0L;
        globalIncomingIpMatchWallTime = 0L;

        /*
         * Reset TLS 0x17 T1 state.
         */
        /*
         * Reset TLS handshake timing state.
         */
        globalTlsRecordType16T0Nano = 0L;
        globalTlsRecordType16T0WallTime = 0L;
        tlsRecordType16Captured.set(false);

        globalTlsRecordType17T1Nano = 0L;
        globalTlsRecordType17T1WallTime = 0L;
        tlsRecordType17Captured.set(false);

        globalTlsHandshakeNano = -1L;
        globalTlsHandshakeMs = -1.0;

        /*
         * Reset TCP handshake timing state.
         */
        tcpHandshakeSynSentNano = 0L;
        tcpHandshakeAckNano = 0L;
        tcpHandshakeNano = -1L;
        tcpHandshakeMs = -1.0;

        /*
         * Reset TCP handshake per-connection T0 state.
         *
         * Every connection gets a fresh T0 map when the VPN session stops.
         */
        tcpHandshakeT0ByConnection.clear();
        tcpHandshakeCaptured.set(false);


        /*
         * Reset TCP connection timing state.
         */
        tcpConnectionStartNano = 0L;
        tcpConnectionEndNano = 0L;
        tcpConnectionNano = -1L;
        tcpConnectionMs = -1.0;

        tcpConnectionStartCaptured.set(false);
        tcpConnectionCaptured.set(false);


        /*
         * Reset TCP transmission/retransmission counters.
         */
        totalTcpTransmissions.set(0);
        totalTcpTransmissionBytes.set(0);

        totalTcpRetransmissions.set(0);
        totalTcpRetransmissionBytes.set(0);


        globalTtfbMs = -1L;
        globalTtfbRequestDestinationIp = null;
        globalTtfbRequestPayloadSize = 0;
        globalTtfbRequestConnectionKey = null;

        firstOutgoingIpMatchLogged.set(false);
        firstIncomingIpMatchLogged.set(false);

        outgoingIpMatchCount.set(0);
        incomingIpMatchCount.set(0);
        webViewT0Nano = 0L;

    }


    void resetGlobalTtfb() {

        /*
         * Reset complete TTFB state when START is pressed
         * / a new VPN session begins.
         */
        globalTtfbCaptured.set(false);

        globalOutgoingIpMatchTime = 0L;
        globalIncomingIpMatchTime = 0L;

        globalDnsT0Nano = 0L;
        globalOutgoingIpMatchWallTime = 0L;
        globalIncomingIpMatchWallTime = 0L;

        /*
         * Reset TLS 0x17 T1 state.
         */
        /*
         * Reset TLS handshake timing state.
         */
        globalTlsRecordType16T0Nano = 0L;
        globalTlsRecordType16T0WallTime = 0L;
        tlsRecordType16Captured.set(false);

        globalTlsRecordType17T1Nano = 0L;
        globalTlsRecordType17T1WallTime = 0L;
        tlsRecordType17Captured.set(false);

        globalTlsHandshakeNano = -1L;
        globalTlsHandshakeMs = -1.0;

        /*
         * Reset TCP handshake timing state.
         */
        tcpHandshakeSynSentNano = 0L;
        tcpHandshakeAckNano = 0L;
        tcpHandshakeNano = -1L;
        tcpHandshakeMs = -1.0;

        /*
         * Reset per-connection TCP handshake T0 state.
         */
        tcpHandshakeT0ByConnection.clear();
        tcpHandshakeCaptured.set(false);


        /*
         * Reset TCP connection timing state.
         */
        tcpConnectionStartNano = 0L;
        tcpConnectionEndNano = 0L;
        tcpConnectionNano = -1L;
        tcpConnectionMs = -1.0;

        tcpConnectionStartCaptured.set(false);
        tcpConnectionCaptured.set(false);


        /*
         * Reset TCP transmission/retransmission counters.
         */
        totalTcpTransmissions.set(0);
        totalTcpTransmissionBytes.set(0);

        totalTcpRetransmissions.set(0);
        totalTcpRetransmissionBytes.set(0);


        globalTtfbMs = -1L;
        webViewT0Nano = 0L;

        globalTtfbRequestDestinationIp = null;
        globalTtfbRequestPayloadSize = 0;
        globalTtfbRequestConnectionKey = null;

        firstOutgoingIpMatchLogged.set(false);
        firstIncomingIpMatchLogged.set(false);

        outgoingIpMatchCount.set(0);
        incomingIpMatchCount.set(0);

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

    /*
     * ============================================================
     * TCP DATA SEGMENT RECORD
     * ============================================================
     *
     * Stores the sequence range of a successfully transmitted
     * TCP data segment.
     */
    static class TcpSegmentRecord {

        final long seqStart;

        final long seqEnd;

        final int payloadLength;

        final long timestampNano;


        TcpSegmentRecord(
                long seqStart,
                long seqEnd,
                int payloadLength,
                long timestampNano
        ) {

            this.seqStart =
                    seqStart;

            this.seqEnd =
                    seqEnd;

            this.payloadLength =
                    payloadLength;

            this.timestampNano =
                    timestampNano;
        }
    }


    /*
     * ============================================================
     * TLS RECORD
     * ============================================================
     *
     * Represents ONE COMPLETE TLS record extracted from
     * the TCP byte stream.
     *
     * TLS record header:
     *
     * Byte 0 = Content Type
     * Byte 1 = TLS Version Major
     * Byte 2 = TLS Version Minor
     * Byte 3 = Record Length MSB
     * Byte 4 = Record Length LSB
     *
     * Examples:
     *
     * 0x14 = Change Cipher Spec
     * 0x15 = Alert
     * 0x16 = Handshake
     * 0x17 = Application Data
     */
    static class TlsRecord {

        final int contentType;

        final int versionMajor;

        final int versionMinor;

        final int recordLength;

        final long observedNano;

        final long observedWallTime;


        TlsRecord(
                int contentType,
                int versionMajor,
                int versionMinor,
                int recordLength,
                long observedNano,
                long observedWallTime
        ) {

            this.contentType =
                    contentType;

            this.versionMajor =
                    versionMajor;

            this.versionMinor =
                    versionMinor;

            this.recordLength =
                    recordLength;

            this.observedNano =
                    observedNano;

            this.observedWallTime =
                    observedWallTime;
        }


        String recordTypeName() {

            switch (contentType) {

                case 0x14:
                    return "Change Cipher Spec";

                case 0x15:
                    return "Alert";

                case 0x16:
                    return "Handshake";

                case 0x17:
                    return "Application Data";

                default:
                    return "Unknown";
            }
        }
    }


    /*
     * ============================================================
     * TLS STREAM PARSER
     * ============================================================
     *
     * IMPORTANT:
     *
     * TCP is a STREAM.
     *
     * A TCP read() is NOT equal to a TLS record.
     *
     * One read may contain:
     *
     * 1. Partial TLS header
     * 2. Partial TLS record
     * 3. One complete TLS record
     * 4. Multiple TLS records
     * 5. End of one TLS record + beginning of another
     *
     * Therefore this parser maintains a persistent byte buffer.
     *
     * TX and RX each have their own parser instance.
     */
    static class TlsRecordParser {

        /*
         * TLS record header size.
         */
        private static final int TLS_HEADER_LENGTH = 5;


        /*
         * Maximum TLS record payload size we accept.
         *
         * TLS records are normally <= 16 KB.
         *
         * 18 KB gives a small safety margin.
         */
        private static final int MAX_TLS_RECORD_LENGTH =
                18 * 1024;


        /*
         * Maximum amount of unparsed TCP stream data
         * that can remain inside this parser.
         *
         * This prevents an invalid stream from growing
         * memory indefinitely.
         */
        private static final int MAX_BUFFER_SIZE =
                256 * 1024;


        /*
         * TX or RX.
         *
         * Used only for debugging/logging if needed.
         */
        private final String direction;


        /*
         * Persistent TCP stream buffer.
         *
         * This buffer survives across multiple append()
         * calls.
         */
        private byte[] buffer =
                new byte[0];


        TlsRecordParser(
                String direction
        ) {

            this.direction =
                    direction;
        }


        /*
         * ============================================================
         * VALID TLS CONTENT TYPE
         * ============================================================
         */
        private static boolean isValidContentType(
                int contentType
        ) {

            return contentType == 0x14
                    || contentType == 0x15
                    || contentType == 0x16
                    || contentType == 0x17;
        }


        /*
         * ============================================================
         * VALID TLS VERSION
         * ============================================================
         *
         * TLS versions:
         *
         * 0x03 0x01 = TLS 1.0
         * 0x03 0x02 = TLS 1.1
         * 0x03 0x03 = TLS 1.2
         * 0x03 0x04 = TLS 1.3
         */
        private static boolean isValidVersion(
                int major,
                int minor
        ) {

            return major == 0x03
                    && minor <= 0x04;
        }


        /*
         * ============================================================
         * APPEND TCP STREAM DATA
         * ============================================================
         *
         * The caller may provide:
         *
         * - partial TLS header
         * - partial TLS record
         * - complete TLS record
         * - multiple TLS records
         *
         * Everything is appended to the persistent buffer.
         */
        synchronized void append(
                byte[] data,
                int offset,
                int length
        ) {

            if (data == null) {
                return;
            }

            if (length <= 0) {
                return;
            }

            if (offset < 0) {
                return;
            }

            if (offset >= data.length) {
                return;
            }

            int safeLength =
                    Math.min(
                            length,
                            data.length - offset
                    );

            if (safeLength <= 0) {
                return;
            }


            /*
             * Create combined buffer:
             *
             * old incomplete bytes
             * +
             * new TCP bytes
             */
            byte[] combined =
                    new byte[
                            buffer.length
                                    + safeLength
                            ];


            /*
             * Copy previous incomplete stream bytes.
             */
            System.arraycopy(
                    buffer,
                    0,
                    combined,
                    0,
                    buffer.length
            );


            /*
             * Append new TCP data.
             */
            System.arraycopy(
                    data,
                    offset,
                    combined,
                    buffer.length,
                    safeLength
            );


            buffer =
                    combined;


            /*
             * Safety protection against an invalid
             * or non-TLS stream continuously growing.
             *
             * Keep only the newest bytes.
             */
            if (buffer.length > MAX_BUFFER_SIZE) {

                int keepLength =
                        MAX_BUFFER_SIZE;

                byte[] trimmed =
                        new byte[keepLength];

                System.arraycopy(
                        buffer,
                        buffer.length - keepLength,
                        trimmed,
                        0,
                        keepLength
                );

                buffer =
                        trimmed;
            }
        }


        /*
         * ============================================================
         * PARSE COMPLETE TLS RECORDS
         * ============================================================
         *
         * Returns every complete TLS record currently available.
         *
         * Incomplete data remains inside the persistent buffer
         * for the next append().
         */
        synchronized java.util.List<TlsRecord>
        parseAvailableRecords() {

            java.util.List<TlsRecord> records =
                    new java.util.ArrayList<>();


            while (true) {

                /*
                 * Need at least the TLS header.
                 */
                if (buffer.length < TLS_HEADER_LENGTH) {
                    break;
                }


                /*
                 * Read TLS record header.
                 */
                int contentType =
                        buffer[0] & 0xFF;

                int versionMajor =
                        buffer[1] & 0xFF;

                int versionMinor =
                        buffer[2] & 0xFF;

                int recordLength =
                        ((buffer[3] & 0xFF) << 8)
                                | (buffer[4] & 0xFF);


                /*
                 * ====================================================
                 * HEADER VALIDATION
                 * ====================================================
                 *
                 * If the current byte sequence does not look like
                 * a TLS record, shift by ONE byte and try again.
                 *
                 * This is important because TCP data may contain
                 * bytes before the TLS record boundary.
                 */
                if (!isValidContentType(contentType)
                        || !isValidVersion(
                        versionMajor,
                        versionMinor
                )
                        || recordLength < 0
                        || recordLength > MAX_TLS_RECORD_LENGTH) {

                    /*
                     * Remove exactly ONE byte.
                     *
                     * Then try to locate the next possible
                     * TLS record header.
                     */
                    byte[] shifted =
                            new byte[
                                    buffer.length - 1
                                    ];

                    System.arraycopy(
                            buffer,
                            1,
                            shifted,
                            0,
                            shifted.length
                    );

                    buffer =
                            shifted;

                    continue;
                }


                /*
                 * ====================================================
                 * COMPLETE RECORD LENGTH
                 * ====================================================
                 *
                 * TLS header = 5 bytes
                 *
                 * Total record =
                 *
                 *     5 + payload length
                 */
                int totalRecordLength =
                        TLS_HEADER_LENGTH
                                + recordLength;


                /*
                 * The header is valid, but the complete TLS
                 * payload has not arrived yet.
                 *
                 * KEEP the bytes in the buffer.
                 *
                 * Do NOT discard them.
                 */
                if (buffer.length < totalRecordLength) {
                    break;
                }


                /*
                 * ====================================================
                 * COMPLETE TLS RECORD FOUND
                 * ====================================================
                 *
                 * Capture timestamps at the moment the complete
                 * TLS record becomes available to the parser.
                 */
                long observedNano =
                        System.nanoTime();

                long observedWallTime =
                        System.currentTimeMillis();


                /*
                 * Create the parsed TLS record.
                 */
                TlsRecord record =
                        new TlsRecord(
                                contentType,
                                versionMajor,
                                versionMinor,
                                recordLength,
                                observedNano,
                                observedWallTime
                        );


                /*
                 * Add complete record to result list.
                 */
                records.add(
                        record
                );


                /*
                 * ====================================================
                 * REMOVE CONSUMED RECORD
                 * ====================================================
                 *
                 * There may be another TLS record immediately
                 * after this one.
                 *
                 * Example:
                 *
                 * [TLS RECORD 1][TLS RECORD 2][TLS RECORD 3]
                 *
                 * After removing record 1:
                 *
                 * [TLS RECORD 2][TLS RECORD 3]
                 *
                 * The loop then parses record 2.
                 */
                int remainingLength =
                        buffer.length
                                - totalRecordLength;


                if (remainingLength <= 0) {

                    buffer =
                            new byte[0];

                } else {

                    byte[] remaining =
                            new byte[
                                    remainingLength
                                    ];

                    System.arraycopy(
                            buffer,
                            totalRecordLength,
                            remaining,
                            0,
                            remainingLength
                    );

                    buffer =
                            remaining;
                }
            }


            return records;
        }


        /*
         * ============================================================
         * RESET PARSER
         * ============================================================
         *
         * Used when a TCP session is closed so that a partial TLS
         * record from the old connection cannot leak into another
         * connection.
         */
        synchronized void reset() {

            buffer =
                    new byte[0];
        }
    }


    /*
     * ============================================================
     * TCP SESSION
     * ============================================================
     */
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


        String serverIp;

        String serverName;

        Socket realSocket;

        OutputStream realOut;

        InputStream realIn;


        /*
         * ============================================================
         * PER-CONNECTION TLS STREAM PARSERS
         * ============================================================
         *
         * TX:
         *
         * Device -> VPN -> Real Server
         *
         * RX:
         *
         * Real Server -> VPN -> Device
         *
         * Each direction MUST have its own parser because TLS
         * records are directional byte streams.
         */
        final TlsRecordParser txTlsParser =
                new TlsRecordParser("TX");


        final TlsRecordParser rxTlsParser =
                new TlsRecordParser("RX");


        /*
         * ============================================================
         * TCP TRANSMISSION HISTORY
         * ============================================================
         *
         * Key   = starting TCP sequence number
         * Value = transmitted sequence range
         *
         * This belongs to the session because TCP sequence numbers
         * are meaningful within a TCP connection.
         */
        final java.util.concurrent.ConcurrentHashMap<Long, TcpSegmentRecord>
                transmittedSegments =
                new java.util.concurrent.ConcurrentHashMap<>();


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


        void startRealSocketReaderThread(
                TcpForwarder forwarder,
                String key) {

            Log.d(
                    TAG,
                    "Starting TCP Reader Thread..."
            );


            Thread t =
                    new Thread(
                            () -> {

                                byte[] buf =
                                        new byte[16384];


                                try {

                                    int n;


                                    while (
                                            (n = realIn.read(buf))
                                                    != -1
                                    ) {

                                        int receivedCount =
                                                forwarder
                                                        .totalPacketsReceived
                                                        .incrementAndGet();


                                        Log.d(
                                                TAG,
                                                "Received "
                                                        + n
                                                        + " bytes from server."
                                        );


                                        Log.d(
                                                TAG,
                                                "realIn.read() = "
                                                        + n
                                        );


                                        Log.d(
                                                TAG,
                                                "Total Packets Received So Far = "
                                                        + receivedCount
                                        );


                                        forwarder.dashboard.logEvent(
                                                TAG
                                                        + "Total Packets Received So Far = "
                                                        + receivedCount,
                                                VpnEvent.Level.INFO,
                                                VpnEvent.Category.TCP
                                        );


                                        Log.d(
                                                TAG,
                                                "First byte condition checking"
                                        );


                                        /*
                                         * ====================================================
                                         * FIRST BYTE RECEIVED
                                         * ====================================================
                                         *
                                         * This existing logic is retained.
                                         */
                                        if (
                                                !firstByteCaptured.get()
                                        ) {

                                            if (
                                                    firstByteCaptured
                                                            .compareAndSet(
                                                                    false,
                                                                    true
                                                            )
                                            ) {

                                                firstByteReceivedTime =
                                                        System.nanoTime();


                                                long firstByteWallTime =
                                                        System.currentTimeMillis();


                                                Log.d(
                                                        TAG,
                                                        "First byte received from real server: "
                                                                + firstByteReceivedTime
                                                                + " ns"
                                                );


                                                forwarder.dashboard.logToFile(
                                                        TAG
                                                                + "========== FIRST BYTE RECEIVED ==========\n"
                                                                + "Connection Key : "
                                                                + key
                                                                + "\n"
                                                                + "Received Bytes : "
                                                                + n
                                                                + "\n"
                                                                + "Timestamp      : "
                                                                + forwarder.formatTimestamp(
                                                                firstByteWallTime
                                                        )
                                                                + "\n"
                                                                + "Timestamp Nano : "
                                                                + firstByteReceivedTime
                                                                + " ns\n"
                                                                + "=========================================="
                                                );
                                            }
                                        }


                                        /*
                                         * =====================================================
                                         * TLS STREAM PARSER - RX
                                         * =====================================================
                                         *
                                         * IMPORTANT:
                                         *
                                         * DO NOT use:
                                         *
                                         *     buf[0] & 0xFF
                                         *
                                         * to determine the TLS record type.
                                         *
                                         * The first byte of a TCP read is not
                                         * necessarily the first byte of a TLS record.
                                         *
                                         * The persistent parser handles:
                                         *
                                         *     partial TLS records
                                         *     multiple TLS records
                                         *     split TLS headers
                                         *     TLS record boundaries
                                         */
                                        if (n > 0) {

                                            /*
                                             * Append the complete TCP read to
                                             * the persistent RX TLS stream parser.
                                             */
                                            rxTlsParser.append(
                                                    buf,
                                                    0,
                                                    n
                                            );


                                            /*
                                             * Parse every complete TLS record
                                             * currently available.
                                             */
                                            java.util.List<TlsRecord>
                                                    rxRecords =
                                                    rxTlsParser
                                                            .parseAvailableRecords();


                                            /*
                                             * One TCP read may contain multiple
                                             * TLS records, so process all of them.
                                             */
                                            for (
                                                    TlsRecord record :
                                                    rxRecords
                                            ) {

                                                int tlsRecordType =
                                                        record.contentType;


                                                String tlsRecordName =
                                                        record.recordTypeName();


                                                /*
                                                 * =================================================
                                                 * COMPLETE TLS RECORD LOG
                                                 * =================================================
                                                 */
                                                String tlsRecordLog =
                                                        "========== TLS RECORD [RX/RECEIVED] ==========\n"
                                                                + "Source IP        : "
                                                                + TcpForwarder.ipStr(
                                                                dstIp
                                                        )
                                                                + "\n"
                                                                + "Destination IP   : "
                                                                + TcpForwarder.ipStr(
                                                                srcIp
                                                        )
                                                                + "\n"
                                                                + "Source Port      : "
                                                                + dstPort
                                                                + "\n"
                                                                + "Destination Port : "
                                                                + srcPort
                                                                + "\n"
                                                                + "TLS Record Type  : 0x"
                                                                + String.format(
                                                                java.util.Locale.US,
                                                                "%02X",
                                                                tlsRecordType
                                                        )
                                                                + "\n"
                                                                + "Record Type      : "
                                                                + tlsRecordName
                                                                + "\n"
                                                                + "TLS Version      : 0x"
                                                                + String.format(
                                                                java.util.Locale.US,
                                                                "%02X%02X",
                                                                record.versionMajor,
                                                                record.versionMinor
                                                        )
                                                                + "\n"
                                                                + "TLS Record Length: "
                                                                + record.recordLength
                                                                + " bytes\n"
                                                                + "Timestamp        : "
                                                                + forwarder.formatTimestamp(
                                                                record.observedWallTime
                                                        )
                                                                + "\n"
                                                                + "Timestamp Nano   : "
                                                                + record.observedNano
                                                                + " ns\n"
                                                                + "Connection Key   : "
                                                                + key
                                                                + "\n"
                                                                + "==============================================";


                                                Log.i(
                                                        TAG,
                                                        tlsRecordLog
                                                );


                                                forwarder.dashboard.logToFile(
                                                        TAG
                                                                + tlsRecordLog
                                                );


                                                /*
                                                 * =================================================
                                                 * T1 = FIRST RX TLS 0x17
                                                 * =================================================
                                                 *
                                                 * T0 = First TX TLS 0x16
                                                 *
                                                 * T1 = First RX TLS 0x17
                                                 *
                                                 * TLS Handshake Time = T1 - T0
                                                 */
                                                if (
                                                        tlsRecordType == 0x17
                                                                && forwarder
                                                                .tlsRecordType17Captured
                                                                .compareAndSet(
                                                                        false,
                                                                        true
                                                                )
                                                ) {

                                                    /*
                                                     * =========================================
                                                     * Capture exact TLS 0x17 timestamp
                                                     * =========================================
                                                     */
                                                    forwarder
                                                            .globalTlsRecordType17T1Nano =
                                                            record.observedNano;


                                                    forwarder
                                                            .globalTlsRecordType17T1WallTime =
                                                            record.observedWallTime;


                                                    /*
                                                     * =========================================
                                                     * T1 LOG
                                                     * =========================================
                                                     */
                                                    String tlsT1Log =
                                                            "========== T1_TLS_RECORD_0x17 ==========\n"
                                                                    + "Direction        : RX / RECEIVED\n"
                                                                    + "TLS Record Type  : 0x17\n"
                                                                    + "Record Type      : Application Data\n"
                                                                    + "TLS Version      : 0x"
                                                                    + String.format(
                                                                    java.util.Locale.US,
                                                                    "%02X%02X",
                                                                    record.versionMajor,
                                                                    record.versionMinor
                                                            )
                                                                    + "\n"
                                                                    + "TLS Record Length: "
                                                                    + record.recordLength
                                                                    + " bytes\n"
                                                                    + "T1 Nano          : "
                                                                    + forwarder
                                                                    .globalTlsRecordType17T1Nano
                                                                    + " ns\n"
                                                                    + "Timestamp        : "
                                                                    + forwarder.formatTimestamp(
                                                                    forwarder
                                                                            .globalTlsRecordType17T1WallTime
                                                            )
                                                                    + "\n"
                                                                    + "Source IP        : "
                                                                    + TcpForwarder.ipStr(
                                                                    dstIp
                                                            )
                                                                    + "\n"
                                                                    + "Destination IP   : "
                                                                    + TcpForwarder.ipStr(
                                                                    srcIp
                                                            )
                                                                    + "\n"
                                                                    + "Source Port      : "
                                                                    + dstPort
                                                                    + "\n"
                                                                    + "Destination Port : "
                                                                    + srcPort
                                                                    + "\n"
                                                                    + "Connection Key   : "
                                                                    + key
                                                                    + "\n"
                                                                    + "==========================================";


                                                    Log.i(
                                                            TAG,
                                                            tlsT1Log
                                                    );


                                                    forwarder.dashboard.logToFile(
                                                            TAG
                                                                    + tlsT1Log
                                                    );


                                                    /*
                                                     * =================================================
                                                     * TLS HANDSHAKE TIME
                                                     * =================================================
                                                     *
                                                     * T0 = First TX TLS 0x16
                                                     *
                                                     * T1 = First RX TLS 0x17
                                                     *
                                                     * TLS Handshake Time = T1 - T0
                                                     */
                                                    if (
                                                            forwarder
                                                                    .globalTlsRecordType16T0Nano
                                                                    > 0L
                                                    ) {

                                                        forwarder
                                                                .globalTlsHandshakeNano =
                                                                forwarder
                                                                        .globalTlsRecordType17T1Nano
                                                                        -
                                                                        forwarder
                                                                                .globalTlsRecordType16T0Nano;


                                                        forwarder
                                                                .globalTlsHandshakeMs =
                                                                forwarder
                                                                        .globalTlsHandshakeNano
                                                                        / 1_000_000.0;


                                                        /*
                                                         * Publish TLS handshake
                                                         * result to dashboard.
                                                         */
                                                        forwarder.dashboard
                                                                .recordTlsHandshake(
                                                                        forwarder
                                                                                .globalTlsHandshakeMs
                                                                );


                                                        String tlsHandshakeLog =
                                                                "========== TLS HANDSHAKE TIME ==========\n"
                                                                        + "T0 TLS Record Type : 0x16 (TX/SENT)\n"
                                                                        + "T0 Timestamp       : "
                                                                        + forwarder.formatTimestamp(
                                                                        forwarder
                                                                                .globalTlsRecordType16T0WallTime
                                                                )
                                                                        + "\n"
                                                                        + "T0 Nano            : "
                                                                        + forwarder
                                                                        .globalTlsRecordType16T0Nano
                                                                        + " ns\n"
                                                                        + "\n"
                                                                        + "T1 TLS Record Type : 0x17 (RX/RECEIVED)\n"
                                                                        + "T1 Timestamp       : "
                                                                        + forwarder.formatTimestamp(
                                                                        forwarder
                                                                                .globalTlsRecordType17T1WallTime
                                                                )
                                                                        + "\n"
                                                                        + "T1 Nano            : "
                                                                        + forwarder
                                                                        .globalTlsRecordType17T1Nano
                                                                        + " ns\n"
                                                                        + "\n"
                                                                        + "TLS Handshake Time = T1 - T0\n"
                                                                        + "                   = "
                                                                        + forwarder
                                                                        .globalTlsRecordType17T1Nano
                                                                        + " - "
                                                                        + forwarder
                                                                        .globalTlsRecordType16T0Nano
                                                                        + "\n"
                                                                        + "                   = "
                                                                        + forwarder
                                                                        .globalTlsHandshakeNano
                                                                        + " ns\n"
                                                                        + "                   = "
                                                                        + String.format(
                                                                        java.util.Locale.US,
                                                                        "%.3f",
                                                                        forwarder
                                                                                .globalTlsHandshakeMs
                                                                )
                                                                        + " ms\n"
                                                                        + "==========================================";


                                                        Log.i(
                                                                TAG,
                                                                tlsHandshakeLog
                                                        );


                                                        forwarder.dashboard.logToFile(
                                                                TAG
                                                                        + tlsHandshakeLog
                                                        );

                                                    } else {

                                                        String tlsHandshakeNotCalculatedLog =
                                                                "========== TLS HANDSHAKE NOT CALCULATED ==========\n"
                                                                        + "Reason : TLS 0x16 TX T0 is not available\n"
                                                                        + "T0 Nano : "
                                                                        + forwarder
                                                                        .globalTlsRecordType16T0Nano
                                                                        + " ns\n"
                                                                        + "T1 Nano : "
                                                                        + forwarder
                                                                        .globalTlsRecordType17T1Nano
                                                                        + " ns\n"
                                                                        + "===================================================";


                                                        Log.w(
                                                                TAG,
                                                                tlsHandshakeNotCalculatedLog
                                                        );


                                                        forwarder.dashboard.logToFile(
                                                                TAG
                                                                        + tlsHandshakeNotCalculatedLog
                                                        );
                                                    }


                                                    /*
                                                     * =================================================
                                                     * TTFB
                                                     * =================================================
                                                     *
                                                     * T0 = DNS request start
                                                     *
                                                     * T1 = First complete RX TLS 0x17
                                                     *
                                                     * TTFB = T1 - T0
                                                     */
                                                    if (
                                                            forwarder
                                                                    .globalDnsT0Nano
                                                                    > 0L
                                                    ) {

                                                        long ttfbNano =
                                                                forwarder
                                                                        .globalTlsRecordType17T1Nano
                                                                        -
                                                                        forwarder
                                                                                .globalDnsT0Nano;


                                                        long ttfbMicros =
                                                                TimeUnit
                                                                        .NANOSECONDS
                                                                        .toMicros(
                                                                                ttfbNano
                                                                        );


                                                        double ttfbMs =
                                                                ttfbNano
                                                                        / 1_000_000.0;


                                                        forwarder.globalTtfbMs =
                                                                (long) ttfbMs;


                                                        String ttfbLog =
                                                                "========== T2_TTFB ==========\n"
                                                                        + "Destination IP : "
                                                                        + forwarder
                                                                        .globalTtfbRequestDestinationIp
                                                                        + "\n"
                                                                        + "Resolved IP    : "
                                                                        + forwarder
                                                                        .globalTtfbRequestResolvedIp
                                                                        + "\n"
                                                                        + "\n"
                                                                        + "DNS T0 Nano          : "
                                                                        + forwarder
                                                                        .globalDnsT0Nano
                                                                        + " ns\n"
                                                                        + "TLS Record Type      : 0x17\n"
                                                                        + "TLS Record           : Application Data\n"
                                                                        + "TLS T1 Nano          : "
                                                                        + forwarder
                                                                        .globalTlsRecordType17T1Nano
                                                                        + " ns\n"
                                                                        + "TLS T1 Timestamp     : "
                                                                        + forwarder.formatTimestamp(
                                                                        forwarder
                                                                                .globalTlsRecordType17T1WallTime
                                                                )
                                                                        + "\n"
                                                                        + "\n"
                                                                        + "TTFB = TLS 0x17 T1 - DNS T0\n"
                                                                        + "     = "
                                                                        + forwarder
                                                                        .globalTlsRecordType17T1Nano
                                                                        + " - "
                                                                        + forwarder
                                                                        .globalDnsT0Nano
                                                                        + "\n"
                                                                        + "     = "
                                                                        + ttfbNano
                                                                        + " ns\n"
                                                                        + "     = "
                                                                        + ttfbMicros
                                                                        + " µs\n"
                                                                        + "     = "
                                                                        + String.format(
                                                                        java.util.Locale.US,
                                                                        "%.3f",
                                                                        ttfbMs
                                                                )
                                                                        + " ms\n"
                                                                        + "==========================";


                                                        Log.i(
                                                                TAG,
                                                                ttfbLog
                                                        );


                                                        forwarder.dashboard.logEvent(
                                                                TAG + ttfbLog,
                                                                VpnEvent.Level.SUCCESS,
                                                                VpnEvent.Category.TCP
                                                        );


                                                        forwarder.reportTtfb(
                                                                this,
                                                                Math.round(ttfbMs),
                                                                key
                                                        );

                                                    } else {

                                                        String noT0Log =
                                                                "========== TTFB NOT CALCULATED ==========\n"
                                                                        + "Reason : DNS T0 is not available\n"
                                                                        + "TLS T1 : "
                                                                        + forwarder
                                                                        .globalTlsRecordType17T1Nano
                                                                        + " ns\n"
                                                                        + "DNS T0 : "
                                                                        + forwarder
                                                                        .globalDnsT0Nano
                                                                        + " ns\n"
                                                                        + "==========================================";


                                                        Log.w(
                                                                TAG,
                                                                noT0Log
                                                        );


                                                        forwarder.dashboard.logToFile(
                                                                TAG + noT0Log
                                                        );
                                                    }
                                                }
                                            }
                                        }


                                        /*
                                         * =====================================================
                                         * RX TCP HEADER LOG
                                         * =====================================================
                                         */
                                        if (n > 0) {

                                            String rxHeaderLog =
                                                    "========== [RX] TCP HEADER ==========\n"
                                                            + "Source IP          : "
                                                            + TcpForwarder.ipStr(
                                                            dstIp
                                                    )
                                                            + "\n"
                                                            + "Destination IP     : "
                                                            + TcpForwarder.ipStr(
                                                            srcIp
                                                    )
                                                            + "\n"
                                                            + "Host Name          : "
                                                            + serverName
                                                            + "\n"
                                                            + "Server IP          : "
                                                            + serverIp
                                                            + "\n"
                                                            + "Source Port        : "
                                                            + dstPort
                                                            + "\n"
                                                            + "Destination Port   : "
                                                            + srcPort
                                                            + "\n"
                                                            + "Payload Length     : "
                                                            + n
                                                            + "\n"
                                                            + "Sequence Number    : "
                                                            + deviceSeq
                                                            + "\n"
                                                            + "ACK Number         : "
                                                            + clientNextSeq
                                                            + "\n"
                                                            + "=====================================";


                                            forwarder.dashboard.logEvent(
                                                    TAG + rxHeaderLog,
                                                    VpnEvent.Level.INFO,
                                                    VpnEvent.Category.TCP
                                            );


                                            /*
                                             * =====================================================
                                             * WEBSITE RESOLVED IP MATCH
                                             * =====================================================
                                             */
                                            String incomingIp =
                                                    TcpForwarder.ipStr(
                                                            dstIp
                                                    );


                                            if (
                                                    forwarder.websiteResolvedIps
                                                            .contains(
                                                                    incomingIp
                                                            )
                                            ) {

                                                boolean isFirstIncomingMatch =
                                                        forwarder
                                                                .firstIncomingIpMatchLogged
                                                                .compareAndSet(
                                                                        false,
                                                                        true
                                                                );


                                                int matchCount =
                                                        forwarder
                                                                .incomingIpMatchCount
                                                                .incrementAndGet();


                                                String evtName =
                                                        isFirstIncomingMatch
                                                                ? "IC_IP_MATCH"
                                                                : "I_IP_MATCH";


                                                /*
                                                 * =================================================
                                                 * FIRST INCOMING IP MATCH
                                                 * =================================================
                                                 */
                                                if (
                                                        isFirstIncomingMatch
                                                ) {

                                                    /*
                                                     * Existing code intentionally
                                                     * keeps this timestamp disabled.
                                                     */
                                                /*
                                                forwarder.globalIncomingIpMatchTime =
                                                        System.nanoTime();
                                                */


                                                    forwarder
                                                            .globalIncomingIpMatchWallTime =
                                                            System.currentTimeMillis();


                                                    forwarder.dashboard.logToFile(
                                                            TAG
                                                                    + "========== T1_Time IC_IP_MATCH PACKET ==========\n"
                                                                    + "Source IP       : "
                                                                    + incomingIp
                                                                    + "\n"
                                                                    + "Destination IP  : "
                                                                    + TcpForwarder.ipStr(
                                                                    srcIp
                                                            )
                                                                    + "\n"
                                                                    + "Source Port     : "
                                                                    + dstPort
                                                                    + "\n"
                                                                    + "Destination Port: "
                                                                    + srcPort
                                                                    + "\n"
                                                                    + "Protocol        : TCP\n"
                                                                    + "Packet Length   : "
                                                                    + n
                                                                    + " bytes\n"
                                                                    + "Timestamp       : "
                                                                    + forwarder.formatTimestamp(
                                                                    forwarder
                                                                            .globalIncomingIpMatchWallTime
                                                            )
                                                                    + "\n"
                                                                    + "Timestamp Nano  : "
                                                                    + forwarder
                                                                    .globalIncomingIpMatchTime
                                                                    + " ns\n"
                                                                    + "============================================"
                                                    );


                                                    Log.d(
                                                            TAG,
                                                            "IC_IP_MATCH T1_Time timestamp captured = "
                                                                    + forwarder
                                                                    .globalIncomingIpMatchTime
                                                                    + " ns"
                                                    );


                                                    /*
                                                     * =====================================================
                                                     * TTFB CALCULATION
                                                     *
                                                     * T0 = DNS request start time
                                                     *
                                                     * T1 = First received TLS Application Data record
                                                     *      where TLS ContentType == 0x17
                                                     *
                                                     * TTFB = TLS 0x17 T1 - DNS T0
                                                     * =====================================================
                                                     */
                                                    if (
                                                            forwarder
                                                                    .globalDnsT0Nano
                                                                    > 0L
                                                                    && forwarder
                                                                    .globalTlsRecordType17T1Nano
                                                                    > 0L
                                                    ) {

                                                        long ttfbNano =
                                                                forwarder
                                                                        .globalTlsRecordType17T1Nano
                                                                        -
                                                                        forwarder
                                                                                .globalDnsT0Nano;


                                                        long ttfbMicros =
                                                                TimeUnit
                                                                        .NANOSECONDS
                                                                        .toMicros(
                                                                                ttfbNano
                                                                        );


                                                        forwarder.globalTtfbMs =
                                                                TimeUnit
                                                                        .NANOSECONDS
                                                                        .toMillis(
                                                                                ttfbNano
                                                                        );


                                                        String ttfbLog =
                                                                "========== T2_TTFB ==========\n"
                                                                        + "Destination IP : "
                                                                        + forwarder
                                                                        .globalTtfbRequestDestinationIp
                                                                        + "\n"
                                                                        + "Resolved IP    : "
                                                                        + forwarder
                                                                        .globalTtfbRequestResolvedIp
                                                                        + "\n"
                                                                        + "\n"
                                                                        + "DNS T0 Nano          : "
                                                                        + forwarder
                                                                        .globalDnsT0Nano
                                                                        + " ns\n"
                                                                        + "TLS Record Type      : 0x17\n"
                                                                        + "TLS T1 Nano          : "
                                                                        + forwarder
                                                                        .globalTlsRecordType17T1Nano
                                                                        + " ns\n"
                                                                        + "TLS T1 Timestamp     : "
                                                                        + forwarder.formatTimestamp(
                                                                        forwarder
                                                                                .globalTlsRecordType17T1WallTime
                                                                )
                                                                        + "\n"
                                                                        + "\n"
                                                                        + "TTFB = TLS 0x17 T1 - DNS T0\n"
                                                                        + "     = "
                                                                        + forwarder
                                                                        .globalTlsRecordType17T1Nano
                                                                        + " - "
                                                                        + forwarder
                                                                        .globalDnsT0Nano
                                                                        + "\n"
                                                                        + "     = "
                                                                        + ttfbNano
                                                                        + " ns\n"
                                                                        + "     = "
                                                                        + ttfbMicros
                                                                        + " µs\n"
                                                                        + "     = "
                                                                        + forwarder
                                                                        .globalTtfbMs
                                                                        + " ms\n"
                                                                        + "==========================";


                                                        Log.i(
                                                                TAG,
                                                                ttfbLog
                                                        );


                                                        forwarder.dashboard.logEvent(
                                                                TAG + ttfbLog,
                                                                VpnEvent.Level.SUCCESS,
                                                                VpnEvent.Category.TCP
                                                        );


                                                        forwarder.reportTtfb(
                                                                this,
                                                                forwarder.globalTtfbMs,
                                                                key
                                                        );
                                                    }
                                                }


                                                /*
                                                 * =================================================
                                                 * IP MATCH LOG
                                                 * =================================================
                                                 */
                                                String ipMatchLog =
                                                        "========== "
                                                                + evtName
                                                                + " ==========\n"
                                                                + "Match Count    : "
                                                                + matchCount
                                                                + "\n"
                                                                + "Source IP      : "
                                                                + incomingIp
                                                                + "\n"
                                                                + "Payload Length : "
                                                                + n
                                                                + " bytes\n"
                                                                + "Connection Key : "
                                                                + key
                                                                + "\n";


                                                if (
                                                        isFirstIncomingMatch
                                                ) {

                                                    ipMatchLog +=
                                                            "IC_IP_MATCH Time: "
                                                                    + forwarder.formatTimestamp(
                                                                    forwarder
                                                                            .globalIncomingIpMatchWallTime
                                                            )
                                                                    + "\n"
                                                                    + "IC_IP_MATCH Nano: "
                                                                    + forwarder
                                                                    .globalIncomingIpMatchTime
                                                                    + " ns\n";
                                                }


                                                ipMatchLog +=
                                                        "===================================";


                                                Log.i(
                                                        TAG,
                                                        ipMatchLog
                                                );


                                                forwarder.dashboard.logEvent(
                                                        TAG + ipMatchLog,
                                                        VpnEvent.Level.INFO,
                                                        VpnEvent.Category.TCP
                                                );
                                            }
                                        }


                                        /*
                                         * =====================================================
                                         * FORWARD RECEIVED DATA TO VPN CLIENT
                                         * =====================================================
                                         */
                                        forwarder.sendDataToClient(
                                                this,
                                                buf,
                                                n
                                        );
                                    }


                                } catch (IOException ignored) {

                                    // socket closed/reset

                                } finally {

                                    forwarder.sendFinToClient(
                                            this
                                    );
                                }

                            },
                            "TcpRead-" + key
                    );


            t.setDaemon(true);

            t.start();


            Log.d(
                    TAG,
                    "TCP Reader Thread Started."
            );
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
