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

    private final java.util.concurrent.atomic.AtomicBoolean
            tcpHandshakeSynCaptured =
            new java.util.concurrent.atomic.AtomicBoolean(false);

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
             * Capture the first transmitted SYN timestamp.
             */
            if (tcpHandshakeSynCaptured.compareAndSet(false, true)) {

                tcpHandshakeSynSentNano = System.nanoTime();

                long synSentWallTime = System.currentTimeMillis();

                String txSynLog =
                        "========== TCP HANDSHAKE | TX SYN ==========\n"
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
                                + "Sequence Number    : "
                                + seq
                                + "\n"
                                + "ACK Number         : "
                                + ack
                                + "\n"
                                + "TCP Flags          : 0x"
                                + String.format(
                                java.util.Locale.US,
                                "%02X",
                                flags
                        )
                                + "\n"
                                + "Window Size        : "
                                + windowSize
                                + "\n"
                                + "Checksum           : 0x"
                                + String.format(
                                java.util.Locale.US,
                                "%04X",
                                checksum
                        )
                                + "\n"
                                + "TCP Header Length  : "
                                + dataOffsetBytes
                                + " bytes\n"
                                + "Payload Length     : "
                                + payloadLen
                                + " bytes\n"
                                + "Handshake T0       : "
                                + tcpHandshakeSynSentNano
                                + " ns\n"
                                + "Timestamp          : "
                                + formatTimestamp(synSentWallTime)
                                + "\n"
                                + "==============================================";

                Log.i(TAG, txSynLog);

                dashboard.logToFile(
                        TAG + txSynLog
                );
            }
            /*
             * ============================================================
             * TCP CONNECTION TIME - T0
             * ============================================================
             *
             * Capture the first SYN received from the device.
             *
             * This does NOT replace the existing TCP handshake T0.
             */

            if (tcpConnectionStartCaptured.compareAndSet(false, true)) {

                tcpConnectionStartNano = System.nanoTime();

                long tcpConnectionStartWallTime =
                        System.currentTimeMillis();

                String tcpConnectionStartLog =
                        "========== TCP CONNECTION | T0 SYN ==========\n"
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
                                + "Sequence Number    : "
                                + seq
                                + "\n"
                                + "TCP Flags          : 0x"
                                + String.format(
                                java.util.Locale.US,
                                "%02X",
                                flags
                        )
                                + "\n"
                                + "Connection T0      : "
                                + tcpConnectionStartNano
                                + " ns\n"
                                + "Timestamp          : "
                                + formatTimestamp(
                                tcpConnectionStartWallTime
                        )
                                + "\n"
                                + "==============================================";

                Log.i(
                        TAG,
                        tcpConnectionStartLog
                );

                dashboard.logToFile(
                        TAG + tcpConnectionStartLog
                );
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
             * TCP HANDSHAKE T1 = TX ACK
             * ============================================================
             *
             * T0 = First TX SYN (0x02)
             * T1 = First TX ACK (0x10)
             *
             * TCP Handshake Time = T1 - T0
             *
             * Only the first ACK completing the handshake
             * is used.
             */

            if (tcpHandshakeSynCaptured.get()
                    && tcpHandshakeCaptured.compareAndSet(false, true)) {

                /*
                 * Capture T1.
                 */
                tcpHandshakeAckNano =
                        System.nanoTime();

                /*
                 * Calculate handshake time.
                 */
                if (tcpHandshakeSynSentNano > 0L) {

                    tcpHandshakeNano =
                            tcpHandshakeAckNano
                                    - tcpHandshakeSynSentNano;

                    tcpHandshakeMs =
                            tcpHandshakeNano / 1_000_000.0;

                    /*
                     * Publish TCP handshake time to dashboard.
                     */
                    dashboard.recordTcpHandshake(
                            tcpHandshakeNano
                    );
                }

                long ackWallTime =
                        System.currentTimeMillis();

                String txAckHandshakeLog =
                        "========== TCP HANDSHAKE | TX ACK ==========\n"
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
                                + "Sequence Number    : "
                                + seq
                                + "\n"
                                + "ACK Number         : "
                                + ack
                                + "\n"
                                + "TCP Flags          : 0x10\n"
                                + "TCP Header Length  : "
                                + dataOffsetBytes
                                + " bytes\n"
                                + "Payload Length     : "
                                + payloadLen
                                + " bytes\n"
                                + "Timestamp          : "
                                + formatTimestamp(ackWallTime)
                                + "\n"
                                + "\n"
                                + "Handshake T0       : "
                                + tcpHandshakeSynSentNano
                                + " ns\n"
                                + "Handshake T1       : "
                                + tcpHandshakeAckNano
                                + " ns\n"
                                + "T1 - T0            : "
                                + tcpHandshakeAckNano
                                + " - "
                                + tcpHandshakeSynSentNano
                                + " = "
                                + tcpHandshakeNano
                                + " ns\n"
                                + "Handshake Time     : "
                                + String.format(
                                java.util.Locale.US,
                                "%.3f",
                                tcpHandshakeMs
                        )
                                + " ms\n"
                                + "==============================================";

                // Logcat
                Log.i(TAG, txAckHandshakeLog);

                // Log file
                dashboard.logToFile(
                        TAG + txAckHandshakeLog
                );
            }

            dashboard.logToFile(TAG+"TCP Handshake completed.");

            session.state = TcpSession.State.ESTABLISHED;

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
                 * ================================================
                 * CAPTURE REQUEST START TIME
                 * ================================================
                 *
                 * Only the FIRST outgoing IP-matched packet
                 * captures TTFB request start time.
                 *
                 * This remains immediately before write().
                 */
//                if (isFirstOutgoingMatch
//                        && globalRequestCaptured.compareAndSet(false, true)) {
//
//                    globalRequestSentTime =
//                            System.nanoTime();
//
//                    globalRequestSentWallTime =
//                            System.currentTimeMillis();
//
//                    globalTtfbRequestDestinationIp =
//                            destinationIp;
//
//                    globalTtfbRequestResolvedIp =
//                            destinationIp;
//
//                    globalTtfbRequestPayloadSize =
//                            payloadLen;
//
//                    globalTtfbRequestConnectionKey =
//                            key;
//
//                    requestTimestampCapturedForThisPacket = true;
//
//                    String ttfbRequestTimestampLog =
//                            "========== T0_REQUEST_START ==========\n"
//                                    + "Timestamp Type   : REQUEST START\n"
//                                    + "Request Time     : "
//                                    + formatTimestamp(globalRequestSentWallTime)
//                                    + "\n"
//                                    + "Destination IP   : "
//                                    + globalTtfbRequestDestinationIp
//                                    + "\n"
//                                    + "Payload Size     : "
//                                    + globalTtfbRequestPayloadSize
//                                    + " bytes\n"
//                                    + "Connection Key   : "
//                                    + key
//                                    + "\n"
//                                    + "=====================================================";
//
//                    Log.i(
//                            TAG,
//                            ttfbRequestTimestampLog
//                    );
//
//                    dashboard.logEvent(
//                            TAG + ttfbRequestTimestampLog,
//                            VpnEvent.Level.INFO,
//                            VpnEvent.Category.TCP
//                    );
//                }  this is old ttfb logic

                /*
                 * ================================================
                 * TLS RECORD TYPE - SENT / TX
                 * ================================================
                 */
                if (data != null && data.length >= 5) {

                    int tlsRecordType = data[0] & 0xFF;

                    String tlsRecordName;

                    switch (tlsRecordType) {
                        case 0x14:
                            tlsRecordName = "Change Cipher Spec";
                            break;

                        case 0x15:
                            tlsRecordName = "Alert";
                            break;

                        case 0x16:
                            tlsRecordName = "Handshake";
                            break;

                        case 0x17:
                            tlsRecordName = "Application Data";
                            break;

                        default:
                            tlsRecordName = "Unknown / Non-standard TLS Record";
                            break;
                    }

                    /*
                     * =====================================================
                     * TLS HANDSHAKE T0
                     * =====================================================
                     *
                     * T0 = first transmitted TLS record with ContentType 0x16
                     */
                    if (tlsRecordType == 0x16
                            && tlsRecordType16Captured.compareAndSet(false, true)) {

                        globalTlsRecordType16T0Nano =
                                System.nanoTime();

                        globalTlsRecordType16T0WallTime =
                                System.currentTimeMillis();

                        String tlsT0Log =
                                "========== T0_TLS_RECORD_0x16 ==========\n"
                                        + "TLS Record Type  : 0x16\n"
                                        + "Record Type      : Handshake\n"
                                        + "Direction         : TX/SENT\n"
                                        + "Sent Bytes       : "
                                        + data.length
                                        + " bytes\n"
                                        + "T0 Nano          : "
                                        + globalTlsRecordType16T0Nano
                                        + " ns\n"
                                        + "T0 Timestamp     : "
                                        + formatTimestamp(
                                        globalTlsRecordType16T0WallTime
                                )
                                        + "\n"
                                        + "Source IP        : "
                                        + ipStr(srcIp)
                                        + "\n"
                                        + "Destination IP   : "
                                        + ipStr(dstIp)
                                        + "\n"
                                        + "Source Port      : "
                                        + srcPort
                                        + "\n"
                                        + "Destination Port : "
                                        + dstPort
                                        + "\n"
                                        + "Connection Key   : "
                                        + key
                                        + "\n"
                                        + "==========================================";

                        Log.i(TAG, tlsT0Log);

                        dashboard.logToFile(
                                TAG + tlsT0Log
                        );
                    }

                    String tlsSentLog =
                            "========== TLS RECORD [TX/SENT] ==========\n"
                                    + "Source IP        : " + ipStr(srcIp) + "\n"
                                    + "Destination IP   : " + ipStr(dstIp) + "\n"
                                    + "Source Port      : " + srcPort + "\n"
                                    + "Destination Port : " + dstPort + "\n"
                                    + "TLS Record Type  : 0x"
                                    + String.format("%02X", tlsRecordType) + "\n"
                                    + "Record Type      : " + tlsRecordName + "\n"
                                    + "Sent Bytes       : " + data.length + " bytes\n"
                                    + "Timestamp        : "
                                    + formatTimestamp(System.currentTimeMillis())
                                    + "\n"
                                    + "Connection Key   : " + key + "\n"
                                    + "============================================";

                    Log.i(TAG, tlsSentLog);

                    dashboard.logToFile(TAG + tlsSentLog);
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

        tcpHandshakeSynCaptured.set(false);
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

        tcpHandshakeSynCaptured.set(false);
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
            this.seqStart = seqStart;
            this.seqEnd = seqEnd;
            this.payloadLength = payloadLength;
            this.timestampNano = timestampNano;
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
                transmittedSegments = new java.util.concurrent.ConcurrentHashMap<>();


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

                        int receivedCount =
                                forwarder.totalPacketsReceived.incrementAndGet();

                        Log.d(TAG, "Received " + n + " bytes from server.");
                        Log.d(TAG, "realIn.read() = " + n);
                        Log.d(TAG, "Total Packets Received So Far = " + receivedCount);

                        forwarder.dashboard.logEvent(
                                TAG +
                                        "Total Packets Received So Far = "
                                        + receivedCount,
                                VpnEvent.Level.INFO,
                                VpnEvent.Category.TCP
                        );

                        Log.d(TAG, "First byte condition checking");



                        /*
                         * ====================================================
                         * T1 = FIRST TLS APPLICATION DATA RECORD
                         * ====================================================
                         *
                         * TLS ContentType:
                         *
                         * 0x14 = Change Cipher Spec
                         * 0x15 = Alert
                         * 0x16 = Handshake
                         * 0x17 = Application Data
                         *
                         * Requirement:
                         * T1 must be captured from the first received
                         * TLS Application Data record (0x17).
                         */
                        if (n >= 5) {

                            int tlsRecordType = buf[0] & 0xFF;

                            String tlsRecordName;

                            switch (tlsRecordType) {
                                case 0x14:
                                    tlsRecordName = "Change Cipher Spec";
                                    break;
                                case 0x15:
                                    tlsRecordName = "Alert";
                                    break;
                                case 0x16:
                                    tlsRecordName = "Handshake";
                                    break;
                                case 0x17:
                                    tlsRecordName = "Application Data";
                                    break;
                                default:
                                    tlsRecordName = "Unknown / Non-standard TLS Record";
                                    break;
                            }

                            String tlsRecordLog =
                                    "========== TLS RECORD [RX/RECEIVED] ==========\n"
                                            + "Source IP        : " + TcpForwarder.ipStr(dstIp) + "\n"
                                            + "Destination IP   : " + TcpForwarder.ipStr(srcIp) + "\n"
                                            + "Source Port      : " + dstPort + "\n"
                                            + "Destination Port : " + srcPort + "\n"
                                            + "TLS Record Type  : 0x"
                                            + String.format("%02X", tlsRecordType) + "\n"
                                            + "Record Type      : " + tlsRecordName + "\n"
                                            + "Received Bytes   : " + n + " bytes\n"
                                            + "Timestamp        : "
                                            + new java.text.SimpleDateFormat(
                                            "HH:mm:ss.SSS",
                                            java.util.Locale.US
                                    ).format(new java.util.Date())
                                            + "\n"
                                            + "Connection Key   : " + key + "\n"
                                            + "==============================================";

                            Log.d(TAG, tlsRecordLog);

                            forwarder.dashboard.logToFile(TAG + tlsRecordLog);
                        }

                        if (n >= 5
                                && !forwarder.tlsRecordType17Captured.get()
                                && isTlsApplicationDataRecord(buf, n)) {

                            if (forwarder.tlsRecordType17Captured
                                    .compareAndSet(false, true)) {

                                /*
                                 * =====================================================
                                 * T1 = FIRST TLS APPLICATION DATA RECORD
                                 * =====================================================
                                 */
                                forwarder.globalTlsRecordType17T1Nano =
                                        System.nanoTime();

                                forwarder.globalTlsRecordType17T1WallTime =
                                        System.currentTimeMillis();


                                String tlsT1Log =
                                        "========== T1_TLS_RECORD_0x17 ==========\n"
                                                + "TLS Record Type  : 0x17\n"
                                                + "Record Type      : Application Data\n"
                                                + "Received Bytes   : "
                                                + n
                                                + " bytes\n"
                                                + "T1 Nano          : "
                                                + forwarder.globalTlsRecordType17T1Nano
                                                + " ns\n"
                                                + "Timestamp        : "
                                                + forwarder.formatTimestamp(
                                                forwarder.globalTlsRecordType17T1WallTime
                                        )
                                                + "\n"
                                                + "Source IP        : "
                                                + TcpForwarder.ipStr(dstIp)
                                                + "\n"
                                                + "Destination IP   : "
                                                + TcpForwarder.ipStr(srcIp)
                                                + "\n"
                                                + "Connection Key   : "
                                                + key
                                                + "\n"
                                                + "==========================================";


                                Log.i(TAG, tlsT1Log);

                                forwarder.dashboard.logToFile(
                                        TAG + tlsT1Log
                                );


                                /*
                                 * =====================================================
                                 * TLS HANDSHAKE TIME
                                 * =====================================================
                                 *
                                 * T0 = first TX 0x16
                                 * T1 = first RX 0x17
                                 *
                                 * TLS Handshake Time = T1 - T0
                                 */

                                if (forwarder.globalTlsRecordType16T0Nano > 0L) {

                                    forwarder.globalTlsHandshakeNano =
                                            forwarder.globalTlsRecordType17T1Nano
                                                    - forwarder.globalTlsRecordType16T0Nano;

                                    forwarder.globalTlsHandshakeMs =
                                            forwarder.globalTlsHandshakeNano / 1_000_000.0;

                                    /*
                                     * Publish TLS handshake result to dashboard.
                                     */
                                    forwarder.dashboard.recordTlsHandshake(
                                            forwarder.globalTlsHandshakeMs
                                    );

                                    String tlsHandshakeLog =
                                            "========== TLS HANDSHAKE TIME ==========\n"
                                                    + "T0 TLS Record Type : 0x16 (TX/SENT)\n"
                                                    + "T0 Timestamp       : "
                                                    + forwarder.formatTimestamp(
                                                    forwarder.globalTlsRecordType16T0WallTime
                                            )
                                                    + "\n"
                                                    + "T0 Nano            : "
                                                    + forwarder.globalTlsRecordType16T0Nano
                                                    + " ns\n"
                                                    + "\n"
                                                    + "T1 TLS Record Type : 0x17 (RX/RECEIVED)\n"
                                                    + "T1 Timestamp       : "
                                                    + forwarder.formatTimestamp(
                                                    forwarder.globalTlsRecordType17T1WallTime
                                            )
                                                    + "\n"
                                                    + "T1 Nano            : "
                                                    + forwarder.globalTlsRecordType17T1Nano
                                                    + " ns\n"
                                                    + "\n"
                                                    + "TLS Handshake Time = T1 - T0\n"
                                                    + "                   = "
                                                    + forwarder.globalTlsRecordType17T1Nano
                                                    + " - "
                                                    + forwarder.globalTlsRecordType16T0Nano
                                                    + "\n"
                                                    + "                   = "
                                                    + forwarder.globalTlsHandshakeNano
                                                    + " ns\n"
                                                    + "                   = "
                                                    + String.format(
                                                    java.util.Locale.US,
                                                    "%.3f",
                                                    forwarder.globalTlsHandshakeMs
                                            )
                                                    + " ms\n"
                                                    + "==========================================";

                                    Log.i(TAG, tlsHandshakeLog);

                                    forwarder.dashboard.logToFile(
                                            TAG + tlsHandshakeLog
                                    );

                                } else {

                                    String tlsHandshakeNotCalculatedLog =
                                            "========== TLS HANDSHAKE NOT CALCULATED ==========\n"
                                                    + "Reason : TLS 0x16 TX T0 is not available\n"
                                                    + "T0 Nano : "
                                                    + forwarder.globalTlsRecordType16T0Nano
                                                    + " ns\n"
                                                    + "T1 Nano : "
                                                    + forwarder.globalTlsRecordType17T1Nano
                                                    + " ns\n"
                                                    + "===================================================";

                                    Log.w(TAG, tlsHandshakeNotCalculatedLog);

                                    forwarder.dashboard.logToFile(
                                            TAG + tlsHandshakeNotCalculatedLog
                                    );
                                }


                                /*
                                 * =====================================================
                                 * TTFB CALCULATION
                                 * =====================================================
                                 *
                                 * T0 = DNS Request Start
                                 * T1 = TLS ContentType 0x17
                                 *
                                 * TTFB = T1 - T0
                                 * =====================================================
                                 */
                                if (forwarder.globalDnsT0Nano > 0L) {

                                    long ttfbNano =
                                            forwarder.globalTlsRecordType17T1Nano
                                                    - forwarder.globalDnsT0Nano;

                                    long ttfbMicros =
                                            TimeUnit.NANOSECONDS.toMicros(
                                                    ttfbNano
                                            );

                                    double ttfbMs =
                                            ttfbNano / 1_000_000.0;

                                    forwarder.globalTtfbMs =
                                            (long) ttfbMs;


                                    String ttfbLog =
                                            "========== T2_TTFB ==========\n"
                                                    + "Destination IP : "
                                                    + forwarder.globalTtfbRequestDestinationIp
                                                    + "\n"
                                                    + "Resolved IP    : "
                                                    + forwarder.globalTtfbRequestResolvedIp
                                                    + "\n"
                                                    + "\n"
                                                    + "DNS T0 Nano          : "
                                                    + forwarder.globalDnsT0Nano
                                                    + " ns\n"
                                                    + "TLS Record Type      : 0x17\n"
                                                    + "TLS T1 Nano          : "
                                                    + forwarder.globalTlsRecordType17T1Nano
                                                    + " ns\n"
                                                    + "\n"
                                                    + "TTFB = TLS 0x17 T1 - DNS T0\n"
                                                    + "     = "
                                                    + forwarder.globalTlsRecordType17T1Nano
                                                    + " - "
                                                    + forwarder.globalDnsT0Nano
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


                                    Log.i(TAG, ttfbLog);

                                    forwarder.dashboard.logToFile(
                                            TAG + ttfbLog
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
                                                    + forwarder.globalTlsRecordType17T1Nano
                                                    + " ns\n"
                                                    + "DNS T0 : "
                                                    + forwarder.globalDnsT0Nano
                                                    + " ns\n"
                                                    + "==========================================";

                                    Log.w(TAG, noT0Log);

                                    forwarder.dashboard.logToFile(
                                            TAG + noT0Log
                                    );
                                }
                            }
                        }

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
//                        if (n > 0
//                                && !forwarder.globalTtfbCaptured.get()
//                                && forwarder.globalRequestCaptured.get()
//                                && forwarder.globalRequestSentTime > 0
//                                && key.equals(forwarder.globalTtfbRequestConnectionKey)) {
//
//                            if (forwarder.globalTtfbCaptured.compareAndSet(false, true)) {
//
//                                /*
//                                 * ================================================
//                                 * FIRST BYTE TIMESTAMP
//                                 * ================================================
//                                 */
//
//                                forwarder.globalFirstByteReceivedTime =
//                                        System.nanoTime();
//
//                                forwarder.globalFirstByteReceivedWallTime =
//                                        System.currentTimeMillis();
//
//                                String ttfbFirstByteTimestampLog =
//                                        "========== T1_FIRST_BYTE_RECEIVED ==========\n"
//                                                + "Timestamp Type   : FIRST BYTE RECEIVED\n"
//                                                + "First Byte Time  : "
//                                                + forwarder.formatTimestamp(
//                                                forwarder.globalFirstByteReceivedWallTime
//                                        )
//                                                + "\n"
//                                                + "Destination IP   : "
//                                                + forwarder.globalTtfbRequestDestinationIp
//                                                + "\n"
//                                                + "Received Payload : "
//                                                + n
//                                                + " bytes\n"
//                                                + "=======================================================";
//
//
//                                Log.i(
//                                        TAG,
//                                        ttfbFirstByteTimestampLog
//                                );
//
//
//                                forwarder.dashboard.logEvent(TAG+
//                                        ttfbFirstByteTimestampLog,
//                                        VpnEvent.Level.INFO,
//                                        VpnEvent.Category.TCP
//                                );
//
//                                /*
//                                 * ================================================
//                                 * TTFB IN MILLISECONDS
//                                 * ================================================
//                                 */
//
//                                forwarder.globalTtfbMs =
//                                        TimeUnit.NANOSECONDS.toMillis(
//                                                forwarder.globalFirstByteReceivedTime
//                                                        - forwarder.globalRequestSentTime
//                                        );
//
//                                /*
//                                 * ================================================
//                                 * TTFB IN MICROSECONDS
//                                 * ================================================
//                                 */
//
//                                long ttfbMicros =
//                                        TimeUnit.NANOSECONDS.toMicros(
//                                                forwarder.globalFirstByteReceivedTime
//                                                        - forwarder.globalRequestSentTime
//                                        );
//
//                                /*
//                                 * ================================================
//                                 * HUMAN READABLE TIMESTAMPS
//                                 * ================================================
//                                 */
//
//                                String requestTimestamp =
//                                        forwarder.formatTimestamp(
//                                                forwarder.globalRequestSentWallTime
//                                        );
//
//                                String firstByteTimestamp =
//                                        forwarder.formatTimestamp(
//                                                forwarder.globalFirstByteReceivedWallTime
//                                        );
//
//                                /*
//                                 * ================================================
//                                 * FINAL TTFB LOG
//                                 * ================================================
//                                 */
//
//                                String ttfbLog =
//                                        "========== T2_TTFB ==========\n"
//                                                + "Destination IP : "
//                                                + forwarder.globalTtfbRequestDestinationIp
//                                                + "\n"
//                                                + "Resolved IP    : "
//                                                + forwarder.globalTtfbRequestResolvedIp
//                                                + "\n"
//                                                + "Request Payload: "
//                                                + forwarder.globalTtfbRequestPayloadSize
//                                                + " bytes\n"
//                                                + "\n"
//                                                + "Request Sent Time: "
//                                                + requestTimestamp
//                                                + "\n"
//                                                + "First Byte Time  : "
//                                                + firstByteTimestamp
//                                                + "\n"
//                                                + "\n"
//                                                + "TTFB = First Byte - Request Sent\n"
//                                                + "     = "
//                                                + firstByteTimestamp
//                                                + " - "
//                                                + requestTimestamp
//                                                + "\n"
//                                                + "     = "
//                                                + ttfbMicros
//                                                + " µs\n"
//                                                + "     = "
//                                                + forwarder.globalTtfbMs
//                                                + " ms\n"
//                                                + "==========================";
//
//                                Log.i(
//                                        TAG,
//                                        ttfbLog
//                                );
//
//                                forwarder.dashboard.logEvent(TAG+
//                                        ttfbLog,
//                                        VpnEvent.Level.INFO,
//                                        VpnEvent.Category.TCP
//                                );
//
//                                forwarder.reportTtfb(
//                                        this,
//                                        forwarder.globalTtfbMs,
//                                        key
//                                );
//                            }
//                        } old ttfb logic

                        if (n > 0) {

                            String rxHeaderLog =
                                    "========== [RX] TCP HEADER ==========\n"
                                            + "Source IP          : " + TcpForwarder.ipStr(dstIp) + "\n"
                                            + "Destination IP     : " + TcpForwarder.ipStr(srcIp) + "\n"
                                            + "Host Name          : " + serverName + "\n"
                                            + "Server IP          : " + serverIp + "\n"
                                            + "Source Port        : " + dstPort + "\n"
                                            + "Destination Port   : " + srcPort + "\n"
                                            + "Payload Length     : " + n + "\n"
                                            + "Sequence Number    : " + deviceSeq + "\n"
                                            + "ACK Number         : " + clientNextSeq + "\n"
                                            + "=====================================";

                            forwarder.dashboard.logEvent(TAG+rxHeaderLog, VpnEvent.Level.INFO, VpnEvent.Category.TCP);

                            String incomingIp = TcpForwarder.ipStr(dstIp);

                            if (forwarder.websiteResolvedIps.contains(incomingIp)) {

                                boolean isFirstIncomingMatch =
                                        forwarder.firstIncomingIpMatchLogged.compareAndSet(false, true);

                                int matchCount =
                                        forwarder.incomingIpMatchCount.incrementAndGet();

                                String evtName =
                                        isFirstIncomingMatch ? "IC_IP_MATCH" : "I_IP_MATCH";

                                /*
                                 * Capture IC_IP_MATCH timestamp only for the first
                                 * incoming IP match.
                                 */
                                if (isFirstIncomingMatch) {

//                                    forwarder.globalIncomingIpMatchTime =
//                                            System.nanoTime();

                                    forwarder.globalIncomingIpMatchWallTime =
                                            System.currentTimeMillis();
                                    forwarder.dashboard.logToFile(
                                            TAG +
                                                    "========== T1_Time IC_IP_MATCH PACKET ==========\n"
                                                    + "Source IP       : " + incomingIp + "\n"
                                                    + "Destination IP  : " + TcpForwarder.ipStr(srcIp) + "\n"
                                                    + "Source Port     : " + dstPort + "\n"
                                                    + "Destination Port: " + srcPort + "\n"
                                                    + "Protocol        : TCP\n"
                                                    + "Packet Length   : " + n + " bytes\n"
                                                    + "Timestamp       : "
                                                    + forwarder.formatTimestamp(
                                                    forwarder.globalIncomingIpMatchWallTime
                                            )
                                                    + "\n"
                                                    + "Timestamp Nano  : "
                                                    + forwarder.globalIncomingIpMatchTime
                                                    + " ns\n"
                                                    + "============================================"
                                    );

                                    Log.d(
                                            TAG,
                                            "IC_IP_MATCH T1_Time timestamp captured = "
                                                    + forwarder.globalIncomingIpMatchTime
                                                    + " ns"
                                    );

//                                    /*
//                                     * =====================================================
//                                     * NEW TTFB CALCULATION
//                                     * TTFB = IC_IP_MATCH - OG_IP_MATCH
//                                     * =====================================================
//                                     */
//                                    if (forwarder.webViewT0Nano > 0L) {
//
//                                        long ttfbNano =
//                                                forwarder.globalIncomingIpMatchTime
//                                                        - forwarder.webViewT0Nano;
//
//                                        long ttfbMicros =
//                                                TimeUnit.NANOSECONDS.toMicros(ttfbNano);
//
//                                        forwarder.globalTtfbMs =
//                                                TimeUnit.NANOSECONDS.toMillis(ttfbNano);
//
//                                        String ttfbLog =
//                                                "========== T2_TTFB ==========\n"
//                                                        + "Destination IP : "
//                                                        + forwarder.globalTtfbRequestDestinationIp
//                                                        + "\n"
//                                                        + "Resolved IP    : "
//                                                        + forwarder.globalTtfbRequestResolvedIp
//                                                        + "\n"
//                                                        + "\n"
//                                                        + "WebView T0 Nano: "
//                                                        + forwarder.webViewT0Nano
//                                                        + " ns\n"
//                                                        + "IC_IP_MATCH T1 Nano: "
//                                                        + forwarder.globalIncomingIpMatchTime
//                                                        + " ns\n"
//                                                        + "\n"
//                                                        + "TTFB = IC_IP_MATCH T1 - WebView T0\n"
//                                                        + "     = "
//                                                        + ttfbNano
//                                                        + " ns\n"
//                                                        + "     = "
//                                                        + ttfbMicros
//                                                        + " µs\n"
//                                                        + "     = "
//                                                        + forwarder.globalTtfbMs
//                                                        + " ms\n"
//                                                        + "==========================";
//                                        Log.i(TAG, ttfbLog);
//
//                                        forwarder.dashboard.logEvent(
//                                                TAG + ttfbLog,
//                                                VpnEvent.Level.SUCCESS,
//                                                VpnEvent.Category.TCP
//                                        );
//
//                                        forwarder.reportTtfb(
//                                                this,
//                                                forwarder.globalTtfbMs,
//                                                key
//                                        );
//                                    }
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
                                    if (forwarder.globalDnsT0Nano > 0L
                                            && forwarder.globalTlsRecordType17T1Nano > 0L) {

                                        long ttfbNano =
                                                forwarder.globalTlsRecordType17T1Nano
                                                        - forwarder.globalDnsT0Nano;

                                        long ttfbMicros =
                                                TimeUnit.NANOSECONDS.toMicros(ttfbNano);

                                        forwarder.globalTtfbMs =
                                                TimeUnit.NANOSECONDS.toMillis(ttfbNano);


                                        String ttfbLog =
                                                "========== T2_TTFB ==========\n"
                                                        + "Destination IP : "
                                                        + forwarder.globalTtfbRequestDestinationIp
                                                        + "\n"
                                                        + "Resolved IP    : "
                                                        + forwarder.globalTtfbRequestResolvedIp
                                                        + "\n"
                                                        + "\n"
                                                        + "DNS T0 Nano          : "
                                                        + forwarder.globalDnsT0Nano
                                                        + " ns\n"
                                                        + "TLS Record Type      : 0x17\n"
                                                        + "TLS T1 Nano          : "
                                                        + forwarder.globalTlsRecordType17T1Nano
                                                        + " ns\n"
                                                        + "TLS T1 Timestamp     : "
                                                        + forwarder.formatTimestamp(
                                                        forwarder.globalTlsRecordType17T1WallTime
                                                )
                                                        + "\n"
                                                        + "\n"
                                                        + "TTFB = TLS 0x17 T1 - DNS T0\n"
                                                        + "     = "
                                                        + forwarder.globalTlsRecordType17T1Nano
                                                        + " - "
                                                        + forwarder.globalDnsT0Nano
                                                        + "\n"
                                                        + "     = "
                                                        + ttfbNano
                                                        + " ns\n"
                                                        + "     = "
                                                        + ttfbMicros
                                                        + " µs\n"
                                                        + "     = "
                                                        + forwarder.globalTtfbMs
                                                        + " ms\n"
                                                        + "==========================";


                                        Log.i(TAG, ttfbLog);

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

                                String ipMatchLog =
                                        "========== " + evtName + " ==========\n"
                                                + "Match Count    : " + matchCount + "\n"
                                                + "Source IP      : " + incomingIp + "\n"
                                                + "Payload Length : " + n + " bytes\n"
                                                + "Connection Key : " + key + "\n";

                                if (isFirstIncomingMatch) {
                                    ipMatchLog +=
                                            "IC_IP_MATCH Time: "
                                                    + forwarder.formatTimestamp(
                                                    forwarder.globalIncomingIpMatchWallTime
                                            )
                                                    + "\n"
                                                    + "IC_IP_MATCH Nano: "
                                                    + forwarder.globalIncomingIpMatchTime
                                                    + " ns\n";
                                }

                                ipMatchLog +=
                                        "===================================";

                                Log.i(TAG, ipMatchLog);

                                forwarder.dashboard.logEvent(
                                        TAG + ipMatchLog,
                                        VpnEvent.Level.INFO,
                                        VpnEvent.Category.TCP
                                );
                            }
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
    /**
     * Checks whether the received bytes start with a TLS
     * Application Data record.
     *
     * TLS Record Header:
     *
     * Byte 0 = Content Type
     * Byte 1 = TLS Version Major
     * Byte 2 = TLS Version Minor
     * Byte 3 = Record Length MSB
     * Byte 4 = Record Length LSB
     *
     * 0x17 = Application Data
     */
    private static boolean isTlsApplicationDataRecord(
            byte[] data,
            int length
    ) {

        if (data == null || length < 5) {
            return false;
        }

        int contentType = data[0] & 0xFF;

        // TLS Application Data
        if (contentType != 0x17) {
            return false;
        }

        /*
         * TLS version validation.
         *
         * 0x03 0x01 = TLS 1.0
         * 0x03 0x02 = TLS 1.1
         * 0x03 0x03 = TLS 1.2
         * 0x03 0x04 = TLS 1.3
         */
        int versionMajor = data[1] & 0xFF;
        int versionMinor = data[2] & 0xFF;

        if (versionMajor != 0x03) {
            return false;
        }

        /*
         * Validate that the TLS record declares
         * a payload length that fits in the received data.
         */
        int recordLength =
                ((data[3] & 0xFF) << 8)
                        | (data[4] & 0xFF);

        return length >= 5 + recordLength;
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
