package com.example.vpntest.appOpen;

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
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import com.example.vpntest.PacketUtils;
import com.example.vpntest.ParsedPacket;
import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.repo.VpnEventRepository;


class AppOpenTcpForwarder {

    private static final String TAG = "AppOpen_TcpForwarder : ";

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

    private final VpnEventRepository dashboard =
            VpnEventRepository.getInstance();

    private final java.util.concurrent.atomic.AtomicBoolean
            globalTtfbCaptured =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    /*
     * Tracks whether the first outgoing TCP payload has already
     * been selected as the TTFB request-side packet.
     */
    private final java.util.concurrent.atomic.AtomicBoolean
            firstOutgoingIpMatchLogged =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    /*
     * Tracks whether the first incoming response packet has already
     * been observed.
     */
    private final java.util.concurrent.atomic.AtomicBoolean
            firstIncomingIpMatchLogged =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    private final java.util.concurrent.atomic.AtomicInteger
            outgoingIpMatchCount =
            new java.util.concurrent.atomic.AtomicInteger(0);

    private final java.util.concurrent.atomic.AtomicInteger
            incomingIpMatchCount =
            new java.util.concurrent.atomic.AtomicInteger(0);

    /*
     * Total TCP packets forwarded device -> real server.
     */
    private final java.util.concurrent.atomic.AtomicInteger
            totalPacketsSent =
            new java.util.concurrent.atomic.AtomicInteger(0);

    /*
     * Total TCP packets received real server -> device.
     */
    private final java.util.concurrent.atomic.AtomicInteger
            totalPacketsReceived =
            new java.util.concurrent.atomic.AtomicInteger(0);


    /*
     * ============================================================
     * TCP TRANSMISSION / RETRANSMISSION TRACKING
     * ============================================================
     *
     * SAME LOGIC AS NORMAL TcpForwarder.
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
    private final java.util.concurrent.atomic.AtomicLong
            totalTcpTransmissions =
            new java.util.concurrent.atomic.AtomicLong(0);

    private final java.util.concurrent.atomic.AtomicLong
            totalTcpTransmissionBytes =
            new java.util.concurrent.atomic.AtomicLong(0);

    private final java.util.concurrent.atomic.AtomicLong
            totalTcpRetransmissions =
            new java.util.concurrent.atomic.AtomicLong(0);

    private final java.util.concurrent.atomic.AtomicLong
            totalTcpRetransmissionBytes =
            new java.util.concurrent.atomic.AtomicLong(0);


    /*
     * =========================================================
     * TCP HANDSHAKE TIMING
     * =========================================================
     *
     * T0 = First TX SYN (0x02)
     * T1 = First TX ACK (0x10)
     *
     * TCP Handshake Time = T1 - T0
     */

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
     * =========================================================
     * TTFB TIMING
     * =========================================================
     *
     * T0 = exact DNS transaction start time selected by matching
     *      the TCP destination IP with DNS Answer IP.
     *
     * T1 = first received valid TLS Application Data record 0x17.
     *
     * TTFB = T1 - DNS T0
     */

    private volatile long globalOutgoingIpMatchTime = 0L;

    private volatile long globalIncomingIpMatchTime = 0L;

    private volatile long globalOutgoingIpMatchWallTime = 0L;

    private volatile long globalIncomingIpMatchWallTime = 0L;

    private volatile long globalDnsT0Nano = 0L;

    /*
     * =========================================================
     * TLS HANDSHAKE TIMING
     * =========================================================
     *
     * T0 = FIRST transmitted TLS record with
     *      ContentType 0x16 (Handshake)
     *
     * T1 = FIRST received TLS record with
     *      ContentType 0x17 (Application Data)
     *
     * TLS Handshake Time = T1 - T0
     */


    /*
     * =========================================================
     * T0 = FIRST TX TLS 0x16
     * =========================================================
     */

    private volatile long globalTlsRecordType16T0Nano = 0L;

    private volatile long globalTlsRecordType16T0WallTime = 0L;

    private final java.util.concurrent.atomic.AtomicBoolean
            tlsRecordType16Captured =
            new java.util.concurrent.atomic.AtomicBoolean(false);


    /*
     * =========================================================
     * T1 = FIRST RX TLS 0x17
     * =========================================================
     */

    private volatile long globalTlsRecordType17T1Nano = 0L;

    private volatile long globalTlsRecordType17T1WallTime = 0L;

    private final java.util.concurrent.atomic.AtomicBoolean
            tlsRecordType17Captured =
            new java.util.concurrent.atomic.AtomicBoolean(false);


    /*
     * =========================================================
     * TLS HANDSHAKE RESULT
     * =========================================================
     */

    private volatile long globalTlsHandshakeNano = -1L;

    private volatile double globalTlsHandshakeMs = -1.0;


    /*
     * =========================================================
     * EXISTING TTFB
     * =========================================================
     */

    private volatile long globalTtfbMs = -1L;

    private volatile String globalTtfbRequestConnectionKey = null;

    private volatile String globalTtfbRequestDestinationIp = null;

    private volatile String globalTtfbRequestResolvedIp = null;

    private volatile int globalTtfbRequestPayloadSize = 0;

    /*
     * =========================================================
     * YOUTUBE TEST LOGGING
     * =========================================================
     */

    private volatile boolean youtubeTestRunning = false;

    private final java.util.concurrent.atomic.AtomicInteger
            youtubePacketCounter =
            new java.util.concurrent.atomic.AtomicInteger(0);


    AppOpenTcpForwarder(
            VpnService vpnService,
            FileOutputStream tunOut,
            Object tunWriteLock,
            Network underlyingNetwork) {

        this.vpnService = vpnService;
        this.tunOut = tunOut;
        this.tunWriteLock = tunWriteLock;
        this.underlyingNetwork = underlyingNetwork;

        Log.d(
                TAG,
                "TcpForwarder underlyingNetwork = "
                        + underlyingNetwork
        );
    }


    /**
     * @param packet full packet bytes as read from the TUN
     * @param length total valid length of packet
     * @param parsed pre-parsed IPv4/IPv6 header info
     */
    void handlePacket(
            byte[] packet,
            int length,
            ParsedPacket parsed) {

        if (shutdown) {
            return;
        }

        byte[] srcIp = parsed.sourceIpBytes;
        byte[] dstIp = parsed.destinationIpBytes;

        int srcPort = parsed.sourcePort;
        int dstPort = parsed.destinationPort;

        Log.d(
                TAG,
                "========== TCP HANDLE PACKET =========="
        );

        Log.d(
                TAG,
                "Src: "
                        + ipStr(srcIp)
                        + ":"
                        + srcPort
        );

        Log.d(
                TAG,
                "Dst: "
                        + ipStr(dstIp)
                        + ":"
                        + dstPort
        );

        Log.d(
                TAG,
                "Length: "
                        + length
        );

        Log.d(
                TAG,
                "======================================="
        );

        int tcpHeaderOffset =
                parsed.transportHeaderOffset;

        if (length < tcpHeaderOffset + 20) {
            return;
        }

        int version =
                parsed.ipVersion;

        int ttl =
                parsed.ttlOrHopLimit;

        /*
         * =========================================================
         * TCP HEADER
         * =========================================================
         */

        long seq =
                readUnsignedInt(
                        packet,
                        tcpHeaderOffset + 4
                );

        long ack =
                readUnsignedInt(
                        packet,
                        tcpHeaderOffset + 8
                );

        int dataOffsetBytes =
                ((packet[tcpHeaderOffset + 12] >> 4) & 0x0F) * 4;

        int flags =
                packet[tcpHeaderOffset + 13] & 0xFF;

        int windowSize =
                ((packet[tcpHeaderOffset + 14] & 0xFF) << 8)
                        | (packet[tcpHeaderOffset + 15] & 0xFF);

        int checksum =
                ((packet[tcpHeaderOffset + 16] & 0xFF) << 8)
                        | (packet[tcpHeaderOffset + 17] & 0xFF);

        int urgentPointer =
                ((packet[tcpHeaderOffset + 18] & 0xFF) << 8)
                        | (packet[tcpHeaderOffset + 19] & 0xFF);

        int payloadOffset =
                tcpHeaderOffset + dataOffsetBytes;

        int payloadLen =
                length - payloadOffset;

        if (payloadLen < 0) {
            payloadLen = 0;
        }

        String key =
                parsed.connectionKey();

        TcpSession session =
                sessions.get(key);

        StringBuilder tcpHeaderLog =
                new StringBuilder();

        tcpHeaderLog
                .append(
                        "========== [TX] TCP/IP HEADER ==========\n"
                )
                .append(
                        "IP Version         : IPv"
                )
                .append(version)
                .append("\n")
                .append(
                        "Source IP          : "
                )
                .append(ipStr(srcIp))
                .append("\n")
                .append(
                        "Destination IP     : "
                )
                .append(ipStr(dstIp))
                .append("\n")
                .append(
                        "Host Name          : "
                )
                .append(
                        session != null
                                ? session.serverName
                                : "Unknown"
                )
                .append("\n")
                .append(
                        "Source Port        : "
                )
                .append(srcPort)
                .append("\n")
                .append(
                        "Destination Port   : "
                )
                .append(dstPort)
                .append("\n");

        if (version == 4) {

            tcpHeaderLog
                    .append(
                            "TTL                : "
                    )
                    .append(ttl)
                    .append("\n")
                    .append(
                            "IP Header Length   : "
                    )
                    .append(parsed.ipHeaderLength)
                    .append("\n");

        } else {

            tcpHeaderLog
                    .append(
                            "Hop Limit          : "
                    )
                    .append(ttl)
                    .append("\n")
                    .append(
                            "IPv6 Header Length : "
                    )
                    .append(parsed.ipHeaderLength)
                    .append("\n")
                    .append(
                            "Transport Offset   : "
                    )
                    .append(tcpHeaderOffset)
                    .append("\n")
                    .append(
                            "IPv6 Payload Length: "
                    )
                    .append(parsed.payloadLength)
                    .append("\n");
        }

        tcpHeaderLog
                .append(
                        "TCP Header Length  : "
                )
                .append(dataOffsetBytes)
                .append("\n")
                .append(
                        "Sequence Number    : "
                )
                .append(seq)
                .append("\n")
                .append(
                        "ACK Number         : "
                )
                .append(ack)
                .append("\n")
                .append(
                        "TCP Flags          : 0x"
                )
                .append(
                        Integer.toHexString(flags)
                )
                .append("\n")
                .append(
                        "Window Size        : "
                )
                .append(windowSize)
                .append("\n")
                .append(
                        "Checksum           : 0x"
                )
                .append(
                        Integer.toHexString(checksum)
                )
                .append("\n")
                .append(
                        "Urgent Pointer     : "
                )
                .append(urgentPointer)
                .append("\n")
                .append(
                        "Payload Length     : "
                )
                .append(payloadLen)
                .append("\n")
                .append(
                        "==================================="
                );

        Log.d(
                TAG,
                tcpHeaderLog.toString()
        );

        dashboard.logEvent(
                TAG + tcpHeaderLog,
                VpnEvent.Level.INFO,
                VpnEvent.Category.TCP
        );


        boolean isSyn =
                (flags & PacketUtils.TCP_SYN) != 0;

        boolean isAck =
                (flags & PacketUtils.TCP_ACK) != 0;

        boolean isFin =
                (flags & PacketUtils.TCP_FIN) != 0;

        boolean isRst =
                (flags & PacketUtils.TCP_RST) != 0;


        Log.d(
                TAG,
                "Flags: SYN="
                        + isSyn
                        + " ACK="
                        + isAck
                        + " FIN="
                        + isFin
                        + " RST="
                        + isRst
        );


        if (session != null) {

            dashboard.logEvent(
                    TAG
                            + "Session State = "
                            + session.state,
                    VpnEvent.Level.INFO,
                    VpnEvent.Category.TCP
            );
        }


        /*
         * =========================================================
         * SYN
         * =========================================================
         */

        if (flags == 0x02) {

            /*
             * =========================================================
             * TCP HANDSHAKE T0 = TX SYN
             * =========================================================
             *
             * T0 = First outgoing SYN
             * TCP Flags = 0x02
             */

            if (tcpHandshakeSynCaptured
                    .compareAndSet(false, true)) {

                tcpHandshakeSynSentNano =
                        System.nanoTime();

                long synSentWallTime =
                        System.currentTimeMillis();

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
                                + formatTimestamp(
                                synSentWallTime
                        )
                                + "\n"
                                + "==============================================";

                Log.i(
                        TAG,
                        txSynLog
                );

                dashboard.logToFile(
                        TAG + txSynLog
                );
            }
        }


        if (isSyn && !isAck) {

            if (session != null) {

                if (session.state ==
                        TcpSession.State.SYN_RCVD
                        || session.state ==
                        TcpSession.State.ESTABLISHED) {

                    if (session.synAckSent.get()) {

                        Log.d(
                                TAG,
                                "Retransmitted SYN for existing session "
                                        + key
                                        + ", re-sending SYN-ACK."
                        );

                        dashboard.logEvent(
                                TAG
                                        + "Retransmitted SYN for existing session "
                                        + key
                                        + ", re-sending SYN-ACK.",
                                VpnEvent.Level.INFO,
                                VpnEvent.Category.TCP
                        );

                        sendSynAck(session);
                    }

                    return;
                }

                closeSession(
                        key,
                        session
                );
            }

            startNewSession(
                    key,
                    srcIp,
                    srcPort,
                    dstIp,
                    dstPort,
                    seq
            );

            return;
        }


        /*
         * =========================================================
         * UNKNOWN SESSION
         * =========================================================
         */

        if (session == null) {

            if (!isRst) {

                sendRst(
                        dstIp,
                        dstPort,
                        srcIp,
                        srcPort,
                        ack,
                        seq + payloadLen
                );
            }

            return;
        }


        if (isRst) {

            closeSession(
                    key,
                    session
            );

            return;
        }


        /*
         * ============================================================
         * TCP HANDSHAKE T1 = TX ACK
         * ============================================================
         *
         * T0 = First TX SYN
         *      Flags = 0x02
         *
         * T1 = First TX ACK
         *      Flags = 0x10
         *
         * TCP Handshake Time = T1 - T0
         *
         * IMPORTANT:
         * SYN-ACK 0x12 is NOT T1.
         */

        if (session.state ==
                TcpSession.State.SYN_RCVD
                && flags == 0x10) {

            /*
             * ========================================================
             * Capture first TX ACK as T1
             * ========================================================
             */

            if (tcpHandshakeSynCaptured.get()
                    && tcpHandshakeCaptured.compareAndSet(
                    false,
                    true
            )) {

                /*
                 * T1 = TX ACK timestamp
                 */
                tcpHandshakeAckNano =
                        System.nanoTime();


                /*
                 * ====================================================
                 * Calculate TCP handshake time
                 * ====================================================
                 */

                if (tcpHandshakeSynSentNano > 0L) {

                    tcpHandshakeNano =
                            tcpHandshakeAckNano
                                    - tcpHandshakeSynSentNano;

                    tcpHandshakeMs =
                            tcpHandshakeNano
                                    / 1_000_000.0;


                    /*
                     * Send handshake value to dashboard
                     */
                    dashboard.recordTcpHandshake(
                            tcpHandshakeNano
                    );
                }


                /*
                 * ====================================================
                 * T1 LOG
                 * ====================================================
                 */

                long ackWallTime =
                        System.currentTimeMillis();

                String txAckLog =
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
                                + "Handshake T0       : "
                                + tcpHandshakeSynSentNano
                                + " ns\n"
                                + "Handshake T1       : "
                                + tcpHandshakeAckNano
                                + " ns\n"
                                + "T1 - T0            : "
                                + tcpHandshakeNano
                                + " ns\n"
                                + "Handshake Time     : "
                                + String.format(
                                java.util.Locale.US,
                                "%.3f",
                                tcpHandshakeMs
                        )
                                + " ms\n"
                                + "Timestamp          : "
                                + formatTimestamp(
                                ackWallTime
                        )
                                + "\n"
                                + "==============================================";


                Log.i(
                        TAG,
                        txAckLog
                );

                dashboard.logToFile(
                        TAG + txAckLog
                );
            }


            /*
             * ========================================================
             * TCP HANDSHAKE COMPLETE
             * ========================================================
             */

            Log.d(
                    TAG,
                    "TCP Handshake completed."
            );

            dashboard.logToFile(
                    TAG + "TCP Handshake completed."
            );


            session.state =
                    TcpSession.State.ESTABLISHED;


            session.startRealSocketReaderThread(
                    this,
                    key
            );
        }


        Log.d(
                TAG,
                "payload len and sessionstate : "
                        + payloadLen
                        + " "
                        + session.state
        );


        boolean isPsh =
                (flags & PacketUtils.TCP_PSH) != 0;


        /*
         * =========================================================
         * OUTGOING TCP PAYLOAD
         * =========================================================
         */

        if (payloadLen > 0
                && isPsh
                && session.state ==
                TcpSession.State.ESTABLISHED) {

            byte[] data =
                    new byte[payloadLen];

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
             * SAME LOGIC AS NORMAL TcpForwarder.
             *
             * Current packet:
             *
             * SEQ       = seq
             * PAYLOAD   = payloadLen
             * END SEQ   = seq + payloadLen
             *
             * Compare this sequence range with previously transmitted
             * ranges of the SAME TCP session.
             */

            long currentSeqStart =
                    seq;

            long currentSeqEnd =
                    seq + payloadLen;

            TcpSegmentRecord overlappingSegment =
                    null;

            long retransmittedBytes =
                    0L;


            /*
             * Check whether any part of this sequence range was already
             * transmitted.
             */

            for (TcpSegmentRecord oldSegment :
                    session.transmittedSegments.values()) {

                long overlapStart =
                        Math.max(
                                currentSeqStart,
                                oldSegment.seqStart
                        );

                long overlapEnd =
                        Math.min(
                                currentSeqEnd,
                                oldSegment.seqEnd
                        );


                /*
                 * If overlapStart < overlapEnd,
                 * some bytes in the current packet were already sent.
                 */

                if (overlapStart < overlapEnd) {

                    long overlapBytes =
                            overlapEnd - overlapStart;

                    if (overlapBytes > retransmittedBytes) {

                        retransmittedBytes =
                                overlapBytes;

                        overlappingSegment =
                                oldSegment;
                    }
                }
            }


            boolean isRetransmission =
                    retransmittedBytes > 0;


            /*
             * ============================================================
             * TRANSMISSION / RETRANSMISSION LOG
             * ============================================================
             */

            long packetTimestampNano =
                    System.nanoTime();

            long packetTimestampWall =
                    System.currentTimeMillis();


            String transmissionType =
                    isRetransmission
                            ? "RETRANSMISSION"
                            : "TRANSMISSION";


            if (!isRetransmission) {

                Log.i(
                        TAG,
                        "TCP Retransmission Count: 0"
                );

                dashboard.logToFile(
                        TAG
                                + "TCP Retransmission Count: 0"
                );
            }


            if (isRetransmission) {

                long retransmissionCount =
                        totalTcpRetransmissions
                                .incrementAndGet();

                long retransmissionByteCount =
                        totalTcpRetransmissionBytes
                                .addAndGet(
                                        retransmittedBytes
                                );


                String retransmissionLog =
                        "========== TCP RETRANSMISSION COUNT AND DATA ==========\n"
                                + "Direction          : TX / DEVICE -> SERVER\n"
                                + "Protocol           : TCP\n"
                                + "Connection Key     : "
                                + key
                                + "\n"
                                + "Host Name          : "
                                + (
                                session.serverName != null
                                        ? session.serverName
                                        : "Unknown"
                        )
                                + "\n"
                                + "Server IP          : "
                                + (
                                session.serverIp != null
                                        ? session.serverIp
                                        : ipStr(dstIp)
                        )
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
                                + "Sequence Number    : "
                                + seq
                                + "\n"
                                + "Sequence End       : "
                                + currentSeqEnd
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
                                + "TCP Header Length  : "
                                + dataOffsetBytes
                                + " bytes\n"
                                + "Payload Length     : "
                                + payloadLen
                                + " bytes\n"
                                + "Previous SEQ Start : "
                                + overlappingSegment.seqStart
                                + "\n"
                                + "Previous SEQ End   : "
                                + overlappingSegment.seqEnd
                                + "\n"
                                + "Retransmitted Bytes: "
                                + retransmittedBytes
                                + " bytes\n"
                                + "Retransmission Count : "
                                + retransmissionCount
                                + "\n"
                                + "Total Retrans Bytes: "
                                + retransmissionByteCount
                                + " bytes\n"
                                + "Timestamp          : "
                                + formatTimestamp(
                                packetTimestampWall
                        )
                                + "\n"
                                + "Timestamp Nano     : "
                                + packetTimestampNano
                                + " ns"
                                + "\n"
                                + "==============================================";


                Log.w(
                        TAG,
                        retransmissionLog
                );

                dashboard.logToFile(
                        TAG + retransmissionLog
                );
            }


            /*
             * ============================================================
             * RECORD TCP TRANSMISSION
             * ============================================================
             *
             * SAME LOGIC AS NORMAL TcpForwarder.
             */

            long transmissionCount =
                    totalTcpTransmissions
                            .incrementAndGet();

            long transmissionByteCount =
                    totalTcpTransmissionBytes
                            .addAndGet(
                                    payloadLen
                            );


            TcpSegmentRecord segmentRecord =
                    new TcpSegmentRecord(
                            currentSeqStart,
                            currentSeqEnd,
                            payloadLen,
                            packetTimestampNano
                    );


            session.transmittedSegments.put(
                    currentSeqStart,
                    segmentRecord
            );


            /*
             * =====================================================
             * APP OPEN TTFB REQUEST CORRELATION
             * =====================================================
             *
             * The VPN is already scoped to the selected app.
             *
             * Therefore:
             *
             *     TCP Destination IP
             *             ↓
             *     AppOpenUdpForwarder
             *             ↓
             *     matching DNS Answer IP
             *             ↓
             *     exact DNS T0
             *
             * NO latest-DNS fallback.
             */

            String destinationIp =
                    ipStr(dstIp);

            boolean isFirstOutgoingMatch =
                    firstOutgoingIpMatchLogged
                            .compareAndSet(
                                    false,
                                    true
                            );

            int matchCount =
                    outgoingIpMatchCount.incrementAndGet();


            if (isFirstOutgoingMatch) {

                globalOutgoingIpMatchTime =
                        System.nanoTime();

                globalOutgoingIpMatchWallTime =
                        System.currentTimeMillis();


                /*
                 * Find the FIRST DNS transaction whose
                 * Answer IP matches this TCP destination IP.
                 *
                 * Selection rule:
                 *
                 *     DNS transactions are checked from oldest to newest.
                 *
                 *     FIRST matching DNS transaction
                 *             ↓
                 *         DNS T0
                 *
                 *     All later matching DNS transactions
                 *     are ignored for this TTFB request.
                 */

                long matchedDnsT0 =
                        AppOpenUdpForwarder
                                .recordDnsLookupForResolvedIp(
                                        destinationIp
                                );


                /*
                 * If no matching DNS transaction exists,
                 * DNS T0 remains unavailable.
                 */

                globalDnsT0Nano =
                        matchedDnsT0 > 0L
                                ? matchedDnsT0
                                : 0L;


                globalTtfbRequestDestinationIp =
                        destinationIp;

                globalTtfbRequestResolvedIp =
                        destinationIp;

                globalTtfbRequestPayloadSize =
                        payloadLen;

                globalTtfbRequestConnectionKey =
                        key;


                /*
                 * =====================================================
                 * EXISTING APP OPEN TTFB CODE CONTINUES HERE
                 * =====================================================
                 */



                String correlationLog =
                        "========== DNS UI CORRELATION REQUEST ==========\n"
                                + "TCP Destination IP : "
                                + destinationIp
                                + "\n"
                                + "Matched DNS T0     : "
                                + matchedDnsT0
                                + " ns\n"
                                + "DNS UI Match       : "
                                + (
                                matchedDnsT0 > 0L
                                        ? "FOUND"
                                        : "NOT_FOUND"
                        )
                                + "\n"
                                + "Payload Length     : "
                                + payloadLen
                                + " bytes\n"
                                + "Connection Key     : "
                                + key
                                + "\n"
                                + "Timestamp          : "
                                + formatTimestamp(
                                globalOutgoingIpMatchWallTime
                        )
                                + "\n"
                                + "==============================================";


                Log.i(
                        TAG,
                        correlationLog
                );

                dashboard.logToFile(
                        TAG + correlationLog
                );

                dashboard.logEvent(
                        TAG + correlationLog,
                        VpnEvent.Level.INFO,
                        VpnEvent.Category.TCP
                );


                String requestLog =
                        "========== OG_TCP_REQUEST ==========\n"
                                + "Source IP       : "
                                + ipStr(srcIp)
                                + "\n"
                                + "Destination IP  : "
                                + destinationIp
                                + "\n"
                                + "Source Port     : "
                                + srcPort
                                + "\n"
                                + "Destination Port: "
                                + dstPort
                                + "\n"
                                + "Payload Length  : "
                                + payloadLen
                                + " bytes\n"
                                + "Connection Key  : "
                                + key
                                + "\n"
                                + "DNS T0          : "
                                + globalDnsT0Nano
                                + " ns\n"
                                + "Timestamp       : "
                                + formatTimestamp(
                                globalOutgoingIpMatchWallTime
                        )
                                + "\n"
                                + "====================================";


                Log.i(
                        TAG,
                        requestLog
                );

                dashboard.logToFile(
                        TAG + requestLog
                );

                dashboard.logEvent(
                        TAG + requestLog,
                        VpnEvent.Level.INFO,
                        VpnEvent.Category.TCP
                );

            } else {

                String packetLog =
                        "========== O_TCP_PACKET ==========\n"
                                + "Source IP       : "
                                + ipStr(srcIp)
                                + "\n"
                                + "Destination IP  : "
                                + destinationIp
                                + "\n"
                                + "Source Port     : "
                                + srcPort
                                + "\n"
                                + "Destination Port: "
                                + dstPort
                                + "\n"
                                + "Match Count     : "
                                + matchCount
                                + "\n"
                                + "Payload Length  : "
                                + payloadLen
                                + " bytes\n"
                                + "Connection Key  : "
                                + key
                                + "\n"
                                + "===================================";

                Log.i(
                        TAG,
                        packetLog
                );

                dashboard.logEvent(
                        TAG + packetLog,
                        VpnEvent.Level.INFO,
                        VpnEvent.Category.TCP
                );
            }


            /*
             * =====================================================
             * TLS RECORD TYPE - SENT / TX
             * =====================================================
             */

            if (data != null
                    && data.length >= 5) {

                int tlsRecordType =
                        data[0] & 0xFF;

                String tlsRecordName;

                switch (tlsRecordType) {

                    case 0x14:
                        tlsRecordName =
                                "Change Cipher Spec";
                        break;

                    case 0x15:
                        tlsRecordName =
                                "Alert";
                        break;

                    case 0x16:
                        tlsRecordName =
                                "Handshake";
                        break;

                    case 0x17:
                        tlsRecordName =
                                "Application Data";
                        break;

                    default:
                        tlsRecordName =
                                "Unknown / Non-standard TLS Record";
                        break;
                }


                /*
                 * =====================================================
                 * TLS HANDSHAKE T0
                 * =====================================================
                 *
                 * T0 = FIRST transmitted TLS record
                 *      with ContentType 0x16.
                 *
                 * IMPORTANT:
                 * Only the FIRST 0x16 is used as T0.
                 */

                if (tlsRecordType == 0x16
                        && tlsRecordType16Captured.compareAndSet(
                        false,
                        true
                )) {

                    globalTlsRecordType16T0Nano =
                            System.nanoTime();

                    globalTlsRecordType16T0WallTime =
                            System.currentTimeMillis();


                    String tlsT0Log =
                            "========== TLS HANDSHAKE T0 | TX 0x16 ==========\n"
                                    + "Direction          : TX / SENT\n"
                                    + "TLS Record Type    : 0x16\n"
                                    + "ContentType        : 0x16\n"
                                    + "Record Type        : Handshake\n"
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
                                    + "TCP Header Length  : "
                                    + dataOffsetBytes
                                    + " bytes\n"
                                    + "Payload Length     : "
                                    + payloadLen
                                    + " bytes\n"
                                    + "\n"
                                    + "TLS Version Major  : 0x"
                                    + String.format(
                                    java.util.Locale.US,
                                    "%02X",
                                    data[1] & 0xFF
                            )
                                    + "\n"
                                    + "TLS Version Minor  : 0x"
                                    + String.format(
                                    java.util.Locale.US,
                                    "%02X",
                                    data[2] & 0xFF
                            )
                                    + "\n"
                                    + "TLS Record Length  : "
                                    + (
                                    ((data[3] & 0xFF) << 8)
                                            | (data[4] & 0xFF)
                            )
                                    + " bytes\n"
                                    + "TLS Header Bytes   : "
                                    + String.format(
                                    java.util.Locale.US,
                                    "%02X %02X %02X %02X %02X",
                                    data[0] & 0xFF,
                                    data[1] & 0xFF,
                                    data[2] & 0xFF,
                                    data[3] & 0xFF,
                                    data[4] & 0xFF
                            )
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
                                    + "Connection Key     : "
                                    + key
                                    + "\n"
                                    + "=================================================";


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
                 * EXISTING TLS TX LOG
                 * =====================================================
                 */

                String tlsSentLog =
                        "========== TLS RECORD [TX/SENT] ==========\n"
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
                                + "TLS Record Type  : 0x"
                                + String.format(
                                "%02X",
                                tlsRecordType
                        )
                                + "\n"
                                + "Record Type      : "
                                + tlsRecordName
                                + "\n"
                                + "Sent Bytes       : "
                                + data.length
                                + " bytes\n"
                                + "Timestamp        : "
                                + formatTimestamp(
                                System.currentTimeMillis()
                        )
                                + "\n"
                                + "Connection Key   : "
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


            /*
             * =====================================================
             * WRITE REQUEST TO REAL SOCKET
             * =====================================================
             */

            try {

                session.realOut.write(
                        data
                );

                session.realOut.flush();

                int sentCount =
                        totalPacketsSent.incrementAndGet();


                logYoutubePacket(
                        true,
                        srcIp,
                        dstIp,
                        srcPort,
                        dstPort,
                        flags,
                        length,
                        payloadLen
                );


                Log.d(
                        TAG,
                        "Payload written successfully."
                );

                Log.d(
                        TAG,
                        "Payload Length = "
                                + payloadLen
                );

                Log.d(
                        TAG,
                        "Total Packets Sent So Far = "
                                + sentCount
                );

                dashboard.logEvent(
                        TAG
                                + "Total Packets Sent So Far = "
                                + sentCount,
                        VpnEvent.Level.INFO,
                        VpnEvent.Category.TCP
                );


            } catch (IOException e) {

                Log.w(
                        TAG,
                        "TCP write to real socket failed for "
                                + key,
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

                closeSession(
                        key,
                        session
                );

                return;
            }


            session.clientNextSeq =
                    seq + payloadLen;

            sendAck(
                    session,
                    false
            );
        }


        /*
         * =========================================================
         * FIN
         * =========================================================
         */

        if (isFin) {

            session.clientNextSeq =
                    seq + 1;

            sendAck(
                    session,
                    false
            );

            try {

                session.realSocket.shutdownOutput();

            } catch (IOException ignored) {
            }

            if (session.state !=
                    TcpSession.State.CLOSED) {

                session.state =
                        TcpSession.State.CLOSING;
            }
        }
    }


    /*
     * Compatibility method.
     *
     * App Open TTFB does not depend on hostname matching because
     * VpnService is already scoped to the selected application.
     */
    void setTargetHostname(String hostname) {

        Log.d(
                TAG,
                "Target hostname received by TcpForwarder = "
                        + hostname
        );
    }


    /*
     * =========================================================
     * START NEW TCP SESSION
     * =========================================================
     */

    private void startNewSession(
            String key,
            byte[] srcIp,
            int srcPort,
            byte[] dstIp,
            int dstPort,
            long clientIsn) {

        TcpSession session =
                new TcpSession();

        session.srcIp =
                srcIp;

        session.srcPort =
                srcPort;

        session.dstIp =
                dstIp;

        session.dstPort =
                dstPort;

        session.clientNextSeq =
                clientIsn + 1;

        session.deviceSeq =
                random.nextInt(
                        Integer.MAX_VALUE
                );

        session.state =
                TcpSession.State.SYN_RCVD;


        sessions.put(
                key,
                session
        );


        new Thread(
                () -> {

                    try {

                        Log.d(
                                TAG,
                                "Creating new TCP session..."
                        );

                        dashboard.logEvent(
                                TAG
                                        + "Creating new TCP session ..",
                                VpnEvent.Level.INFO,
                                VpnEvent.Category.TCP
                        );


                        Log.d(
                                TAG,
                                "Destination = "
                                        + intToInetName(
                                        dstIp
                                ).getHostAddress()
                                        + ":"
                                        + dstPort
                        );


                        dashboard.logEvent(
                                TAG
                                        + "Destination = "
                                        + intToInetName(
                                        dstIp
                                ).getHostAddress()
                                        + ":"
                                        + dstPort,
                                VpnEvent.Level.INFO,
                                VpnEvent.Category.TCP
                        );


                        /*
                         * Physical network must be available.
                         */

                        if (underlyingNetwork == null) {

                            Log.e(
                                    TAG,
                                    "No underlying Network available for "
                                            + key
                            );

                            dashboard.logEvent(
                                    TAG
                                            + "No underlying Network available for "
                                            + key,
                                    VpnEvent.Level.ERROR,
                                    VpnEvent.Category.TCP
                            );

                            sendRst(
                                    srcIp,
                                    srcPort,
                                    dstIp,
                                    dstPort,
                                    session.deviceSeq,
                                    session.clientNextSeq
                            );

                            sessions.remove(
                                    key
                            );

                            return;
                        }


                        Socket socket =
                                new Socket();


                        Log.d(
                                TAG,
                                "Created forwarding socket for "
                                        + key
                        );


                        /*
                         * Bind socket to the physical network.
                         */

                        try {

                            underlyingNetwork.bindSocket(
                                    socket
                            );

                            Log.d(
                                    TAG,
                                    "Underlying Network bindSocket SUCCESS for "
                                            + key
                            );

                            dashboard.logEvent(
                                    TAG
                                            + "Underlying Network bindSocket SUCCESS for "
                                            + key,
                                    VpnEvent.Level.SUCCESS,
                                    VpnEvent.Category.TCP
                            );

                        } catch (IOException e) {

                            Log.e(
                                    TAG,
                                    "Underlying Network bindSocket FAILED for "
                                            + key,
                                    e
                            );

                            dashboard.logEvent(
                                    TAG
                                            + "Underlying Network bindSocket FAILED for "
                                            + key
                                            + " : "
                                            + e.getMessage(),
                                    VpnEvent.Level.ERROR,
                                    VpnEvent.Category.TCP
                            );


                            try {

                                socket.close();

                            } catch (IOException ignored) {
                            }


                            sendRst(
                                    srcIp,
                                    srcPort,
                                    dstIp,
                                    dstPort,
                                    session.deviceSeq,
                                    session.clientNextSeq
                            );

                            sessions.remove(
                                    key
                            );

                            return;
                        }


                        Log.d(
                                TAG,
                                "Connecting socket to "
                                        + intToInetName(
                                        dstIp
                                ).getHostAddress()
                                        + ":"
                                        + dstPort
                        );


                        /*
                         * Connect directly to the IP.
                         *
                         * TCP does not perform DNS here.
                         */

                        socket.connect(
                                new InetSocketAddress(
                                        intToInetName(dstIp),
                                        dstPort
                                ),
                                8000
                        );


                        Log.d(
                                TAG,
                                "Socket connected successfully."
                        );


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


                        session.realSocket =
                                socket;


                        String serverIp =
                                socket
                                        .getInetAddress()
                                        .getHostAddress();


                        String serverName;


                        try {

                            serverName =
                                    socket
                                            .getInetAddress()
                                            .getCanonicalHostName();

                        } catch (Exception e) {

                            serverName =
                                    "Unknown";

                            Log.e(
                                    TAG,
                                    "Exception while resolving host name : "
                                            + intToInetName(
                                            dstIp
                                    ).getHostAddress()
                                            + ":"
                                            + dstPort,
                                    e
                            );

                            dashboard.logEvent(
                                    TAG
                                            + "Exception while resolving host name : "
                                            + intToInetName(
                                            dstIp
                                    ).getHostAddress()
                                            + ":"
                                            + dstPort
                                            + " exception is : "
                                            + e.getMessage(),
                                    VpnEvent.Level.INFO,
                                    VpnEvent.Category.TCP
                            );
                        }


                        session.serverIp =
                                serverIp;

                        session.serverName =
                                serverName;


                        Log.d(
                                TAG,
                                "Creating TCP session"
                        );


                        session.realOut =
                                socket.getOutputStream();

                        session.realIn =
                                socket.getInputStream();


                        /*
                         * Send SYN-ACK only after the real server
                         * connection is established.
                         */

                        sendSynAck(
                                session
                        );


                    } catch (IOException e) {

                        Log.e(
                                TAG,
                                "TCP connect failed for "
                                        + key
                                        + ": "
                                        + e.getMessage(),
                                e
                        );

                        dashboard.logEvent(
                                TAG
                                        + "TCP socket exception "
                                        + e.getMessage(),
                                VpnEvent.Level.ERROR,
                                VpnEvent.Category.TCP
                        );


                        sendRst(
                                srcIp,
                                srcPort,
                                dstIp,
                                dstPort,
                                session.deviceSeq,
                                session.clientNextSeq
                        );

                        sessions.remove(
                                key
                        );
                    }

                },
                "TcpConnect-" + key
        ).start();
    }


    private InetAddress intToInetName(
            byte[] ip
    ) throws IOException {

        return InetAddress.getByAddress(
                ip
        );
    }


    /*
     * =========================================================
     * SEND SYN ACK
     * =========================================================
     */

    private void sendSynAck(
            TcpSession s
    ) {

        boolean firstSend =
                s.synAckSent.compareAndSet(
                        false,
                        true
                );


        int flags =
                PacketUtils.TCP_SYN
                        | PacketUtils.TCP_ACK;


        /*
         * =========================================================
         * SEND SYN-ACK
         * =========================================================
         *
         * IMPORTANT:
         *
         * SYN-ACK = 0x12
         *
         * This packet is NOT used as TCP handshake T1.
         *
         * TCP handshake timing is measured later using:
         *
         * T0 = TX SYN 0x02
         * T1 = TX ACK 0x10
         *
         * Therefore there is NO tcpHandshake calculation here.
         */

        writeTcpPacket(
                s.dstIp,
                s.dstPort,
                s.srcIp,
                s.srcPort,
                s.deviceSeq,
                s.clientNextSeq,
                PacketUtils.TCP_SYN
                        | PacketUtils.TCP_ACK,
                null,
                0
        );


        if (firstSend) {

            s.deviceSeq += 1;
        }
    }


    /*
     * =========================================================
     * SEND ACK
     * =========================================================
     */

    private void sendAck(
            TcpSession s,
            boolean pshFlag
    ) {

        int flags =
                PacketUtils.TCP_ACK
                        | (
                        pshFlag
                                ? PacketUtils.TCP_PSH
                                : 0
                );


        writeTcpPacket(
                s.dstIp,
                s.dstPort,
                s.srcIp,
                s.srcPort,
                s.deviceSeq,
                s.clientNextSeq,
                flags,
                null,
                0
        );
    }


    /*
     * =========================================================
     * SEND DATA TO CLIENT
     * =========================================================
     */

    void sendDataToClient(
            TcpSession s,
            byte[] data,
            int len
    ) {

        writeTcpPacket(
                s.dstIp,
                s.dstPort,
                s.srcIp,
                s.srcPort,
                s.deviceSeq,
                s.clientNextSeq,
                PacketUtils.TCP_ACK
                        | PacketUtils.TCP_PSH,
                data,
                len
        );

        s.deviceSeq += len;
    }


    /*
     * =========================================================
     * SEND FIN TO CLIENT
     * =========================================================
     */

    void sendFinToClient(
            TcpSession s
    ) {

        writeTcpPacket(
                s.dstIp,
                s.dstPort,
                s.srcIp,
                s.srcPort,
                s.deviceSeq,
                s.clientNextSeq,
                PacketUtils.TCP_ACK
                        | PacketUtils.TCP_FIN,
                null,
                0
        );

        s.deviceSeq += 1;
    }


    /*
     * =========================================================
     * REPORT TTFB
     * =========================================================
     */

    void reportTtfb(
            TcpSession s,
            long ttfbMs,
            String key
    ) {

        Log.d(
                TAG,
                "Reporting TTFB = "
                        + ttfbMs
                        + " ms"
        );


        dashboard.logEvent(
                TAG
                        + "TTFB : "
                        + ttfbMs
                        + " ms  ("
                        + key
                        + ")",
                VpnEvent.Level.SUCCESS,
                VpnEvent.Category.TCP
        );


        dashboard.recordTtfb(
                ttfbMs
        );


        Log.d(
                TAG,
                "Dashboard updated with TTFB."
        );
    }


    /*
     * =========================================================
     * SEND RST
     * =========================================================
     */

    private void sendRst(
            byte[] fromIp,
            int fromPort,
            byte[] toIp,
            int toPort,
            long seq,
            long ack
    ) {

        writeTcpPacket(
                fromIp,
                fromPort,
                toIp,
                toPort,
                seq,
                ack,
                PacketUtils.TCP_RST,
                null,
                0
        );
    }


    /*
     * =========================================================
     * WRITE TCP PACKET TO TUN
     * =========================================================
     */

    private void writeTcpPacket(
            byte[] fromIp,
            int fromPort,
            byte[] toIp,
            int toPort,
            long seq,
            long ack,
            int flags,
            byte[] payload,
            int payloadLen
    ) {

        boolean ipv6 =
                fromIp.length == 16;

        int ipHeaderLen =
                ipv6
                        ? 40
                        : 20;

        int tcpHeaderLen =
                20;

        int tcpSegmentLen =
                tcpHeaderLen + payloadLen;

        int total =
                ipHeaderLen + tcpSegmentLen;


        ByteBuffer buf =
                ByteBuffer.allocate(
                        total
                );


        if (ipv6) {

            PacketUtils.writeIPv6Header(
                    buf,
                    tcpSegmentLen,
                    PacketUtils.PROTO_TCP,
                    fromIp,
                    toIp
            );

        } else {

            PacketUtils.writeIPv4Header(
                    buf,
                    total,
                    PacketUtils.PROTO_TCP,
                    fromIp,
                    toIp
            );
        }


        int tcpStart =
                buf.position();


        PacketUtils.writeTcpHeader(
                buf,
                fromPort,
                toPort,
                seq,
                ack,
                flags,
                65535
        );


        if (payload != null
                && payloadLen > 0) {

            buf.put(
                    payload,
                    0,
                    payloadLen
            );
        }


        PacketUtils.fixTcpChecksum(
                buf,
                0,
                tcpStart,
                tcpSegmentLen,
                fromIp,
                toIp
        );


        synchronized (tunWriteLock) {

            try {

                tunOut.write(
                        buf.array(),
                        0,
                        total
                );

            } catch (IOException e) {

                Log.w(
                        TAG,
                        "Failed writing TCP packet back to TUN",
                        e
                );
            }
        }
    }


    /*
     * =========================================================
     * CLOSE SESSION
     * =========================================================
     */

    private void closeSession(
            String key,
            TcpSession session
    ) {

        sessions.remove(
                key
        );

        session.state =
                TcpSession.State.CLOSED;


        try {

            if (session.realSocket != null) {

                session.realSocket.close();
            }

        } catch (IOException ignored) {
        }
    }


    /*
     * =========================================================
     * SHUTDOWN
     * =========================================================
     */

    void shutdown() {

        shutdown = true;


        for (
                Map.Entry<String, TcpSession> e
                : sessions.entrySet()
        ) {

            closeSession(
                    e.getKey(),
                    e.getValue()
            );
        }


        /*
         * Reset complete TTFB state.
         */

        globalTtfbCaptured.set(
                false
        );

        globalOutgoingIpMatchTime =
                0L;

        globalIncomingIpMatchTime =
                0L;

        globalOutgoingIpMatchWallTime =
                0L;

        globalIncomingIpMatchWallTime =
                0L;

        globalDnsT0Nano =
                0L;

        globalTlsRecordType17T1Nano =
                0L;

        globalTlsRecordType17T1WallTime =
                0L;

        tlsRecordType17Captured.set(
                false
        );

        globalTtfbMs =
                -1L;

        globalTtfbRequestDestinationIp =
                null;

        globalTtfbRequestResolvedIp =
                null;

        globalTtfbRequestPayloadSize =
                0;

        globalTtfbRequestConnectionKey =
                null;


        firstOutgoingIpMatchLogged.set(
                false
        );

        firstIncomingIpMatchLogged.set(
                false
        );

        outgoingIpMatchCount.set(
                0
        );

        incomingIpMatchCount.set(
                0
        );
    }


    /*
     * =========================================================
     * YOUTUBE TEST
     * =========================================================
     */

    void startYoutubeTest() {

        youtubeTestRunning =
                true;

        youtubePacketCounter.set(
                0
        );

        Log.d(
                TAG,
                "YouTube Test packet logging ENABLED"
        );
    }


    void stopYoutubeTest() {

        youtubeTestRunning =
                false;

        Log.d(
                TAG,
                "YouTube Test packet logging DISABLED"
        );
    }


    private void logYoutubePacket(
            boolean isTx,
            byte[] logSrcIp,
            byte[] logDstIp,
            int logSrcPort,
            int logDstPort,
            int flags,
            int packetLen,
            int payloadLen
    ) {

        if (!youtubeTestRunning) {
            return;
        }


        int count =
                youtubePacketCounter.incrementAndGet();


        String direction =
                isTx
                        ? "TX"
                        : "RX";


        String log =
                "========== YOUTUBE "
                        + direction
                        + " PACKET ==========\n"
                        + "Source IP       : "
                        + ipStr(logSrcIp)
                        + "\n"
                        + "Destination IP  : "
                        + ipStr(logDstIp)
                        + "\n"
                        + "Source Port     : "
                        + logSrcPort
                        + "\n"
                        + "Destination Port: "
                        + logDstPort
                        + "\n"
                        + (
                        flags >= 0
                                ? "TCP Flags       : 0x"
                                + Integer.toHexString(flags)
                                + "\n"
                                : ""
                )
                        + "Packet Length   : "
                        + packetLen
                        + "\n"
                        + "Payload Length  : "
                        + payloadLen
                        + "\n"
                        + "Packet Count    : "
                        + count
                        + "\n"
                        + "Timestamp       : "
                        + formatTimestamp(
                        System.currentTimeMillis()
                )
                        + "\n"
                        + "=======================================";


        dashboard.logToFile(
                TAG + log
        );

        dashboard.logEvent(
                TAG + log,
                VpnEvent.Level.INFO,
                VpnEvent.Category.TCP
        );
    }


    /*
     * =========================================================
     * RESET GLOBAL TTFB
     * =========================================================
     */

    void resetGlobalTtfb() {

        globalTtfbCaptured.set(
                false
        );

        globalOutgoingIpMatchTime =
                0L;

        globalIncomingIpMatchTime =
                0L;

        globalOutgoingIpMatchWallTime =
                0L;

        globalIncomingIpMatchWallTime =
                0L;

        globalDnsT0Nano =
                0L;

        globalTlsRecordType17T1Nano =
                0L;

        globalTlsRecordType17T1WallTime =
                0L;

        tlsRecordType17Captured.set(
                false
        );

        globalTtfbMs =
                -1L;

        globalTtfbRequestDestinationIp =
                null;

        globalTtfbRequestResolvedIp =
                null;

        globalTtfbRequestPayloadSize =
                0;

        globalTtfbRequestConnectionKey =
                null;


        /*
         * Reset TCP transmission/retransmission counters.
         */

        totalTcpTransmissions.set(
                0
        );

        totalTcpTransmissionBytes.set(
                0
        );

        totalTcpRetransmissions.set(
                0
        );

        totalTcpRetransmissionBytes.set(
                0
        );


        firstOutgoingIpMatchLogged.set(
                false
        );

        firstIncomingIpMatchLogged.set(
                false
        );

        outgoingIpMatchCount.set(
                0
        );

        incomingIpMatchCount.set(
                0
        );


        Log.d(
                TAG,
                "GLOBAL TTFB state RESET"
        );
    }


    /*
     * =========================================================
     * READ UNSIGNED INT
     * =========================================================
     */

    private static long readUnsignedInt(
            byte[] b,
            int off
    ) {

        return (
                ((long) (b[off] & 0xFF) << 24)
                        |
                        ((long) (b[off + 1] & 0xFF) << 16)
                        |
                        ((long) (b[off + 2] & 0xFF) << 8)
                        |
                        ((long) (b[off + 3] & 0xFF))
        );
    }


    /*
     * =========================================================
     * IP STRING
     * =========================================================
     */

    static String ipStr(
            byte[] ip
    ) {

        try {

            return InetAddress
                    .getByAddress(ip)
                    .getHostAddress();

        } catch (UnknownHostException e) {

            return "invalid-ip";
        }
    }


    /*
     * =========================================================
     * TCP SESSION
     * =========================================================
     */

    /*
     * ============================================================
     * TCP DATA SEGMENT RECORD
     * ============================================================
     *
     * SAME LOGIC AS NORMAL TcpForwarder.
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
         * TCP TRANSMITTED SEGMENTS
         * ============================================================
         *
         * SAME LOGIC AS NORMAL TcpForwarder.
         *
         * Stores previously transmitted sequence ranges for THIS
         * TCP session.
         */
        final Map<Long, TcpSegmentRecord>
                transmittedSegments =
                new ConcurrentHashMap<>();


        /*
         * Session-level fields retained for compatibility.
         */

        final java.util.concurrent.atomic.AtomicBoolean
                requestSentCaptured =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        final java.util.concurrent.atomic.AtomicBoolean
                firstByteCaptured =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        final java.util.concurrent.atomic.AtomicBoolean
                synAckSent =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        volatile long requestSentTime =
                0L;

        volatile long firstByteReceivedTime =
                0L;

        volatile long ttfbMs =
                -1L;


        /*
         * =====================================================
         * REAL SOCKET READER THREAD
         * =====================================================
         */

        void startRealSocketReaderThread(
                AppOpenTcpForwarder forwarder,
                String key
        ) {

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
                                         * =================================================
                                         * RX TCP HEADER
                                         * =================================================
                                         */

                                        if (n > 0) {

                                            String rxHeaderLog =
                                                    "========== [RX] TCP HEADER ==========\n"
                                                            + "Source IP          : "
                                                            + AppOpenTcpForwarder
                                                            .ipStr(dstIp)
                                                            + "\n"
                                                            + "Destination IP     : "
                                                            + AppOpenTcpForwarder
                                                            .ipStr(srcIp)
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
                                                    TAG
                                                            + rxHeaderLog,
                                                    VpnEvent.Level.INFO,
                                                    VpnEvent.Category.TCP
                                            );


                                            forwarder.logYoutubePacket(
                                                    false,
                                                    dstIp,
                                                    srcIp,
                                                    dstPort,
                                                    srcPort,
                                                    -1,
                                                    n,
                                                    n
                                            );


                                            /*
                                             * =================================================
                                             * TLS RECORD RX
                                             * =================================================
                                             */

                                            if (n >= 5) {

                                                int tlsRecordType =
                                                        buf[0] & 0xFF;


                                                String tlsRecordName;


                                                switch (
                                                        tlsRecordType
                                                ) {

                                                    case 0x14:

                                                        tlsRecordName =
                                                                "Change Cipher Spec";

                                                        break;


                                                    case 0x15:

                                                        tlsRecordName =
                                                                "Alert";

                                                        break;


                                                    case 0x16:

                                                        tlsRecordName =
                                                                "Handshake";

                                                        break;


                                                    case 0x17:

                                                        tlsRecordName =
                                                                "Application Data";

                                                        break;


                                                    default:

                                                        tlsRecordName =
                                                                "Unknown / Non-standard TLS Record";

                                                        break;
                                                }


                                                String tlsRecordLog =
                                                        "========== TLS RECORD [RX/RECEIVED] ==========\n"
                                                                + "Source IP        : "
                                                                + AppOpenTcpForwarder
                                                                .ipStr(dstIp)
                                                                + "\n"
                                                                + "Destination IP   : "
                                                                + AppOpenTcpForwarder
                                                                .ipStr(srcIp)
                                                                + "\n"
                                                                + "Source Port      : "
                                                                + dstPort
                                                                + "\n"
                                                                + "Destination Port : "
                                                                + srcPort
                                                                + "\n"
                                                                + "TLS Record Type  : 0x"
                                                                + String.format(
                                                                "%02X",
                                                                tlsRecordType
                                                        )
                                                                + "\n"
                                                                + "Record Type      : "
                                                                + tlsRecordName
                                                                + "\n"
                                                                + "Received Bytes   : "
                                                                + n
                                                                + " bytes\n"
                                                                + "Timestamp        : "
                                                                + forwarder
                                                                .formatTimestamp(
                                                                        System.currentTimeMillis()
                                                                )
                                                                + "\n"
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
                                            }


                                            /*
                                             * =================================================
                                             * T1 = FIRST TLS APPLICATION DATA 0x17
                                             * =================================================
                                             *
                                             * IMPORTANT:
                                             *
                                             * T1 = FIRST received TLS record
                                             *      with ContentType 0x17
                                             *
                                             * This T1 is used for:
                                             *
                                             * 1. TLS Handshake Time
                                             * 2. TTFB
                                             *
                                             * TLS Handshake:
                                             *
                                             * T0 = first TX TLS 0x16
                                             * T1 = first RX TLS 0x17
                                             *
                                             * TLS Handshake Time = T1 - T0
                                             *
                                             * TTFB remains separate:
                                             *
                                             * TTFB = TLS 0x17 T1 - matched DNS T0
                                             */

                                            if (
                                                    n >= 5
                                                            && !forwarder
                                                            .tlsRecordType17Captured
                                                            .get()
                                                            && isTlsApplicationDataRecord(
                                                            buf,
                                                            n
                                                    )
                                            ) {

                                                if (
                                                        forwarder
                                                                .tlsRecordType17Captured
                                                                .compareAndSet(
                                                                        false,
                                                                        true
                                                                )
                                                ) {

                                                    /*
                                                     * =================================================
                                                     * CAPTURE T1
                                                     * =================================================
                                                     */

                                                    forwarder
                                                            .globalTlsRecordType17T1Nano =
                                                            System.nanoTime();

                                                    forwarder
                                                            .globalTlsRecordType17T1WallTime =
                                                            System.currentTimeMillis();


                                                    /*
                                                     * =================================================
                                                     * COMPLETE T1 PACKET LOG
                                                     * =================================================
                                                     */

                                                    String tlsT1Log =
                                                            "========== T1_TLS_RECORD_0x17 ==========\n"
                                                                    + "Direction        : RX / RECEIVED\n"
                                                                    + "TLS Record Type  : 0x17\n"
                                                                    + "Record Type      : Application Data\n"
                                                                    + "Received Bytes   : "
                                                                    + n
                                                                    + " bytes\n"
                                                                    + "T1 Nano          : "
                                                                    + forwarder
                                                                    .globalTlsRecordType17T1Nano
                                                                    + " ns\n"
                                                                    + "Timestamp        : "
                                                                    + forwarder
                                                                    .formatTimestamp(
                                                                            forwarder
                                                                                    .globalTlsRecordType17T1WallTime
                                                                    )
                                                                    + "\n"
                                                                    + "Source IP        : "
                                                                    + AppOpenTcpForwarder
                                                                    .ipStr(dstIp)
                                                                    + "\n"
                                                                    + "Destination IP   : "
                                                                    + AppOpenTcpForwarder
                                                                    .ipStr(srcIp)
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
                                                     * T0 = FIRST TX TLS 0x16
                                                     * T1 = FIRST RX TLS 0x17
                                                     *
                                                     * TLS Handshake Time = T1 - T0
                                                     */

                                                    if (
                                                            forwarder
                                                                    .globalTlsRecordType16T0Nano
                                                                    > 0L
                                                    ) {

                                                        forwarder.globalTlsHandshakeNano =
                                                                forwarder
                                                                        .globalTlsRecordType17T1Nano
                                                                        -
                                                                        forwarder
                                                                                .globalTlsRecordType16T0Nano;


                                                        forwarder.globalTlsHandshakeMs =
                                                                forwarder
                                                                        .globalTlsHandshakeNano
                                                                        / 1_000_000.0;


                                                        /*
                                                         * Send TLS handshake metric to dashboard.
                                                         */

                                                        forwarder.dashboard.recordTlsHandshake(
                                                                forwarder.globalTlsHandshakeMs
                                                        );


                                                        /*
                                                         * =================================================
                                                         * TLS HANDSHAKE CALCULATION LOG
                                                         * =================================================
                                                         */

                                                        String tlsHandshakeLog =
                                                                "========== TLS HANDSHAKE TIME ==========\n"
                                                                        + "\n"
                                                                        + "T0 PACKET\n"
                                                                        + "------------------------------------------\n"
                                                                        + "Direction        : TX / SENT\n"
                                                                        + "TLS Record Type  : 0x16\n"
                                                                        + "Record Type      : Handshake\n"
                                                                        + "T0 Nano          : "
                                                                        + forwarder
                                                                        .globalTlsRecordType16T0Nano
                                                                        + " ns\n"
                                                                        + "T0 Timestamp     : "
                                                                        + forwarder
                                                                        .formatTimestamp(
                                                                                forwarder
                                                                                        .globalTlsRecordType16T0WallTime
                                                                        )
                                                                        + "\n"
                                                                        + "\n"
                                                                        + "T1 PACKET\n"
                                                                        + "------------------------------------------\n"
                                                                        + "Direction        : RX / RECEIVED\n"
                                                                        + "TLS Record Type  : 0x17\n"
                                                                        + "Record Type      : Application Data\n"
                                                                        + "T1 Nano          : "
                                                                        + forwarder
                                                                        .globalTlsRecordType17T1Nano
                                                                        + " ns\n"
                                                                        + "T1 Timestamp     : "
                                                                        + forwarder
                                                                        .formatTimestamp(
                                                                                forwarder
                                                                                        .globalTlsRecordType17T1WallTime
                                                                        )
                                                                        + "\n"
                                                                        + "\n"
                                                                        + "TLS HANDSHAKE CALCULATION\n"
                                                                        + "------------------------------------------\n"
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
                                                                        + forwarder
                                                                        .globalTlsHandshakeMs
                                                                        + " ms\n"
                                                                        + "==========================================";


                                                        Log.i(
                                                                TAG,
                                                                tlsHandshakeLog
                                                        );


                                                        /*
                                                         * IMPORTANT:
                                                         *
                                                         * This is written to the LOG FILE.
                                                         */

                                                        forwarder.dashboard.logToFile(
                                                                TAG
                                                                        + tlsHandshakeLog
                                                        );
                                                    }


                                                    /*
                                                     * =================================================
                                                     * EXISTING TTFB
                                                     * =================================================
                                                     *
                                                     * DO NOT CHANGE THIS LOGIC.
                                                     *
                                                     * TTFB =
                                                     *
                                                     * TLS 0x17 T1
                                                     * -
                                                     * exact matched DNS T0
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
                                                                        + "Request Payload: "
                                                                        + forwarder
                                                                        .globalTtfbRequestPayloadSize
                                                                        + " bytes\n"
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
                                                                        + forwarder
                                                                        .formatTimestamp(
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


//                                                        forwarder.dashboard.logEvent(
//                                                                TAG
//                                                                        + ttfbLog,
//                                                                VpnEvent.Level.SUCCESS,
//                                                                VpnEvent.Category.TCP
//                                                        );


                                                        forwarder.dashboard.logToFile(
                                                                TAG
                                                                        + ttfbLog
                                                        );


                                                        forwarder.reportTtfb(
                                                                this,
                                                                forwarder.globalTtfbMs,
                                                                key
                                                        );


                                                    } else {

                                                        /*
                                                         * TLS 0x17 arrived but no DNS transaction
                                                         * matched the TCP destination IP.
                                                         *
                                                         * Therefore TTFB is NOT calculated.
                                                         */

                                                        String noDnsLog =
                                                                "========== TTFB NOT CALCULATED ==========\n"
                                                                        + "Reason: No matched DNS T0\n"
                                                                        + "TLS Record Type : 0x17\n"
                                                                        + "TLS T1 Nano     : "
                                                                        + forwarder
                                                                        .globalTlsRecordType17T1Nano
                                                                        + " ns\n"
                                                                        + "==========================================";


                                                        Log.i(
                                                                TAG,
                                                                noDnsLog
                                                        );


                                                        forwarder.dashboard.logToFile(
                                                                TAG
                                                                        + noDnsLog
                                                        );
                                                    }
                                                }
                                            }                                        }


                                        /*
                                         * =================================================
                                         * SEND SERVER DATA BACK TO APP
                                         * =================================================
                                         */

                                        forwarder.sendDataToClient(
                                                this,
                                                buf,
                                                n
                                        );
                                    }


                                } catch (IOException ignored) {

                                    /*
                                     * Socket closed/reset.
                                     */

                                } finally {

                                    forwarder.sendFinToClient(
                                            this
                                    );
                                }


                            },
                            "TcpRead-" + key
                    );


            t.setDaemon(
                    true
            );

            t.start();


            Log.d(
                    TAG,
                    "TCP Reader Thread Started."
            );
        }
    }


    /*
     * =========================================================
     * TLS APPLICATION DATA DETECTOR
     * =========================================================
     *
     * TLS Record:
     *
     * Byte 0 = Content Type
     * Byte 1 = Version Major
     * Byte 2 = Version Minor
     * Byte 3 = Record Length MSB
     * Byte 4 = Record Length LSB
     *
     * 0x17 = Application Data
     */

    private static boolean isTlsApplicationDataRecord(
            byte[] data,
            int length
    ) {

        if (
                data == null
                        || length < 5
        ) {

            return false;
        }


        int contentType =
                data[0] & 0xFF;


        if (contentType != 0x17) {

            return false;
        }


        int versionMajor =
                data[1] & 0xFF;

        int versionMinor =
                data[2] & 0xFF;


        /*
         * TLS versions:
         *
         * 03 01 = TLS 1.0
         * 03 02 = TLS 1.1
         * 03 03 = TLS 1.2
         * 03 04 = TLS 1.3
         */

        if (versionMajor != 0x03) {

            return false;
        }


        /*
         * Validate declared TLS record length.
         */

        int recordLength =
                (
                        ((data[3] & 0xFF) << 8)
                                |
                                (data[4] & 0xFF)
                );


        return length >=
                5 + recordLength;
    }


    /*
     * =========================================================
     * TIMESTAMP
     * =========================================================
     */

    private String formatTimestamp(
            long timestamp
    ) {

        return new java.text.SimpleDateFormat(
                "HH:mm:ss:SSS",
                java.util.Locale.getDefault()
        ).format(
                new java.util.Date(
                        timestamp
                )
        );
    }
}