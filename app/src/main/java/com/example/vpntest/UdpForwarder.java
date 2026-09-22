package com.example.vpntest;

import android.net.VpnService;
import android.util.Log;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.repo.VpnEventRepository;


public class UdpForwarder {

    private static final String TAG = "VPN_UdpForwarder : ";

    private static volatile long latestDnsStartTimeNano = 0L;

    /*
     * Completed DNS transactions.
     *
     * Every DNS response is stored here after T0/T1/resolution
     * has been calculated.
     *
     * TCP will later use the actual destination/resolved IP
     * to find the DNS transaction whose Answer IP matches.
     */
    private static final ConcurrentLinkedDeque<DnsTransactionInfo>
            completedDnsTransactions =
            new ConcurrentLinkedDeque<>();

    /*
     * Keep only recent DNS transactions.
     * This prevents old DNS transactions from being matched
     * against a later TCP connection.
     */
    private static final long DNS_TRANSACTION_MAX_AGE_MS = 60_000;


    private static final long SESSION_IDLE_TIMEOUT_MS = 60_000;

    private final VpnService vpnService;
    private final FileOutputStream tunOut;
    private final Object tunWriteLock;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupExecutor =
            Executors.newSingleThreadScheduledExecutor();
    private volatile boolean shutdown = false;

    private final VpnEventRepository dashboard = VpnEventRepository.getInstance();
    UdpForwarder(VpnService vpnService, FileOutputStream tunOut, Object tunWriteLock) {
        this.vpnService = vpnService;
        this.tunOut = tunOut;
        this.tunWriteLock = tunWriteLock;
        cleanupExecutor.scheduleAtFixedRate(this::reapIdleSessions, 30, 30, TimeUnit.SECONDS);
    }

    /**
     * @param packet full packet bytes as read from the TUN
     * @param length total valid length of packet
     * @param parsed pre-parsed IPv4/IPv6 header info (addresses, ports, transport header offset)
     */
    void handlePacket(byte[] packet, int length, ParsedPacket parsed) {
        if (shutdown) return;

        int udpPayloadOffset = parsed.transportHeaderOffset + 8; // 8-byte UDP header
        int udpPayloadLen = length - udpPayloadOffset;
        if (udpPayloadLen < 0) return;

        byte[] srcIp = parsed.sourceIpBytes;
        byte[] dstIp = parsed.destinationIpBytes;
        int srcPort = parsed.sourcePort;
        int dstPort = parsed.destinationPort;

        String key = parsed.connectionKey();
        Session session = sessions.get(key);
        if (session == null) {
            session = createSession(key, srcIp, srcPort, dstIp, dstPort);
            if (session == null) return; // failed to open socket
            sessions.put(key, session);
        }

        byte[] payload = new byte[udpPayloadLen];
        System.arraycopy(packet, udpPayloadOffset, payload, 0, udpPayloadLen);

        try {
            DatagramPacket out = new DatagramPacket(
                    payload, payload.length, session.destAddress, dstPort);

            int dnsTransactionId = -1;
            long dnsStartTime = 0L;
            String dnsQueryName = null;
            String dnsQueryType = null;

            if (dstPort == 53 && payload.length >= 12) {

                dnsTransactionId =
                        ((payload[0] & 0xFF) << 8) |
                                (payload[1] & 0xFF);

                // DNS query name starts at byte 12
                dnsQueryName = parseDnsQueryName(payload);

                // Query type comes immediately after QNAME
                dnsQueryType = parseDnsQueryType(payload);

                /*
                 * DNS T0.
                 * Keep this immediately before sending the packet.
                 */

                dnsStartTime = System.nanoTime();

                latestDnsStartTimeNano = dnsStartTime;

// Store the actual clock time of DNS start.
                long dnsStartClockMillis = System.currentTimeMillis();

                session.dnsRequests.put(
                        dnsTransactionId,
                        new DnsRequestInfo(
                                dnsStartTime,
                                dnsStartClockMillis,
                                dnsQueryName,
                                dnsQueryType
                        )
                );
            }

            /*
             * =====================================================
             * QUIC HANDSHAKE T0
             * =====================================================
             *
             * Capture the FIRST outgoing QUIC Initial packet.
             *
             * T0 = timestamp immediately before UDP send.
             */
            if (!session.quicT0Captured
                    && isQuicInitialPacket(
                    payload,
                    payload.length)) {

                session.quicHandshakeT0Nano =
                        System.nanoTime();

                session.quicT0Captured = true;

                dashboard.logToFile(
                        TAG+
                        "QUIC HANDSHAKE T0 captured = "
                                + session.quicHandshakeT0Nano
                                + " ns"
                );
            }

            session.socket.send(out);
            session.touch();

            String udpTxLog =
                    "========== [TX] UDP ==========\n" +
                            "IP Version          : IPv" + parsed.ipVersion + "\n" +
                            "Source IP           : " + ipStr(srcIp) + "\n" +
                            "Destination IP      : " + ipStr(dstIp) + "\n" +
                            "Source Port         : " + srcPort + "\n" +
                            "Destination Port    : " + dstPort + "\n" +
                            "Packet Length       : " + payload.length + "\n";

            /*
             * Add DNS timing information to the log
             * when this is a DNS request.
             */
            if (dstPort == 53 && dnsTransactionId >= 0) {
                udpTxLog +=
                        "DNS Packet          : REQUEST\n" +
                                "DNS Transaction ID  : 0x" +
                                String.format("%04X", dnsTransactionId) + "\n" +
                                "Query Name          : " +
                                dnsQueryName + "\n" +
                                "Query Type          : " +
                                dnsQueryType + "\n" +
                                "DNS Start Time (ns) : " +
                                dnsStartTime + "\n";
            }

            udpTxLog +=
                    "==============================";

            dashboard.logEvent(
                    TAG + udpTxLog,
                    VpnEvent.Level.INFO,
                    VpnEvent.Category.UDP
            );

        } catch (IOException e) {
            Log.w(TAG, "UDP send failed for " + key + ": " + e.getMessage());
            closeSession(key, session);
        }
    }

    private Session createSession(String key, byte[] srcIp, int srcPort,
                                  byte[] dstIp, int dstPort) {
        try {
            DatagramSocket socket = new DatagramSocket();
            vpnService.protect(socket); // CRITICAL: keeps this socket's traffic out of the tunnel
            InetAddress destAddress = InetAddress.getByAddress(dstIp);

            Session session = new Session(socket, destAddress, srcIp, srcPort, dstIp, dstPort);
            startReplyListener(key, session);
            return session;
        } catch (IOException e) {
            Log.e(TAG, "Could not create UDP session for " + key, e);
            return null;
        }
    }

    private void startReplyListener(String key, Session session) {
        Thread t = new Thread(() -> {
            byte[] buf = new byte[32767];
            DatagramPacket reply = new DatagramPacket(buf, buf.length);
            while (!session.socket.isClosed()) {
                try {
                    session.socket.receive(reply);

                    /*
                     * =====================================================
                     * QUIC HANDSHAKE T1
                     * =====================================================
                     *
                     * Capture the FIRST incoming QUIC Initial packet.
                     *
                     * T1 = timestamp when the QUIC Initial response
                     *      arrives from the server.
                     */
                    if (!session.quicT1Captured
                            && isQuicInitialPacket(
                            buf,
                            reply.getLength())) {

                        session.quicHandshakeT1Nano =
                                System.nanoTime();

                        session.quicT1Captured = true;

                        if (session.quicHandshakeT0Nano > 0L) {

                            session.quicHandshakeNano =
                                    session.quicHandshakeT1Nano
                                            - session.quicHandshakeT0Nano;

                            session.quicHandshakeMs =
                                    session.quicHandshakeNano
                                            / 1_000_000.0;

                            dashboard.recordQuicHandshake(
                                    session.quicHandshakeMs
                            );

                            String quicHandshakeLog =
                                    "========== QUIC HANDSHAKE ==========\n"
                                            + "Direction          : TX -> RX\n"
                                            + "Protocol           : QUIC\n"
                                            + "Source IP          : "
                                            + ipStr(session.srcIp)
                                            + "\n"
                                            + "Destination IP     : "
                                            + ipStr(session.dstIp)
                                            + "\n"
                                            + "Source Port        : "
                                            + session.srcPort
                                            + "\n"
                                            + "Destination Port   : "
                                            + session.dstPort
                                            + "\n"
                                            + "QUIC T0            : "
                                            + session.quicHandshakeT0Nano
                                            + " ns\n"
                                            + "QUIC T1            : "
                                            + session.quicHandshakeT1Nano
                                            + " ns\n"
                                            + "QUIC Handshake     : "
                                            + String.format(
                                            Locale.US,
                                            "%.3f",
                                            session.quicHandshakeMs
                                    )
                                            + " ms\n"
                                            + "====================================";

                            Log.i(
                                    TAG,
                                    quicHandshakeLog
                            );

                            dashboard.logEvent(
                                    TAG + quicHandshakeLog,
                                    VpnEvent.Level.INFO,
                                    VpnEvent.Category.UDP
                            );

                        }
                    }

                    session.touch();

                    writeUdpReplyToTun(
                            session,
                            buf,
                            reply.getLength()
                    );

                } catch (IOException e) {
                    break; // socket closed or errored
                }
            }
        }, "UdpReply-" + key);
        t.setDaemon(true);
        t.start();
    }

    private void writeUdpReplyToTun(
            Session session,
            byte[] data,
            int dataLength) {

        /*
         * DNS RESPONSE
         *
         * The response comes from the DNS server.
         * Therefore the original destination port was 53.
         *
         * Match the response with the original request
         * using the DNS transaction ID.
         */
        if (session.dstPort == 53 && dataLength >= 2) {

            int dnsTransactionId =
                    ((data[0] & 0xFF) << 8) |
                            (data[1] & 0xFF);

            DnsRequestInfo dnsRequest =
                    session.dnsRequests.remove(dnsTransactionId);

            if (dnsRequest != null) {

                long dnsStartTime = dnsRequest.startTime;

                long dnsStartClockMillis = dnsRequest.startClockMillis;

                String dnsStartClockTime = new SimpleDateFormat(
                        "yyyy-MM-dd HH:mm:ss.SSS",
                        Locale.getDefault()
                ).format(new Date(dnsStartClockMillis));

                String queryName = dnsRequest.queryName;

                String queryType = dnsRequest.queryType;

                /*
                 * Record DNS response arrival time.
                 */
                long dnsEndTime = System.nanoTime();
                long dnsEndClockMillis = System.currentTimeMillis();

                String dnsEndClockTime = new SimpleDateFormat(
                        "yyyy-MM-dd HH:mm:ss.SSS",
                        Locale.getDefault()
                ).format(new Date(dnsEndClockMillis));


                /*
                 * DNS Lookup Time
                 *
                 * = DNS End Time - DNS Start Time
                 */
                long dnsLookupTimeNanos =
                        dnsEndTime - dnsStartTime;

                double dnsLookupTimeMs =
                        dnsLookupTimeNanos / 1_000_000.0;

                String answerIps = parseDnsAnswerIps(data);

                String dnsServerIp = ipStr(session.dstIp);

                /*
                 * IMPORTANT:
                 *
                 * Do NOT update the DNS UI here.
                 *
                 * Every DNS transaction is calculated and logged,
                 * but the UI must receive only the DNS transaction
                 * whose Answer IP matches the TCP resolved/destination IP.
                 */
                DnsTransactionInfo completedTransaction =
                        new DnsTransactionInfo(
                                dnsTransactionId,
                                dnsRequest.queryName,
                                dnsRequest.queryType,
                                answerIps,
                                dnsStartTime,
                                dnsEndTime,
                                dnsStartClockMillis,
                                dnsEndClockMillis,
                                dnsLookupTimeMs,
                                dnsServerIp
                        );

                /*
                 * Store every completed DNS transaction.
                 */
                completedDnsTransactions.addLast(completedTransaction);

                /*
                 * Remove old DNS transactions.
                 */
                cleanupOldDnsTransactions();

                String dnsTimingLog =
                        "========== DNS TRANSACTION ==========\n" +
                                "DNS Transaction ID  : 0x" +
                                String.format(Locale.US, "%04X", dnsTransactionId) + "\n" +
                                "Query Name          : " +
                                dnsRequest.queryName + "\n" +
                                "Query Type          : " +
                                dnsRequest.queryType + "\n" +
                                "Answer IP(s)        : " +
                                (answerIps.isEmpty() ? "NONE" : answerIps) + "\n" +
                                "DNS Start Time Clock: " +
                                dnsStartClockTime + "\n" +
                                "DNS Start Time (ns) : " +
                                dnsStartTime + "\n" +
                                "DNS End Time Clock  : " +
                                dnsEndClockTime + "\n" +
                                "DNS End Time (ns)   : " +
                                dnsEndTime + "\n" +
                                "DNS Resolution      : " +
                                String.format(Locale.US, "%.3f", dnsLookupTimeMs) +
                                " ms\n" +
                                "UI Match Status     : WAITING_FOR_IP_MATCH\n" +
                                "======================================";
                /*
                 * Write DNS timing to the same dashboard/file
                 * logging mechanism already being used.
                 */
                dashboard.logEvent(
                        TAG + dnsTimingLog,
                        VpnEvent.Level.INFO,
                        VpnEvent.Category.UDP
                );

                Log.d(TAG, dnsTimingLog);
            }
        }

        boolean ipv6 = session.dstIp.length == 16;
        int ipHeaderLen = ipv6 ? 40 : 20;
        int udpHeaderLen = 8;
        int udpSegmentLen = udpHeaderLen + dataLength;
        int totalLen = ipHeaderLen + udpSegmentLen;

        ByteBuffer packet = ByteBuffer.allocate(totalLen);

        // Response is from the ORIGINAL destination back to the ORIGINAL source.
        if (ipv6) {
            PacketUtils.writeIPv6Header(packet, udpSegmentLen, PacketUtils.PROTO_UDP,
                    session.dstIp, session.srcIp);
        } else {
            PacketUtils.writeIPv4Header(packet, totalLen, PacketUtils.PROTO_UDP,
                    session.dstIp, session.srcIp);
        }

        int udpHeaderStart = packet.position();
        PacketUtils.writeUdpHeader(packet, session.dstPort, session.srcPort, udpSegmentLen);
        packet.put(data, 0, dataLength);

        if (ipv6) {
            // UDP checksum is mandatory for IPv6.
            PacketUtils.fixUdpChecksum(packet, udpHeaderStart, udpSegmentLen, session.dstIp, session.srcIp);
        }
        // IPv4 UDP checksum remains optional and is left as 0, matching prior behavior.

        String udpRxLog =
                "========== [RX] UDP ==========\n" +
                        "IP Version          : IPv" + (ipv6 ? 6 : 4) + "\n" +
                        "Source IP          : " + ipStr(session.dstIp) + "\n" +
                        "Destination IP     : " + ipStr(session.srcIp) + "\n" +
                        "Source Port        : " + session.dstPort + "\n" +
                        "Destination Port   : " + session.srcPort + "\n" +
                        "Packet Length      : " + dataLength + "\n" +
                        "==============================";

        dashboard.logEvent(TAG+
                udpRxLog,
                VpnEvent.Level.INFO,
                VpnEvent.Category.UDP
        );

        synchronized (tunWriteLock) {
            try {
                tunOut.write(packet.array(), 0, totalLen);
            } catch (IOException e) {
                Log.w(TAG, "Failed writing UDP reply back to TUN", e);
            }
        }
    }

    private void reapIdleSessions() {
        long now = System.currentTimeMillis();
        for (Map.Entry<String, Session> e : sessions.entrySet()) {
            if (now - e.getValue().lastActivity > SESSION_IDLE_TIMEOUT_MS) {
                closeSession(e.getKey(), e.getValue());
            }
        }
    }

    private void closeSession(String key, Session session) {
        sessions.remove(key);
        session.socket.close();
    }

    void shutdown() {
        shutdown = true;
        cleanupExecutor.shutdownNow();
        for (Session s : sessions.values()) {
            s.socket.close();
        }
        sessions.clear();
    }

    /** Works for both 4-byte (IPv4) and 16-byte (IPv6) address arrays. */
    private static String ipStr(byte[] ip) {
        try {
            return InetAddress.getByAddress(ip).getHostAddress();
        } catch (IOException e) {
            return "invalid-ip";
        }
    }
    /*
     * =====================================================
     * QUIC INITIAL PACKET DETECTION
     * =====================================================
     *
     * QUIC Long Header:
     *
     * Bit 7 = Header Form
     * Bit 6 = Fixed Bit
     *
     * Long Header + Initial packet:
     * Packet Type bits = 00
     *
     * Therefore:
     *
     *   (firstByte & 0x80) != 0
     *       -> Long Header
     *
     *   (firstByte & 0x40) != 0
     *       -> Fixed Bit set
     *
     *   (firstByte & 0x30) == 0x00
     *       -> Initial packet
     */
    private static boolean isQuicInitialPacket(
            byte[] data,
            int length) {

        if (data == null || length < 1) {
            return false;
        }

        int firstByte = data[0] & 0xFF;

        boolean longHeader =
                (firstByte & 0x80) != 0;

        boolean fixedBit =
                (firstByte & 0x40) != 0;

        int packetType =
                firstByte & 0x30;

        boolean initialPacket =
                packetType == 0x00;

        return longHeader
                && fixedBit
                && initialPacket;
    }

    private static String parseDnsQueryName(byte[] data) {

        try {
            int pos = 12;
            StringBuilder name = new StringBuilder();

            while (pos < data.length) {

                int len = data[pos++] & 0xFF;

                // End of QNAME
                if (len == 0) {
                    break;
                }

                // DNS compression pointer should not occur
                // in a normal query QNAME.
                if ((len & 0xC0) != 0) {
                    return "unknown";
                }

                if (pos + len > data.length) {
                    return "unknown";
                }

                if (name.length() > 0) {
                    name.append(".");
                }

                name.append(
                        new String(
                                data,
                                pos,
                                len,
                                java.nio.charset.StandardCharsets.US_ASCII
                        )
                );

                pos += len;
            }

            return name.toString();

        } catch (Exception e) {
            return "unknown";
        }
    }
    private static String parseDnsQueryType(byte[] data) {

        try {
            int pos = 12;

            while (pos < data.length) {

                int len = data[pos++] & 0xFF;

                if (len == 0) {
                    break;
                }

                if ((len & 0xC0) != 0) {
                    return "UNKNOWN";
                }

                pos += len;
            }

            // Need 2 bytes for QTYPE
            if (pos + 2 > data.length) {
                return "UNKNOWN";
            }

            int qtype =
                    ((data[pos] & 0xFF) << 8) |
                            (data[pos + 1] & 0xFF);

            return dnsTypeToString(qtype);

        } catch (Exception e) {
            return "UNKNOWN";
        }
    }
    private static String dnsTypeToString(int type) {

        switch (type) {
            case 1:
                return "A";

            case 28:
                return "AAAA";

            case 5:
                return "CNAME";

            case 15:
                return "MX";

            case 16:
                return "TXT";

            case 2:
                return "NS";

            case 12:
                return "PTR";

            case 6:
                return "SOA";

            default:
                return "TYPE_" + type;
        }
    }
    /**
     * Called by TcpForwarder when the actual TCP destination IP
     * matches one of the website's resolved IPs.
     *
     * IMPORTANT:
     *
     * The DNS UI is updated ONLY when a DNS transaction's
     * Answer IP(s) contain this resolved/destination IP.
     *
     * All DNS transactions are calculated and logged separately.
     */
    static long recordDnsLookupForResolvedIp(String resolvedIp) {

        if (resolvedIp == null || resolvedIp.trim().isEmpty()) {

            Log.d(
                    TAG,
                    "DNS UI MATCH -> invalid resolved IP: " + resolvedIp
            );

            return 0L;
        }

        String normalizedResolvedIp =
                resolvedIp.trim();

        cleanupOldDnsTransactions();

        java.util.Iterator<DnsTransactionInfo> iterator =
                completedDnsTransactions.descendingIterator();

        while (iterator.hasNext()) {

            DnsTransactionInfo transaction =
                    iterator.next();

            if (transaction.answerIps == null
                    || transaction.answerIps.isEmpty()) {

                continue;
            }

            String[] answerIpArray =
                    transaction.answerIps.split(",");

            for (String answerIp : answerIpArray) {

                String normalizedAnswerIp =
                        answerIp.trim();

                /*
                 * =====================================================
                 * DNS ANSWER IP == TCP RESOLVED / DESTINATION IP
                 * =====================================================
                 */
                if (normalizedResolvedIp.equals(normalizedAnswerIp)) {

                    /*
                     * MATCH FOUND
                     *
                     * This is the EXACT DNS transaction whose
                     * Answer IP matches the TCP destination IP.
                     *
                     * Therefore use THIS transaction's T0.
                     */
                    long matchedDnsT0 =
                            transaction.startTime;

                    long matchedDnsT1 =
                            transaction.endTime;

                    Log.d(
                            TAG,
                            "DNS TRANSACTION MATCH FOUND"
                                    + " -> Resolved IP = "
                                    + normalizedResolvedIp
                                    + ", Answer IP = "
                                    + normalizedAnswerIp
                                    + ", Transaction ID = 0x"
                                    + String.format(
                                    Locale.US,
                                    "%04X",
                                    transaction.transactionId
                            )
                                    + ", DNS T0 = "
                                    + matchedDnsT0
                                    + " ns"
                    );

                    /*
                     * Existing DNS UI update.
                     */
                    VpnEventRepository
                            .getInstance()
                            .recordDnsLookup(
                                    transaction.dnsLookupTimeMs,
                                    transaction.dnsServerIp,
                                    normalizedResolvedIp
                            );

                    /*
                     * Existing file log.
                     */
                    VpnEventRepository
                            .getInstance()
                            .logToFile(
                                    TAG
                                            + "DNS ANSWER IP MATCHED RESOLVED IP\n"
                                            + "DNS Transaction ID : 0x"
                                            + String.format(
                                            Locale.US,
                                            "%04X",
                                            transaction.transactionId
                                    )
                                            + "\n"
                                            + "Query Name         : "
                                            + transaction.queryName
                                            + "\n"
                                            + "Query Type         : "
                                            + transaction.queryType
                                            + "\n"
                                            + "Answer IP(s)       : "
                                            + transaction.answerIps
                                            + "\n"
                                            + "Matched Answer IP  : "
                                            + normalizedAnswerIp
                                            + "\n"
                                            + "Resolved IP        : "
                                            + normalizedResolvedIp
                                            + "\n"
                                            + "DNS Server IP      : "
                                            + transaction.dnsServerIp
                                            + "\n"
                                            + "DNS T0             : "
                                            + matchedDnsT0
                                            + " ns\n"
                                            + "DNS T1             : "
                                            + matchedDnsT1
                                            + " ns\n"
                                            + "DNS Resolution     : "
                                            + String.format(
                                            Locale.US,
                                            "%.3f",
                                            transaction.dnsLookupTimeMs
                                    )
                                            + " ms\n"
                                            + "UI Update          : YES"
                            );

                    /*
                     * Prevent same DNS transaction from being reused.
                     */
                    completedDnsTransactions.remove(transaction);

                    /*
                     * IMPORTANT:
                     * Return the T0 of THIS matched DNS transaction.
                     */
                    return matchedDnsT0;
                }
            }
        }

        /*
         * No DNS transaction matched this TCP destination IP.
         */
        Log.d(
                TAG,
                "DNS UI MATCH NOT FOUND -> "
                        + "Resolved IP = "
                        + normalizedResolvedIp
        );

        VpnEventRepository
                .getInstance()
                .logToFile(
                        TAG
                                + "DNS ANSWER IP MATCH NOT FOUND\n"
                                + "Resolved IP        : "
                                + normalizedResolvedIp
                                + "\n"
                                + "UI Update          : NO"
                );

        /*
         * 0 means no matching DNS transaction.
         */
        return 0L;
    }
    /**
     * Remove DNS transactions older than the allowed matching window.
     */
    private static void cleanupOldDnsTransactions() {

        long now = System.currentTimeMillis();

        while (true) {

            DnsTransactionInfo oldest =
                    completedDnsTransactions.peekFirst();

            if (oldest == null) {
                break;
            }

            long age =
                    now - oldest.endClockMillis;

            if (age > DNS_TRANSACTION_MAX_AGE_MS) {

                completedDnsTransactions.pollFirst();

            } else {

                break;
            }
        }
    }
    private static String parseDnsAnswerIps(byte[] data) {

        try {
            if (data.length < 12) {
                return "";
            }

            int qdCount =
                    ((data[4] & 0xFF) << 8) |
                            (data[5] & 0xFF);

            int anCount =
                    ((data[6] & 0xFF) << 8) |
                            (data[7] & 0xFF);

            int pos = 12;

            // Skip Questions
            for (int i = 0; i < qdCount; i++) {

                pos = skipDnsName(data, pos);

                if (pos < 0 || pos + 4 > data.length) {
                    return "";
                }

                // QTYPE + QCLASS
                pos += 4;
            }

            StringBuilder ips = new StringBuilder();

            // Parse Answers
            for (int i = 0; i < anCount; i++) {

                pos = skipDnsName(data, pos);

                if (pos < 0 || pos + 10 > data.length) {
                    break;
                }

                int type =
                        ((data[pos] & 0xFF) << 8) |
                                (data[pos + 1] & 0xFF);

                int dataLength =
                        ((data[pos + 8] & 0xFF) << 8) |
                                (data[pos + 9] & 0xFF);

                pos += 10;

                if (pos + dataLength > data.length) {
                    break;
                }

                // A record = IPv4
                if (type == 1 && dataLength == 4) {

                    String ip =
                            (data[pos] & 0xFF) + "." +
                                    (data[pos + 1] & 0xFF) + "." +
                                    (data[pos + 2] & 0xFF) + "." +
                                    (data[pos + 3] & 0xFF);

                    if (ips.length() > 0) {
                        ips.append(", ");
                    }

                    ips.append(ip);
                }

                // AAAA record = IPv6
                else if (type == 28 && dataLength == 16) {

                    try {
                        byte[] ipv6 = new byte[16];
                        System.arraycopy(data, pos, ipv6, 0, 16);

                        String ip =
                                InetAddress
                                        .getByAddress(ipv6)
                                        .getHostAddress();

                        if (ips.length() > 0) {
                            ips.append(", ");
                        }

                        ips.append(ip);

                    } catch (Exception ignored) {
                    }
                }

                pos += dataLength;
            }

            return ips.toString();

        } catch (Exception e) {
            return "";
        }
    }
    private static int skipDnsName(byte[] data, int pos) {

        try {

            while (pos < data.length) {

                int len = data[pos] & 0xFF;

                // End of name
                if (len == 0) {
                    return pos + 1;
                }

                // Compression pointer
                if ((len & 0xC0) == 0xC0) {

                    if (pos + 1 >= data.length) {
                        return -1;
                    }

                    return pos + 2;
                }

                pos++;

                if (pos + len > data.length) {
                    return -1;
                }

                pos += len;
            }

            return -1;

        } catch (Exception e) {
            return -1;
        }
    }

    private static class DnsRequestInfo {
        final long startTime;
        final long startClockMillis;
        final String queryName;
        final String queryType;

        DnsRequestInfo(
                long startTime,
                long startClockMillis,
                String queryName,
                String queryType) {

            this.startTime = startTime;
            this.startClockMillis = startClockMillis;
            this.queryName = queryName;
            this.queryType = queryType;
        }
    }
    public static class DnsTransactionInfo {

        final int transactionId;
        final String queryName;
        final String queryType;
        final String answerIps;

        final long startTime;
        final long endTime;

        final long startClockMillis;
        final long endClockMillis;

        final double dnsLookupTimeMs;

        final String dnsServerIp;

        DnsTransactionInfo(
                int transactionId,
                String queryName,
                String queryType,
                String answerIps,
                long startTime,
                long endTime,
                long startClockMillis,
                long endClockMillis,
                double dnsLookupTimeMs,
                String dnsServerIp) {

            this.transactionId = transactionId;
            this.queryName = queryName;
            this.queryType = queryType;
            this.answerIps = answerIps;

            this.startTime = startTime;
            this.endTime = endTime;

            this.startClockMillis = startClockMillis;
            this.endClockMillis = endClockMillis;

            this.dnsLookupTimeMs = dnsLookupTimeMs;

            this.dnsServerIp = dnsServerIp;
        }
    }
    private static class Session {

        final DatagramSocket socket;
        final InetAddress destAddress;

        final byte[] srcIp;
        final int srcPort;

        final byte[] dstIp;
        final int dstPort;

        volatile long lastActivity;

        /*
         * DNS transaction tracking.
         *
         * Key   = DNS Transaction ID
         * Value = DNS request information
         */
        final Map<Integer, DnsRequestInfo> dnsRequests =
                new ConcurrentHashMap<>();

        /*
         * =====================================================
         * QUIC HANDSHAKE TIMING
         * =====================================================
         *
         * QUIC T0 = first outgoing QUIC Initial packet
         * QUIC T1 = first incoming QUIC Initial packet
         *
         * QUIC Handshake Time = T1 - T0
         *
         * Only the first packet in each direction is used.
         */
        volatile long quicHandshakeT0Nano = 0L;

        volatile long quicHandshakeT1Nano = 0L;

        volatile long quicHandshakeNano = -1L;

        volatile double quicHandshakeMs = -1.0;

        boolean quicT0Captured = false;

        boolean quicT1Captured = false;

        Session(
                DatagramSocket socket,
                InetAddress destAddress,
                byte[] srcIp,
                int srcPort,
                byte[] dstIp,
                int dstPort) {

            this.socket = socket;
            this.destAddress = destAddress;

            this.srcIp = srcIp;
            this.srcPort = srcPort;

            this.dstIp = dstIp;
            this.dstPort = dstPort;

            touch();
        }

        void touch() {
            lastActivity = System.currentTimeMillis();
        }
    }
}