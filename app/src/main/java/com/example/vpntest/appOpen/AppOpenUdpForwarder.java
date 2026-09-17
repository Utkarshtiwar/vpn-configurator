package com.example.vpntest.appOpen;

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

import com.example.vpntest.PacketUtils;
import com.example.vpntest.ParsedPacket;
import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.repo.VpnEventRepository;


class AppOpenUdpForwarder {

    private static final String TAG = "AppOpen_UdpForwarder : ";

    private static final long SESSION_IDLE_TIMEOUT_MS = 60_000;

    private static volatile long latestDnsStartTimeNano = 0L;

    private static final ConcurrentLinkedDeque<DnsTransactionInfo>
            completedDnsTransactions =
            new ConcurrentLinkedDeque<>();

    private static final long DNS_TRANSACTION_MAX_AGE_MS = 60_000;


    private final VpnService vpnService;
    private final FileOutputStream tunOut;
    private final Object tunWriteLock;

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    private final ScheduledExecutorService cleanupExecutor =
            Executors.newSingleThreadScheduledExecutor();

    private volatile boolean shutdown = false;

    private final VpnEventRepository dashboard =
            VpnEventRepository.getInstance();


    AppOpenUdpForwarder(
            VpnService vpnService,
            FileOutputStream tunOut,
            Object tunWriteLock) {

        this.vpnService = vpnService;
        this.tunOut = tunOut;
        this.tunWriteLock = tunWriteLock;

        cleanupExecutor.scheduleAtFixedRate(
                this::reapIdleSessions,
                30,
                30,
                TimeUnit.SECONDS
        );
    }


    /**
     * @param packet full packet bytes as read from the TUN
     * @param length total valid length of packet
     * @param parsed pre-parsed IPv4/IPv6 header info
     *               (addresses, ports, transport header offset)
     */
    void handlePacket(
            byte[] packet,
            int length,
            ParsedPacket parsed) {

        if (shutdown) {
            return;
        }

        int udpPayloadOffset =
                parsed.transportHeaderOffset + 8;

        int udpPayloadLen =
                length - udpPayloadOffset;

        if (udpPayloadLen < 0) {
            return;
        }

        byte[] srcIp = parsed.sourceIpBytes;
        byte[] dstIp = parsed.destinationIpBytes;

        int srcPort = parsed.sourcePort;
        int dstPort = parsed.destinationPort;

        String key = parsed.connectionKey();

        Session session = sessions.get(key);

        if (session == null) {

            session = createSession(
                    key,
                    srcIp,
                    srcPort,
                    dstIp,
                    dstPort
            );

            if (session == null) {
                return;
            }

            sessions.put(key, session);
        }

        byte[] payload = new byte[udpPayloadLen];

        System.arraycopy(
                packet,
                udpPayloadOffset,
                payload,
                0,
                udpPayloadLen
        );


        try {

            DatagramPacket out =
                    new DatagramPacket(
                            payload,
                            payload.length,
                            session.destAddress,
                            dstPort
                    );




            if (dstPort == 53 && payload.length >= 12) {

                int transactionId =
                        ((payload[0] & 0xFF) << 8)
                                | (payload[1] & 0xFF);

                String queryName =
                        parseDnsQueryName(payload);

                String queryType =
                        parseDnsQueryType(payload);


                long dnsStartTime =
                        System.nanoTime();

                long dnsStartClockMillis =
                        System.currentTimeMillis();


                session.dnsRequests.put(
                        transactionId,
                        new DnsRequestInfo(
                                dnsStartTime,
                                dnsStartClockMillis,
                                queryName,
                                queryType
                        )
                );

                latestDnsStartTimeNano =
                        dnsStartTime;


                /*
                 * Actual DNS packet transmission.
                 */
                session.socket.send(out);


                logDnsRequest(
                        transactionId,
                        queryName,
                        queryType,
                        dnsStartClockMillis,
                        ipStr(dstIp)
                );

            } else {

                /*
                 * Normal UDP forwarding.
                 */
                session.socket.send(out);
            }


            session.touch();


            String udpTxLog =
                    "========== [TX] UDP ==========\n" +
                            "IP Version          : IPv" +
                            parsed.ipVersion + "\n" +
                            "Source IP           : " +
                            ipStr(srcIp) + "\n" +
                            "Destination IP      : " +
                            ipStr(dstIp) + "\n" +
                            "Source Port         : " +
                            srcPort + "\n" +
                            "Destination Port    : " +
                            dstPort + "\n" +
                            "Packet Length       : " +
                            payload.length + "\n" +
                            "==============================";


            dashboard.logEvent(
                    TAG + udpTxLog,
                    VpnEvent.Level.INFO,
                    VpnEvent.Category.UDP
            );


        } catch (IOException e) {

            Log.w(
                    TAG,
                    "UDP send failed for "
                            + key
                            + ": "
                            + e.getMessage()
            );

            closeSession(key, session);
        }
    }


    private Session createSession(
            String key,
            byte[] srcIp,
            int srcPort,
            byte[] dstIp,
            int dstPort) {

        try {

            DatagramSocket socket =
                    new DatagramSocket();

            /*
             * CRITICAL:
             *
             * Keeps this socket's traffic outside
             * the VPN tunnel.
             */
            vpnService.protect(socket);

            InetAddress destAddress =
                    InetAddress.getByAddress(dstIp);


            Session session =
                    new Session(
                            socket,
                            destAddress,
                            srcIp,
                            srcPort,
                            dstIp,
                            dstPort
                    );


            startReplyListener(
                    key,
                    session
            );


            return session;

        } catch (IOException e) {

            Log.e(
                    TAG,
                    "Could not create UDP session for "
                            + key,
                    e
            );

            return null;
        }
    }


    private void startReplyListener(
            String key,
            Session session) {

        Thread t =
                new Thread(
                        () -> {

                            byte[] buf =
                                    new byte[32767];

                            DatagramPacket reply =
                                    new DatagramPacket(
                                            buf,
                                            buf.length
                                    );


                            while (
                                    !session.socket.isClosed()
                            ) {

                                try {

                                    session.socket.receive(
                                            reply
                                    );

                                    session.touch();


                                    /*
                                     * DNS RESPONSE PROCESSING
                                     *
                                     * This happens before the response
                                     * is written back into the VPN TUN.
                                     */
                                    writeUdpReplyToTun(
                                            session,
                                            buf,
                                            reply.getLength()
                                    );


                                } catch (IOException e) {

                                    break;
                                }
                            }

                        },
                        "UdpReply-" + key
                );


        t.setDaemon(true);
        t.start();
    }


    private void writeUdpReplyToTun(
            Session session,
            byte[] data,
            int dataLength) {


        /*
         * ============================================================
         * DNS RESPONSE
         * ============================================================
         *
         * Match DNS response Transaction ID against the request
         * that was stored when the DNS query was sent.
         */
        if (
                session.dstPort == 53
                        && dataLength >= 2
        ) {

            int transactionId =
                    ((data[0] & 0xFF) << 8)
                            | (data[1] & 0xFF);


            DnsRequestInfo request =
                    session.dnsRequests.remove(
                            transactionId
                    );


            if (request != null) {

                long dnsEndTime =
                        System.nanoTime();

                long dnsEndClockMillis =
                        System.currentTimeMillis();


                long dnsLookupTimeNanos =
                        dnsEndTime
                                - request.startTime;


                double dnsLookupTimeMs =
                        dnsLookupTimeNanos
                                / 1_000_000.0;


                String answerIps =
                        parseDnsAnswerIps(
                                data
                        );


                String dnsServerIp =
                        ipStr(session.dstIp);


                DnsTransactionInfo transaction =
                        new DnsTransactionInfo(
                                transactionId,
                                request.queryName,
                                request.queryType,
                                answerIps,
                                request.startTime,
                                dnsEndTime,
                                request.startClockMillis,
                                dnsEndClockMillis,
                                dnsLookupTimeMs,
                                dnsServerIp
                        );


                completedDnsTransactions.addLast(
                        transaction
                );


                cleanupOldDnsTransactions();


                /*
                 * ====================================================
                 * DNS RESULT LOG
                 * ====================================================
                 */
                String dnsLog =
                        "========== DNS TRANSACTION ==========\n" +

                                "DNS Transaction ID  : 0x" +
                                String.format(
                                        Locale.US,
                                        "%04X",
                                        transactionId
                                ) + "\n" +

                                "Query Name          : " +
                                request.queryName + "\n" +

                                "Query Type          : " +
                                request.queryType + "\n" +

                                "Answer IP(s)        : " +
                                (answerIps.isEmpty()
                                        ? "NONE"
                                        : answerIps) + "\n" +

                                "DNS Server IP       : " +
                                dnsServerIp + "\n" +

                                "DNS Start Time Clock: " +
                                formatTimestamp(
                                        request.startClockMillis
                                ) + "\n" +

                                "DNS Start Time (ns) : " +
                                request.startTime + "\n" +

                                "DNS End Time Clock  : " +
                                formatTimestamp(
                                        dnsEndClockMillis
                                ) + "\n" +

                                "DNS End Time (ns)   : " +
                                dnsEndTime + "\n" +

                                "DNS Resolution      : " +
                                String.format(
                                        Locale.US,
                                        "%.3f",
                                        dnsLookupTimeMs
                                ) + " ms\n" +

                                "UI Match Status     : WAITING_FOR_IP_MATCH\n" +

                                "======================================";


                dashboard.logEvent(
                        TAG + dnsLog,
                        VpnEvent.Level.INFO,
                        VpnEvent.Category.UDP
                );
            }
        }


        boolean ipv6 =
                session.dstIp.length == 16;

        int ipHeaderLen =
                ipv6 ? 40 : 20;

        int udpHeaderLen = 8;

        int udpSegmentLen =
                udpHeaderLen + dataLength;

        int totalLen =
                ipHeaderLen + udpSegmentLen;


        ByteBuffer packet =
                ByteBuffer.allocate(
                        totalLen
                );


        /*
         * Response is from the ORIGINAL destination
         * back to the ORIGINAL source.
         */
        if (ipv6) {

            PacketUtils.writeIPv6Header(
                    packet,
                    udpSegmentLen,
                    PacketUtils.PROTO_UDP,
                    session.dstIp,
                    session.srcIp
            );

        } else {

            PacketUtils.writeIPv4Header(
                    packet,
                    totalLen,
                    PacketUtils.PROTO_UDP,
                    session.dstIp,
                    session.srcIp
            );
        }


        int udpHeaderStart =
                packet.position();


        PacketUtils.writeUdpHeader(
                packet,
                session.dstPort,
                session.srcPort,
                udpSegmentLen
        );


        packet.put(
                data,
                0,
                dataLength
        );


        if (ipv6) {

            /*
             * UDP checksum is mandatory for IPv6.
             */
            PacketUtils.fixUdpChecksum(
                    packet,
                    udpHeaderStart,
                    udpSegmentLen,
                    session.dstIp,
                    session.srcIp
            );
        }

        /*
         * IPv4 UDP checksum remains optional and is left as 0,
         * matching previous behavior.
         */


        String udpRxLog =
                "========== [RX] UDP ==========\n" +
                        "IP Version          : IPv" +
                        (ipv6 ? 6 : 4) + "\n" +

                        "Source IP           : " +
                        ipStr(session.dstIp) + "\n" +

                        "Destination IP      : " +
                        ipStr(session.srcIp) + "\n" +

                        "Source Port         : " +
                        session.dstPort + "\n" +

                        "Destination Port    : " +
                        session.srcPort + "\n" +

                        "Packet Length       : " +
                        dataLength + "\n" +

                        "==============================";


        dashboard.logEvent(
                TAG + udpRxLog,
                VpnEvent.Level.INFO,
                VpnEvent.Category.UDP
        );


        synchronized (tunWriteLock) {

            try {

                tunOut.write(
                        packet.array(),
                        0,
                        totalLen
                );

            } catch (IOException e) {

                Log.w(
                        TAG,
                        "Failed writing UDP reply back to TUN",
                        e
                );
            }
        }
    }


    /**
     * ================================================================
     * DNS QUERY NAME
     * ================================================================
     *
     * DNS question section:
     *
     *     QNAME
     *     QTYPE
     *     QCLASS
     *
     * Example:
     *
     *     03 www 06 google 03 com 00
     *
     * becomes:
     *
     *     www.google.com
     */
    private static String parseDnsQueryName(
            byte[] dns) {

        try {

            if (
                    dns == null
                            || dns.length < 13
            ) {
                return "unknown";
            }


            int pos = 12;

            StringBuilder name =
                    new StringBuilder();


            while (
                    pos < dns.length
            ) {

                int len =
                        dns[pos++] & 0xFF;


                if (len == 0) {
                    break;
                }


                /*
                 * DNS compression pointer.
                 */
                if (
                        (len & 0xC0) == 0xC0
                ) {

                    break;
                }


                if (
                        pos + len > dns.length
                ) {
                    break;
                }


                if (
                        name.length() > 0
                ) {
                    name.append('.');
                }


                name.append(
                        new String(
                                dns,
                                pos,
                                len,
                                java.nio.charset.StandardCharsets.UTF_8
                        )
                );


                pos += len;
            }


            return name.length() > 0
                    ? name.toString()
                    : "unknown";


        } catch (Exception e) {

            return "unknown";
        }
    }


    /**
     * ================================================================
     * DNS QUERY TYPE
     * ================================================================
     */
    private static String parseDnsQueryType(
            byte[] dns) {

        try {

            if (
                    dns == null
                            || dns.length < 16
            ) {
                return "UNKNOWN";
            }


            int pos = 12;


            /*
             * Skip QNAME.
             */
            while (
                    pos < dns.length
            ) {

                int len =
                        dns[pos++] & 0xFF;


                if (len == 0) {
                    break;
                }


                if (
                        (len & 0xC0) == 0xC0
                ) {

                    pos++;
                    break;
                }


                pos += len;
            }


            if (
                    pos + 2 > dns.length
            ) {
                return "UNKNOWN";
            }


            int type =
                    ((dns[pos] & 0xFF) << 8)
                            | (dns[pos + 1] & 0xFF);


            switch (type) {

                case 1:
                    return "A";

                case 2:
                    return "NS";

                case 5:
                    return "CNAME";

                case 6:
                    return "SOA";

                case 12:
                    return "PTR";

                case 15:
                    return "MX";

                case 16:
                    return "TXT";

                case 28:
                    return "AAAA";

                case 33:
                    return "SRV";

                case 255:
                    return "ANY";

                default:
                    return "TYPE_" + type;
            }


        } catch (Exception e) {

            return "UNKNOWN";
        }
    }


    /**
     * ================================================================
     * DNS ANSWER IP PARSER
     * ================================================================
     *
     * Extracts IPv4 A-record addresses from DNS response.
     *
     * Example:
     *
     *     google.com -> 142.250.195.14
     *
     * These IPs are later used by TCP forwarder to correlate:
     *
     *     DNS -> TCP destination IP
     */
    private static String parseDnsAnswerIps(
            byte[] dns) {

        try {

            if (
                    dns == null
                            || dns.length < 12
            ) {
                return "";
            }


            int qdCount =
                    ((dns[4] & 0xFF) << 8)
                            | (dns[5] & 0xFF);


            int anCount =
                    ((dns[6] & 0xFF) << 8)
                            | (dns[7] & 0xFF);


            int pos = 12;


            /*
             * Skip Question Section.
             */
            for (
                    int i = 0;
                    i < qdCount;
                    i++
            ) {

                pos =
                        skipDnsName(
                                dns,
                                pos
                        );


                if (
                        pos < 0
                                || pos + 4 > dns.length
                ) {
                    return "";
                }


                /*
                 * QTYPE + QCLASS
                 */
                pos += 4;
            }


            StringBuilder ips =
                    new StringBuilder();


            /*
             * Parse Answer Section.
             */
            for (
                    int i = 0;
                    i < anCount;
                    i++
            ) {

                pos =
                        skipDnsName(
                                dns,
                                pos
                        );


                if (
                        pos < 0
                                || pos + 10 > dns.length
                ) {
                    break;
                }


                int type =
                        ((dns[pos] & 0xFF) << 8)
                                | (dns[pos + 1] & 0xFF);


                int clazz =
                        ((dns[pos + 2] & 0xFF) << 8)
                                | (dns[pos + 3] & 0xFF);


                int dataLength =
                        ((dns[pos + 8] & 0xFF) << 8)
                                | (dns[pos + 9] & 0xFF);


                pos += 10;


                if (
                        pos + dataLength
                                > dns.length
                ) {
                    break;
                }


                /*
                 * A record = IPv4.
                 */
                if (
                        type == 1
                                && clazz == 1
                                && dataLength == 4
                ) {

                    try {

                        byte[] ip =
                                new byte[4];

                        System.arraycopy(
                                dns,
                                pos,
                                ip,
                                0,
                                4
                        );


                        String ipString =
                                InetAddress
                                        .getByAddress(ip)
                                        .getHostAddress();


                        if (
                                ips.length() > 0
                        ) {
                            ips.append(", ");
                        }


                        ips.append(
                                ipString
                        );

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


    /**
     * Skip one DNS name.
     *
     * Supports:
     *
     *     normal labels
     *
     * and
     *
     *     compression pointers
     */
    private static int skipDnsName(
            byte[] dns,
            int pos) {

        if (
                dns == null
                        || pos < 0
                        || pos >= dns.length
        ) {
            return -1;
        }


        while (
                pos < dns.length
        ) {

            int len =
                    dns[pos] & 0xFF;


            /*
             * End of DNS name.
             */
            if (len == 0) {

                return pos + 1;
            }


            /*
             * Compression pointer.
             *
             * Pointer consumes 2 bytes.
             */
            if (
                    (len & 0xC0) == 0xC0
            ) {

                if (
                        pos + 2 > dns.length
                ) {
                    return -1;
                }

                return pos + 2;
            }


            pos++;


            if (
                    pos + len > dns.length
            ) {
                return -1;
            }


            pos += len;
        }


        return -1;
    }


    /**
     * ================================================================
     * CLEAN OLD DNS TRANSACTIONS
     * ================================================================
     */
    private static void cleanupOldDnsTransactions() {

        long now =
                System.currentTimeMillis();


        while (true) {

            DnsTransactionInfo first =
                    completedDnsTransactions.peekFirst();


            if (first == null) {
                break;
            }


            if (
                    now - first.endClockMillis
                            <= DNS_TRANSACTION_MAX_AGE_MS
            ) {
                break;
            }


            completedDnsTransactions.pollFirst();
        }
    }


    /**
     * ================================================================
     * DNS -> TCP DESTINATION IP CORRELATION
     * ================================================================
     *
     * Called by AppOpenTcpForwarder.
     *
     * Example:
     *
     * DNS:
     *
     *     Query = youtube.com
     *     Answer = 142.250.1.1
     *     T0 = 1000000000 ns
     *
     * TCP:
     *
     *     destination IP = 142.250.1.1
     *
     * Result:
     *
     *     returns DNS T0 = 1000000000 ns
     *
     * That T0 is then used for:
     *
     *     TTFB = TLS 0x17 T1 - DNS T0
     */
    static long recordDnsLookupForResolvedIp(
            String resolvedIp) {

        if (
                resolvedIp == null
                        || resolvedIp.trim().isEmpty()
        ) {
            return 0L;
        }

        /*
         * IMPORTANT:
         * Keep normalizedResolvedIp INSIDE this method,
         * before iterating DNS transactions.
         */
        String normalizedResolvedIp =
                resolvedIp.trim();

        cleanupOldDnsTransactions();

        /*
         * Search newest DNS transactions first.
         */
        for (
                DnsTransactionInfo transaction
                : completedDnsTransactions
        ) {

            if (
                    transaction.answerIps == null
                            || transaction.answerIps.isEmpty()
            ) {
                continue;
            }

            /*
             * Split all DNS Answer IPs.
             */
            String[] answerIpArray =
                    transaction.answerIps.split(",");

            for (String answerIp : answerIpArray) {

                /*
                 * IMPORTANT:
                 * normalizedAnswerIp must be declared INSIDE
                 * this loop because it belongs to this answer IP.
                 */
                String normalizedAnswerIp =
                        answerIp.trim();

                /*
                 * =====================================================
                 * DNS ANSWER IP == TCP RESOLVED / DESTINATION IP
                 * =====================================================
                 */
                if (
                        normalizedResolvedIp.equals(
                                normalizedAnswerIp
                        )
                ) {

                    /*
                     * =================================================
                     * MATCH FOUND
                     * =================================================
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
                     * =================================================
                     * DNS UI UPDATE
                     * =================================================
                     */
                    VpnEventRepository
                            .getInstance()
                            .recordDnsLookup(
                                    transaction.dnsLookupTimeMs,
                                    transaction.dnsServerIp,
                                    normalizedResolvedIp
                            );

                    /*
                     * =================================================
                     * EXISTING EVENT LOG
                     * =================================================
                     */
                    String matchLog =
                            "========== [DNS -> TCP MATCH] ==========\n"
                                    + "Resolved IP        : "
                                    + normalizedResolvedIp
                                    + "\n"
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
                                    + "DNS Server         : "
                                    + transaction.dnsServerIp
                                    + "\n"
                                    + "Answer IPs         : "
                                    + transaction.answerIps
                                    + "\n"
                                    + "DNS T0             : "
                                    + matchedDnsT0
                                    + " ns\n"
                                    + "DNS Lookup Time    : "
                                    + String.format(
                                    Locale.US,
                                    "%.3f",
                                    transaction.dnsLookupTimeMs
                            )
                                    + " ms\n"
                                    + "========================================";

                    VpnEventRepository
                            .getInstance()
                            .logEvent(
                                    TAG + matchLog,
                                    VpnEvent.Level.INFO,
                                    VpnEvent.Category.UDP
                            );

                    /*
                     * =================================================
                     * DETAILED FILE LOG
                     * Same DNS ANSWER IP MATCHED RESOLVED IP
                     * format as Web UdpForwarder
                     * =================================================
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
                     * Remove the transaction so that the same DNS
                     * transaction is not reused for another TCP connection.
                     */
                    completedDnsTransactions.remove(
                            transaction
                    );

                    /*
                     * Return DNS T0 for TTFB calculation.
                     */
                    return transaction.startTime;
                }
            }
        }

        return 0L;
    }


    /**
     * Avoid false matches such as:
     *
     * 1.1.1.1
     *
     * matching:
     *
     * 11.1.1.10
     */
    private static boolean containsIp(
            String answerIps,
            String resolvedIp) {

        String[] values =
                answerIps.split(",");


        for (String value : values) {

            if (
                    resolvedIp.equals(
                            value.trim()
                    )
            ) {
                return true;
            }
        }


        return false;
    }


    /**
     * ================================================================
     * DNS REQUEST LOG
     * ================================================================
     */
    private void logDnsRequest(
            int transactionId,
            String queryName,
            String queryType,
            long startClockMillis,
            String dnsServerIp) {


        String dnsRequestLog =
                "========== [DNS REQUEST] ==========\n" +

                        "Transaction ID      : 0x" +
                        String.format(
                                Locale.US,
                                "%04X",
                                transactionId
                        ) + "\n" +

                        "Query Name          : " +
                        queryName + "\n" +

                        "Query Type          : " +
                        queryType + "\n" +

                        "DNS Server          : " +
                        dnsServerIp + "\n" +

                        "DNS Start           : " +
                        formatTimestamp(
                                startClockMillis
                        ) + "\n" +

                        "===================================";


        dashboard.logEvent(
                TAG + dnsRequestLog,
                VpnEvent.Level.INFO,
                VpnEvent.Category.UDP
        );
    }


    /**
     * Human-readable wall-clock timestamp.
     */
    private static String formatTimestamp(
            long millis) {

        try {

            SimpleDateFormat sdf =
                    new SimpleDateFormat(
                            "HH:mm:ss.SSS",
                            Locale.US
                    );


            return sdf.format(
                    new Date(millis)
            );

        } catch (Exception e) {

            return String.valueOf(
                    millis
            );
        }
    }


    private void reapIdleSessions() {

        long now =
                System.currentTimeMillis();


        for (
                Map.Entry<String, Session> e
                : sessions.entrySet()
        ) {

            if (
                    now - e.getValue().lastActivity
                            > SESSION_IDLE_TIMEOUT_MS
            ) {

                closeSession(
                        e.getKey(),
                        e.getValue()
                );
            }
        }


        cleanupOldDnsTransactions();
    }


    private void closeSession(
            String key,
            Session session) {

        sessions.remove(
                key
        );

        session.socket.close();
    }


    void shutdown() {

        shutdown = true;

        cleanupExecutor.shutdownNow();


        for (
                Session s
                : sessions.values()
        ) {

            s.socket.close();
        }


        sessions.clear();


        completedDnsTransactions.clear();
    }


    /** Works for both 4-byte IPv4 and 16-byte IPv6 address arrays. */
    private static String ipStr(
            byte[] ip) {

        try {

            return InetAddress
                    .getByAddress(ip)
                    .getHostAddress();

        } catch (IOException e) {

            return "invalid-ip";
        }
    }


    /**
     * ================================================================
     * DNS REQUEST INFORMATION
     * ================================================================
     */
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

            this.startTime =
                    startTime;

            this.startClockMillis =
                    startClockMillis;

            this.queryName =
                    queryName;

            this.queryType =
                    queryType;
        }
    }


    /**
     * ================================================================
     * COMPLETED DNS TRANSACTION
     * ================================================================
     */
    private static class DnsTransactionInfo {

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

            this.transactionId =
                    transactionId;

            this.queryName =
                    queryName;

            this.queryType =
                    queryType;

            this.answerIps =
                    answerIps;

            this.startTime =
                    startTime;

            this.endTime =
                    endTime;

            this.startClockMillis =
                    startClockMillis;

            this.endClockMillis =
                    endClockMillis;

            this.dnsLookupTimeMs =
                    dnsLookupTimeMs;

            this.dnsServerIp =
                    dnsServerIp;
        }
    }


    /**
     * ================================================================
     * UDP SESSION
     * ================================================================
     */
    private static class Session {

        final DatagramSocket socket;

        final InetAddress destAddress;

        final byte[] srcIp;
        final int srcPort;

        final byte[] dstIp;
        final int dstPort;

        volatile long lastActivity;


        /*
         * DNS requests currently waiting for a response.
         *
         * Key:
         *
         *     DNS Transaction ID
         */
        final Map<Integer, DnsRequestInfo> dnsRequests =
                new ConcurrentHashMap<>();


        Session(
                DatagramSocket socket,
                InetAddress destAddress,
                byte[] srcIp,
                int srcPort,
                byte[] dstIp,
                int dstPort) {

            this.socket =
                    socket;

            this.destAddress =
                    destAddress;

            this.srcIp =
                    srcIp;

            this.srcPort =
                    srcPort;

            this.dstIp =
                    dstIp;

            this.dstPort =
                    dstPort;

            touch();
        }


        void touch() {

            lastActivity =
                    System.currentTimeMillis();
        }
    }
}