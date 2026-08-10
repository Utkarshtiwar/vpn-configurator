package com.example.vpntest;

import android.net.VpnService;
import android.util.Log;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.repo.VpnEventRepository;


class TcpForwarder {
    private static final String TAG = "TcpForwarder";

    private final VpnService vpnService;
    private final FileOutputStream tunOut;
    private final Object tunWriteLock;
    private final Random random = new Random();

    private final Map<String, TcpSession> sessions = new ConcurrentHashMap<>();
    private volatile boolean shutdown = false;
    private final VpnEventRepository dashboard = VpnEventRepository.getInstance();

    private final java.util.concurrent.atomic.AtomicBoolean globalTtfbCaptured =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    TcpForwarder(VpnService vpnService, FileOutputStream tunOut, Object tunWriteLock) {
        this.vpnService = vpnService;
        this.tunOut = tunOut;
        this.tunWriteLock = tunWriteLock;
    }

    void handlePacket(byte[] packet, int length, int ipHeaderLen,
                      byte[] srcIp, byte[] dstIp, int srcPort, int dstPort) {
        if (shutdown) return;

        Log.d(TAG, "========== TCP HANDLE PACKET ==========");
        Log.d(TAG, "Src: " + ipStr(srcIp) + ":" + srcPort);
        Log.d(TAG, "Dst: " + ipStr(dstIp) + ":" + dstPort);
        Log.d(TAG, "Length: " + length);
        Log.d(TAG, "=======================================");

        int tcpHeaderOffset = ipHeaderLen;
        if (length < tcpHeaderOffset + 20) return;

        // -------------------- IPv4 Header --------------------

        int version = (packet[0] >> 4) & 0xF;

        int ipHeaderLength = (packet[0] & 0x0F) * 4;

        int dscp = (packet[1] >> 2) & 0x3F;

        int ecn = packet[1] & 0x03;

        int totalLength =
                ((packet[2] & 0xFF) << 8)
                        | (packet[3] & 0xFF);

        int identification =
                ((packet[4] & 0xFF) << 8)
                        | (packet[5] & 0xFF);

        int flagsAndOffset =
                ((packet[6] & 0xFF) << 8)
                        | (packet[7] & 0xFF);

        int ipFlags = (flagsAndOffset >> 13) & 0x07;

        int fragmentOffset = flagsAndOffset & 0x1FFF;

        int ttl = packet[8] & 0xFF;


// -------------------- TCP Header --------------------

        long seq = readUnsignedInt(packet, tcpHeaderOffset + 4);

        long ack = readUnsignedInt(packet, tcpHeaderOffset + 8);

        int dataOffsetBytes =
                ((packet[tcpHeaderOffset + 12] >> 4) & 0x0F) * 4;

        int flags = packet[tcpHeaderOffset + 13] & 0xFF;

        int windowSize =
                ((packet[tcpHeaderOffset + 14] & 0xFF) << 8)
                        | (packet[tcpHeaderOffset + 15] & 0xFF);

        int checksum =
                ((packet[tcpHeaderOffset + 16] & 0xFF) << 8)
                        | (packet[tcpHeaderOffset + 17] & 0xFF);

        int urgentPointer =
                ((packet[tcpHeaderOffset + 18] & 0xFF) << 8)
                        | (packet[tcpHeaderOffset + 19] & 0xFF);

        int payloadOffset = tcpHeaderOffset + dataOffsetBytes;

        int payloadLen = length - payloadOffset;

        if (payloadLen < 0)
            payloadLen = 0;

        String tcpHeaderLog =
                "========== [TX] TCP/IP HEADER ==========\n" +
                        "Source IP          : " + ipStr(srcIp) + "\n" +
                        "Destination IP     : " + ipStr(dstIp) + "\n" +
                        "Source Port        : " + srcPort + "\n" +
                        "Destination Port   : " + dstPort + "\n" +
                        "Version            : IPv" + version + "\n" +
                        "TTL                : " + ttl + "\n" +
                        "DSCP               : " + dscp + "\n" +
                        "ECN                : " + ecn + "\n" +
                        "IP Header Length   : " + ipHeaderLength + "\n" +
                        "TCP Header Length  : " + dataOffsetBytes + "\n" +
                        "Packet Length      : " + totalLength + "\n" +
                        "Identification     : " + identification + "\n" +
                        "IP Flags           : " + ipFlags + "\n" +
                        "Fragment Offset    : " + fragmentOffset + "\n" +
                        "Sequence Number    : " + seq + "\n" +
                        "ACK Number         : " + ack + "\n" +
                        "TCP Flags          : 0x" + Integer.toHexString(flags) + "\n" +
                        "Window Size        : " + windowSize + "\n" +
                        "Checksum           : 0x" + Integer.toHexString(checksum) + "\n" +
                        "Urgent Pointer     : " + urgentPointer + "\n" +
                        "Payload Length     : " + payloadLen + "\n" +
                        "===================================";


        Log.d(TAG, tcpHeaderLog);

        dashboard.logEvent(
                tcpHeaderLog,
                VpnEvent.Level.INFO,
                VpnEvent.Category.TCP
        );

        String key = ipStr(srcIp) + ":" + srcPort + "->" + ipStr(dstIp) + ":" + dstPort;
        boolean isSyn = (flags & PacketUtils.TCP_SYN) != 0;
        boolean isAck = (flags & PacketUtils.TCP_ACK) != 0;
        boolean isFin = (flags & PacketUtils.TCP_FIN) != 0;
        boolean isRst = (flags & PacketUtils.TCP_RST) != 0;
        Log.d(TAG,
                "Flags: SYN=" + isSyn
                        + " ACK=" + isAck
                        + " FIN=" + isFin
                        + " RST=" + isRst);

        TcpSession session = sessions.get(key);

        if (isSyn && !isAck) {
            if (session != null) {
                if (session.state == TcpSession.State.SYN_RCVD
                        || session.state == TcpSession.State.ESTABLISHED) {
                    // Retransmitted SYN for a connection we're already
                    // handling (or have already established) — don't tear
                    // down the in-flight session and lose the handshake;
                    // just re-send the SYN-ACK if we've already sent one.
                    if (session.synAckSent.get()) {
                        Log.d(TAG, "Retransmitted SYN for existing session " + key
                                + ", re-sending SYN-ACK.");
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

            if (!isRst) sendRst(dstIp, dstPort, srcIp, srcPort, ack, seq + payloadLen);
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


        Log.d(TAG,"payload len and sessionstate : "+payloadLen +" "+session.state);
        if (payloadLen > 0 && session.state == TcpSession.State.ESTABLISHED) {
            byte[] data = new byte[payloadLen];
            System.arraycopy(packet, payloadOffset, data, 0, payloadLen);
            try {
                // TTFB START

//                Log.d(TAG, "Writing HTTP payload.");

                // TTFB END
                session.realOut.write(data);
                session.realOut.flush();
                Log.d(TAG, "Payload written successfully.");
                if (session.requestSentCaptured.compareAndSet(false, true)) {
                    session.requestSentTime = System.nanoTime();
                    Log.i(TAG, "Request Sent : " + session.requestSentTime);
                }
                Log.d(TAG, "Payload Length = " + payloadLen);
            } catch (IOException e) {
                Log.w(TAG, "TCP write to real socket failed for " + key, e);
                sendRst(srcIp, srcPort, dstIp, dstPort, session.deviceSeq, seq + payloadLen);
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
                dashboard.logEvent("Creating new TCP session ..",
                        VpnEvent.Level.INFO,
                        VpnEvent.Category.TCP
                        );
                Log.d(TAG, "Destination = " + intToInetName(dstIp).getHostAddress() + ":" + dstPort);
                dashboard.logEvent("Destination = "+ intToInetName(dstIp).getHostAddress() + ":" + dstPort,
                        VpnEvent.Level.INFO,
                        VpnEvent.Category.TCP
                );
                Socket socket = new Socket();
                boolean protectvalue = vpnService.protect(socket); // CRITICAL: avoid routing this back into the tunnel
                dashboard.logEvent("Protect value : "+protectvalue,
                        VpnEvent.Level.INFO,
                        VpnEvent.Category.TCP
                        );
                socket.connect(new InetSocketAddress(intToInetName(dstIp), dstPort), 8000);

                Log.d(TAG, "Socket connected successfully.");
                dashboard.logEvent("Socket connected successfully.",
                        VpnEvent.Level.INFO,
                        VpnEvent.Category.TCP
                );
                session.realSocket = socket;

                String serverIp =
                        socket.getInetAddress().getHostAddress();

                String serverName;

                try {
                    serverName = socket.getInetAddress().getCanonicalHostName();
                } catch (Exception e) {
                    serverName = "Unknown";
                    Log.e(TAG,
                            "Exception while rsolving host name  : "
                                    + intToInetName(dstIp).getHostAddress()
                                    + ":" + dstPort,
                            e);
                    dashboard.logEvent("Exception while rsolving host name  : "
                            + intToInetName(dstIp).getHostAddress()
                            + ":" + dstPort+"exception is : "+e.getMessage(),
                            VpnEvent.Level.INFO,
                            VpnEvent.Category.TCP
                            );
                }

                Log.d(TAG, "Creating TCP session");

                dashboard.logEvent(
                        "========== SERVER ==========\n" +
                                "Server IP      : " + serverIp + "\n" +
                                "Server Name    : " + serverName + "\n" +
                                "============================",
                        VpnEvent.Level.INFO,
                        VpnEvent.Category.TCP
                );

                session.realOut = socket.getOutputStream();
                session.realIn = socket.getInputStream();

                // Handshake: send SYN-ACK
                sendSynAck(session);
            } catch (IOException e) {

                e.printStackTrace();
                Log.w(TAG, "TCP connect failed for " + key + ": " + e.getMessage());
                dashboard.logEvent("TCP socket exception "+e.getMessage(),VpnEvent.Level.INFO,
                        VpnEvent.Category.TCP);
                sendRst(srcIp, srcPort, dstIp, dstPort, session.deviceSeq, session.clientNextSeq);
                sessions.remove(key);
            }
        }, "TcpConnect-" + key).start();
    }

    private java.net.InetAddress intToInetName(byte[] ip) throws IOException {
        return java.net.InetAddress.getByAddress(ip);
    }

    private void sendSynAck(TcpSession s) {
        boolean firstSend = s.synAckSent.compareAndSet(false, true);
        writeTcpPacket(s.dstIp, s.dstPort, s.srcIp, s.srcPort,
                s.deviceSeq, s.clientNextSeq,
                PacketUtils.TCP_SYN | PacketUtils.TCP_ACK, null, 0);
        if (firstSend) {
            s.deviceSeq += 1; // SYN consumes a sequence number, only once
        }
    }

    private void sendAck(TcpSession s, boolean pshFlag) {
        int flags = PacketUtils.TCP_ACK | (pshFlag ? PacketUtils.TCP_PSH : 0);
        writeTcpPacket(s.dstIp, s.dstPort, s.srcIp, s.srcPort,
                s.deviceSeq, s.clientNextSeq, flags, null, 0);
    }

    /** Called by TcpSession's reader thread when data arrives from the real socket. */
    void sendDataToClient(TcpSession s, byte[] data, int len) {
        writeTcpPacket(s.dstIp, s.dstPort, s.srcIp, s.srcPort,
                s.deviceSeq, s.clientNextSeq,
                PacketUtils.TCP_ACK | PacketUtils.TCP_PSH, data, len);
        s.deviceSeq += len;
    }

    /** Called when the real socket hits EOF - tell the client we're done sending. */
    void sendFinToClient(TcpSession s) {
        writeTcpPacket(s.dstIp, s.dstPort, s.srcIp, s.srcPort,
                s.deviceSeq, s.clientNextSeq,
                PacketUtils.TCP_ACK | PacketUtils.TCP_FIN, null, 0);
        s.deviceSeq += 1;
    }


    void reportTtfb(TcpSession s, long ttfbMs, String key) {
        Log.d(TAG,
                "Reporting TTFB = "
                        + ttfbMs + " ms");
        dashboard.logEvent(
                "TTFB : " + ttfbMs + " ms  (" + key + ")",
                VpnEvent.Level.SUCCESS,
                VpnEvent.Category.TCP);
        dashboard.recordTtfb(ttfbMs); // drives tvLastTtfb on the dashboard card
        Log.d(TAG,
                "Dashboard updated with TTFB.");
    }


    private void sendRst(byte[] fromIp, int fromPort, byte[] toIp, int toPort,
                         long seq, long ack) {
        writeTcpPacket(fromIp, fromPort, toIp, toPort, seq, ack, PacketUtils.TCP_RST, null, 0);
    }

    private void writeTcpPacket(byte[] fromIp, int fromPort, byte[] toIp, int toPort,
                                long seq, long ack, int flags, byte[] payload, int payloadLen) {
        int ipHeaderLen = 20;
        int tcpHeaderLen = 20;
        int total = ipHeaderLen + tcpHeaderLen + payloadLen;
        ByteBuffer buf = ByteBuffer.allocate(total);

        PacketUtils.writeIPv4Header(buf, total, PacketUtils.PROTO_TCP, fromIp, toIp);
        int tcpStart = buf.position();
        PacketUtils.writeTcpHeader(buf, fromPort, toPort, seq, ack, flags, 65535);
        if (payload != null && payloadLen > 0) {
            buf.put(payload, 0, payloadLen);
        }
        PacketUtils.fixTcpChecksum(buf, 0, tcpStart, tcpHeaderLen + payloadLen, fromIp, toIp);

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
            if (session.realSocket != null) session.realSocket.close();
        } catch (IOException ignored) {
        }
    }

    void shutdown() {
        shutdown = true;
        for (Map.Entry<String, TcpSession> e : sessions.entrySet()) {
            closeSession(e.getKey(), e.getValue());
        }
        globalTtfbCaptured.set(false);
    }


    void resetGlobalTtfb() {
        globalTtfbCaptured.set(false);
    }


    private static long readUnsignedInt(byte[] b, int off) {
        return ((long) (b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16)
                | ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
    }

    private static String ipStr(byte[] ip) {
        return (ip[0] & 0xFF) + "." + (ip[1] & 0xFF) + "." + (ip[2] & 0xFF) + "." + (ip[3] & 0xFF);
    }

    /** Per-connection state. */
    static class TcpSession {
        enum State { SYN_RCVD, ESTABLISHED, CLOSING, CLOSED }

        State state;
        byte[] srcIp;
        int srcPort;
        byte[] dstIp;
        int dstPort;

        long clientNextSeq; // next byte we expect from the client (our ACK number)
        long deviceSeq;     // next sequence number we use when sending to the client

        Socket realSocket;
        OutputStream realOut;
        InputStream realIn;



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
                        // TTFB START
                        Log.d(TAG, "Received " + n + " bytes from server.");
                        Log.d(TAG, "realIn.read() = " + n);
                        Log.d(TAG,
                                "First byte condition checking");
                        if (n > 0 && firstByteCaptured.compareAndSet(false, true)) {

                            firstByteReceivedTime = System.nanoTime();

                            if (requestSentTime > 0) {

                                ttfbMs = TimeUnit.NANOSECONDS.toMillis(
                                        firstByteReceivedTime - requestSentTime);

                                String ttfbLog =
                                        "========== TTFB ==========\n" +
                                                "Request Sent      : " + requestSentTime + "\n" +
                                                "First Byte        : " + firstByteReceivedTime + "\n" +
                                                "TTFB              : " + ttfbMs + " ms\n" +
                                                "==========================";

                                Log.i(TAG, ttfbLog);

                                forwarder.dashboard.logEvent(
                                        ttfbLog,
                                        VpnEvent.Level.INFO,
                                        VpnEvent.Category.TCP
                                );


                                forwarder.reportTtfb(this, ttfbMs, key);

                            } else {

                                Log.w(TAG, "Request time not available.");
                            }
                        }

                        if (n > 0) {

                            String rxHeaderLog =
                                    "========== [RX] TCP HEADER ==========\n" +
                                            "Source IP          : " + TcpForwarder.ipStr(dstIp) + "\n" +
                                            "Destination IP     : " + TcpForwarder.ipStr(srcIp) + "\n" +
                                            "Source Port        : " + dstPort + "\n" +
                                            "Destination Port   : " + srcPort + "\n" +
                                            "Payload Length     : " + n + "\n" +
                                            "Sequence Number    : " + deviceSeq + "\n" +
                                            "ACK Number         : " + clientNextSeq + "\n" +
                                            "=====================================";

                            forwarder.dashboard.logEvent(
                                    rxHeaderLog,
                                    VpnEvent.Level.INFO,
                                    VpnEvent.Category.TCP
                            );
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
}