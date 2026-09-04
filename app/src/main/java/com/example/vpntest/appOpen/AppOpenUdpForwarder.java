package com.example.vpntest.appOpen;

import android.net.VpnService;
import android.util.Log;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.example.vpntest.PacketUtils;
import com.example.vpntest.ParsedPacket;
import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.repo.VpnEventRepository;


class AppOpenUdpForwarder {
    private static final String TAG = "VPN_UdpForwarder : ";
    private static final long SESSION_IDLE_TIMEOUT_MS = 60_000;

    private final VpnService vpnService;
    private final FileOutputStream tunOut;
    private final Object tunWriteLock;

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupExecutor =
            Executors.newSingleThreadScheduledExecutor();
    private volatile boolean shutdown = false;

    private final VpnEventRepository dashboard = VpnEventRepository.getInstance();
    AppOpenUdpForwarder(VpnService vpnService, FileOutputStream tunOut, Object tunWriteLock) {
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
            if (dstPort == 53) {
                session.dnsRequestTime = System.currentTimeMillis();
            }

            session.socket.send(out);
            session.touch();

            String udpTxLog =
                    "========== [TX] UDP ==========\n" +
                            "IP Version          : IPv" + parsed.ipVersion + "\n" +
                            "Source IP          : " + ipStr(srcIp) + "\n" +
                            "Destination IP     : " + ipStr(dstIp) + "\n" +
                            "Source Port        : " + srcPort + "\n" +
                            "Destination Port   : " + dstPort + "\n" +
                            "Packet Length      : " + payload.length + "\n" +
                            "==============================";

            dashboard.logEvent(TAG+
                            udpTxLog,
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
                    session.touch();
                    writeUdpReplyToTun(session, buf, reply.getLength());
                } catch (IOException e) {
                    break; // socket closed or errored
                }
            }
        }, "UdpReply-" + key);
        t.setDaemon(true);
        t.start();
    }

    private void writeUdpReplyToTun(Session session, byte[] data, int dataLength) {
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

    private static class Session {
        final DatagramSocket socket;
        final InetAddress destAddress;
        final byte[] srcIp;
        final int srcPort;
        final byte[] dstIp;
        final int dstPort;
        volatile long lastActivity;

        // DNS lookup measurement
        long dnsRequestTime;

        Session(DatagramSocket socket, InetAddress destAddress,
                byte[] srcIp, int srcPort, byte[] dstIp, int dstPort) {
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