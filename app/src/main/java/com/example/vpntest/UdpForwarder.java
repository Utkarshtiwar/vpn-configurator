package com.example.vpntest;

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


class UdpForwarder {
    private static final String TAG = "UdpForwarder";
    private static final long SESSION_IDLE_TIMEOUT_MS = 60_000;

    private final VpnService vpnService;
    private final FileOutputStream tunOut;
    private final Object tunWriteLock;

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupExecutor =
            Executors.newSingleThreadScheduledExecutor();

    UdpForwarder(VpnService vpnService, FileOutputStream tunOut, Object tunWriteLock) {
        this.vpnService = vpnService;
        this.tunOut = tunOut;
        this.tunWriteLock = tunWriteLock;
        cleanupExecutor.scheduleAtFixedRate(this::reapIdleSessions, 30, 30, TimeUnit.SECONDS);
    }

    /**
     * @param ipHeaderLen  length of the IPv4 header (usually 20)
     * @param packet       full packet bytes as read from the TUN
     * @param length       total valid length of packet
     */
    void handlePacket(byte[] packet, int length, int ipHeaderLen,
                      byte[] srcIp, byte[] dstIp, int srcPort, int dstPort) {
        int udpPayloadOffset = ipHeaderLen + 8; // 8-byte UDP header
        int udpPayloadLen = length - udpPayloadOffset;
        if (udpPayloadLen < 0) return;

        String key = ipToString(srcIp) + ":" + srcPort + "->" + ipToString(dstIp) + ":" + dstPort;
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
            session.socket.send(out);
            session.touch();
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
        int ipHeaderLen = 20;
        int udpHeaderLen = 8;
        int totalLen = ipHeaderLen + udpHeaderLen + dataLength;

        ByteBuffer packet = ByteBuffer.allocate(totalLen);

        // Response is from the ORIGINAL destination back to the ORIGINAL source.
        PacketUtils.writeIPv4Header(packet, totalLen, PacketUtils.PROTO_UDP,
                session.dstIp, session.srcIp);
        PacketUtils.writeUdpHeader(packet, session.dstPort, session.srcPort,
                udpHeaderLen + dataLength);
        packet.put(data, 0, dataLength);

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
        cleanupExecutor.shutdownNow();
        for (Session s : sessions.values()) {
            s.socket.close();
        }
        sessions.clear();
    }

    private static String ipToString(byte[] ip) {
        return (ip[0] & 0xFF) + "." + (ip[1] & 0xFF) + "." + (ip[2] & 0xFF) + "." + (ip[3] & 0xFF);
    }

    private static class Session {
        final DatagramSocket socket;
        final InetAddress destAddress;
        final byte[] srcIp;
        final int srcPort;
        final byte[] dstIp;
        final int dstPort;
        volatile long lastActivity;

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