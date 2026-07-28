package com.example.vpntest;

import java.nio.ByteBuffer;


final class PacketUtils {

    private PacketUtils() {}


    static int checksum(byte[] data, int offset, int length) {
        long sum = 0;
        int i = offset;
        int end = offset + length;
        while (i < end - 1) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
            i += 2;
        }
        if (i < end) {
            sum += (data[i] & 0xFF) << 8;
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (int) (~sum & 0xFFFF);
    }

    /** Builds a 20-byte IPv4 header (no options). */
    static void writeIPv4Header(ByteBuffer buf, int totalLength, int protocol,
                                byte[] srcIp, byte[] dstIp) {
        int start = buf.position();
        buf.put((byte) 0x45);       // version=4, IHL=5
        buf.put((byte) 0x00);       // DSCP/ECN
        buf.putShort((short) totalLength);
        buf.putShort((short) 0);    // identification
        buf.putShort((short) 0x4000); // flags=DF, fragment offset=0
        buf.put((byte) 64);         // TTL
        buf.put((byte) protocol);
        int checksumPos = buf.position();
        buf.putShort((short) 0);    // checksum placeholder
        buf.put(srcIp);
        buf.put(dstIp);

        // buf must be array-backed (allocate(), not allocateDirect()) for this to work.
        int checksum = checksum(buf.array(), buf.arrayOffset() + start, 20);
        buf.putShort(checksumPos, (short) checksum);
    }

    /** Builds an 8-byte UDP header (checksum optional -> set to 0 for IPv4). */
    static void writeUdpHeader(ByteBuffer buf, int srcPort, int dstPort, int udpLength) {
        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putShort((short) udpLength);
        buf.putShort((short) 0); // checksum optional for IPv4, skip computing it
    }

    /**
     * Builds a 20-byte TCP header (no options).
     * flags: use the TCP flag bit constants below (FIN|SYN|RST|PSH|ACK).
     */
    static void writeTcpHeader(ByteBuffer buf, int srcPort, int dstPort,
                               long seq, long ack, int flags, int window) {
        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putInt((int) seq);
        buf.putInt((int) ack);
        buf.put((byte) 0x50);           // data offset=5 (20 bytes), reserved bits
        buf.put((byte) flags);
        buf.putShort((short) window);
        buf.putShort((short) 0);        // checksum placeholder, fixed up by caller
        buf.putShort((short) 0);        // urgent pointer
    }

    /** Computes TCP/UDP checksum over the pseudo header + segment and patches it in. */
    static void fixTcpChecksum(ByteBuffer packet, int ipHeaderStart, int tcpHeaderStart,
                               int tcpSegmentLength, byte[] srcIp, byte[] dstIp) {
        ByteBuffer pseudo = ByteBuffer.allocate(12 + tcpSegmentLength);
        pseudo.put(srcIp);
        pseudo.put(dstIp);
        pseudo.put((byte) 0);
        pseudo.put((byte) 6); // TCP protocol number
        pseudo.putShort((short) tcpSegmentLength);

        // packet must be array-backed (allocate(), not allocateDirect()).
        pseudo.put(packet.array(), packet.arrayOffset() + tcpHeaderStart, tcpSegmentLength);

        int checksum = checksum(pseudo.array(), 0, pseudo.capacity());
        packet.putShort(tcpHeaderStart + 16, (short) checksum);
    }

    // TCP flag bits
    static final int TCP_FIN = 0x01;
    static final int TCP_SYN = 0x02;
    static final int TCP_RST = 0x04;
    static final int TCP_PSH = 0x08;
    static final int TCP_ACK = 0x10;

    static final int PROTO_TCP = 6;
    static final int PROTO_UDP = 17;
}