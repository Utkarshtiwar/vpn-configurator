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

    /**
     * Builds a 40-byte IPv6 fixed header (no extension headers).
     *
     * @param payloadLength length of everything AFTER this 40-byte header
     *                      (i.e. the transport segment length, not including this header)
     * @param nextHeader    transport protocol number (e.g. PROTO_TCP / PROTO_UDP)
     * @param srcIp         16-byte source address
     * @param dstIp         16-byte destination address
     */
    static void writeIPv6Header(ByteBuffer buf, int payloadLength, int nextHeader,
                                byte[] srcIp, byte[] dstIp) {
        // Version=6, Traffic Class=0, Flow Label=0 -> first 4 bytes are 0x60000000.
        buf.putInt(0x60000000);
        buf.putShort((short) payloadLength);
        buf.put((byte) nextHeader);
        buf.put((byte) 64); // Hop Limit
        buf.put(srcIp);
        buf.put(dstIp);
    }

    /** Builds an 8-byte UDP header. Checksum is left as a placeholder (0); patch it afterwards if needed. */
    static void writeUdpHeader(ByteBuffer buf, int srcPort, int dstPort, int udpLength) {
        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putShort((short) udpLength);
        buf.putShort((short) 0); // checksum placeholder
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

    /**
     * Computes the pseudo-header + segment internet checksum for TCP/UDP,
     * for either a 4-byte (IPv4) or 16-byte (IPv6) address pair.
     */
    private static int transportChecksum(byte[] srcIp, byte[] dstIp, int protocol,
                                         byte[] segment, int segmentOffset, int segmentLength) {
        boolean ipv6 = srcIp.length == 16;
        int pseudoHeaderLen = ipv6 ? 40 : 12;

        ByteBuffer pseudo = ByteBuffer.allocate(pseudoHeaderLen + segmentLength);
        pseudo.put(srcIp);
        pseudo.put(dstIp);

        if (ipv6) {
            pseudo.putInt(segmentLength);   // Upper-Layer Packet Length (4 bytes)
            pseudo.put((byte) 0);
            pseudo.put((byte) 0);
            pseudo.put((byte) 0);
            pseudo.put((byte) protocol);    // Next Header (1 byte, zero-padded above)
        } else {
            pseudo.put((byte) 0);
            pseudo.put((byte) protocol);
            pseudo.putShort((short) segmentLength);
        }

        pseudo.put(segment, segmentOffset, segmentLength);

        return checksum(pseudo.array(), 0, pseudo.capacity());
    }

    /** Computes TCP checksum over the pseudo header + segment and patches it in. Works for IPv4 or IPv6 addresses. */
    static void fixTcpChecksum(ByteBuffer packet, int ipHeaderStart, int tcpHeaderStart,
                               int tcpSegmentLength, byte[] srcIp, byte[] dstIp) {
        int checksum = transportChecksum(srcIp, dstIp, PROTO_TCP,
                packet.array(), packet.arrayOffset() + tcpHeaderStart, tcpSegmentLength);
        packet.putShort(tcpHeaderStart + 16, (short) checksum);
    }

    /**
     * Computes UDP checksum over the pseudo header + segment and patches it in.
     * Mandatory for IPv6 (a computed value of 0 is stored as 0xFFFF per RFC 2460 8.1);
     * for IPv4 the caller may skip calling this since UDP checksum is optional there.
     */
    static void fixUdpChecksum(ByteBuffer packet, int udpHeaderStart,
                               int udpSegmentLength, byte[] srcIp, byte[] dstIp) {
        int checksum = transportChecksum(srcIp, dstIp, PROTO_UDP,
                packet.array(), packet.arrayOffset() + udpHeaderStart, udpSegmentLength);
        if (checksum == 0) {
            checksum = 0xFFFF;
        }
        packet.putShort(udpHeaderStart + 6, (short) checksum);
    }

    // TCP flag bits
    static final int TCP_FIN = 0x01;
    static final int TCP_SYN = 0x02;
    static final int TCP_RST = 0x04;
    static final int TCP_PSH = 0x08;
    static final int TCP_ACK = 0x10;

    static final int PROTO_TCP = 6;
    static final int PROTO_UDP = 17;
    static final int PROTO_ICMPV4 = 1;
    static final int PROTO_ICMPV6 = 58;
}