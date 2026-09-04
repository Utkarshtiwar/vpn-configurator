package com.example.vpntest;

/**
 * Immutable result of parsing a single packet read from the TUN device.
 *
 * Introduced so that AppOpenMediatorVpnService / TcpForwarder / UdpForwarder can
 * share one parsing pipeline for both IPv4 and IPv6 instead of duplicating
 * header-parsing logic per address family.
 */
public final class ParsedPacket {

    public enum Status {
        /** Parsing succeeded; transportHeaderOffset/ports are valid (when protocol is TCP/UDP). */
        OK,
        /** Packet was truncated / internally inconsistent and must be dropped. */
        MALFORMED,
        /**
         * Packet is a valid IPv4/IPv6 fragment but NOT the first fragment, so no
         * transport header (and therefore no ports) is available in this packet.
         */
        NON_FIRST_FRAGMENT
    }

    public final Status status;
    public final String reason; // human readable, only meaningful for MALFORMED / NON_FIRST_FRAGMENT

    public final int ipVersion; // 4 or 6 (0 if status == MALFORMED and version could not even be read)

    public final String sourceIp;        // textual representation (dotted-decimal or compressed IPv6)
    public final String destinationIp;

    public final byte[] sourceIpBytes;      // 4 bytes for IPv4, 16 bytes for IPv6
    public final byte[] destinationIpBytes;

    public final int transportProtocol;     // IPv4 Protocol / IPv6 Next Header of the transport layer (-1 if unknown)
    public final int transportHeaderOffset; // offset into the packet where the TCP/UDP/ICMP header begins (-1 if unavailable)
    public final int ipHeaderLength;        // IPv4: IHL*4. IPv6: 40 + extension headers walked (informational).

    public final int sourcePort;      // -1 if not TCP/UDP or not available
    public final int destinationPort; // -1 if not TCP/UDP or not available

    public final int ttlOrHopLimit;
    public final int payloadLength;   // bytes after the (fixed) IP header: IPv4 = total-IHL*4, IPv6 = Payload Length field

    final boolean isFirstFragment;

    public ParsedPacket(Status status, String reason, int ipVersion,
                         String sourceIp, String destinationIp,
                         byte[] sourceIpBytes, byte[] destinationIpBytes,
                         int transportProtocol, int transportHeaderOffset, int ipHeaderLength,
                         int sourcePort, int destinationPort,
                         int ttlOrHopLimit, int payloadLength, boolean isFirstFragment) {
        this.status = status;
        this.reason = reason;
        this.ipVersion = ipVersion;
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.sourceIpBytes = sourceIpBytes;
        this.destinationIpBytes = destinationIpBytes;
        this.transportProtocol = transportProtocol;
        this.transportHeaderOffset = transportHeaderOffset;
        this.ipHeaderLength = ipHeaderLength;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.ttlOrHopLimit = ttlOrHopLimit;
        this.payloadLength = payloadLength;
        this.isFirstFragment = isFirstFragment;
    }

    static ParsedPacket malformed(String reason) {
        return new ParsedPacket(Status.MALFORMED, reason, 0, null, null, null, null,
                -1, -1, -1, -1, -1, -1, -1, false);
    }

    static ParsedPacket nonFirstFragment(int ipVersion, String sourceIp, String destinationIp,
                                         byte[] sourceIpBytes, byte[] destinationIpBytes,
                                         int transportProtocol, int ipHeaderLength,
                                         int ttlOrHopLimit, int payloadLength) {
        return new ParsedPacket(Status.NON_FIRST_FRAGMENT,
                "Non-first fragment: transport header unavailable in this packet",
                ipVersion, sourceIp, destinationIp, sourceIpBytes, destinationIpBytes,
                transportProtocol, -1, ipHeaderLength, -1, -1,
                ttlOrHopLimit, payloadLength, false);
    }

    static ParsedPacket ok(int ipVersion, String sourceIp, String destinationIp,
                           byte[] sourceIpBytes, byte[] destinationIpBytes,
                           int transportProtocol, int transportHeaderOffset, int ipHeaderLength,
                           int sourcePort, int destinationPort,
                           int ttlOrHopLimit, int payloadLength) {
        return new ParsedPacket(Status.OK, null, ipVersion, sourceIp, destinationIp,
                sourceIpBytes, destinationIpBytes, transportProtocol, transportHeaderOffset,
                ipHeaderLength, sourcePort, destinationPort, ttlOrHopLimit, payloadLength, true);
    }

    /** "1.2.3.4:80" for IPv4, "[2001:db8::1]:443" for IPv6 - safe for use as a map key. */
    static String formatHostPort(int ipVersion, String ip, int port) {
        return ipVersion == 6 ? ("[" + ip + "]:" + port) : (ip + ":" + port);
    }

    public String connectionKey() {
        return formatHostPort(ipVersion, sourceIp, sourcePort) + "->" + formatHostPort(ipVersion, destinationIp, destinationPort);
    }
}