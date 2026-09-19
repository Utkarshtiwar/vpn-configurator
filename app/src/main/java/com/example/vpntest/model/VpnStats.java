package com.example.vpntest.model;

public final class VpnStats {

    public final String vpnStatus;
    public final String permissionStatus;
    public final String interfaceStatus;
    public final String readerStatus;

    public final int totalPackets;
    public final int tcpCount;
    public final int udpCount;
    public final int ipv6SkippedCount;

    public final String lastProtocol;
    public final String lastSourceIp;
    public final String lastDestIp;
    public final int lastPacketSize;
    public final long lastPacketTimestamp;

    public final long lastTtfbMs;
    public final long tcpHandshakeNano;

    // TLS handshake metric
    public final double tlsHandshakeMs;

    // DNS metrics
    public final double lastDnsLookupMs;
    public final String lastDnsServerIp;

    // Destination IP from [MATCH] event
    public final String lastDnsDestinationIp;

    // Hostname associated with resolved destination IP
    public final String lastDnsHostName;


    public VpnStats() {

        this(
                "Stopped",
                "Not requested",
                "Not established",
                "Stopped",

                0,
                0,
                0,
                0,

                "-",
                "-",
                "-",
                0,
                0L,

                -1L,
                -1L,

                -1.0,

                -1.0,
                "-",
                "-",
                "-"
        );
    }


    private VpnStats(
            String vpnStatus,
            String permissionStatus,
            String interfaceStatus,
            String readerStatus,

            int totalPackets,
            int tcpCount,
            int udpCount,
            int ipv6SkippedCount,

            String lastProtocol,
            String lastSourceIp,
            String lastDestIp,
            int lastPacketSize,
            long lastPacketTimestamp,

            long lastTtfbMs,
            long tcpHandshakeNano,

            double tlsHandshakeMs,

            double lastDnsLookupMs,
            String lastDnsServerIp,
            String lastDnsDestinationIp,
            String lastDnsHostName
    ) {

        this.vpnStatus = vpnStatus;
        this.permissionStatus = permissionStatus;
        this.interfaceStatus = interfaceStatus;
        this.readerStatus = readerStatus;

        this.totalPackets = totalPackets;
        this.tcpCount = tcpCount;
        this.udpCount = udpCount;
        this.ipv6SkippedCount = ipv6SkippedCount;

        this.lastProtocol = lastProtocol;
        this.lastSourceIp = lastSourceIp;
        this.lastDestIp = lastDestIp;
        this.lastPacketSize = lastPacketSize;
        this.lastPacketTimestamp = lastPacketTimestamp;

        this.lastTtfbMs = lastTtfbMs;
        this.tcpHandshakeNano = tcpHandshakeNano;

        this.tlsHandshakeMs = tlsHandshakeMs;

        this.lastDnsLookupMs = lastDnsLookupMs;
        this.lastDnsServerIp = lastDnsServerIp;
        this.lastDnsDestinationIp = lastDnsDestinationIp;
        this.lastDnsHostName = lastDnsHostName;
    }


    public VpnStats withVpnStatus(String value) {

        return new VpnStats(
                value,
                permissionStatus,
                interfaceStatus,
                readerStatus,

                totalPackets,
                tcpCount,
                udpCount,
                ipv6SkippedCount,

                lastProtocol,
                lastSourceIp,
                lastDestIp,
                lastPacketSize,
                lastPacketTimestamp,

                lastTtfbMs,
                tcpHandshakeNano,

                tlsHandshakeMs,

                lastDnsLookupMs,
                lastDnsServerIp,
                lastDnsDestinationIp,
                lastDnsHostName
        );
    }


    public VpnStats withPermissionStatus(String value) {

        return new VpnStats(
                vpnStatus,
                value,
                interfaceStatus,
                readerStatus,

                totalPackets,
                tcpCount,
                udpCount,
                ipv6SkippedCount,

                lastProtocol,
                lastSourceIp,
                lastDestIp,
                lastPacketSize,
                lastPacketTimestamp,

                lastTtfbMs,
                tcpHandshakeNano,

                tlsHandshakeMs,

                lastDnsLookupMs,
                lastDnsServerIp,
                lastDnsDestinationIp,
                lastDnsHostName
        );
    }


    public VpnStats withInterfaceStatus(String value) {

        return new VpnStats(
                vpnStatus,
                permissionStatus,
                value,
                readerStatus,

                totalPackets,
                tcpCount,
                udpCount,
                ipv6SkippedCount,

                lastProtocol,
                lastSourceIp,
                lastDestIp,
                lastPacketSize,
                lastPacketTimestamp,

                lastTtfbMs,
                tcpHandshakeNano,

                tlsHandshakeMs,

                lastDnsLookupMs,
                lastDnsServerIp,
                lastDnsDestinationIp,
                lastDnsHostName
        );
    }


    public VpnStats withReaderStatus(String value) {

        return new VpnStats(
                vpnStatus,
                permissionStatus,
                interfaceStatus,
                value,

                totalPackets,
                tcpCount,
                udpCount,
                ipv6SkippedCount,

                lastProtocol,
                lastSourceIp,
                lastDestIp,
                lastPacketSize,
                lastPacketTimestamp,

                lastTtfbMs,
                tcpHandshakeNano,

                tlsHandshakeMs,

                lastDnsLookupMs,
                lastDnsServerIp,
                lastDnsDestinationIp,
                lastDnsHostName
        );
    }


    public VpnStats withPacket(
            String protocol,
            String sourceIp,
            String destIp,
            int packetSize,
            long packetTimestamp
    ) {

        int newTotalPackets = totalPackets + 1;

        int newTcpCount = tcpCount;
        int newUdpCount = udpCount;

        if ("TCP".equalsIgnoreCase(protocol)) {
            newTcpCount++;
        } else if ("UDP".equalsIgnoreCase(protocol)) {
            newUdpCount++;
        }

        return new VpnStats(
                vpnStatus,
                permissionStatus,
                interfaceStatus,
                readerStatus,

                newTotalPackets,
                newTcpCount,
                newUdpCount,
                ipv6SkippedCount,

                protocol,
                sourceIp,
                destIp,
                packetSize,
                packetTimestamp,

                lastTtfbMs,
                tcpHandshakeNano,

                tlsHandshakeMs,

                lastDnsLookupMs,
                lastDnsServerIp,
                lastDnsDestinationIp,
                lastDnsHostName
        );
    }


    public VpnStats withIpv6Skipped() {

        return new VpnStats(
                vpnStatus,
                permissionStatus,
                interfaceStatus,
                readerStatus,

                totalPackets,
                tcpCount,
                udpCount,
                ipv6SkippedCount + 1,

                lastProtocol,
                lastSourceIp,
                lastDestIp,
                lastPacketSize,
                lastPacketTimestamp,

                lastTtfbMs,
                tcpHandshakeNano,

                tlsHandshakeMs,

                lastDnsLookupMs,
                lastDnsServerIp,
                lastDnsDestinationIp,
                lastDnsHostName
        );
    }


    public VpnStats withTtfb(long ttfbMs) {

        return new VpnStats(
                vpnStatus,
                permissionStatus,
                interfaceStatus,
                readerStatus,

                totalPackets,
                tcpCount,
                udpCount,
                ipv6SkippedCount,

                lastProtocol,
                lastSourceIp,
                lastDestIp,
                lastPacketSize,
                lastPacketTimestamp,

                ttfbMs,
                tcpHandshakeNano,

                tlsHandshakeMs,

                lastDnsLookupMs,
                lastDnsServerIp,
                lastDnsDestinationIp,
                lastDnsHostName
        );
    }


    public VpnStats withTcpHandshake(long handshakeNano) {

        return new VpnStats(
                vpnStatus,
                permissionStatus,
                interfaceStatus,
                readerStatus,

                totalPackets,
                tcpCount,
                udpCount,
                ipv6SkippedCount,

                lastProtocol,
                lastSourceIp,
                lastDestIp,
                lastPacketSize,
                lastPacketTimestamp,

                lastTtfbMs,
                handshakeNano,

                tlsHandshakeMs,

                lastDnsLookupMs,
                lastDnsServerIp,
                lastDnsDestinationIp,
                lastDnsHostName
        );
    }


    public VpnStats withTlsHandshake(double handshakeMs) {

        return new VpnStats(
                vpnStatus,
                permissionStatus,
                interfaceStatus,
                readerStatus,

                totalPackets,
                tcpCount,
                udpCount,
                ipv6SkippedCount,

                lastProtocol,
                lastSourceIp,
                lastDestIp,
                lastPacketSize,
                lastPacketTimestamp,

                lastTtfbMs,
                tcpHandshakeNano,

                handshakeMs,

                lastDnsLookupMs,
                lastDnsServerIp,
                lastDnsDestinationIp,
                lastDnsHostName
        );
    }


    public VpnStats withDnsLookup(
            double dnsLookupMs,
            String dnsServerIp
    ) {

        return new VpnStats(
                vpnStatus,
                permissionStatus,
                interfaceStatus,
                readerStatus,

                totalPackets,
                tcpCount,
                udpCount,
                ipv6SkippedCount,

                lastProtocol,
                lastSourceIp,
                lastDestIp,
                lastPacketSize,
                lastPacketTimestamp,

                lastTtfbMs,
                tcpHandshakeNano,

                tlsHandshakeMs,

                dnsLookupMs,
                dnsServerIp,
                lastDnsDestinationIp,
                lastDnsHostName
        );
    }


    public VpnStats withDnsDestinationIp(
            String destinationIp
    ) {

        return new VpnStats(
                vpnStatus,
                permissionStatus,
                interfaceStatus,
                readerStatus,

                totalPackets,
                tcpCount,
                udpCount,
                ipv6SkippedCount,

                lastProtocol,
                lastSourceIp,
                lastDestIp,
                lastPacketSize,
                lastPacketTimestamp,

                lastTtfbMs,
                tcpHandshakeNano,

                tlsHandshakeMs,

                lastDnsLookupMs,
                lastDnsServerIp,
                destinationIp,
                lastDnsHostName
        );
    }


    public VpnStats withDnsHostName(
            String hostName
    ) {

        return new VpnStats(
                vpnStatus,
                permissionStatus,
                interfaceStatus,
                readerStatus,

                totalPackets,
                tcpCount,
                udpCount,
                ipv6SkippedCount,

                lastProtocol,
                lastSourceIp,
                lastDestIp,
                lastPacketSize,
                lastPacketTimestamp,

                lastTtfbMs,
                tcpHandshakeNano,

                tlsHandshakeMs,

                lastDnsLookupMs,
                lastDnsServerIp,
                lastDnsDestinationIp,
                hostName
        );
    }
}