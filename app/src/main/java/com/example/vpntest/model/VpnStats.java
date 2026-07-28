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

    public VpnStats() {
        this("Stopped", "Not requested", "Not established", "Stopped",
                0, 0, 0, 0, "-", "-", "-", 0, 0L);
    }

    private VpnStats(String vpnStatus, String permissionStatus, String interfaceStatus,
                     String readerStatus, int totalPackets, int tcpCount, int udpCount,
                     int ipv6SkippedCount, String lastProtocol, String lastSourceIp,
                     String lastDestIp, int lastPacketSize, long lastPacketTimestamp) {
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
    }

    public VpnStats withVpnStatus(String v) {
        return new VpnStats(v, permissionStatus, interfaceStatus, readerStatus, totalPackets,
                tcpCount, udpCount, ipv6SkippedCount, lastProtocol, lastSourceIp, lastDestIp,
                lastPacketSize, lastPacketTimestamp);
    }

    public VpnStats withPermissionStatus(String v) {
        return new VpnStats(vpnStatus, v, interfaceStatus, readerStatus, totalPackets,
                tcpCount, udpCount, ipv6SkippedCount, lastProtocol, lastSourceIp, lastDestIp,
                lastPacketSize, lastPacketTimestamp);
    }

    public VpnStats withInterfaceStatus(String v) {
        return new VpnStats(vpnStatus, permissionStatus, v, readerStatus, totalPackets,
                tcpCount, udpCount, ipv6SkippedCount, lastProtocol, lastSourceIp, lastDestIp,
                lastPacketSize, lastPacketTimestamp);
    }

    public VpnStats withReaderStatus(String v) {
        return new VpnStats(vpnStatus, permissionStatus, interfaceStatus, v, totalPackets,
                tcpCount, udpCount, ipv6SkippedCount, lastProtocol, lastSourceIp, lastDestIp,
                lastPacketSize, lastPacketTimestamp);
    }


    public VpnStats withPacket(String protocol, String srcIp, String dstIp, int size, long ts) {
        int newTcp = tcpCount + ("TCP".equals(protocol) ? 1 : 0);
        int newUdp = udpCount + ("UDP".equals(protocol) ? 1 : 0);
        return new VpnStats(vpnStatus, permissionStatus, interfaceStatus, readerStatus,
                totalPackets + 1, newTcp, newUdp, ipv6SkippedCount,
                protocol, srcIp, dstIp, size, ts);
    }

    public VpnStats withIpv6Skipped() {
        return new VpnStats(vpnStatus, permissionStatus, interfaceStatus, readerStatus,
                totalPackets, tcpCount, udpCount, ipv6SkippedCount + 1,
                lastProtocol, lastSourceIp, lastDestIp, lastPacketSize, lastPacketTimestamp);
    }
}