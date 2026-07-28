package com.example.vpntest.model;

public class ConnectionInfo {

    private int uid;

    private String sourceIp;
    private int sourcePort;

    private String destinationIp;
    private int destinationPort;

    private String hostName;

    private String protocol;

    private long bytesSent;
    private long bytesReceived;

    private long startTime;
    private long endTime;

    private long rtt;

    // Getters

    public int getUid() {
        return uid;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    public String getHostName() {
        return hostName;
    }

    public String getProtocol() {
        return protocol;
    }

    public long getBytesSent() {
        return bytesSent;
    }

    public long getBytesReceived() {
        return bytesReceived;
    }

    public long getStartTime() {
        return startTime;
    }

    public long getEndTime() {
        return endTime;
    }

    public long getRtt() {
        return rtt;
    }

    // Setters

    public void setUid(int uid) {
        this.uid = uid;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public void setSourcePort(int sourcePort) {
        this.sourcePort = sourcePort;
    }

    public void setDestinationIp(String destinationIp) {
        this.destinationIp = destinationIp;
    }

    public void setDestinationPort(int destinationPort) {
        this.destinationPort = destinationPort;
    }

    public void setHostName(String hostName) {
        this.hostName = hostName;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public void setBytesSent(long bytesSent) {
        this.bytesSent = bytesSent;
    }

    public void setBytesReceived(long bytesReceived) {
        this.bytesReceived = bytesReceived;
    }

    public void setStartTime(long startTime) {
        this.startTime = startTime;
    }

    public void setEndTime(long endTime) {
        this.endTime = endTime;
    }

    public void setRtt(long rtt) {
        this.rtt = rtt;
    }
}