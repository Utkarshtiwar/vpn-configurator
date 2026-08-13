package com.example.vpntest.model;

public class VpnEvent {

    public enum Level {
        SUCCESS, INFO, WARNING, ERROR
    }

    public enum Category {
        GENERAL, TCP, UDP, ICMP, OTHER, IPV6_SKIPPED, ERROR, MATCH
    }

    public final String message;
    public final Level level;
    public final Category category;
    public final long timestampMillis;

    public VpnEvent(String message, Level level, Category category, long timestampMillis) {
        this.message = message;
        this.level = level;
        this.category = category;
        this.timestampMillis = timestampMillis;
    }
}