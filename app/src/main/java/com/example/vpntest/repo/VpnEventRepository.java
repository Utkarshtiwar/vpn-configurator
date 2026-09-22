package com.example.vpntest.repo;

import androidx.annotation.NonNull;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.model.VpnStats;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
public final class VpnEventRepository {

    private static volatile VpnEventRepository instance;

    private final MutableLiveData<VpnEvent> latestEvent = new MutableLiveData<>();
    private final MutableLiveData<VpnStats> stats = new MutableLiveData<>(new VpnStats());


    private final AtomicReference<VpnStats> currentStats = new AtomicReference<>(new VpnStats());

    private VpnEventRepository() { }

    public static VpnEventRepository getInstance() {
        if (instance == null) {
            synchronized (VpnEventRepository.class) {
                if (instance == null) {
                    instance = new VpnEventRepository();
                }
            }
        }
        return instance;
    }

    @NonNull
    public LiveData<VpnEvent> getLatestEvent() {
        return latestEvent;
    }

    @NonNull
    public LiveData<VpnStats> getStats() {
        return stats;
    }

    public void logEvent(String message,
                         VpnEvent.Level level,
                         VpnEvent.Category category) {

        long eventTimestamp = System.currentTimeMillis();

        String formattedTimestamp =
                new SimpleDateFormat(
                        "HH:mm:ss:SSS",
                        Locale.getDefault()
                ).format(new Date(eventTimestamp));

        String timestampedMessage =
                "[" + formattedTimestamp + "] " + message;

        latestEvent.postValue(
                new VpnEvent(
                        timestampedMessage,
                        level,
                        category,
                        eventTimestamp
                )
        );

        /*
         * Save the SAME timestamped event into the log file.
         */
        com.example.vpntest.utils.VpnLogFileManager
                .getInstance()
                .log(timestampedMessage);
    }
    private void updateStats(UnaryOperator<VpnStats> transform) {
        VpnStats updated = currentStats.updateAndGet(transform);
        stats.postValue(updated);
    }
    public void logToFile(String message) {
        String timestampedMessage =
                "[" + getCurrentTimestamp() + "] " + message;
        com.example.vpntest.utils.VpnLogFileManager
                .getInstance()
                .log(timestampedMessage);
    }

    public void setVpnStatus(String status) {
        updateStats(s -> s.withVpnStatus(status));
    }

    public void setPermissionStatus(String status) {
        updateStats(s -> s.withPermissionStatus(status));
    }

    public void setInterfaceStatus(String status) {
        updateStats(s -> s.withInterfaceStatus(status));
    }

    public void setReaderStatus(String status) {
        updateStats(s -> s.withReaderStatus(status));
    }

    public void recordPacket(String protocol, String srcIp, String dstIp, int size) {
        long ts = System.currentTimeMillis();
        updateStats(s -> s.withPacket(protocol, srcIp, dstIp, size, ts));
    }

    public void recordIpv6Skipped() {
        updateStats(VpnStats::withIpv6Skipped);
    }
    public void recordTtfb(long ttfbMs) {
        updateStats(s -> s.withTtfb(ttfbMs));
    }
    public void resetTtfb() {
        updateStats(s -> s.withTtfb(-1L));
    }

    public void recordTcpHandshake(long handshakeNano) {
        updateStats(s -> s.withTcpHandshake(handshakeNano));
    }

    public void resetTcpHandshake() {
        updateStats(s -> s.withTcpHandshake(-1L));
    }

    /*
     * TCP Connection Time
     *
     * T0 = first TCP SYN packet, flags 0x02
     * T1 = first TCP ACK packet, flags 0x10
     *
     * Value is stored in nanoseconds.
     */
    public void recordTcpConnectionTime(long connectionTimeMs) {
        updateStats(s -> s.withTcpConnectionTime(connectionTimeMs));
    }

    public void resetTcpConnectionTime() {
        updateStats(s -> s.withTcpConnectionTime(-1L));
    }

    /*
     * TCP Retransmission Count
     *
     * Stores the cumulative number of detected TCP retransmissions.
     */
    public void recordTcpRetransmissionCount(long retransmissionCount) {
        updateStats(s -> s.withTcpRetransmissionCount(retransmissionCount));
    }

    public void resetTcpRetransmissionCount() {
        updateStats(s -> s.withTcpRetransmissionCount(0L));
    }

    /*
     * QUIC Handshake
     *
     * T0 = first QUIC Initial packet TX
     * T1 = first QUIC Initial packet RX
     *
     * Value is stored in milliseconds.
     */
    public void recordQuicHandshake(double handshakeMs) {
        updateStats(s -> s.withQuicHandshake(handshakeMs));
    }

    public void resetQuicHandshake() {
        updateStats(s -> s.withQuicHandshake(-1.0));
    }

    /*
     * TLS Handshake
     *
     * T0 = first TX TLS 0x16
     * T1 = first RX TLS 0x17
     *
     * Value is stored in milliseconds.
     */
    public void recordTlsHandshake(double handshakeMs) {
        updateStats(s -> s.withTlsHandshake(handshakeMs));
    }

    public void resetTlsHandshake() {
        updateStats(s -> s.withTlsHandshake(-1.0));
    }

    public void recordDnsLookup(
            double dnsLookupTimeMs,
            String dnsServerIp,
            String destinationIp) {

        updateStats(s -> s
                .withDnsLookup(
                        dnsLookupTimeMs,
                        dnsServerIp
                )
                .withDnsDestinationIp(
                        destinationIp
                )
        );
    }

    // ADD: Destination IP from [MATCH] event
    public void setDnsDestinationIp(String destinationIp) {
        updateStats(s -> {

            if (s.lastDnsDestinationIp != null
                    && !s.lastDnsDestinationIp.equals("-")
                    && !s.lastDnsDestinationIp.isEmpty()) {

                return s;
            }

            return s.withDnsDestinationIp(destinationIp);
        });
    }

    // ADD: Reset Destination IP for new VPN session
    // ADD: Reset Destination IP for new VPN session
    public void resetDnsDestinationIp() {
        updateStats(s -> s.withDnsDestinationIp("-"));
    }

    // ADD: Store hostname associated with DNS resolved IP
    public void setDnsHostName(String hostName) {
        updateStats(s -> s.withDnsHostName(hostName));
    }

    // ADD: Reset hostname for new VPN session
    public void resetDnsHostName() {
        updateStats(s -> s.withDnsHostName("-"));
    }

    public void resetDnsLookup() {
        updateStats(s -> s.withDnsLookup(
                -1.0,
                "-"
        ));
    }
    private String getCurrentTimestamp() {

        return new SimpleDateFormat(
                "HH:mm:ss:SSS",
                Locale.getDefault()
        ).format(new Date());
    }
}