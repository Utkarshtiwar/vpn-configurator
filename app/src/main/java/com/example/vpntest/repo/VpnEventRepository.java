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

    private final MutableLiveData<VpnEvent> latestEvent =
            new MutableLiveData<>();

    private final MutableLiveData<VpnStats> stats =
            new MutableLiveData<>(new VpnStats());

    private final AtomicReference<VpnStats> currentStats =
            new AtomicReference<>(new VpnStats());

    private VpnEventRepository() {
    }

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

    public void logEvent(
            String message,
            VpnEvent.Level level,
            VpnEvent.Category category
    ) {

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

    public void recordPacket(
            String protocol,
            String srcIp,
            String dstIp,
            int size
    ) {
        long ts = System.currentTimeMillis();

        updateStats(s ->
                s.withPacket(
                        protocol,
                        srcIp,
                        dstIp,
                        size,
                        ts
                )
        );
    }

    public void recordIpv6Skipped() {
        updateStats(VpnStats::withIpv6Skipped);
    }

    // ============================================================
    // VPN TTFB
    //
    // ttfbMs       = calculated duration
    // t0WallTime   = exact T0 wall-clock timestamp
    // t1WallTime   = exact T1 wall-clock timestamp
    //
    // Duration calculation must happen outside this repository
    // using monotonic time.
    // ============================================================

    public void recordTtfb(long ttfbMs) {
        updateStats(s -> s.withTtfb(ttfbMs));
    }

    public void recordTtfb(
            long ttfbMs,
            long t0WallTime,
            long t1WallTime
    ) {
        updateStats(s ->
                s.withTtfb(ttfbMs)
                        .withTtfbWallTimes(
                                t0WallTime,
                                t1WallTime
                        )
        );
    }

    public void resetTtfb() {
        updateStats(s ->
                s.withTtfb(-1L)
                        .withTtfbWallTimes(
                                -1L,
                                -1L
                        )
        );
    }

    // ============================================================
    // WEB TEST TTFB
    //
    // Separate from VPN TTFB.
    // Stores exact wall-clock T0/T1 received from WebViewHelper.
    // ============================================================

    public void recordWebTtfb(
            long ttfbMs,
            long t0WallTime,
            long t1WallTime
    ) {
        updateStats(s ->
                s.withWebTtfbWallTimes(
                        t0WallTime,
                        t1WallTime
                )
        );
    }

    public void resetWebTtfb() {
        updateStats(s ->
                s.withWebTtfbWallTimes(
                        -1L,
                        -1L
                )
        );
    }

    // ============================================================
    // TCP HANDSHAKE
    //
    // handshakeNano = T1 monotonic - T0 monotonic
    // t0WallTime    = exact SYN wall-clock timestamp
    // t1WallTime    = exact ACK wall-clock timestamp
    // ============================================================

    public void recordTcpHandshake(long handshakeNano) {
        updateStats(s -> s.withTcpHandshake(handshakeNano));
    }

    public void recordTcpHandshake(
            long handshakeNano,
            long t0WallTime,
            long t1WallTime
    ) {
        updateStats(s ->
                s.withTcpHandshake(handshakeNano)
                        .withTcpHandshakeWallTimes(
                                t0WallTime,
                                t1WallTime
                        )
        );
    }

    public void resetTcpHandshake() {
        updateStats(s ->
                s.withTcpHandshake(-1L)
                        .withTcpHandshakeWallTimes(
                                -1L,
                                -1L
                        )
        );
    }

    // ============================================================
    // TCP CONNECTION TIME
    //
    // T0 = first TCP SYN packet, flags 0x02
    // T1 = first TCP ACK packet, flags 0x10
    //
    // Existing metric retained.
    // ============================================================



    public void resetTcpConnectionTime() {
        updateStats(s ->
                s.withTcpConnectionTime(-1L)
                        .withTcpConnectionWallTimes(
                                -1L,
                                -1L
                        )
        );
    }

    // ============================================================
    // TCP RETRANSMISSION COUNT
    // ============================================================

    public void recordTcpRetransmissionCount(
            long retransmissionCount
    ) {
        updateStats(s ->
                s.withTcpRetransmissionCount(
                        retransmissionCount
                )
        );
    }

    public void resetTcpRetransmissionCount() {
        updateStats(s ->
                s.withTcpRetransmissionCount(0L)
        );
    }

    // ============================================================
    // QUIC HANDSHAKE
    //
    // Existing metric retained.
    // ============================================================

    public void recordQuicHandshake(double handshakeMs) {
        updateStats(s ->
                s.withQuicHandshake(handshakeMs)
        );
    }

    public void resetQuicHandshake() {
        updateStats(s ->
                s.withQuicHandshake(-1.0)
        );
    }

    // ============================================================
    // TLS HANDSHAKE
    //
    // handshakeMs    = calculated monotonic duration
    // t0WallTime     = exact TLS 0x16 timestamp
    // t1WallTime     = exact TLS 0x17 timestamp
    // ============================================================

    public void recordTlsHandshake(double handshakeMs) {
        updateStats(s ->
                s.withTlsHandshake(handshakeMs)
        );
    }

    public void recordTlsHandshake(
            double handshakeMs,
            long t0WallTime,
            long t1WallTime
    ) {
        updateStats(s ->
                s.withTlsHandshake(handshakeMs)
                        .withTlsHandshakeWallTimes(
                                t0WallTime,
                                t1WallTime
                        )
        );
    }

    public void resetTlsHandshake() {
        updateStats(s ->
                s.withTlsHandshake(-1.0)
                        .withTlsHandshakeWallTimes(
                                -1L,
                                -1L
                        )
        );
    }

    // ============================================================
    // DNS RESOLUTION
    //
    // dnsLookupTimeMs = calculated monotonic duration
    // t0WallTime      = exact DNS query timestamp
    // t1WallTime      = exact matching DNS response timestamp
    //
    // The caller is responsible for making sure T0/T1 belong
    // to the SAME DNS transaction.
    // ============================================================

    public void recordDnsLookup(
            double dnsLookupTimeMs,
            String dnsServerIp,
            String destinationIp
    ) {

        updateStats(s ->
                s.withDnsLookup(
                                dnsLookupTimeMs,
                                dnsServerIp
                        )
                        .withDnsDestinationIp(
                                destinationIp
                        )
        );
    }

    public void recordDnsLookup(
            double dnsLookupTimeMs,
            String dnsServerIp,
            String destinationIp,
            long t0WallTime,
            long t1WallTime
    ) {

        updateStats(s ->
                s.withDnsLookup(
                                dnsLookupTimeMs,
                                dnsServerIp
                        )
                        .withDnsDestinationIp(
                                destinationIp
                        )
                        .withDnsResolutionWallTimes(
                                t0WallTime,
                                t1WallTime
                        )
        );
    }

    // ============================================================
    // DNS DESTINATION IP
    // ============================================================

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

    public void resetDnsDestinationIp() {
        updateStats(s ->
                s.withDnsDestinationIp("-")
        );
    }

    // ============================================================
    // DNS HOSTNAME
    // ============================================================

    public void setDnsHostName(String hostName) {
        updateStats(s ->
                s.withDnsHostName(hostName)
        );
    }

    public void resetDnsHostName() {
        updateStats(s ->
                s.withDnsHostName("-")
        );
    }

    // ============================================================
    // RESET DNS
    // ============================================================

    public void resetDnsLookup() {
        updateStats(s ->
                s.withDnsLookup(
                                -1.0,
                                "-"
                        )
                        .withDnsResolutionWallTimes(
                                -1L,
                                -1L
                        )
        );
    }

    // ============================================================
    // RESET ALL STATS
    // ============================================================

    public void resetAllStats() {
        VpnStats freshStats = new VpnStats();

        currentStats.set(freshStats);
        stats.postValue(freshStats);
    }

    // ============================================================
    // LOG TIMESTAMP
    // ============================================================

    private String getCurrentTimestamp() {

        return new SimpleDateFormat(
                "HH:mm:ss:SSS",
                Locale.getDefault()
        ).format(new Date());
    }
    // ============================================================
    // APP OPEN TTFB
    // ============================================================

    public void recordAppOpenTtfb(
            long ttfbMs,
            long t0WallTime,
            long t1WallTime
    ) {
        updateStats(s ->
                s.withAppOpenTtfb(
                        ttfbMs,
                        t0WallTime,
                        t1WallTime
                )
        );
    }

    public void resetAppOpenTtfb() {
        updateStats(s ->
                s.withAppOpenTtfb(
                        -1L,
                        -1L,
                        -1L
                )
        );
    }
    // ============================================================
    // APP OPEN TIME
    // Separate from APP OPEN TTFB
    // ============================================================

    public void recordAppOpenTime(
            long appOpenTimeMs,
            long t0WallTime,
            long t1WallTime
    ) {
        updateStats(s ->
                s.withAppOpenTime(
                        appOpenTimeMs,
                        t0WallTime,
                        t1WallTime
                )
        );
    }

    public void resetAppOpenTime() {
        updateStats(s ->
                s.withAppOpenTime(
                        -1L,
                        -1L,
                        -1L
                )
        );
    }

    // ============================================================
    // APP OPEN TCP HANDSHAKE
    // ============================================================

    public void recordAppOpenTcpHandshake(
            long handshakeNano,
            long t0WallTime,
            long t1WallTime
    ) {
        updateStats(s ->
                s.withAppOpenTcpHandshake(
                        handshakeNano,
                        t0WallTime,
                        t1WallTime
                )
        );
    }

    public void resetAppOpenTcpHandshake() {
        updateStats(s ->
                s.withAppOpenTcpHandshake(
                        -1L,
                        -1L,
                        -1L
                )
        );
    }

    // ============================================================
    // APP OPEN TLS HANDSHAKE
    // ============================================================

    public void recordAppOpenTlsHandshake(
            double handshakeMs,
            long t0WallTime,
            long t1WallTime
    ) {
        updateStats(s ->
                s.withAppOpenTlsHandshake(
                        handshakeMs,
                        t0WallTime,
                        t1WallTime
                )
        );
    }

    public void resetAppOpenTlsHandshake() {
        updateStats(s ->
                s.withAppOpenTlsHandshake(
                        -1.0,
                        -1L,
                        -1L
                )
        );
    }

    // ============================================================
    // APP OPEN DNS LOOKUP
    // ============================================================

    public void recordAppOpenDnsLookup(
            double lookupMs,
            long t0WallTime,
            long t1WallTime,
            String serverIp,
            String destinationIp
    ) {
        updateStats(s ->
                s.withAppOpenDnsLookup(
                        lookupMs,
                        t0WallTime,
                        t1WallTime,
                        serverIp,
                        destinationIp
                )
        );
    }


}
