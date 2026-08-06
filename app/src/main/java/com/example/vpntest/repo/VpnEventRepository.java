package com.example.vpntest.repo;

import androidx.annotation.NonNull;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.model.VpnStats;

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

        latestEvent.postValue(
                new VpnEvent(
                        message,
                        level,
                        category,
                        System.currentTimeMillis()));

        // Save every UI log into the session log file.
        com.example.vpntest.utils.VpnLogFileManager
                .getInstance()
                .log(message);
    }
    private void updateStats(UnaryOperator<VpnStats> transform) {
        VpnStats updated = currentStats.updateAndGet(transform);
        stats.postValue(updated);
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
}