package com.example.vpntest.repo;

import androidx.annotation.NonNull;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.model.VpnStats;

public final class VpnEventRepository {

    private static volatile VpnEventRepository instance;

    private final MutableLiveData<VpnEvent> latestEvent = new MutableLiveData<>();
    private final MutableLiveData<VpnStats> stats = new MutableLiveData<>(new VpnStats());

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



    public void logEvent(String message, VpnEvent.Level level, VpnEvent.Category category) {
        latestEvent.postValue(new VpnEvent(message, level, category, System.currentTimeMillis()));
    }



    public void setVpnStatus(String status) {
        VpnStats current = stats.getValue();
        stats.postValue((current != null ? current : new VpnStats()).withVpnStatus(status));
    }

    public void setPermissionStatus(String status) {
        VpnStats current = stats.getValue();
        stats.postValue((current != null ? current : new VpnStats()).withPermissionStatus(status));
    }

    public void setInterfaceStatus(String status) {
        VpnStats current = stats.getValue();
        stats.postValue((current != null ? current : new VpnStats()).withInterfaceStatus(status));
    }

    public void setReaderStatus(String status) {
        VpnStats current = stats.getValue();
        stats.postValue((current != null ? current : new VpnStats()).withReaderStatus(status));
    }

    public void recordPacket(String protocol, String srcIp, String dstIp, int size) {
        VpnStats current = stats.getValue();
        stats.postValue((current != null ? current : new VpnStats())
                .withPacket(protocol, srcIp, dstIp, size, System.currentTimeMillis()));
    }

    public void recordIpv6Skipped() {
        VpnStats current = stats.getValue();
        stats.postValue((current != null ? current : new VpnStats()).withIpv6Skipped());
    }
}