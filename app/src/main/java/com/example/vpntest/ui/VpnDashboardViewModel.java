package com.example.vpntest.ui;

import androidx.lifecycle.LiveData;
import androidx.lifecycle.ViewModel;

import com.example.vpntest.model.VpnEvent;
import com.example.vpntest.model.VpnStats;
import com.example.vpntest.repo.VpnEventRepository;


public class VpnDashboardViewModel extends ViewModel {

    private final VpnEventRepository repository = VpnEventRepository.getInstance();

    public LiveData<VpnEvent> getLatestEvent() {
        return repository.getLatestEvent();
    }

    public LiveData<VpnStats> getStats() {
        return repository.getStats();
    }
}