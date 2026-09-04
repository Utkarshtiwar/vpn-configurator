package com.example.vpntest.appOpen;

public class AppInfo {

    public final String appName;
    public final String packageName;

    public AppInfo(
            String appName,
            String packageName
    ) {
        this.appName = appName;
        this.packageName = packageName;
    }

    @Override
    public String toString() {
        return appName;
    }
}