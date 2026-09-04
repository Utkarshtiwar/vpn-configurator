package com.example.vpntest.utils;

public final class TestSessionManager {

    public enum TestType {
        NONE,
        WEB,
        APP_OPEN
    }

    private static TestType activeTest = TestType.NONE;

    private TestSessionManager() {
    }

    public static synchronized boolean isRunning() {
        return activeTest != TestType.NONE;
    }

    public static synchronized TestType getActiveTest() {
        return activeTest;
    }

    public static synchronized boolean startTest(TestType testType) {
        if (activeTest != TestType.NONE) {
            return false;
        }

        activeTest = testType;
        return true;
    }

    public static synchronized void stopTest() {
        activeTest = TestType.NONE;
    }
}