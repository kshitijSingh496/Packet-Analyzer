package com.packetanalyzer.model;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;

public final class Stats {

    public final LongAdder totalPackets =
            new LongAdder();

    public final LongAdder totalBytes =
            new LongAdder();

    public final LongAdder forwarded =
            new LongAdder();

    public final LongAdder dropped =
            new LongAdder();

    public final LongAdder tcp =
            new LongAdder();

    public final LongAdder udp =
            new LongAdder();

    public final LongAdder other =
            new LongAdder();

    public final ConcurrentHashMap<AppType, LongAdder>
            applications =
            new ConcurrentHashMap<>();

    public void app(AppType application) {

        applications
                .computeIfAbsent(
                        application,
                        key -> new LongAdder()
                )
                .increment();
    }
}