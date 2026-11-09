package com.packetanalyzer.model;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

public final class Connection {

    public final FiveTuple tuple;

    public volatile ConnectionState state =
            ConnectionState.NEW;

    public volatile AppType appType =
            AppType.UNKNOWN;

    public volatile String domain = "";

    public volatile PacketAction action =
            PacketAction.FORWARD;

    public final AtomicLong packets =
            new AtomicLong();

    public final AtomicLong bytes =
            new AtomicLong();

    public final Instant firstSeen =
            Instant.now();

    public volatile Instant lastSeen =
            firstSeen;

    public Connection(FiveTuple tuple) {
        this.tuple = tuple;
    }
}