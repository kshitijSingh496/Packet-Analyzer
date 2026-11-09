package com.packetanalyzer.dpi;

import com.packetanalyzer.model.AppType;
import com.packetanalyzer.model.Connection;
import com.packetanalyzer.model.ConnectionState;
import com.packetanalyzer.model.FiveTuple;
import com.packetanalyzer.model.Packet;
import com.packetanalyzer.model.PacketAction;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

public final class ConnectionTracker {

    private final ConcurrentHashMap<FiveTuple, Connection> connections =
            new ConcurrentHashMap<>();

    public Connection get(FiveTuple tuple) {
        FiveTuple key = canonical(tuple);
        return connections.computeIfAbsent(key, Connection::new);
    }

    public Connection getEither(FiveTuple tuple) {
        return get(tuple);
    }

    public int size() {
        return connections.size();
    }

    private FiveTuple canonical(FiveTuple tuple) {
        FiveTuple reverse = tuple.reverse();
        return compare(tuple, reverse) <= 0 ? tuple : reverse;
    }

    private int compare(FiveTuple left, FiveTuple right) {
        int result = left.srcIp().compareTo(right.srcIp());
        if (result != 0) {
            return result;
        }

        result = left.dstIp().compareTo(right.dstIp());
        if (result != 0) {
            return result;
        }

        result = Integer.compare(left.srcPort(), right.srcPort());
        if (result != 0) {
            return result;
        }

        result = Integer.compare(left.dstPort(), right.dstPort());
        if (result != 0) {
            return result;
        }

        return Integer.compare(left.protocol(), right.protocol());
    }

    public void update(
            Connection connection,
            Packet packet,
            AppType application,
            String domain,
            PacketAction action
    ) {
        connection.packets.incrementAndGet();
        connection.bytes.addAndGet(packet.data().length);
        connection.lastSeen = Instant.now();

        if (application != AppType.UNKNOWN) {
            connection.appType = application;
        }

        if (!domain.isBlank()) {
            connection.domain = domain;
        }

        connection.action = action;
        connection.state = action == PacketAction.DROP
                ? ConnectionState.BLOCKED
                : ConnectionState.CLASSIFIED;
    }
}
