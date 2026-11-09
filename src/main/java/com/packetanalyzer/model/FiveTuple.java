package com.packetanalyzer.model;

import java.util.Objects;

public record FiveTuple(
        String srcIp,
        String dstIp,
        int srcPort,
        int dstPort,
        int protocol
) {

    public FiveTuple reverse() {

        return new FiveTuple(
                dstIp,
                srcIp,
                dstPort,
                srcPort,
                protocol
        );
    }

    @Override
    public String toString() {

        return srcIp
                + ":"
                + srcPort
                + " -> "
                + dstIp
                + ":"
                + dstPort
                + "/"
                + protocol;
    }

    @Override
    public boolean equals(Object object) {

        return object instanceof FiveTuple tuple
                && srcPort == tuple.srcPort
                && dstPort == tuple.dstPort
                && protocol == tuple.protocol
                && Objects.equals(
                        srcIp,
                        tuple.srcIp
                )
                && Objects.equals(
                        dstIp,
                        tuple.dstIp
                );
    }

    @Override
    public int hashCode() {

        return Objects.hash(
                srcIp,
                dstIp,
                srcPort,
                dstPort,
                protocol
        );
    }
}