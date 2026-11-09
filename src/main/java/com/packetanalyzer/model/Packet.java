package com.packetanalyzer.model;

import java.util.Arrays;

public record Packet(
        long id,
        long tsSec,
        long tsUsec,
        byte[] data,
        FiveTuple tuple,
        int ipOffset,
        int transportOffset,
        int payloadOffset,
        int payloadLength,
        int tcpFlags,
        int protocol,
        String srcIp,
        String dstIp,
        int srcPort,
        int dstPort
) {

    public byte[] payload() {

        return Arrays.copyOfRange(
                data,
                payloadOffset,
                payloadOffset + payloadLength
        );
    }
}