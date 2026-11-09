package com.packetanalyzer.parser;

import com.packetanalyzer.model.FiveTuple;

public record ParsedPacket(
        boolean valid,
        int linkType,
        String srcMac,
        String dstMac,
        String srcIp,
        String dstIp,
        int protocol,
        int srcPort,
        int dstPort,
        int ipOffset,
        int transportOffset,
        int payloadOffset,
        int payloadLength,
        int tcpFlags,
        FiveTuple tuple,
        byte[] payload
) {
}