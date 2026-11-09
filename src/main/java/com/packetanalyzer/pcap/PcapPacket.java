package com.packetanalyzer.pcap;

public record PcapPacket(
        long tsSec,
        long tsUsec,
        int originalLength,
        byte[] data
) {
}