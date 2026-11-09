package com.packetanalyzer;

import com.packetanalyzer.parser.PacketParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;

class PacketParserSelfTest {

    @Test
    void rejectsTruncatedEthernetFrame() {

        PacketParser parser =
                new PacketParser();

        var result =
                parser.parse(
                        new byte[10],
                        1
                );

        assertFalse(
                result.valid(),
                "Short/truncated Ethernet frame should be rejected"
        );
    }
}