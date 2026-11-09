package com.packetanalyzer.parser;

import com.packetanalyzer.model.FiveTuple;

import java.util.Arrays;

public final class PacketParser {

    public ParsedPacket parse(
            byte[] data,
            int linkType
    ) {

        try {

            int offset = 0;

            String sourceMac = "";
            String destinationMac = "";

            if (linkType == 1) {

                if (data.length < 14) {
                    return invalid();
                }

                destinationMac =
                        mac(data, 0);

                sourceMac =
                        mac(data, 6);

                int etherType =
                        ushort(data, 12);

                offset = 14;

                if (etherType == 0x8100) {

                    if (data.length < 18) {
                        return invalid();
                    }

                    etherType =
                            ushort(data, 16);

                    offset = 18;
                }

                if (etherType != 0x0800) {
                    return invalid();
                }

            } else if (linkType != 101) {

                return invalid();
            }

            if (data.length < offset + 20) {
                return invalid();
            }

            int version =
                    (data[offset] >>> 4) & 15;

            int headerLength =
                    (data[offset] & 15) * 4;

            if (version != 4
                    || headerLength < 20
                    || data.length < offset + headerLength) {

                return invalid();
            }

            int totalLength =
                    ushort(data, offset + 2);

            if (totalLength < headerLength) {
                return invalid();
            }

            int protocol =
                    data[offset + 9] & 255;

            String sourceIp =
                    ip(data, offset + 12);

            String destinationIp =
                    ip(data, offset + 16);

            int transportOffset =
                    offset + headerLength;

            int sourcePort = 0;
            int destinationPort = 0;

            int payloadOffset =
                    transportOffset;

            int tcpFlags = 0;

            if (protocol == 6) {

                if (data.length < transportOffset + 20) {
                    return invalid();
                }

                sourcePort =
                        ushort(data, transportOffset);

                destinationPort =
                        ushort(data, transportOffset + 2);

                int tcpHeaderLength =
                        ((data[transportOffset + 12] >>> 4)
                                & 15) * 4;

                if (tcpHeaderLength < 20
                        || data.length
                        < transportOffset + tcpHeaderLength) {

                    return invalid();
                }

                tcpFlags =
                        data[transportOffset + 13] & 255;

                payloadOffset =
                        transportOffset
                                + tcpHeaderLength;

            } else if (protocol == 17) {

                if (data.length < transportOffset + 8) {
                    return invalid();
                }

                sourcePort =
                        ushort(data, transportOffset);

                destinationPort =
                        ushort(
                                data,
                                transportOffset + 2
                        );

                payloadOffset =
                        transportOffset + 8;
            }

            int end =
                    Math.min(
                            data.length,
                            offset + totalLength
                    );

            if (payloadOffset > end) {
                payloadOffset = end;
            }

            int payloadLength =
                    Math.max(
                            0,
                            end - payloadOffset
                    );

            byte[] payload =
                    Arrays.copyOfRange(
                            data,
                            payloadOffset,
                            payloadOffset + payloadLength
                    );

            FiveTuple tuple =
                    new FiveTuple(
                            sourceIp,
                            destinationIp,
                            sourcePort,
                            destinationPort,
                            protocol
                    );

            return new ParsedPacket(
                    true,
                    linkType,
                    sourceMac,
                    destinationMac,
                    sourceIp,
                    destinationIp,
                    protocol,
                    sourcePort,
                    destinationPort,
                    offset,
                    transportOffset,
                    payloadOffset,
                    payloadLength,
                    tcpFlags,
                    tuple,
                    payload
            );

        } catch (Exception e) {

            return invalid();
        }
    }

    private ParsedPacket invalid() {

        return new ParsedPacket(
                false,
                0,
                "",
                "",
                "",
                "",
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                null,
                new byte[0]
        );
    }

    private static int ushort(
            byte[] bytes,
            int offset
    ) {

        return ((bytes[offset] & 255) << 8)
                | (bytes[offset + 1] & 255);
    }

    private static String ip(
            byte[] bytes,
            int offset
    ) {

        return (bytes[offset] & 255)
                + "."
                + (bytes[offset + 1] & 255)
                + "."
                + (bytes[offset + 2] & 255)
                + "."
                + (bytes[offset + 3] & 255);
    }

    private static String mac(
            byte[] bytes,
            int offset
    ) {

        return String.format(
                "%02x:%02x:%02x:%02x:%02x:%02x",
                bytes[offset] & 255,
                bytes[offset + 1] & 255,
                bytes[offset + 2] & 255,
                bytes[offset + 3] & 255,
                bytes[offset + 4] & 255,
                bytes[offset + 5] & 255
        );
    }
}