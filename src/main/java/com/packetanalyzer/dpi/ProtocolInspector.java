package com.packetanalyzer.dpi;

import com.packetanalyzer.model.AppType;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ProtocolInspector {

    private static final Pattern HOST =
            Pattern.compile(
                    "(?i)(?:Host:|host)\\s*:\\s*([^\\r\\n:]+)"
            );

    public static String httpHost(byte[] payload) {

        String text =
                new String(
                        payload,
                        StandardCharsets.ISO_8859_1
                );

        Matcher matcher =
                HOST.matcher(text);

        return matcher.find()
                ? matcher.group(1).trim()
                : "";
    }

    public static String tlsSni(byte[] payload) {

        try {

            if (payload.length < 5
                    || (payload[0] & 255) != 22) {

                return "";
            }

            int handshakeStart = 5;

            if (payload.length < handshakeStart + 4
                    || (payload[5] & 255) != 1) {

                return "";
            }

            int end = Math.min(
                    payload.length,
                    handshakeStart
                            + 4
                            + u24(payload, handshakeStart + 1)
            );

            int offset =
                    handshakeStart
                            + 4
                            + 2
                            + 32;

            if (offset + 1 > end) {
                return "";
            }

            int sessionIdLength =
                    payload[offset] & 255;

            offset += 1 + sessionIdLength;

            if (offset + 2 > end) {
                return "";
            }

            int cipherSuiteLength =
                    u16(payload, offset);

            offset += 2 + cipherSuiteLength;

            if (offset + 1 > end) {
                return "";
            }

            int compressionMethodsLength =
                    payload[offset] & 255;

            offset += 1 + compressionMethodsLength;

            if (offset + 2 > end) {
                return "";
            }

            int extensionsLength =
                    u16(payload, offset);

            offset += 2;

            int extensionsEnd =
                    Math.min(
                            end,
                            offset + extensionsLength
                    );

            while (offset + 4 <= extensionsEnd) {

                int type = u16(payload, offset);
                int length = u16(payload, offset + 2);

                offset += 4;

                if (offset + length > extensionsEnd) {
                    return "";
                }

                if (type == 0) {

                    if (length < 5) {
                        return "";
                    }

                    int serverNameListLength =
                            u16(payload, offset);

                    int current =
                            offset + 2;

                    int listEnd =
                            Math.min(
                                    offset + 2
                                            + serverNameListLength,
                                    offset + length
                            );

                    while (current + 3 <= listEnd) {

                        int nameType =
                                payload[current] & 255;

                        int nameLength =
                                u16(payload, current + 1);

                        current += 3;

                        if (current + nameLength > listEnd) {
                            return "";
                        }

                        if (nameType == 0) {

                            return new String(
                                    payload,
                                    current,
                                    nameLength,
                                    StandardCharsets.US_ASCII
                            );
                        }

                        current += nameLength;
                    }
                }

                offset += length;
            }

            return "";

        } catch (Exception e) {
            return "";
        }
    }

    private static int u16(byte[] bytes, int offset) {
        return ((bytes[offset] & 255) << 8)
                | (bytes[offset + 1] & 255);
    }

    private static int u24(byte[] bytes, int offset) {
        return ((bytes[offset] & 255) << 16)
                | ((bytes[offset + 1] & 255) << 8)
                | (bytes[offset + 2] & 255);
    }

    public static AppType classify(
            int protocol,
            int sourcePort,
            int destinationPort,
            String domain
    ) {

        if (protocol == 17
                && (sourcePort == 53
                || destinationPort == 53)) {

            return AppType.DNS;
        }

        if (protocol == 17
                && (sourcePort == 443
                || destinationPort == 443)) {

            return AppType.QUIC;
        }

        if (protocol == 6
                && (sourcePort == 80
                || destinationPort == 80)) {

            return AppType.HTTP;
        }

        if (protocol == 6
                && (sourcePort == 443
                || destinationPort == 443)) {

            if (!domain.isBlank()) {
                return AppType.fromDomain(domain);
            }

            return AppType.TLS;
        }

        return domain.isBlank()
                ? AppType.UNKNOWN
                : AppType.fromDomain(domain);
    }
}