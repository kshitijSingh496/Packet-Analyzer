package com.packetanalyzer.pcap;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class PcapReader implements Closeable {

    private final DataInputStream input;
    private final ByteOrder byteOrder;
    private final boolean nano;

    public final int network;

    public PcapReader(String path) throws IOException {
        input = new DataInputStream(
                new BufferedInputStream(new FileInputStream(path))
        );

        byte[] header = input.readNBytes(24);

        if (header.length < 24) {
            throw new EOFException("Incomplete PCAP global header");
        }

        int magic = ByteBuffer
                .wrap(header, 0, 4)
                .order(ByteOrder.BIG_ENDIAN)
                .getInt();

        if (magic == 0xa1b2c3d4) {
            byteOrder = ByteOrder.BIG_ENDIAN;
            nano = false;
        } else if (magic == 0xd4c3b2a1) {
            byteOrder = ByteOrder.LITTLE_ENDIAN;
            nano = false;
        } else if (magic == 0xa1b23c4d) {
            byteOrder = ByteOrder.BIG_ENDIAN;
            nano = true;
        } else if (magic == 0x4d3cb2a1) {
            byteOrder = ByteOrder.LITTLE_ENDIAN;
            nano = true;
        } else {
            throw new IOException("Unsupported PCAP magic number");
        }

        network = readInt(header, 20);
    }

    private int readInt(byte[] bytes, int offset) {
        return ByteBuffer
                .wrap(bytes, offset, 4)
                .order(byteOrder)
                .getInt();
    }

    private long readUnsignedInt(byte[] bytes, int offset) {
        return Integer.toUnsignedLong(readInt(bytes, offset));
    }

    public PcapPacket next() throws IOException {
        byte[] header = input.readNBytes(16);

        if (header.length == 0) {
            return null;
        }

        if (header.length < 16) {
            throw new EOFException("Truncated packet header");
        }

        long timestampSeconds = readUnsignedInt(header, 0);
        long timestampFraction = readUnsignedInt(header, 4);

        long timestampMicroseconds = nano
                ? timestampFraction / 1_000
                : timestampFraction;

        long capturedLengthUnsigned = readUnsignedInt(header, 8);
        long originalLengthUnsigned = readUnsignedInt(header, 12);

        if (capturedLengthUnsigned > 64L * 1024 * 1024) {
            throw new IOException(
                    "Invalid captured length: " + capturedLengthUnsigned
            );
        }

        if (originalLengthUnsigned > Integer.MAX_VALUE) {
            throw new IOException(
                    "Invalid original length: " + originalLengthUnsigned
            );
        }

        int capturedLength = (int) capturedLengthUnsigned;
        int originalLength = (int) originalLengthUnsigned;

        byte[] data = input.readNBytes(capturedLength);

        if (data.length < capturedLength) {
            throw new EOFException("Truncated packet data");
        }

        return new PcapPacket(
                timestampSeconds,
                timestampMicroseconds,
                originalLength,
                data
        );
    }

    @Override
    public void close() throws IOException {
        input.close();
    }
}
