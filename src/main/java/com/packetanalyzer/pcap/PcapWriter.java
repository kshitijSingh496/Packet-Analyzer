package com.packetanalyzer.pcap;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class PcapWriter implements Closeable {

    private final DataOutputStream output;

    private final ByteOrder byteOrder =
            ByteOrder.LITTLE_ENDIAN;

    public PcapWriter(
            String path,
            int network
    ) throws IOException {

        output =
                new DataOutputStream(
                        new BufferedOutputStream(
                                new FileOutputStream(path)
                        )
                );

        writeInt(0xa1b2c3d4);
        writeShort(2);
        writeShort(4);
        writeInt(0);
        writeInt(0);
        writeInt(65_535);
        writeInt(network);
    }

    private void writeInt(long value)
            throws IOException {

        byte[] bytes =
                ByteBuffer
                        .allocate(4)
                        .order(byteOrder)
                        .putInt((int) value)
                        .array();

        output.write(bytes);
    }

    private void writeShort(int value)
            throws IOException {

        byte[] bytes =
                ByteBuffer
                        .allocate(2)
                        .order(byteOrder)
                        .putShort((short) value)
                        .array();

        output.write(bytes);
    }

    public synchronized void write(
            PcapPacket packet
    ) throws IOException {

        writeInt(packet.tsSec());
        writeInt(packet.tsUsec());
        writeInt(packet.data().length);
        writeInt(packet.originalLength());

        output.write(packet.data());
    }

    @Override
    public void close()
            throws IOException {

        output.flush();
        output.close();
    }
}