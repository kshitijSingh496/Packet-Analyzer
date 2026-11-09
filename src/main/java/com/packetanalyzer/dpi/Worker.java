package com.packetanalyzer.dpi;

import com.packetanalyzer.model.AppType;
import com.packetanalyzer.model.Connection;
import com.packetanalyzer.model.Packet;
import com.packetanalyzer.model.PacketAction;
import com.packetanalyzer.model.Stats;
import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.parser.ParsedPacket;
import com.packetanalyzer.pcap.PcapPacket;
import com.packetanalyzer.rule.RuleManager;

import java.util.concurrent.BlockingQueue;

public final class Worker implements Runnable {

    private final BlockingQueue<Job> queue;
    private final BlockingQueue<Result> outputQueue;
    private final PacketParser parser;
    private final RuleManager rules;
    private final ConnectionTracker tracker;
    private final Stats stats;
    private final int linkType;

    public Worker(
            BlockingQueue<Job> queue,
            BlockingQueue<Result> outputQueue,
            PacketParser parser,
            RuleManager rules,
            ConnectionTracker tracker,
            Stats stats,
            int linkType
    ) {
        this.queue = queue;
        this.outputQueue = outputQueue;
        this.parser = parser;
        this.rules = rules;
        this.tracker = tracker;
        this.stats = stats;
        this.linkType = linkType;
    }

    @Override
    public void run() {
        try {
            while (true) {
                Job job = queue.take();

                if (job.poison()) {
                    return;
                }

                process(job);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void process(Job job) throws InterruptedException {
        try {
            ParsedPacket parsed = parser.parse(job.p().data(), linkType);

            stats.totalPackets.increment();
            stats.totalBytes.add(job.p().data().length);

            if (!parsed.valid()) {
                stats.other.increment();
                stats.dropped.increment();
                outputQueue.put(new Result(job.id(), job.p(), PacketAction.DROP));
                return;
            }

            if (parsed.protocol() == 6) {
                stats.tcp.increment();
            } else if (parsed.protocol() == 17) {
                stats.udp.increment();
            } else {
                stats.other.increment();
            }

            String domain = "";

            if (parsed.protocol() == 6) {
                domain = ProtocolInspector.httpHost(parsed.payload());

                if (domain.isBlank()) {
                    domain = ProtocolInspector.tlsSni(parsed.payload());
                }
            }

            AppType application = ProtocolInspector.classify(
                    parsed.protocol(),
                    parsed.srcPort(),
                    parsed.dstPort(),
                    domain
            );

            Packet packet = new Packet(
                    job.id(),
                    job.p().tsSec(),
                    job.p().tsUsec(),
                    job.p().data(),
                    parsed.tuple(),
                    parsed.ipOffset(),
                    parsed.transportOffset(),
                    parsed.payloadOffset(),
                    parsed.payloadLength(),
                    parsed.tcpFlags(),
                    parsed.protocol(),
                    parsed.srcIp(),
                    parsed.dstIp(),
                    parsed.srcPort(),
                    parsed.dstPort()
            );

            PacketAction action = rules.action(packet, domain, application);

            Connection connection = tracker.get(parsed.tuple());
            tracker.update(connection, packet, application, domain, action);

            stats.app(application);

            if (action == PacketAction.DROP) {
                stats.dropped.increment();
            } else {
                stats.forwarded.increment();
            }

            outputQueue.put(new Result(job.id(), job.p(), action));
        } catch (RuntimeException e) {
            stats.other.increment();
            stats.dropped.increment();
            outputQueue.put(new Result(job.id(), job.p(), PacketAction.DROP));
        }
    }

    public record Job(long id, PcapPacket p, boolean poison) {

        static Job data(long id, PcapPacket packet) {
            return new Job(id, packet, false);
        }

        static Job stop() {
            return new Job(-1, null, true);
        }
    }

    public record Result(long id, PcapPacket p, PacketAction action) {
    }
}
