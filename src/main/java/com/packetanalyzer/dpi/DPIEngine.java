package com.packetanalyzer.dpi;

import com.packetanalyzer.model.PacketAction;
import com.packetanalyzer.model.Stats;
import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.pcap.PcapPacket;
import com.packetanalyzer.pcap.PcapReader;
import com.packetanalyzer.pcap.PcapWriter;
import com.packetanalyzer.rule.RuleManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicReference;

public final class DPIEngine {

    public record Config(
            int workers,
            int queueSize,
            boolean verbose
    ) {
        public Config {
            if (workers < 1) {
                workers = Runtime.getRuntime().availableProcessors();
            }

            if (queueSize < 100) {
                queueSize = 100;
            }
        }
    }

    private final Config cfg;
    private final RuleManager rules = new RuleManager();
    private final ConnectionTracker tracker = new ConnectionTracker();
    private final Stats stats = new Stats();
    private final PacketParser parser = new PacketParser();

    public DPIEngine(Config config) {
        this.cfg = config;
    }

    public RuleManager rules() {
        return rules;
    }

    public Stats stats() {
        return stats;
    }

    public int connections() {
        return tracker.size();
    }

    public void process(String input, String output) throws Exception {
        BlockingQueue<Worker.Job> queue =
                new ArrayBlockingQueue<>(cfg.queueSize());

        BlockingQueue<Worker.Result> outputQueue =
                new ArrayBlockingQueue<>(cfg.queueSize());

        AtomicReference<Throwable> writerFailure =
                new AtomicReference<>();

        List<Thread> workers = new ArrayList<>();
        PcapReader reader = new PcapReader(input);
        int linkType = reader.network;

        try {
            for (int i = 0; i < cfg.workers(); i++) {
                Thread thread = new Thread(
                        new Worker(
                                queue,
                                outputQueue,
                                parser,
                                rules,
                                tracker,
                                stats,
                                linkType
                        ),
                        "DPI-Worker-" + i
                );

                workers.add(thread);
                thread.start();
            }

            Thread writer = new Thread(
                    () -> writeOutput(
                            output,
                            linkType,
                            outputQueue,
                            writerFailure,
                            workers
                    ),
                    "PCAP-Writer"
            );

            writer.start();

            long id = 0;
            PcapPacket packet;

            while ((packet = reader.next()) != null) {
                Worker.Job job = Worker.Job.data(++id, packet);

                while (!queue.offer(job, 100, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                    checkFailure(writerFailure);
                }

                checkFailure(writerFailure);
            }

            for (int i = 0; i < cfg.workers(); i++) {
                queue.put(Worker.Job.stop());
            }

            for (Thread thread : workers) {
                thread.join();
            }

            checkFailure(writerFailure);

            outputQueue.put(
                    new Worker.Result(
                            Long.MAX_VALUE,
                            null,
                            PacketAction.FORWARD
                    )
            );

            writer.join();
            checkFailure(writerFailure);
        } finally {
            reader.close();

            for (Thread worker : workers) {
                if (worker.isAlive()) {
                    worker.interrupt();
                }
            }
        }

        if (cfg.verbose()) {
            printReport();
        }
    }

    private void writeOutput(
            String output,
            int linkType,
            BlockingQueue<Worker.Result> outputQueue,
            AtomicReference<Throwable> writerFailure,
            List<Thread> workers
    ) {
        try (PcapWriter pcapWriter = new PcapWriter(output, linkType)) {
            long nextId = 1;
            Map<Long, Worker.Result> pending = new HashMap<>();

            while (true) {
                Worker.Result result = outputQueue.take();

                if (result.p() == null) {
                    return;
                }

                pending.put(result.id(), result);

                while (pending.containsKey(nextId)) {
                    Worker.Result ready = pending.remove(nextId++);

                    if (ready.action() != PacketAction.DROP) {
                        pcapWriter.write(ready.p());
                    }
                }
            }
        } catch (Throwable error) {
            writerFailure.compareAndSet(null, error);

            for (Thread worker : workers) {
                worker.interrupt();
            }
        }
    }

    private static void checkFailure(AtomicReference<Throwable> failure)
            throws Exception {
        Throwable error = failure.get();

        if (error == null) {
            return;
        }

        if (error instanceof Exception exception) {
            throw exception;
        }

        if (error instanceof Error fatalError) {
            throw fatalError;
        }

        throw new RuntimeException(error);
    }

    public void printReport() {
        System.out.println("\n=== DPI REPORT ===");
        System.out.println("Packets: " + stats.totalPackets.sum());
        System.out.println("Bytes: " + stats.totalBytes.sum());
        System.out.println("Forwarded: " + stats.forwarded.sum());
        System.out.println("Dropped: " + stats.dropped.sum());
        System.out.println(
                "TCP: " + stats.tcp.sum()
                        + " | UDP: " + stats.udp.sum()
        );
        System.out.println("Connections: " + connections());
        System.out.println("Applications:");

        stats.applications
                .entrySet()
                .stream()
                .sorted(
                        (a, b) -> Long.compare(
                                b.getValue().sum(),
                                a.getValue().sum()
                        )
                )
                .forEach(
                        entry -> System.out.printf(
                                "  %-12s %d%n",
                                entry.getKey(),
                                entry.getValue().sum()
                        )
                );
    }
}
