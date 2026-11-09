package com.packetanalyzer;

import com.packetanalyzer.dpi.DPIEngine;

import java.nio.file.Path;

public final class Main {

    private Main() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }

        String input = null;
        String output = "output.pcap";
        String rulesFile = null;

        int workers = Math.max(2, Runtime.getRuntime().availableProcessors() / 2);
        int queueSize = 10_000;
        boolean verbose = true;

        for (int i = 0; i < args.length; i++) {
            String option = args[i];

            switch (option) {
                case "--input" -> input = requireValue(args, ++i, option);
                case "--output" -> output = requireValue(args, ++i, option);
                case "--rules" -> rulesFile = requireValue(args, ++i, option);
                case "--workers" -> workers = positiveInt(requireValue(args, ++i, option), option);
                case "--queue" -> queueSize = positiveInt(requireValue(args, ++i, option), option);
                case "--quiet" -> verbose = false;
                case "--help", "-h" -> {
                    usage();
                    return;
                }
                default -> {
                    if (option.startsWith("--")) {
                        throw new IllegalArgumentException("Unknown option: " + option);
                    }
                }
            }
        }

        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("--input is required");
        }

        DPIEngine engine = new DPIEngine(
                new DPIEngine.Config(workers, queueSize, verbose)
        );

        if (rulesFile != null) {
            engine.rules().load(rulesFile);
        }

        engine.process(input, output);

        System.out.println("Output PCAP: " + Path.of(output).toAbsolutePath());
    }

    private static String requireValue(String[] args, int index, String option) {
        if (index >= args.length || args[index].startsWith("--")) {
            throw new IllegalArgumentException("Missing value for " + option);
        }

        return args[index];
    }

    private static int positiveInt(String value, String option) {
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < 1) {
                throw new IllegalArgumentException(option + " must be greater than 0");
            }
            return parsed;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    option + " must be a positive integer: " + value
            );
        }
    }

    static void usage() {
        System.out.println(
                "Packet Analyzer Java 2.0\n"
                        + "Usage: java -jar packet-analyzer-2.0.0.jar "
                        + "--input capture.pcap "
                        + "--output output.pcap "
                        + "[--rules rules.txt] "
                        + "[--workers 4] "
                        + "[--queue 10000] "
                        + "[--quiet]"
        );
    }
}
