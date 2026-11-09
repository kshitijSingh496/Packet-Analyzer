package com.packetanalyzer.rule;

import com.packetanalyzer.model.AppType;
import com.packetanalyzer.model.Packet;
import com.packetanalyzer.model.PacketAction;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Comparator;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public final class RuleManager {

    private final Set<String> blockedIps =
            ConcurrentHashMap.newKeySet();

    private final Set<String> blockedDomains =
            ConcurrentHashMap.newKeySet();

    private final Set<AppType> blockedApplications =
            ConcurrentHashMap.newKeySet();

    public void blockIp(String ip) {
        blockedIps.add(ip.trim());
    }

    public void unblockIp(String ip) {
        blockedIps.remove(ip.trim());
    }

    public void blockDomain(String domain) {
        blockedDomains.add(
                normalize(domain)
        );
    }

    public void unblockDomain(String domain) {
        blockedDomains.remove(
                normalize(domain)
        );
    }

    public void blockApp(AppType application) {
        blockedApplications.add(application);
    }

    public void unblockApp(AppType application) {
        blockedApplications.remove(application);
    }

    public PacketAction action(
            Packet packet,
            String domain,
            AppType application
    ) {

        if (blockedIps.contains(packet.srcIp())
                || blockedIps.contains(packet.dstIp())
                || blockedApplications.contains(application)
                || domainBlocked(domain)) {

            return PacketAction.DROP;
        }

        return PacketAction.FORWARD;
    }

    private boolean domainBlocked(String domain) {

        if (domain == null || domain.isBlank()) {
            return false;
        }

        String normalized =
                normalize(domain);

        for (String rule : blockedDomains) {

            if (normalized.equals(rule)
                    || normalized.endsWith("." + rule)) {

                return true;
            }
        }

        return false;
    }

    private static String normalize(String domain) {

        return domain == null
                ? ""
                : domain
                    .toLowerCase(Locale.ROOT)
                    .trim()
                    .replaceAll("\\.$", "");
    }

    public void load(String file)
            throws IOException {

        try (
                BufferedReader reader =
                        new BufferedReader(
                                new FileReader(file)
                        )
        ) {

            String line;

            while ((line = reader.readLine()) != null) {

                line = line.trim();

                if (line.isEmpty()
                        || line.startsWith("#")) {

                    continue;
                }

                String[] parts =
                        line.split("\\s+", 2);

                if (parts.length < 2) {
                    continue;
                }

                switch (parts[0].toUpperCase()) {

                    case "IP" ->
                            blockIp(parts[1]);

                    case "DOMAIN" ->
                            blockDomain(parts[1]);

                    case "APP" ->
                            blockApp(
                                    AppType.valueOf(
                                            parts[1]
                                                    .toUpperCase()
                                    )
                            );

                    default -> {
                    }
                }
            }
        }
    }

    public void save(String file)
            throws IOException {

        try (PrintWriter writer =
                     new PrintWriter(file)) {

            blockedIps
                    .stream()
                    .sorted()
                    .forEach(
                            ip ->
                                    writer.println(
                                            "IP " + ip
                                    )
                    );

            blockedDomains
                    .stream()
                    .sorted()
                    .forEach(
                            domain ->
                                    writer.println(
                                            "DOMAIN " + domain
                                    )
                    );

            blockedApplications
                    .stream()
                    .sorted(
                            Comparator.comparing(
                                    Enum::name
                            )
                    )
                    .forEach(
                            application ->
                                    writer.println(
                                            "APP "
                                                    + application
                                    )
                    );
        }
    }
}