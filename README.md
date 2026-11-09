# Packet Analyzer — Java Deep Packet Inspection Engine

A multithreaded **Deep Packet Inspection (DPI) and PCAP analysis system written in Java**. The project reads offline PCAP captures, parses Ethernet/IPv4/TCP/UDP traffic, tracks bidirectional flows, inspects HTTP Host and TLS ClientHello SNI metadata, classifies applications, applies IP/domain/application blocking rules, writes a filtered PCAP, and reports traffic statistics.

**Language:** Java 
**Build:** Maven  
**Packaging:** Executable JAR  
**License:** Add your preferred license before publishing if required.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Packet Processing Pipeline](#packet-processing-pipeline)
- [Project Structure](#project-structure)
- [Deep Packet Inspection](#deep-packet-inspection)
- [Flow and Connection Tracking](#flow-and-connection-tracking)
- [Rule-Based Blocking](#rule-based-blocking)
- [Concurrency Design](#concurrency-design)
- [Requirements](#requirements)
- [Build](#build)
- [Run](#run)
- [Rules File](#rules-file)
- [Testing](#testing)
- [Verified Results](#verified-results)
- [Command Reference](#command-reference)
- [Limitations](#limitations)
- [Future Enhancements](#future-enhancements)
- [Conclusion](#conclusion)

---

## Overview

Traditional packet filtering can make decisions from information such as IP addresses, ports, and transport protocols. DPI goes further by examining available application-layer metadata inside captured packets.

This project implements an offline DPI pipeline:

```text
                    Input PCAP
                        │
                        ▼
                 ┌─────────────┐
                 │ PcapReader  │
                 └──────┬──────┘
                        │
                        ▼
                 ┌─────────────┐
                 │ PacketParser│
                 └──────┬──────┘
                        │
                        ▼
              ┌─────────────────────┐
              │ Protocol / DPI       │
              │ HTTP Host / TLS SNI │
              │ DNS / Ports         │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │ Application          │
              │ Classification       │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │ RuleManager          │
              │ IP / Domain / APP    │
              └───────┬───────┬─────┘
                      │       │
                    DROP    FORWARD
                      │       │
                      └───┬───┘
                          ▼
                   ┌────────────┐
                   │ PcapWriter │
                   └─────┬──────┘
                         ▼
                  Filtered PCAP
                         +
                    DPI Report
```

---

## Features

### Packet parsing

- Classic PCAP reading
- PCAP endianness handling
- Microsecond/nanosecond PCAP timestamp handling
- Ethernet II parsing
- 802.1Q VLAN handling
- IPv4 parsing and validation
- TCP parsing
- UDP parsing
- Defensive handling of truncated/malformed packets

### Deep Packet Inspection

- HTTP Host extraction
- TLS ClientHello SNI extraction
- TLS/HTTPS recognition
- DNS recognition
- TCP/UDP protocol identification
- Domain-based application classification
- Port-based classification signals

### Flow tracking

- Five-tuple connection keys
- Bidirectional/reverse-flow lookup
- Per-connection packet counters
- Per-connection byte counters
- Application and domain state
- Forward/drop connection state

### Rule engine

Three rule types are supported:

```text
IP
DOMAIN
APP
```

Examples:

```text
IP 192.168.1.100
DOMAIN example.com
APP TWITTER
```

Domain rules support subdomain matching:

```text
DOMAIN example.com
```

matches:

```text
example.com
www.example.com
api.example.com
```

but not:

```text
notexample.com
```

### Concurrency

- Configurable worker threads
- Bounded producer/consumer queues
- Parallel packet inspection
- Dedicated ordered PCAP writer
- Thread-safe connection tracking
- Low-contention statistics using concurrent counters
- Packet sequence IDs preserve input order in output

### CLI

Supports:

```text
--input
--output
--rules
--workers
--queue
--quiet
--help
-h
```

---

## Architecture

The application is organized into focused Java packages:

```text
src/
├── main/
│   └── java/
│       └── com/
│           └── packetanalyzer/
│               ├── Main.java
│               │
│               ├── dpi/
│               │   ├── ConnectionTracker.java
│               │   ├── DPIEngine.java
│               │   ├── ProtocolInspector.java
│               │   └── Worker.java
│               │
│               ├── model/
│               │   ├── AppType.java
│               │   ├── Connection.java
│               │   ├── ConnectionState.java
│               │   ├── FiveTuple.java
│               │   ├── Packet.java
│               │   ├── PacketAction.java
│               │   └── Stats.java
│               │
│               ├── parser/
│               │   ├── PacketParser.java
│               │   └── ParsedPacket.java
│               │
│               ├── pcap/
│               │   ├── PcapPacket.java
│               │   ├── PcapReader.java
│               │   └── PcapWriter.java
│               │
│               └── rule/
│                   └── RuleManager.java
│
└── test/
    └── java/
        └── com/
            └── packetanalyzer/
                └── PacketParserSelfTest.java
```

### Main responsibilities

| Component | Responsibility |
|---|---|
| `Main` | CLI argument parsing and application startup |
| `DPIEngine` | Coordinates the complete processing pipeline |
| `PcapReader` | Reads packets from PCAP |
| `PacketParser` | Parses Ethernet/IPv4/TCP/UDP headers |
| `ProtocolInspector` | Extracts DPI metadata and classifies applications |
| `ConnectionTracker` | Maintains bidirectional connection state |
| `RuleManager` | Applies IP/domain/application rules |
| `Worker` | Performs packet processing concurrently |
| `PcapWriter` | Writes forwarded packets to output PCAP |
| `Stats` | Maintains packet, byte, protocol, and application statistics |

---

## Packet Processing Pipeline

For every packet:

```text
PCAP packet
    │
    ▼
Assign sequence ID
    │
    ▼
Parse Ethernet
    │
    ▼
Parse IPv4
    │
    ▼
Parse TCP / UDP
    │
    ▼
Extract HTTP Host / TLS SNI
    │
    ▼
Classify application
    │
    ▼
Create Packet model
    │
    ▼
Apply rules
    │
    ├── DROP ───────► Do not write packet
    │
    └── FORWARD ────► Write packet
                         │
                         ▼
                    Update report
```

Malformed packets are handled without breaking packet ordering or hanging the output stage.

---

## Deep Packet Inspection

### HTTP

For HTTP payloads, the inspector looks for the `Host` header.

Conceptually:

```text
GET / HTTP/1.1
Host: example.com
```

The extracted hostname can then participate in application classification and domain rules.

### TLS

For TLS ClientHello packets, the inspector attempts to extract the Server Name Indication (SNI).

Example:

```text
TLS ClientHello
      │
      ▼
SNI = www.example.com
      │
      ▼
Application classification
      │
      ▼
Rule matching
```

The project does **not** decrypt TLS traffic.

SNI is treated as an available metadata signal. Modern encrypted-client mechanisms can reduce or hide hostname visibility.

### DNS

DNS traffic is recognized using protocol and port information, allowing DNS traffic to appear separately in the report.

---

## Flow and Connection Tracking

A transport flow is represented using a five-tuple:

```text
Source IP
Destination IP
Source Port
Destination Port
Protocol
```

Example:

```text
192.168.1.10
        ↓
142.250.72.14

53124 → 443
TCP
```

The reverse tuple is also considered:

```text
142.250.72.14:443
        ↓
192.168.1.10:53124
```

This allows packets in both directions to share one logical connection.

The final implementation uses canonical connection handling to avoid duplicate flow objects when opposite-direction packets are processed concurrently.

---

## Rule-Based Blocking

The rule engine supports **three independently tested blocking mechanisms**.

### 1. IP blocking

```text
IP 192.168.1.100
```

A packet is dropped when either its source or destination IP matches the blocked address.

### 2. Domain blocking

```text
DOMAIN example.com
```

The rule matches the domain itself and its subdomains.

### 3. Application blocking

```text
APP TWITTER
```

The rule blocks packets whose classified application matches the configured application type.

### Combined rules

A single file can contain all three:

```text
IP 192.168.1.100
DOMAIN example.com
APP TWITTER
```

Rules are evaluated during packet processing. Forwarded packets are written to the output PCAP; dropped packets are omitted.

### Rule file format

Blank lines and comments are ignored:

```text
# Network policy
IP 192.168.1.100

# Web policy
DOMAIN example.com

# Application policy
APP TWITTER
```

---

## Concurrency Design

The engine uses a producer/worker/writer architecture.

```text
                  PcapReader
                      │
                      ▼
                Job Queue
                      │
       ┌──────────────┼──────────────┐
       ▼              ▼              ▼
   Worker 0       Worker 1       Worker N
       │              │              │
       └──────────────┼──────────────┘
                      ▼
                 Result Queue
                      │
                      ▼
                Ordered Writer
                      │
                      ▼
                 Output PCAP
```

### Why a bounded queue?

The queue prevents unlimited memory growth if packet reading is faster than packet processing.

```text
Reader faster
     │
     ▼
Queue fills
     │
     ▼
Reader blocks
     │
     ▼
Workers catch up
```

### Why a dedicated writer?

Multiple workers process packets concurrently, but PCAP output must be serialized. Each result carries its original sequence ID so the writer can preserve input order.

---

## Requirements

### Software

- Java 17+
- Maven 3.8+
- Windows, Linux, or macOS

Optional:

- Wireshark for inspecting input/output PCAP files
- Python 3.x for the supplied test-PCAP generation script

Check Java:

```bash
java -version
```

Check Maven:

```bash
mvn -version
```

---

## Build

Clone the repository:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd Packet_analyzer
```

Build and run tests:

```bash
mvn clean test
```

Create the executable JAR:

```bash
mvn clean package
```

The JAR is generated at:

```text
target/packet-analyzer-2.0.0.jar
```

---

## Run

### Basic run

```bash
java -jar target/packet-analyzer-2.0.0.jar \
  --input test_dpi.pcap \
  --output analyzed_output.pcap
```

### Windows PowerShell

```powershell
java -jar target\packet-analyzer-2.0.0.jar --input test_dpi.pcap --output analyzed_output.pcap
```

### Configure workers

```powershell
java -jar target\packet-analyzer-2.0.0.jar `
  --input test_dpi.pcap `
  --output analyzed_output.pcap `
  --workers 8 `
  --queue 20000
```

### Use rules

```powershell
java -jar target\packet-analyzer-2.0.0.jar `
  --input test_dpi.pcap `
  --output filtered_output.pcap `
  --rules rules.txt
```

### Quiet mode

```powershell
java -jar target\packet-analyzer-2.0.0.jar `
  --input test_dpi.pcap `
  --output analyzed_output.pcap `
  --quiet
```

### Help

```powershell
java -jar target\packet-analyzer-2.0.0.jar --help
```

---

## Rules File

Example `rules.txt`:

```text
# Block an IP
IP 192.168.1.100

# Block a domain and its subdomains
DOMAIN example.com

# Block a classified application
APP TWITTER
```

Then:

```powershell
java -jar target\packet-analyzer-2.0.0.jar `
  --input test_dpi.pcap `
  --output filtered_output.pcap `
  --rules rules.txt
```

The report shows how many packets were forwarded and dropped.

---

## Testing

### Automated Maven test

Run:

```powershell
mvn clean test
```

The current JUnit test verifies that a truncated Ethernet frame is rejected safely.

Expected result:

```text
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

### Package verification

Run:

```powershell
mvn clean package
```

Expected:

```text
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

### End-to-end PCAP test

```powershell
java -jar target\packet-analyzer-2.0.0.jar `
  --input test_dpi.pcap `
  --output analyzed_output.pcap
```

### Rule tests

The three rule mechanisms have been tested against the supplied capture:

- IP blocking — **verified**
- Domain blocking — **verified**
- Application blocking — **verified**

Application blocking was also verified with a Twitter rule, producing dropped packets while forwarding the remaining traffic.

---

## Verified Results

The final Java 2.0.0 build was tested using the supplied `test_dpi.pcap`.

### Build

```text
mvn clean test
```

```text
Tests run: 1
Failures: 0
Errors: 0
Skipped: 0
BUILD SUCCESS
```

### Package

```text
mvn clean package
```

```text
Compiling 18 source files with javac [debug release 17]
Tests run: 1
Failures: 0
Errors: 0
Skipped: 0
BUILD SUCCESS
```

### End-to-end processing

```text
Packets: 77
Bytes: 5738
Forwarded: 77
Dropped: 0
TCP: 73 | UDP: 4
Connections: 27
```

Detected application categories in the verified capture included:

```text
TLS
HTTP
DNS
TWITTER
DISCORD
CLOUDFLARE
TELEGRAM
YOUTUBE
GITHUB
SPOTIFY
TIKTOK
GOOGLE
APPLE
ZOOM
FACEBOOK
INSTAGRAM
MICROSOFT
AMAZON
```

The analyzer successfully generated:

```text
analyzed_output.pcap
```

### Malformed-packet verification

A capture containing a deliberately truncated packet was also processed without hanging. The invalid packet was handled as a dropped packet while the processing pipeline completed normally.

This validates the final packet-ordering/deadlock fix.

---

## Command Reference

| Purpose | Command |
|---|---|
| Run tests | `mvn clean test` |
| Build JAR | `mvn clean package` |
| Basic analysis | `java -jar target\packet-analyzer-2.0.0.jar --input test_dpi.pcap --output analyzed_output.pcap` |
| Use rules | `java -jar target\packet-analyzer-2.0.0.jar --input test_dpi.pcap --output filtered.pcap --rules rules.txt` |
| Set workers | `--workers 8` |
| Set queue size | `--queue 20000` |
| Disable report | `--quiet` |
| Show help | `--help` |

---

## Limitations

This is an educational/research-oriented offline DPI engine rather than a production IDS/IPS.

Current scope includes:

- IPv4 rather than full IPv6 processing
- Classic PCAP rather than PCAPNG
- No TCP stream reassembly
- No IPv4 fragment reassembly
- TLS metadata inspection without TLS decryption
- SNI extraction only when the required handshake data is available
- No full QUIC application-layer parser
- Deterministic application classification rather than ML-based classification
- Offline PCAP processing rather than inline/live packet forwarding

These boundaries make the project suitable for demonstrating networking, packet parsing, Java concurrency, DPI concepts, and rule-based traffic control while leaving clear paths for future development.

---

## Future Enhancements

### Networking

- IPv6 support
- PCAPNG support
- TCP stream reassembly
- IPv4 fragmentation reassembly
- Live packet capture

### DPI

- HTTP/2 metadata inspection
- QUIC metadata inspection
- DNS query/response parsing
- TLS fingerprinting
- More application signatures
- Statistical or ML-based traffic classification

### Engineering

- More unit/integration tests
- JMH performance benchmarks
- Hot rule reload
- JSON/YAML rule configuration
- Structured logging
- Metrics/observability
- Connection expiry and memory limits
- More advanced ordered-output scaling

---

## Conclusion

Packet Analyzer 2.0 is a Java implementation of an offline Deep Packet Inspection pipeline combining:

```text
PCAP Reading
     ↓
Packet Parsing
     ↓
Protocol Detection
     ↓
HTTP/TLS DPI
     ↓
Application Classification
     ↓
Bidirectional Flow Tracking
     ↓
IP / Domain / Application Rules
     ↓
FORWARD / DROP
     ↓
Filtered PCAP + Statistics
```

The project demonstrates practical knowledge of:

- Computer Networks
- TCP/IP
- Packet parsing
- Deep Packet Inspection
- Java concurrency
- Producer/consumer architecture
- Thread-safe data structures
- Rule engines
- PCAP processing
- Maven build systems
- Defensive programming
- Network traffic classification