# Windows Setup – Java Packet Analyzer

## 1. Install Java 17+

Install a JDK and verify in PowerShell:

```powershell
java -version
javac -version
```

## 2. Install Maven

Verify:

```powershell
mvn -version
```

## 3. Build

From the project directory:

```powershell
mvn clean package
```

## 4. Run

```powershell
java -jar target\packet-analyzer-2.0.0.jar --input test_dpi.pcap --output output_java.pcap --workers 4
```

## 5. Rules

```powershell
java -jar target\packet-analyzer-2.0.0.jar --input test_dpi.pcap --output filtered.pcap --rules rules.txt
```

No CMake, MinGW or native packet-capture DLL is required for offline PCAP analysis.
