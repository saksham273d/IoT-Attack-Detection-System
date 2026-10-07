# IoT Cyber Attack Detection Dashboard

A real-time Intrusion Prevention System (IPS) prototype built with Java Swing. It monitors network traffic on port 8080, detects DoS attacks and suspicious Telnet activity, and automatically blocks offending IP addresses for 60 seconds.

## Features
- **Real-Time Monitoring:** Listens for incoming TCP/HTTP connections on a dedicated port.
- **Auto-Defense:** Detects DoS patterns (>20 requests/sec) and immediately blacklists the source IP.
- **Persistent Logging:** Saves all detected events to daily text files (`./iot_logs/`) compatible with external analysis tools (like C/C++ parsers).
- **Responsive UI:** Uses asynchronous threading and ring buffers to keep the GUI smooth even under heavy attack simulation.
- **Simulation Tool:** Includes a "Real DoS" simulator that sends actual network packets to test the blocking logic end-to-end.

## Prerequisites
- Java Development Kit (JDK) 8 or higher
- Maven or Gradle (optional, but plain `javac` works too)

## How to Run

### 1. Compile
Navigate to the `src` directory and compile the code:
```bash
cd src
javac IoTAttackDetectionDashboard.java