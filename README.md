
# Network Traffic Monitor and Blocker

## Overview
This Rust application monitors network traffic on a specified network interface, identifying and blocking IP addresses that exhibit scanning behavior by targeting a large number of ports. It leverages the `pcap` library for capturing traffic and the `pnet` crate for packet analysis. The application can distinguish between TCP and UDP traffic and implements platform-specific methods to block offending IP addresses automatically.

## Requirements
- Rust
- `pcap` library
- `pnet` crate
- Elevated permissions (root on Unix/Linux or Administrator on Windows)

## Features
- Monitors network traffic in real-time for scanning activities.
- Blocks IP addresses scanning more than a predefined number of ports.
- Supports both Windows (using `netsh`) and Unix/Linux (using `iptables`) for IP blocking.
- Requires elevated permissions to run.

## Usage
1. **Compile the Application:** Use Rust's cargo tool to compile the application:
    ```shell
    cargo build --release
    ```
2. **Run the Application:** Execute the application with elevated permissions. The application requires the index of the network interface you wish to monitor as a command-line argument. If no argument is provided, it will list the available network interfaces and exit.
    - **Unix/Linux:** Use `sudo` or run as root.
    - **Windows:** Run as Administrator.
    ```shell
    sudo ./target/release/network_traffic_monitor [interface_index]
    ```
   Replace `[interface_index]` with the index of the network interface you want to monitor.

## Implementation Details
- The application uses the `pcap` library for capturing packets and the `pnet` crate for packet processing.
- It maintains a record of IP addresses and the ports they have attempted to connect to. If an IP address scans more than 20 ports (configurable via `ALLOWED_AMOUNT_OF_PORTS`), it is automatically blocked.
- Blocking is achieved using `iptables` on Unix/Linux and `netsh` on Windows.
- The application checks for elevated permissions at startup and exits if not run with the necessary privileges.

## Platform-Specific Functions
- **Windows:** Utilizes `netsh advfirewall firewall add rule` commands to block IP addresses.
- **Unix/Linux:** Utilizes `iptables -A INPUT -s [IP] -j DROP` commands to block IP addresses.

## Note
This application modifies your system's firewall rules. Please use it with caution and understand the implications of automatically blocking IP addresses based on network traffic analysis.

