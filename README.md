# NetDigger - Enhanced Network Packet Sniffer v3.0

```
          ███╗   ██╗███████╗████████╗██████╗ ██╗ ██████╗  ██████╗ ███████╗██████╗ 
          ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║██╔════╝ ██╔════╝ ██╔════╝██╔══██╗
          ██╔██╗ ██║█████╗     ██║   ██║  ██║██║██║  ███╗██║  ███╗█████╗  ██████╔╝
          ██║╚██╗██║██╔══╝     ██║   ██║  ██║██║██║   ██║██║   ██║██╔══╝  ██╔══██╗
          ██║ ╚████║███████╗   ██║   ██████╔╝██║╚██████╔╝╚██████╔╝███████╗██║  ██║
          ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═════╝ ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝

                          I LOVE FROGS
                   ═══════════════════════════════════════
```

A powerful, feature-rich network packet sniffer and analyzer built in C for Linux systems. NetDigger captures and analyzes network traffic with comprehensive filtering options, detailed packet inspection, and flexible output formats.

## ✨ Features

- **Multi-Protocol Support**: TCP, UDP, ICMP packet capture and analysis
- **Advanced Filtering**: Filter by IP addresses, ports, protocols, and network interfaces
- **Detailed Packet Analysis**: Complete header inspection for Ethernet, IP, TCP, UDP, and ICMP
- **Flexible Payload Display**: View packet payloads in hexadecimal, ASCII, or both formats
- **Interface Binding**: Capture from specific network interfaces
- **Real-time Statistics**: Monitor capture statistics with configurable intervals
- **Comprehensive Logging**: Detailed packet logs with timestamps
- **Graceful Shutdown**: Signal handling for clean exit and final statistics
- **MAC Address Resolution**: Interface MAC address lookup and display

## 🔧 Requirements

- **Operating System**: Linux
- **Privileges**: Root access (required for raw socket creation)
- **Compiler**: GCC with standard libraries
- **Dependencies**: Standard Linux networking headers

## 📦 Installation

1. **Clone or download** the NetDigger source files
2. **Compile** using the provided Makefile:
   ```bash
   make
   ```
3. **Run** with appropriate privileges:
   ```bash
   sudo ./netdigger [options]
   ```

### Alternative Compilation

If you prefer manual compilation:
```bash
gcc -Wall -Wextra -O2 -o netdigger sniffer.c
```

## 🚀 Usage

### Basic Usage
```bash
sudo ./netdigger
```

### Command Line Options

#### Protocol Filters
- `-t, --tcp` - Capture only TCP packets
- `-u, --udp` - Capture only UDP packets  
- `-m, --icmp` - Capture only ICMP packets

#### Address Filters
- `-s, --sip <IP>` - Filter by source IP address
- `-d, --dip <IP>` - Filter by destination IP address
- `-p, --sport <PORT>` - Filter by source port
- `-o, --dport <PORT>` - Filter by destination port
- `-i, --interface <NAME>` - Capture from specific interface

#### Output Options
- `-f, --logfile <FILE>` - Specify output log file (default: netdigger.log)
- `-v, --verbose` - Enable verbose console output
- `-x, --hex` - Show payload in hexadecimal format
- `-a, --ascii` - Show payload in ASCII format

#### Control Options
- `-c, --count <N>` - Stop after capturing N packets
- `-S, --stats <N>` - Print statistics every N packets
- `-h, --help` - Show help message

## 📋 Examples

### Capture TCP Traffic from Specific IP
```bash
sudo ./netdigger -t -s 192.168.1.1 -v
```

### Monitor DNS Queries
```bash
sudo ./netdigger -u -p 53 -f dns.log
```

### Capture HTTP Traffic with ASCII Payload
```bash
sudo ./netdigger -t -o 80 -a -S 1000
```

### Interface-Specific Capture
```bash
sudo ./netdigger -i eth0 -c 100 -x
```

### ICMP Traffic Analysis
```bash
sudo ./netdigger -m -v -f icmp_traffic.log
```

### Comprehensive Web Traffic Monitoring
```bash
sudo ./netdigger -t -o 80 -o 443 -x -a -v -S 500
```

## 📊 Output Format

NetDigger provides detailed packet analysis including:

### Ethernet Header Information
- Source and destination MAC addresses
- Protocol type (IPv4, ARP, IPv6)

### IP Header Details
- Version, header length, type of service
- Total length, identification, flags
- Fragment offset, TTL, protocol
- Header checksum, source/destination IPs

### Transport Layer Analysis
**TCP Headers:**
- Source/destination ports
- Sequence and acknowledgment numbers
- Header length and flags (SYN, ACK, FIN, etc.)
- Window size, checksum, urgent pointer

**UDP Headers:**
- Source/destination ports
- UDP length and checksum

**ICMP Headers:**
- Type and code (Echo Request/Reply, etc.)
- Checksum, ID, and sequence numbers

### Payload Display
- Hexadecimal dump with offset addresses
- ASCII representation with printable characters
- Configurable payload size limits

## 📁 File Structure

```
netdigger/
├── sniffer.c      # Main source code
├── Makefile       # Build configuration
└── README.md      # This file
```

## 🔒 Security Considerations

- **Root Privileges**: NetDigger requires root access to create raw sockets
- **Network Monitoring**: Ensure compliance with local network policies
- **Data Privacy**: Be mindful of sensitive information in captured packets
- **Legal Compliance**: Use only on networks you own or have permission to monitor

## 🐛 Troubleshooting

### Common Issues

**"Permission denied" errors:**
```bash
# Ensure running with sudo
sudo ./netdigger [options]
```

**Interface not found:**
```bash
# List available interfaces
ip link show
# Use correct interface name
sudo ./netdigger -i eth0
```

**Compilation errors:**
```bash
# Install development tools if needed
sudo apt-get install build-essential
# Or on RHEL/CentOS
sudo yum install gcc make
```

### Performance Tips

- Use specific filters to reduce processing overhead
- Limit payload display for high-traffic scenarios
- Consider packet count limits for long-running captures
- Use appropriate statistics intervals for monitoring

## 📈 Statistics and Monitoring

NetDigger provides real-time statistics including:
- Total packets processed
- Packets matching filters  
- Match rate percentage
- Configurable statistics intervals

Example output:
```
[STATS] Processed: 15420 | Filtered: 1534 | Match Rate: 9.95%
```

## 🛠️ Advanced Usage

### Combining Filters
```bash
# TCP traffic from specific IP to specific port
sudo ./netdigger -t -s 192.168.1.100 -o 443 -v

# UDP traffic on specific interface with payload analysis
sudo ./netdigger -u -i wlan0 -x -a -c 500
```

### Long-term Monitoring
```bash
# Continuous monitoring with periodic stats
sudo ./netdigger -v -S 10000 -f long_term.log &
```

## 🤝 Contributing

Contributions are welcome! Please ensure:
- Code follows existing style and structure
- New features include appropriate documentation
- Testing on multiple Linux distributions
- Proper error handling and resource cleanup

## 📄 License

This project is provided as-is for educational and legitimate network analysis purposes. Users are responsible for ensuring compliance with applicable laws and regulations.

## ⚠️ Disclaimer

NetDigger is intended for:
- Network troubleshooting and analysis
- Security research and education
- Network performance monitoring
- Protocol analysis and learning

**Use responsibly and only on networks you own or have explicit permission to monitor.**

---

*NetDigger v3.0 - Enhanced Network Packet Sniffer*
