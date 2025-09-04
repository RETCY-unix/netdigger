#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <getopt.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>

#define exit_with_error(msg) do {perror(msg); exit(EXIT_FAILURE);} while(0)
#define BUFFER_SIZE 65536
#define MAX_PAYLOAD_DISPLAY 512
#define MAX_PATH_LEN 256

// Global variables
static int sockfd = -1;
static FILE *logfile = NULL;
static uint8_t *buffer = NULL;
static uint64_t packet_count = 0;
static uint64_t filtered_count = 0;

typedef struct {
    uint8_t t_protocol;
    char *source_ip;
    char *dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    char *interface_name;  // Changed from separate source/dest interfaces
    uint8_t interface_mac[6];
    int verbose;
    int payload_hex;
    int payload_ascii;
    int stats_interval;
    uint64_t max_packets;
} packet_filter_t;

void display_banner(void) {
    printf("\n");
    printf("███╗   ██╗███████╗████████╗██████╗ ██╗ ██████╗  ██████╗ ███████╗██████╗ \n");
    printf("████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║██╔════╝ ██╔════╝ ██╔════╝██╔══██╗\n");
    printf("██╔██╗ ██║█████╗     ██║   ██║  ██║██║██║  ███╗██║  ███╗█████╗  ██████╔╝\n");
    printf("██║╚██╗██║██╔══╝     ██║   ██║  ██║██║██║   ██║██║   ██║██╔══╝  ██╔══██╗\n");
    printf("██║ ╚████║███████╗   ██║   ██████╔╝██║╚██████╔╝╚██████╔╝███████╗██║  ██║\n");
    printf("╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═════╝ ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝\n");
    printf("\n");
    printf("                    Enhanced Network Packet Sniffer v3.0\n");
    printf("                   ═══════════════════════════════════════\n\n");
}

void cleanup(void) {
    if (buffer) {
        free(buffer);
        buffer = NULL;
    }
    if (logfile && logfile != stdout) {
        fclose(logfile);
        logfile = NULL;
    }
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
    printf("\n[NETDIGGER] Final Statistics:\n");
    printf("Total packets processed: %lu\n", packet_count);
    printf("Packets matching filters: %lu\n", filtered_count);
    printf("Cleanup completed. Exiting gracefully.\n");
}

void signal_handler(int sig) {
    printf("\n[NETDIGGER] Received signal %d. Shutting down...\n", sig);
    cleanup();
    exit(0);
}

void print_stats(void) {
    printf("[STATS] Processed: %lu | Filtered: %lu | Match Rate: %.2f%%\n", 
           packet_count, filtered_count, 
           packet_count > 0 ? (double)filtered_count / packet_count * 100 : 0.0);
    fflush(stdout);
}

int get_interface_mac(const char *if_name, uint8_t *mac_addr) {
    int fd;
    struct ifreq ifr;
    
    if (!if_name || !mac_addr) {
        return -1;
    }
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("[WARNING] Could not create socket for MAC lookup\n");
        return -1;
    }
 
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
 
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        printf("[WARNING] Could not get MAC address for interface %s\n", if_name);
        close(fd);
        return -1;
    }
    close(fd);

    memcpy(mac_addr, (uint8_t *)ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

int bind_to_interface(int sockfd, const char *if_name) {
    struct sockaddr_ll sll;
    int if_index;
    
    if (!if_name) {
        return 0; // No interface specified, bind to all
    }
    
    if_index = if_nametoindex(if_name);
    if (if_index == 0) {
        printf("[ERROR] Interface %s not found\n", if_name);
        return -1;
    }
    
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_index;
    sll.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        printf("[ERROR] Failed to bind to interface %s\n", if_name);
        return -1;
    }
    
    printf("[INFO] Bound to interface %s (index: %d)\n", if_name, if_index);
    return 0;
}

void format_mac_address(const uint8_t *mac, char *buffer, size_t size) {
    snprintf(buffer, size, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void format_ip_address(uint32_t ip, char *buffer, size_t size) {
    struct in_addr addr;
    addr.s_addr = ip;
    strncpy(buffer, inet_ntoa(addr), size - 1);
    buffer[size - 1] = '\0';
}

void log_timestamp(FILE *lf) {
    time_t now;
    struct tm *timeinfo;
    char timestamp[64];

    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    fprintf(lf, "\n═══════════════════════════════════════════════════════\n");
    fprintf(lf, "Packet #%lu captured at: %s\n", filtered_count, timestamp);
    fprintf(lf, "═══════════════════════════════════════════════════════\n");
}

void log_eth_headers(struct ethhdr *eth, FILE *lf) {
    char src_mac[18], dst_mac[18];
    
    format_mac_address(eth->h_source, src_mac, sizeof(src_mac));
    format_mac_address(eth->h_dest, dst_mac, sizeof(dst_mac));
    
    fprintf(lf, "\nEthernet Header\n");
    fprintf(lf, "\t-Source MAC: %s\n", src_mac);
    fprintf(lf, "\t-Destination MAC: %s\n", dst_mac);
    fprintf(lf, "\t-Protocol: 0x%04X", ntohs(eth->h_proto));
    
    switch (ntohs(eth->h_proto)) {
        case 0x0800: fprintf(lf, " (IPv4)\n"); break;
        case 0x0806: fprintf(lf, " (ARP)\n"); break;
        case 0x86DD: fprintf(lf, " (IPv6)\n"); break;
        default: fprintf(lf, " (Unknown)\n"); break;
    }
}

void log_ip_headers(struct iphdr *ip, FILE *lf) {
    char src_ip[16], dst_ip[16];
    
    format_ip_address(ip->saddr, src_ip, sizeof(src_ip));
    format_ip_address(ip->daddr, dst_ip, sizeof(dst_ip));
    
    fprintf(lf, "\nIP Header\n");
    fprintf(lf, "\t-Version: %d\n", (uint32_t)ip->version);
    fprintf(lf, "\t-Header Length: %d bytes\n", (uint32_t)(ip->ihl * 4));
    fprintf(lf, "\t-Type of Service: 0x%02X\n", (uint32_t)ip->tos);
    fprintf(lf, "\t-Total Length: %d bytes\n", ntohs(ip->tot_len));
    fprintf(lf, "\t-Identification: 0x%04X\n", ntohs(ip->id));
    fprintf(lf, "\t-Flags: 0x%04X\n", ntohs(ip->frag_off) & 0xE000);
    fprintf(lf, "\t-Fragment Offset: %d\n", (ntohs(ip->frag_off) & 0x1FFF) * 8);
    fprintf(lf, "\t-Time to Live: %d\n", (uint32_t)ip->ttl);
    fprintf(lf, "\t-Protocol: %d", (uint32_t)ip->protocol);
    
    switch (ip->protocol) {
        case IPPROTO_TCP: fprintf(lf, " (TCP)\n"); break;
        case IPPROTO_UDP: fprintf(lf, " (UDP)\n"); break;
        case IPPROTO_ICMP: fprintf(lf, " (ICMP)\n"); break;
        default: fprintf(lf, " (Unknown)\n"); break;
    }
    
    fprintf(lf, "\t-Header Checksum: 0x%04X\n", ntohs(ip->check));
    fprintf(lf, "\t-Source IP: %s\n", src_ip);
    fprintf(lf, "\t-Destination IP: %s\n", dst_ip);
}

void log_tcp_headers(struct tcphdr *tcp, FILE *lf) {
    fprintf(lf, "\nTCP Header\n");
    fprintf(lf, "\t-Source Port: %d\n", ntohs(tcp->source));
    fprintf(lf, "\t-Destination Port: %d\n", ntohs(tcp->dest));
    fprintf(lf, "\t-Sequence Number: %u\n", ntohl(tcp->seq));
    fprintf(lf, "\t-Acknowledgement Number: %u\n", ntohl(tcp->ack_seq));
    fprintf(lf, "\t-Header Length: %d bytes\n", (uint32_t)tcp->doff * 4);
    fprintf(lf, "\t-Flags: ");
    
    if (tcp->urg) fprintf(lf, "URG ");
    if (tcp->ack) fprintf(lf, "ACK ");
    if (tcp->psh) fprintf(lf, "PSH ");
    if (tcp->rst) fprintf(lf, "RST ");
    if (tcp->syn) fprintf(lf, "SYN ");
    if (tcp->fin) fprintf(lf, "FIN ");
    fprintf(lf, "\n");
    
    fprintf(lf, "\t-Window Size: %d\n", ntohs(tcp->window));
    fprintf(lf, "\t-Checksum: 0x%04X\n", ntohs(tcp->check));
    fprintf(lf, "\t-Urgent Pointer: %d\n", ntohs(tcp->urg_ptr));
}

void log_udp_headers(struct udphdr *udp, FILE *lf) {
    fprintf(lf, "\nUDP Header\n");
    fprintf(lf, "\t-Source Port: %d\n", ntohs(udp->source));
    fprintf(lf, "\t-Destination Port: %d\n", ntohs(udp->dest));
    fprintf(lf, "\t-UDP Length: %d bytes\n", ntohs(udp->len));
    fprintf(lf, "\t-UDP Checksum: 0x%04X\n", ntohs(udp->check));
}

void log_icmp_headers(struct icmphdr *icmp, FILE *lf) {
    fprintf(lf, "\nICMP Header\n");
    fprintf(lf, "\t-Type: %d", icmp->type);
    
    switch (icmp->type) {
        case 0: fprintf(lf, " (Echo Reply)\n"); break;
        case 3: fprintf(lf, " (Destination Unreachable)\n"); break;
        case 8: fprintf(lf, " (Echo Request)\n"); break;
        case 11: fprintf(lf, " (Time Exceeded)\n"); break;
        default: fprintf(lf, " (Other)\n"); break;
    }
    
    fprintf(lf, "\t-Code: %d\n", icmp->code);
    fprintf(lf, "\t-Checksum: 0x%04X\n", ntohs(icmp->checksum));
    fprintf(lf, "\t-ID: %d\n", ntohs(icmp->un.echo.id));
    fprintf(lf, "\t-Sequence: %d\n", ntohs(icmp->un.echo.sequence));
}

void log_payload_hex(uint8_t *data, int size, FILE *lf) {
    fprintf(lf, "\nPayload (Hex) - %d bytes:\n", size);
    for (int i = 0; i < size; i++) {
        if (i % 16 == 0) {
            fprintf(lf, "%04X: ", i);
        }
        fprintf(lf, "%02X ", data[i]);
        if ((i + 1) % 16 == 0) {
            fprintf(lf, "\n");
        }
    }
    if (size % 16 != 0) {
        fprintf(lf, "\n");
    }
}

void log_payload_ascii(uint8_t *data, int size, FILE *lf) {
    fprintf(lf, "\nPayload (ASCII) - %d bytes:\n", size);
    for (int i = 0; i < size; i++) {
        if (isprint(data[i])) {
            fprintf(lf, "%c", data[i]);
        } else {
            fprintf(lf, ".");
        }
        if ((i + 1) % 64 == 0) {
            fprintf(lf, "\n");
        }
    }
    fprintf(lf, "\n");
}

void log_payload(uint8_t *buffer, int bufflen, int iphdrlen, uint8_t protocol, 
                 FILE *lf, struct tcphdr *tcp, packet_filter_t *filter) {
    uint32_t protocol_header_size = 0;
    
    switch (protocol) {
        case IPPROTO_TCP:
            protocol_header_size = tcp ? (uint32_t)tcp->doff * 4 : sizeof(struct tcphdr);
            break;
        case IPPROTO_UDP:
            protocol_header_size = sizeof(struct udphdr);
            break;
        case IPPROTO_ICMP:
            protocol_header_size = sizeof(struct icmphdr);
            break;
        default:
            protocol_header_size = 0;
            break;
    }
    
    uint8_t *payload = buffer + sizeof(struct ethhdr) + iphdrlen + protocol_header_size;
    int payload_size = bufflen - (sizeof(struct ethhdr) + iphdrlen + protocol_header_size);

    if (payload_size <= 0) {
        fprintf(lf, "\nPayload: No data\n");
        return;
    }

    int display_size = (payload_size > MAX_PAYLOAD_DISPLAY) ? MAX_PAYLOAD_DISPLAY : payload_size;
    
    if (filter->payload_hex) {
        log_payload_hex(payload, display_size, lf);
    }
    
    if (filter->payload_ascii) {
        log_payload_ascii(payload, display_size, lf);
    }
    
    if (!filter->payload_hex && !filter->payload_ascii) {
        // Default: show limited hex dump
        log_payload_hex(payload, display_size > 64 ? 64 : display_size, lf);
    }
    
    if (payload_size > display_size) {
        fprintf(lf, "... (%d more bytes truncated)\n", payload_size - display_size);
    }
}

int filter_packet(struct iphdr *ip, struct tcphdr *tcp, struct udphdr *udp, 
                  packet_filter_t *filter) {
    char src_ip[16], dst_ip[16];
    uint16_t src_port = 0, dst_port = 0;
    
    format_ip_address(ip->saddr, src_ip, sizeof(src_ip));
    format_ip_address(ip->daddr, dst_ip, sizeof(dst_ip));
    
    // Protocol filter
    if (filter->t_protocol != 0 && ip->protocol != filter->t_protocol) {
        return 0;
    }
    
    // IP filters
    if (filter->source_ip && strcmp(filter->source_ip, src_ip) != 0) {
        return 0;
    }
    if (filter->dest_ip && strcmp(filter->dest_ip, dst_ip) != 0) {
        return 0;
    }
    
    // Port filters
    if (tcp) {
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
    } else if (udp) {
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
    }
    
    if (filter->source_port != 0 && src_port != filter->source_port) {
        return 0;
    }
    if (filter->dest_port != 0 && dst_port != filter->dest_port) {
        return 0;
    }
    
    return 1; // Packet passes all filters
}

void process_packet(uint8_t *buffer, int bufflen, packet_filter_t *filter, FILE *lf) {
    packet_count++;
    
    // Check minimum packet size
    if (bufflen < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        return;
    }

    struct ethhdr *eth = (struct ethhdr*)buffer;
    
    // Only process IPv4 packets
    if (ntohs(eth->h_proto) != 0x0800) {
        return;
    }

    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    int iphdrlen = ip->ihl * 4;
    
    // Validate IP header length
    if (iphdrlen < 20 || bufflen < sizeof(struct ethhdr) + iphdrlen) {
        return;
    }

    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    struct icmphdr *icmp = NULL;
    
    if (ip->protocol == IPPROTO_TCP && bufflen >= sizeof(struct ethhdr) + iphdrlen + sizeof(struct tcphdr)) {
        tcp = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + iphdrlen);
    } else if (ip->protocol == IPPROTO_UDP && bufflen >= sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr)) {
        udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + iphdrlen);
    } else if (ip->protocol == IPPROTO_ICMP && bufflen >= sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr)) {
        icmp = (struct icmphdr*)(buffer + sizeof(struct ethhdr) + iphdrlen);
    }

    // Apply filters
    if (!filter_packet(ip, tcp, udp, filter)) {
        return;
    }

    filtered_count++;
    
    // Log packet details
    log_timestamp(lf);
    log_eth_headers(eth, lf);
    log_ip_headers(ip, lf);
    
    if (tcp) {
        log_tcp_headers(tcp, lf);
    } else if (udp) {
        log_udp_headers(udp, lf);
    } else if (icmp) {
        log_icmp_headers(icmp, lf);
    }
    
    log_payload(buffer, bufflen, iphdrlen, ip->protocol, lf, tcp, filter);
    
    // Verbose console output
    if (filter->verbose) {
        char src_ip[16], dst_ip[16];
        format_ip_address(ip->saddr, src_ip, sizeof(src_ip));
        format_ip_address(ip->daddr, dst_ip, sizeof(dst_ip));
        
        const char *proto_str = "OTHER";
        switch (ip->protocol) {
            case IPPROTO_TCP: proto_str = "TCP"; break;
            case IPPROTO_UDP: proto_str = "UDP"; break;
            case IPPROTO_ICMP: proto_str = "ICMP"; break;
        }
        
        printf("[#%lu] %s -> %s (%s)\n", filtered_count, src_ip, dst_ip, proto_str);
    }
    
    // Stats output
    if (filter->stats_interval > 0 && packet_count % filter->stats_interval == 0) {
        print_stats();
    }
    
    // Check max packet limit
    if (filter->max_packets > 0 && filtered_count >= filter->max_packets) {
        printf("\n[NETDIGGER] Captured %lu packets. Limit reached, stopping.\n", filter->max_packets);
        raise(SIGINT);
    }
}

void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("PROTOCOL FILTERS:\n");
    printf("  -t, --tcp               Capture only TCP packets\n");
    printf("  -u, --udp               Capture only UDP packets\n");
    printf("  -m, --icmp              Capture only ICMP packets\n\n");
    printf("ADDRESS FILTERS:\n");
    printf("  -s, --sip <IP>          Filter by source IP address\n");
    printf("  -d, --dip <IP>          Filter by destination IP address\n");
    printf("  -p, --sport <PORT>      Filter by source port\n");
    printf("  -o, --dport <PORT>      Filter by destination port\n");
    printf("  -i, --interface <NAME>  Capture from specific interface\n\n");
    printf("OUTPUT OPTIONS:\n");
    printf("  -f, --logfile <FILE>    Specify output log file (default: netdigger.log)\n");
    printf("  -v, --verbose           Enable verbose console output\n");
    printf("  -x, --hex               Show payload in hexadecimal format\n");
    printf("  -a, --ascii             Show payload in ASCII format\n\n");
    printf("CONTROL OPTIONS:\n");
    printf("  -c, --count <N>         Stop after capturing N packets\n");
    printf("  -S, --stats <N>         Print statistics every N packets\n");
    printf("  -h, --help              Show this help message\n\n");
    printf("EXAMPLES:\n");
    printf("  %s -t -s 192.168.1.1 -v    # TCP packets from specific IP\n", program_name);
    printf("  %s -u -p 53 -f dns.log     # UDP DNS queries to file\n", program_name);
    printf("  %s -i eth0 -c 100 -x       # 100 packets from eth0 with hex\n", program_name);
    printf("  %s -t -o 80 -a -S 1000     # HTTP traffic with ASCII payload\n", program_name);
    printf("\nNote: Requires root privileges to capture packets.\n\n");
}

int validate_ip(const char *ip) {
    struct in_addr addr;
    return inet_aton(ip, &addr) != 0;
}

int validate_port(const char *port_str) {
    char *endptr;
    long port = strtol(port_str, &endptr, 10);
    return (*endptr == '\0' && port >= 1 && port <= 65535);
}

int main(int argc, char **argv) {
    int c;
    char logfile_path[MAX_PATH_LEN] = "netdigger.log";
    packet_filter_t filter = {0};
    struct sockaddr saddr;
    int saddr_len, bufflen;

    display_banner();
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    atexit(cleanup);

    // Check for root privileges
    if (geteuid() != 0) {
        fprintf(stderr, "[ERROR] NetDigger requires root privileges to capture packets.\n");
        fprintf(stderr, "Please run with: sudo %s [options]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Allocate packet buffer
    buffer = (uint8_t*)malloc(BUFFER_SIZE);
    if (!buffer) {
        exit_with_error("Failed to allocate packet buffer");
    }
    memset(buffer, 0, BUFFER_SIZE);

    // Parse command line arguments
    while (1) {
        static struct option long_options[] = {
            {"sip", required_argument, NULL, 's'},
            {"dip", required_argument, NULL, 'd'},
            {"sport", required_argument, NULL, 'p'},
            {"dport", required_argument, NULL, 'o'},
            {"interface", required_argument, NULL, 'i'},
            {"logfile", required_argument, NULL, 'f'},
            {"count", required_argument, NULL, 'c'},
            {"stats", required_argument, NULL, 'S'},
            {"tcp", no_argument, NULL, 't'},
            {"udp", no_argument, NULL, 'u'},
            {"icmp", no_argument, NULL, 'm'},
            {"verbose", no_argument, NULL, 'v'},
            {"hex", no_argument, NULL, 'x'},
            {"ascii", no_argument, NULL, 'a'},
            {"help", no_argument, NULL, 'h'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "tumvxahs:d:p:o:i:f:c:S:", long_options, NULL);

        if (c == -1) break;

        switch(c) {
            case 't':
                filter.t_protocol = IPPROTO_TCP;
                break;
            case 'u':
                filter.t_protocol = IPPROTO_UDP;
                break;
            case 'm':
                filter.t_protocol = IPPROTO_ICMP;
                break;
            case 'v':
                filter.verbose = 1;
                break;
            case 'x':
                filter.payload_hex = 1;
                break;
            case 'a':
                filter.payload_ascii = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            case 's':
                if (!validate_ip(optarg)) {
                    fprintf(stderr, "[ERROR] Invalid source IP address: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                filter.source_ip = optarg;
                break;
            case 'd':
                if (!validate_ip(optarg)) {
                    fprintf(stderr, "[ERROR] Invalid destination IP address: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                filter.dest_ip = optarg;
                break;
            case 'p':
                if (!validate_port(optarg)) {
                    fprintf(stderr, "[ERROR] Invalid source port: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                filter.source_port = (uint16_t)atoi(optarg);
                break;
            case 'o':
                if (!validate_port(optarg)) {
                    fprintf(stderr, "[ERROR] Invalid destination port: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                filter.dest_port = (uint16_t)atoi(optarg);
                break;
            case 'i':
                filter.interface_name = optarg;
                break;
            case 'f':
                strncpy(logfile_path, optarg, MAX_PATH_LEN - 1);
                logfile_path[MAX_PATH_LEN - 1] = '\0';
                break;
            case 'c':
                filter.max_packets = (uint64_t)atoll(optarg);
                if (filter.max_packets == 0) {
                    fprintf(stderr, "[ERROR] Invalid packet count: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'S':
                filter.stats_interval = atoi(optarg);
                if (filter.stats_interval <= 0) {
                    fprintf(stderr, "[ERROR] Invalid stats interval: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        exit_with_error("Failed to create raw socket");
    }

    // Bind to specific interface if requested
    if (bind_to_interface(sockfd, filter.interface_name) < 0) {
        exit(EXIT_FAILURE);
    }

    // Get interface MAC if specified
    if (filter.interface_name) {
        if (get_interface_mac(filter.interface_name, filter.interface_mac) < 0) {
            printf("[WARNING] Could not get MAC address for interface %s\n", filter.interface_name);
        } else {
            char mac_str[18];
            format_mac_address(filter.interface_mac, mac_str, sizeof(mac_str));
            printf("[INFO] Interface %s MAC: %s\n", filter.interface_name, mac_str);
        }
    }

    // Open log file
    logfile = fopen(logfile_path, "w");
    if (!logfile) {
        exit_with_error("Failed to open log file");
    }

    // Print configuration
    printf("\n[CONFIGURATION]\n");
    printf("═══════════════════════════════════════════════════════════\n");
    
    if (filter.t_protocol == IPPROTO_TCP) printf("Protocol: TCP\n");
    else if (filter.t_protocol == IPPROTO_UDP) printf("Protocol: UDP\n");
    else if (filter.t_protocol == IPPROTO_ICMP) printf("Protocol: ICMP\n");
    else printf("Protocol: All\n");
    
    printf("Source IP: %s\n", filter.source_ip ? filter.source_ip : "Any");
    printf("Destination IP: %s\n", filter.dest_ip ? filter.dest_ip : "Any");
    printf("Source Port: %s\n", filter.source_port ? (char[16]){0} : "Any");
    if (filter.source_port) sprintf((char[16]){0}, "%d", filter.source_port);
    printf("Destination Port: %s\n", filter.dest_port ? (char[16]){0} : "Any");
    if (filter.dest_port) sprintf((char[16]){0}, "%d", filter.dest_port);
    printf("Interface: %s\n", filter.interface_name ? filter.interface_name : "All");
    printf("Log file: %s\n", logfile_path);
    printf("Verbose mode: %s\n", filter.verbose ? "Yes" : "No");
    printf("Payload format: %s%s%s\n", 
           filter.payload_hex ? "Hex " : "",
           filter.payload_ascii ? "ASCII " : "",
           (!filter.payload_hex && !filter.payload_ascii) ? "Default" : "");
    
    if (filter.max_packets > 0) {
        printf("Packet limit: %lu\n", filter.max_packets);
    }
    if (filter.stats_interval > 0) {
        printf("Stats interval: every %d packets\n", filter.stats_interval);
    }

    printf("═══════════════════════════════════════════════════════════\n");
    printf("[NETDIGGER] Starting packet capture... Press Ctrl+C to stop.\n");
    printf("═══════════════════════════════════════════════════════════\n");

    // Write header to log file
    fprintf(logfile, "NetDigger Enhanced Packet Capture Log\n");
    fprintf(logfile, "Started: %s", ctime(&(time_t){time(NULL)}));
    fprintf(logfile, "═══════════════════════════════════════════════════════\n");
    fflush(logfile);

    // Main packet capture loop
    while (1) {
        saddr_len = sizeof(saddr);
        bufflen = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, &saddr, (socklen_t *)&saddr_len);
        
        if (bufflen < 0) {
            if (errno == EINTR) {
                continue; // Interrupted by signal, continue
            }
            exit_with_error("Failed to receive packet");
        }

        process_packet(buffer, bufflen, &filter, logfile);
        fflush(logfile); // Ensure data is written immediately
    }

    return 0;
}
