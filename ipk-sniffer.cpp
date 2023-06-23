// VUT FIT - IPK
// Project 2 - ZETA: Network sniffer
// Author: Baturov Illia (xbatur00)

// Libraries
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <getopt.h>
#include <pcap/pcap.h>
#include <ctime>
#include <iomanip>
#include <signal.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;

// Global variables
string interface;
bool tcp, udp, icmp4, icmp6, arp, ndp, igmp, mld = false;
int port = -1;
int number_of_packets = 1;
string filter = ""; // The filter expression
struct bpf_program fp; // The compiled filter
pcap_t *handle; // Session handle

// Usage
void print_usage() {
    cout << "Usage: ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}" << endl;
    return;
}

// Print all interfaces
void print_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_interfaces;
    if (pcap_findalldevs(&all_interfaces, errbuf) == -1) {
        cerr << "ERROR: No devices. INFO: " << errbuf;
        exit(EXIT_FAILURE);
    }
    while(all_interfaces->next != NULL) {
        cout << all_interfaces->name << endl;
        all_interfaces = all_interfaces->next;
    }
    pcap_freealldevs(all_interfaces);
    exit(0);
}

// Print timestamp in RFC 3339 format
void print_timestamp(const struct pcap_pkthdr *header) {
    // Get the current timestamp
    time_t s = header->ts.tv_sec;
    suseconds_t ms = header->ts.tv_usec;

    // Convert to the required format
    char timestamp[30];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", localtime(&s));
    sprintf(timestamp + strlen(timestamp), ".%03ld", ms / 1000);
    // Note: Dividing by 1000 to remove the seconds.
    strftime(timestamp + strlen(timestamp), sizeof(timestamp) - strlen(timestamp), "%z", localtime(&s));

    // Print the timestamp
    cout << "timestamp: " << timestamp << endl;
    // Format: 2021-03-19T18:42:52.362+01:00
    return;
}

// Parse program arguments
void parse_arguments(int argc, const char **argv) {
    // If no parameters are specified, print a list of active interfaces
    if (argc == 1) {
        print_interfaces();
        exit(0);
    }

    // Array of struct option structures needed for getopt_long() function
    static struct option options[] = {
        {"interface", required_argument, 0, 'i'},
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {"icmp4", no_argument, 0, 0},
        {"icmp6", no_argument, 0, 0},
        {"arp", no_argument, 0, 0},
        {"ndp", no_argument, 0, 0},
        {"igmp", no_argument, 0, 0},
        {"mld", no_argument, 0, 0},
        {0, 0, 0, 0}
    };

    // Parse all arguments
    char** args = (char**)argv;
    // Note: Cast to avoid getopt_long() error, argv is const char**, function need const* char* parameter.
    int index = 0;
    int option;
    while ((option = getopt_long(argc, args, "i:p:tun:", options, &index)) != -1) {
        switch(option) {
            case 'i':
                interface = optarg;
                break;
            case 'p':
                port = stoi(optarg);
                break;
            case 't':
                tcp = true;
                break;
            case 'u':
                udp = true;
                break;
            case 'n':
                number_of_packets = stoi(optarg);
                break;
            case 0:
                if (string(options[index].name) == "icmp4") {
                    icmp4 = true;
                } else if (string(options[index].name) == "icmp6") {
                    icmp6 = true;
                } else if (string(options[index].name) == "arp") {
                    arp = true;
                } else if (string(options[index].name) == "ndp") {
                    ndp = true;
                } else if (string(options[index].name) == "igmp") {
                    igmp = true;
                } else if (string(options[index].name) == "mld") {
                    mld = true;
                }
                break;
            default:
                cerr << "ERROR: Wrong program arguments." << endl;
                print_usage();
                exit(EXIT_FAILURE);
        }
    }
}

// Create a protocol filter
void create_filter() {
    // 
    if (port == -1) {
        if (tcp) {
            filter += "tcp or ";
        }
        if (udp) {
            filter += "udp or ";
        }
    } else {
        if (tcp) {
            filter += "tcp and port " + to_string(port) + " or ";
        }
        if (udp) {
            filter += "udp and port " + to_string(port) + " or ";
        }
    }

    // Add protocol filter
    if (icmp4) {
        filter += "icmp or ";
    }
    if (icmp6) {
        filter += "icmp6 or ";
    }
    if (arp) {
        filter += "arp or ";
    }
    if (ndp) {
        filter += "icmp6 and icmp6[0] = 135 or ";
    }
    if (igmp) {
        filter += "igmp or ";
    }
    if (mld) {
        filter += "icmp6 and icmp6[0] = 130 or ";
    }

    // Delete last 3 characters
    if (filter != "") {
        filter.erase(filter.size() - 3);
    }

    return;
}

// Print byte_offset_hexa byte_offset_ASCII
void print_packet_content(const u_char* packet, int length) {
    int zero = 0;
    int byte_count = 0;
    int byte_offset = 0;
    const int bytes_per_row = 16;

    // Loop through the packet printing out each byte
    cout << endl;
    while (byte_offset < length) {
        // Print the byte offset in hexadecimal format
        printf("0x%04x: ", byte_offset);

        // Print out the bytes in hexadecimal format
        for (int i = 0; i < bytes_per_row; i++) {
            if (byte_offset < length) {
                printf("%02x ", packet[byte_offset]);
            } else {
                printf("%02x ", zero);
            }
            byte_offset++;
            byte_count++;
        }

        // Print out the ASCII representation of the bytes
        for (int i = byte_count - bytes_per_row; i < byte_count; i++) {
            if (byte_count - i == 8) {
                printf("%c", ' ');
            }
            // Note: Print white space after 8th byte.
            if (i < length) {
                if (isprint(packet[i])) {
                    printf("%c", packet[i]);

                } else {
                    printf("%c",'.');
                }
            } else {
                printf("%c",'.');
            }
        }
        cout << endl;
    }
    return;
}

// Callback function for looping through packets
void print_packet_info(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    // Variables
    const struct ether_header *ether_h = (const struct ether_header *)packet; // ethernet header
    const struct ip *ipv4_h = (const struct ip *)(packet + sizeof(struct ether_header)); // ipv4 header
    const struct ip6_hdr* ipv6_h = (struct ip6_hdr*)(packet + sizeof(struct ether_header)); // ipv6 header
    const struct tcphdr *tcp_h = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip)); // tcp header
    const struct udphdr *udp_h = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip)); // udp header

    print_timestamp(header); // timestamp
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", \
            ether_h->ether_shost[0], ether_h->ether_shost[1], ether_h->ether_shost[2], \
            ether_h->ether_shost[3], ether_h->ether_shost[4], ether_h->ether_shost[5]); // src MAC
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", \
            ether_h->ether_dhost[0], ether_h->ether_dhost[1], ether_h->ether_dhost[2], \
            ether_h->ether_dhost[3], ether_h->ether_dhost[4], ether_h->ether_dhost[5]); // dst MAC
    printf("frame length: %d bytes\n", header->len); // frame length

    // IPv4
    if (ntohs(ether_h->ether_type) == ETHERTYPE_IP) {
        // ICMP protocol
        if (ipv4_h->ip_p == 1) {
            // Print the packet information
            printf("src IP: %s\n", inet_ntoa(ipv4_h->ip_src)); // src IP
            printf("dst IP: %s\n", inet_ntoa(ipv4_h->ip_dst)); // dst IP
        // TCP protocol
        } else if (ipv4_h->ip_p == 6) {
            // Print the packet information
            printf("src IP: %s\n", inet_ntoa(ipv4_h->ip_src)); // src IP
            printf("dst IP: %s\n", inet_ntoa(ipv4_h->ip_dst)); // dst IP
            printf("src port: %d\n", ntohs(tcp_h->th_sport)); // src port
            printf("dst port: %d\n", ntohs(tcp_h->th_dport)); // dst port
        // UDP protocol
        } else if (ipv4_h->ip_p == 17) {
            // Print the packet information
            printf("src IP: %s\n", inet_ntoa(ipv4_h->ip_src)); // src IP
            printf("dst IP: %s\n", inet_ntoa(ipv4_h->ip_dst)); // dst IP
            printf("src port: %d\n", ntohs(udp_h->uh_sport)); // src port
            printf("dst port: %d\n", ntohs(udp_h->uh_dport)); // dst port
        }
    // IPv6
    } else if (ntohs(ether_h->ether_type) == ETHERTYPE_IPV6) {
        char src_ipv6[INET6_ADDRSTRLEN], dst_ipv6[INET6_ADDRSTRLEN];
        // Note: Convert IPv6 address to string.
        inet_ntop(AF_INET6, &(ipv6_h->ip6_src), src_ipv6, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ipv6_h->ip6_dst), dst_ipv6, INET6_ADDRSTRLEN);
        // TCP protocol
        if (ipv6_h->ip6_nxt == 6) {
            // Print the packet information
            printf("src IP: %s\n", src_ipv6); // src IP
            printf("dst IP: %s\n", dst_ipv6); // dst IP
            printf("src port: %d\n", ntohs(tcp_h->th_sport)); // src port
            printf("dst port: %d\n", ntohs(tcp_h->th_dport)); // dst port
        // UDP protocol
        } else if (ipv6_h->ip6_nxt == 17) {
            // Print the packet information
            printf("src IP: %s\n", src_ipv6); // src IP
            printf("dst IP: %s\n", dst_ipv6); // dst IP
            printf("src port: %d\n", ntohs(udp_h->uh_sport)); // src port
            printf("dst port: %d\n", ntohs(udp_h->uh_dport)); // dst port
        // ICMP protocol
        } else if (ipv6_h->ip6_nxt == 58) {
            // Print the packet information
            printf("src IP: %s\n", src_ipv6); // src IP
            printf("dst IP: %s\n", dst_ipv6); // dst IP
        }
    }
    print_packet_content(packet, header->len); // print packet content
    cout << endl;
    return;
}

// Function for CTRL + C
void handle_signal(int signum)
{
    cout << endl << "Received signal: " << signum << ". Exiting..." << endl;
    pcap_close(handle);
    exit(signum);
}

// Main
int main (int argc, const char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE]; // Error string
    bpf_u_int32 net; // IP address of device
    bpf_u_int32 mask; // Netmask of device
    struct pcap_pkthdr header; // pcup packet header
    const u_char *packet; // actual packet

    signal(SIGINT, handle_signal); // Handle a signal

    parse_arguments(argc, argv); // Parse arguments

    create_filter(); // Create a filter

    // Find the properties for the device
    if (pcap_lookupnet(interface.c_str(), &net, &mask, errbuf) == PCAP_ERROR) {
        cerr << "ERROR: Can't get netmask of device. INFO: " << errbuf;
        exit(EXIT_FAILURE);
    }
    // Open the session
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "ERROR: Can't open device. INFO: " << errbuf;
        exit(EXIT_FAILURE);
    }
    // Check if device is an Ethernet device
    if (pcap_datalink(handle) != DLT_EN10MB) {
        // Note: Data link type of an Ethernet devise is "DLT_EN10MB".
        pcap_close(handle);
        cerr << "ERROR: Device is not an Ethernet device." << errbuf;
        exit(EXIT_FAILURE);
    }
    // Filtering
    if (filter != "") {
        // Compile the filter
        if (pcap_compile(handle, &fp, filter.c_str(), 0, net) == -1) {
            pcap_close(handle);
            cerr << "ERROR: Can't compile filter. INFO: " << pcap_geterr(handle);
            exit(EXIT_FAILURE);
        }
        // Apply the filter
        if (pcap_setfilter(handle, &fp) == -1) {
            pcap_close(handle);
            cerr << "ERROR: Can't apply filter. INFO: " << pcap_geterr(handle);
            exit(EXIT_FAILURE);
        }
    }
    // Grab a packet
    if (pcap_loop(handle, number_of_packets, print_packet_info, nullptr) == PCAP_ERROR) {
        pcap_close(handle);
        cerr << "ERROR: Can't read packets. INFO: " << pcap_geterr(handle);
        exit(EXIT_FAILURE);
    }

    // Close the session
    pcap_close(handle);
    return 0;
}

// End of program
