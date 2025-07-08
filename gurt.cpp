#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <mutex>
#include <getopt.h>
#include <signal.h>
#include <atomic>
#include <algorithm>
#include <cmath>

using namespace std;
using namespace std::chrono;

struct PingSettings {
    bool help = false;
    int interval = 1; // Default interval in seconds
    vector<string> ip_addresses;
};

struct PingStats {
    string ip_address;
    int instance_id; // To differentiate duplicate IPs
    atomic<int> packets_sent{0};
    atomic<int> packets_received{0};
    atomic<long> total_latency{0}; // in microseconds
    atomic<long> min_latency{LONG_MAX};
    atomic<long> max_latency{0};
    mutex latency_mutex;
    vector<long> latencies; // Store all successful latencies for percentiles/stddev
    
    PingStats(const string& ip, int id) : ip_address(ip), instance_id(id) {}
};

mutex output_mutex; // For thread-safe console output
atomic<bool> should_exit{false};
vector<PingStats*> ping_stats;

// ANSI color codes that work well in both dark and light terminals
const vector<string> IP_COLORS = {
    "\033[1;31m", // Bright Red
    "\033[1;32m", // Bright Green
    "\033[1;33m", // Bright Yellow
    "\033[1;34m", // Bright Blue
    "\033[1;35m", // Bright Magenta
    "\033[1;36m", // Bright Cyan
    "\033[1;91m", // Bright Light Red
    "\033[1;92m", // Bright Light Green
    "\033[1;93m", // Bright Light Yellow
    "\033[1;94m", // Bright Light Blue
    "\033[1;95m", // Bright Light Magenta
    "\033[1;96m"  // Bright Light Cyan
};
const string RESET_COLOR = "\033[0m";

string getColorForIP(const string& ip_address, int instance_id) {
    // Simple hash to assign consistent color to each IP + instance
    size_t hash = 0;
    string unique_key = ip_address + "_" + to_string(instance_id);
    for (char c : unique_key) {
        hash = hash * 31 + c;
    }
    return IP_COLORS[hash % IP_COLORS.size()];
}

// Calculate checksum for ICMP packet
unsigned short checksum(void* b, int len) {
    unsigned short* buf = (unsigned short*)b;
    unsigned int sum = 0;
    unsigned short result;

    // Make 16 bit words out of every two adjacent 8 bit words and 
    // calculate the sum of all 16 bit words
    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }

    // Add left-over byte, if any
    if (len == 1) {
        sum += *(unsigned char*)buf << 8;
    }

    // Fold 32-bit sum to 16 bits: add carrier to result
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    result = ~sum; // One's complement
    return result;
}

void printSummary() {
    cout << "\n--- gurt yo summary ---\n";
    for (const auto& stats : ping_stats) {
        int sent = stats->packets_sent.load();
        int received = stats->packets_received.load();
        long total = stats->total_latency.load();
        long min_lat = stats->min_latency.load();
        long max_lat = stats->max_latency.load();
        
        double loss_percent = sent > 0 ? ((double)(sent - received) / sent) * 100.0 : 0.0;
        double avg_latency = received > 0 ? (double)total / received / 1000.0 : 0.0;
        
        // Get all IPs for instance labeling
        vector<string> all_ips;
        for (const auto& s : ping_stats) {
            all_ips.push_back(s->ip_address);
        }
        
        string color = getColorForIP(stats->ip_address, stats->instance_id);
        cout << "\n" << color << stats->ip_address << RESET_COLOR << ":\n";
        cout << "  " << sent << " gurt" << (sent == 1 ? "" : "s") << ", " << received << " yo" << (received == 1 ? "" : "s") << ", ";
        cout << fixed << setprecision(1) << loss_percent << "% no yo\n";
        if (received > 0) {
            cout << "  round-trip min/avg/max = " 
                 << fixed << setprecision(3) 
                 << min_lat/1000.0 << "/" << avg_latency << "/" << max_lat/1000.0 << " ms\n";
            
            // Calculate additional statistics
            vector<long> latencies_copy;
            {
                lock_guard<mutex> lock(stats->latency_mutex);
                latencies_copy = stats->latencies;
            }
            
            if (latencies_copy.size() > 0) {
                sort(latencies_copy.begin(), latencies_copy.end());
                
                // Calculate median
                double median;
                size_t n = latencies_copy.size();
                if (n % 2 == 0) {
                    median = (latencies_copy[n/2 - 1] + latencies_copy[n/2]) / 2000.0;
                } else {
                    median = latencies_copy[n/2] / 1000.0;
                }
                
                // Calculate 25th and 75th percentiles
                size_t p25_idx = (n - 1) * 25 / 100;
                size_t p75_idx = (n - 1) * 75 / 100;
                double p25 = latencies_copy[p25_idx] / 1000.0;
                double p75 = latencies_copy[p75_idx] / 1000.0;
                
                // Calculate standard deviation
                double mean = avg_latency;
                double variance = 0.0;
                for (long lat : latencies_copy) {
                    double diff = lat / 1000.0 - mean;
                    variance += diff * diff;
                }
                variance /= latencies_copy.size();
                double stddev = sqrt(variance);

                cout << "  statistics: p25=" << fixed << setprecision(3) << p25 
                     << " median=" << median << " p75=" << p75 
                     << " stddev=" << stddev << " ms\n";
            }
        }
        else {
            cout << "  no yo received\n";
        }
    }
    cout << endl;
}

void signalHandler(int signal) {
    should_exit.store(true);
    cout << "\n\nreceived signal " << signal << ", shutting down...\n";
    printSummary();
    exit(0);
}

void help() {
    cout << "yo wsg 0ms response btw\n" << endl;
    cout << "usage: " << "gurt [OPTIONS] <IP1> [IP2] [IP3] ..." << endl;
    cout << "utility to measure latency to multiple IP addresses using ICMP" << endl;
    cout << endl;
    cout << "options:" << endl;
    cout << "  -h, --help         show this help message" << endl;
    cout << "  -i, --interval N   set gurt interval in seconds (default: 1)\n" << endl;
}

PingSettings parseArguments(int argc, char* argv[]) {
    PingSettings settings;
    
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"interval", required_argument, 0, 'i'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "hi:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                settings.help = true;
                break;
            case 'i':
                try {
                    settings.interval = stoi(optarg);
                    if (settings.interval <= 0) {
                        cerr << "error: interval must be greater than 0" << endl;
                        exit(1);
                    }
                } catch (const exception& e) {
                    cerr << "error: invalid interval value" << endl;
                    exit(1);
                }
                break;
            case '?':
                cerr << "unknown option. use -h for help." << endl;
                exit(1);
            default:
                exit(1);
        }
    }
    
    // Collect remaining arguments as IP addresses
    for (int i = optind; i < argc; i++) {
        settings.ip_addresses.push_back(argv[i]);
    }
    
    return settings;
}

int ping(const string& ip_address, int sequence = 1) {
    auto start = high_resolution_clock::now();
    
    // Create raw socket for ICMP (requires root privileges)
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        return -1; // Error creating socket (likely need root privileges)
    }
    
    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 5;  // 5 second timeout
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Configure destination address
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = 0; // Not used for ICMP
    
    if (inet_pton(AF_INET, ip_address.c_str(), &dest_addr.sin_addr) <= 0) {
        close(sock);
        return -2; // Invalid IP address
    }
    
    // Create ICMP packet
    struct icmp icmp_packet;
    memset(&icmp_packet, 0, sizeof(icmp_packet));
    icmp_packet.icmp_type = ICMP_ECHO;
    icmp_packet.icmp_code = 0;
    icmp_packet.icmp_id = getpid() & 0xFFFF;
    icmp_packet.icmp_seq = sequence;
    icmp_packet.icmp_cksum = 0;
    
    // Calculate checksum
    icmp_packet.icmp_cksum = checksum(&icmp_packet, sizeof(icmp_packet));
    
    // Send ICMP packet
    if (sendto(sock, &icmp_packet, sizeof(icmp_packet), 0, 
               (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        close(sock);
        return -3; // Send failed
    }
    
    // Receive reply
    char recv_buffer[1024];
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);
    
    ssize_t bytes_received = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0,
                                      (struct sockaddr*)&recv_addr, &addr_len);
    auto end = high_resolution_clock::now();
    
    close(sock);
    
    if (bytes_received < 0) {
        return -4; // Receive timeout or error
    }
    
    // Parse IP header to get to ICMP header
    struct ip* ip_header = (struct ip*)recv_buffer;
    int ip_header_len = ip_header->ip_hl * 4;
    
    if (bytes_received < ip_header_len + sizeof(struct icmp)) {
        return -5; // Packet too short
    }
    
    struct icmp* recv_icmp = (struct icmp*)(recv_buffer + ip_header_len);
    
    // Check if it's our echo reply
    if (recv_icmp->icmp_type == ICMP_ECHOREPLY && 
        recv_icmp->icmp_id == (getpid() & 0xFFFF) &&
        recv_icmp->icmp_seq == sequence) {
        
        // Calculate latency in microseconds
        auto duration = duration_cast<microseconds>(end - start);
        return duration.count();
    }
    
    return -6; // Not our packet
}

void pingWorker(const string& ip_address, int interval, PingStats* stats) {
    int sequence_number = 1;
    
    // Get all IPs for instance labeling
    vector<string> all_ips;
    for (const auto& s : ping_stats) {
        all_ips.push_back(s->ip_address);
    }
    
    while (!should_exit.load()) {
        int latency = ping(ip_address, sequence_number);
        stats->packets_sent++;
        
        {
            lock_guard<mutex> lock(output_mutex);
            if (latency >= 0) {
                stats->packets_received++;
                stats->total_latency += latency;
                
                // Store latency for statistical calculations
                {
                    lock_guard<mutex> lat_lock(stats->latency_mutex);
                    stats->latencies.push_back(latency);
                }
                
                // Update min/max latency
                long current_min = stats->min_latency.load();
                while (latency < current_min && !stats->min_latency.compare_exchange_weak(current_min, latency));
                
                long current_max = stats->max_latency.load();
                while (latency > current_max && !stats->max_latency.compare_exchange_weak(current_max, latency));
                
                string color = getColorForIP(ip_address, stats->instance_id);
                cout << color << "yo " << RESET_COLOR << fixed << setprecision(3) << latency/1000.0 << "ms" << endl;
            } else {
                string error_msg;
                switch (latency) {
                    case -1: error_msg = "socket creation failed (run 'sudo make install' to set up permissions)"; break;
                    case -2: error_msg = "invalid IP address"; break;
                    case -3: error_msg = "send failed"; break;
                    case -4: error_msg = "receive timeout or error"; break;
                    case -5: error_msg = "packet too short"; break;
                    case -6: error_msg = "not our packet"; break;
                    default: error_msg = "unknown error"; break;
                }
                string color = getColorForIP(ip_address, stats->instance_id);
                cout << color << "nah " << RESET_COLOR << ": " << error_msg << endl;
            }
        }
        
        sequence_number++;
        this_thread::sleep_for(seconds(interval));
    }
}

int main(int argc, char* argv[]) {
    // Set up signal handlers
    signal(SIGINT, signalHandler);  // Ctrl+C
    signal(SIGTSTP, signalHandler); // Ctrl+Z
    
    // Parse command line arguments
    PingSettings settings = parseArguments(argc, argv);
    
    // Show help if requested or if no arguments provided
    if (settings.help || argc == 1) {
        help();
        return 0;
    }
    
    // Validate that at least one IP address was provided
    if (settings.ip_addresses.empty()) {
        cerr << "error: at least one IP address is required" << endl;
        cerr << "use -h or --help for help" << endl;
        return 1;
    }
    
    // Initialize ping statistics for each IP
    for (size_t i = 0; i < settings.ip_addresses.size(); i++) {
        ping_stats.push_back(new PingStats(settings.ip_addresses[i], i));
    }
    
    // Display settings
    cout << "interval: " << settings.interval << " second" << (settings.interval == 1 ? "" : "s") << endl;
    cout << "target ip" << (settings.ip_addresses.size() == 1 ? "" : "s") << ": ";
    for (size_t i = 0; i < settings.ip_addresses.size(); i++) {
        string color = getColorForIP(settings.ip_addresses[i], i);
        cout << color << settings.ip_addresses[i] << RESET_COLOR;
        if (i < settings.ip_addresses.size() - 1) cout << ", ";
    }
    cout << endl << endl;
    
    // Create threads for each IP address
    vector<thread> ping_threads;
    
    for (size_t i = 0; i < settings.ip_addresses.size(); i++) {
        ping_threads.emplace_back(pingWorker, settings.ip_addresses[i], settings.interval, ping_stats[i]);
    }
    
    // Wait for all threads to complete
    for (auto& t : ping_threads) {
        t.join();
    }
    
    // Clean up
    for (auto* stats : ping_stats) {
        delete stats;
    }
    
    return 0;
}